"""Per-packet protection logic (pure functions of bytes -> bytes, no I/O).

Protected packet on the wire between Device1 and Device2:

    +-----------+-----------+---------------------------+-----------+
    | IPv4 hdr  | TCP hdr   | AES-GCM ciphertext        | GCM tag   |
    | (original)| (original)| (same length as plaintext)| (16 bytes)|
    +-----------+-----------+---------------------------+-----------+

Only the TCP payload is encrypted. IP and TCP headers are kept (so the packet is
still routable ordinary TCP/IPv4); IPv4 total length, IP header checksum and TCP
checksum are recomputed. Headers are authenticated as GCM associated data.
"""
from __future__ import annotations

import logging
import struct
import threading
from collections import Counter
from typing import Optional

from . import crypto
from .packet import (Ipv4Info, PacketError, parse_ipv4, recompute_checksums,
                     tcp_checksum_valid)
from .policy import DROP, PASS, PROTECT, Policy

log = logging.getLogger("sic.datapath")

AAD_VERSION = b"SIC1"


def build_aad(info: Ipv4Info) -> bytes:
    """Immutable header fields bound to the ciphertext. TTL, ToS, IP-ID, window,
    urgent pointer and checksums are deliberately excluded because they may
    legitimately change in transit; length is implied by the ciphertext."""
    return AAD_VERSION + struct.pack("!4s4sHHIIH", info.src, info.dst, info.sport,
                                     info.dport, info.seq, info.ack, info.flags)


class Stats:
    def __init__(self):
        self._c: Counter = Counter()
        self._lock = threading.Lock()

    def inc(self, key: str, n: int = 1) -> None:
        with self._lock:
            self._c[key] += n

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._c)


class Datapath:
    def __init__(self, policy: Policy, manager: crypto.SessionManager,
                 verify_checksums: bool = True, stats: Optional[Stats] = None):
        self.policy = policy
        self.manager = manager
        self.verify = verify_checksums
        self.stats = stats or Stats()

    # Each method returns: the bytes to forward (the *same object* when the packet
    # is untouched) or None to drop the packet.

    def outbound(self, raw: bytes) -> Optional[bytes]:
        """Packet arriving from the plain side (host) -> protect towards the peer."""
        st = self.stats
        try:
            info = parse_ipv4(raw)
        except PacketError:
            st.inc("out_malformed")
            return None
        verdict = self.policy.classify(info)
        if verdict == PASS:
            st.inc("out_unselected")
            return raw
        if verdict == DROP:
            st.inc("out_dropped_fragment")
            return None
        if info.payload_len == 0:              # SYN / pure ACK / FIN / RST: nothing to encrypt
            st.inc("out_control_passthrough")
            return raw
        if self.verify and not tcp_checksum_valid(raw, info.ihl, info.total_len):
            st.inc("out_dropped_bad_checksum")
            return None
        sess = self.manager.current_tx()
        if sess is None:
            st.inc("out_dropped_no_session")   # fail closed until the handshake is done
            return None
        if info.total_len + crypto.TAG_LEN > 65535:
            st.inc("out_dropped_too_big")
            return None
        try:
            sealed = sess.tx.encrypt(bytes(raw[info.payload_off:info.total_len]), build_aad(info))
        except crypto.SessionExhausted:
            st.inc("out_dropped_session_exhausted")
            return None
        out = bytearray(raw[:info.payload_off])
        out += sealed
        recompute_checksums(out, info.ihl, len(out))
        st.inc("out_encrypted")
        return bytes(out)

    def inbound(self, raw: bytes) -> Optional[bytes]:
        """Packet arriving from the peer device -> verify, decrypt, restore."""
        st = self.stats
        try:
            info = parse_ipv4(raw)
        except PacketError:
            st.inc("in_malformed")
            return None
        verdict = self.policy.classify(info)
        if verdict == PASS:
            st.inc("in_unselected")
            return raw
        if verdict == DROP:
            st.inc("in_dropped_fragment")
            return None
        if info.payload_len == 0:
            st.inc("in_control_passthrough")
            return raw
        if info.payload_len <= crypto.TAG_LEN:         # needs >=1 byte of data + tag
            st.inc("in_dropped_short")
            return None
        if self.verify and not tcp_checksum_valid(raw, info.ihl, info.total_len):
            st.inc("in_dropped_bad_checksum")
            return None
        sealed = bytes(raw[info.payload_off:info.total_len])
        aad = build_aad(info)
        plain = None
        for sess in self.manager.rx_sessions():
            plain = sess.rx.decrypt(sealed, aad)
            if plain is not None:
                break
        if plain is None:
            st.inc("in_dropped_auth_fail")             # bad tag, replay, or no session
            return None
        out = bytearray(raw[:info.payload_off])
        out += plain
        recompute_checksums(out, info.ihl, len(out))
        st.inc("in_decrypted")
        return bytes(out)
