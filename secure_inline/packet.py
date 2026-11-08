"""Minimal IPv4/TCP parsing and checksum helpers (no third-party dependencies)."""
from __future__ import annotations

import struct
from dataclasses import dataclass


class PacketError(ValueError):
    """Raised for malformed IPv4/TCP packets."""


@dataclass
class Ipv4Info:
    ihl: int                 # IP header length in bytes (at least 20; more if IP options are present)
    total_len: int           # IPv4 total length field (IP header + TCP header + payload)
    proto: int               # IP protocol number (6 = TCP)
    src: bytes               # 4 bytes source IP address
    dst: bytes               # 4 bytes destination IP address
    is_fragment: bool        # True if this is a fragment (MF flag set or non-zero fragment offset)
    # TCP fields (valid only if proto == 6 and not is_fragment)
    sport: int = 0           # TCP source port
    dport: int = 0           # TCP destination port
    seq: int = 0             # TCP sequence number
    ack: int = 0             # TCP acknowledgement number
    flags: int = 0           # low 9 bits of the TCP flags field (NS..FIN)
    thl: int = 0             # TCP header length in bytes (at least 20; more if TCP options present)
    payload_off: int = 0     # byte offset where the TCP payload starts inside the IP packet

    @property
    def is_tcp(self) -> bool:
        return self.proto == 6 and not self.is_fragment

    @property
    def payload_len(self) -> int:
        # Number of bytes of actual TCP payload (what we encrypt)
        return self.total_len - self.payload_off


def parse_ipv4(raw: bytes) -> Ipv4Info:
    n = len(raw)
    if n < 20:
        raise PacketError("short packet")
    if raw[0] >> 4 != 4:
        raise PacketError("not IPv4")
    # IHL is the number of 32-bit words in the IP header; multiply by 4 to get bytes
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or ihl > n:
        raise PacketError("bad IHL")
    total_len = struct.unpack_from("!H", raw, 2)[0]
    if total_len < ihl or total_len > n:
        raise PacketError("bad total length")
    # Bits 13-0 of the flags+offset field: MF (bit 13) or any non-zero offset means fragmented
    frag_field = struct.unpack_from("!H", raw, 6)[0]
    info = Ipv4Info(
        ihl=ihl,
        total_len=total_len,
        proto=raw[9],
        src=bytes(raw[12:16]),
        dst=bytes(raw[16:20]),
        is_fragment=bool(frag_field & 0x3FFF),   # MF flag or non-zero offset
    )
    # Only parse the TCP header if this is a non-fragmented TCP packet
    if info.proto != 6 or info.is_fragment:
        return info
    if total_len < ihl + 20:
        raise PacketError("short TCP header")
    sport, dport, seq, ack, off_flags = struct.unpack_from("!HHIIH", raw, ihl)
    # Data offset is the top 4 bits of the 16-bit field; it counts 32-bit words
    thl = (off_flags >> 12) * 4
    if thl < 20 or ihl + thl > total_len:
        raise PacketError("bad TCP data offset")
    info.sport, info.dport, info.seq, info.ack = sport, dport, seq, ack
    info.flags = off_flags & 0x01FF  # keep only the 9 flag bits
    info.thl = thl
    info.payload_off = ihl + thl
    return info


# ---------------------------------------------------------------- checksums

def _sum16(data: bytes) -> int:
    # Pad to even length and sum all 16-bit big-endian words
    if len(data) & 1:
        data += b"\x00"
    return sum(struct.unpack(f"!{len(data) // 2}H", data))


def _fold(s: int) -> int:
    # Fold a 32-bit sum down to 16 bits by adding the carry bits
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def inet_checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum."""
    return (~_fold(_sum16(data))) & 0xFFFF


def _pseudo_header(pkt: bytes, seg_len: int) -> bytes:
    # TCP checksum is computed over a 12-byte pseudo-header (src IP, dst IP, proto, length)
    # followed by the full TCP segment; this binds the checksum to the IP addresses
    return bytes(pkt[12:20]) + struct.pack("!BBH", 0, 6, seg_len)


def tcp_checksum_valid(pkt: bytes, ihl: int, total_len: int) -> bool:
    # A correct TCP checksum produces an all-ones result (0xFFFF after folding)
    seg = bytes(pkt[ihl:total_len])
    return _fold(_sum16(_pseudo_header(pkt, len(seg))) + _sum16(seg)) == 0xFFFF


def recompute_checksums(pkt: bytearray, ihl: int, total_len: int) -> None:
    """Rewrite IPv4 total length, IP header checksum and TCP checksum in place.

    `pkt` must already be exactly `total_len` bytes long.
    """
    if len(pkt) != total_len:
        raise PacketError("buffer length != total_len")
    # Update total length first (it changed when we added/removed the GCM tag)
    struct.pack_into("!H", pkt, 2, total_len)
    # Recompute TCP checksum: zero the field first so it is not included in its own calculation
    struct.pack_into("!H", pkt, ihl + 16, 0)
    seg = bytes(pkt[ihl:total_len])
    csum = (~_fold(_sum16(_pseudo_header(pkt, len(seg))) + _sum16(seg))) & 0xFFFF
    struct.pack_into("!H", pkt, ihl + 16, csum)
    # Recompute IP header checksum last (it covers the total-length field we just updated)
    struct.pack_into("!H", pkt, 10, 0)
    struct.pack_into("!H", pkt, 10, inet_checksum(bytes(pkt[:ihl])))
