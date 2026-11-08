import os
import socket
import struct

from secure_inline import crypto
from secure_inline.packet import inet_checksum, recompute_checksums


def build_packet(payload: bytes, src="10.0.1.2", dst="10.0.2.2", sport=40000, dport=5001,
                 seq=1000, ack=2000, flags=0x18, ip_opts=b"", tcp_opts=b"") -> bytes:
    # Build a valid IPv4/TCP packet from scratch with correct checksums.
    # flags=0x18 means PSH+ACK, which is a typical data packet.
    ihl = 20 + len(ip_opts)   # IP header length in bytes
    thl = 20 + len(tcp_opts)  # TCP header length in bytes
    total = ihl + thl + len(payload)
    # Pack the fixed IP header fields; checksum field is zeroed and computed below
    ip = struct.pack("!BBHHHBBH4s4s", 0x40 | (ihl // 4), 0, total, 0x1234, 0x4000, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + ip_opts
    # Pack TCP header; checksum field is zeroed and computed by recompute_checksums
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (thl // 4) << 12 | flags, 65535, 0, 0) + tcp_opts
    pkt = bytearray(ip + tcp + payload)
    recompute_checksums(pkt, ihl, total)
    return bytes(pkt)


def session_pair(**kw):
    """Two SessionManagers (Device1 initiator / Device2 responder) with matching keys,
    created without a network handshake."""
    # Use random bytes as the DH shared secret so each test gets independent keys
    shared = os.urandom(256)
    ni, nr = os.urandom(32), os.urandom(32)
    km = crypto.derive_keys(shared, ni, nr, crypto.transcript_hash(ni, nr))
    d1, d2 = crypto.SessionManager(), crypto.SessionManager()
    # Build both sessions from the same key material, with opposite roles
    s1 = crypto.build_session(km, "initiator", **kw)
    s2 = crypto.build_session(km, "responder", **kw)
    for m, s in ((d1, s1), (d2, s2)):
        m.install_rx(s)
        m.activate_tx(s)
    return d1, d2
