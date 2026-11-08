"""Minimal IPv4/TCP parsing and checksum helpers (no third-party dependencies)."""
from __future__ import annotations

import struct
from dataclasses import dataclass


class PacketError(ValueError):
    """Raised for malformed IPv4/TCP packets."""


@dataclass
class Ipv4Info:
    ihl: int                 # IP header length in bytes
    total_len: int           # IPv4 total length field
    proto: int
    src: bytes               # 4 bytes
    dst: bytes               # 4 bytes
    is_fragment: bool
    # TCP fields (valid only if proto == 6 and not is_fragment)
    sport: int = 0
    dport: int = 0
    seq: int = 0
    ack: int = 0
    flags: int = 0           # low 9 bits of the TCP flags field (NS..FIN)
    thl: int = 0             # TCP header length in bytes
    payload_off: int = 0     # offset of TCP payload inside the IP packet

    @property
    def is_tcp(self) -> bool:
        return self.proto == 6 and not self.is_fragment

    @property
    def payload_len(self) -> int:
        return self.total_len - self.payload_off


def parse_ipv4(raw: bytes) -> Ipv4Info:
    n = len(raw)
    if n < 20:
        raise PacketError("short packet")
    if raw[0] >> 4 != 4:
        raise PacketError("not IPv4")
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or ihl > n:
        raise PacketError("bad IHL")
    total_len = struct.unpack_from("!H", raw, 2)[0]
    if total_len < ihl or total_len > n:
        raise PacketError("bad total length")
    frag_field = struct.unpack_from("!H", raw, 6)[0]
    info = Ipv4Info(
        ihl=ihl,
        total_len=total_len,
        proto=raw[9],
        src=bytes(raw[12:16]),
        dst=bytes(raw[16:20]),
        is_fragment=bool(frag_field & 0x3FFF),   # MF flag or non-zero offset
    )
    if info.proto != 6 or info.is_fragment:
        return info
    if total_len < ihl + 20:
        raise PacketError("short TCP header")
    sport, dport, seq, ack, off_flags = struct.unpack_from("!HHIIH", raw, ihl)
    thl = (off_flags >> 12) * 4
    if thl < 20 or ihl + thl > total_len:
        raise PacketError("bad TCP data offset")
    info.sport, info.dport, info.seq, info.ack = sport, dport, seq, ack
    info.flags = off_flags & 0x01FF
    info.thl = thl
    info.payload_off = ihl + thl
    return info


# ---------------------------------------------------------------- checksums

def _sum16(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    return sum(struct.unpack(f"!{len(data) // 2}H", data))


def _fold(s: int) -> int:
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def inet_checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum."""
    return (~_fold(_sum16(data))) & 0xFFFF


def _pseudo_header(pkt: bytes, seg_len: int) -> bytes:
    return bytes(pkt[12:20]) + struct.pack("!BBH", 0, 6, seg_len)


def tcp_checksum_valid(pkt: bytes, ihl: int, total_len: int) -> bool:
    seg = bytes(pkt[ihl:total_len])
    return _fold(_sum16(_pseudo_header(pkt, len(seg))) + _sum16(seg)) == 0xFFFF


def recompute_checksums(pkt: bytearray, ihl: int, total_len: int) -> None:
    """Rewrite IPv4 total length, IP header checksum and TCP checksum in place.

    `pkt` must already be exactly `total_len` bytes long.
    """
    if len(pkt) != total_len:
        raise PacketError("buffer length != total_len")
    struct.pack_into("!H", pkt, 2, total_len)
    # TCP
    struct.pack_into("!H", pkt, ihl + 16, 0)
    seg = bytes(pkt[ihl:total_len])
    csum = (~_fold(_sum16(_pseudo_header(pkt, len(seg))) + _sum16(seg))) & 0xFFFF
    struct.pack_into("!H", pkt, ihl + 16, csum)
    # IP header
    struct.pack_into("!H", pkt, 10, 0)
    struct.pack_into("!H", pkt, 10, inet_checksum(bytes(pkt[:ihl])))
