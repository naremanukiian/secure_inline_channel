import unittest

from secure_inline.packet import (inet_checksum, parse_ipv4, tcp_checksum_valid,
                                  PacketError)
from tests.helpers import build_packet


class PacketTests(unittest.TestCase):
    def test_rfc1071_vector(self):
        # Known test vector from RFC 1071 to verify the checksum algorithm is correct
        self.assertEqual(inet_checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)

    def test_known_ip_header_checksum(self):
        # Verify against a pre-computed IP header checksum
        hdr = bytearray.fromhex("45000073000040004011" "0000" "c0a80001c0a800c7")
        self.assertEqual(inet_checksum(bytes(hdr)), 0xB861)

    def test_parse_and_checksum(self):
        # Build a packet with both IP and TCP options to test non-minimal header lengths
        pkt = build_packet(b"hello", ip_opts=b"\x01\x01\x01\x01", tcp_opts=b"\x02\x04\x05\xb4")
        info = parse_ipv4(pkt)
        # IP header = 20 + 4 bytes of options = 24; TCP header = 20 + 4 = 24; payload = 5
        self.assertEqual((info.ihl, info.thl, info.payload_len), (24, 24, 5))
        self.assertEqual((info.sport, info.dport, info.seq, info.ack), (40000, 5001, 1000, 2000))
        # Both checksums must validate correctly on a freshly built packet
        self.assertTrue(tcp_checksum_valid(pkt, info.ihl, info.total_len))
        self.assertEqual(inet_checksum(pkt[:info.ihl]), 0)

    def test_corrupt_checksum_detected(self):
        # Flipping a single bit in the payload must invalidate the TCP checksum
        pkt = bytearray(build_packet(b"hello"))
        pkt[-1] ^= 1
        info = parse_ipv4(bytes(pkt))
        self.assertFalse(tcp_checksum_valid(bytes(pkt), info.ihl, info.total_len))

    def test_malformed(self):
        # Packets that are too short or have an impossible total_len must raise PacketError
        with self.assertRaises(PacketError):
            parse_ipv4(b"\x45\x00")  # only 2 bytes; minimum is 20
        pkt = bytearray(build_packet(b"x"))
        pkt[2:4] = b"\xff\xff"  # set total_len = 65535 on a much shorter packet
        with self.assertRaises(PacketError):
            parse_ipv4(bytes(pkt))


if __name__ == "__main__":
    unittest.main()
