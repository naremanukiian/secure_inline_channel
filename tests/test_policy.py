import unittest

from secure_inline.packet import parse_ipv4
from secure_inline.policy import DROP, PASS, PROTECT, Policy, parse_ports
from tests.helpers import build_packet


class PolicyTests(unittest.TestCase):
    def test_ports_and_nets(self):
        p = Policy(parse_ports(["5001,6000:6002"]), ["10.0.1.0/24"], ["10.0.2.0/24"])
        c = lambda **k: p.classify(parse_ipv4(build_packet(b"x", **k)))
        self.assertEqual(c(), PROTECT)
        self.assertEqual(c(src="10.0.2.2", dst="10.0.1.2", sport=5001, dport=40000), PROTECT)
        self.assertEqual(c(dport=6001), PROTECT)
        self.assertEqual(c(dport=80), PASS)
        self.assertEqual(c(dst="10.9.9.9"), PASS)

    def test_fragments_dropped_when_addresses_match(self):
        raw = bytearray(build_packet(b"x" * 8))
        raw[6] = 0x20                                  # MF set
        self.assertEqual(Policy({5001}).classify(parse_ipv4(bytes(raw))), DROP)


if __name__ == "__main__":
    unittest.main()
