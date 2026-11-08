import unittest

from secure_inline.packet import parse_ipv4
from secure_inline.policy import DROP, PASS, PROTECT, Policy, parse_ports
from tests.helpers import build_packet


class PolicyTests(unittest.TestCase):
    def test_ports_and_nets(self):
        # Policy that protects ports 5001 and 6000-6002 between two specific /24 subnets
        p = Policy(parse_ports(["5001,6000:6002"]), ["10.0.1.0/24"], ["10.0.2.0/24"])
        c = lambda **k: p.classify(parse_ipv4(build_packet(b"x", **k)))
        # Default packet is 10.0.1.2:40000 -> 10.0.2.2:5001 which should be protected
        self.assertEqual(c(), PROTECT)
        # Reverse direction (src and dst swapped) must also be protected
        self.assertEqual(c(src="10.0.2.2", dst="10.0.1.2", sport=5001, dport=40000), PROTECT)
        # Port 6001 is within the 6000:6002 range; should be protected
        self.assertEqual(c(dport=6001), PROTECT)
        # Port 80 is not in the policy; should be passed through
        self.assertEqual(c(dport=80), PASS)
        # Destination outside both subnets; not covered by the policy
        self.assertEqual(c(dst="10.9.9.9"), PASS)

    def test_fragments_dropped_when_addresses_match(self):
        # Fragmented packets that match the address policy must be dropped, not passed through,
        # because later fragments have no TCP header and cannot be safely handled in the clear
        raw = bytearray(build_packet(b"x" * 8))
        raw[6] = 0x20                                  # MF set -> this is a fragment
        self.assertEqual(Policy({5001}).classify(parse_ipv4(bytes(raw))), DROP)


if __name__ == "__main__":
    unittest.main()
