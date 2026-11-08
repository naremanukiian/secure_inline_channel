"""Selection of which TCP/IPv4 flows are protected.

Both devices MUST run the same policy: each device decides purely from the
packet's addresses/ports whether a packet is a protected one.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable

from .packet import Ipv4Info

# The three possible verdicts for a packet
PASS = "pass"       # forward the packet untouched (not our business)
PROTECT = "protect" # encrypt (outbound) or decrypt-and-verify (inbound)
DROP = "drop"       # silently discard (e.g. fragments we cannot safely classify)


def parse_ports(specs: Iterable[str]) -> frozenset[int]:
    """Accept '5001', '5001,5002', '8000:8010'. Empty => all ports."""
    ports: set[int] = set()
    for spec in specs:
        for tok in str(spec).split(","):
            tok = tok.strip()
            if not tok or tok == "all":
                continue
            # Range syntax: lo:hi (inclusive on both ends)
            if ":" in tok:
                lo, hi = (int(x) for x in tok.split(":", 1))
            else:
                lo = hi = int(tok)
            if not (0 < lo <= hi <= 65535):
                raise ValueError(f"bad port spec {tok!r}")
            ports.update(range(lo, hi + 1))
    return frozenset(ports)


class Policy:
    """A packet is protected when its address pair lies between net_a and net_b
    (either direction) and the TCP source or destination port is selected."""

    def __init__(self, ports: Iterable[int] = (), net_a=("0.0.0.0/0",), net_b=("0.0.0.0/0",)):
        self.ports = frozenset(ports)
        # Store networks as (network_address, netmask) integer pairs for fast matching
        self._a = [self._net(n) for n in net_a]
        self._b = [self._net(n) for n in net_b]

    @staticmethod
    def _net(cidr: str):
        n = ipaddress.IPv4Network(cidr, strict=False)
        return int(n.network_address), int(n.netmask)

    @staticmethod
    def _in(nets, ip: int) -> bool:
        # Check if the IP address belongs to any of the given networks
        return any((ip & mask) == net for net, mask in nets)

    def classify(self, info: Ipv4Info) -> str:
        # Only TCP traffic can be protected; pass everything else (UDP, ICMP, etc.)
        if info.proto != 6:
            return PASS
        s = int.from_bytes(info.src, "big")
        d = int.from_bytes(info.dst, "big")
        # Traffic is selected if the source/dest pair matches net_a <-> net_b in either direction
        if not ((self._in(self._a, s) and self._in(self._b, d)) or
                (self._in(self._b, s) and self._in(self._a, d))):
            return PASS
        # Drop fragments: later fragments have no TCP header, so we can't tell if they
        # belong to a protected flow, and passing them in the clear would be a leak
        if info.is_fragment:
            return DROP          # cannot be classified/protected safely
        # If a port list was specified, only protect traffic on those ports
        if self.ports and info.sport not in self.ports and info.dport not in self.ports:
            return PASS
        return PROTECT
