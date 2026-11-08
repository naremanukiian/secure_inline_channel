#!/usr/bin/env python3
"""Capture on an interface (AF_PACKET) and report whether a marker is visible on the wire."""
import argparse
import socket
import struct
import sys
import time

ap = argparse.ArgumentParser()
ap.add_argument("--iface", required=True)
ap.add_argument("--marker", required=True)
ap.add_argument("--port", type=int, default=5001)
ap.add_argument("--seconds", type=float, default=8)
a = ap.parse_args()

# Open a raw socket that receives all Ethernet frames on the specified interface
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((a.iface, 0))
s.settimeout(0.5)  # short timeout so we keep looping until the capture period ends
m = a.marker.encode()
frames = tcp_data = leaked = 0
end = time.time() + a.seconds
while time.time() < end:
    try:
        f = s.recv(65535)
    except socket.timeout:
        continue
    frames += 1
    # Skip non-IPv4 frames (Ethernet type 0x0800) and non-TCP packets (proto 6)
    if len(f) < 54 or f[12:14] != b"\x08\x00" or f[23] != 6:
        continue
    # Parse the IP header to find where the TCP header starts
    ihl = (f[14] & 0xF) * 4
    sport, dport = struct.unpack_from("!HH", f, 14 + ihl)
    tot = struct.unpack_from("!H", f, 16)[0]
    thl = (f[14 + ihl + 12] >> 4) * 4
    # Only count segments on our port that actually carry payload (not SYN/FIN/ACK)
    if a.port in (sport, dport) and tot - ihl - thl > 0:
        tcp_data += 1
        # If the marker string appears anywhere in the raw frame, the payload is in plaintext
        if m in f:
            leaked += 1
print(f"sniff[{a.iface}]: frames={frames} tcp_data_segments_on_port_{a.port}={tcp_data} segments_containing_marker={leaked}")
# Exit 1 if any plaintext was detected (useful for CI pass/fail checking)
sys.exit(1 if leaked else 0)
