#!/usr/bin/env python3
"""Tiny TCP test application used by the demo: verifies integrity in both directions."""
import argparse
import hashlib
import random
import socket
import sys


def blob(n: int, marker: bytes, seed: int) -> bytes:
    # Generate a deterministic pseudo-random byte string of exactly n bytes.
    # The marker is embedded repeatedly so a sniffer can search for it on the wire.
    rnd = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        out += marker + rnd.randbytes(1000)
    return bytes(out[:n])


def server(a):
    marker = a.marker.encode()
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.bind, a.port))
    s.listen(1)
    print("server ready", flush=True)
    c, addr = s.accept()
    # Read everything the client sends and compute a SHA-256 hash to verify integrity
    h, total = hashlib.sha256(), 0
    while True:
        d = c.recv(65536)
        if not d:
            break
        h.update(d)
        total += len(d)
    # Send the hash and total byte count back so the client can check the uplink
    reply = blob(a.reply_size, marker, 2)
    c.sendall(b"%s %d\n" % (h.hexdigest().encode(), total) + reply)
    c.close()
    print(f"server received {total} bytes from {addr[0]}", flush=True)


def client(a):
    marker = a.marker.encode()
    # Generate the same deterministic data the server expects (seed=1 for client->server)
    data = blob(a.size, marker, 1)
    s = socket.create_connection((a.host, a.port), timeout=20)
    s.sendall(data)
    s.shutdown(socket.SHUT_WR)  # signal end-of-upload; server will now send its reply
    resp = bytearray()
    while True:
        d = s.recv(65536)
        if not d:
            break
        resp += d
    # Parse the response: first line is "sha256hex bytecount\n", rest is the reply blob
    line, _, body = bytes(resp).partition(b"\n")
    digest, n = line.split()
    # Verify uplink integrity: does the server's hash match what we sent?
    ok_up = digest.decode() == hashlib.sha256(data).hexdigest() and int(n) == len(data)
    # Verify downlink integrity: does the reply body match the expected deterministic blob?
    ok_down = body == blob(a.reply_size, marker, 2)
    print(f"client->server integrity: {'OK' if ok_up else 'FAIL'} ({len(data)} bytes)")
    print(f"server->client integrity: {'OK' if ok_down else 'FAIL'} ({len(body)} bytes)")
    return 0 if ok_up and ok_down else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    sp = sub.add_parser("server"); sp.add_argument("--bind", default="0.0.0.0")
    cp = sub.add_parser("client"); cp.add_argument("--host", required=True)
    cp.add_argument("--size", type=int, default=2_000_000)
    for p in (sp, cp):
        p.add_argument("--port", type=int, default=5001)
        p.add_argument("--marker", default="SECRET-MARKER-0123456789")
        p.add_argument("--reply-size", type=int, default=500_000)
    a = ap.parse_args()
    sys.exit(server(a) if a.mode == "server" else client(a))
