"""Device daemon: runs the handshake and the two NFQUEUE packet loops.

    sudo python3 -m secure_inline.device --role initiator --peer 10.0.12.2 --psk-file psk --port 5001
    sudo python3 -m secure_inline.device --role responder --listen 10.0.12.2 --psk-file psk --port 5001
"""
from __future__ import annotations

import argparse
import logging
import signal
import socket
import sys
import threading

from . import crypto, handshake
from .datapath import Datapath, Stats
from .policy import Policy, parse_ports

log = logging.getLogger("sic.device")


def load_psk(path: str) -> bytes:
    # Read the pre-shared key from a file; strip trailing whitespace so a newline doesn't
    # end up as part of the key when the file was created with e.g. `echo "key" > psk`
    with open(path, "rb") as f:
        psk = f.read().strip()
    if len(psk) < 16:
        raise SystemExit("PSK must be at least 16 bytes (use e.g. 32 random bytes, hex encoded)")
    return psk


def run_queue(num: int, fn, stop: threading.Event, name: str) -> None:
    from netfilterqueue import NetfilterQueue   # imported lazily so tests need no libnetfilter_queue

    def cb(pkt):
        raw = pkt.get_payload()
        try:
            out = fn(raw)
        except Exception:                        # never let a bug turn into a plaintext leak
            log.exception("%s: processing error, dropping packet", name)
            out = None
        if out is None:
            pkt.drop()
        elif out is raw:
            # Packet object is the same (not modified); tell netfilter to accept it as-is
            pkt.accept()
        else:
            # Payload was transformed (encrypted or decrypted); update the packet and accept
            pkt.set_payload(out)
            pkt.accept()

    nfq = NetfilterQueue()
    nfq.bind(num, cb, max_len=8192)
    # Wrap the netfilter file descriptor in a socket so we can apply a timeout and
    # check the stop event periodically without blocking forever in nfq.run()
    s = socket.fromfd(nfq.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # Increase the kernel socket receive buffer to handle traffic bursts without drops
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    except OSError:
        pass
    s.settimeout(1.0)
    log.info("%s loop bound to NFQUEUE %d", name, num)
    try:
        while not stop.is_set():
            try:
                nfq.run_socket(s)
            except socket.timeout:
                continue  # just loop back and check stop
    finally:
        nfq.unbind()
        s.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--role", required=True, choices=["initiator", "responder"],
                    help="initiator = Device1 (dials the peer), responder = Device2 (listens)")
    ap.add_argument("--peer", help="initiator: peer device address for the control channel")
    ap.add_argument("--listen", default="0.0.0.0", help="responder: control channel bind address")
    ap.add_argument("--control-port", type=int, default=9000)
    ap.add_argument("--psk-file", required=True)
    ap.add_argument("--port", action="append", default=[],
                    help="TCP port(s) to protect (5001 | 5001,5002 | 8000:8010 | all). Repeatable.")
    ap.add_argument("--net-a", action="append", default=[], help="CIDR on one side (default any)")
    ap.add_argument("--net-b", action="append", default=[], help="CIDR on the other side (default any)")
    ap.add_argument("--enc-queue", type=int, default=0, help="NFQUEUE for packets from the plain side")
    ap.add_argument("--dec-queue", type=int, default=1, help="NFQUEUE for packets from the peer device")
    ap.add_argument("--rekey-seconds", type=float, default=600.0)
    ap.add_argument("--rekey-packets", type=int, default=2 ** 28)
    ap.add_argument("--fwd-window", type=int, default=1024, help="max packets lost/skipped between devices")
    ap.add_argument("--back-window", type=int, default=128, help="reordering tolerance")
    ap.add_argument("--no-verify-checksums", action="store_true",
                    help="skip TCP checksum validation (needed if NIC checksum offload leaves partial checksums)")
    ap.add_argument("--stats-interval", type=float, default=10.0, help="0 disables")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if a.role == "initiator" and not a.peer:
        ap.error("--peer is required for the initiator")

    psk = load_psk(a.psk_file)
    # Build the traffic policy; default to protecting all TCP between any two addresses
    policy = Policy(parse_ports(a.port), a.net_a or ["0.0.0.0/0"], a.net_b or ["0.0.0.0/0"])
    manager = crypto.SessionManager()
    stats = Stats()
    dp = Datapath(policy, manager, verify_checksums=not a.no_verify_checksums, stats=stats)
    # Session kwargs passed to the handshake; rekey_packets*2 gives headroom for in-flight packets
    skw = dict(max_packets=a.rekey_packets * 2, fwd_window=a.fwd_window, back_window=a.back_window)

    # A single threading.Event lets all threads shut down cleanly when we receive SIGINT/SIGTERM
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    threads = []
    # One control-channel thread (initiator dials out; responder listens)
    if a.role == "initiator":
        threads.append(threading.Thread(target=handshake.initiator_loop, name="ctl", daemon=True, args=(
            manager, a.peer, a.control_port, psk, stop, a.rekey_seconds, a.rekey_packets), kwargs=skw))
    else:
        threads.append(threading.Thread(target=handshake.serve, name="ctl", daemon=True, args=(
            manager, a.listen, a.control_port, psk, stop), kwargs=skw))
    # Two packet-processing threads: one for outbound (encrypt) and one for inbound (decrypt)
    threads.append(threading.Thread(target=run_queue, name="enc", daemon=True,
                                    args=(a.enc_queue, dp.outbound, stop, "encrypt")))
    threads.append(threading.Thread(target=run_queue, name="dec", daemon=True,
                                    args=(a.dec_queue, dp.inbound, stop, "decrypt")))
    for t in threads:
        t.start()

    # Main thread just prints stats periodically and waits for the stop event
    while not stop.wait(a.stats_interval if a.stats_interval > 0 else 3600):
        if a.stats_interval > 0:
            log.info("stats %s", dict(sorted(stats.snapshot().items())))
    log.info("shutting down; final stats %s", dict(sorted(stats.snapshot().items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
