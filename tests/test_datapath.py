import os
import threading
import unittest

from secure_inline import crypto
from secure_inline.datapath import Datapath
from secure_inline.packet import inet_checksum, parse_ipv4, tcp_checksum_valid
from secure_inline.policy import Policy
from tests.helpers import build_packet, session_pair

POLICY = Policy({5001})


def pair(**kw):
    d1m, d2m = session_pair(**kw)
    return Datapath(POLICY, d1m), Datapath(POLICY, d2m), d1m, d2m


class DatapathTests(unittest.TestCase):
    def test_roundtrip_both_directions(self):
        d1, d2, _, _ = pair()
        for payload in (b"x", b"hello world", os.urandom(1400)):
            pkt = build_packet(payload)
            wire = d1.outbound(pkt)
            self.assertEqual(len(wire), len(pkt) + 16)
            self.assertEqual(d2.inbound(wire), pkt)          # byte-exact restoration
            # reverse direction (PC2 -> PC1): Device2 encrypts, Device1 decrypts
            rev = build_packet(payload, src="10.0.2.2", dst="10.0.1.2", sport=5001, dport=40000)
            self.assertEqual(d1.inbound(d2.outbound(rev)), rev)

    def test_only_payload_encrypted_headers_preserved(self):
        d1, _, _, _ = pair()
        payload = b"TOPSECRET" * 20
        pkt = build_packet(payload, ip_opts=b"\x01\x01\x01\x01", tcp_opts=b"\x01\x01\x01\x01")
        wire = d1.outbound(pkt)
        info, w = parse_ipv4(pkt), parse_ipv4(wire)
        off = info.payload_off
        # IP+TCP headers identical except total length (2:4), IP csum (10:12), TCP csum (ihl+16:ihl+18)
        mask = bytearray(wire[:off])
        orig = bytearray(pkt[:off])
        for rng in ((2, 4), (10, 12), (info.ihl + 16, info.ihl + 18)):
            mask[rng[0]:rng[1]] = b"\0\0"
            orig[rng[0]:rng[1]] = b"\0\0"
        self.assertEqual(mask, orig)
        self.assertNotIn(b"TOPSECRET", wire)
        self.assertEqual(w.total_len, info.total_len + 16)
        self.assertEqual(inet_checksum(wire[:w.ihl]), 0)
        self.assertTrue(tcp_checksum_valid(wire, w.ihl, w.total_len))

    def test_tamper_detected(self):
        d1, d2, _, _ = pair()
        wire = bytearray(d1.outbound(build_packet(b"payload-data")))
        for idx in (-1, -17, 40):             # tag, ciphertext, TCP header (seq byte)
            bad = bytearray(wire)
            bad[idx] ^= 0x01
            info = parse_ipv4(bytes(bad))
            from secure_inline.packet import recompute_checksums
            recompute_checksums(bad, info.ihl, len(bad))     # attacker fixes checksums
            self.assertIsNone(d2.inbound(bytes(bad)), idx)
        self.assertIsNotNone(d2.inbound(bytes(wire)))          # untouched copy still fine

    def test_header_binding(self):
        d1, d2, _, _ = pair()
        wire = d1.outbound(build_packet(b"abcdef", seq=5000))
        redirected = bytearray(wire)
        redirected[12:16] = bytes([10, 0, 1, 99])            # spoofed source address
        from secure_inline.packet import recompute_checksums
        recompute_checksums(redirected, 20, len(redirected))
        self.assertIsNone(d2.inbound(bytes(redirected)))

    def test_replay_and_reorder(self):
        d1, d2, _, _ = pair()
        wires = [d1.outbound(build_packet(b"p%d" % i, seq=i)) for i in range(10)]
        order = [3, 0, 1, 2, 9, 5, 4]
        for i in order:
            self.assertIsNotNone(d2.inbound(wires[i]), i)
        for i in order:
            self.assertIsNone(d2.inbound(wires[i]), f"replay {i}")

    def test_loss_gap_within_window(self):
        d1, d2, _, _ = pair(fwd_window=64)
        wires = [d1.outbound(build_packet(b"a")) for _ in range(300)]
        self.assertIsNotNone(d2.inbound(wires[0]))
        self.assertIsNotNone(d2.inbound(wires[50]))      # 49 packets lost: inside the window
        self.assertIsNotNone(d2.inbound(wires[99]))      # next expected is 51, window covers up to 114
        self.assertIsNone(d2.inbound(wires[299]))        # ~200 lost: outside the window -> dropped

    def test_nonce_unique_per_packet_even_for_retransmission(self):
        d1, _, d1m, _ = pair()
        pkt = build_packet(b"identical payload", seq=77)
        outs = {d1.outbound(pkt) for _ in range(500)}
        self.assertEqual(len(outs), 500)                  # same plaintext => different ciphertext

    def test_nonce_counter_threadsafe_unique(self):
        tx = crypto.TxState(os.urandom(32), b"\0\0\0\1")
        seen, lock = [], threading.Lock()

        def work():
            local = [tx.reserve_nonce() for _ in range(2000)]
            with lock:
                seen.extend(local)
        ts = [threading.Thread(target=work) for _ in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(len(seen), len(set(seen)))
        self.assertEqual(len(seen), 16000)

    def test_session_exhaustion_fails_closed(self):
        d1, _, _, _ = pair(max_packets=3)
        outs = [d1.outbound(build_packet(b"x")) for _ in range(5)]
        self.assertEqual([o is not None for o in outs], [True, True, True, False, False])

    def test_no_session_drops_protected_but_not_control_or_other(self):
        dp = Datapath(POLICY, crypto.SessionManager())
        self.assertIsNone(dp.outbound(build_packet(b"data")))
        syn = build_packet(b"", flags=0x02)
        self.assertIs(dp.outbound(syn), syn)               # handshake of the TCP connection itself
        other = build_packet(b"data", dport=80)
        self.assertIs(dp.outbound(other), other)           # unselected traffic untouched

    def test_plaintext_injection_rejected(self):
        _, d2, _, _ = pair()
        self.assertIsNone(d2.inbound(build_packet(b"A" * 64)))   # unencrypted data from the "peer"
        self.assertIsNone(d2.inbound(build_packet(b"short")))    # shorter than a tag

    def test_session_switch_grace(self):
        d1, d2, d1m, d2m = pair()
        old_wire = d1.outbound(build_packet(b"old session"))
        # responder re-keys: a new session becomes current, old one stays acceptable
        shared = os.urandom(256)
        ni, nr = os.urandom(32), os.urandom(32)
        km = crypto.derive_keys(shared, ni, nr, crypto.transcript_hash(ni, nr))
        s2 = crypto.build_session(km, "responder")
        d2m.install_rx(s2)
        d2m.activate_tx(s2)
        self.assertIsNotNone(d2.inbound(old_wire))


if __name__ == "__main__":
    unittest.main()
