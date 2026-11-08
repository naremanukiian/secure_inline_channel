import socket
import threading
import time
import unittest

from secure_inline import crypto, handshake
from secure_inline.datapath import Datapath
from secure_inline.policy import Policy
from tests.helpers import build_packet

PSK = b"0123456789abcdef0123456789abcdef"


def free_port():
    # Bind to port 0 to get an OS-assigned free port, then release it for the test to use
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_for(cond, t=5.0):
    # Poll a condition function up to `t` seconds; returns True if the condition was met
    end = time.time() + t
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


class HandshakeTests(unittest.TestCase):
    def setUp(self):
        self.stop = threading.Event()
        self.port = free_port()
        self.m1, self.m2 = crypto.SessionManager(), crypto.SessionManager()

    def tearDown(self):
        # Signal all daemon threads to stop after each test
        self.stop.set()
        time.sleep(0.2)

    def start_responder(self, psk=PSK):
        threading.Thread(target=handshake.serve, daemon=True,
                         args=(self.m2, "127.0.0.1", self.port, psk, self.stop)).start()
        time.sleep(0.2)  # give the server thread time to bind and listen

    def test_handshake_and_data_both_ways(self):
        # Full handshake followed by encrypted traffic in both directions
        self.start_responder()
        sock, sess = handshake.initiate("127.0.0.1", self.port, PSK, self.m1)
        self.assertTrue(wait_for(lambda: self.m2.current_tx() is not None))
        d1, d2 = Datapath(Policy({5001}), self.m1), Datapath(Policy({5001}), self.m2)
        pkt = build_packet(b"through the tunnel")
        # Encrypted by Device1, decrypted by Device2 -> should equal the original
        self.assertEqual(d2.inbound(d1.outbound(pkt)), pkt)
        rev = build_packet(b"and back", src="10.0.2.2", dst="10.0.1.2", sport=5001, dport=40000)
        # Reverse direction: Device2 encrypts, Device1 decrypts
        self.assertEqual(d1.inbound(d2.outbound(rev)), rev)
        sock.close()

    def test_wrong_psk_rejected_and_no_session(self):
        # A wrong PSK must cause the handshake to fail and leave no active session on either side
        self.start_responder()
        with self.assertRaises((handshake.HandshakeError, OSError)):
            handshake.initiate("127.0.0.1", self.port, b"x" * 32, self.m1)
        self.assertIsNone(self.m1.current_tx())
        self.assertIsNone(self.m2.current_tx())

    def test_fresh_keys_each_session(self):
        # Two consecutive handshakes must produce sessions with different identifiers
        self.start_responder()
        s1, a = handshake.initiate("127.0.0.1", self.port, PSK, self.m1)
        s2, b = handshake.initiate("127.0.0.1", self.port, PSK, self.m1)
        self.assertNotEqual(a.sid, b.sid)
        s1.close(); s2.close()

    def test_initiator_loop_rekeys_and_recovers(self):
        # The initiator_loop should automatically rekey when the session age limit is reached
        self.start_responder()
        threading.Thread(target=handshake.initiator_loop, daemon=True, args=(
            self.m1, "127.0.0.1", self.port, PSK, self.stop, 0.5, 10 ** 9)).start()
        self.assertTrue(wait_for(lambda: self.m1.current_tx() is not None))
        first = self.m1.current_tx().sid
        # Wait for the 0.5-second time limit to trigger a rekey; the session ID must change
        self.assertTrue(wait_for(lambda: self.m1.current_tx().sid != first, 5))   # time-based rekey
        d1, d2 = Datapath(Policy({5001}), self.m1), Datapath(Policy({5001}), self.m2)
        pkt = build_packet(b"after rekey")
        self.assertTrue(wait_for(lambda: self.m2.current_tx() is not None))
        # Data must still flow correctly with the new session keys
        self.assertEqual(d2.inbound(d1.outbound(pkt)), pkt)


if __name__ == "__main__":
    unittest.main()
