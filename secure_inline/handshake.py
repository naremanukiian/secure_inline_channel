"""Authenticated Diffie-Hellman handshake between Device1 (initiator) and
Device2 (responder) over a dedicated TCP control connection.

The control connection is local traffic of the two devices (INPUT/OUTPUT), it is
never touched by the FORWARD-chain packet protection. No protected data is sent
until the handshake has completed on both sides.

    I -> R : "SIC1" 01 | nonce_i(32) | dh_pub_i(256) | HMAC(psk, "init" | nonce_i | pub_i)
    R -> I : "SIC1" 02 | nonce_r(32) | dh_pub_r(256) | HMAC(psk, "resp" | nonce_i | pub_i | nonce_r | pub_r)
    I -> R : "SIC1" 03 | HMAC(confirm_key, "initiator-confirm" | transcript_hash)
    R -> I : "SIC1" 04 | HMAC(confirm_key, "responder-confirm" | transcript_hash)

* DH group: RFC 3526 group 14 (2048 bit); session keys come from HKDF-SHA256.
* The PSK authenticates both DH values (defeats an active man-in-the-middle);
  the DH exchange gives forward secrecy w.r.t. the PSK.
* Messages 3/4 are key-confirmation: each side proves it derived the same keys.
* Receive-side keys are installed before the confirmation is sent, transmit
  keys are activated only after the peer has proven possession of the keys.
"""
from __future__ import annotations

import hmac
import hashlib
import logging
import os
import select
import socket
import threading
import time
from typing import Optional

from . import crypto

log = logging.getLogger("sic.handshake")

# Protocol magic bytes at the start of every handshake message
MAGIC = b"SIC1"
NONCE_LEN = 32   # 256-bit random nonce per side per session
MAC_LEN = 32     # HMAC-SHA256 output length
# Total byte lengths for each of the four handshake messages
M1_LEN = 5 + NONCE_LEN + crypto.DH_LEN + MAC_LEN  # magic(4) + type(1) + nonce + pub + mac
M2_LEN = M1_LEN
M3_LEN = 5 + MAC_LEN   # magic(4) + type(1) + confirmation mac


class HandshakeError(Exception):
    pass


def _mac(key: bytes, label: bytes, *parts: bytes) -> bytes:
    # HMAC-SHA256 with a label prefix to domain-separate different MAC uses
    return hmac.new(key, label + b"".join(parts), hashlib.sha256).digest()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    # TCP may deliver data in multiple chunks; loop until we have exactly n bytes
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise HandshakeError("connection closed during handshake")
        buf += chunk
    return bytes(buf)


def _check_hdr(msg: bytes, typ: int) -> None:
    # Verify the 4-byte magic and the 1-byte message type code
    if msg[:4] != MAGIC or msg[4] != typ:
        raise HandshakeError(f"unexpected message (wanted type {typ})")


# ------------------------------------------------------------------ initiator
def initiate(host: str, port: int, psk: bytes, manager: crypto.SessionManager,
             timeout: float = 5.0, **session_kw) -> tuple[socket.socket, crypto.Session]:
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        # --- Message 1: send our DH public key and a PSK-authenticated nonce ---
        priv, pub_i = crypto.dh_generate()
        nonce_i = os.urandom(NONCE_LEN)
        body1 = nonce_i + pub_i
        sock.sendall(MAGIC + b"\x01" + body1 + _mac(psk, b"init", body1))

        # --- Message 2: receive the responder's DH public key and verify their PSK ---
        m2 = _recv_exact(sock, M2_LEN)
        _check_hdr(m2, 2)
        nonce_r = m2[5:5 + NONCE_LEN]
        pub_r = m2[5 + NONCE_LEN:5 + NONCE_LEN + crypto.DH_LEN]
        mac_r = m2[-MAC_LEN:]
        # The responder's MAC covers both sides' nonces and public keys, so we can't be MITM'd
        if not hmac.compare_digest(mac_r, _mac(psk, b"resp", nonce_i, pub_i, nonce_r, pub_r)):
            raise HandshakeError("responder authentication failed (PSK mismatch?)")

        # Compute the DH shared secret and derive all session keys from it
        try:
            shared = crypto.dh_shared(priv, pub_r)
        except ValueError as e:
            raise HandshakeError(str(e))
        th = crypto.transcript_hash(MAGIC, nonce_i, pub_i, nonce_r, pub_r)
        km = crypto.derive_keys(shared, nonce_i, nonce_r, th)
        sess = crypto.build_session(km, "initiator", **session_kw)

        # Install RX keys first so we can decrypt the responder's confirmation (message 4)
        # before we activate TX; this ensures we never send protected data with unconfirmed keys
        manager.install_rx(sess)
        try:
            # --- Message 3: prove we derived the right keys ---
            sock.sendall(MAGIC + b"\x03" + _mac(km.confirm_key, b"initiator-confirm", th))
            # --- Message 4: verify the responder also derived the right keys ---
            m4 = _recv_exact(sock, M3_LEN)
            _check_hdr(m4, 4)
            if not hmac.compare_digest(m4[5:], _mac(km.confirm_key, b"responder-confirm", th)):
                raise HandshakeError("responder key confirmation failed")
        except BaseException:
            # If anything goes wrong after RX install, clean up so we don't accept garbage
            manager.discard(sess)
            raise
        # Both sides confirmed matching keys; it is now safe to start sending
        manager.activate_tx(sess)
        sock.settimeout(None)
        log.info("session %s established (initiator)", sess.sid)
        return sock, sess
    except BaseException:
        sock.close()
        raise


def _peer_closed(sock: socket.socket) -> bool:
    # Non-blocking peek to detect if the peer has closed the control connection
    try:
        r, _, _ = select.select([sock], [], [], 0)
        if not r:
            return False
        return sock.recv(1, socket.MSG_PEEK) == b""
    except OSError:
        return True


def initiator_loop(manager: crypto.SessionManager, host: str, port: int, psk: bytes,
                   stop: threading.Event, rekey_seconds: float, rekey_packets: int,
                   **session_kw) -> None:
    # Runs in a background thread; continuously maintains a valid session with the responder
    current: Optional[tuple[socket.socket, crypto.Session]] = None
    backoff = 1.0  # exponential back-off on repeated handshake failures
    while not stop.is_set():
        reason = None
        if current is None:
            reason = "initial"
        elif _peer_closed(current[0]):
            # Control connection dropped; retire the session so protected traffic is blocked
            # until a new handshake completes (fail-closed behaviour)
            log.warning("control connection lost - protected traffic blocked until re-handshake")
            manager.retire(current[1])
            current[0].close()
            current, reason = None, "peer closed"
        elif manager.needs_rekey(rekey_seconds, rekey_packets):
            reason = "rekey"
        if reason:
            try:
                new = initiate(host, port, psk, manager, **session_kw)
            except (OSError, HandshakeError) as e:
                log.warning("handshake (%s) failed: %s", reason, e)
                stop.wait(backoff)
                backoff = min(backoff * 2, 10.0)  # cap back-off at 10 seconds
                continue
            backoff = 1.0  # reset back-off after a successful handshake
            if current is not None:
                # Retire the old session gracefully; in-flight packets may still arrive
                manager.retire(current[1])
                current[0].close()
            current = new
        stop.wait(0.5)  # check conditions every 500 ms
    if current is not None:
        manager.retire(current[1])
        current[0].close()


# ------------------------------------------------------------------ responder
def _respond(conn: socket.socket, psk: bytes, manager: crypto.SessionManager,
             **session_kw) -> crypto.Session:
    # --- Message 1: receive the initiator's nonce and DH public key ---
    m1 = _recv_exact(conn, M1_LEN)
    _check_hdr(m1, 1)
    nonce_i = m1[5:5 + NONCE_LEN]
    pub_i = m1[5 + NONCE_LEN:5 + NONCE_LEN + crypto.DH_LEN]
    # Verify the PSK MAC before doing any expensive DH work
    if not hmac.compare_digest(m1[-MAC_LEN:], _mac(psk, b"init", nonce_i, pub_i)):
        raise HandshakeError("initiator authentication failed (PSK mismatch?)")
    try:
        crypto.dh_validate_public(pub_i)
    except ValueError as e:
        raise HandshakeError(str(e))

    # --- Message 2: send our DH public key, authenticated with the PSK ---
    priv, pub_r = crypto.dh_generate()
    nonce_r = os.urandom(NONCE_LEN)
    body2 = nonce_r + pub_r
    # Our MAC covers the full transcript so far (both nonces + both public keys)
    conn.sendall(MAGIC + b"\x02" + body2 + _mac(psk, b"resp", nonce_i, pub_i, nonce_r, pub_r))

    # Derive the shared secret and all keys from the completed DH exchange
    shared = crypto.dh_shared(priv, pub_i)
    th = crypto.transcript_hash(MAGIC, nonce_i, pub_i, nonce_r, pub_r)
    km = crypto.derive_keys(shared, nonce_i, nonce_r, th)

    # --- Message 3: verify the initiator's key confirmation before activating our TX ---
    m3 = _recv_exact(conn, M3_LEN)
    _check_hdr(m3, 3)
    if not hmac.compare_digest(m3[5:], _mac(km.confirm_key, b"initiator-confirm", th)):
        raise HandshakeError("initiator key confirmation failed")

    # Initiator has proven it has the right keys; now install and activate our session
    sess = crypto.build_session(km, "responder", **session_kw)
    manager.install_rx(sess)
    manager.activate_tx(sess)
    # --- Message 4: confirm that we also derived the right keys ---
    conn.sendall(MAGIC + b"\x04" + _mac(km.confirm_key, b"responder-confirm", th))
    log.info("session %s established (responder)", sess.sid)
    return sess


def _serve_conn(conn: socket.socket, psk: bytes, manager: crypto.SessionManager,
                stop: threading.Event, sem: threading.Semaphore, session_kw: dict) -> None:
    sess = None
    try:
        conn.settimeout(5.0)
        try:
            sess = _respond(conn, psk, manager, **session_kw)
        except (OSError, HandshakeError) as e:
            log.warning("handshake rejected: %s", e)
            return
        finally:
            sem.release()  # allow another incoming connection to start its handshake
        # Keep the connection open; the session lives as long as the TCP connection does
        conn.settimeout(1.0)
        while not stop.is_set():          # hold the session for as long as the peer keeps the connection
            try:
                if conn.recv(1) == b"":
                    break
            except socket.timeout:
                continue
            except OSError:
                break
    finally:
        # Always retire the session when the control connection closes
        if sess is not None:
            manager.retire(sess)
            log.info("control connection for session %s closed", sess.sid)
        conn.close()


def serve(manager: crypto.SessionManager, bind: str, port: int, psk: bytes,
          stop: threading.Event, max_pending: int = 16, **session_kw) -> None:
    # Listen for incoming initiator connections; each connection gets its own thread
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(16)
    srv.settimeout(0.5)  # short timeout so we can poll the stop event
    sem = threading.Semaphore(max_pending)  # limit concurrent in-progress handshakes
    log.info("control channel listening on %s:%d", bind, srv.getsockname()[1])
    try:
        while not stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            # Reject new connections if we already have too many handshakes in flight
            if not sem.acquire(blocking=False):
                conn.close()
                continue
            threading.Thread(target=_serve_conn, args=(conn, psk, manager, stop, sem, session_kw),
                             daemon=True).start()
    finally:
        srv.close()
