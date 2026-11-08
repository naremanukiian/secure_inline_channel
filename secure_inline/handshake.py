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

MAGIC = b"SIC1"
NONCE_LEN = 32
MAC_LEN = 32
M1_LEN = 5 + NONCE_LEN + crypto.DH_LEN + MAC_LEN
M2_LEN = M1_LEN
M3_LEN = 5 + MAC_LEN


class HandshakeError(Exception):
    pass


def _mac(key: bytes, label: bytes, *parts: bytes) -> bytes:
    return hmac.new(key, label + b"".join(parts), hashlib.sha256).digest()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise HandshakeError("connection closed during handshake")
        buf += chunk
    return bytes(buf)


def _check_hdr(msg: bytes, typ: int) -> None:
    if msg[:4] != MAGIC or msg[4] != typ:
        raise HandshakeError(f"unexpected message (wanted type {typ})")


# ------------------------------------------------------------------ initiator
def initiate(host: str, port: int, psk: bytes, manager: crypto.SessionManager,
             timeout: float = 5.0, **session_kw) -> tuple[socket.socket, crypto.Session]:
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        priv, pub_i = crypto.dh_generate()
        nonce_i = os.urandom(NONCE_LEN)
        body1 = nonce_i + pub_i
        sock.sendall(MAGIC + b"\x01" + body1 + _mac(psk, b"init", body1))

        m2 = _recv_exact(sock, M2_LEN)
        _check_hdr(m2, 2)
        nonce_r = m2[5:5 + NONCE_LEN]
        pub_r = m2[5 + NONCE_LEN:5 + NONCE_LEN + crypto.DH_LEN]
        mac_r = m2[-MAC_LEN:]
        if not hmac.compare_digest(mac_r, _mac(psk, b"resp", nonce_i, pub_i, nonce_r, pub_r)):
            raise HandshakeError("responder authentication failed (PSK mismatch?)")

        try:
            shared = crypto.dh_shared(priv, pub_r)
        except ValueError as e:
            raise HandshakeError(str(e))
        th = crypto.transcript_hash(MAGIC, nonce_i, pub_i, nonce_r, pub_r)
        km = crypto.derive_keys(shared, nonce_i, nonce_r, th)
        sess = crypto.build_session(km, "initiator", **session_kw)

        manager.install_rx(sess)         # be ready to receive before we confirm
        try:
            sock.sendall(MAGIC + b"\x03" + _mac(km.confirm_key, b"initiator-confirm", th))
            m4 = _recv_exact(sock, M3_LEN)
            _check_hdr(m4, 4)
            if not hmac.compare_digest(m4[5:], _mac(km.confirm_key, b"responder-confirm", th)):
                raise HandshakeError("responder key confirmation failed")
        except BaseException:
            manager.discard(sess)
            raise
        manager.activate_tx(sess)
        sock.settimeout(None)
        log.info("session %s established (initiator)", sess.sid)
        return sock, sess
    except BaseException:
        sock.close()
        raise


def _peer_closed(sock: socket.socket) -> bool:
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
    current: Optional[tuple[socket.socket, crypto.Session]] = None
    backoff = 1.0
    while not stop.is_set():
        reason = None
        if current is None:
            reason = "initial"
        elif _peer_closed(current[0]):
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
                backoff = min(backoff * 2, 10.0)
                continue
            backoff = 1.0
            if current is not None:
                manager.retire(current[1])
                current[0].close()
            current = new
        stop.wait(0.5)
    if current is not None:
        manager.retire(current[1])
        current[0].close()


# ------------------------------------------------------------------ responder
def _respond(conn: socket.socket, psk: bytes, manager: crypto.SessionManager,
             **session_kw) -> crypto.Session:
    m1 = _recv_exact(conn, M1_LEN)
    _check_hdr(m1, 1)
    nonce_i = m1[5:5 + NONCE_LEN]
    pub_i = m1[5 + NONCE_LEN:5 + NONCE_LEN + crypto.DH_LEN]
    if not hmac.compare_digest(m1[-MAC_LEN:], _mac(psk, b"init", nonce_i, pub_i)):
        raise HandshakeError("initiator authentication failed (PSK mismatch?)")
    try:
        crypto.dh_validate_public(pub_i)
    except ValueError as e:
        raise HandshakeError(str(e))

    priv, pub_r = crypto.dh_generate()
    nonce_r = os.urandom(NONCE_LEN)
    body2 = nonce_r + pub_r
    conn.sendall(MAGIC + b"\x02" + body2 + _mac(psk, b"resp", nonce_i, pub_i, nonce_r, pub_r))

    shared = crypto.dh_shared(priv, pub_i)
    th = crypto.transcript_hash(MAGIC, nonce_i, pub_i, nonce_r, pub_r)
    km = crypto.derive_keys(shared, nonce_i, nonce_r, th)

    m3 = _recv_exact(conn, M3_LEN)
    _check_hdr(m3, 3)
    if not hmac.compare_digest(m3[5:], _mac(km.confirm_key, b"initiator-confirm", th)):
        raise HandshakeError("initiator key confirmation failed")

    sess = crypto.build_session(km, "responder", **session_kw)
    manager.install_rx(sess)
    manager.activate_tx(sess)
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
            sem.release()
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
        if sess is not None:
            manager.retire(sess)
            log.info("control connection for session %s closed", sess.sid)
        conn.close()


def serve(manager: crypto.SessionManager, bind: str, port: int, psk: bytes,
          stop: threading.Event, max_pending: int = 16, **session_kw) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(16)
    srv.settimeout(0.5)
    sem = threading.Semaphore(max_pending)
    log.info("control channel listening on %s:%d", bind, srv.getsockname()[1])
    try:
        while not stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            if not sem.acquire(blocking=False):
                conn.close()
                continue
            threading.Thread(target=_serve_conn, args=(conn, psk, manager, stop, sem, session_kw),
                             daemon=True).start()
    finally:
        srv.close()
