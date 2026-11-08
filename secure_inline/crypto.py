"""Key agreement (finite-field Diffie-Hellman), key schedule, AES-GCM state.

Nonce construction (96 bits, per direction, per session)
--------------------------------------------------------
    nonce = prefix(4 bytes, from HKDF) || counter(8 bytes, big endian)

* Every direction of every session has its own AES key, so (key, nonce) pairs
  can never collide across directions or sessions.
* The sender increments the counter for EVERY packet it encrypts, under a lock,
  and never reuses or rewinds it - TCP retransmissions are simply new packets
  and therefore get fresh nonces.
* No header carries the counter (the packet format must stay plain IP/TCP), so
  the receiver recovers it by trial decryption inside a sliding window and
  rejects counters it has already accepted (replay protection).
"""
from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TAG_LEN = 16
NONCE_PREFIX_LEN = 4
HARD_PACKET_LIMIT = 2 ** 32       # absolute cap of packets per key/direction

# ----------------------------------------------------------- DH (RFC 3526 #14)
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_G = 2
DH_Q = (DH_P - 1) // 2
DH_LEN = 256                      # bytes of a group-14 public value


# Plain modular arithmetic is used (instead of a library FFDH API, which
# `cryptography` has deprecated). Exponents are 512-bit random values, i.e.
# well above the ~224-bit exponent size recommended for a 2048-bit group.
def dh_generate() -> tuple[int, bytes]:
    while True:
        x = secrets.randbits(512)
        if x > 1:
            break
    return x, pow(DH_G, x, DH_P).to_bytes(DH_LEN, "big")


def dh_validate_public(pub: bytes) -> int:
    """Reject small-subgroup / out-of-range values (P is a safe prime)."""
    if len(pub) != DH_LEN:
        raise ValueError("bad DH public length")
    y = int.from_bytes(pub, "big")
    if not (2 <= y <= DH_P - 2) or pow(y, DH_Q, DH_P) != 1:
        raise ValueError("invalid DH public value")
    return y


def dh_shared(priv: int, peer_pub: bytes) -> bytes:
    y = dh_validate_public(peer_pub)
    return pow(y, priv, DH_P).to_bytes(DH_LEN, "big")


# --------------------------------------------------------------- key schedule
@dataclass
class KeyMaterial:
    key_i2r: bytes
    key_r2i: bytes
    prefix_i2r: bytes
    prefix_r2i: bytes
    confirm_key: bytes
    transcript_hash: bytes


def derive_keys(shared: bytes, nonce_i: bytes, nonce_r: bytes, transcript_hash: bytes) -> KeyMaterial:
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=32 + 32 + NONCE_PREFIX_LEN * 2 + 32,
        salt=nonce_i + nonce_r,
        info=b"secure-inline v1 key schedule" + transcript_hash,
    ).derive(shared)
    p = NONCE_PREFIX_LEN
    return KeyMaterial(
        key_i2r=okm[0:32],
        key_r2i=okm[32:64],
        prefix_i2r=okm[64:64 + p],
        prefix_r2i=okm[64 + p:64 + 2 * p],
        confirm_key=okm[64 + 2 * p:],
        transcript_hash=transcript_hash,
    )


# ------------------------------------------------------------- AES-GCM states
class SessionExhausted(Exception):
    """The per-key packet limit was reached; a new session is required."""


class TxState:
    """Sender side: unique nonce per encrypted packet."""

    def __init__(self, key: bytes, prefix: bytes, max_packets: int = HARD_PACKET_LIMIT):
        self._aead = AESGCM(key)
        self._prefix = prefix
        self._ctr = 0
        self._lock = threading.Lock()
        self.max_packets = min(max_packets, HARD_PACKET_LIMIT)

    @property
    def counter(self) -> int:
        return self._ctr

    def reserve_nonce(self) -> bytes:
        """Atomically consume one counter value. A value is never handed out twice,
        even if the packet it was reserved for is dropped afterwards."""
        with self._lock:
            if self._ctr >= self.max_packets:
                raise SessionExhausted
            c = self._ctr
            self._ctr += 1
        return self._prefix + c.to_bytes(8, "big")

    def encrypt(self, plaintext: bytes, aad: bytes) -> bytes:
        """Returns ciphertext || 16-byte tag."""
        return self._aead.encrypt(self.reserve_nonce(), plaintext, aad)


class RxState:
    """Receiver side: recover the implicit counter by windowed trial decryption
    and enforce replay protection."""

    def __init__(self, key: bytes, prefix: bytes, fwd_window: int = 1024, back_window: int = 128):
        self._aead = AESGCM(key)
        self._prefix = prefix
        self.fwd = fwd_window
        self.back = back_window
        self._next = 0          # highest accepted counter + 1
        self._mask = 0          # bit i <=> counter (_next - 1 - i) already accepted
        self._lock = threading.Lock()

    def _candidates(self):
        with self._lock:
            n, mask = self._next, self._mask
        yield from range(n, n + self.fwd)                    # in-order / after loss
        for i in range(self.back):                           # reordered, not yet seen
            c = n - 1 - i
            if c < 0:
                break
            if not (mask >> i) & 1:
                yield c

    def _accept(self, c: int) -> bool:
        with self._lock:
            n = self._next
            if c >= n:
                shift = c + 1 - n
                self._mask = ((self._mask << shift) | 1) & ((1 << self.back) - 1)
                self._next = c + 1
                return True
            i = n - 1 - c
            if i >= self.back or (self._mask >> i) & 1:
                return False                                  # replay / too old
            self._mask |= 1 << i
            return True

    def decrypt(self, data: bytes, aad: bytes) -> Optional[bytes]:
        """`data` = ciphertext || tag. Returns plaintext or None (auth failure)."""
        for c in self._candidates():
            try:
                pt = self._aead.decrypt(self._prefix + c.to_bytes(8, "big"), data, aad)
            except InvalidTag:
                continue
            return pt if self._accept(c) else None
        return None


# ------------------------------------------------------------------- sessions
@dataclass
class Session:
    sid: str
    tx: TxState
    rx: RxState
    created: float = field(default_factory=time.monotonic)
    retired_at: Optional[float] = None


def build_session(km: KeyMaterial, role: str, max_packets: int = HARD_PACKET_LIMIT,
                  fwd_window: int = 1024, back_window: int = 128) -> Session:
    if role == "initiator":
        tx_key, tx_pre, rx_key, rx_pre = km.key_i2r, km.prefix_i2r, km.key_r2i, km.prefix_r2i
    elif role == "responder":
        tx_key, tx_pre, rx_key, rx_pre = km.key_r2i, km.prefix_r2i, km.key_i2r, km.prefix_i2r
    else:
        raise ValueError(role)
    return Session(
        sid=km.transcript_hash[:4].hex(),
        tx=TxState(tx_key, tx_pre, max_packets),
        rx=RxState(rx_key, rx_pre, fwd_window, back_window),
    )


class SessionManager:
    """Holds the active TX session and the (newest-first) RX sessions.

    Protected traffic is dropped while no TX session exists (fail closed)."""

    def __init__(self, grace: float = 30.0):
        self._lock = threading.RLock()
        self._tx: Optional[Session] = None
        self._rx: list[Session] = []
        self.grace = grace

    def install_rx(self, s: Session) -> None:
        with self._lock:
            self._rx.insert(0, s)

    def activate_tx(self, s: Session) -> None:
        with self._lock:
            now = time.monotonic()
            for o in self._rx:
                if o is not s and o.retired_at is None:
                    o.retired_at = now
            self._tx = s

    def discard(self, s: Session) -> None:
        with self._lock:
            if s in self._rx:
                self._rx.remove(s)
            if self._tx is s:
                self._tx = None

    def retire(self, s: Session) -> None:
        """Stop sending with `s`; keep accepting it for `grace` seconds."""
        with self._lock:
            if s.retired_at is None:
                s.retired_at = time.monotonic()
            if self._tx is s:
                self._tx = None

    def current_tx(self) -> Optional[Session]:
        with self._lock:
            return self._tx

    def rx_sessions(self) -> list[Session]:
        with self._lock:
            now = time.monotonic()
            self._rx = [s for s in self._rx if s.retired_at is None or now - s.retired_at <= self.grace]
            return list(self._rx)

    def needs_rekey(self, max_age: float, max_packets: int) -> bool:
        with self._lock:
            s = self._tx
            if s is None:
                return True
            return time.monotonic() - s.created >= max_age or s.tx.counter >= max_packets


def transcript_hash(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()
