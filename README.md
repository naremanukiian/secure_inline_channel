# secure-inline-channel

Linux prototype of a transparent, inline, authenticated-encrypted channel between two devices:

```
PC1 ──► Device1 ══════════════════════► Device2 ──► PC2
 plain   encrypt TCP payload (AES-GCM)    verify + decrypt    plain
```

Protected TCP/IPv4 packets stay ordinary IP/TCP packets between the devices: **no UDP encapsulation and no custom
header**. Only the TCP payload is encrypted; the 16-byte GCM tag is appended to it.

```
 original :  [ IPv4 hdr ][ TCP hdr ][ payload            ]
 on wire  :  [ IPv4 hdr ][ TCP hdr ][ ciphertext ][ tag16 ]      (len/checksums recomputed)
 restored :  [ IPv4 hdr ][ TCP hdr ][ payload            ]      (byte-identical to the original)
```

## How it works

| Requirement | Implementation |
|---|---|
| Select traffic | `policy.py`: ports (`--port`) and optional address ranges (`--net-a/--net-b`). iptables sends candidate packets to NFQUEUE; the Python policy makes the final decision. Both devices must use the same policy. |
| Secure session before data | `handshake.py`: Device1 (initiator) dials Device2 (responder) on a separate TCP control port. Until a session exists, protected packets are **dropped** (fail closed); TCP retransmits once the session is up. |
| Diffie–Hellman | RFC 3526 group 14 (2048-bit, safe prime), 512-bit random exponents, peer public values validated (range + subgroup). Keys via HKDF-SHA256 over the DH secret, both nonces and the transcript: one AES-256 key + nonce prefix **per direction**. |
| Handshake authentication | Both DH messages are HMAC'd with a pre-shared key (stops an active MITM), followed by explicit key-confirmation messages. TX keys are activated only after the peer proves it has the same keys. |
| Encrypt only the payload | `datapath.py`: AES-256-GCM over the TCP payload; tag appended. IP/TCP headers untouched except IPv4 total length, IP checksum and TCP checksum. |
| Header authentication | Immutable header fields (src/dst IP, ports, seq, ack, flags) are GCM associated data, so header tampering/splicing fails verification. TTL, ToS, IP-ID, window and urgent pointer are excluded (they may legitimately change). |
| Receiver | Verifies tag → decrypts → restores the payload → restores total length → recomputes IP and TCP checksums → forwards. Any failure ⇒ packet dropped. |
| **Unique nonce per packet** | `nonce = 4-byte HKDF prefix ‖ 64-bit counter`. The sender consumes one counter value per encryption under a lock; values are never reused (even when the packet is dropped later, and TCP retransmissions are new packets with new nonces). Per-direction keys, fresh keys per session, hard cap of 2³² packets per key (fail closed), automatic rekey well before (default 2²⁸ packets / 10 min). |

### Nonce without a header
The wire format has no room for a counter, so the receiver derives it: it tries the expected counter first,
then up to `--fwd-window` (default 1024) counters ahead (packets lost between devices) and `--back-window`
(default 128) not-yet-seen counters behind (reordering). A bitmap rejects replays. In the normal in-order case
this costs one decryption per packet.

### Rekeying
Device1 re-runs the handshake every `--rekey-seconds` / `--rekey-packets`. The receiver keeps the previous
session for 30 s, so in-flight packets are still accepted. If the control connection drops (e.g. Device2
restarts) the sender stops encrypting and protected traffic is blocked until a new handshake succeeds.

## Requirements

Linux with root, `iptables` (NFQUEUE, TCPMSS, CT), `ethtool`, Python ≥ 3.9.

```bash
sudo apt install python3-cryptography python3-netfilterqueue iptables ethtool iproute2
# or: pip install -r requirements.txt   (NetfilterQueue needs libnetfilter-queue-dev)
```

## Quick start: one-machine lab (network namespaces)

```bash
sudo scripts/demo_netns.sh up      # pc1 ─ dev1 ─ dev2 ─ pc2, starts both devices, waits for the handshake
sudo scripts/demo_netns.sh test    # 2 MB up + 0.5 MB down, SHA-256 checked, sniffs the dev1↔dev2 link
sudo scripts/demo_netns.sh down
```
`test` reports PASS when the data arrives intact and the marker string is never visible in any TCP segment on the
Device1–Device2 link. Logs: `/tmp/secure-inline-demo/*.log`.

## Real deployment (two Linux boxes)

```bash
# once: shared secret, copy it to both devices (mode 600)
python3 -c 'import os;print(os.urandom(32).hex())' > psk

# Device2 (responder) – eth_pc2 faces PC2, eth_peer faces Device1
sudo scripts/setup_device.sh up eth_pc2 eth_peer 5001
sudo python3 -m secure_inline.device --role responder --listen <dev2-ip-towards-dev1> --psk-file psk --port 5001

# Device1 (initiator) – eth_pc1 faces PC1, eth_peer faces Device2
sudo scripts/setup_device.sh up eth_pc1 eth_peer 5001
sudo python3 -m secure_inline.device --role initiator --peer <dev2-ip> --psk-file psk --port 5001
```
Both devices need IP forwarding and routes so that PC1↔PC2 traffic traverses Device1 and Device2.
`scripts/setup_device.sh down ...` removes the rules. Useful flags: `--net-a/--net-b` (CIDRs), `--no-verify-checksums`
(if NIC offload leaves partial checksums), `--fwd-window`, `-v`.

`setup_device.sh` also: disables GRO/GSO/TSO (1 packet = 1 AES-GCM record), clamps MSS by 16 bytes (the tag must
fit in the MTU), drops non-first IP fragments (they carry no TCP header and could not be protected), and excludes
the protected flows from conntrack.

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
```
Covers checksum correctness, byte-exact round trips in both directions, header preservation, tamper/header-splice
detection, replay/reordering/loss windows, nonce uniqueness (incl. 8 concurrent threads and retransmitted plaintext),
fail-closed behavior without a session or after exhaustion, and the full DH handshake + rekey over loopback.
The NFQUEUE/netfilter part is exercised by `scripts/demo_netns.sh`, which needs root and cannot run in CI.

## Limitations (prototype)

* **Confidentiality/integrity cover TCP payload and the listed header fields only.** Payload-less packets (SYN, pure
  ACK, FIN, RST) are forwarded unprotected, so RST/FIN injection between the devices is possible; window, urgent
  pointer, TTL, options and IP-ID are not authenticated. Packet sizes and timing are visible.
* The handshake is authenticated with a **pre-shared key**: either device can impersonate the other, and a leaked PSK
  allows active MITM of *future* handshakes (past sessions stay safe thanks to DH). Certificates/signatures would be the next step.
* Sequence/ack numbers stay in clear and unchanged, so PC1 and PC2 see a normal TCP connection.
* The implicit nonce means bogus packets cost up to `fwd+back` failed decryptions (DoS amplification), and a loss
  burst longer than `--fwd-window` desynchronizes the counter until the next rekey (restart the initiator to force one).
* IPv4/TCP only; fragmented TCP is dropped; no IPv6. Selected flows are not NAT-friendly (addresses are authenticated).
* Python + NFQUEUE is meant for functionality, not throughput.
* Not audited. Do not use to protect real secrets without a security review.
