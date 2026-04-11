# City of Hats – Cryptographic Architecture

> Secure messaging and cyber intelligence platform  
> Identity-based communication without phone numbers or emails

---

## Overview

City of Hats is a next-generation secure communication platform designed to provide private, identity-based messaging without relying on traditional identifiers such as phone numbers or email addresses.

This repository contains the **cryptographic architecture documentation, formal protocol specification, and production source code** for the encryption layer used to secure messaging, voice, and data exchange within the platform.

📄 **[Read the full Protocol Specification →](PROTOCOL.md)**

---

## Source Code

The [`PROTOCOL.md`](PROTOCOL.md) document provides a complete protocol specification covering key exchange flows, Double Ratchet parameters, hybrid post-quantum integration, group sender key distribution, sealed payload format, wire formats, and all cryptographic primitives used.

The `src/` directory contains the actual production cryptographic implementation:

| File | Description |
|------|-------------|
| [`src/crypto.ts`](src/crypto.ts) | Core E2E encryption — X25519 + ML-KEM-768 hybrid key exchange, Double Ratchet with header encryption, AES-256-GCM, HKDF key derivation, metadata padding, safety numbers, steganography (LSB), time-locked encryption, PIN-based key wrapping (PBKDF2), tamper-evident audit log chain, and key rotation alerts. |
| [`src/groupCrypto.ts`](src/groupCrypto.ts) | Group chat Sender Keys protocol — HMAC chain ratchet, AES-256-GCM encryption, ECDSA P-256 sender signature verification. |

These are the same modules running in the production application (API URLs sanitized).

---

## Design Principles

City of Hats is built around the following core principles:

- **End-to-End Encryption by Default**  
  All messages and calls are encrypted such that only communicating parties can access the content.

- **Identity Abstraction**  
  Users communicate via "Hat IDs", removing dependency on phone numbers or emails.

- **Forward Secrecy**  
  Compromise of long-term keys does not expose past communications.

- **Post-Quantum Readiness**  
  Hybrid key exchange mechanisms are used to prepare for future cryptographic threats.

- **Minimal Data Exposure**  
  System design minimizes metadata generation and storage wherever possible.

---

## Cryptographic Stack

### Key Exchange (1:1 Chat)

City of Hats uses a **hybrid key exchange model** combining:

- `X25519` (Elliptic Curve Diffie-Hellman) with automatic `P-256` fallback
- `ML-KEM-768 (Kyber)` (Post-Quantum Key Encapsulation)

Both shared secrets are concatenated and fed through HKDF to produce a hybrid root key, providing:
- Strong classical security
- Resistance against future quantum attacks

### Message Encryption

- **AES-256-GCM** — Authenticated encryption ensuring confidentiality and integrity
- **12-byte random IV** per message
- **Metadata padding** — Plaintext is padded to fixed-size buckets (64–4096 bytes) so ciphertext length does not reveal message length

### Session Protocol (1:1 Chat)

City of Hats uses a **Double Ratchet protocol** (Signal specification family), providing:

- Forward secrecy
- Break-in recovery
- Per-message key evolution
- **Encrypted headers** — DH ratchet public keys and message counters are encrypted with a separate header key, preventing metadata leakage

Key derivation functions:
- **KDF_RK**: HKDF-SHA-256 deriving root key + chain key + header key (96 bytes)
- **KDF_CK**: HMAC-SHA-256 deriving message key + next chain key
- **Max skip**: 200 messages (out-of-order tolerance)

### Group Encryption (Sender Keys)

Group chat uses a **Sender Keys protocol**:

- Each member generates a sender key (32-byte chain key + ECDSA P-256 signing key pair)
- Sender keys are distributed to group members encrypted via existing 1:1 channels
- Messages are encrypted once with the sender's chain key (HMAC ratchet → AES-256-GCM)
- Each message is signed with ECDSA P-256 for sender verification
- Chain ratchets forward after each message for forward secrecy

### Key Verification

- **Safety Numbers** — 30-digit codes (6 groups of 5) derived from double SHA-256 hash of both parties' sorted public keys. Users can compare out-of-band to verify no MITM attack.
- **Key Change Alerts** — Peer public key changes are detected and flagged to the user.

### Additional Cryptographic Features

- **Sealed Sender** — Sender identity is included inside the encrypted payload, preventing server-side attribution tampering
- **Steganography** — LSB encoding to embed ciphertext inside PNG images
- **Time-Locked Encryption** — Decryption key derived from URL key + server-held fragment via HKDF
- **XOR Secret Splitting** — Split ciphertext into two shares for multi-path delivery
- **EchoDrop** — Passphrase-derived encryption using PBKDF2 (600,000 iterations)

### Local Key Protection

- **PIN Protection** — PBKDF2 (SHA-256, 600,000 iterations) derives an AES-256-GCM key from a user PIN
- All sensitive localStorage keys are wrapped with the PIN-derived key
- Derived key is cached in sessionStorage (one unlock per browser session)

### Audit Trail

- **Tamper-Evident Audit Log** — Local hash chain (SHA-256) recording all cryptographic operations
- Each entry chains to the previous via its hash, making tampering detectable
- Users can verify chain integrity at any time

---

## Identity Model (Hat System)

Instead of traditional accounts:

- Users create **Hat IDs**
- Hats can be:
  - Disposable (temporary)
  - Persistent (long-term identity)
  - Context-specific (per conversation or use case)

This reduces:
- Identity correlation
- Centralized user tracking

---

## Message Security Features

The platform supports advanced sender-controlled protections:

- View-once messages
- Burn-after-read messages
- Time-based expiration
- Message recall
- Sealed (PIN-protected) files

These features operate on top of the encrypted transport layer.

---

## Architecture Notes

- Messages are encrypted **client-side before transmission**
- Servers act as **relay infrastructure only**
- No plaintext message content is stored on servers
- Double Ratchet state is backed up to the server **encrypted with a key derived from the user's private key** — the server stores only opaque ciphertext

For detailed information on what the server can and cannot see, visit our [Transparency Page](https://cityofhats.com/transparency).

---

## Transparency Status

City of Hats is currently:

- ✅ Cryptographic source code published (this repository)
- ✅ Architecture documentation published (this repository)
- ✅ Formal protocol specification published ([PROTOCOL.md](PROTOCOL.md))
- ✅ Privacy & logging transparency page published ([cityofhats.com/transparency](https://cityofhats.com/transparency))
- ✅ MIT licensed for maximum openness
- 🔒 Closed-source (core platform, non-crypto components)
- 🧪 Preparing for independent security review

Planned next steps:

- Conduct third-party security audit
- Expand open-source scope

---

## Scope of This Repository

This repository includes:

- Formal protocol specification ([`PROTOCOL.md`](PROTOCOL.md))
- Production cryptographic source code ([`src/`](src/))
- High-level architecture overview (this README)

It does **not** include:

- Backend infrastructure implementation
- Frontend UI components
- Proprietary intelligence systems

---

## Contact

📧 admin@cityofhats.com

---

## Disclaimer

This document provides an overview of the cryptographic design and includes production source code.  
Implementation details may evolve as the platform matures and undergoes formal review.

---

## License

This repository is licensed under the [MIT License](LICENSE).

---

**City of Hats**  
Private communication. In your control.
