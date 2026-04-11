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

## What Makes City of Hats Different

Most secure messengers still require a phone number or email to create an account. That single requirement creates a permanent link between your real identity and every conversation you have.

City of Hats replaces this with **Hat IDs** — cryptographic identities that exist independently of any personal identifier. This enables:

- **Anonymous yet persistent identities** — You can maintain a reputation without revealing who you are
- **Context-specific identities** — Use a different Hat for work, personal, investigative, or temporary conversations. No correlation between them.
- **No phone number, no email, no identity graph** — There is nothing to subpoena that links a Hat to a person

In addition, City of Hats integrates **sender-enforced security controls** directly into the encryption layer. Message lifecycle policies — expiration, recall, view-once, burn-after-read — are not UI features bolted on top. They are enforced at the protocol level, inside the encrypted payload, before the server ever sees the message.

This is not a Signal clone with a different logo. The identity model is fundamentally different.

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

## Metadata Considerations

"We encrypt your messages" is not enough. Metadata — who talks to whom, when, how often, from where — can be as revealing as content. City of Hats is designed to minimize metadata exposure:

- **No phone numbers or emails** — Hat IDs are the only identifier. There is no mapping from Hat to real-world identity on our servers.
- **No plaintext content stored** — The server relays ciphertext. For E2E channels, we cannot decrypt it even if compelled.
- **No persistent IP logging in the app** — IP addresses are hashed for rate limiting and discarded. We do not maintain IP-to-Hat association logs.
- **Encrypted headers** — DH ratchet public keys and message counters are encrypted, not visible to the server in transit.
- **Metadata padding** — Message lengths are padded to fixed buckets so ciphertext size does not reveal content length.

**What we are honest about:**
- The server does see Hat codes, pair/group IDs, timestamps, and delivery status — this is required to route messages.
- Push notification tokens are stored to deliver notifications.
- We are working toward reducing even these operational metadata points.

Full details: [cityofhats.com/transparency](https://cityofhats.com/transparency)

---

## Threat Model

City of Hats is designed to protect against:

- **Passive network surveillance** — All traffic is E2E encrypted. An observer on the network sees only ciphertext with encrypted headers.
- **Server compromise** — For E2E channels, the server holds no decryption keys. A complete database breach yields only opaque ciphertext, public keys, and routing metadata.
- **Identity correlation** — No phone number or email is required. Hat IDs are not linked to real-world identity on our infrastructure.
- **Message content analysis** — Metadata padding prevents length-based analysis. Sealed sender prevents server-side attribution tampering.
- **Future quantum attacks** — Hybrid X25519 + ML-KEM-768 key exchange provides post-quantum resistance today.
- **Key compromise (forward secrecy)** — Double Ratchet ensures that compromising current keys does not expose past messages. Each message uses a unique derived key that is discarded after use.

**What we do not yet claim to protect against:**

- **Advanced nation-state endpoint compromise** — If your device is compromised at the OS level, encryption cannot help. This is true of every messaging app.
- **Traffic analysis at scale** — While we pad message lengths and encrypt headers, sophisticated traffic analysis (timing, frequency, volume patterns) is an open research problem that no messenger has fully solved.
- **Formal verification** — Our protocol has not yet undergone formal mathematical verification or a completed third-party audit. This is planned.

We believe stating limitations clearly is more credible than claiming invulnerability.

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

## License

This repository is licensed under the [MIT License](LICENSE).

---

## Disclaimer

This document provides an overview of the cryptographic design and includes production source code. Implementation details may evolve as the platform matures and undergoes formal review.

---

City of Hats is actively evolving toward greater transparency and external validation. We welcome review, feedback, and discussion from the security community.

📧 admin@cityofhats.com

**City of Hats Inc.** · Toronto, Canada  
Private communication. In your control.
