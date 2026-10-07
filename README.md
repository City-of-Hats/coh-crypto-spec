# City of Hats – Cryptographic Architecture

> Public cryptographic source and protocol documentation for City of Hats.
> Independent review is our next priority.

City of Hats is a communication platform built around **Hat IDs**: identities for different contexts, without using a phone number or email as the messaging identity. This repository publishes two cryptographic modules and their protocol documentation under the MIT license.

## Current Status · October 2026

We are seeking sponsorship to support open-source maintenance and fund an **independent security audit**. The proposed review scope and preparation checklist are in [AUDIT.md](AUDIT.md).

| Item | Status |
|------|--------|
| Public cryptographic modules | Published under MIT; April 2026 source snapshot |
| Documentation | Updated October 7, 2026 with audit preparation and clearer scope |
| Independent security audit | Not completed; seeking funding |
| Auditor, agreed scope, budget and schedule | Not announced |
| Current application/source correspondence | Not verified by this documentation update |

**[Sponsor the open-source work and audit →](https://support.cityofhats.com)**

[Protocol specification](PROTOCOL.md) · [Proposed audit scope](AUDIT.md) · [Report a vulnerability](SECURITY.md) · [Contribute](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## Why an Independent Audit Matters

“How do I know my messages aren't being copied to the FBI—or anyone else?”

Think of an encrypted message as a locked parcel. A delivery service can carry the parcel without having the key. But that promise depends on the locks working, the keys staying with the right people, and the application not making another readable copy before locking the parcel.

An independent auditor checks the code and how the application uses it: how keys are created and stored, who can decrypt a message, and whether logs, backups or other paths could expose readable content. Publishing code lets people inspect it; a funded audit gives experienced reviewers dedicated time to investigate and report their findings.

An audit provides evidence about a **specific version and agreed scope**. It cannot guarantee that a service will always be secure, rule out every possible attack, or protect messages on an already compromised device. We have not completed an independent audit and do not present this repository as proof that the whole service is secure.

## What Is Published

| File | Contents |
|------|----------|
| [src/crypto.ts](src/crypto.ts) | Classical and hybrid key exchange, Double Ratchet with header encryption, AES-GCM helpers, padding, safety numbers, optional PIN storage helpers, encrypted state backup helpers, and additional cryptographic utilities |
| [src/groupCrypto.ts](src/groupCrypto.ts) | Group Sender Keys: HMAC chain ratchet, AES-GCM message encryption and ECDSA P-256 sender signatures |
| [PROTOCOL.md](PROTOCOL.md) | Version 1.0 description of the published design, with an October documentation status update |

The modules were published on April 11, 2026, with API URLs sanitized. Their original publication commit is [`40b03a5`](https://github.com/City-of-Hats/coh-crypto-spec/commit/40b03a5ded6db3571bcc0eb2ddec6682a9bbb891). This update leaves those source files unchanged. It does not establish that they match the current browser, Android or iOS application.

This is a **partial source publication**, not the complete City of Hats application. Backend infrastructure, frontend integration, native clients and call/media integration are not included. The repository also has no standalone package manifest, dependency lockfile or automated test suite. Those are preparation gaps to address before a reproducible audit; see [AUDIT.md](AUDIT.md#preparation-before-the-audit).

## Cryptographic Design in the Published Snapshot

### One-to-One Messaging

- **Classical key agreement:** X25519, with a P-256 fallback.
- **Hybrid key agreement:** ML-KEM-768 shared secret combined with the classical secret through HKDF. Peers without a post-quantum public key use classical-only agreement; hybrid protection is conditional on its use and correct integration.
- **Message encryption:** AES-256-GCM with a 12-byte random IV.
- **Session evolution:** Double Ratchet with HKDF-SHA-256 root derivation and HMAC-SHA-256 chain derivation; maximum skipped-message allowance of 200.
- **Header encryption:** Separate keys encrypt ratchet public keys and message counters. This does not hide all routing metadata.
- **Padding:** Buckets of 64–4096 bytes, with larger payloads rounded to a multiple of 4096. Padding reduces length precision; it does not eliminate length or traffic analysis.
- **Key verification:** 30-digit safety numbers and peer key-change detection helpers. Effective verification depends on application behavior and users comparing numbers through a trusted channel.

The design aims to provide forward secrecy and recovery after some key compromises. The guarantees depend on correct session establishment, state persistence, key deletion and integration, which need review alongside the algorithms.

### Group Messaging

Each sender uses a 32-byte chain key and an ECDSA P-256 signing key pair. Messages use an HMAC-derived AES-GCM key and a sender signature. Sender key distribution is described through existing one-to-one channels. Membership changes, key rotation and application-level authorization need review beyond these two files.

### Storage and Additional Utilities

The snapshot includes PIN-derived storage helpers using PBKDF2-SHA-256 (600,000 iterations), encrypted state backup helpers, a local hash-chain log, passphrase-based encryption, time-lock key derivation, LSB steganography and XOR splitting.

**Local storage needs particular review:** optional `secureSet`/`secureGet` helpers coexist with persistence functions that directly write keys and state to `localStorage`. The PIN-derived key is cached in `sessionStorage`. These files alone do not demonstrate that all sensitive data is protected at rest, and a hash-chain log is not an independent security audit.

## Privacy Goals and Limits

Hat IDs allow separate identities for different contexts. They do not guarantee anonymity or prevent correlation through network activity, infrastructure records, device compromise or information a user shares.

For an end-to-end encrypted message, the intended design is that the relay carries ciphertext while the endpoints hold the decryption keys. Confirming this across the deployed system requires review of clients, servers, logs, backups and key distribution. The published modules alone cannot establish server logging practices or the security of voice and video calls.

Operational metadata may include Hat codes, pair/group identifiers, timestamps, delivery status and push notification tokens. Encrypted headers and padding do not hide all of it. Infrastructure privacy statements are described separately on the [transparency page](https://cityofhats.com/transparency); they have not been independently validated by this repository update.

Message expiration, recall and view-once controls depend on recipient application behavior. They cannot prevent a recipient from photographing, recording or copying content after decryption.

## Review and Help

Security researchers can start with the [protocol](PROTOCOL.md) and [audit questions](AUDIT.md). Use [GitHub issues](https://github.com/City-of-Hats/coh-crypto-spec/issues) for public documentation questions. For a suspected vulnerability, follow [SECURITY.md](SECURITY.md) and contact us privately before posting exploit details.

Sponsorship supports the open-source work and planned independent review. No completed audit, booked auditor or security certification is implied by contributing. [Support the work](https://support.cityofhats.com), or contact [admin@cityofhats.com](mailto:admin@cityofhats.com) about audit proposals and sponsorship.

## License

The published files are licensed under the [MIT License](LICENSE). This license applies to this repository, not unpublished platform components.

**City of Hats Inc.** · Toronto, Canada
