# City of Hats – Cryptographic Architecture

> Secure messaging and cyber intelligence platform  
> Identity-based communication without phone numbers or emails

---

## Overview

City of Hats is a next-generation secure communication platform designed to provide private, identity-based messaging without relying on traditional identifiers such as phone numbers or email addresses.

This repository outlines the **cryptographic architecture and protocol design** used to secure messaging, voice, and data exchange within the platform.

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

### Key Exchange

City of Hats uses a **hybrid key exchange model** combining:

- `X25519` (Elliptic Curve Diffie-Hellman)
- `ML-KEM-768 (Kyber)` (Post-Quantum Key Encapsulation)

This provides both:
- strong classical security
- resistance against future quantum attacks

---

### Message Encryption

- **AES-256-GCM**
  - Authenticated encryption
  - Ensures confidentiality and integrity of messages

---

### Session Protocol

City of Hats uses a **Double Ratchet-based protocol** (similar design family to Signal), providing:

- Forward secrecy  
- Break-in recovery  
- Per-message key evolution  

---

## Identity Model (Hat System)

Instead of traditional accounts:

- Users create **Hat IDs**
- Hats can be:
  - Disposable (temporary)
  - Persistent (long-term identity)
  - Context-specific (per conversation or use case)

This reduces:
- identity correlation
- centralized user tracking

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

Further details on metadata handling and system architecture will be published in a dedicated transparency document.

---

## Transparency Status

City of Hats is currently:

- 🔒 Closed-source (core platform)
- 📄 Publishing architecture documentation (this repository)
- 🧪 Preparing for independent security review

Planned next steps:

- Open-source selected cryptographic components  
- Publish detailed privacy & logging specification  
- Conduct third-party security audit  

---

## Scope of This Repository

This repository is intended to:

- Document the cryptographic design
- Provide high-level protocol understanding
- Support external review and discussion

It does **not** include:

- Full production source code
- Backend infrastructure implementation
- Proprietary intelligence systems

---

## Contact

For security inquiries:

📧 admin@cityofhats.com

---

## Disclaimer

This document provides a high-level overview of the cryptographic design.  
Implementation details may evolve as the platform matures and undergoes formal review.

---

**City of Hats**  
Private communication. In your control.
