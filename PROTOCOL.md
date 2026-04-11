# City of Hats – Protocol Specification

> Version 1.0 · April 2026  
> Status: Production implementation — subject to evolution pending formal audit

This document specifies the cryptographic protocols used in City of Hats. It is intended for security researchers, auditors, and anyone evaluating the platform's encryption design.

For the production source code implementing these protocols, see [`src/crypto.ts`](src/crypto.ts) and [`src/groupCrypto.ts`](src/groupCrypto.ts).

---

## Table of Contents

1. [Notation and Conventions](#1-notation-and-conventions)
2. [Key Exchange — 1:1 Channels](#2-key-exchange--11-channels)
3. [Hybrid Post-Quantum Integration](#3-hybrid-post-quantum-integration)
4. [Double Ratchet Protocol](#4-double-ratchet-protocol)
5. [Header Encryption](#5-header-encryption)
6. [Wire Format](#6-wire-format)
7. [Metadata Padding](#7-metadata-padding)
8. [Sealed Payload Format](#8-sealed-payload-format)
9. [Group Encryption — Sender Keys](#9-group-encryption--sender-keys)
10. [Key Verification — Safety Numbers](#10-key-verification--safety-numbers)
11. [Key Rotation and Alerts](#11-key-rotation-and-alerts)
12. [Local Key Protection (PIN)](#12-local-key-protection-pin)
13. [DR State Backup](#13-dr-state-backup)
14. [Audit Log Chain](#14-audit-log-chain)
15. [Dead Drop Encryption](#15-dead-drop-encryption)
16. [EchoDrop — Passphrase-Based Encryption](#16-echodrop--passphrase-based-encryption)
17. [Steganography](#17-steganography)
18. [Time-Locked Encryption](#18-time-locked-encryption)
19. [Multi-Path Delivery (XOR Split)](#19-multi-path-delivery-xor-split)
20. [Cryptographic Primitive Summary](#20-cryptographic-primitive-summary)

---

## 1. Notation and Conventions

| Symbol | Meaning |
|--------|---------|
| `‖` | Byte concatenation |
| `b64(x)` | Base64 encoding of byte array `x` |
| `b64url(x)` | Base64url encoding (URL-safe, no padding) |
| `HKDF(ikm, salt, info, len)` | HKDF-SHA-256 with specified input key material, salt, info, and output length |
| `HMAC(key, data)` | HMAC-SHA-256 |
| `AES-GCM(key, iv, plaintext)` | AES-256-GCM authenticated encryption |
| `SHA-256(data)` | SHA-256 hash digest |
| `ECDH(priv, pub)` | Elliptic curve Diffie-Hellman key agreement |

All keys are 256 bits (32 bytes) unless otherwise specified.  
All IVs/nonces are 96 bits (12 bytes), randomly generated per operation.

---

## 2. Key Exchange — 1:1 Channels

### 2.1 Key Generation

Each Hat generates a long-term identity key pair on registration:

**Primary (preferred):**
- Algorithm: `X25519`
- Public key: 32 bytes (raw format)
- Private key: JWK format, stored in `localStorage`

**Fallback (browsers without X25519 support):**
- Algorithm: `ECDH P-256`
- Public key: 65 bytes (uncompressed point, raw format)
- Private key: JWK format, stored in `localStorage`

Algorithm detection is based on public key length:
- 32 bytes → X25519
- 65 bytes → P-256

### 2.2 Key Agreement

When two Hats establish a channel:

```
shared_bits = ECDH(my_private_key, peer_public_key)    // 256 bits
```

The shared bits are never used directly. They are passed through HKDF to derive session keys (see §4 for Double Ratchet initialization).

### 2.3 Public Key Publication

- Public keys are uploaded to the server as base64-encoded raw bytes
- The server stores public keys but never sees private keys
- Key publication happens at Hat creation time and on key rotation

---

## 3. Hybrid Post-Quantum Integration

### 3.1 ML-KEM-768 (Kyber) Key Pair

In addition to the classical key pair, each Hat generates an ML-KEM-768 key pair:

- **Public key**: 1184 bytes
- **Secret key**: 2400 bytes
- Implementation: `@noble/post-quantum` library (`ml_kem768`)

The ML-KEM public key is published alongside the classical public key. The secret key is stored locally.

### 3.2 Hybrid Key Encapsulation

When initiating a channel with a peer that has a PQ public key:

```
(ciphertext, pq_shared_secret) = ML-KEM-768.Encapsulate(peer_pq_public_key)
```

The encapsulated ciphertext is sent to the peer. The peer decapsulates:

```
pq_shared_secret = ML-KEM-768.Decapsulate(ciphertext, my_pq_secret_key)
```

### 3.3 Hybrid Root Key Derivation

Both shared secrets are combined:

```
combined = x25519_shared_bits ‖ pq_shared_secret
hybrid_root = HKDF(combined, salt="pq-hybrid-root", info="hats-pqxdh", len=256)
```

This hybrid root key replaces the classical-only shared secret as input to Double Ratchet initialization. If the classical key exchange is broken by a quantum computer, the PQ component still protects the session. If ML-KEM is broken, the classical component still provides security.

### 3.4 Graceful Degradation

If the peer does not have a PQ public key (older client), the system falls back to classical-only key exchange. The `pq` flag in the DR state tracks which mode is active.

---

## 4. Double Ratchet Protocol

City of Hats implements the Double Ratchet algorithm as specified by the Signal protocol family, with header encryption extensions.

### 4.1 State

Each party maintains a `DRState` containing:

| Field | Type | Description |
|-------|------|-------------|
| `algo` | `"X25519" \| "P-256"` | Key agreement algorithm |
| `pq` | boolean | Whether hybrid PQ root key was used |
| `RK` | 32 bytes (b64) | Root key |
| `CKs` | 32 bytes (b64) or null | Send chain key |
| `CKr` | 32 bytes (b64) or null | Receive chain key |
| `Ns` | integer | Send message counter |
| `Nr` | integer | Receive message counter |
| `PN` | integer | Previous send chain length |
| `DHs` | key pair | Our current ephemeral DH key pair |
| `DHr` | public key (b64) or null | Peer's current ephemeral DH public key |
| `MKSKIPPED` | map<string, b64> | Skipped message keys, keyed by `"dhPub:n"` |
| `HKs` | 32 bytes (b64) or null | Current send header key |
| `HKr` | 32 bytes (b64) or null | Current receive header key |
| `NHKs` | 32 bytes (b64) or null | Next send header key |
| `NHKr` | 32 bytes (b64) or null | Next receive header key |

### 4.2 Initialization

**Alice (initiator, hat_code_1):**

```
root_input = hybrid_root_key  (or classical shared_bits if no PQ)

RK = HKDF(root_input, salt="dr-init", info="dr-root", len=256)
(hk_alice, hk_bob) = DeriveInitialHeaderKeys(root_input)

DHs = GenerateDH(algo)
dh_out = DH(DHs.priv, peer_signed_prekey)
(RK, CKs, NHKs) = KDF_RK(RK, dh_out)

State = {
  RK, CKs, CKr=null, Ns=0, Nr=0, PN=0,
  DHs, DHr=peer_signed_prekey,
  HKs=hk_alice, HKr=null,
  NHKs, NHKr=hk_bob
}
```

**Bob (responder, hat_code_2):**

```
root_input = hybrid_root_key  (or classical shared_bits if no PQ)

RK = HKDF(root_input, salt="dr-init", info="dr-root", len=256)
(hk_alice, hk_bob) = DeriveInitialHeaderKeys(root_input)

State = {
  RK, CKs=null, CKr=null, Ns=0, Nr=0, PN=0,
  DHs=my_signed_prekey, DHr=null,
  HKs=null, HKr=null,
  NHKs=hk_bob, NHKr=hk_alice
}
```

### 4.3 KDF_RK — Root Key Derivation

```
Input: rk (32 bytes), dh_output (32 bytes)
Output: new_rk (32 bytes), chain_key (32 bytes), header_key (32 bytes)

hkdf_key = ImportKey(dh_output, "HKDF")
output = HKDF(hkdf_key, salt=rk, info="dr-rk", len=768)   // 96 bytes

new_rk     = output[0..32]
chain_key  = output[32..64]
header_key = output[64..96]
```

### 4.4 KDF_CK — Chain Key Derivation

```
Input: ck (32 bytes)
Output: new_ck (32 bytes), message_key (AES-256-GCM key)

hmac_key = ImportHMAC(ck)
mk_raw = HMAC(hmac_key, 0x01)    // message key material
new_ck = HMAC(hmac_key, 0x02)    // next chain key

message_key = ImportAES(mk_raw)
```

### 4.5 Encrypting a Message

```
(CKs, mk) = KDF_CK(CKs)
header = { dh: DHs.pub, pn: PN, n: Ns }
Ns += 1

padded_payload = Pad(sealed_json)           // See §7, §8
ciphertext = AES-GCM(mk, random_iv, padded_payload)
enc_header = AES-GCM(HKs, random_iv, JSON(header))

wire_message = "E" + b64(enc_header) + "." + b64(iv ‖ ciphertext)
```

### 4.6 Decrypting a Message

```
Parse wire_message → prefix, enc_header_b64, ciphertext_b64

1. Try decrypt header with HKr (current recv header key)
   - If success: header decoded, no DH ratchet needed
2. Try decrypt header with NHKr (next recv header key)
   - If success: header decoded, DH ratchet step required
3. If both fail: decryption error

4. Check MKSKIPPED for key "{header.dh}:{header.n}"
   - If found: decrypt with cached key, remove from cache, return

5. If new DH ratchet:
   - Skip message keys up to header.pn (cache them)
   - Perform DH ratchet step (see §4.7)

6. Skip message keys up to header.n (cache them)

7. (CKr, mk) = KDF_CK(CKr)
   Nr += 1
   plaintext = AES-GCM-Decrypt(mk, ciphertext)
```

### 4.7 DH Ratchet Step

Triggered when receiving a message with a new ephemeral DH public key:

```
PN = Ns
Ns = 0
Nr = 0
DHr = new_peer_dh

HKr = NHKr
HKs = NHKs

dh_out_1 = DH(DHs.priv, DHr)
(RK, CKr, NHKr) = KDF_RK(RK, dh_out_1)

DHs = GenerateDH(algo)
dh_out_2 = DH(DHs.priv, DHr)
(RK, CKs, NHKs) = KDF_RK(RK, dh_out_2)
```

### 4.8 Parameters

| Parameter | Value |
|-----------|-------|
| Max skipped messages | 200 |
| DH algorithm | X25519 (preferred) or P-256 (fallback) |
| Root KDF | HKDF-SHA-256, 96-byte output |
| Chain KDF | HMAC-SHA-256 |
| Message encryption | AES-256-GCM, 12-byte random IV |
| Header encryption | AES-256-GCM, 12-byte random IV |

---

## 5. Header Encryption

Message headers contain the sender's current ephemeral DH public key, previous chain length, and message number. To prevent metadata leakage:

### 5.1 Header Structure

```json
{
  "dh": "<base64 ephemeral DH public key>",
  "pn": <previous chain length>,
  "n": <message number in current chain>
}
```

### 5.2 Encryption

```
header_json = JSON.stringify(header)
iv = RandomBytes(12)
ciphertext = AES-GCM(header_key, iv, header_json)
encrypted_header = b64(iv ‖ ciphertext)
```

### 5.3 Initial Header Keys

Derived from the shared secret at session initialization:

```
output = HKDF(shared_secret, salt="dr-hk-init", info="hk-init", len=512)
hk_alice = output[0..32]     // Alice's send header key / Bob's recv header key
hk_bob   = output[32..64]    // Bob's send header key / Alice's recv header key
```

Header keys rotate with each DH ratchet step via KDF_RK (see §4.3).

---

## 6. Wire Format

Messages on the wire use a prefix byte to indicate the format:

| Prefix | Format | Description |
|--------|--------|-------------|
| `E` | `E<enc_header_b64>.<ciphertext_b64>` | Encrypted header (current protocol) |
| `D` | `D<plaintext_header_b64>.<ciphertext_b64>` | Plaintext header (backward compatibility, initial messages before header keys are established) |
| `R` | `R<send_index>:<ciphertext_b64>` | Legacy symmetric ratchet format (deprecated) |

### 6.1 Ciphertext Format

The ciphertext component is base64-encoded:

```
b64(iv[12 bytes] ‖ aes_gcm_ciphertext ‖ auth_tag[16 bytes])
```

The IV is prepended to the ciphertext. The 16-byte GCM authentication tag is appended by the AES-GCM operation.

---

## 7. Metadata Padding

To prevent message-length analysis, plaintext is padded to fixed-size buckets before encryption.

### 7.1 Bucket Sizes

```
64, 128, 256, 512, 1024, 2048, 4096 bytes
```

For messages exceeding 4096 bytes, the bucket size is rounded up to the next multiple of 4096.

### 7.2 Padding Format

```
[length_prefix: 4 bytes, big-endian uint32]
[plaintext: variable]
[random_fill: remaining bytes]
```

- The 4-byte length prefix records the actual plaintext length
- Remaining space is filled with `crypto.getRandomValues()` (indistinguishable from ciphertext)

### 7.3 Unpadding

```
actual_length = ReadUint32BigEndian(padded[0..4])
plaintext = padded[4 .. 4 + actual_length]
```

---

## 8. Sealed Payload Format

Before padding and encryption, the actual message content is wrapped in a sealed payload that includes sender identity inside the ciphertext.

### 8.1 Purpose

The server routes messages based on channel/pair metadata, but the sender identity inside the encrypted payload allows the recipient to verify that the server has not tampered with message attribution.

### 8.2 JSON Structure

```json
{
  "s": "<sender_hat_code>",
  "m": "<message_content>",
  "t": "msg"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `s` | string | Sender's Hat code (e.g., `"HAT-ABC123"`) |
| `m` | string | The actual message text or content |
| `t` | string | Payload type: `"msg"` for real messages, `"decoy"` for traffic analysis countermeasures |

### 8.3 Processing Pipeline

```
1. Build sealed JSON:  sealed = { s: myHatCode, m: messageText, t: "msg" }
2. Serialize:          json_str = JSON.stringify(sealed)
3. Pad:                padded = PadPayload(json_str)        // See §7
4. Encrypt:            ciphertext = DR_Encrypt(padded)      // See §4.5
5. Transmit:           wire_message sent to server
```

On receipt:
```
1. Decrypt:            padded = DR_Decrypt(wire_message)    // See §4.6
2. Unpad:              json_str = UnpadPayload(padded)      // See §7.3
3. Parse:              sealed = JSON.parse(json_str)
4. Verify sender:      assert sealed.s === expected_sender
5. Extract message:    plaintext = sealed.m
```

---

## 9. Group Encryption — Sender Keys

Group chat uses a Sender Keys protocol where each member encrypts once for the entire group, rather than N times for N members.

### 9.1 Sender Key Structure

Each group member generates:

```
SenderKey = {
  chainKey:       32 random bytes (hex-encoded)
  signPublicKey:  ECDSA P-256 public key (SPKI, base64)
  signPrivateKey: ECDSA P-256 private key (PKCS8, base64)
  generation:     integer (key rotation counter)
  chainIndex:     integer (message counter within this generation)
}
```

### 9.2 Key Distribution

The public portion of a sender key (chain key + signing public key + generation + chain index) is distributed to each group member via their existing 1:1 encrypted channels. This means:

1. Member A generates a sender key for Group G
2. For each other member B in Group G:
   - A encrypts the sender key using the A↔B Double Ratchet channel
   - A sends the encrypted sender key to B via the server
3. B decrypts and stores A's sender key locally

### 9.3 HMAC Chain Ratchet

The chain key advances after each message:

```
hmac_key = ImportHMAC(chain_key)
message_key_raw = HMAC(hmac_key, "MessageKey")     // literal ASCII string
next_chain_key  = HMAC(hmac_key, "ChainKey")        // literal ASCII string

message_key = ImportAES-GCM(message_key_raw)
```

### 9.4 Encrypting a Group Message

```
1. (message_key, next_chain_key) = RatchetChainKey(sender_key.chainKey)
2. iv = RandomBytes(12)
3. ciphertext = AES-GCM(message_key, iv, plaintext)
4. signature = ECDSA-P256-SHA256.Sign(sign_private_key, ciphertext)
5. Envelope = {
     ct:  b64(ciphertext),
     iv:  b64(iv),
     sig: b64(signature),
     gen: sender_key.generation,
     idx: sender_key.chainIndex
   }
6. Update: sender_key.chainKey = next_chain_key
           sender_key.chainIndex += 1
```

### 9.5 Decrypting a Group Message

```
1. Verify signature:
   valid = ECDSA-P256-SHA256.Verify(peer_sign_public_key, envelope.sig, envelope.ct)
   If !valid → reject message

2. Advance peer's chain key from stored chainIndex to envelope.idx:
   for i in [stored_index .. envelope.idx]:
     (mk, next_ck) = RatchetChainKey(ck)
   The final mk is the message key

3. plaintext = AES-GCM-Decrypt(message_key, envelope.iv, envelope.ct)

4. Update stored peer key: chainKey = next_ck, chainIndex = envelope.idx + 1
```

### 9.6 Key Rotation

When a member leaves the group or after a threshold number of messages, a new sender key is generated with `generation += 1` and distributed to remaining members.

### 9.7 Parameters

| Parameter | Value |
|-----------|-------|
| Chain key | 32 bytes, HMAC-SHA-256 ratchet |
| Message encryption | AES-256-GCM, 12-byte random IV |
| Sender verification | ECDSA P-256, SHA-256 |
| Key format | SPKI (public), PKCS8 (private) |

---

## 10. Key Verification — Safety Numbers

### 10.1 Computation

Both parties compute the same safety number from their public keys:

```
keys = sort([my_public_key_b64, peer_public_key_b64])
input = encode(keys[0] + "|" + keys[1])
h1 = SHA-256(input)
h2 = SHA-256(h1)        // double hash for extra mixing
```

### 10.2 Display Format

The hash is converted to a 30-digit decimal string displayed in 6 groups of 5:

```
for i in 0..29:
  digit = h2[i % 32] mod 10

Format: "XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX"
```

### 10.3 Verification

Users compare safety numbers out-of-band (in person, phone call, etc.). A mismatch indicates a potential man-in-the-middle attack or key substitution.

---

## 11. Key Rotation and Alerts

### 11.1 Detection

Each time a peer's public key is received, it is compared against the previously stored value:

```
stored_key = localStorage.get("known_peer_key_" + peer_hat_code)
if stored_key exists AND stored_key ≠ current_key:
    alert user: "Key changed for [peer]"
    store new key
```

### 11.2 Causes

Key changes occur when:
- Peer reinstalled the app
- Peer switched to a new device
- Peer's keys were rotated
- A man-in-the-middle attack is in progress

The user is notified to re-verify safety numbers after a key change.

---

## 12. Local Key Protection (PIN)

### 12.1 Key Derivation

```
salt = RandomBytes(16)
base_key = ImportPBKDF2(pin_utf8)
storage_key = PBKDF2(base_key, salt, iterations=600000, hash=SHA-256, len=256)
```

### 12.2 Verification

A known plaintext `"pin-ok"` is encrypted with the derived key and stored. On PIN entry, the system derives the key and attempts to decrypt the check value.

### 12.3 Key Wrapping

When PIN protection is active, sensitive `localStorage` values are encrypted:

```
Store:   localStorage[key] = "ENC:" + AES-GCM(storage_key, random_iv, value)
Load:    value = AES-GCM-Decrypt(storage_key, localStorage[key].removePrefix("ENC:"))
```

The derived key is cached in `sessionStorage` (cleared on tab close) so the PIN is only required once per session.

### 12.4 Parameters

| Parameter | Value |
|-----------|-------|
| KDF | PBKDF2-SHA-256 |
| Iterations | 600,000 |
| Salt | 16 random bytes |
| Output | AES-256-GCM key |

---

## 13. DR State Backup

Double Ratchet state is backed up to the server for multi-device recovery, but the server cannot read it.

### 13.1 Backup Key Derivation

```
priv_json = JSON.stringify(private_key_jwk)
backup_key = SHA-256(priv_json)              // 32 bytes → AES-256-GCM key
```

The backup key is derived from the user's private key, which the server never sees.

### 13.2 Backup Format

```
iv = RandomBytes(12)
plaintext = JSON.stringify(dr_state)
ciphertext = AES-GCM(backup_key, iv, plaintext)
blob = b64(iv ‖ ciphertext)
```

The server stores `blob` as an opaque string indexed by `(hat_code, device_id, pair_id)`.

### 13.3 Restore

The restoring device derives the same backup key from its private key and decrypts the blob.

### 13.4 Debouncing

Backups are debounced to 5 seconds after the last state change to avoid flooding during rapid message exchange.

---

## 14. Audit Log Chain

### 14.1 Entry Structure

```json
{
  "ts": 1712800000000,
  "op": "encrypt",
  "detail": "DR encrypt for pair 42, msg #7",
  "chain": "<hex SHA-256 hash of previous entry>"
}
```

### 14.2 Chain Computation

```
payload = "{prev.ts}|{prev.op}|{prev.detail}|{prev.chain}"
chain = hex(SHA-256(payload))
```

The first entry uses a chain value of `"0" × 64` (64 zero characters).

### 14.3 Verification

To verify integrity, recompute each entry's chain hash from the previous entry and compare. A mismatch at index `i` indicates the log was tampered with at or before that point.

### 14.4 Storage

- Stored in `localStorage` as JSON array
- Maximum 500 entries (oldest are pruned)
- Operations logged: `keygen`, `encrypt`, `decrypt`, `ratchet`, `pq_encap`, `pq_decap`, `key_change`

---

## 15. Dead Drop Encryption

Dead Drops are anonymous, one-time encrypted messages accessible via a URL.

### 15.1 Key Generation

```
key = AES-256-GCM.GenerateKey(extractable=true)
key_string = b64url(ExportKey(key))
```

### 15.2 Sharing

The key is placed in the URL fragment (`#`), which is never sent to the server:

```
https://hats.cityofhats.com/drop/<code>#<key_string>
```

### 15.3 Encryption / Decryption

Standard AES-256-GCM with 12-byte random IV (see §6.1 for ciphertext format).

---

## 16. EchoDrop — Passphrase-Based Encryption

EchoDrop messages are encrypted with a key derived from a shared passphrase.

### 16.1 Passphrase Normalization

```
normalized = lowercase(trim(passphrase)).replace(/\s+/, " ")
```

### 16.2 Passphrase Hashing (for server lookup)

```
hash = hex(SHA-256(normalized))
```

The server stores messages indexed by passphrase hash. It never sees the passphrase or derived key.

### 16.3 Key Derivation

```
salt = <message-specific salt from server>
base_key = ImportPBKDF2(normalized)
key = PBKDF2(base_key, salt, iterations=600000, hash=SHA-256, len=256)
```

---

## 17. Steganography

Ciphertext can be embedded in PNG images using LSB (Least Significant Bit) encoding.

### 17.1 Payload Format

```
[MAGIC: 4 bytes "HATS" (0x48 0x41 0x54 0x53)]
[LENGTH: 4 bytes, big-endian uint32]
[DATA: variable length]
```

### 17.2 Embedding

1. Calculate required image size: `pixels = max(payload_bits + 64, 1024)`
2. Create square canvas: `side = ceil(sqrt(pixels))`
3. Fill with random pixel data (cover noise)
4. Set all alpha channels to 255
5. For each bit of payload: set LSB of red channel of pixel `i`

### 17.3 Extraction

1. Read pixel data from image
2. Check first 32 bits (4 bytes) of red channel LSBs for magic bytes `"HATS"`
3. Read next 32 bits for length
4. Read `length` bytes from subsequent LSBs

---

## 18. Time-Locked Encryption

Time-locked messages use a two-part key: one part in the URL, one held by the server until the unlock time.

### 18.1 Fragment Generation

```
fragment = RandomBytes(32)     // stored on server with release timestamp
```

### 18.2 Key Derivation

```
url_key_raw = ExportKey(url_key)
combined = url_key_raw ‖ fragment
hkdf_key = ImportHKDF(combined)
decryption_key = HKDF(hkdf_key, salt="time-lock", info="hats-tl", len=256)
```

Neither the URL key alone nor the server fragment alone can decrypt the message.

---

## 19. Multi-Path Delivery (XOR Split)

For high-sensitivity messages, ciphertext can be split across multiple delivery channels.

### 19.1 Splitting

```
share1 = RandomBytes(data.length)
share2 = data XOR share1
```

### 19.2 Reconstruction

```
data = share1 XOR share2
```

Each share alone reveals nothing about the original data (information-theoretic security for the split).

---

## 20. Cryptographic Primitive Summary

| Purpose | Primitive | Parameters |
|---------|-----------|------------|
| Key agreement (classical) | X25519 or ECDH P-256 | 256-bit shared secret |
| Key agreement (post-quantum) | ML-KEM-768 (Kyber) | 256-bit shared secret |
| Hybrid root key | HKDF-SHA-256 | salt=`"pq-hybrid-root"`, info=`"hats-pqxdh"` |
| Root key derivation | HKDF-SHA-256 | 96-byte output (root + chain + header key) |
| Chain key derivation | HMAC-SHA-256 | 0x01 → message key, 0x02 → next chain key |
| Message encryption | AES-256-GCM | 12-byte random IV |
| Header encryption | AES-256-GCM | 12-byte random IV |
| Group chain ratchet | HMAC-SHA-256 | `"MessageKey"` / `"ChainKey"` as HMAC input |
| Group sender verification | ECDSA P-256 | SHA-256 hash |
| Safety numbers | SHA-256 (double) | 30 digits, 6 groups of 5 |
| PIN key derivation | PBKDF2-SHA-256 | 600,000 iterations, 16-byte salt |
| Passphrase key derivation | PBKDF2-SHA-256 | 600,000 iterations |
| Audit chain | SHA-256 | Hash of previous entry |
| Steganography | LSB (red channel) | Magic: `0x48415453` |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | April 2026 | Initial publication |

---

**City of Hats Inc.**  
Toronto, Canada · Incorporated in Ontario  
[cityofhats.com/transparency](https://cityofhats.com/transparency)
