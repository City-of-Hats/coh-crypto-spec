/**
 * Client-side encryption for Secure Channels (Web Crypto API + ML-KEM).
 *
 * Encryption layers:
 * 1. Dead Drops: AES-256-GCM, key shared via URL fragment (#)
 * 2. Hat-to-Hat Chat: X25519 + ML-KEM-768 hybrid → Double Ratchet (Signal-spec)
 *    with header encryption, metadata padding, and verified sender.
 *
 * The server NEVER sees plaintext, private keys, or encryption keys.
 */
// @ts-ignore — noble post-quantum uses .js exports
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'

// ── Key Management ──

export async function generateDropKey(): Promise<{ key: CryptoKey; keyString: string }> {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )
  const raw = await crypto.subtle.exportKey('raw', key)
  const keyString = bufferToBase64url(raw)
  return { key, keyString }
}

export async function importDropKey(keyString: string): Promise<CryptoKey> {
  const raw = base64urlToBuffer(keyString)
  return crypto.subtle.importKey(
    'raw',
    raw.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    true,  // extractable — needed for time-lock HKDF derivation
    ['encrypt', 'decrypt']
  )
}

// ── Text Encryption ──

export async function encryptText(plaintext: string, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encoded = new TextEncoder().encode(plaintext)
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  )
  // IV (12 bytes) + ciphertext (includes 16-byte GCM auth tag)
  const combined = new Uint8Array(iv.length + ciphertext.byteLength)
  combined.set(iv)
  combined.set(new Uint8Array(ciphertext), iv.length)
  return bufferToBase64(combined.buffer)
}

export async function decryptText(ciphertextB64: string, key: CryptoKey): Promise<string> {
  const combined = base64ToBuffer(ciphertextB64)
  const iv = combined.slice(0, 12)
  const ciphertext = combined.slice(12)
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  )
  return new TextDecoder().decode(decrypted)
}

// ── File Encryption ──

export async function encryptFile(data: ArrayBuffer, key: CryptoKey): Promise<Blob> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  )
  const combined = new Uint8Array(iv.length + ciphertext.byteLength)
  combined.set(iv)
  combined.set(new Uint8Array(ciphertext), iv.length)
  return new Blob([combined])
}

export async function decryptFile(encryptedBlob: Blob, key: CryptoKey): Promise<Blob> {
  const buffer = await encryptedBlob.arrayBuffer()
  const combined = new Uint8Array(buffer)
  const iv = combined.slice(0, 12)
  const ciphertext = combined.slice(12)
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  )
  return new Blob([decrypted])
}

// ── Encoding Helpers ──

export function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  bytes.forEach(b => (binary += String.fromCharCode(b)))
  return btoa(binary)
}

export function base64ToBuffer(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function bufferToBase64url(buffer: ArrayBuffer): string {
  return bufferToBase64(buffer)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function base64urlToBuffer(b64url: string): Uint8Array {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/')
  while (b64.length % 4) b64 += '='
  return base64ToBuffer(b64)
}

// ── URL Key Extraction ──

export function extractKeyFromHash(): string | null {
  const hash = window.location.hash
  if (!hash || hash.length < 2) return null
  return hash.slice(1) // remove the '#'
}

export function parseDropCodeWithKey(input: string): { code: string; key: string | null } {
  const hashIdx = input.indexOf('#')
  if (hashIdx !== -1) {
    return {
      code: input.substring(0, hashIdx),
      key: input.substring(hashIdx + 1)
    }
  }
  return { code: input, key: null }
}

// ════════════════════════════════════════════════════════════════
// ECDH Key Agreement for Hat-to-Hat E2E Chat
// ════════════════════════════════════════════════════════════════

/**
 * Generate an ECDH P-256 key pair.
 * Public key is published to the server (base64 of raw bytes).
 * Private key stays in localStorage (JWK format).
 */
export async function generateECDHKeyPair(): Promise<{
  publicKeyB64: string
  privateKeyJwk: JsonWebKey
}> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  )
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey)
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)
  return {
    publicKeyB64: bufferToBase64(publicKeyRaw),
    privateKeyJwk
  }
}

/**
 * Derive a shared AES-256-GCM key from our ECDH private key and the peer's public key.
 * Uses HKDF with pair_id as salt for domain separation.
 */
export async function deriveSharedChatKey(
  privateKeyJwk: JsonWebKey,
  peerPublicKeyB64: string,
  pairId: number
): Promise<CryptoKey> {
  // Import our private key
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    privateKeyJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits']
  )

  // Import peer's public key from raw bytes
  const peerPubRaw = base64ToBuffer(peerPublicKeyB64)
  const peerPublicKey = await crypto.subtle.importKey(
    'raw',
    peerPubRaw.buffer as ArrayBuffer,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  )

  // ECDH: derive shared bits
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPublicKey },
    privateKey,
    256
  )

  // HKDF: derive AES-256-GCM key from shared secret
  const hkdfKey = await crypto.subtle.importKey(
    'raw', sharedBits, 'HKDF', false, ['deriveKey']
  )

  const salt = new TextEncoder().encode(`hat-pair-${pairId}`)
  const info = new TextEncoder().encode('hat-e2e-chat-v1')

  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

// ── ECDH Key Persistence (localStorage) ──

export function storeECDHPrivateKey(hatCode: string, jwk: JsonWebKey): void {
  localStorage.setItem(`ecdh_${hatCode}`, JSON.stringify(jwk))
}

export function loadECDHPrivateKey(hatCode: string): JsonWebKey | null {
  const stored = localStorage.getItem(`ecdh_${hatCode}`)
  if (!stored) return null
  try {
    return JSON.parse(stored) as JsonWebKey
  } catch {
    return null
  }
}

// ════════════════════════════════════════════════════════════════
// Symmetric Key Ratchet — Forward Secrecy for Hat-to-Hat Chat
// ════════════════════════════════════════════════════════════════
//
// Each message uses a unique AES-256-GCM key derived from a chain.
// After use, the chain advances and old keys are discarded.
// Compromising the current state cannot reveal past message keys.
//
// Chain split:
//   hat_code_1 sends on chain A, receives on chain B
//   hat_code_2 sends on chain B, receives on chain A
//
// Wire format for ratcheted messages: R<sendIndex>:<base64-ciphertext>

export interface RatchetState {
  sendChainKey: string          // base64 — current send chain key
  sendIndex: number             // next send position
  recvChainKey: string          // base64 — current receive chain key
  recvIndex: number             // next expected receive position
  skippedKeys: Record<string, string>  // "index" → base64 message key (out-of-order)
}

/**
 * Derive two independent chain keys from the ECDH shared secret.
 */
export async function deriveRatchetChains(
  privateKeyJwk: JsonWebKey,
  peerPublicKeyB64: string,
  pairId: number
): Promise<{ chainA: string; chainB: string }> {
  // ECDH key agreement (same math as deriveSharedChatKey)
  const privateKey = await crypto.subtle.importKey(
    'jwk', privateKeyJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false, ['deriveBits']
  )
  const peerPubRaw = base64ToBuffer(peerPublicKeyB64)
  const peerPublicKey = await crypto.subtle.importKey(
    'raw', peerPubRaw.buffer as ArrayBuffer,
    { name: 'ECDH', namedCurve: 'P-256' },
    false, []
  )
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPublicKey },
    privateKey, 256
  )

  const hkdfKey = await crypto.subtle.importKey(
    'raw', sharedBits, 'HKDF', false, ['deriveBits']
  )
  const salt = new TextEncoder().encode(`ratchet-pair-${pairId}`)

  const chainABits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('chain-a') },
    hkdfKey, 256
  )
  const chainBBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('chain-b') },
    hkdfKey, 256
  )

  return {
    chainA: bufferToBase64(chainABits),
    chainB: bufferToBase64(chainBBits)
  }
}

/**
 * Create initial ratchet state from the two chain keys.
 */
export function initRatchetState(
  chainA: string, chainB: string, isHatCode1: boolean
): RatchetState {
  return {
    sendChainKey: isHatCode1 ? chainA : chainB,
    sendIndex: 0,
    recvChainKey: isHatCode1 ? chainB : chainA,
    recvIndex: 0,
    skippedKeys: {}
  }
}

/**
 * Advance a chain key by one step using HKDF.
 * Returns a per-message AES key and the next chain key.
 */
async function advanceChain(
  chainKeyB64: string, index: number
): Promise<{ messageKey: CryptoKey; nextChainKey: string }> {
  const chainKeyRaw = base64ToBuffer(chainKeyB64)
  const hkdfKey = await crypto.subtle.importKey(
    'raw', chainKeyRaw.buffer as ArrayBuffer,
    'HKDF', false, ['deriveKey', 'deriveBits']
  )
  const salt = new TextEncoder().encode('hat-ratchet')

  const messageKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(`msg-${index}`) },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    true,   // extractable — needed for caching skipped keys
    ['encrypt', 'decrypt']
  )

  const nextBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(`next-${index}`) },
    hkdfKey, 256
  )

  return { messageKey, nextChainKey: bufferToBase64(nextBits) }
}

/**
 * Ratchet-encrypt: get the next send message key and advance the send chain.
 */
export async function ratchetEncryptStep(state: RatchetState): Promise<{
  messageKey: CryptoKey
  sendIndex: number
  updatedState: RatchetState
}> {
  const { messageKey, nextChainKey } = await advanceChain(state.sendChainKey, state.sendIndex)
  return {
    messageKey,
    sendIndex: state.sendIndex,
    updatedState: {
      ...state,
      sendChainKey: nextChainKey,
      sendIndex: state.sendIndex + 1
    }
  }
}

/**
 * Ratchet-decrypt: derive the message key for a received message index.
 * Handles out-of-order delivery by caching skipped keys.
 */
export async function ratchetDecryptStep(
  state: RatchetState, messageIndex: number
): Promise<{ messageKey: CryptoKey; updatedState: RatchetState }> {
  // 1. Check skipped keys cache
  const cached = state.skippedKeys[String(messageIndex)]
  if (cached) {
    const raw = base64ToBuffer(cached)
    const messageKey = await crypto.subtle.importKey(
      'raw', raw.buffer as ArrayBuffer,
      { name: 'AES-GCM', length: 256 },
      false, ['encrypt', 'decrypt']
    )
    const newSkipped = { ...state.skippedKeys }
    delete newSkipped[String(messageIndex)]
    return { messageKey, updatedState: { ...state, skippedKeys: newSkipped } }
  }

  // 2. Can't go backward
  if (messageIndex < state.recvIndex) {
    throw new Error(`Cannot decrypt: index ${messageIndex} < recv position ${state.recvIndex}`)
  }

  // 3. Fast-forward, caching any skipped keys along the way
  let chainKey = state.recvChainKey
  let idx = state.recvIndex
  const newSkipped = { ...state.skippedKeys }

  while (idx < messageIndex) {
    const { messageKey: skipKey, nextChainKey } = await advanceChain(chainKey, idx)
    const rawKey = await crypto.subtle.exportKey('raw', skipKey)
    newSkipped[String(idx)] = bufferToBase64(rawKey)
    chainKey = nextChainKey
    idx++
  }

  // 4. Derive the target message key
  const { messageKey, nextChainKey } = await advanceChain(chainKey, messageIndex)

  return {
    messageKey,
    updatedState: {
      ...state,
      recvChainKey: nextChainKey,
      recvIndex: messageIndex + 1,
      skippedKeys: newSkipped
    }
  }
}

// ── Ratchet State Persistence ──

export function saveRatchetState(pairId: number, state: RatchetState, peerDeviceId?: string): void {
  const key = peerDeviceId ? `ratchet_${pairId}_${peerDeviceId}` : `ratchet_${pairId}`
  localStorage.setItem(key, JSON.stringify(state))
}

export function loadRatchetState(pairId: number, peerDeviceId?: string): RatchetState | null {
  const key = peerDeviceId ? `ratchet_${pairId}_${peerDeviceId}` : `ratchet_${pairId}`
  const saved = localStorage.getItem(key)
  if (!saved) return null
  try { return JSON.parse(saved) } catch { return null }
}

// ── Decrypted Message Cache ──
// Messages are cached locally after first decryption so we never
// need to re-derive old ratchet keys on page refresh.

export interface CachedChatMessage {
  id: number
  pair_id: number
  sender_hat_code: string
  content: string
  sent_at: string
  read_at: string | null
  unsent_at?: string | null
}

export function saveChatCache(pairId: number, msgs: CachedChatMessage[]): void {
  localStorage.setItem(`chat_${pairId}`, JSON.stringify(msgs))
}

export function loadChatCache(pairId: number): CachedChatMessage[] {
  const saved = localStorage.getItem(`chat_${pairId}`)
  if (!saved) return []
  try { return JSON.parse(saved) } catch { return [] }
}

export function clearChatData(pairId: number): void {
  localStorage.removeItem(`ratchet_${pairId}`)
  localStorage.removeItem(`dr_${pairId}`)
  localStorage.removeItem(`chat_${pairId}`)
  // Also clear per-device DR/ratchet states
  const keysToRemove: string[] = []
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)
    if (k && (k.startsWith(`dr_${pairId}_`) || k.startsWith(`ratchet_${pairId}_`))) {
      keysToRemove.push(k)
    }
  }
  keysToRemove.forEach(k => localStorage.removeItem(k))
}

// ════════════════════════════════════════════════════════════════
// #5  Metadata Padding
// ════════════════════════════════════════════════════════════════
// Pad plaintext to fixed-size buckets so ciphertext length doesn't
// reveal message length to the server.

const PAD_BUCKETS = [64, 128, 256, 512, 1024, 2048, 4096]

export function padPayload(jsonStr: string): Uint8Array {
  const encoded = new TextEncoder().encode(jsonStr)
  const needed = 4 + encoded.length                 // 4-byte length prefix
  const bucket = PAD_BUCKETS.find(b => b >= needed)
    || Math.ceil(needed / 4096) * 4096
  const padded = new Uint8Array(bucket)
  new DataView(padded.buffer).setUint32(0, encoded.length)
  padded.set(encoded, 4)
  crypto.getRandomValues(padded.subarray(4 + encoded.length))  // random fill
  return padded
}

export function unpadPayload(padded: Uint8Array): string {
  const length = new DataView(padded.buffer, padded.byteOffset).getUint32(0)
  return new TextDecoder().decode(padded.slice(4, 4 + length))
}

// Binary-level AES-256-GCM (works with Uint8Array, not strings)
export async function encryptBinary(data: Uint8Array, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data.buffer as ArrayBuffer)
  const out = new Uint8Array(12 + ct.byteLength)
  out.set(iv)
  out.set(new Uint8Array(ct), 12)
  return bufferToBase64(out.buffer)
}

export async function decryptBinary(b64: string, key: CryptoKey): Promise<Uint8Array> {
  const combined = base64ToBuffer(b64)
  const iv = combined.slice(0, 12)
  const ct = combined.slice(12)
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)
  return new Uint8Array(pt)
}

// ════════════════════════════════════════════════════════════════
// #3  Safety Numbers (Key Verification)
// ════════════════════════════════════════════════════════════════
// Both parties compute the same code from their public keys.
// Displayed as 30 digits in 6 groups for easy comparison.

export async function generateSafetyNumber(
  myPublicKeyB64: string,
  peerPublicKeyB64: string
): Promise<string> {
  const keys = [myPublicKeyB64, peerPublicKeyB64].sort()
  const encoded = new TextEncoder().encode(keys[0] + '|' + keys[1])
  // Double hash for extra mixing
  const h1 = await crypto.subtle.digest('SHA-256', encoded)
  const h2 = await crypto.subtle.digest('SHA-256', h1)
  const bytes = new Uint8Array(h2)
  let result = ''
  for (let i = 0; i < 30; i++) {
    result += String(bytes[i % 32] % 10)
    if ((i + 1) % 5 === 0 && i < 29) result += ' '
  }
  return result
}

// ════════════════════════════════════════════════════════════════
// #6  Verified Sender (Sealed Sender Lite)
// ════════════════════════════════════════════════════════════════
// Sender identity is included in the encrypted payload so the
// recipient can verify the server hasn't tampered with attribution.

export function buildSealedPayload(
  senderHatCode: string, message: string, type: 'msg' | 'decoy' = 'msg'
): string {
  return JSON.stringify({ s: senderHatCode, m: message, t: type })
}

export function openSealedPayload(json: string): { sender: string; message: string; type: string } {
  const obj = JSON.parse(json)
  return { sender: obj.s, message: obj.m, type: obj.t || 'msg' }
}

// ════════════════════════════════════════════════════════════════
// #2  X25519 Key Generation (with P-256 auto-fallback)
// ════════════════════════════════════════════════════════════════

export type KeyAlgo = 'X25519' | 'P-256'

export function detectKeyAlgo(publicKeyB64: string): KeyAlgo {
  return base64ToBuffer(publicKeyB64).length === 32 ? 'X25519' : 'P-256'
}

export async function publicKeyFromPrivateJwk(jwk: JsonWebKey): Promise<string> {
  const pubJwk: JsonWebKey = { ...jwk }
  delete pubJwk.d
  pubJwk.key_ops = []
  const isX = pubJwk.crv === 'X25519'
  const algo: any = isX ? 'X25519' : { name: 'ECDH', namedCurve: 'P-256' }
  const pubKey = await crypto.subtle.importKey('jwk', pubJwk, algo, true, [])
  const raw = await crypto.subtle.exportKey('raw', pubKey)
  return bufferToBase64(raw)
}

export async function generateKeyPair(): Promise<{
  publicKeyB64: string
  privateKeyJwk: JsonWebKey
  algorithm: KeyAlgo
}> {
  try {
    const kp = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair
    const pub = await crypto.subtle.exportKey('raw', kp.publicKey)
    const priv = await crypto.subtle.exportKey('jwk', kp.privateKey)
    return { publicKeyB64: bufferToBase64(pub), privateKeyJwk: priv, algorithm: 'X25519' }
  } catch {
    // Fallback for browsers without X25519
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
    )
    const pub = await crypto.subtle.exportKey('raw', kp.publicKey)
    const priv = await crypto.subtle.exportKey('jwk', kp.privateKey)
    return { publicKeyB64: bufferToBase64(pub), privateKeyJwk: priv, algorithm: 'P-256' }
  }
}

/** Compute raw shared bits — works with either X25519 or P-256 keys. */
export async function deriveSharedBits(
  privateKeyJwk: JsonWebKey, peerPublicKeyB64: string
): Promise<ArrayBuffer> {
  const raw = base64ToBuffer(peerPublicKeyB64)
  const isX = raw.length === 32
  const algo: AlgorithmIdentifier = isX
    ? 'X25519'
    : { name: 'ECDH', namedCurve: 'P-256' } as EcKeyImportParams
  const privKey = await crypto.subtle.importKey(
    'jwk', privateKeyJwk, algo, false, ['deriveBits']
  )
  const pubKey = await crypto.subtle.importKey(
    'raw', raw.buffer as ArrayBuffer, algo, false, []
  )
  return crypto.subtle.deriveBits(
    { name: isX ? 'X25519' : 'ECDH', public: pubKey } as EcdhKeyDeriveParams,
    privKey, 256
  )
}

// ════════════════════════════════════════════════════════════════
// Post-Quantum: ML-KEM-768 (Kyber) for hybrid key exchange
// ════════════════════════════════════════════════════════════════

export function generatePQKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return ml_kem768.keygen()
}

export function pqEncapsulate(publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array } {
  return ml_kem768.encapsulate(publicKey)
}

export function pqDecapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_kem768.decapsulate(cipherText, secretKey)
}

export function storePQSecretKey(hatCode: string, sk: Uint8Array): void {
  localStorage.setItem(`pq_${hatCode}`, bufferToBase64(sk.buffer as ArrayBuffer))
}

export function loadPQSecretKey(hatCode: string): Uint8Array | null {
  const b64 = localStorage.getItem(`pq_${hatCode}`)
  if (!b64) return null
  return base64ToBuffer(b64)
}

/** Derive a hybrid root key from X25519 shared bits + ML-KEM shared secret. */
export async function deriveHybridRootKey(
  x25519Shared: ArrayBuffer, pqShared: Uint8Array
): Promise<ArrayBuffer> {
  // Concatenate both shared secrets
  const combined = new Uint8Array(x25519Shared.byteLength + pqShared.length)
  combined.set(new Uint8Array(x25519Shared), 0)
  combined.set(pqShared, x25519Shared.byteLength)
  const hkdfKey = await crypto.subtle.importKey('raw', combined, 'HKDF', false, ['deriveBits'])
  return crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256',
      salt: new TextEncoder().encode('pq-hybrid-root'),
      info: new TextEncoder().encode('hats-pqxdh') },
    hkdfKey, 256
  )
}

// ════════════════════════════════════════════════════════════════
// Double Ratchet (Signal-spec) with Header Encryption
// ════════════════════════════════════════════════════════════════

const MAX_SKIP = 200

export interface DRState {
  algo: KeyAlgo
  pq: boolean                                   // true if hybrid PQ root
  RK: string                                    // root key (b64)
  CKs: string | null                            // send chain key
  CKr: string | null                            // recv chain key
  Ns: number                                    // send msg #
  Nr: number                                    // recv msg #
  PN: number                                    // prev send chain length
  DHs: { pub: string; priv: JsonWebKey }        // our ephemeral DH
  DHr: string | null                            // peer's ephemeral DH pub
  MKSKIPPED: Record<string, string>             // "dhPub:n" → msgKey b64
  // Header encryption keys
  HKs: string | null                            // current send header key
  HKr: string | null                            // current recv header key
  NHKs: string | null                           // next send header key
  NHKr: string | null                           // next recv header key
}

export interface DRHeader {
  dh: string   // sender's current ephemeral DH pub (b64)
  pn: number   // previous chain length
  n: number    // message number in current chain
}

// ── Internal KDFs ──

async function KDF_RK(rk: string, dhOut: ArrayBuffer): Promise<{ rk: string; ck: string; hk: string }> {
  const salt = base64ToBuffer(rk)
  const hkdfKey = await crypto.subtle.importKey('raw', dhOut, 'HKDF', false, ['deriveBits'])
  const out = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256',
      salt: salt.buffer as ArrayBuffer,
      info: new TextEncoder().encode('dr-rk') },
    hkdfKey, 768    // 96 bytes: 32 root + 32 chain + 32 header
  )
  const bytes = new Uint8Array(out)
  return {
    rk: bufferToBase64(bytes.slice(0, 32).buffer),
    ck: bufferToBase64(bytes.slice(32, 64).buffer),
    hk: bufferToBase64(bytes.slice(64, 96).buffer)
  }
}

async function KDF_CK(ck: string): Promise<{ ck: string; mk: CryptoKey }> {
  const ckBytes = base64ToBuffer(ck)
  const hmacKey = await crypto.subtle.importKey(
    'raw', ckBytes.buffer as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  const mkRaw = await crypto.subtle.sign('HMAC', hmacKey, new Uint8Array([0x01]))
  const newCk = await crypto.subtle.sign('HMAC', hmacKey, new Uint8Array([0x02]))
  const mk = await crypto.subtle.importKey(
    'raw', mkRaw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
  )
  return { ck: bufferToBase64(newCk), mk }
}

async function GENERATE_DH(algo: KeyAlgo): Promise<{ pub: string; priv: JsonWebKey }> {
  if (algo === 'X25519') {
    try {
      const kp = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair
      const pub = await crypto.subtle.exportKey('raw', kp.publicKey)
      const priv = await crypto.subtle.exportKey('jwk', kp.privateKey)
      return { pub: bufferToBase64(pub), priv }
    } catch { /* fall through to P-256 */ }
  }
  const kp = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  )
  const pub = await crypto.subtle.exportKey('raw', kp.publicKey)
  const priv = await crypto.subtle.exportKey('jwk', kp.privateKey)
  return { pub: bufferToBase64(pub), priv }
}

async function DH(privJwk: JsonWebKey, peerPubB64: string): Promise<ArrayBuffer> {
  return deriveSharedBits(privJwk, peerPubB64)
}

// ── Double Ratchet Initialization ──

/**
 * Derive initial header keys from the shared secret.
 * Both sides compute the same two keys (for Alice's send and Bob's send).
 */
async function deriveInitialHeaderKeys(
  sharedSecret: ArrayBuffer
): Promise<{ hkAlice: string; hkBob: string }> {
  const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits'])
  const out = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256',
      salt: new TextEncoder().encode('dr-hk-init'),
      info: new TextEncoder().encode('hk-init') },
    hkdfKey, 512
  )
  const bytes = new Uint8Array(out)
  return {
    hkAlice: bufferToBase64(bytes.slice(0, 32).buffer),
    hkBob: bufferToBase64(bytes.slice(32, 64).buffer)
  }
}

/**
 * Initialise the Double Ratchet for the "Alice" role (hat_code_1).
 * Supports hybrid PQ root key if pqShared is provided.
 */
export async function drInitAlice(
  sharedSecret: ArrayBuffer, peerSignedPrekey: string, algo: KeyAlgo,
  pqShared?: Uint8Array
): Promise<DRState> {
  // Derive root key — hybrid if PQ is available
  const rootInput = pqShared
    ? await deriveHybridRootKey(sharedSecret, pqShared)
    : sharedSecret
  const rootKeyRaw = await crypto.subtle.importKey('raw', rootInput, 'HKDF', false, ['deriveBits'])
  const rkBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256',
      salt: new TextEncoder().encode('dr-init'),
      info: new TextEncoder().encode('dr-root') },
    rootKeyRaw, 256
  )
  const RK = bufferToBase64(rkBits)

  // Initial header keys (both sides derive the same pair)
  const { hkAlice, hkBob } = await deriveInitialHeaderKeys(rootInput)

  const DHs = await GENERATE_DH(algo)
  const dhOut = await DH(DHs.priv, peerSignedPrekey)
  const { rk, ck, hk } = await KDF_RK(RK, dhOut)

  return {
    algo, pq: !!pqShared, RK: rk, CKs: ck, CKr: null,
    Ns: 0, Nr: 0, PN: 0,
    DHs, DHr: peerSignedPrekey,
    MKSKIPPED: {},
    HKs: hkAlice, HKr: null,
    NHKs: hk, NHKr: hkBob
  }
}

/**
 * Initialise the Double Ratchet for the "Bob" role (hat_code_2).
 * Supports hybrid PQ root key if pqShared is provided.
 */
export async function drInitBob(
  sharedSecret: ArrayBuffer,
  mySignedPrekey: { pub: string; priv: JsonWebKey },
  algo: KeyAlgo,
  pqShared?: Uint8Array
): Promise<DRState> {
  const rootInput = pqShared
    ? await deriveHybridRootKey(sharedSecret, pqShared)
    : sharedSecret
  const rootKeyRaw = await crypto.subtle.importKey('raw', rootInput, 'HKDF', false, ['deriveBits'])
  const rkBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256',
      salt: new TextEncoder().encode('dr-init'),
      info: new TextEncoder().encode('dr-root') },
    rootKeyRaw, 256
  )

  const { hkAlice, hkBob } = await deriveInitialHeaderKeys(rootInput)

  return {
    algo, pq: !!pqShared, RK: bufferToBase64(rkBits), CKs: null, CKr: null,
    Ns: 0, Nr: 0, PN: 0,
    DHs: mySignedPrekey, DHr: null,
    MKSKIPPED: {},
    HKs: null, HKr: null,
    NHKs: hkBob, NHKr: hkAlice
  }
}

// ── DH Ratchet Step ──

async function dhRatchetStep(state: DRState, newPeerDH: string): Promise<void> {
  state.PN = state.Ns
  state.Ns = 0
  state.Nr = 0
  state.DHr = newPeerDH

  // Promote next header keys to current
  state.HKr = state.NHKr
  state.HKs = state.NHKs

  const dhOut1 = await DH(state.DHs.priv, state.DHr)
  const kdf1 = await KDF_RK(state.RK, dhOut1)
  state.RK = kdf1.rk
  state.CKr = kdf1.ck
  state.NHKr = kdf1.hk       // next recv header key

  state.DHs = await GENERATE_DH(state.algo)
  const dhOut2 = await DH(state.DHs.priv, state.DHr)
  const kdf2 = await KDF_RK(state.RK, dhOut2)
  state.RK = kdf2.rk
  state.CKs = kdf2.ck
  state.NHKs = kdf2.hk       // next send header key
}

// ── Skip Message Keys ──

async function skipMessageKeys(state: DRState, until: number): Promise<void> {
  if (state.CKr === null) return
  if (until - state.Nr > MAX_SKIP) throw new Error('Too many skipped messages')
  while (state.Nr < until) {
    const { ck, mk } = await KDF_CK(state.CKr)
    const mkRaw = await crypto.subtle.exportKey('raw', mk)
    state.MKSKIPPED[`${state.DHr}:${state.Nr}`] = bufferToBase64(mkRaw)
    state.CKr = ck
    state.Nr++
  }
}

// ── Public Encrypt / Decrypt ──

// ── Header encryption helpers ──

async function encryptHeader(header: DRHeader, hk: string): Promise<string> {
  const headerJson = JSON.stringify(header)
  const encoded = new TextEncoder().encode(headerJson)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const keyRaw = base64ToBuffer(hk)
  const key = await crypto.subtle.importKey(
    'raw', keyRaw.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  )
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded)
  const out = new Uint8Array(12 + ct.byteLength)
  out.set(iv)
  out.set(new Uint8Array(ct), 12)
  return bufferToBase64(out.buffer)
}

async function tryDecryptHeader(encHeaderB64: string, hk: string | null): Promise<DRHeader | null> {
  if (!hk) return null
  try {
    const combined = base64ToBuffer(encHeaderB64)
    const iv = combined.slice(0, 12)
    const ct = combined.slice(12)
    const keyRaw = base64ToBuffer(hk)
    const key = await crypto.subtle.importKey(
      'raw', keyRaw.buffer as ArrayBuffer,
      { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    )
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)
    return JSON.parse(new TextDecoder().decode(pt))
  } catch {
    return null
  }
}

/**
 * Double-Ratchet encrypt with encrypted header.
 * Wire format: E<encHeaderB64>.<ctB64>
 */
export async function drEncrypt(
  state: DRState, paddedPayload: Uint8Array
): Promise<{ wireMessage: string; updatedState: DRState }> {
  const s = { ...state, DHs: { ...state.DHs }, MKSKIPPED: { ...state.MKSKIPPED } }
  if (s.CKs === null) throw new Error('Send chain not initialised')
  const { ck, mk } = await KDF_CK(s.CKs)
  s.CKs = ck
  const header: DRHeader = { dh: s.DHs.pub, pn: s.PN, n: s.Ns }
  s.Ns++
  const ciphertext = await encryptBinary(paddedPayload, mk)

  // Encrypt the header with the current send header key
  let wireMessage: string
  if (s.HKs) {
    const encHeader = await encryptHeader(header, s.HKs)
    wireMessage = `E${encHeader}.${ciphertext}`
  } else {
    // Fallback: plaintext header (first init before header keys ready)
    wireMessage = `D${btoa(JSON.stringify(header))}.${ciphertext}`
  }
  return { wireMessage, updatedState: s }
}

/**
 * Double-Ratchet decrypt with encrypted header.
 * Handles both E (encrypted header) and D (plaintext header, backward compat).
 */
export async function drDecrypt(
  state: DRState, wirePayload: string
): Promise<{ plaintext: Uint8Array; updatedState: DRState }> {
  const s: DRState = {
    ...state,
    DHs: { ...state.DHs },
    MKSKIPPED: { ...state.MKSKIPPED }
  }

  const prefix = wirePayload[0]
  const dotIdx = wirePayload.indexOf('.')
  const headerPart = wirePayload.substring(1, dotIdx)
  const ciphertext = wirePayload.substring(dotIdx + 1)

  let header: DRHeader
  let isNewChain = false

  if (prefix === 'E') {
    // Encrypted header — try current recv key, then next recv key
    const h1 = await tryDecryptHeader(headerPart, s.HKr)
    if (h1) {
      header = h1
      isNewChain = false
    } else {
      const h2 = await tryDecryptHeader(headerPart, s.NHKr)
      if (h2) {
        header = h2
        isNewChain = true
      } else {
        throw new Error('Header decryption failed with both HKr and NHKr')
      }
    }
  } else {
    // D prefix — plaintext header (backward compat)
    header = JSON.parse(atob(headerPart))
    isNewChain = header.dh !== s.DHr
  }

  // 1. Try skipped keys
  const skKey = `${header.dh}:${header.n}`
  if (s.MKSKIPPED[skKey]) {
    const mkRaw = base64ToBuffer(s.MKSKIPPED[skKey])
    const mk = await crypto.subtle.importKey(
      'raw', mkRaw.buffer as ArrayBuffer,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    )
    delete s.MKSKIPPED[skKey]
    const plaintext = await decryptBinary(ciphertext, mk)
    return { plaintext, updatedState: s }
  }

  // 2. New DH ratchet step?
  if (isNewChain) {
    await skipMessageKeys(s, header.pn)
    await dhRatchetStep(s, header.dh)
  }

  // 3. Skip within current chain
  await skipMessageKeys(s, header.n)

  // 4. Derive message key
  if (s.CKr === null) throw new Error('Receive chain not initialised')
  const { ck, mk } = await KDF_CK(s.CKr)
  s.CKr = ck
  s.Nr++

  const plaintext = await decryptBinary(ciphertext, mk)
  return { plaintext, updatedState: s }
}

// ── Double Ratchet Persistence ──

const _drBackupTimers: Record<string, ReturnType<typeof setTimeout>> = {}

export function saveDRState(pairId: number, state: DRState, peerDeviceId?: string): void {
  const key = peerDeviceId ? `dr_${pairId}_${peerDeviceId}` : `dr_${pairId}`
  localStorage.setItem(key, JSON.stringify(state))

  // Debounced server backup (5s after last write to avoid flooding during rapid message exchange)
  if (_drBackupTimers[key]) clearTimeout(_drBackupTimers[key])
  _drBackupTimers[key] = setTimeout(() => {
    delete _drBackupTimers[key]
    try {
      const sessionRaw = localStorage.getItem('hatSession')
      if (!sessionRaw) return
      const session = JSON.parse(sessionRaw)
      const hatCode = session?.hatCode
      const deviceId = localStorage.getItem('coh_device_id')
      if (!hatCode || !deviceId) return
      const privRaw = localStorage.getItem(`ecdh_${hatCode}`)
      if (!privRaw) return
      const privJwk = JSON.parse(privRaw)
      backupDRState(hatCode, deviceId, pairId, state, privJwk, peerDeviceId)
    } catch { /* non-critical */ }
  }, 5000)
}

export function loadDRState(pairId: number, peerDeviceId?: string): DRState | null {
  const key = peerDeviceId ? `dr_${pairId}_${peerDeviceId}` : `dr_${pairId}`
  const saved = localStorage.getItem(key)
  if (!saved) return null
  try { return JSON.parse(saved) } catch { return null }
}

// ── DR State Server Backup (encrypted, opaque to server) ──

const DR_BACKUP_API = 'https://api.example.com/api/v2/hats' // sanitized

async function deriveDRBackupKey(privJwk: JsonWebKey): Promise<CryptoKey> {
  const privJson = JSON.stringify(privJwk)
  const rawBytes = new TextEncoder().encode(privJson)
  const hash = await crypto.subtle.digest('SHA-256', rawBytes)
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

export async function backupDRState(
  hatCode: string, deviceId: string, pairId: number,
  state: DRState, privJwk: JsonWebKey, peerDeviceId?: string
): Promise<void> {
  try {
    const key = await deriveDRBackupKey(privJwk)
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const plain = new TextEncoder().encode(JSON.stringify(state))
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain)
    const combined = new Uint8Array(12 + ct.byteLength)
    combined.set(iv)
    combined.set(new Uint8Array(ct), 12)
    const encrypted = bufferToBase64(combined.buffer)

    fetch(`${DR_BACKUP_API}/dr-state/backup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hat_code: hatCode, device_id: deviceId, pair_id: pairId,
        encrypted_state: encrypted, peer_device_id: peerDeviceId || null,
      }),
    }).catch(() => {})
  } catch (e) {
    console.warn('DR backup failed (non-critical):', e)
  }
}

export async function restoreDRState(
  hatCode: string, deviceId: string, pairId: number,
  privJwk: JsonWebKey, peerDeviceId?: string
): Promise<DRState | null> {
  try {
    const peerDev = peerDeviceId || '__default__'
    const res = await fetch(
      `${DR_BACKUP_API}/dr-state/restore/${hatCode}/${deviceId}/${pairId}?peer_device_id=${peerDev}`
    )
    if (!res.ok) return null
    const data = await res.json()
    if (!data.found) return null

    const key = await deriveDRBackupKey(privJwk)
    const combined = base64ToBuffer(data.encrypted_state)
    const iv = combined.slice(0, 12)
    const ct = combined.slice(12)
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)
    return JSON.parse(new TextDecoder().decode(plain))
  } catch (e) {
    console.warn('DR restore failed:', e)
    return null
  }
}

// ── Sent Message Cache (for re-request mechanism) ──

const SENT_CACHE_KEY = 'coh_sent_cache'
const SENT_CACHE_MAX = 100

interface SentCacheEntry {
  pairId: number
  plaintext: string  // the sealed JSON before padding
  ts: number
}

export function cacheSentMessage(pairId: number, sealedPayload: string): void {
  try {
    const raw = sessionStorage.getItem(SENT_CACHE_KEY)
    const entries: SentCacheEntry[] = raw ? JSON.parse(raw) : []
    entries.push({ pairId, plaintext: sealedPayload, ts: Date.now() })
    // Keep only the newest entries
    while (entries.length > SENT_CACHE_MAX) entries.shift()
    sessionStorage.setItem(SENT_CACHE_KEY, JSON.stringify(entries))
  } catch { /* non-critical */ }
}

export function getCachedSentMessages(pairId: number): SentCacheEntry[] {
  try {
    const raw = sessionStorage.getItem(SENT_CACHE_KEY)
    if (!raw) return []
    const entries: SentCacheEntry[] = JSON.parse(raw)
    // Only return entries from the last 24h for the given pair
    const cutoff = Date.now() - 24 * 60 * 60 * 1000
    return entries.filter(e => e.pairId === pairId && e.ts > cutoff)
  } catch { return [] }
}

// ════════════════════════════════════════════════════════════════
// #4  Encrypted localStorage (optional PIN protection)
// ════════════════════════════════════════════════════════════════
// When a PIN is set, all sensitive keys are wrapped with an AES key
// derived from the PIN via PBKDF2. The derived key is cached in
// sessionStorage so the PIN is only needed once per browser session.

const PBKDF2_ITERATIONS = 600_000

export async function deriveStorageKey(pin: string, salt: Uint8Array): Promise<CryptoKey> {
  const raw = new TextEncoder().encode(pin)
  const baseKey = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt.buffer as ArrayBuffer, iterations: PBKDF2_ITERATIONS },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )
}

export async function setupPin(pin: string): Promise<void> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key = await deriveStorageKey(pin, salt)
  localStorage.setItem('pin_salt', bufferToBase64(salt.buffer))
  // Store a known-plaintext check so we can verify the PIN later
  const check = await encryptText('pin-ok', key)
  localStorage.setItem('pin_check', check)
  // Cache derived key in sessionStorage for this browser session
  const rawKey = await crypto.subtle.exportKey('raw', key)
  sessionStorage.setItem('_sk', bufferToBase64(rawKey))
}

export async function verifyPin(pin: string): Promise<boolean> {
  const saltB64 = localStorage.getItem('pin_salt')
  const checkCt = localStorage.getItem('pin_check')
  if (!saltB64 || !checkCt) return false
  const salt = base64ToBuffer(saltB64)
  const key = await deriveStorageKey(pin, salt)
  try {
    const pt = await decryptText(checkCt, key)
    if (pt !== 'pin-ok') return false
    const rawKey = await crypto.subtle.exportKey('raw', key)
    sessionStorage.setItem('_sk', bufferToBase64(rawKey))
    return true
  } catch {
    return false
  }
}

export function isPinSet(): boolean {
  return !!localStorage.getItem('pin_salt')
}

export function isPinUnlocked(): boolean {
  return !!sessionStorage.getItem('_sk')
}

export async function getStorageKey(): Promise<CryptoKey | null> {
  const b64 = sessionStorage.getItem('_sk')
  if (!b64) return null
  const raw = base64ToBuffer(b64)
  return crypto.subtle.importKey(
    'raw', raw.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  )
}

/** Encrypt a string value before storing in localStorage. */
export async function secureSet(key: string, value: string): Promise<void> {
  const sk = await getStorageKey()
  if (sk) {
    const ct = await encryptText(value, sk)
    localStorage.setItem(key, 'ENC:' + ct)
  } else {
    localStorage.setItem(key, value)
  }
}

/** Decrypt a string value read from localStorage. */
export async function secureGet(key: string): Promise<string | null> {
  const raw = localStorage.getItem(key)
  if (!raw) return null
  if (raw.startsWith('ENC:')) {
    const sk = await getStorageKey()
    if (!sk) return null
    try { return await decryptText(raw.slice(4), sk) } catch { return null }
  }
  return raw
}

export function clearPin(): void {
  localStorage.removeItem('pin_salt')
  localStorage.removeItem('pin_check')
  sessionStorage.removeItem('_sk')
}

// ════════════════════════════════════════════════════════════════
// #11  Client-Side Audit Log — tamper-evident local crypto log
// ════════════════════════════════════════════════════════════════

export interface AuditEntry {
  ts: number          // timestamp (ms since epoch)
  op: string          // operation: keygen | encrypt | decrypt | ratchet | pq_encap | pq_decap | key_change | etc.
  detail: string      // human-readable detail
  chain?: string      // SHA-256 hash of previous entry (tamper-evident chain)
}

const AUDIT_KEY = 'hats_audit_log'
const AUDIT_MAX = 500 // keep last 500 entries

function getAuditLog(): AuditEntry[] {
  try {
    const raw = localStorage.getItem(AUDIT_KEY)
    if (!raw) return []
    return JSON.parse(raw) as AuditEntry[]
  } catch { return [] }
}

async function computeChain(prev: AuditEntry | null): Promise<string> {
  if (!prev) return '0'.repeat(64)
  const payload = `${prev.ts}|${prev.op}|${prev.detail}|${prev.chain || ''}`
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload))
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')
}

export async function auditLog(op: string, detail: string): Promise<void> {
  const log = getAuditLog()
  const prev = log.length > 0 ? log[log.length - 1] : null
  const chain = await computeChain(prev)
  const entry: AuditEntry = { ts: Date.now(), op, detail, chain }
  log.push(entry)
  // Trim to max size (keep most recent)
  if (log.length > AUDIT_MAX) log.splice(0, log.length - AUDIT_MAX)
  localStorage.setItem(AUDIT_KEY, JSON.stringify(log))
}

export function readAuditLog(): AuditEntry[] {
  return getAuditLog()
}

export async function verifyAuditChain(): Promise<{ valid: boolean; brokenAt?: number }> {
  const log = getAuditLog()
  for (let i = 1; i < log.length; i++) {
    const expected = await computeChain(log[i - 1])
    if (log[i].chain !== expected) return { valid: false, brokenAt: i }
  }
  return { valid: true }
}

export function clearAuditLog(): void {
  localStorage.removeItem(AUDIT_KEY)
}

// ════════════════════════════════════════════════════════════════
// #12  Key Rotation Alerts — detect peer public key changes
// ════════════════════════════════════════════════════════════════

const KNOWN_KEYS_PREFIX = 'known_peer_key_'

export function checkPeerKeyChange(peerHatCode: string, currentPubKeyB64: string): {
  changed: boolean; previousKey: string | null
} {
  const storageKey = `${KNOWN_KEYS_PREFIX}${peerHatCode}`
  const stored = localStorage.getItem(storageKey)
  if (!stored) {
    // First time seeing this peer — store and return no change
    localStorage.setItem(storageKey, currentPubKeyB64)
    return { changed: false, previousKey: null }
  }
  if (stored !== currentPubKeyB64) {
    // Key changed! Update stored key but flag it
    localStorage.setItem(storageKey, currentPubKeyB64)
    return { changed: true, previousKey: stored }
  }
  return { changed: false, previousKey: null }
}

// ════════════════════════════════════════════════════════════════
// #5  Steganography — hide ciphertext inside PNG images (LSB)
// ════════════════════════════════════════════════════════════════

const STEGO_MAGIC = new Uint8Array([0x48, 0x41, 0x54, 0x53]) // "HATS"

/**
 * Embed arbitrary data into a PNG image using LSB steganography.
 * Image size is calculated dynamically to keep the PNG small.
 * Uses standard HTMLCanvasElement for maximum browser compatibility.
 */
export async function embedInImage(data: Uint8Array): Promise<Blob> {
  // Build payload: MAGIC(4) + LENGTH(4) + DATA
  const payload = new Uint8Array(8 + data.length)
  payload.set(STEGO_MAGIC, 0)
  new DataView(payload.buffer).setUint32(4, data.length)
  payload.set(data, 8)

  // Calculate minimum image size (1 pixel per bit, using R channel LSB)
  const totalBits = payload.length * 8
  const totalPixels = Math.max(totalBits + 64, 1024) // min 32x32
  const side = Math.ceil(Math.sqrt(totalPixels))

  const canvas = document.createElement('canvas')
  canvas.width = side
  canvas.height = side
  const ctx = canvas.getContext('2d')!

  const imageData = ctx.createImageData(side, side)
  // Fill with random data (cover noise) — chunk to stay within getRandomValues 64KB limit
  const arr = imageData.data
  const CHUNK = 65536
  for (let offset = 0; offset < arr.length; offset += CHUNK) {
    const end = Math.min(offset + CHUNK, arr.length)
    crypto.getRandomValues(arr.subarray(offset, end))
  }
  for (let i = 3; i < arr.length; i += 4) arr[i] = 255 // full alpha

  if (totalBits > side * side) throw new Error('Data too large for image')

  for (let i = 0; i < totalBits; i++) {
    const bit = (payload[Math.floor(i / 8)] >> (7 - (i % 8))) & 1
    const px = i * 4
    arr[px] = (arr[px] & 0xFE) | bit
  }
  ctx.putImageData(imageData, 0, 0)

  return new Promise<Blob>((resolve, reject) => {
    canvas.toBlob(
      blob => blob ? resolve(blob) : reject(new Error('Canvas toBlob failed')),
      'image/png'
    )
  })
}

/**
 * Extract hidden data from a steganographic PNG image.
 * Returns null if the image doesn't contain a valid HATS header.
 */
export async function extractFromImage(imageBlob: Blob): Promise<Uint8Array | null> {
  const bitmap = await createImageBitmap(imageBlob)
  const canvas = document.createElement('canvas')
  canvas.width = bitmap.width
  canvas.height = bitmap.height
  const ctx = canvas.getContext('2d')!
  ctx.drawImage(bitmap, 0, 0)
  const { data: px } = ctx.getImageData(0, 0, bitmap.width, bitmap.height)

  function readBits(startBit: number, numBytes: number): Uint8Array {
    const out = new Uint8Array(numBytes)
    for (let i = 0; i < numBytes * 8; i++) {
      const bit = px[(startBit + i) * 4] & 1
      out[Math.floor(i / 8)] |= bit << (7 - (i % 8))
    }
    return out
  }

  const magic = readBits(0, 4)
  if (magic[0] !== 0x48 || magic[1] !== 0x41 || magic[2] !== 0x54 || magic[3] !== 0x53) return null

  const lenBytes = readBits(32, 4)
  const len = new DataView(lenBytes.buffer).getUint32(0)
  if (64 + len * 8 > bitmap.width * bitmap.height) return null

  return readBits(64, len)
}

// ════════════════════════════════════════════════════════════════
// #8  Multi-Path Delivery — XOR-split across channels
// ════════════════════════════════════════════════════════════════

/** Split data into two XOR shares. share1 is random; share2 = data XOR share1. */
export function xorSplit(data: Uint8Array): { share1: Uint8Array; share2: Uint8Array } {
  const share1 = new Uint8Array(data.length)
  crypto.getRandomValues(share1)
  const share2 = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i++) share2[i] = data[i] ^ share1[i]
  return { share1, share2 }
}

/** Reconstruct data from two XOR shares. */
export function xorCombine(share1: Uint8Array, share2: Uint8Array): Uint8Array {
  const out = new Uint8Array(share1.length)
  for (let i = 0; i < share1.length; i++) out[i] = share1[i] ^ share2[i]
  return out
}

// ════════════════════════════════════════════════════════════════
// #6  Time-Locked Encryption — combine URL key + server fragment
// ════════════════════════════════════════════════════════════════

/** Generate a random time-lock fragment (32 bytes, base64). */
export function generateTimeLockFragment(): string {
  const frag = new Uint8Array(32)
  crypto.getRandomValues(frag)
  return bufferToBase64(frag.buffer as ArrayBuffer)
}

/** Derive the actual decryption key from URL key + server fragment. */
export async function deriveTimeLockKey(
  urlKey: CryptoKey, fragmentB64: string
): Promise<CryptoKey> {
  const urlKeyRaw = await crypto.subtle.exportKey('raw', urlKey)
  const fragBytes = base64ToBuffer(fragmentB64)
  const combined = new Uint8Array(urlKeyRaw.byteLength + fragBytes.length)
  combined.set(new Uint8Array(urlKeyRaw), 0)
  combined.set(fragBytes, urlKeyRaw.byteLength)

  const hkdfKey = await crypto.subtle.importKey('raw', combined, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256',
      salt: new TextEncoder().encode('time-lock'),
      info: new TextEncoder().encode('hats-tl') },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

// ════════════════════════════════════════════════════════════════
// EchoDrop — passphrase-derived encryption
// ════════════════════════════════════════════════════════════════

function normalizePassphrase(raw: string): string {
  return raw.toLowerCase().trim().replace(/\s+/g, ' ')
}

export async function hashPassphrase(passphrase: string): Promise<string> {
  const normalized = normalizePassphrase(passphrase)
  const encoded = new TextEncoder().encode(normalized)
  const hash = await crypto.subtle.digest('SHA-256', encoded)
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')
}

export async function deriveKeyFromPassphrase(passphrase: string, salt: string): Promise<CryptoKey> {
  const normalized = normalizePassphrase(passphrase)
  const encoded = new TextEncoder().encode(normalized)
  const saltBytes = new TextEncoder().encode(salt)
  const baseKey = await crypto.subtle.importKey('raw', encoded, 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes.buffer as ArrayBuffer, iterations: PBKDF2_ITERATIONS },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )
}
