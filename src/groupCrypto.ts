/**
 * Sender Keys E2E encryption for Group Chat
 *
 * Each group member generates a sender key (chain key + signature key pair).
 * The sender key is distributed to all other members encrypted via their
 * existing 1:1 shared keys. Messages are encrypted once with the sender's
 * chain key (HMAC ratchet + AES-256-GCM) and verified with ECDSA P-256.
 */

// ─── Types ────────────────────────────────────────────────────

export interface SenderKey {
  chainKey: string        // hex-encoded 32-byte chain key
  signPublicKey: string   // base64 SPKI
  signPrivateKey: string  // base64 PKCS8
  generation: number
  chainIndex: number
}

export interface SenderKeyPublic {
  chainKey: string
  signPublicKey: string
  generation: number
  chainIndex: number
}

export interface EncryptedEnvelope {
  ct: string   // base64 ciphertext
  iv: string   // base64 12-byte IV
  sig: string  // base64 ECDSA signature
  gen: number  // key generation
  idx: number  // chain index
}

// ─── Helpers ──────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function toBase64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
}

function fromBase64(str: string): ArrayBuffer {
  const bin = atob(str)
  const buf = new ArrayBuffer(bin.length)
  const view = new Uint8Array(buf)
  for (let i = 0; i < bin.length; i++) view[i] = bin.charCodeAt(i)
  return buf
}

// ─── Key Generation ───────────────────────────────────────────

export async function generateSenderKey(): Promise<SenderKey> {
  const chainKeyBytes = crypto.getRandomValues(new Uint8Array(32))

  const signKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )

  const pubExported = await crypto.subtle.exportKey('spki', signKeyPair.publicKey)
  const privExported = await crypto.subtle.exportKey('pkcs8', signKeyPair.privateKey)

  return {
    chainKey: bytesToHex(chainKeyBytes),
    signPublicKey: toBase64(pubExported),
    signPrivateKey: toBase64(privExported),
    generation: 0,
    chainIndex: 0,
  }
}

export function extractPublicSenderKey(sk: SenderKey): SenderKeyPublic {
  return {
    chainKey: sk.chainKey,
    signPublicKey: sk.signPublicKey,
    generation: sk.generation,
    chainIndex: sk.chainIndex,
  }
}

// ─── HMAC Chain Ratchet ───────────────────────────────────────

async function ratchetChainKey(chainKeyHex: string): Promise<{ messageKey: CryptoKey; nextChainKeyHex: string }> {
  const ck = hexToBytes(chainKeyHex)
  const baseKey = await crypto.subtle.importKey('raw', ck.buffer as ArrayBuffer, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])

  const mkBuf = await crypto.subtle.sign('HMAC', baseKey, new TextEncoder().encode('MessageKey'))
  const nckBuf = await crypto.subtle.sign('HMAC', baseKey, new TextEncoder().encode('ChainKey'))

  const messageKey = await crypto.subtle.importKey('raw', mkBuf, 'AES-GCM', false, ['encrypt', 'decrypt'])
  return { messageKey, nextChainKeyHex: bytesToHex(new Uint8Array(nckBuf)) }
}

// Advance chain to a target index, returning the message key at that index
async function advanceChain(chainKeyHex: string, currentIdx: number, targetIdx: number): Promise<{ messageKey: CryptoKey; chainKeyHex: string; chainIndex: number }> {
  let ck = chainKeyHex
  let mk: CryptoKey | null = null
  for (let i = currentIdx; i <= targetIdx; i++) {
    const r = await ratchetChainKey(ck)
    mk = r.messageKey
    ck = r.nextChainKeyHex
  }
  return { messageKey: mk!, chainKeyHex: ck, chainIndex: targetIdx + 1 }
}

// ─── Encrypt ──────────────────────────────────────────────────

export async function senderKeyEncrypt(
  plaintext: string,
  senderKey: SenderKey,
): Promise<{ envelope: EncryptedEnvelope; updatedKey: SenderKey }> {
  const { messageKey, nextChainKeyHex } = await ratchetChainKey(senderKey.chainKey)
  const ivBuf = new ArrayBuffer(12)
  const ivView = new Uint8Array(ivBuf)
  crypto.getRandomValues(ivView)
  const encoded = new TextEncoder().encode(plaintext)

  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivBuf }, messageKey, encoded)

  const signKey = await crypto.subtle.importKey(
    'pkcs8', fromBase64(senderKey.signPrivateKey),
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'],
  )
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, signKey, ciphertext,
  )

  const envelope: EncryptedEnvelope = {
    ct: toBase64(ciphertext),
    iv: toBase64(ivBuf),
    sig: toBase64(signature),
    gen: senderKey.generation,
    idx: senderKey.chainIndex,
  }

  const updatedKey: SenderKey = {
    ...senderKey,
    chainKey: nextChainKeyHex,
    chainIndex: senderKey.chainIndex + 1,
  }

  return { envelope, updatedKey }
}

// ─── Decrypt ──────────────────────────────────────────────────

export async function senderKeyDecrypt(
  envelope: EncryptedEnvelope,
  peerKey: SenderKeyPublic,
): Promise<{ plaintext: string; updatedKey: SenderKeyPublic }> {
  const ciphertext = fromBase64(envelope.ct)

  const verifyKey = await crypto.subtle.importKey(
    'spki', fromBase64(peerKey.signPublicKey),
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
  )
  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' }, verifyKey, fromBase64(envelope.sig), ciphertext as ArrayBuffer,
  )
  if (!valid) throw new Error('Sender key signature verification failed')

  const { messageKey, chainKeyHex, chainIndex } = await advanceChain(
    peerKey.chainKey, peerKey.chainIndex, envelope.idx,
  )

  const ivBuf = fromBase64(envelope.iv)
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBuf }, messageKey, ciphertext)
  const plaintext = new TextDecoder().decode(decrypted)

  return {
    plaintext,
    updatedKey: { ...peerKey, chainKey: chainKeyHex, chainIndex },
  }
}

// ─── Storage ──────────────────────────────────────────────────

export function saveSelfSenderKey(groupId: number, key: SenderKey): void {
  localStorage.setItem(`sk_${groupId}_self`, JSON.stringify(key))
}

export function loadSelfSenderKey(groupId: number): SenderKey | null {
  const raw = localStorage.getItem(`sk_${groupId}_self`)
  return raw ? JSON.parse(raw) : null
}

export function savePeerSenderKey(groupId: number, hatCode: string, key: SenderKeyPublic): void {
  localStorage.setItem(`sk_${groupId}_${hatCode}`, JSON.stringify(key))
}

export function loadPeerSenderKey(groupId: number, hatCode: string): SenderKeyPublic | null {
  const raw = localStorage.getItem(`sk_${groupId}_${hatCode}`)
  return raw ? JSON.parse(raw) : null
}

export function clearGroupKeys(groupId: number): void {
  const prefix = `sk_${groupId}_`
  const toRemove: string[] = []
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)
    if (k?.startsWith(prefix)) toRemove.push(k)
  }
  toRemove.forEach(k => localStorage.removeItem(k))
}

// ─── Key Serialization (for distribution) ─────────────────────

export function serializeSenderKeyForDistribution(sk: SenderKey): string {
  const pub = extractPublicSenderKey(sk)
  return JSON.stringify(pub)
}

export function deserializeSenderKeyFromDistribution(data: string): SenderKeyPublic {
  return JSON.parse(data) as SenderKeyPublic
}
