/**
 * Secure Transfer encryption core. Runs in the browser and in Node 20+ (both have WebCrypto).
 *
 * - Every person has an ECDH P-256 key pair made in their browser. The private key is stored only wrapped
 *   (AES-256-GCM under a PBKDF2-SHA-256 key from their password).
 * - Every file gets a random AES-256-GCM key. The file is encrypted in 1 MiB chunks; each chunk's IV is a
 *   per-file random prefix + chunk counter, and its additional data binds the chunk index and a "last chunk"
 *   flag, so chunks cannot be reordered, dropped or truncated without decryption failing.
 * - The file key is wrapped separately for each reader and for the commission recovery key:
 *   ephemeral ECDH -> HKDF-SHA-256 -> AES-KW.
 * - The file name is encrypted with the file key too. A SHA-256 fingerprint of the plaintext is kept so both
 *   sides can confirm a file arrived unchanged.
 */
const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const PBKDF2_ITERATIONS = 600000;
export const CHUNK_SIZE = 1024 * 1024;
const MAGIC = [0x48, 0x53, 0x54, 0x31]; // "HST1"
const HEADER_LEN = 4 + 8 + 4;           // magic, IV prefix, chunk size
const TAG_LEN = 16;
const WRAP_INFO = 'HCEC Secure Transfer file key v1';

// ---------- encoding helpers ----------
export function toB64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
export function fromB64(b64) {
  const s = atob(b64);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}
function randomBytes(n) { return globalThis.crypto.getRandomValues(new Uint8Array(n)); }
function hex(buf) { return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join(''); }

// ---------- personal key pairs ----------
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };

export async function generateKeyPair() {
  const kp = await subtle.generateKey(ECDH, true, ['deriveBits']);
  return { publicJwk: await exportPublic(kp.publicKey), privateKey: kp.privateKey };
}
async function exportPublic(key) {
  const { kty, crv, x, y } = await subtle.exportKey('jwk', key);
  return { kty, crv, x, y };
}
export function importPublic(jwk) {
  return subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, ECDH, true, []);
}
/** Short, human-checkable fingerprint of a public key (to compare over the phone if ever needed). */
export async function publicKeyFingerprint(jwk) {
  const h = await subtle.digest('SHA-256', enc.encode(`${jwk.crv}:${jwk.x}:${jwk.y}`));
  return hex(h).slice(0, 20).match(/.{4}/g).join(' ');
}

async function passwordKey(password, salt, iterations) {
  const base = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Wrap a private key under a password. Returns a plain object safe to store. */
export async function wrapPrivateKey(privateKey, password, iterations = PBKDF2_ITERATIONS) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const pkcs8 = await subtle.exportKey('pkcs8', privateKey);
  const k = await passwordKey(password, salt, iterations);
  const wrapped = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode('private key v1') }, k, pkcs8);
  return { wrapped: toB64(wrapped), salt: toB64(salt), iv: toB64(iv), iterations };
}

/** Unwrap a stored private key. Throws if the password is wrong. */
export async function unwrapPrivateKey(record, password, extractable = false) {
  const k = await passwordKey(password, fromB64(record.salt), record.iterations);
  let pkcs8;
  try {
    pkcs8 = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(record.iv), additionalData: enc.encode('private key v1') },
      k, fromB64(record.wrapped));
  } catch (e) {
    throw new Error('Wrong password for this key.');
  }
  return subtle.importKey('pkcs8', pkcs8, ECDH, extractable, ['deriveBits']);
}

// ---------- file keys, wrapped per recipient ----------
export async function newFileKey() {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

async function kekFor(privateKey, publicKey, salt, recipientId) {
  const bits = await subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  const hk = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(`${WRAP_INFO}|${recipientId}`) },
    hk, { name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}

/** Wrap a file key for one recipient (a person's uid, or "recovery"). */
export async function wrapFileKey(fileKey, recipientId, recipientPublicJwk) {
  const eph = await subtle.generateKey(ECDH, true, ['deriveBits']);
  const salt = randomBytes(16);
  const kek = await kekFor(eph.privateKey, await importPublic(recipientPublicJwk), salt, recipientId);
  const wrapped = await subtle.wrapKey('raw', fileKey, kek, 'AES-KW');
  return { epk: await exportPublic(eph.publicKey), salt: toB64(salt), wrapped: toB64(wrapped) };
}

/** Unwrap a file key with the recipient's private key. */
export async function unwrapFileKey(entry, recipientId, privateKey, extractable = false) {
  const kek = await kekFor(privateKey, await importPublic(entry.epk), fromB64(entry.salt), recipientId);
  try {
    return await subtle.unwrapKey('raw', fromB64(entry.wrapped), kek, 'AES-KW',
      { name: 'AES-GCM', length: 256 }, extractable, ['encrypt', 'decrypt']);
  } catch (e) {
    throw new Error('This key cannot open the file.');
  }
}

// ---------- small text (file names, messages, notes) ----------
export async function encryptText(key, text, context) {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(context) }, key, enc.encode(text));
  return { iv: toB64(iv), ct: toB64(ct) };
}
export async function decryptText(key, box, context) {
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(box.iv), additionalData: enc.encode(context) },
    key, fromB64(box.ct));
  return dec.decode(pt);
}

// ---------- file contents ----------
function chunkIv(prefix, index) {
  const iv = new Uint8Array(12);
  iv.set(prefix, 0);
  new DataView(iv.buffer).setUint32(8, index);
  return iv;
}
function chunkAad(index, last) {
  const a = new Uint8Array(9);
  a.set(MAGIC, 0);
  new DataView(a.buffer).setUint32(4, index);
  a[8] = last ? 1 : 0;
  return a;
}

/**
 * Encrypt file bytes. `data` is a Uint8Array (or ArrayBuffer). Returns { ciphertext: Uint8Array,
 * sha256: hex of the plaintext }. onProgress(fraction) is optional.
 */
export async function encryptFile(fileKey, data, onProgress) {
  const pt = data instanceof Uint8Array ? data : new Uint8Array(data);
  const count = Math.max(1, Math.ceil(pt.length / CHUNK_SIZE));
  if (count > 0xffffffff) throw new Error('File too large.');
  const prefix = randomBytes(8);
  const out = new Uint8Array(HEADER_LEN + pt.length + count * TAG_LEN);
  out.set(MAGIC, 0);
  out.set(prefix, 4);
  new DataView(out.buffer).setUint32(12, CHUNK_SIZE);
  let w = HEADER_LEN;
  for (let i = 0; i < count; i++) {
    const chunk = pt.subarray(i * CHUNK_SIZE, Math.min(pt.length, (i + 1) * CHUNK_SIZE));
    const ct = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: chunkIv(prefix, i), additionalData: chunkAad(i, i === count - 1) }, fileKey, chunk));
    out.set(ct, w);
    w += ct.length;
    if (onProgress) onProgress((i + 1) / count);
  }
  const sha256 = hex(await subtle.digest('SHA-256', pt));
  return { ciphertext: out, sha256 };
}

/** Decrypt what encryptFile produced. Throws on any tampering. Returns { data, sha256 }. */
export async function decryptFile(fileKey, ciphertext, onProgress) {
  const ct = ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext);
  if (ct.length < HEADER_LEN + TAG_LEN || MAGIC.some((b, i) => ct[i] !== b)) throw new Error('Not a Secure Transfer file.');
  const prefix = ct.subarray(4, 12);
  const chunkSize = new DataView(ct.buffer, ct.byteOffset).getUint32(12);
  const body = ct.length - HEADER_LEN;
  const full = chunkSize + TAG_LEN;
  const count = Math.max(1, Math.ceil(body / full));
  const out = new Uint8Array(body - count * TAG_LEN);
  let r = HEADER_LEN, w = 0;
  for (let i = 0; i < count; i++) {
    const len = Math.min(full, ct.length - r);
    let pt;
    try {
      pt = new Uint8Array(await subtle.decrypt(
        { name: 'AES-GCM', iv: chunkIv(prefix, i), additionalData: chunkAad(i, i === count - 1) },
        fileKey, ct.subarray(r, r + len)));
    } catch (e) {
      throw new Error('This file was changed or damaged after it was encrypted.');
    }
    out.set(pt, w);
    w += pt.length; r += len;
    if (onProgress) onProgress((i + 1) / count);
  }
  return { data: out, sha256: hex(await subtle.digest('SHA-256', out)) };
}

export async function sha256Hex(data) {
  return hex(await subtle.digest('SHA-256', data instanceof Uint8Array ? data : new Uint8Array(data)));
}

// ---------- one call for the common case ----------
/**
 * Encrypt a file for a set of recipients. recipients: [{ id, publicJwk }], must include "recovery".
 * Returns { ciphertext, sha256, name: {iv, ct}, keys: { [id]: wrappedEntry } }.
 */
export async function sealFile(data, fileName, recipients, onProgress) {
  if (!recipients.some((r) => r.id === 'recovery')) throw new Error('The recovery key must be a recipient.');
  const fileKey = await newFileKey();
  const { ciphertext, sha256 } = await encryptFile(fileKey, data, onProgress);
  const name = await encryptText(fileKey, fileName, 'file name v1');
  const keys = {};
  for (const r of recipients) keys[r.id] = await wrapFileKey(fileKey, r.id, r.publicJwk);
  return { ciphertext, sha256, name, keys };
}

/** Open a sealed file as recipient `id`. Checks the fingerprint. Returns { data, fileName, sha256 }. */
export async function openFile(sealed, id, privateKey, onProgress) {
  const entry = sealed.keys[id];
  if (!entry) throw new Error('This file was not shared with you.');
  const fileKey = await unwrapFileKey(entry, id, privateKey);
  const fileName = await decryptText(fileKey, sealed.name, 'file name v1');
  const { data, sha256 } = await decryptFile(fileKey, sealed.ciphertext, onProgress);
  if (sealed.sha256 && sha256 !== sealed.sha256) throw new Error('Fingerprint does not match.');
  return { data, fileName, sha256 };
}
