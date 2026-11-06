// Pure helpers shared by the functions. No Firebase imports here, so they test without emulators.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const DAY_MS = 864e5;
export const ALLOWED_DAYS = [1, 7, 14, 30, 60, 90, 180];
export const MAX_FILE_BYTES = 250 * 1024 * 1024;
export const PERMS = ['download', 'upload', 'both'];

/** File types people may send. Encrypted contents can't be scanned, so we limit by extension. */
export const ALLOWED_EXTENSIONS = [
  'txt', 'csv', 'tsv', 'json', 'xml', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'odt', 'ods',
  'png', 'jpg', 'jpeg', 'gif', 'tif', 'tiff', 'heic', 'zip', 'geojson', 'kml', 'kmz', 'shp', 'dbf', 'prj', 'md',
];
export function extensionAllowed(name) {
  const m = /\.([a-z0-9]+)$/i.exec(String(name || ''));
  return !!m && ALLOWED_EXTENSIONS.includes(m[1].toLowerCase());
}

export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().filter((k) => value[k] !== undefined)
    .map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}

/** Hash for one audit entry, chained to the previous entry's hash. */
export function chainHash(prevHash, seq, entry) {
  return createHash('sha256').update(`${prevHash}|${seq}|${canonical(entry)}`).digest('hex');
}
export const GENESIS = '0'.repeat(64);

/**
 * Check a run of audit entries (sorted by seq, each { seq, hash, prevHash, entry }).
 * Returns { ok: true } or { ok: false, seq, reason }.
 */
export function verifyChain(rows, startPrev = GENESIS, startSeq = 1) {
  let prev = startPrev, expect = startSeq;
  for (const r of rows) {
    if (r.seq !== expect) return { ok: false, seq: expect, reason: 'missing entry' };
    if (r.prevHash !== prev) return { ok: false, seq: r.seq, reason: 'chain broken' };
    if (chainHash(prev, r.seq, r.entry) !== r.hash) return { ok: false, seq: r.seq, reason: 'entry changed' };
    prev = r.hash; expect++;
  }
  return { ok: true, last: prev, count: rows.length };
}

export function csvCell(v) {
  const s = v === null || v === undefined ? '' : String(v);
  // Guard against spreadsheet formula injection as well as quoting.
  const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
  return /[",\n\r]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe;
}
export function toCsv(header, rows) {
  return [header, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
}

export function expiresAt(uploadedMs, days) { return uploadedMs + days * DAY_MS; }

/** What a folder member may do. member = { perm, until (ms) } or undefined. */
export function access(member, nowMs, isAdmin) {
  if (isAdmin) return { read: true, upload: true, readAll: true, admin: true };
  if (!member || !(member.until > nowMs)) return { read: false, upload: false, readAll: false };
  return {
    read: true,
    upload: member.perm === 'upload' || member.perm === 'both',
    readAll: member.perm === 'download' || member.perm === 'both',
  };
}

/** May this person download this file? file = { uploadedBy, visibleTo?: [uid], downloads, maxDownloads } */
export function mayDownload(file, uid, acc) {
  if (!acc.read) return { ok: false, why: 'You no longer have access to this folder.' };
  const own = file.uploadedBy === uid;
  if (!own && !acc.readAll) return { ok: false, why: 'This file was not shared with you.' };
  if (!own && !acc.admin && Array.isArray(file.visibleTo) && file.visibleTo.length && !file.visibleTo.includes(uid)) {
    return { ok: false, why: 'This file was not shared with you.' };
  }
  if (!own && !acc.admin && file.maxDownloads && (file.downloads || 0) >= file.maxDownloads) {
    return { ok: false, why: 'This file has reached its download limit.' };
  }
  return { ok: true };
}

export function newId(bytes = 12) { return randomBytes(bytes).toString('base64url'); }

/** Drop-off codes: 10 characters people can read aloud, stored only as a salted hash. */
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
export function newDropoffCode() {
  const b = randomBytes(10);
  let s = '';
  for (let i = 0; i < 10; i++) s += CODE_ALPHABET[b[i] % CODE_ALPHABET.length];
  return s.slice(0, 5) + '-' + s.slice(5);
}
export function normalizeCode(code) { return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, ''); }
export function hashCode(code, salt) {
  return createHash('sha256').update(salt + ':' + normalizeCode(code)).digest('hex');
}
export function codeMatches(code, salt, hash) {
  const a = Buffer.from(hashCode(code, salt), 'hex'), b = Buffer.from(String(hash), 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

export function cleanText(s, max) {
  return String(s ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
}
export function isEmail(s) { return /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(String(s || '')); }
