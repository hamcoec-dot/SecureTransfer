// Secure Transfer Cloud Functions. Every change to who can see what goes through here, and every action is
// written to the tamper-evident audit log. File contents are encrypted in the browser; nothing here can read them.
import { initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore, FieldValue, Timestamp } from 'firebase-admin/firestore';
import { getStorage } from 'firebase-admin/storage';
import { onCall, HttpsError } from 'firebase-functions/v2/https';
import { onSchedule } from 'firebase-functions/v2/scheduler';
import { beforeUserCreated, beforeUserSignedIn, HttpsError as IdentityError } from 'firebase-functions/v2/identity';
import { setGlobalOptions, logger } from 'firebase-functions/v2';
import { createHash, timingSafeEqual } from 'node:crypto';
import * as L from './lib.js';
import * as WA from '@simplewebauthn/server';
import { sendMail, mailConfigured, SMTP_URL } from './mail.js';

initializeApp();
setGlobalOptions({ region: 'us-east1', maxInstances: 5, memory: '256MiB' });
const db = getFirestore();
const bucket = () => getStorage().bucket();
const callOpts = { enforceAppCheck: process.env.FUNCTIONS_EMULATOR !== 'true', secrets: [SMTP_URL] };
const PORTAL_URL = 'https://govotehamiltontn.gov/SecureTransfer/';

// ---------------------------------------------------------------- audit log (hash-chained)
async function audit(action, details, req) {
  const entry = {
    at: Date.now(),
    action,
    actor: req?.auth?.uid || details.actor || 'system',
    actorEmail: req?.auth?.token?.email || details.actorEmail || '',
    ip: req?.rawRequest?.ip || details.ip || '',
    ua: String(req?.rawRequest?.headers?.['user-agent'] || details.ua || '').slice(0, 200),
    folder: details.folder || '',
    file: details.file || '',
    target: details.target || '',
    note: details.note || '',
  };
  const head = db.doc('auditMeta/head');
  await db.runTransaction(async (tx) => {
    const h = await tx.get(head);
    const seq = (h.exists ? h.data().seq : 0) + 1;
    const prevHash = h.exists ? h.data().hash : L.GENESIS;
    const hash = L.chainHash(prevHash, seq, entry);
    tx.set(db.doc(`audit/${String(seq).padStart(12, '0')}`), { seq, prevHash, hash, entry });
    tx.set(head, { seq, hash, at: entry.at });
  });
}

// ---------------------------------------------------------------- helpers
const EMULATED = process.env.FUNCTIONS_EMULATOR === 'true';
/** A 5-minute read link. On the emulators (no signing key) the emulator's download URL stands in. */
async function readUrl(path) {
  if (EMULATED) {
    const host = process.env.FIREBASE_STORAGE_EMULATOR_HOST || '127.0.0.1:9199';
    return `http://${host}/download/storage/v1/b/${bucket().name}/o/${encodeURIComponent(path)}?alt=media`;
  }
  const [url] = await bucket().file(path).getSignedUrl({ version: 'v4', action: 'read', expires: Date.now() + 5 * 60e3 });
  return url;
}

function requireUser(req) {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Please sign in.');
  const t = req.auth.token;
  const viaPasskey = t.firebase?.sign_in_provider === 'custom' && t.passkey === true;
  if (!t.firebase?.sign_in_second_factor && !viaPasskey) {
    throw new HttpsError('permission-denied', 'Sign in with your authenticator code first.');
  }
  return { uid: req.auth.uid, email: t.email || '', admin: t.admin === true };
}
function requireAdmin(req) {
  const u = requireUser(req);
  if (!u.admin) throw new HttpsError('permission-denied', 'Only administrators can do that.');
  return u;
}
const ms = (t) => (t instanceof Timestamp ? t.toMillis() : Number(t) || 0);
function memberOf(folder, uid) {
  const m = folder.members?.[uid];
  return m ? { perm: m.perm, until: ms(m.until) } : undefined;
}
async function getFolder(fid) {
  const snap = await db.doc(`folders/${fid}`).get();
  if (!snap.exists) throw new HttpsError('not-found', 'That folder no longer exists.');
  return snap.data();
}
function checkDays(days, max) {
  const d = Number(days);
  if (!L.ALLOWED_DAYS.includes(d) || d > max) throw new HttpsError('invalid-argument', `Pick a period up to ${max} days.`);
  return d;
}
async function settings() {
  const s = await db.doc('settings/main').get();
  return { defaultDays: 7, maxDays: 90, removeUnusedDays: 90, ...(s.exists ? s.data() : {}) };
}
async function adminEmails() {
  const q = await db.collection('users').where('admin', '==', true).get();
  return q.docs.map((d) => d.data().email).filter(Boolean);
}
async function notify(to, subject, text) {
  if (!to || (Array.isArray(to) && !to.length)) return;
  try { await sendMail(to, subject, text + `\n\n${PORTAL_URL}\n\nHamilton County Election Commission · Secure Transfer`); }
  catch (e) { logger.warn('mail failed', e.message); }
}
async function userEmail(uid) {
  const s = await db.doc(`users/${uid}`).get();
  return s.exists ? s.data().email : '';
}
function keysValid(keys, required) {
  if (!keys || typeof keys !== 'object') return false;
  for (const id of required) {
    const k = keys[id];
    if (!k || typeof k.wrapped !== 'string' || typeof k.salt !== 'string' || !k.epk) return false;
  }
  return Object.keys(keys).length <= 60;
}

// ---------------------------------------------------------------- accounts
// Nobody can create an account from the sign-in page; accounts come only from invitations (Admin SDK).
export const blockSignUp = beforeUserCreated({ region: 'us-east1' }, () => {
  throw new IdentityError('permission-denied', 'Accounts are by invitation only.');
});

// Blocks people whose access was removed, and people marked "no self-service reset" whose password was
// changed outside an administrator's reset.
export const checkSignIn = beforeUserSignedIn({ region: 'us-east1' }, async (event) => {
  const u = event.data;
  const snap = await db.doc(`users/${u.uid}`).get();
  if (!snap.exists || snap.data().removed) throw new IdentityError('permission-denied', 'This account no longer has access.');
  const p = snap.data();
  const validAfter = Date.parse(u.tokensValidAfterTime || 0) || 0;
  if (p.noSelfReset && p.approvedValidAfter && validAfter > p.approvedValidAfter + 5000) {
    await audit('signin.blocked', { actor: u.uid, actorEmail: u.email, ip: event.ipAddress, note: 'password changed without approval' });
    await notify(await adminEmails(), 'Secure Transfer: sign-in blocked',
      `${u.email}'s password was changed through the email reset link, which is turned off for this account. ` +
      'Their sign-in was blocked. If this was them, reset their access from the People page.');
    throw new IdentityError('permission-denied', 'Your password was reset in a way this account does not allow. Contact the Election Commission.');
  }
});

/** Called by the browser right after a full sign-in. Records the device and alerts on new ones. */
export const recordSignIn = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const device = L.cleanText(req.data?.deviceId, 64);
  const label = L.cleanText(req.data?.deviceLabel, 120);
  const ref = db.doc(`users/${u.uid}`);
  const snap = await ref.get();
  const known = snap.exists ? snap.data().devices || {} : {};
  const isNew = device && !known[device];
  await ref.set({ lastSignIn: Date.now(), devices: device ? { [device]: { label, first: known[device]?.first || Date.now(), last: Date.now() } } : {} }, { merge: true });
  await audit('signin', { note: isNew ? `new device: ${label}` : label }, req);
  if (isNew && Object.keys(known).length) {
    const text = `${u.email} signed in to Secure Transfer from a new device (${label || 'unknown browser'}, IP ${req.rawRequest?.ip || 'unknown'}).` +
      ' If this was not you, contact the Election Commission right away.';
    await notify(u.email, 'Secure Transfer: new sign-in', text);
    await notify((await adminEmails()).filter((e) => e !== u.email), 'Secure Transfer: new device sign-in', text);
  }
  const user = snap.exists ? snap.data() : {};
  return { admin: u.admin, needsKey: !(await db.doc(`publicKeys/${u.uid}`).get()).exists, name: user.name || '' };
});

/** Admin: invite a person to a folder (creating their account if needed). The browser then sends the
 *  password-setup email with Firebase Auth's own mailer. */
export const invite = onCall(callOpts, async (req) => {
  const me = requireAdmin(req);
  const email = String(req.data?.email || '').trim().toLowerCase();
  if (!L.isEmail(email)) throw new HttpsError('invalid-argument', 'Enter a full email address.');
  const name = L.cleanText(req.data?.name, 80) || email;
  const org = L.cleanText(req.data?.org, 80);
  const fid = String(req.data?.folder || '');
  const perm = req.data?.perm;
  if (fid && !L.PERMS.includes(perm)) throw new HttpsError('invalid-argument', 'Pick what they can do.');
  const days = Number(req.data?.days || 0);
  let user, created = false;
  try { user = await getAuth().getUserByEmail(email); }
  catch { user = await getAuth().createUser({ email, displayName: name, emailVerified: false }); created = true; }
  await db.doc(`users/${user.uid}`).set({
    email, name, org, removed: false, invitedBy: me.uid, ...(created ? { createdAt: Date.now() } : {}),
    noSelfReset: req.data?.noSelfReset === true,
  }, { merge: true });
  if (fid) {
    const folder = await getFolder(fid);
    const until = days > 0 ? Date.now() + days * L.DAY_MS : ms(folder.deleteAt) || Date.now() + 3650 * L.DAY_MS;
    await db.doc(`folders/${fid}`).update({ [`members.${user.uid}`]: { perm, until: Timestamp.fromMillis(until), addedAt: Date.now() } });
    await audit('member.add', { folder: fid, target: email, note: `${perm} until ${new Date(until).toISOString().slice(0, 10)}` }, req);
    if (!created) await notify(email, 'Secure Transfer: you were added to a folder',
      `The Hamilton County Election Commission shared a folder with you (${perm === 'upload' ? 'you can send files' : perm === 'download' ? 'you can download files' : 'you can send and download files'}).`);
  } else {
    await audit('user.invite', { target: email }, req);
  }
  return { uid: user.uid, created };
});

export const updateMember = onCall(callOpts, async (req) => {
  requireAdmin(req);
  const { folder: fid, uid, perm, days, remove } = req.data || {};
  const folder = await getFolder(fid);
  if (!folder.members?.[uid]) throw new HttpsError('not-found', 'That person is not in this folder.');
  if (remove) {
    await db.doc(`folders/${fid}`).update({ [`members.${uid}`]: FieldValue.delete() });
    await audit('member.remove', { folder: fid, target: await userEmail(uid) }, req);
    return { ok: true };
  }
  const patch = {};
  if (perm) { if (!L.PERMS.includes(perm)) throw new HttpsError('invalid-argument', 'Unknown permission.'); patch[`members.${uid}.perm`] = perm; }
  if (days) patch[`members.${uid}.until`] = Timestamp.fromMillis(Date.now() + Number(days) * L.DAY_MS);
  await db.doc(`folders/${fid}`).update(patch);
  await audit('member.change', { folder: fid, target: await userEmail(uid), note: L.canonical({ perm, days }) }, req);
  return { ok: true };
});

/** Admin: remove a person everywhere and sign them out of every device. */
export const removeUser = onCall(callOpts, async (req) => {
  requireAdmin(req);
  const uid = String(req.data?.uid || '');
  // There must always be an administrator: admin accounts can't be removed from the portal.
  if ((await db.doc(`users/${uid}`).get()).data()?.admin === true) throw new HttpsError('failed-precondition', 'Administrator accounts can’t be removed here.');
  const folders = await db.collection('folders').where(`members.${uid}.perm`, 'in', L.PERMS).get();
  const batch = db.batch();
  folders.docs.forEach((d) => batch.update(d.ref, { [`members.${uid}`]: FieldValue.delete() }));
  (await db.collection('passkeys').where('uid', '==', uid).get()).docs.forEach((d) => batch.delete(d.ref));
  batch.set(db.doc(`users/${uid}`), { removed: true, removedAt: Date.now() }, { merge: true });
  await batch.commit();
  await getAuth().revokeRefreshTokens(uid);
  await getAuth().updateUser(uid, { disabled: true });
  await audit('user.remove', { target: await userEmail(uid) }, req);
  return { ok: true };
});

/** Admin: approve a password reset for a "no self-service reset" account (after confirming with the person). */
export const approveReset = onCall(callOpts, async (req) => {
  requireAdmin(req);
  const uid = String(req.data?.uid || '');
  const u = await getAuth().getUser(uid);
  await db.doc(`users/${uid}`).set({ approvedValidAfter: Date.parse(u.tokensValidAfterTime || 0) || Date.now() }, { merge: true });
  await audit('user.reset-approved', { target: u.email }, req);
  return { ok: true };
});

/** A person stores their public key once; a function replaces it after a reset (the old one is kept). */
export const replaceKey = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const jwk = req.data?.jwk;
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new HttpsError('invalid-argument', 'Bad key.');
  }
  const ref = db.doc(`publicKeys/${u.uid}`);
  const old = await ref.get();
  if (old.exists) await db.collection(`publicKeys/${u.uid}/history`).add(old.data());
  for (const d of (await db.collection('passkeys').where('uid', '==', u.uid).get()).docs) await d.ref.update({ privateKey: null });
  await ref.set({ jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, createdAt: FieldValue.serverTimestamp() });
  await audit('key.replace', { target: u.email }, req);
  // Files they had access to are re-shared with the new key by an administrator (rewrapFor).
  await notify(await adminEmails(), 'Secure Transfer: someone needs files re-shared',
    `${u.email} set up a new encryption key (usually after a password reset). Open Secure Transfer to re-share their files.`);
  return { ok: true };
});

// ---------------------------------------------------------------- folders
/** The folders this person can open, with what they may do in each (admins see all, with members). */
export const listFolders = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const now = Date.now();
  const out = [];
  const people = {};
  if (u.admin) (await db.collection('users').get()).docs.forEach((d) => { people[d.id] = d.data(); });
  for (const d of (await db.collection('folders').get()).docs) {
    const f = d.data();
    const m = memberOf(f, u.uid);
    const acc = L.access(m, now, u.admin);
    if (!acc.read) continue;
    const item = { id: d.id, name: f.name, kind: f.kind || 'folder', days: f.days, note: f.note || '', createdAt: f.createdAt,
      notes: f.notes || null, perm: u.admin ? 'admin' : m.perm, until: m ? m.until : null };
    if (u.admin) {
      item.members = Object.entries(f.members || {}).map(([uid, x]) => ({ uid, perm: x.perm, until: ms(x.until),
        name: people[uid]?.name || '', email: people[uid]?.email || '', org: people[uid]?.org || '' }));
    }
    out.push(item);
  }
  out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return { folders: out, admin: u.admin };
});

export const createFolder = onCall(callOpts, async (req) => {
  const me = requireAdmin(req);
  const s = await settings();
  const name = L.cleanText(req.data?.name, 100);
  if (!name) throw new HttpsError('invalid-argument', 'Give the folder a name.');
  const days = checkDays(req.data?.days ?? s.defaultDays, s.maxDays);
  const kind = req.data?.kind === 'request' ? 'request' : 'folder';
  const ref = db.collection('folders').doc();
  await ref.set({
    name, days, kind, createdAt: Date.now(), createdBy: me.uid,
    note: L.cleanText(req.data?.note, 500),
    members: {},
  });
  await audit(kind === 'request' ? 'request.create' : 'folder.create', { folder: ref.id, note: `${name}; files deleted after ${days} days` }, req);
  return { id: ref.id };
});

export const updateFolder = onCall(callOpts, async (req) => {
  requireAdmin(req);
  const s = await settings();
  const fid = String(req.data?.folder || '');
  await getFolder(fid);
  const patch = {};
  if (req.data?.name) patch.name = L.cleanText(req.data.name, 100);
  if (req.data?.days) patch.days = checkDays(req.data.days, s.maxDays);
  if (typeof req.data?.notes === 'object' && req.data.notes) patch.notes = req.data.notes; // encrypted note box + keys
  await db.doc(`folders/${fid}`).update(patch);
  await audit('folder.change', { folder: fid, note: Object.keys(patch).join(', ') }, req);
  return { ok: true };
});

export const deleteFolder = onCall(callOpts, async (req) => {
  requireAdmin(req);
  const fid = String(req.data?.folder || '');
  await bucket().deleteFiles({ prefix: `folders/${fid}/` }).catch(() => {});
  await db.recursiveDelete(db.doc(`folders/${fid}`));
  await audit('folder.delete', { folder: fid }, req);
  return { ok: true };
});

/** Public keys of everyone who should be able to open a new file in this folder, plus the recovery key. */
export const recipients = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const fid = String(req.data?.folder || '');
  const folder = await getFolder(fid);
  const acc = L.access(memberOf(folder, u.uid), Date.now(), u.admin);
  if (!acc.read) throw new HttpsError('permission-denied', 'You no longer have access to this folder.');
  const ids = new Set([u.uid]);
  (await db.collection('users').where('admin', '==', true).get()).docs.forEach((d) => ids.add(d.id));
  const now = Date.now();
  // Files from people outside the commission go only to them and the administrators. Messages and notes, and
  // files from administrators, go to everyone in the folder who may read them.
  const forAll = req.data?.purpose === 'message';
  if (u.admin || forAll) {
    for (const [uid, m] of Object.entries(folder.members || {})) {
      if (ms(m.until) > now && (forAll || m.perm === 'download' || m.perm === 'both')) ids.add(uid);
    }
  }
  const out = [];
  for (const id of ids) {
    const k = await db.doc(`publicKeys/${id}`).get();
    if (k.exists) out.push({ id, publicJwk: k.data().jwk });
  }
  const rec = await db.doc('settings/recovery').get();
  if (!rec.exists) throw new HttpsError('failed-precondition', 'The recovery key has not been set up yet.');
  out.push({ id: 'recovery', publicJwk: rec.data().jwk });
  return { recipients: out };
});

// ---------------------------------------------------------------- files
/** After the browser uploads ciphertext to folders/{fid}/{uid}/{fileId}, it records the file here. */
export const finalizeUpload = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const { folder: fid, fileId, name, sha256, size, keys, ext } = req.data || {};
  const folder = await getFolder(fid);
  const acc = L.access(memberOf(folder, u.uid), Date.now(), u.admin);
  if (!acc.upload) throw new HttpsError('permission-denied', 'You can’t upload to this folder.');
  if (!/^[A-Za-z0-9_-]{8,40}$/.test(String(fileId))) throw new HttpsError('invalid-argument', 'Bad file id.');
  if (!L.extensionAllowed('x.' + ext)) throw new HttpsError('invalid-argument', 'That type of file can’t be sent here.');
  if (!/^[0-9a-f]{64}$/.test(String(sha256))) throw new HttpsError('invalid-argument', 'Missing fingerprint.');
  if (!name || typeof name.iv !== 'string' || typeof name.ct !== 'string' || name.ct.length > 2000) throw new HttpsError('invalid-argument', 'Bad name.');
  if (!keysValid(keys, [u.uid, 'recovery'])) throw new HttpsError('invalid-argument', 'The file must be shared with you and the recovery key.');
  const path = `folders/${fid}/${u.uid}/${fileId}`;
  const [exists] = await bucket().file(path).exists();
  if (!exists) throw new HttpsError('failed-precondition', 'The upload did not finish. Try again.');
  const [meta] = await bucket().file(path).getMetadata();
  if (Number(meta.size) > L.MAX_FILE_BYTES + 1e6) { await bucket().file(path).delete(); throw new HttpsError('invalid-argument', 'File too large.'); }
  const ref = db.doc(`folders/${fid}/files/${fileId}`);
  if ((await ref.get()).exists) throw new HttpsError('already-exists', 'Already recorded.');
  const now = Date.now();
  const opts = req.data?.options || {};
  const picked = u.admin && Array.isArray(opts.visibleTo) ? opts.visibleTo.filter((x) => typeof x === 'string').slice(0, 50) : [];
  const everyone = u.admin && picked.length === 0;
  const visibleTo = [...new Set([u.uid, ...picked])];
  const maxDownloads = u.admin && Number(opts.maxDownloads) > 0 ? Math.min(100, Number(opts.maxDownloads)) : 0;
  await ref.set({
    path, name, sha256, ext: String(ext).toLowerCase(), size: Number(meta.size), plainSize: Number(size) || 0,
    keys, uploadedBy: u.uid, uploaderEmail: u.email, uploadedAt: now,
    expiresAt: Timestamp.fromMillis(L.expiresAt(now, folder.days)),
    everyone, visibleTo, maxDownloads, deleteAfterDownload: u.admin && opts.deleteAfterDownload === true, downloads: 0,
  });
  await audit('file.upload', { folder: fid, file: fileId, note: `sha256 ${sha256.slice(0, 16)}…, ${meta.size} bytes` }, req);
  if (!u.admin) {
    await notify(await adminEmails(), `Secure Transfer: new file in "${folder.name}"`,
      `${u.email} sent a file to "${folder.name}". It will be deleted automatically on ${new Date(L.expiresAt(now, folder.days)).toDateString()}.`);
  } else {
    const now2 = Date.now();
    const readers = Object.entries(folder.members || {}).filter(([uid, m]) => ms(m.until) > now2 && m.perm !== 'upload'
      && (everyone || visibleTo.includes(uid))).map(([uid]) => uid);
    const emails = (await Promise.all(readers.map(userEmail))).filter(Boolean);
    await notify(emails, 'Secure Transfer: a file is ready for you',
      `The Hamilton County Election Commission shared a file with you in "${folder.name}". Sign in to download it before ${new Date(L.expiresAt(now, folder.days)).toDateString()}.`);
  }
  return { ok: true };
});

/** Checks access, counts and logs the download, returns a 5-minute link to the ciphertext. */
export const getDownload = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const { folder: fid, file: fileId } = req.data || {};
  const folder = await getFolder(fid);
  const acc = L.access(memberOf(folder, u.uid), Date.now(), u.admin);
  const ref = db.doc(`folders/${fid}/files/${fileId}`);
  const file = await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists) throw new HttpsError('not-found', 'That file was deleted.');
    const f = snap.data();
    const ok = L.mayDownload(f, u.uid, acc);
    if (!ok.ok) throw new HttpsError('permission-denied', ok.why);
    if (ms(f.expiresAt) < Date.now()) throw new HttpsError('not-found', 'That file reached its deletion date.');
    const patch = { downloads: FieldValue.increment(1), [`downloadedBy.${u.uid}`]: Date.now() };
    if (f.deleteAfterDownload && f.uploadedBy !== u.uid) patch.expiresAt = Timestamp.fromMillis(Date.now() + 10 * 60e3);
    tx.update(ref, patch);
    return f;
  });
  const url = await readUrl(file.path);
  await audit('file.download', { folder: fid, file: fileId }, req);
  if (file.uploadedBy !== u.uid) {
    const to = await userEmail(file.uploadedBy);
    await notify(to, 'Secure Transfer: your file was downloaded',
      `${u.email} downloaded a file you shared in "${folder.name}" on ${new Date().toLocaleString('en-US', { timeZone: 'America/New_York' })}.` +
      (file.deleteAfterDownload ? ' It was set to delete after download and will be removed within 10 minutes.' : ''));
  }
  const keys = {};
  if (file.keys[u.uid]) keys[u.uid] = file.keys[u.uid];
  if (u.admin && req.data?.useRecovery === true) keys.recovery = file.keys.recovery;
  return { url, keys, name: file.name, sha256: file.sha256 };
});

export const deleteFile = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const { folder: fid, file: fileId } = req.data || {};
  const ref = db.doc(`folders/${fid}/files/${fileId}`);
  const snap = await ref.get();
  if (!snap.exists) return { ok: true };
  if (!u.admin && snap.data().uploadedBy !== u.uid) throw new HttpsError('permission-denied', 'Only the sender or an administrator can delete this.');
  await bucket().file(snap.data().path).delete({ ignoreNotFound: true });
  await ref.delete();
  await audit('file.delete', { folder: fid, file: fileId }, req);
  return { ok: true };
});

/** Admin: add wrapped keys so more people (or someone with a new key) can open existing files. */
export const addFileKeys = onCall(callOpts, async (req) => {
  requireAdmin(req);
  const { folder: fid, file: fileId, keys } = req.data || {};
  if (!keysValid(keys, Object.keys(keys || {}))) throw new HttpsError('invalid-argument', 'Bad keys.');
  const patch = {};
  for (const [id, k] of Object.entries(keys)) if (id !== 'recovery') patch[`keys.${id}`] = k;
  await db.doc(`folders/${fid}/files/${fileId}`).update(patch);
  await audit('file.share', { folder: fid, file: fileId, note: Object.keys(patch).length + ' people' }, req);
  return { ok: true };
});

// ---------------------------------------------------------------- messages (encrypted in the browser)
export const postMessage = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const { folder: fid, box, keys } = req.data || {};
  const folder = await getFolder(fid);
  const acc = L.access(memberOf(folder, u.uid), Date.now(), u.admin);
  if (!acc.read) throw new HttpsError('permission-denied', 'You no longer have access to this folder.');
  if (!box || typeof box.ct !== 'string' || box.ct.length > 20000) throw new HttpsError('invalid-argument', 'Message too long.');
  if (!keysValid(keys, [u.uid, 'recovery'])) throw new HttpsError('invalid-argument', 'Bad keys.');
  const now = Date.now();
  await db.collection(`folders/${fid}/messages`).add({ box, keys, from: u.uid, fromEmail: u.email, at: now,
    expiresAt: Timestamp.fromMillis(L.expiresAt(now, folder.days)) });
  await audit('message.post', { folder: fid }, req);
  return { ok: true };
});

/** Private one-to-one thread with a person: a hidden two-member folder, made on first use. */
export const openThread = onCall(callOpts, async (req) => {
  const me = requireAdmin(req);
  const uid = String(req.data?.uid || '');
  const id = 'dm_' + createHash('sha256').update([me.uid, uid].sort().join(':')).digest('hex').slice(0, 20);
  const ref = db.doc(`folders/${id}`);
  if (!(await ref.get()).exists) {
    const s = await settings();
    await ref.set({ name: 'Private messages', kind: 'thread', days: s.maxDays, createdAt: Date.now(), createdBy: me.uid,
      members: { [uid]: { perm: 'both', until: Timestamp.fromMillis(Date.now() + 3650 * L.DAY_MS) } } });
    await audit('thread.open', { folder: id, target: await userEmail(uid) }, req);
  }
  return { id };
});

// ---------------------------------------------------------------- drop-off page (code instead of an account)
export const createDropoff = onCall(callOpts, async (req) => {
  const me = requireAdmin(req);
  const s = await settings();
  const label = L.cleanText(req.data?.label, 100) || 'Drop-off';
  const days = checkDays(req.data?.days ?? s.defaultDays, s.maxDays);
  const open = Math.min(30, Math.max(1, Number(req.data?.openDays) || 7));
  const code = L.newDropoffCode();
  const salt = L.newId(16);
  const fref = db.collection('folders').doc();
  await fref.set({ name: label, kind: 'dropoff', days, createdAt: Date.now(), createdBy: me.uid, members: {} });
  const id = L.newId(9);
  await db.doc(`dropoffs/${id}`).set({ folder: fref.id, label, salt, hash: L.hashCode(code, salt),
    closesAt: Timestamp.fromMillis(Date.now() + open * L.DAY_MS), uploads: 0, maxUploads: 50, failures: 0 });
  await audit('dropoff.create', { folder: fref.id, note: `${label}; open ${open} days` }, req);
  return { id, code, url: `${PORTAL_URL}#dropoff-${id}` };
});

async function dropoffFor(req) {
  const id = String(req.data?.id || '');
  const ref = db.doc(`dropoffs/${id}`);
  const snap = await ref.get();
  if (!snap.exists) throw new HttpsError('not-found', 'This drop-off link is not valid.');
  const d = snap.data();
  if (ms(d.closesAt) < Date.now()) throw new HttpsError('failed-precondition', 'This drop-off has closed.');
  if (d.failures >= 10) throw new HttpsError('resource-exhausted', 'Too many wrong codes. Ask the Election Commission for a new link.');
  if (!L.codeMatches(req.data?.code, d.salt, d.hash)) {
    await ref.update({ failures: FieldValue.increment(1) });
    await audit('dropoff.bad-code', { folder: d.folder, actor: 'anonymous' }, req);
    throw new HttpsError('permission-denied', 'That code is not right.');
  }
  return { ref, d };
}

/** Anyone with the link and code: get the keys to encrypt to and a one-time upload URL. */
export const dropoffStart = onCall(callOpts, async (req) => {
  const { ref, d } = await dropoffFor(req);
  if (d.uploads >= d.maxUploads) throw new HttpsError('resource-exhausted', 'This drop-off is full.');
  if (!L.extensionAllowed('x.' + req.data?.ext)) throw new HttpsError('invalid-argument', 'That type of file can’t be sent here.');
  const out = [];
  for (const a of (await db.collection('users').where('admin', '==', true).get()).docs) {
    const k = await db.doc(`publicKeys/${a.id}`).get();
    if (k.exists) out.push({ id: a.id, publicJwk: k.data().jwk });
  }
  const rec = await db.doc('settings/recovery').get();
  if (!rec.exists) throw new HttpsError('failed-precondition', 'Not ready yet.');
  out.push({ id: 'recovery', publicJwk: rec.data().jwk });
  const fileId = L.newId(15);
  const path = `folders/${d.folder}/dropoff/${fileId}`;
  const [url] = EMULATED ? [`emulator:${path}`] : await bucket().file(path).getSignedUrl({
    version: 'v4', action: 'write', expires: Date.now() + 30 * 60e3, contentType: 'application/octet-stream',
    extensionHeaders: { 'x-goog-content-length-range': `0,${L.MAX_FILE_BYTES + 1e6}` },
  });
  await ref.update({ uploads: FieldValue.increment(1) });
  return { url, fileId, label: d.label, recipients: out };
});

export const dropoffFinish = onCall(callOpts, async (req) => {
  const { d } = await dropoffFor(req);
  const { fileId, name, sha256, size, keys, ext, sender } = req.data || {};
  if (!/^[A-Za-z0-9_-]{8,40}$/.test(String(fileId))) throw new HttpsError('invalid-argument', 'Bad file id.');
  if (!keysValid(keys, ['recovery'])) throw new HttpsError('invalid-argument', 'Bad keys.');
  const path = `folders/${d.folder}/dropoff/${fileId}`;
  const [exists] = await bucket().file(path).exists();
  if (!exists) throw new HttpsError('failed-precondition', 'The upload did not finish. Try again.');
  const [meta] = await bucket().file(path).getMetadata();
  const folder = await getFolder(d.folder);
  const now = Date.now();
  await db.doc(`folders/${d.folder}/files/${fileId}`).set({
    path, name, sha256: String(sha256), ext: String(ext).toLowerCase(), size: Number(meta.size), plainSize: Number(size) || 0,
    keys, uploadedBy: 'dropoff', uploaderEmail: L.cleanText(sender, 120), uploadedAt: now,
    expiresAt: Timestamp.fromMillis(L.expiresAt(now, folder.days)), everyone: false, visibleTo: [], maxDownloads: 0, downloads: 0,
  });
  await audit('dropoff.upload', { folder: d.folder, file: fileId, actor: 'dropoff', actorEmail: L.cleanText(sender, 120) }, req);
  await notify(await adminEmails(), `Secure Transfer: new file at drop-off "${d.label}"`,
    `${L.cleanText(sender, 120) || 'Someone'} sent a file through the drop-off "${d.label}".`);
  return { ok: true };
});

// ---------------------------------------------------------------- quick send (link + optional password)
export const createSend = onCall(callOpts, async (req) => {
  const u = requireAdmin(req);
  const s = await settings();
  const { fileId, name, sha256, size, keys, ext, accessHash, salt, iterations, hasPassword, label } = req.data || {};
  if (!/^[A-Za-z0-9_-]{8,40}$/.test(String(fileId))) throw new HttpsError('invalid-argument', 'Bad file id.');
  if (!L.extensionAllowed('x.' + ext)) throw new HttpsError('invalid-argument', 'That type of file can’t be sent.');
  if (!/^[0-9a-f]{64}$/.test(String(accessHash)) || !/^[0-9a-f]{64}$/.test(String(sha256))) throw new HttpsError('invalid-argument', 'Bad request.');
  if (!keysValid(keys, [u.uid, 'recovery'])) throw new HttpsError('invalid-argument', 'The file must be shared with you and the recovery key.');
  const days = checkDays(req.data?.days ?? 7, s.maxDays);
  const maxDownloads = Math.min(10, Math.max(1, Number(req.data?.maxDownloads) || 1));
  const path = `sends/${u.uid}/${fileId}`;
  const [exists] = await bucket().file(path).exists();
  if (!exists) throw new HttpsError('failed-precondition', 'The upload did not finish. Try again.');
  const [meta] = await bucket().file(path).getMetadata();
  const id = L.newId(12);
  const now = Date.now();
  await db.doc(`sends/${id}`).set({
    path, name, sha256, ext: String(ext).toLowerCase(), size: Number(meta.size), plainSize: Number(size) || 0, keys,
    accessHash, salt: String(salt), iterations: Number(iterations) || 600000, hasPassword: hasPassword === true,
    label: L.cleanText(label, 100), createdBy: u.uid, creatorEmail: u.email, createdAt: now,
    expiresAt: Timestamp.fromMillis(now + days * L.DAY_MS), maxDownloads, downloads: 0, failures: 0,
  });
  await audit('send.create', { file: id, note: `${L.cleanText(label, 100) || 'quick send'}; ${maxDownloads} download(s), ${days} days${hasPassword ? ', password' : ''}` }, req);
  return { id };
});

async function sendFor(id) {
  const ref = db.doc(`sends/${String(id || '').slice(0, 40)}`);
  const snap = await ref.get();
  if (!snap.exists) throw new HttpsError('not-found', 'This link has expired or was already used.');
  const d = snap.data();
  if (ms(d.expiresAt) < Date.now() || d.downloads >= d.maxDownloads) throw new HttpsError('not-found', 'This link has expired or was already used.');
  return { ref, d };
}

/** Anyone with the link: what the page needs to ask for (never the file name). */
export const sendInfo = onCall(callOpts, async (req) => {
  const { d } = await sendFor(req.data?.id);
  return { hasPassword: d.hasPassword, salt: d.salt, iterations: d.iterations, expiresAt: ms(d.expiresAt),
    remaining: d.maxDownloads - d.downloads, size: d.plainSize || d.size, label: d.label || '' };
});

/** Anyone with the link (and password): check access, count the download, return a 5-minute link. */
export const sendOpen = onCall(callOpts, async (req) => {
  const { ref, d } = await sendFor(req.data?.id);
  if (d.failures >= 10) throw new HttpsError('resource-exhausted', 'Too many wrong passwords. Ask the Election Commission to send it again.');
  const given = createHash('sha256').update(String(req.data?.access || '')).digest('hex');
  const a = Buffer.from(given, 'hex'), b = Buffer.from(d.accessHash, 'hex');
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    await ref.update({ failures: FieldValue.increment(1) });
    await audit('send.bad-password', { file: ref.id, actor: 'anonymous' }, req);
    throw new HttpsError('permission-denied', d.hasPassword ? 'That password is not right.' : 'This link is not complete. Copy the whole link.');
  }
  const after = d.downloads + 1;
  const patch = { downloads: FieldValue.increment(1), lastDownloadAt: Date.now() };
  if (after >= d.maxDownloads) patch.expiresAt = Timestamp.fromMillis(Date.now() + 10 * 60e3); // removed by cleanup
  await ref.update(patch);
  const url = await readUrl(d.path);
  await audit('send.download', { file: ref.id, actor: 'link', note: `${after} of ${d.maxDownloads}` }, req);
  await notify(d.creatorEmail, 'Secure Transfer: your quick send was downloaded',
    `Your quick send${d.label ? ` "${d.label}"` : ''} was downloaded (${after} of ${d.maxDownloads}) on ` +
    `${new Date().toLocaleString('en-US', { timeZone: 'America/New_York' })}, from IP ${req.rawRequest?.ip || 'unknown'}.` +
    (after >= d.maxDownloads ? ' It has reached its limit and will be deleted within 10 minutes.' : ''));
  return { url, name: d.name, sha256: d.sha256 };
});

export const deleteSend = onCall(callOpts, async (req) => {
  requireAdmin(req);
  const ref = db.doc(`sends/${String(req.data?.id || '')}`);
  const snap = await ref.get();
  if (snap.exists) { await bucket().file(snap.data().path).delete({ ignoreNotFound: true }); await ref.delete(); }
  await audit('send.delete', { file: ref.id }, req);
  return { ok: true };
});

// ---------------------------------------------------------------- settings, log export
export const saveSettings = onCall(callOpts, async (req) => {
  requireAdmin(req);
  const { defaultDays, maxDays, removeUnusedDays } = req.data || {};
  const max = Number(maxDays);
  if (!L.ALLOWED_DAYS.includes(max)) throw new HttpsError('invalid-argument', 'Pick a longest period from the list.');
  const def = checkDays(defaultDays, max);
  const unused = [0, 30, 60, 90, 180].includes(Number(removeUnusedDays)) ? Number(removeUnusedDays) : 90;
  await db.doc('settings/main').set({ defaultDays: def, maxDays: max, removeUnusedDays: unused }, { merge: true });
  await audit('settings.change', { note: L.canonical({ def, max, unused }) }, req);
  return { ok: true };
});

/** Admin, once: store the public half of the offline recovery key. Can't be replaced from the app. */
export const setRecoveryKey = onCall(callOpts, async (req) => {
  requireAdmin(req);
  const ref = db.doc('settings/recovery');
  if ((await ref.get()).exists) throw new HttpsError('already-exists', 'The recovery key is already set.');
  const jwk = req.data?.jwk;
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new HttpsError('invalid-argument', 'Bad key.');
  await ref.set({ jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, setAt: Date.now() });
  await audit('recovery.set', {}, req);
  return { ok: true };
});

export const exportLog = onCall(callOpts, async (req) => {
  requireAdmin(req);
  const snap = await db.collection('audit').orderBy('seq').get();
  const rows = snap.docs.map((d) => d.data());
  const check = L.verifyChain(rows);
  await audit('log.export', { note: check.ok ? `${rows.length} entries, chain intact` : `chain problem at ${check.seq}` }, req);
  const csv = L.toCsv(['seq', 'time (UTC)', 'action', 'who', 'email', 'folder', 'file', 'target', 'note', 'ip', 'hash'],
    rows.map((r) => [r.seq, new Date(r.entry.at).toISOString(), r.entry.action, r.entry.actor, r.entry.actorEmail,
      r.entry.folder, r.entry.file, r.entry.target, r.entry.note, r.entry.ip, r.hash]));
  return { csv, chain: check };
});

export const verifyLog = onCall(callOpts, async (req) => {
  requireAdmin(req);
  const rows = (await db.collection('audit').orderBy('seq').get()).docs.map((d) => d.data());
  const head = await db.doc('auditMeta/head').get();
  const check = L.verifyChain(rows);
  if (check.ok && head.exists && (head.data().seq !== rows.length || head.data().hash !== check.last)) {
    return { ok: false, reason: 'latest entries missing' };
  }
  return check;
});

// ---------------------------------------------------------------- automatic deletion
export async function runCleanup(now = Date.now()) {
  const due = await db.collectionGroup('files').where('expiresAt', '<=', Timestamp.fromMillis(now)).limit(500).get();
  let files = 0;
  for (const d of due.docs) {
    await bucket().file(d.data().path).delete({ ignoreNotFound: true });
    await d.ref.delete();
    files++;
  }
  const sends = await db.collection('sends').where('expiresAt', '<=', Timestamp.fromMillis(now)).limit(500).get();
  for (const d of sends.docs) {
    await bucket().file(d.data().path).delete({ ignoreNotFound: true });
    await d.ref.delete();
    files++;
  }
  const msgs = await db.collectionGroup('messages').where('expiresAt', '<=', Timestamp.fromMillis(now)).limit(500).get();
  for (const d of msgs.docs) await d.ref.delete();
  let members = 0;
  for (const f of (await db.collection('folders').get()).docs) {
    const patch = {};
    for (const [uid, m] of Object.entries(f.data().members || {})) if (ms(m.until) <= now) { patch[`members.${uid}`] = FieldValue.delete(); members++; }
    if (Object.keys(patch).length) await f.ref.update(patch);
  }
  for (const d of (await db.collection('webauthn').where('expiresAt', '<=', Timestamp.fromMillis(now)).limit(500).get()).docs) await d.ref.delete();
  const s = await settings();
  let users = 0;
  if (s.removeUnusedDays) {
    const cutoff = now - s.removeUnusedDays * L.DAY_MS;
    for (const u of (await db.collection('users').where('removed', '==', false).get()).docs) {
      const x = u.data();
      // Administrators are never removed for being unused.
      if (!x.admin && Math.max(x.lastSignIn || 0, x.createdAt || 0) < cutoff) {
        await db.doc(`users/${u.id}`).update({ removed: true, removedAt: now, removedWhy: 'unused' });
        await getAuth().updateUser(u.id, { disabled: true }).catch(() => {});
        users++;
      }
    }
  }
  if (files || msgs.size || members || users) {
    await audit('cleanup', { note: `${files} files, ${msgs.size} messages, ${members} expired memberships, ${users} unused accounts removed` });
  }
  return { files, messages: msgs.size, members, users };
}
export const cleanup = onSchedule({ schedule: 'every 60 minutes', timeZone: 'America/New_York', retryCount: 1 }, async () => {
  const r = await runCleanup();
  logger.info('cleanup', r);
});

export const mailStatus = onCall(callOpts, async (req) => { requireAdmin(req); return { configured: mailConfigured() }; });

// ---------------------------------------------------------------- passkeys (WebAuthn)
// Identity Platform has no passkeys, so the portal runs WebAuthn itself: a verified passkey assertion (which
// requires the device's fingerprint, face or PIN) earns a Firebase custom token marked passkey:true. The
// security rules and requireUser treat that as a complete two-factor sign-in.
const PASSKEY_ORIGINS = { 'https://govotehamiltontn.gov': 'govotehamiltontn.gov', 'http://localhost:8000': 'localhost' };
const STAGING = (process.env.GCLOUD_PROJECT || '').endsWith('-staging');
function rpFor(req) {
  const origin = String(req.rawRequest?.headers?.origin || '');
  const rpID = PASSKEY_ORIGINS[origin];
  if (!rpID) throw new HttpsError('failed-precondition', 'Passkeys work only on the Secure Transfer site.');
  return { origin, rpID };
}
async function newChallenge(kind, uid, challenge) {
  const ref = db.collection('webauthn').doc();
  await ref.set({ kind, uid: uid || '', challenge, expiresAt: Timestamp.fromMillis(Date.now() + 5 * 60e3) });
  return ref.id;
}
/** Uses a stored challenge exactly once. */
async function takeChallenge(id, kind, uid) {
  const ref = db.doc(`webauthn/${String(id || '').slice(0, 40) || 'x'}`);
  return db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists) throw new HttpsError('deadline-exceeded', 'That took too long. Try again.');
    tx.delete(ref);
    const c = snap.data();
    if (c.kind !== kind || (uid && c.uid !== uid) || ms(c.expiresAt) < Date.now()) throw new HttpsError('deadline-exceeded', 'That took too long. Try again.');
    return c.challenge;
  });
}
const b64u = (u8) => Buffer.from(u8).toString('base64url');
const passkeyRef = (id) => db.doc(`passkeys/${createHash('sha256').update(String(id)).digest('hex')}`);

/** Signed in: options for adding a passkey to this account. */
export const passkeyRegisterOptions = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const { rpID } = rpFor(req);
  const user = (await db.doc(`users/${u.uid}`).get()).data() || {};
  const existing = await db.collection('passkeys').where('uid', '==', u.uid).get();
  const options = await WA.generateRegistrationOptions({
    rpName: 'HCEC Secure Transfer' + (STAGING ? ' (test)' : ''), rpID,
    userID: new TextEncoder().encode(u.uid), userName: u.email + (STAGING ? ' (test site)' : ''),
    userDisplayName: user.name || u.email, attestationType: 'none', timeout: 120000,
    excludeCredentials: existing.docs.map((d) => ({ id: d.data().credentialId, transports: d.data().transports || [] })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
  });
  return { id: await newChallenge('register', u.uid, options.challenge), options };
});

/** Signed in: check the new passkey and store it, with the private key copy it unlocks (if any). */
export const passkeyRegister = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const { origin, rpID } = rpFor(req);
  const challenge = await takeChallenge(req.data?.id, 'register', u.uid);
  let v;
  try {
    v = await WA.verifyRegistrationResponse({ response: req.data?.response, expectedChallenge: challenge,
      expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true });
  } catch (e) { throw new HttpsError('invalid-argument', 'The passkey could not be checked: ' + e.message); }
  if (!v.verified) throw new HttpsError('invalid-argument', 'The passkey could not be checked.');
  const cred = v.registrationInfo.credential;
  const k = req.data?.privateKey;
  const privateKey = k && typeof k.wrapped === 'string' && typeof k.iv === 'string' && k.wrapped.length < 2000 ? { wrapped: k.wrapped, iv: k.iv, v: 1 } : null;
  const label = L.cleanText(req.data?.label, 60) || 'Passkey';
  await passkeyRef(cred.id).set({
    uid: u.uid, credentialId: cred.id, publicKey: b64u(cred.publicKey), counter: cred.counter,
    transports: (cred.transports || []).slice(0, 8), label, createdAt: Date.now(), lastUsed: 0,
    backedUp: v.registrationInfo.credentialBackedUp === true, privateKey,
  });
  await audit('passkey.add', { target: u.email, note: `${label}${privateKey ? ', unlocks files' : ''}` }, req);
  await notify(u.email, 'Secure Transfer: a passkey was added',
    `A passkey ("${label}") was added to your Secure Transfer account. If this was not you, contact the Election Commission right away.`);
  return { ok: true, unlocks: !!privateKey };
});

/** Anyone: options for signing in with a passkey (the browser offers the passkeys it holds for this site). */
export const passkeyLoginOptions = onCall(callOpts, async (req) => {
  const { rpID } = rpFor(req);
  const options = await WA.generateAuthenticationOptions({ rpID, userVerification: 'required', timeout: 120000 });
  return { id: await newChallenge('login', '', options.challenge), options };
});

/** Anyone: check a passkey sign-in; returns a sign-in token and the private key copy this passkey unlocks. */
export const passkeyLogin = onCall(callOpts, async (req) => {
  const { origin, rpID } = rpFor(req);
  const challenge = await takeChallenge(req.data?.id, 'login');
  const response = req.data?.response;
  const ref = passkeyRef(response?.id);
  const snap = await ref.get();
  const fail = async (why) => {
    logger.warn('passkey sign-in failed', why);
    await audit('passkey.failed', { actor: snap.exists ? snap.data().uid : 'anonymous', note: why }, req);
    throw new HttpsError('permission-denied', 'That passkey isn’t set up for this site. Sign in with your password and code instead.');
  };
  if (!snap.exists) return fail('unknown passkey');
  const pk = snap.data();
  let v;
  try {
    v = await WA.verifyAuthenticationResponse({ response, expectedChallenge: challenge, expectedOrigin: origin, expectedRPID: rpID,
      credential: { id: pk.credentialId, publicKey: Buffer.from(pk.publicKey, 'base64url'), counter: pk.counter, transports: pk.transports },
      requireUserVerification: true });
  } catch (e) { return fail('check failed: ' + e.message); }
  if (!v.verified) return fail('check failed');
  const user = await db.doc(`users/${pk.uid}`).get();
  if (!user.exists || user.data().removed) return fail('account removed');
  const authUser = await getAuth().getUser(pk.uid).catch(() => null);
  if (!authUser || authUser.disabled) return fail('account disabled');
  await ref.update({ counter: v.authenticationInfo.newCounter, lastUsed: Date.now() });
  await audit('passkey.signin', { actor: pk.uid, actorEmail: authUser.email, note: pk.label }, req);
  const token = await getAuth().createCustomToken(pk.uid, { passkey: true });
  return { token, privateKey: pk.privateKey || null, credentialId: pk.credentialId };
});

/** Signed in: store the file-unlock copy for one of your passkeys (for passkeys that report PRF only when used,
 *  such as some password-manager extensions: set up after the first passkey sign-in). */
export const passkeySetUnlock = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const ref = passkeyRef(req.data?.credentialId);
  const snap = await ref.get();
  if (!snap.exists || snap.data().uid !== u.uid) throw new HttpsError('not-found', 'That passkey isn’t on your account.');
  const k = req.data?.privateKey;
  if (!k || typeof k.wrapped !== 'string' || typeof k.iv !== 'string' || k.wrapped.length >= 2000) throw new HttpsError('invalid-argument', 'Bad key.');
  await ref.update({ privateKey: { wrapped: k.wrapped, iv: k.iv, v: 1 } });
  await audit('passkey.unlock', { target: u.email, note: snap.data().label }, req);
  return { ok: true };
});

/** Signed in: your passkeys; an administrator may ask for anyone's. */
export const passkeyList = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const uid = u.admin && req.data?.uid ? String(req.data.uid) : u.uid;
  const q = await db.collection('passkeys').where('uid', '==', uid).get();
  return { passkeys: q.docs.map((d) => ({ id: d.id, label: d.data().label, createdAt: d.data().createdAt, lastUsed: d.data().lastUsed,
    unlocks: !!d.data().privateKey, synced: d.data().backedUp })).sort((a, b) => b.createdAt - a.createdAt) };
});

/** Signed in: remove one of your passkeys, or (administrator) one or all of someone else's. */
export const passkeyDelete = onCall(callOpts, async (req) => {
  const u = requireUser(req);
  const uid = u.admin && req.data?.uid ? String(req.data.uid) : u.uid;
  const q = await db.collection('passkeys').where('uid', '==', uid).get();
  const gone = q.docs.filter((d) => req.data?.all === true || d.id === req.data?.id);
  if (!gone.length) throw new HttpsError('not-found', req.data?.all ? 'They have no passkeys.' : 'That passkey was already removed.');
  await Promise.all(gone.map((d) => d.ref.delete()));
  const email = await userEmail(uid);
  await audit('passkey.remove', { target: email, note: gone.map((d) => d.data().label).join(', ') }, req);
  if (uid !== u.uid) await notify(email, 'Secure Transfer: your passkeys were removed',
    'An administrator removed passkeys from your Secure Transfer account. Sign in with your password and authenticator code.');
  return { removed: gone.length };
});
