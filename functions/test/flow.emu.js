// End-to-end flows through the real Cloud Functions on the emulators: npm run test:flows (repo root).
// Callables are invoked over HTTP with unsigned ID tokens, which the Functions emulator accepts.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { getFirestore, Timestamp } from 'firebase-admin/firestore';
import { getStorage } from 'firebase-admin/storage';
import { getAuth } from 'firebase-admin/auth';
import * as C from '../../js/crypto.js';
import { softPasskey } from './webauthn-soft.js';

const PROJECT = 'demo-secure-transfer';
process.env.GCLOUD_PROJECT = PROJECT;
process.env.FIREBASE_CONFIG = JSON.stringify({ projectId: PROJECT, storageBucket: `${PROJECT}.appspot.com` });
process.env.FIREBASE_STORAGE_EMULATOR_HOST ||= '127.0.0.1:9199';
// Same Admin SDK app the functions use, so runCleanup can be run directly.
const { runCleanup } = await import('../src/index.js');
const db = getFirestore();
const bucket = getStorage().bucket();
const FAST = 1000;

function token(uid, { admin = false, mfa = true, email = `${uid}@example.gov` } = {}) {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  return `${b({ alg: 'none', typ: 'JWT' })}.${b({
    iss: `https://securetoken.google.com/${PROJECT}`, aud: PROJECT, sub: uid, user_id: uid, iat: now, exp: now + 3600, auth_time: now,
    email, ...(admin ? { admin: true } : {}),
    firebase: { sign_in_provider: 'password', ...(mfa ? { sign_in_second_factor: 'totp' } : {}) },
  })}.`;
}
// Every flow goes through the single "api" function, as the portal does; legacy() calls an old separate address.
async function call(name, data, who, headers = {}) { return post('api', { op: name, data }, who, headers); }
async function legacy(name, data, who) { return post(name, data, who); }
async function post(fn, data, who, headers = {}) {
  const res = await fetch(`http://127.0.0.1:5001/${PROJECT}/us-east1/${fn}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...(who ? { Authorization: `Bearer ${who}` } : {}), ...headers },
    body: JSON.stringify({ data }),
  });
  const body = await res.json();
  if (body.error) { const e = new Error(body.error.message); e.status = body.error.status; throw e; }
  return body.result;
}
const rejects = async (p, status) => { await assert.rejects(p, (e) => { assert.equal(e.status, status, e.message); return true; }); };

const K = {};
const ADMIN = token('admin1', { admin: true, email: 'nate@example.gov' });
async function seedUser(uid, admin = false) {
  K[uid] = await C.generateKeyPair();
  await db.doc(`users/${uid}`).set({ email: `${uid}@example.gov`, name: uid, admin, removed: false, createdAt: Date.now() });
  await db.doc(`publicKeys/${uid}`).set({ jwk: K[uid].publicJwk });
}
async function put(path, bytes) { await bucket.file(path).save(Buffer.from(bytes), { contentType: 'application/octet-stream' }); }
async function fetchBytes(url) { const r = await fetch(url); assert.equal(r.status, 200, 'download ' + url); return new Uint8Array(await r.arrayBuffer()); }

async function upload(fid, uid, who, text, options = {}) {
  const { recipients } = await call('recipients', { folder: fid }, who);
  const sealed = await C.sealFile(new TextEncoder().encode(text), `${uid}-${Date.now()}.csv`, recipients);
  const fileId = C.b64url(crypto.getRandomValues(new Uint8Array(12)));
  await put(`folders/${fid}/${uid}/${fileId}`, sealed.ciphertext);
  await call('finalizeUpload', { folder: fid, fileId, name: sealed.name, sha256: sealed.sha256, size: text.length, keys: sealed.keys, ext: 'csv', options }, who);
  return { fileId, recipients: recipients.map((r) => r.id) };
}
async function download(fid, fileId, uid, who) {
  const r = await call('getDownload', { folder: fid, file: fileId }, who);
  const ct = await fetchBytes(r.url);
  const out = await C.openFile({ keys: r.keys, name: r.name, sha256: r.sha256, ciphertext: ct }, uid, K[uid].privateKey);
  return new TextDecoder().decode(out.data);
}

let fid, bobUid, carolUid, BOB, CAROL;
before(async () => {
  await getAuth().createUser({ uid: 'admin1', email: 'nate@example.gov' });
  await seedUser('admin1', true);
  K.recovery = await C.generateKeyPair();
  await db.doc('settings/recovery').set({ jwk: K.recovery.publicJwk, setAt: Date.now() });
});

test('the authenticator step is required, and only admins manage', async () => {
  await rejects(call('listFolders', {}, token('admin1', { admin: true, mfa: false })), 'PERMISSION_DENIED');
  await rejects(call('listFolders', {}), 'UNAUTHENTICATED');
  await rejects(call('createFolder', { name: 'x', days: 7 }, token('someone')), 'PERMISSION_DENIED');
});

test('folder, invitations and permissions', async () => {
  ({ id: fid } = await call('createFolder', { name: 'Canvass', days: 7 }, ADMIN));
  bobUid = (await call('invite', { folder: fid, email: 'bob@example.gov', name: 'Bob', perm: 'download', days: 30 }, ADMIN)).uid;
  carolUid = (await call('invite', { folder: fid, email: 'carol@example.gov', name: 'Carol', perm: 'upload', days: 30 }, ADMIN)).uid;
  assert.ok((await getAuth().getUser(bobUid)).email === 'bob@example.gov');
  for (const uid of [bobUid, carolUid]) {
    K[uid] = await C.generateKeyPair();
    await db.doc(`publicKeys/${uid}`).set({ jwk: K[uid].publicJwk });
  }
  BOB = token(bobUid, { email: 'bob@example.gov' });
  CAROL = token(carolUid, { email: 'carol@example.gov' });
  const bobView = await call('listFolders', {}, BOB);
  assert.deepEqual(bobView.folders.map((f) => [f.id, f.perm]), [[fid, 'download']]);
  assert.equal(bobView.folders[0].members, undefined, 'members list is admin-only');
  assert.equal((await call('listFolders', {}, token('stranger'))).folders.length, 0);
});

test('admin file reaches the download member; fingerprints and recovery key work', async () => {
  const { fileId, recipients } = await upload(fid, 'admin1', ADMIN, 'precinct,votes\n101,422\n');
  assert.ok(recipients.includes(bobUid) && recipients.includes('recovery') && !recipients.includes(carolUid));
  assert.equal(await download(fid, fileId, bobUid, BOB), 'precinct,votes\n101,422\n');
  await rejects(call('getDownload', { folder: fid, file: fileId }, CAROL), 'PERMISSION_DENIED');
  const r = await call('getDownload', { folder: fid, file: fileId, useRecovery: true }, ADMIN);
  const out = await C.openFile({ keys: r.keys, name: r.name, sha256: r.sha256, ciphertext: await fetchBytes(r.url) }, 'recovery', K.recovery.privateKey);
  assert.equal(new TextDecoder().decode(out.data), 'precinct,votes\n101,422\n');
});

test('an outside uploader’s file goes only to the commission', async () => {
  const { fileId, recipients } = await upload(fid, carolUid, CAROL, 'signed,petition\n');
  assert.deepEqual(recipients.sort(), ['admin1', carolUid, 'recovery'].sort());
  await rejects(call('getDownload', { folder: fid, file: fileId }, BOB), 'PERMISSION_DENIED');
  assert.equal(await download(fid, fileId, carolUid, CAROL), 'signed,petition\n');
  assert.equal(await download(fid, fileId, 'admin1', ADMIN), 'signed,petition\n');
});

test('download limits and delete-after-download', async () => {
  const { fileId } = await upload(fid, 'admin1', ADMIN, 'once', { maxDownloads: 1, deleteAfterDownload: true });
  assert.equal(await download(fid, fileId, bobUid, BOB), 'once');
  await rejects(call('getDownload', { folder: fid, file: fileId }, BOB), 'PERMISSION_DENIED');
  const rec = (await db.doc(`folders/${fid}/files/${fileId}`).get()).data();
  assert.ok(rec.expiresAt.toMillis() < Date.now() + 11 * 60e3, 'set to delete within 10 minutes');
});

test('per-file visibility', async () => {
  const daveUid = (await call('invite', { folder: fid, email: 'dave@example.gov', name: 'Dave', perm: 'download', days: 30 }, ADMIN)).uid;
  K[daveUid] = await C.generateKeyPair();
  await db.doc(`publicKeys/${daveUid}`).set({ jwk: K[daveUid].publicJwk });
  const { fileId } = await upload(fid, 'admin1', ADMIN, 'for bob only', { visibleTo: [bobUid] });
  assert.equal(await download(fid, fileId, bobUid, BOB), 'for bob only');
  await rejects(call('getDownload', { folder: fid, file: fileId }, token(daveUid)), 'PERMISSION_DENIED');
});

test('removed members lose access at once', async () => {
  await call('updateMember', { folder: fid, uid: bobUid, remove: true }, ADMIN);
  await rejects(call('recipients', { folder: fid }, BOB), 'PERMISSION_DENIED');
});

test('drop-off: wrong code refused, right code delivers to the commission', async () => {
  const d = await call('createDropoff', { label: 'Petitions', days: 7, openDays: 7 }, ADMIN);
  await rejects(call('dropoffStart', { id: d.id, code: 'AAAAA-AAAAA', ext: 'pdf' }), 'PERMISSION_DENIED');
  await rejects(call('dropoffStart', { id: d.id, code: d.code, ext: 'exe' }), 'INVALID_ARGUMENT');
  const start = await call('dropoffStart', { id: d.id, code: d.code.toLowerCase(), ext: 'pdf' });
  assert.ok(start.recipients.some((r) => r.id === 'recovery') && start.recipients.some((r) => r.id === 'admin1'));
  const sealed = await C.sealFile(new TextEncoder().encode('%PDF-1.7'), 'petition.pdf', start.recipients);
  const dropFolder = (await db.doc(`dropoffs/${d.id}`).get()).data().folder;
  await put(`folders/${dropFolder}/dropoff/${start.fileId}`, sealed.ciphertext);
  await call('dropoffFinish', { id: d.id, code: d.code, fileId: start.fileId, name: sealed.name, sha256: sealed.sha256, size: 8, keys: sealed.keys, ext: 'pdf', sender: 'Pat, pat@example.com' });
  assert.equal(await download(dropFolder, start.fileId, 'admin1', ADMIN), '%PDF-1.7');
});

test('quick send: password, download limit, then gone', async () => {
  const sealed = await C.sealSend(new TextEncoder().encode('your record'), 'Record.pdf', 'maple-river-123',
    [{ id: 'admin1', publicJwk: K.admin1.publicJwk }, { id: 'recovery', publicJwk: K.recovery.publicJwk }], FAST);
  const fileId = C.b64url(crypto.getRandomValues(new Uint8Array(12)));
  await put(`sends/admin1/${fileId}`, sealed.ciphertext);
  const { id } = await call('createSend', { fileId, name: sealed.name, sha256: sealed.sha256, size: 11, keys: sealed.keys, ext: 'pdf',
    accessHash: sealed.accessHash, salt: sealed.salt, iterations: sealed.iterations, hasPassword: true, maxDownloads: 1, days: 7 }, ADMIN);
  const info = await call('sendInfo', { id });
  assert.equal(info.hasPassword, true); assert.equal(info.remaining, 1); assert.equal(info.label, '');
  await rejects(call('sendOpen', { id, access: await C.sendAccess(sealed.secret, 'wrong', info.salt, info.iterations) }), 'PERMISSION_DENIED');
  const r = await call('sendOpen', { id, access: await C.sendAccess(sealed.secret, 'maple-river-123', info.salt, info.iterations) });
  const out = await C.openSend(sealed.secret, 'maple-river-123', info.salt, info.iterations, { ...r, ciphertext: await fetchBytes(r.url) });
  assert.equal(new TextDecoder().decode(out.data), 'your record');
  await rejects(call('sendInfo', { id }), 'NOT_FOUND');
});

test('automatic deletion removes expired files, sends and memberships', async () => {
  const { fileId } = await upload(fid, 'admin1', ADMIN, 'old');
  const recPath = (await db.doc(`folders/${fid}/files/${fileId}`).get()).data().path;
  await db.doc(`folders/${fid}/files/${fileId}`).update({ expiresAt: Timestamp.fromMillis(Date.now() - 1000) });
  await db.doc(`folders/${fid}`).update({ [`members.${carolUid}.until`]: Timestamp.fromMillis(Date.now() - 1000) });
  const r = await runCleanup(Date.now());
  assert.ok(r.files >= 1 && r.members >= 1, JSON.stringify(r));
  assert.equal((await db.doc(`folders/${fid}/files/${fileId}`).get()).exists, false);
  assert.equal((await bucket.file(recPath).exists())[0], false);
  assert.equal((await db.doc(`folders/${fid}`).get()).data().members[carolUid], undefined);
});

test('administrators are never removed: not for being unused, not from the People page', async () => {
  await db.doc('users/admin1').update({ lastSignIn: Date.now() - 400 * 864e5, createdAt: Date.now() - 400 * 864e5 });
  await runCleanup(Date.now());
  assert.equal((await db.doc('users/admin1').get()).data().removed, false);
  await rejects(call('removeUser', { uid: 'admin1' }, ADMIN), 'FAILED_PRECONDITION');
});

test('activity log: everything recorded, chain intact, tampering detected', async () => {
  const v = await call('verifyLog', {}, ADMIN);
  assert.equal(v.ok, true, JSON.stringify(v));
  const actions = (await db.collection('audit').get()).docs.map((d) => d.data().entry.action);
  for (const a of ['folder.create', 'member.add', 'file.upload', 'file.download', 'dropoff.bad-code', 'dropoff.upload', 'send.create', 'send.bad-password', 'send.download', 'member.remove', 'cleanup']) {
    assert.ok(actions.includes(a), 'missing ' + a);
  }
  const csv = (await call('exportLog', {}, ADMIN)).csv;
  assert.match(csv, /^seq,time \(UTC\),action/);
  const first = (await db.collection('audit').orderBy('seq').limit(3).get()).docs[2];
  await first.ref.update({ 'entry.note': 'edited by someone' });
  const bad = await call('verifyLog', {}, ADMIN);
  assert.equal(bad.ok, false); assert.equal(bad.seq, 3); assert.equal(bad.reason, 'entry changed');
});

test('passkeys: add, sign in (unlocking files), reject a stranger\u2019s, remove', async () => {
  const site = { Origin: 'http://localhost:8000' };
  const pk = softPasskey('http://localhost:8000', 'localhost');
  await rejects(call('passkeyRegisterOptions', {}, ADMIN, { Origin: 'https://evil.example' }), 'FAILED_PRECONDITION');
  const reg = await call('passkeyRegisterOptions', {}, ADMIN, site);
  assert.equal(reg.options.rp.id, 'localhost');
  assert.equal(reg.options.authenticatorSelection.userVerification, 'required');
  const prf = crypto.getRandomValues(new Uint8Array(32));
  const extractable = await C.generateKeyPair();
  const wrapped = await C.wrapPrivateKeyWithPrf(extractable.privateKey, prf, pk.id);
  const done = await call('passkeyRegister', { id: reg.id, response: pk.register(reg.options), label: 'Test key', privateKey: wrapped }, ADMIN, site);
  assert.equal(done.unlocks, true);
  await rejects(call('passkeyRegister', { id: reg.id, response: pk.register(reg.options) }, ADMIN, site), 'DEADLINE_EXCEEDED'); // challenge used once

  const opts = await call('passkeyLoginOptions', {}, null, site);
  const r = await call('passkeyLogin', { id: opts.id, response: pk.login(opts.options) }, null, site);
  assert.equal(r.credentialId, pk.id);
  const key = await C.unwrapPrivateKeyWithPrf(r.privateKey, prf, r.credentialId);
  assert.equal(key.type, 'private');
  // The custom token signs in, and the resulting session passes the two-factor check.
  const s = await (await fetch(`http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=fake`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: r.token, returnSecureToken: true }) })).json();
  assert.ok(s.idToken, JSON.stringify(s));
  const listed = await call('passkeyList', {}, s.idToken);
  assert.equal(listed.passkeys.length, 1); assert.ok(listed.passkeys[0].lastUsed > 0);

  // A replayed sign-in, a passkey nobody registered, and a wrong origin all fail.
  const again = await call('passkeyLoginOptions', {}, null, site);
  await rejects(call('passkeyLogin', { id: opts.id, response: pk.login(again.options) }, null, site), 'DEADLINE_EXCEEDED');
  const stranger = softPasskey('http://localhost:8000', 'localhost');
  await rejects(call('passkeyLogin', { id: again.id, response: stranger.login(again.options) }, null, site), 'PERMISSION_DENIED');
  const o3 = await call('passkeyLoginOptions', {}, null, site);
  await rejects(call('passkeyLogin', { id: o3.id, response: pk.login(o3.options, { asOrigin: 'https://evil.example' }) }, null, site), 'PERMISSION_DENIED');

  // A passkey that gave no unlock copy at first can have one added by its owner, and only its owner.
  await rejects(call('passkeySetUnlock', { credentialId: pk.id, privateKey: wrapped }, BOB), 'NOT_FOUND');
  await call('passkeySetUnlock', { credentialId: pk.id, privateKey: wrapped }, s.idToken);

  // Removing works, and the passkey then no longer signs in.
  await call('passkeyDelete', { uid: 'admin1', all: true }, ADMIN);
  const o4 = await call('passkeyLoginOptions', {}, null, site);
  await rejects(call('passkeyLogin', { id: o4.id, response: pk.login(o4.options) }, null, site), 'PERMISSION_DENIED');
});

test('forgot password answers the same for real and unknown addresses', async () => {
  assert.deepEqual(await call('requestPasswordEmail', { email: 'nobody@example.gov' }), { ok: true });
  assert.deepEqual(await call('requestPasswordEmail', { email: 'nate@example.gov' }), { ok: true });
  assert.deepEqual(await call('requestPasswordEmail', { email: 'not an email' }), { ok: true });
});

test('one entry point: ping needs no sign-in, unknown actions refused, old addresses still work', async () => {
  assert.deepEqual(await post('api', { op: 'ping' }), { ok: true });
  await rejects(call('nope', {}, ADMIN), 'NOT_FOUND');
  await rejects(call('hasOwnProperty', {}, ADMIN), 'NOT_FOUND');
  const viaApi = await call('listFolders', {}, ADMIN);
  const viaOld = await legacy('listFolders', {}, ADMIN);
  assert.deepEqual(viaOld.folders.map((f) => f.id), viaApi.folders.map((f) => f.id));
  await rejects(legacy('listFolders', {}, null), 'UNAUTHENTICATED');
});
