// Security rules tests. Run on the emulators: npm run test:rules
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { initializeTestEnvironment, assertFails, assertSucceeds } from '@firebase/rules-unit-testing';
import { doc, getDoc, getDocs, setDoc, collection, query, where, Timestamp, serverTimestamp } from 'firebase/firestore';
import { ref, uploadBytes, getBytes } from 'firebase/storage';

let env;
const MFA = { firebase: { sign_in_provider: 'password', sign_in_second_factor: 'totp' } };
const later = () => Timestamp.fromMillis(Date.now() + 864e5);
const earlier = () => Timestamp.fromMillis(Date.now() - 864e5);

before(async () => {
  env = await initializeTestEnvironment({
    projectId: 'demo-secure-transfer',
    firestore: { rules: readFileSync('firestore.rules', 'utf8'), host: '127.0.0.1', port: 8080 },
    storage: { rules: readFileSync('storage.rules', 'utf8'), host: '127.0.0.1', port: 9199 },
  });
});
after(async () => { await env.cleanup(); });
beforeEach(async () => {
  await env.clearFirestore();
  await env.withSecurityRulesDisabled(async (ctx) => {
    const db = ctx.firestore();
    await setDoc(doc(db, 'folders/f1'), { members: {
      dl: { perm: 'download', until: later() },
      up: { perm: 'upload', until: later() },
      both: { perm: 'both', until: later() },
      gone: { perm: 'both', until: earlier() },
    } });
    await setDoc(doc(db, 'folders/f1/files/a'), { uploadedBy: 'admin1', everyone: true, visibleTo: ['admin1'] });
    await setDoc(doc(db, 'folders/f1/files/b'), { uploadedBy: 'up', everyone: false, visibleTo: ['up'] });
    await setDoc(doc(db, 'folders/f1/files/c'), { uploadedBy: 'admin1', everyone: false, visibleTo: ['admin1', 'both'] });
    await setDoc(doc(db, 'audit/x'), { action: 'test' });
    await setDoc(doc(db, 'privateKeys/dl'), { wrapped: 'w' });
  });
});

const user = (uid, extra = {}) => env.authenticatedContext(uid, { ...MFA, ...extra }).firestore();
const noMfa = (uid) => env.authenticatedContext(uid, { firebase: { sign_in_provider: 'password' } }).firestore();

test('nothing is readable without the authenticator step', async () => {
  await assertFails(getDoc(doc(noMfa('dl'), 'folders/f1')));
  await assertFails(getDoc(doc(noMfa('admin1'), 'audit/x')));
  await assertFails(getDoc(doc(env.unauthenticatedContext().firestore(), 'folders/f1')));
});

test('members see their folder; non-members and expired members do not', async () => {
  await assertSucceeds(getDoc(doc(user('dl'), 'folders/f1')));
  await assertFails(getDoc(doc(user('stranger'), 'folders/f1')));
  await assertFails(getDoc(doc(user('gone'), 'folders/f1')));
});

test('files: shared-with-everyone, named people, and upload-only members see only their own', async () => {
  await assertSucceeds(getDoc(doc(user('dl'), 'folders/f1/files/a')));
  await assertFails(getDoc(doc(user('dl'), 'folders/f1/files/b')));   // an outside uploader's file
  await assertFails(getDoc(doc(user('dl'), 'folders/f1/files/c')));   // shared with someone else by name
  await assertSucceeds(getDoc(doc(user('both'), 'folders/f1/files/c')));
  await assertSucceeds(getDoc(doc(user('up'), 'folders/f1/files/b')));
  await assertFails(getDoc(doc(user('up'), 'folders/f1/files/a')));
  await assertFails(getDocs(collection(user('up'), 'folders/f1/files')));
  // The queries the portal runs:
  await assertSucceeds(getDocs(query(collection(user('up'), 'folders/f1/files'), where('uploadedBy', '==', 'up'))));
  await assertSucceeds(getDocs(query(collection(user('dl'), 'folders/f1/files'), where('everyone', '==', true))));
  await assertSucceeds(getDocs(query(collection(user('both'), 'folders/f1/files'), where('visibleTo', 'array-contains', 'both'))));
  await assertFails(getDocs(collection(user('dl'), 'folders/f1/files')));
});

test('admins read everything; nobody writes access data from the browser', async () => {
  const admin = user('admin1', { admin: true });
  await assertSucceeds(getDoc(doc(admin, 'folders/f1/files/b')));
  await assertSucceeds(getDoc(doc(admin, 'audit/x')));
  await assertFails(getDoc(doc(user('dl'), 'audit/x')));
  await assertFails(setDoc(doc(admin, 'folders/f2'), { members: {} }));
  await assertFails(setDoc(doc(admin, 'audit/y'), { action: 'forged' }));
  await assertFails(setDoc(doc(user('dl'), 'folders/f1/files/c'), { uploadedBy: 'dl' }));
});

test('people manage only their own keys', async () => {
  await assertSucceeds(setDoc(doc(user('dl'), 'publicKeys/dl'), { jwk: { x: 1 }, createdAt: serverTimestamp() }));
  await assertFails(setDoc(doc(user('dl'), 'publicKeys/up'), { jwk: { x: 1 }, createdAt: serverTimestamp() }));
  await assertFails(setDoc(doc(user('dl'), 'publicKeys/dl'), { jwk: { x: 2 }, createdAt: serverTimestamp() })); // no replace
  await assertSucceeds(getDoc(doc(user('up'), 'publicKeys/dl')));
  await assertSucceeds(getDoc(doc(user('dl'), 'privateKeys/dl')));
  await assertFails(getDoc(doc(user('admin1', { admin: true }), 'privateKeys/dl')));
});

const st = (uid, extra = {}) => env.authenticatedContext(uid, { ...MFA, ...extra }).storage();
const bytes = new Uint8Array([1, 2, 3]);
const octet = { contentType: 'application/octet-stream' };

test('uploaders can add new encrypted objects in their own path only', async () => {
  await assertSucceeds(uploadBytes(ref(st('up'), 'folders/f1/up/file1'), bytes, octet));
  await assertSucceeds(uploadBytes(ref(st('both'), 'folders/f1/both/file2'), bytes, octet));
  await assertFails(uploadBytes(ref(st('up'), 'folders/f1/both/file3'), bytes, octet));   // someone else's path
  await assertFails(uploadBytes(ref(st('dl'), 'folders/f1/dl/file4'), bytes, octet));     // download-only
  await assertFails(uploadBytes(ref(st('gone'), 'folders/f1/gone/file5'), bytes, octet)); // access ended
  await assertFails(uploadBytes(ref(st('up'), 'folders/f1/up/file6'), bytes, { contentType: 'text/csv' }));
  await assertFails(uploadBytes(ref(st('up'), 'folders/f1/up/file1'), bytes, octet));     // no overwrite
});

test('nobody reads storage objects directly', async () => {
  await assertSucceeds(uploadBytes(ref(st('up'), 'folders/f1/up/file7'), bytes, octet));
  await assertFails(getBytes(ref(st('up'), 'folders/f1/up/file7')));
  await assertFails(getBytes(ref(st('admin1', { admin: true }), 'folders/f1/up/file7')));
});
