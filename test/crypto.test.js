import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as c from '../js/crypto.js';

const FAST = 1000; // PBKDF2 iterations for tests only

test('private key round-trips under the right password and fails under a wrong one', async () => {
  const { privateKey } = await c.generateKeyPair();
  const rec = await c.wrapPrivateKey(privateKey, 'correct horse', FAST);
  const back = await c.unwrapPrivateKey(rec, 'correct horse');
  assert.equal(back.type, 'private');
  await assert.rejects(c.unwrapPrivateKey(rec, 'wrong'), /Wrong password/);
});

test('a sealed file opens for each recipient and for the recovery key, and the name is hidden', async () => {
  const alice = await c.generateKeyPair(), bob = await c.generateKeyPair(), rec = await c.generateKeyPair();
  const data = new TextEncoder().encode('precinct,votes\n101,422\n');
  const sealed = await c.sealFile(data, 'Totals.csv', [
    { id: 'alice', publicJwk: alice.publicJwk }, { id: 'bob', publicJwk: bob.publicJwk },
    { id: 'recovery', publicJwk: rec.publicJwk }]);
  assert.ok(!JSON.stringify(sealed.name).includes('Totals'));
  for (const [id, kp] of [['alice', alice], ['bob', bob], ['recovery', rec]]) {
    const out = await c.openFile(sealed, id, kp.privateKey);
    assert.equal(out.fileName, 'Totals.csv');
    assert.deepEqual(out.data, data);
    assert.equal(out.sha256, await c.sha256Hex(data));
  }
});

test('someone not on the list cannot open it, even with another entry', async () => {
  const a = await c.generateKeyPair(), r = await c.generateKeyPair(), eve = await c.generateKeyPair();
  const sealed = await c.sealFile(new Uint8Array([1, 2, 3]), 'x.txt',
    [{ id: 'a', publicJwk: a.publicJwk }, { id: 'recovery', publicJwk: r.publicJwk }]);
  await assert.rejects(c.openFile(sealed, 'eve', eve.privateKey), /not shared/);
  await assert.rejects(c.unwrapFileKey(sealed.keys.a, 'a', eve.privateKey), /cannot open/);
  // An entry made for "a" cannot be relabelled for another recipient id.
  await assert.rejects(c.unwrapFileKey(sealed.keys.a, 'recovery', a.privateKey), /cannot open/);
});

test('sealing without the recovery key is refused', async () => {
  const a = await c.generateKeyPair();
  await assert.rejects(c.sealFile(new Uint8Array(1), 'x', [{ id: 'a', publicJwk: a.publicJwk }]), /recovery/);
});

test('multi-chunk files survive; tampering, truncation and reordering are caught', async () => {
  const key = await c.newFileKey();
  const data = globalThis.crypto.getRandomValues(new Uint8Array(65536));
  const big = new Uint8Array(c.CHUNK_SIZE * 2 + 1234);
  for (let i = 0; i < big.length; i += 65536) big.set(data.subarray(0, Math.min(65536, big.length - i)), i);
  const { ciphertext } = await c.encryptFile(key, big);
  const ok = await c.decryptFile(key, ciphertext);
  assert.deepEqual(ok.data, big);

  const flipped = ciphertext.slice(); flipped[flipped.length - 5] ^= 1;
  await assert.rejects(c.decryptFile(key, flipped), /changed or damaged/);

  const full = c.CHUNK_SIZE + 16;
  const truncated = ciphertext.slice(0, 16 + full * 2); // drop the last chunk
  await assert.rejects(c.decryptFile(key, truncated), /changed or damaged/);

  const swapped = ciphertext.slice();
  swapped.set(ciphertext.subarray(16 + full, 16 + 2 * full), 16);
  swapped.set(ciphertext.subarray(16, 16 + full), 16 + full);
  await assert.rejects(c.decryptFile(key, swapped), /changed or damaged/);
});

test('empty files work', async () => {
  const key = await c.newFileKey();
  const { ciphertext } = await c.encryptFile(key, new Uint8Array(0));
  const out = await c.decryptFile(key, ciphertext);
  assert.equal(out.data.length, 0);
});

test('public key fingerprints are stable and readable', async () => {
  const { publicJwk } = await c.generateKeyPair();
  const f = await c.publicKeyFingerprint(publicJwk);
  assert.match(f, /^[0-9a-f]{4}( [0-9a-f]{4}){4}$/);
  assert.equal(f, await c.publicKeyFingerprint({ ...publicJwk }));
});

test('quick send: link + password open it; wrong password or link fails; access hash matches', async () => {
  const rec = await c.generateKeyPair();
  const data = new TextEncoder().encode('one file, one time');
  const s = await c.sealSend(data, 'Notice.txt', 'river terminal 700', [{ id: 'recovery', publicJwk: rec.publicJwk }], FAST);
  const access = await c.sendAccess(s.secret, 'river terminal 700', s.salt, s.iterations);
  assert.equal(await c.sha256Hex(new TextEncoder().encode(access)), s.accessHash);
  const wrongAccess = await c.sendAccess(s.secret, 'wrong', s.salt, s.iterations);
  assert.notEqual(await c.sha256Hex(new TextEncoder().encode(wrongAccess)), s.accessHash);
  const out = await c.openSend(s.secret, 'river terminal 700', s.salt, s.iterations, s);
  assert.equal(out.fileName, 'Notice.txt');
  assert.deepEqual(out.data, data);
  await assert.rejects(c.openSend(s.secret, 'wrong', s.salt, s.iterations, s));
  const other = c.b64url(crypto.getRandomValues(new Uint8Array(24)));
  await assert.rejects(c.openSend(other, 'river terminal 700', s.salt, s.iterations, s));
  // The commission can still open it with the recovery key.
  const viaRecovery = await c.openFile(s, 'recovery', rec.privateKey);
  assert.equal(viaRecovery.fileName, 'Notice.txt');
});

test('quick send without a password works from the link alone', async () => {
  const rec = await c.generateKeyPair();
  const s = await c.sealSend(new Uint8Array([9, 9]), 'a.csv', '', [{ id: 'recovery', publicJwk: rec.publicJwk }], FAST);
  const out = await c.openSend(s.secret, '', s.salt, s.iterations, s);
  assert.deepEqual(out.data, new Uint8Array([9, 9]));
});
