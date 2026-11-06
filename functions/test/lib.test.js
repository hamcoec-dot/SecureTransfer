import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as L from '../src/lib.js';

test('audit chain verifies, and detects edits, gaps and reordering', () => {
  const rows = [];
  let prev = L.GENESIS;
  for (let seq = 1; seq <= 5; seq++) {
    const entry = { at: seq, action: 'x', note: 'n' + seq };
    const hash = L.chainHash(prev, seq, entry);
    rows.push({ seq, prevHash: prev, hash, entry });
    prev = hash;
  }
  assert.equal(L.verifyChain(rows).ok, true);
  const edited = structuredClone(rows); edited[2].entry.note = 'changed';
  assert.deepEqual(L.verifyChain(edited), { ok: false, seq: 3, reason: 'entry changed' });
  const gap = rows.filter((r) => r.seq !== 3);
  assert.equal(L.verifyChain(gap).reason, 'missing entry');
  const rehashed = structuredClone(rows); rehashed[2].entry.note = 'x'; rehashed[2].hash = L.chainHash(rehashed[2].prevHash, 3, rehashed[2].entry);
  assert.equal(L.verifyChain(rehashed).reason, 'chain broken');
});

test('canonical JSON ignores key order', () => {
  assert.equal(L.canonical({ b: 1, a: [1, { d: 2, c: 3 }] }), L.canonical({ a: [1, { c: 3, d: 2 }], b: 1 }));
});

test('CSV quotes and defuses spreadsheet formulas', () => {
  assert.equal(L.toCsv(['a'], [['=SUM(A1)'], ['x,"y"']]), 'a\r\n\'=SUM(A1)\r\n"x,""y"""\r\n');
});

test('access follows permission and end date', () => {
  const now = 1000;
  assert.deepEqual(L.access({ perm: 'upload', until: 2000 }, now, false), { read: true, upload: true, readAll: false });
  assert.deepEqual(L.access({ perm: 'download', until: 2000 }, now, false), { read: true, upload: false, readAll: true });
  assert.equal(L.access({ perm: 'both', until: 999 }, now, false).read, false);
  assert.equal(L.access(undefined, now, true).readAll, true);
});

test('download rules: own files, per-file visibility, limits', () => {
  const dl = L.access({ perm: 'download', until: 2 }, 1, false);
  const up = L.access({ perm: 'upload', until: 2 }, 1, false);
  const admin = L.access(undefined, 1, true);
  const f = { uploadedBy: 'admin', visibleTo: ['bob'], maxDownloads: 1, downloads: 0 };
  assert.equal(L.mayDownload(f, 'bob', dl).ok, true);
  assert.equal(L.mayDownload(f, 'carol', dl).ok, false);
  assert.equal(L.mayDownload(f, 'bob', up).ok, false);
  assert.equal(L.mayDownload({ ...f, downloads: 1 }, 'bob', dl).ok, false);
  assert.equal(L.mayDownload({ ...f, downloads: 1 }, 'admin', admin).ok, true);
  assert.equal(L.mayDownload({ uploadedBy: 'up1' }, 'up1', up).ok, true);
});

test('drop-off codes are readable, hashed and compared safely', () => {
  const code = L.newDropoffCode();
  assert.match(code, /^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
  const salt = 's';
  const h = L.hashCode(code, salt);
  assert.equal(L.codeMatches(code.toLowerCase().replace('-', ' '), salt, h), true);
  assert.equal(L.codeMatches('AAAAA-AAAAA', salt, h), false);
});

test('file types and text cleaning', () => {
  assert.equal(L.extensionAllowed('Totals.CSV'), true);
  assert.equal(L.extensionAllowed('setup.exe'), false);
  assert.equal(L.extensionAllowed('noext'), false);
  assert.equal(L.cleanText(' a\u0000b ', 10), 'a b');
  assert.equal(L.isEmail('a@b.gov'), true);
  assert.equal(L.isEmail('nope'), false);
});
