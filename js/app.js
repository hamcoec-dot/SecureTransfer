// Secure Transfer portal. Talks to Firebase; every file, file name, message and note is encrypted here in the
// browser before it leaves the device (see crypto.js).
import { initializeApp } from 'https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js';
import {
  getAuth, connectAuthEmulator, setPersistence, browserSessionPersistence, signInWithEmailAndPassword,
  getMultiFactorResolver, TotpMultiFactorGenerator, multiFactor, sendPasswordResetEmail, signOut, onAuthStateChanged,
  verifyPasswordResetCode, confirmPasswordReset, signInWithCustomToken,
} from 'https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js';
import {
  getFirestore, connectFirestoreEmulator, doc, getDoc, setDoc, collection, query, where, orderBy, limit, getDocs,
  serverTimestamp,
} from 'https://www.gstatic.com/firebasejs/11.10.0/firebase-firestore.js';
import { getStorage, connectStorageEmulator, ref as sref, uploadBytesResumable } from 'https://www.gstatic.com/firebasejs/11.10.0/firebase-storage.js';
import { getFunctions, connectFunctionsEmulator, httpsCallable } from 'https://www.gstatic.com/firebasejs/11.10.0/firebase-functions.js';
import { initializeAppCheck, ReCaptchaEnterpriseProvider } from 'https://www.gstatic.com/firebasejs/11.10.0/firebase-app-check.js';
import { CONFIG, MODE, FUNCTIONS_REGION, IDLE_MINUTES, PORTAL_URL } from './config.js';
import * as C from './crypto.js';

// ---------------------------------------------------------------- Firebase
const app = initializeApp(CONFIG);
if (CONFIG.recaptchaKey) initializeAppCheck(app, { provider: new ReCaptchaEnterpriseProvider(CONFIG.recaptchaKey), isTokenAutoRefreshEnabled: true });
const auth = getAuth(app);
const db = getFirestore(app);
const storage = getStorage(app);
const fns = getFunctions(app, FUNCTIONS_REGION);
if (MODE === 'emulator') {
  connectAuthEmulator(auth, 'http://127.0.0.1:9099', { disableWarnings: true });
  connectFirestoreEmulator(db, '127.0.0.1', 8080);
  connectStorageEmulator(storage, '127.0.0.1', 9199);
  connectFunctionsEmulator(fns, '127.0.0.1', 5001);
}
setPersistence(auth, browserSessionPersistence);
const call = (name) => async (data) => (await httpsCallable(fns, name, { timeout: 120000 })(data)).data;
const api = Object.fromEntries(['recordSignIn', 'invite', 'updateMember', 'removeUser', 'approveReset', 'replaceKey',
  'listFolders', 'createFolder', 'updateFolder', 'deleteFolder', 'recipients', 'finalizeUpload', 'getDownload', 'deleteFile',
  'addFileKeys', 'postMessage', 'openThread', 'createDropoff', 'dropoffStart', 'dropoffFinish', 'saveSettings',
  'setRecoveryKey', 'exportLog', 'verifyLog', 'mailStatus', 'createSend', 'sendInfo', 'sendOpen', 'deleteSend',
  'passkeyRegisterOptions', 'passkeyRegister', 'passkeyLoginOptions', 'passkeyLogin', 'passkeyList', 'passkeyDelete'].map((n) => [n, call(n)]));

// ---------------------------------------------------------------- state
const S = { user: null, admin: false, name: '', privateKey: null, folders: [], files: {}, people: [], route: 'overview', arg: null };
const DAY = 864e5;
const PERM_TEXT = { download: 'Download only', upload: 'Upload only', both: 'Upload & download', admin: 'Administrator' };
const DAYS = [1, 7, 14, 30, 60, 90, 180];

// ---------------------------------------------------------------- tiny helpers
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const tsMs = (t) => (t && typeof t.toMillis === 'function' ? t.toMillis() : Number(t) || 0);
function fmtSize(b) { if (b < 1024) return b + ' B'; if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'; return (b / 1048576).toFixed(1) + ' MB'; }
function fmtDate(t) { return new Date(t).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }); }
function fmtWhen(t) {
  const h = (Date.now() - t) / 36e5;
  if (h < 1 / 60) return 'Just now';
  if (h < 1) return Math.round(h * 60) + ' min ago';
  if (h < 24) return Math.round(h) + ' h ago';
  return new Date(t).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}
function left(t) {
  const d = (t - Date.now()) / DAY;
  if (d < 1) return { txt: Math.max(1, Math.round(d * 24)) + ' h left', cls: 'bad' };
  if (d < 3) return { txt: Math.ceil(d) + ' days left', cls: 'warn' };
  return { txt: Math.ceil(d) + ' days left', cls: '' };
}
const initials = (n) => String(n || '?').split(/[\s@.]+/).filter(Boolean).map((w) => w[0]).slice(0, 2).join('').toUpperCase();
const extOf = (n) => (/\.([a-z0-9]+)$/i.exec(n) || [, ''])[1].toLowerCase();
let toastT;
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => { t.hidden = true; }, 4000); }
function errText(e) {
  const m = (e?.message || String(e)).replace(/^Firebase:\s*/, '').replace(/\s*\(auth\/[^)]+\)\.?$/, '');
  // A bare "Error" helps nobody: show the code so a screenshot says what went wrong.
  return m && m !== 'Error' ? m : `Something went wrong (${e?.code || 'unknown'}). Try again in a minute.`;
}
function saveBlob(data, name, type = 'application/octet-stream') {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60e3);
}
function deviceId() {
  try {
    let id = localStorage.getItem('st-device');
    if (!id) { id = C.toB64(crypto.getRandomValues(new Uint8Array(12))).replace(/[^A-Za-z0-9]/g, ''); localStorage.setItem('st-device', id); }
    return id;
  } catch { return ''; }
}
function deviceLabel() {
  const ua = navigator.userAgent;
  const os = /Windows/.test(ua) ? 'Windows' : /iPhone|iPad/.test(ua) ? 'iPhone/iPad' : /Android/.test(ua) ? 'Android' : /Mac/.test(ua) ? 'Mac' : 'Other';
  const br = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'browser';
  return `${br} on ${os}`;
}

// ---------------------------------------------------------------- dialogs
/** Opens the shared dialog. fields: html string. Resolves with FormData values, or null on cancel. */
function dialog({ title, sub = '', body = '', ok = 'OK', danger = false, cancel = 'Cancel', onOpen }) {
  const dlg = $('#dlg'), form = $('#dlg-form');
  form.innerHTML = `<div class="dlg-h"><h2 id="dlg-title">${esc(title)}</h2>${sub ? `<p>${sub}</p>` : ''}</div>
    <div class="dlg-b form">${body}<p class="field-error" id="dlg-err" role="alert"></p></div>
    <div class="dlg-f">${cancel ? `<button class="btn" value="cancel" formnovalidate>${esc(cancel)}</button>` : ''}
    <button class="btn primary" value="ok"${danger ? ' style="background:var(--bad);border-color:var(--bad)"' : ''}>${esc(ok)}</button></div>`;
  return new Promise((resolve) => {
    form.onsubmit = (e) => {
      const btn = e.submitter;
      if (btn?.value === 'ok' && !form.checkValidity()) { e.preventDefault(); $('#dlg-err').textContent = 'Fill in the required fields.'; form.reportValidity(); return; }
      e.preventDefault();
      dlg.close();
      if (btn?.value !== 'ok') return resolve(null);
      const out = {};
      for (const el of form.elements) {
        if (!el.name) continue;
        if (el.type === 'checkbox') { (out[el.name] ||= []); if (el.checked) out[el.name].push(el.value); }
        else if (el.type === 'radio') { if (el.checked) out[el.name] = el.value; }
        else out[el.name] = el.value;
      }
      resolve(out);
    };
    dlg.oncancel = () => resolve(null);
    dlg.showModal();
    onOpen?.(form);
    form.querySelector('input,select,textarea')?.focus();
  });
}
const daySelect = (name, value, max = 180) => `<select name="${name}" id="${name}">${DAYS.filter((d) => d <= max).map((d) =>
  `<option value="${d}"${d === value ? ' selected' : ''}>${d === 1 ? '1 day' : d + ' days'}</option>`).join('')}</select>`;

// ---------------------------------------------------------------- key cache for this tab
// The unlocked private key is kept as a non-exportable CryptoKey in IndexedDB so a reload of the same tab
// doesn't ask for the password again. A marker in sessionStorage ties it to this tab: a new tab or a closed
// browser finds no marker and wipes the cached key. Sign-out and idle sign-out wipe it too.
function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('secure-transfer', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('keys');
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function idbDo(mode, fn) {
  const d = await idb();
  return new Promise((res, rej) => { const t = d.transaction('keys', mode); const out = fn(t.objectStore('keys')); t.oncomplete = () => res(out.result); t.onerror = () => rej(t.error); });
}
async function cacheKey(uid, key) {
  try { sessionStorage.setItem('st-tab', uid); await idbDo('readwrite', (st) => st.put(key, uid)); } catch {}
}
async function cachedKey(uid) {
  try {
    if (sessionStorage.getItem('st-tab') !== uid) { await clearKeys(); return null; }
    return (await idbDo('readonly', (st) => st.get(uid))) || null;
  } catch { return null; }
}
async function clearKeys() {
  try { sessionStorage.removeItem('st-tab'); await idbDo('readwrite', (st) => st.clear()); } catch {}
}

// ---------------------------------------------------------------- sign-in
let resolver = null, pendingPassword = '', enrollSecret = null, pendingPrf = null;
function showStep(id) {
  for (const f of ['#f-pass', '#f-code', '#f-enroll', '#f-busy', '#f-setpass', '#f-unlock']) $(f).hidden = f !== id;
  $('#step2bar').className = id === '#f-pass' ? '' : 'on';
  $(id).querySelector('input')?.focus();
}
function showSignIn() {
  $('#app').hidden = true; $('#dropoff').hidden = true; $('#sendpage').hidden = true; $('#signin').hidden = false;
  if (resetCode) return;
  showStep('#f-pass');
}

// Password setup and reset links land here (the email's action link points at this page).
const params = new URLSearchParams(location.search);
let resetCode = params.get('mode') === 'resetPassword' ? params.get('oobCode') : null;
async function startSetPassword() {
  $('#signin').hidden = false; $('#app').hidden = true;
  try {
    const email = await verifyPasswordResetCode(auth, resetCode);
    $('#sp-email').textContent = email;
    $('#si-email').value = email;
    showStep('#f-setpass');
  } catch {
    resetCode = null;
    showStep('#f-pass');
    $('#err-pass').textContent = 'That link has expired or was already used. Type your email and click \u201cForgot your password?\u201d for a new one.';
  }
}
$('#f-setpass').addEventListener('submit', async (e) => {
  e.preventDefault();
  const a = $('#sp-pass').value, b = $('#sp-pass2').value, err = $('#err-setpass');
  if (a.length < 12) { err.textContent = 'Use at least 12 characters.'; return; }
  if (a !== b) { err.textContent = 'The two passwords don\u2019t match.'; return; }
  try {
    await confirmPasswordReset(auth, resetCode, a);
    resetCode = null;
    history.replaceState(null, '', location.pathname + (params.has('staging') ? '?staging' : ''));
    $('#sp-pass').value = $('#sp-pass2').value = '';
    showStep('#f-pass');
    toast('Password saved. Sign in now.');
  } catch (ex) {
    err.textContent = ex.code === 'auth/weak-password' ? 'Pick a longer password.' : errText(ex);
  }
});
if (resetCode) startSetPassword();

$('#f-pass').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#err-pass').textContent = '';
  const email = $('#si-email').value.trim(), pass = $('#si-pass').value;
  if (!email || !pass) { $('#err-pass').textContent = 'Enter your email and password.'; return; }
  pendingPassword = pass;
  try {
    const cred = await signInWithEmailAndPassword(auth, email, pass);
    // Signed in with only a password: the account has no authenticator yet. Set one up now.
    await startEnroll(cred.user);
  } catch (err) {
    if (err.code === 'auth/multi-factor-auth-required') {
      resolver = getMultiFactorResolver(auth, err);
      showStep('#f-code');
    } else if (['auth/invalid-credential', 'auth/wrong-password', 'auth/user-not-found', 'auth/invalid-email'].includes(err.code)) {
      $('#err-pass').textContent = 'That email and password don’t match an account.';
    } else if (err.code === 'auth/too-many-requests') {
      $('#err-pass').textContent = 'Too many tries. Wait a few minutes, or reset your password.';
    } else if (err.code === 'auth/user-disabled') {
      $('#err-pass').textContent = 'This account no longer has access. Contact the Election Commission.';
    } else {
      $('#err-pass').textContent = errText(err);
    }
  }
});

$('#f-code').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#err-code').textContent = '';
  const code = $('#si-code').value.replace(/\D/g, '');
  const hint = resolver?.hints.find((h) => h.factorId === TotpMultiFactorGenerator.FACTOR_ID);
  if (!hint) { $('#err-code').textContent = 'This account has no authenticator set up. Contact the Election Commission.'; return; }
  try {
    await resolver.resolveSignIn(TotpMultiFactorGenerator.assertionForSignIn(hint.uid, code));
    $('#si-code').value = '';
  } catch (err) {
    $('#err-code').textContent = err.code === 'auth/invalid-verification-code' ? 'That code didn’t work. Check the app and try the newest code.' : errText(err);
  }
});

async function startEnroll(user) {
  try {
    const session = await multiFactor(user).getSession();
    enrollSecret = await TotpMultiFactorGenerator.generateSecret(session);
    const url = enrollSecret.generateQrCodeUrl(user.email, 'HCEC Secure Transfer');
    $('#totp-secret').textContent = enrollSecret.secretKey;
    const qrBox = $('#qr');
    qrBox.innerHTML = '';
    if (window.qrcode) {
      const qr = window.qrcode(0, 'M'); qr.addData(url); qr.make();
      qrBox.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 2, scalable: true });
      qrBox.firstElementChild.setAttribute('style', 'width:200px;height:200px');
      qrBox.firstElementChild.setAttribute('aria-label', 'QR code for your authenticator app');
    }
    showStep('#f-enroll');
  } catch (err) {
    await signOut(auth);
    showStep('#f-pass');
    $('#err-pass').textContent = err.code === 'auth/unverified-email'
      ? 'Finish setting your password from the invitation email first, then sign in.'
      : 'Couldn’t start authenticator setup: ' + errText(err);
  }
}
$('#f-enroll').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#err-enroll').textContent = '';
  try {
    const code = $('#en-code').value.replace(/\D/g, '');
    await multiFactor(auth.currentUser).enroll(TotpMultiFactorGenerator.assertionForEnrollment(enrollSecret, code), 'Authenticator app');
    // Enrolling ends the session; sign in again with the new code so every token carries the second step.
    toast('Authenticator turned on. Sign in again with a new code.');
    $('#en-code').value = '';
    await signOut(auth).catch(() => {});
    showStep('#f-pass');
  } catch (err) {
    $('#err-enroll').textContent = err.code === 'auth/invalid-verification-code' ? 'That code didn’t work. Try the newest one.' : errText(err);
  }
});

$('#forgot').addEventListener('click', async () => {
  const email = $('#si-email').value.trim();
  if (!email) { $('#err-pass').textContent = 'Type your email above first.'; return; }
  try { await sendPasswordResetEmail(auth, email, { url: PORTAL_URL }); } catch { /* same message either way */ }
  $('#err-pass').textContent = '';
  toast('If that address has an account, a reset link is on its way. Files shared before the reset need the Commission to re-share them.');
});
$('#signout').addEventListener('click', () => signOutNow('Signed out.'));
async function signOutNow(msg) {
  S.privateKey = null; S.files = {}; S.folders = [];
  await clearKeys();
  await signOut(auth).catch(() => {});
  if (msg) toast(msg);
}

// Idle sign-out
let idleT;
function bumpIdle() { clearTimeout(idleT); if (S.user) idleT = setTimeout(() => signOutNow('Signed out after 30 minutes without activity.'), IDLE_MINUTES * 60e3); }
['pointerdown', 'keydown', 'scroll'].forEach((ev) => addEventListener(ev, bumpIdle, { passive: true }));

// The skip link must not touch the address: routes and Quick send secrets live in the fragment.
document.getElementById('skip')?.addEventListener('click', (e) => {
  e.preventDefault();
  [...document.querySelectorAll('main')].find((m) => m.offsetParent !== null)?.focus();
});
const isPublicLink = () => location.hash.startsWith('#dropoff-') || location.hash.startsWith('#send-');
function showPublicLink() { return location.hash.startsWith('#send-') ? showSendPage() : showDropoff(); }
onAuthStateChanged(auth, async (user) => {
  if (isPublicLink()) return showPublicLink();
  if (!user) { S.user = null; return showSignIn(); }
  const tok = await user.getIdTokenResult();
  if (!tok.claims.firebase?.sign_in_second_factor && tok.claims.passkey !== true) return; // still in enrollment
  S.user = user; S.admin = tok.claims.admin === true;
  $('#signin').hidden = false; showStep('#f-busy');
  try {
    S.info = await api.recordSignIn({ deviceId: deviceId(), deviceLabel: deviceLabel() });
    S.name = S.info.name || user.email;
    await unlockKeys(user, S.info.needsKey);
    pendingPassword = '';
    await enterApp(user);
  } catch (err) {
    if (err.code === 'need-password') {
      $('#ul-email').value = user.email || ''; $('#err-unlock').textContent = ''; showStep('#f-unlock');
      return;
    }
    await signOutNow();
    showSignIn();
    $('#err-pass').textContent = errText(err);
  }
});
async function enterApp(user) {
  $('#me-name').textContent = S.name; $('#me-initials').textContent = initials(S.name);
  $('#me-role').textContent = S.admin ? 'Administrator' : user.email;
  document.body.classList.toggle('is-admin', S.admin);
  if (MODE !== 'prod') { $('#env-bar').hidden = false; $('#env-bar').textContent = MODE === 'staging' ? 'Test site: use only test files.' : 'Local emulators.'; }
  $('#signin').hidden = true; $('#app').hidden = false;
  bumpIdle();
  await loadFolders();
  route();
}

// Signed in (passkey, or a reload in a new tab) but the files key isn't unlocked yet: the password unwraps it.
$('#f-unlock').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pass = $('#ul-pass').value;
  if (!pass || !S.user) return;
  $('#err-unlock').textContent = '';
  try {
    const snap = await getDoc(doc(db, `privateKeys/${S.user.uid}`));
    S.privateKey = await C.unwrapPrivateKey(snap.data(), pass);
    $('#ul-pass').value = '';
    await cacheKey(S.user.uid, S.privateKey);
    await enterApp(S.user);
  } catch (err) {
    $('#err-unlock').textContent = /Wrong password/.test(err.message) ? 'That password didn’t unlock your files.' : errText(err);
  }
});
$('#ul-cancel').addEventListener('click', () => signOutNow('Signed out.'));

// ---------------------------------------------------------------- passkeys (WebAuthn)
// The browser, the operating system (Windows Hello, iCloud Keychain, Google Password Manager) or an extension
// such as Bitwarden holds the passkey. Its PRF output, which never leaves this page, unlocks the files key.
const fromU = (s) => C.fromB64url(s);
const toU = (b) => C.b64url(new Uint8Array(b));
const pkCreate = (o) => ({ ...o, challenge: fromU(o.challenge), user: { ...o.user, id: fromU(o.user.id) },
  excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: fromU(c.id) })) });
const pkGet = (o) => ({ ...o, challenge: fromU(o.challenge), allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: fromU(c.id) })) });
function credJSON(c) {
  const r = c.response;
  const out = { id: c.id, rawId: toU(c.rawId), type: c.type, clientExtensionResults: {}, response: { clientDataJSON: toU(r.clientDataJSON) } };
  if (c.authenticatorAttachment) out.authenticatorAttachment = c.authenticatorAttachment;
  if (r.attestationObject) { out.response.attestationObject = toU(r.attestationObject); out.response.transports = r.getTransports?.() || []; }
  if (r.authenticatorData) {
    out.response.authenticatorData = toU(r.authenticatorData); out.response.signature = toU(r.signature);
    if (r.userHandle) out.response.userHandle = toU(r.userHandle);
  }
  return out;
}
const prfOf = (c) => { const x = c?.getClientExtensionResults?.().prf?.results?.first; return x ? new Uint8Array(x) : null; };
const PRF_EXT = { prf: { eval: { first: C.PASSKEY_PRF_SALT } } };
if (window.PublicKeyCredential) $('#pk-signin').hidden = false;

$('#pk-signin').addEventListener('click', async () => {
  $('#err-pass').textContent = '';
  try {
    const { id, options } = await api.passkeyLoginOptions({});
    const cred = await navigator.credentials.get({ publicKey: { ...pkGet(options), extensions: PRF_EXT } });
    if (!cred) return;
    showStep('#f-busy'); $('#busy-text').textContent = 'Signing in…';
    const r = await api.passkeyLogin({ id, response: credJSON(cred) });
    const prf = prfOf(cred);
    pendingPrf = r.privateKey && prf ? { record: r.privateKey, prf, credentialId: r.credentialId } : null;
    await signInWithCustomToken(auth, r.token);
  } catch (err) {
    showStep('#f-pass');
    $('#err-pass').textContent = err.name === 'NotAllowedError' ? 'The passkey request was cancelled or timed out.' : errText(err);
  }
});

async function addPasskey() {
  if (!window.PublicKeyCredential) { toast('This browser can’t use passkeys.'); return; }
  const r = await dialog({ title: 'Add a passkey', ok: 'Continue',
    sub: 'Your device will ask for your fingerprint, face or PIN, or your passkey manager (such as Bitwarden) will offer to save it. To let it unlock your files too, confirm your password first.',
    body: `<div class="field"><label for="pk-label">Name for this passkey</label><input name="label" id="pk-label" maxlength="60" required value="${esc(deviceLabel().split(' on ')[1] || 'My passkey')}"></div>
      <input type="email" autocomplete="username" value="${esc(S.user.email)}" hidden>
      <div class="field"><label for="pk-pass">Your password</label><input name="password" id="pk-pass" type="password" autocomplete="current-password" required></div>` });
  if (!r) return;
  let key;
  try { key = await C.unwrapPrivateKey((await getDoc(doc(db, `privateKeys/${S.user.uid}`))).data(), r.password, true); }
  catch { toast('That password isn’t right.'); return; }
  const { id, options } = await api.passkeyRegisterOptions({});
  let cred;
  try { cred = await navigator.credentials.create({ publicKey: { ...pkCreate(options), extensions: { credProps: true, ...PRF_EXT } } }); }
  catch (err) { toast(err.name === 'InvalidStateError' ? 'This device already has a passkey for your account.' : err.name === 'NotAllowedError' ? 'Cancelled.' : errText(err)); return; }
  let prf = prfOf(cred);
  if (!prf && cred.getClientExtensionResults?.().prf?.enabled) {
    // Some passkeys only produce the unlock secret when used, not when made: one more touch.
    toast('One more time, so this passkey can unlock your files.');
    try {
      const a = await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: options.rp.id,
        allowCredentials: [{ type: 'public-key', id: cred.rawId }], userVerification: 'required', extensions: PRF_EXT } });
      prf = prfOf(a);
    } catch { /* still works for sign-in; files then ask for the password */ }
  }
  const privateKey = prf ? await C.wrapPrivateKeyWithPrf(key, prf, cred.id) : null;
  const res = await api.passkeyRegister({ id, response: credJSON(cred), label: r.label, privateKey });
  toast(res.unlocks ? 'Passkey added. It signs you in and unlocks your files.' : 'Passkey added. After signing in with it, you’ll type your password once to unlock files.');
  await render(true);
}

async function viewAccount() {
  const { passkeys } = await api.passkeyList({});
  return `<div class="head"><div><div class="eyebrow">Your account</div><h1>Passkeys &amp; account</h1>
    <p>A passkey signs you in with your fingerprint, face or device PIN instead of your password and code. It can live in Windows Hello, your iPhone or Mac,
    your Android phone, or a password manager such as Bitwarden. Your password and authenticator code keep working as a backup.</p></div>
    <div class="actions"><button class="btn primary" data-act="pkadd"><svg class="icon"><use href="#i-plus"/></svg>Add a passkey</button></div></div>
    <div class="panel"><div class="panel-h"><h2>Your passkeys</h2></div>${passkeys.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Added</th><th>Last used</th><th>Files</th><th><span class="sr">Actions</span></th></tr></thead><tbody>
      ${passkeys.map((k) => `<tr><td class="fname">${esc(k.label)}</td><td>${fmtDate(k.createdAt)}</td><td>${k.lastUsed ? fmtWhen(k.lastUsed) : '<span class="fine">Not yet</span>'}</td>
        <td>${k.unlocks ? '<span class="chip ok">Unlocks files</span>' : '<span class="chip">Asks for password</span>'}</td>
        <td class="num"><button class="btn small danger" data-act="pkremove" data-id="${esc(k.id)}" aria-label="Remove ${esc(k.label)}">Remove</button></td></tr>`).join('')}
      </tbody></table></div>` : '<div class="empty">No passkeys yet.</div>'}</div>
    <div class="panel panel-b secure-note"><svg class="icon" style="color:var(--ok);width:20px;height:20px"><use href="#i-lock"/></svg>
      <div><b>Signed in as ${esc(S.user.email)}.</b> If you lose a device that holds a passkey, remove it here, or ask the Commission to remove it.</div></div>`;
}

/** Make or unlock this person's key pair with the password they just typed. */
async function unlockKeys(user, needsKey) {
  if (!pendingPassword) {
    const k = needsKey ? null : await cachedKey(user.uid);
    if (k) { S.privateKey = k; return; }
    if (pendingPrf && !needsKey) {
      const p = pendingPrf; pendingPrf = null;
      try { S.privateKey = await C.unwrapPrivateKeyWithPrf(p.record, p.prf, p.credentialId); await cacheKey(user.uid, S.privateKey); return; }
      catch { /* fall back to the password */ }
    }
    if (needsKey) throw new Error('Sign in with your password the first time.');
    throw Object.assign(new Error('Enter your password to unlock your files.'), { code: 'need-password' });
  }
  $('#busy-text').textContent = 'Unlocking your files…';
  const privRef = doc(db, `privateKeys/${user.uid}`);
  if (!needsKey) {
    const snap = await getDoc(privRef);
    if (snap.exists()) {
      try { S.privateKey = await C.unwrapPrivateKey(snap.data(), pendingPassword); await cacheKey(user.uid, S.privateKey); return; }
      catch { /* password was reset: fall through and make a new key */ }
    }
  }
  $('#busy-text').textContent = 'Setting up encryption for your account…';
  const kp = await C.generateKeyPair();
  const wrapped = await C.wrapPrivateKey(kp.privateKey, pendingPassword);
  await setDoc(privRef, { ...wrapped, updatedAt: serverTimestamp() });
  if (needsKey) await setDoc(doc(db, `publicKeys/${user.uid}`), { jwk: kp.publicJwk, createdAt: serverTimestamp() });
  else { await api.replaceKey({ jwk: kp.publicJwk }); toast('Your password changed, so older files must be re-shared with you by the Commission.'); }
  S.privateKey = await C.unwrapPrivateKey(wrapped, pendingPassword);
  await cacheKey(user.uid, S.privateKey);
}

// ---------------------------------------------------------------- data
async function loadFolders() {
  const r = await api.listFolders({});
  S.folders = r.folders;
  if (S.admin) {
    const snap = await getDocs(collection(db, 'users'));
    S.people = snap.docs.map((d) => ({ uid: d.id, ...d.data() })).filter((p) => !p.removed);
  }
}
const folderById = (id) => S.folders.find((f) => f.id === id);

async function loadFiles(f) {
  const base = collection(db, `folders/${f.id}/files`);
  const queries = f.perm === 'admin' ? [base]
    : f.perm === 'upload' ? [query(base, where('uploadedBy', '==', S.user.uid))]
    : [query(base, where('everyone', '==', true)), query(base, where('visibleTo', 'array-contains', S.user.uid))];
  const seen = new Map();
  for (const q of queries) (await getDocs(q)).docs.forEach((d) => seen.set(d.id, d));
  const files = [];
  for (const d of seen.values()) {
    const x = { id: d.id, ...d.data() };
    x.expires = tsMs(x.expiresAt);
    x.locked = !x.keys?.[S.user.uid];
    if (!x.locked) {
      try { x.fileKey = await C.unwrapFileKey(x.keys[S.user.uid], S.user.uid, S.privateKey, S.admin); x.plainName = await C.decryptText(x.fileKey, x.name, 'file name v1'); }
      catch { x.locked = true; }
    }
    files.push(x);
  }
  files.sort((a, b) => b.uploadedAt - a.uploadedAt);
  S.files[f.id] = files;
  if (S.admin) shareMissingKeys(f, files).catch(() => {});
  return files;
}

/** Admin's browser: give people who joined (or reset their key) the keys to files they're allowed to open. */
async function shareMissingKeys(f, files) {
  const now = Date.now();
  const readers = (f.members || []).filter((m) => m.until > now && m.perm !== 'upload').map((m) => m.uid);
  const pub = {};
  let shared = 0;
  for (const file of files) {
    if (!file.fileKey) continue;
    const allowed = file.everyone ? readers : readers.filter((u) => file.visibleTo?.includes(u));
    const add = {};
    for (const uid of allowed) {
      if (file.keys[uid]) continue;
      if (!(uid in pub)) { const k = await getDoc(doc(db, `publicKeys/${uid}`)); pub[uid] = k.exists() ? k.data().jwk : null; }
      if (pub[uid]) add[uid] = await C.wrapFileKey(file.fileKey, uid, pub[uid]);
    }
    if (Object.keys(add).length) { await api.addFileKeys({ folder: f.id, file: file.id, keys: add }); Object.assign(file.keys, add); shared++; }
  }
  if (shared) toast(`Unlocked ${shared} file${shared === 1 ? '' : 's'} for people recently added.`);
}

// ---------------------------------------------------------------- rail + router
function renderRail() {
  const visible = S.folders.filter((f) => f.kind !== 'thread');
  $('#rail-folders').innerHTML = '<div class="rail-label">Shared folders</div>' + (visible.length ? visible.map((f) =>
    `<a class="rail-link" href="#folder-${f.id}"${S.route === 'folder' && S.arg === f.id ? ' aria-current="page"' : ''}>
      <svg class="icon"><use href="#i-${f.kind === 'folder' ? 'folder' : 'inbox'}"/></svg><span class="t">${esc(f.name)}</span><span class="n">${S.files[f.id]?.length ?? ''}</span></a>`).join('')
    : '<p class="fine" style="color:var(--rail-muted);padding:0 10px">No folders yet.</p>');
  document.querySelectorAll('.rail-section.nav .rail-link').forEach((a) => {
    if (a.getAttribute('href') === '#' + S.route) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  });
}
async function route() {
  const h = location.hash.replace(/^#/, '');
  if (isPublicLink()) return showPublicLink();
  const m = /^folder-([\w-]+)$/.exec(h);
  if (m) { S.route = 'folder'; S.arg = m[1]; }
  else if (S.admin && ['sends', 'requests', 'people', 'activity', 'rules'].includes(h)) { S.route = h; S.arg = null; }
  else if (h === 'account') { S.route = h; S.arg = null; }
  else { S.route = 'overview'; S.arg = null; }
  await render();
}
addEventListener('hashchange', () => { if (isPublicLink()) showPublicLink(); else if (S.user) route(); else showSignIn(); });

async function render(keepFocus) {
  const v = $('#view');
  try {
    const html = await ({ sends: viewSends, overview: viewOverview, folder: () => viewFolder(S.arg), requests: viewRequests, people: viewPeople, activity: viewActivity, rules: viewRules, account: viewAccount }[S.route])();
    v.innerHTML = html;
  } catch (err) {
    v.innerHTML = `<div class="panel panel-b">Couldn’t load this page: ${esc(errText(err))}</div>`;
  }
  renderRail();
  if (!keepFocus) v.focus({ preventScroll: true });
  wireDrop();
}

// ---------------------------------------------------------------- views
const secureNote = () => `<div class="panel panel-b secure-note"><svg class="icon" style="color:var(--ok);width:20px;height:20px"><use href="#i-lock"/></svg>
  <div><b>How files are protected.</b> Files and their names are encrypted in your browser before they leave your computer, and stay encrypted in storage.
  Everyone signs in with a password and a code from an authenticator app, or with a passkey. Every upload, download and change is recorded.</div></div>`;

async function viewOverview() {
  const list = S.folders.filter((f) => f.kind !== 'thread');
  const hour = new Date().getHours();
  const hello = hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening';
  return `<div class="head"><div><div class="eyebrow">Shared folders</div><h1>${hello}, ${esc(S.name.split(' ')[0])}</h1>
    <p>${list.length ? `${list.length} folder${list.length === 1 ? '' : 's'} shared with you.` : S.admin ? 'Create a shared folder to send files, or request files from someone.' : 'Nothing has been shared with you yet.'}</p></div>
    ${S.admin ? `<div class="actions"><button class="btn" data-act="request"><svg class="icon"><use href="#i-inbox"/></svg>Request files</button>
    <button class="btn primary" data-act="newfolder"><svg class="icon"><use href="#i-plus"/></svg>New shared folder</button></div>` : ''}</div>
    <div class="cards">${list.map((f) => `<a class="fcard" href="#folder-${f.id}"><div style="display:flex;gap:10px;align-items:center">
      <svg class="icon" style="color:var(--navy);width:20px;height:20px"><use href="#i-${f.kind === 'folder' ? 'folder' : 'inbox'}"/></svg><h2>${esc(f.name)}</h2></div>
      <div class="row"><span>${f.kind === 'request' ? 'File request' : f.kind === 'dropoff' ? 'Drop-off' : PERM_TEXT[f.perm]}</span><span>${S.admin ? (f.members?.length || 0) + ' people' : ''}</span></div>
      <div class="facts"><span class="chip"><svg class="icon"><use href="#i-clock"/></svg>Deletes after ${f.days} days</span></div></a>`).join('')}</div>${secureNote()}`;
}

async function viewFolder(id) {
  const f = folderById(id);
  if (!f) return '<div class="empty">That folder was deleted, or your access ended. <a href="#overview">Back to all folders</a></div>';
  const files = await loadFiles(f);
  const canUp = S.admin || f.perm === 'upload' || f.perm === 'both';
  const size = files.reduce((a, x) => a + x.size, 0);
  const rows = files.map((x) => {
    const e = x.locked ? 'file' : extOf(x.plainName), l = left(x.expires);
    const who = x.uploadedBy === S.user.uid ? 'You' : x.uploaderEmail || 'Drop-off';
    const extra = [x.maxDownloads ? `${x.downloads || 0} of ${x.maxDownloads} downloads` : '', x.deleteAfterDownload ? 'deletes after download' : '',
      S.admin && !x.everyone && x.uploadedBy === S.user.uid ? `visible to ${Math.max(0, (x.visibleTo?.length || 1) - 1)} people` : ''].filter(Boolean).join(' · ');
    return `<tr><td><div class="file"><span class="ext ${esc(e)}">${esc((e || 'file').slice(0, 4).toUpperCase())}</span><div>
      <div class="fname">${x.locked ? '<i>Waiting for the Commission to unlock this file for you</i>' : esc(x.plainName)}</div>
      <div class="fmeta">${esc(who)} · ${fmtWhen(x.uploadedAt)}${extra ? ' · ' + esc(extra) : ''}</div>
      <div class="fmeta mono" title="SHA-256 fingerprint of the original file">${x.sha256.slice(0, 16)}…</div></div></div></td>
      <td class="num mono">${fmtSize(x.plainSize || x.size)}</td>
      <td><span class="chip ${l.cls}" title="Deleted ${fmtDate(x.expires)}"><svg class="icon"><use href="#i-clock"/></svg>${l.txt}</span></td>
      <td class="num"><div class="actions" style="justify-content:flex-end;flex-wrap:nowrap">
      ${x.locked && S.admin ? `<button class="btn small" data-act="recover" data-id="${x.id}">Open with recovery key</button>`
        : `<button class="btn small" data-act="download" data-id="${x.id}"${x.locked ? ' disabled' : ''}><svg class="icon"><use href="#i-down"/></svg>Download</button>`}
      ${S.admin || x.uploadedBy === S.user.uid ? `<button class="btn small danger" data-act="delete" data-id="${x.id}" aria-label="Delete"><svg class="icon"><use href="#i-trash"/></svg></button>` : ''}</div></td></tr>`;
  }).join('');
  const people = S.admin ? (f.members || []).map((m) => `<div class="person"><span class="avatar">${initials(m.name || m.email)}</span><div style="min-width:0">
      <div class="nm">${esc(m.name || m.email)}</div><div class="em">${esc(m.email)}</div><div class="em">Access ends ${fmtDate(m.until)}</div></div>
      <div style="display:grid;gap:4px;justify-items:end"><span class="perm${m.perm === 'upload' ? ' up' : ''}">${PERM_TEXT[m.perm]}</span>
      <button class="linkish" style="color:var(--bad)" data-act="removemember" data-uid="${m.uid}">Remove</button></div></div>`).join('') : '';
  const messages = await loadMessages(f);
  const note = await folderNote(f);
  return `<div class="head"><div><div class="eyebrow"><a href="#overview" style="color:inherit">Shared folders</a></div><h1>${esc(f.name)}</h1>
    ${f.note ? `<p>${esc(f.note)}</p>` : ''}
    <div class="facts" style="margin-top:10px"><span class="chip"><svg class="icon"><use href="#i-clock"/></svg>Each file deleted ${f.days} days after upload</span>
    <span class="chip ok"><svg class="icon"><use href="#i-lock"/></svg>Encrypted</span><span class="chip mono">${files.length} files · ${fmtSize(size)}</span>
    ${!S.admin ? `<span class="chip">${PERM_TEXT[f.perm]} until ${fmtDate(f.until)}</span>` : ''}</div></div>
    <div class="actions">${S.admin ? `<button class="btn" data-act="invite"><svg class="icon"><use href="#i-people"/></svg>Add someone</button>
      <button class="btn danger" data-act="deletefolder">Delete folder</button>` : ''}
    ${canUp ? `<button class="btn primary" data-act="pick"><svg class="icon"><use href="#i-up"/></svg>Upload files</button>` : ''}</div></div>
    <div class="grid-2"><div style="display:grid;gap:20px;min-width:0"><div class="panel">
      ${canUp ? `<div class="panel-b" style="border-bottom:1px solid var(--border)"><label class="drop" id="drop" for="file-input">
        <svg class="icon" style="width:26px;height:26px;color:var(--navy)"><use href="#i-up"/></svg><strong>Drop files here or choose files</strong>
        <small>Up to 250 MB each. Encrypted before upload. Deleted automatically after ${f.days} days.</small></label>
        <input id="file-input" type="file" multiple hidden><p class="fine" id="up-status" role="status"></p></div>` : ''}
      ${rows ? `<div class="table-wrap"><table><thead><tr><th>File</th><th class="num">Size</th><th>Deleted in</th><th class="num"><span class="sr">Actions</span></th></tr></thead><tbody>${rows}</tbody></table></div>`
        : `<div class="empty">${f.perm === 'upload' ? 'You haven’t sent anything yet. Your files appear here, and only you and the Commission can see them.' : 'No files yet.'}</div>`}
    </div>
    <div class="panel"><div class="panel-h"><h2>Messages</h2><span class="fine">Encrypted · deleted with the folder’s files</span></div>
      <div class="panel-b" style="display:grid;gap:12px">${messages || '<p class="fine">No messages yet.</p>'}
      <form id="msg-form" class="linkbox" novalidate><label for="msg-text" class="sr">Message</label><input id="msg-text" maxlength="4000" placeholder="Write a message" style="min-height:40px;padding:8px 10px;border:1.5px solid var(--border);border-radius:var(--r-sm);background:var(--surface)">
      <button class="btn primary" type="submit">Send</button></form></div></div></div>
    <div style="display:grid;gap:20px">
      ${S.admin ? `<div class="panel"><div class="panel-h"><h2>People with access</h2><button class="btn small" data-act="invite"><svg class="icon"><use href="#i-plus"/></svg>Add</button></div>
        <div class="panel-b people">${people || '<p class="fine">Only administrators can see this folder.</p>'}</div></div>` : ''}
      <div class="panel"><div class="panel-h"><h2>Folder note</h2>${S.admin ? '<button class="btn small" data-act="editnote">Edit</button>' : ''}</div>
        <div class="panel-b"><p class="fine" style="white-space:pre-wrap;color:var(--fg)">${note ? esc(note) : 'No note.'}</p></div></div>
      <div class="panel panel-b secure-note"><svg class="icon" style="color:var(--ok);width:20px;height:20px"><use href="#i-lock"/></svg>
        <div>People with <b>Upload only</b> see just the files they sent, never anyone else’s.</div></div>
    </div></div>`;
}

async function loadMessages(f) {
  const snap = await getDocs(query(collection(db, `folders/${f.id}/messages`), orderBy('at', 'asc'), limit(200)));
  const out = [];
  for (const d of snap.docs) {
    const m = d.data();
    let text = '<i>You can’t read this message yet.</i>';
    if (m.keys?.[S.user.uid]) {
      try { const k = await C.unwrapFileKey(m.keys[S.user.uid], S.user.uid, S.privateKey); text = esc(await C.decryptText(k, m.box, 'message v1')); } catch {}
    }
    out.push(`<div style="display:grid;gap:2px"><div class="fmeta"><b style="color:var(--fg)">${esc(m.from === S.user.uid ? 'You' : m.fromEmail)}</b> · ${fmtWhen(m.at)}</div><div style="white-space:pre-wrap">${text}</div></div>`);
  }
  return out.join('');
}
async function folderNote(f) {
  if (!f.notes?.keys?.[S.user.uid]) return '';
  try { const k = await C.unwrapFileKey(f.notes.keys[S.user.uid], S.user.uid, S.privateKey); return await C.decryptText(k, f.notes.box, 'note v1'); } catch { return ''; }
}
/** Seal a short text for everyone who can read this folder. */
async function sealText(f, text, context) {
  const { recipients } = await api.recipients({ folder: f.id, purpose: 'message' });
  const key = await C.newFileKey();
  const box = await C.encryptText(key, text, context);
  const keys = {};
  for (const r of recipients) keys[r.id] = await C.wrapFileKey(key, r.id, r.publicJwk);
  return { box, keys };
}

async function viewSends() {
  const snap = await getDocs(query(collection(db, 'sends'), orderBy('createdAt', 'desc'), limit(100)));
  const rows = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  const out = [];
  for (const x of rows) {
    let nm = x.label || 'File';
    if (x.keys?.[S.user.uid]) { try { const k = await C.unwrapFileKey(x.keys[S.user.uid], S.user.uid, S.privateKey); nm = await C.decryptText(k, x.name, 'file name v1'); } catch {} }
    const l = left(tsMs(x.expiresAt));
    const used = x.downloads >= x.maxDownloads;
    out.push(`<tr><td><div class="fname">${esc(nm)}</div>${x.label && x.label !== nm ? `<div class="fmeta">${esc(x.label)}</div>` : ''}<div class="fmeta">${fmtWhen(x.createdAt)}${x.hasPassword ? ' · password' : ''}</div></td>
      <td class="mono">${x.downloads} of ${x.maxDownloads}</td>
      <td>${used ? '<span class="chip ok">Downloaded</span>' : `<span class="chip ${l.cls}"><svg class="icon"><use href="#i-clock"/></svg>${l.txt}</span>`}</td>
      <td class="num"><button class="btn small danger" data-act="deletesend" data-id="${x.id}">Delete now</button></td></tr>`);
  }
  return `<div class="head"><div><div class="eyebrow">Send without an account</div><h1>Quick send</h1>
    <p>Send one file with a link and an optional password. The recipient doesn’t need an account. The file is deleted after its downloads are used or it expires, whichever comes first.</p></div>
    <div class="actions"><button class="btn primary" data-act="newsend"><svg class="icon"><use href="#i-plus"/></svg>New quick send</button></div></div>
    <div class="panel"><div class="table-wrap"><table><thead><tr><th>File</th><th>Downloads</th><th>Status</th><th><span class="sr">Actions</span></th></tr></thead><tbody>
    ${out.join('') || '<tr><td colspan="4" class="empty">Nothing sent yet.</td></tr>'}</tbody></table></div></div>`;
}

function randomPassword() {
  const words = ['river', 'maple', 'lantern', 'harbor', 'copper', 'meadow', 'granite', 'willow', 'summit', 'cedar', 'falcon', 'orchard', 'beacon', 'canyon', 'prairie', 'timber', 'quarry', 'saddle', 'thistle', 'voyage'];
  const r = crypto.getRandomValues(new Uint32Array(4));
  return [words[r[0] % 20], words[r[1] % 20], words[r[2] % 20], String(r[3] % 900 + 100)].join('-');
}

async function newQuickSend(s) {
  const pw = randomPassword();
  const r = await dialog({ title: 'New quick send', ok: 'Encrypt and create link',
    sub: 'The recipient gets a link. Give them the password another way, for example by phone or text.',
    body: `<div class="field"><label for="qs-file">File</label><input type="file" id="qs-file" name="file" required></div>
      <div class="field"><label for="label">What is it? (shown to them)</label><input name="label" id="label" maxlength="100" placeholder="For example: Your voter registration record"></div>
      <div class="field"><label for="qs-pw">Password</label><div class="linkbox"><input id="qs-pw" name="pw" value="${pw}" class="mono" autocomplete="off"></div>
        <span class="hint">Clear it to send with the link alone (less safe: anyone with the link can download).</span></div>
      <div class="field"><label for="maxDownloads">Downloads allowed</label><select name="maxDownloads" id="maxDownloads"><option value="1" selected>1</option><option value="2">2</option><option value="5">5</option><option value="10">10</option></select></div>
      <div class="field"><label for="days">Delete after</label>${daySelect('days', Math.min(7, s.maxDays), s.maxDays)}</div>` });
  if (!r) return;
  const file = document.getElementById('qs-file').files[0];
  if (!file) return toast('Choose a file.');
  if (file.size > MAX || !ALLOWED.includes(extOf(file.name))) return toast('Files must be under 250 MB and a document, spreadsheet, image, text or zip file.');
  toast('Encrypting…');
  const rec = await getDoc(doc(db, 'settings/recovery'));
  if (!rec.exists()) return toast('Create the recovery key in Settings first.');
  const mine = await getDoc(doc(db, `publicKeys/${S.user.uid}`));
  const sealed = await C.sealSend(new Uint8Array(await file.arrayBuffer()), file.name, r.pw.trim(),
    [{ id: S.user.uid, publicJwk: mine.data().jwk }, { id: 'recovery', publicJwk: rec.data().jwk }]);
  const fileId = C.b64url(crypto.getRandomValues(new Uint8Array(15)));
  toast('Uploading…');
  const task = uploadBytesResumable(sref(storage, `sends/${S.user.uid}/${fileId}`), sealed.ciphertext, { contentType: 'application/octet-stream' });
  await new Promise((res, rej) => task.on('state_changed', null, rej, res));
  const { id } = await api.createSend({ fileId, name: sealed.name, sha256: sealed.sha256, size: file.size, keys: sealed.keys, ext: extOf(file.name),
    accessHash: sealed.accessHash, salt: sealed.salt, iterations: sealed.iterations, hasPassword: !!r.pw.trim(), label: r.label,
    maxDownloads: Number(r.maxDownloads), days: Number(r.days) });
  const link = `${PORTAL_URL}${MODE === 'staging' ? '?staging' : ''}#send-${id}.${sealed.secret}`;
  await dialog({ title: 'Link ready', ok: 'Done', cancel: '', sub: 'This is the only time the link is shown. The server doesn’t keep a copy, so copy it now.',
    body: `<div class="field"><label for="ql">Link</label><div class="linkbox"><input id="ql" readonly value="${esc(link)}"><button class="btn small" type="button" data-copy="ql">Copy</button></div></div>
      ${r.pw.trim() ? `<div class="field"><label for="qp">Password (send separately)</label><div class="linkbox"><input id="qp" readonly class="mono" value="${esc(r.pw.trim())}"><button class="btn small" type="button" data-copy="qp">Copy</button></div></div>` : ''}` });
  if (S.route === 'sends') await render(true); else location.hash = 'sends';
}

async function viewRequests() {
  const list = S.folders.filter((f) => f.kind === 'request' || f.kind === 'dropoff');
  return `<div class="head"><div><div class="eyebrow">Receive files</div><h1>File requests</h1>
    <p>Ask someone to send you files. A request goes to a named person who signs in. A drop-off works with a link and a code, without an account.</p></div>
    <div class="actions"><button class="btn" data-act="dropoff"><svg class="icon"><use href="#i-lock"/></svg>New drop-off link</button>
    <button class="btn primary" data-act="request"><svg class="icon"><use href="#i-plus"/></svg>Request files</button></div></div>
    <div class="panel"><div class="table-wrap"><table><thead><tr><th>Request</th><th>From</th><th>Created</th><th>Files deleted after</th></tr></thead><tbody>
    ${list.map((f) => `<tr><td><a href="#folder-${f.id}">${esc(f.name)}</a>${f.note ? `<div class="fmeta">${esc(f.note)}</div>` : ''}</td>
      <td>${f.kind === 'dropoff' ? 'Anyone with the link and code' : esc((f.members || []).map((m) => m.email).join(', '))}</td>
      <td>${fmtWhen(f.createdAt)}</td><td>${f.days} days</td></tr>`).join('') || '<tr><td colspan="4" class="empty">No requests yet.</td></tr>'}
    </tbody></table></div></div>`;
}

async function viewPeople() {
  await loadFolders();
  return `<div class="head"><div><div class="eyebrow">Accounts</div><h1>People</h1><p>Everyone with an account. Only administrators can invite people; nobody can sign up on their own.</p></div>
    <div class="actions"><button class="btn primary" data-act="inviteperson"><svg class="icon"><use href="#i-plus"/></svg>Invite someone</button></div></div>
    <div class="panel"><div class="table-wrap"><table><thead><tr><th>Name</th><th>Organization</th><th>Folders</th><th>Last sign-in</th><th><span class="sr">Actions</span></th></tr></thead><tbody>
    ${S.people.map((p) => {
      const fs = S.folders.filter((f) => (f.members || []).some((m) => m.uid === p.uid));
      return `<tr><td><div class="person" style="border:0;padding:0;grid-template-columns:30px minmax(0,1fr)"><span class="avatar">${initials(p.name || p.email)}</span>
        <div style="min-width:0"><div class="nm">${esc(p.name || p.email)}${p.admin ? ' <span class="perm">Admin</span>' : ''}</div><div class="em">${esc(p.email)}</div></div></div></td>
        <td>${esc(p.org || '')}</td><td>${fs.map((f) => esc(f.name)).join('<br>') || '<span class="fine">None</span>'}</td>
        <td>${p.lastSignIn ? fmtWhen(p.lastSignIn) : '<span class="fine">Never</span>'}${p.noSelfReset ? '<div class="fmeta">Email reset turned off</div>' : ''}</td>
        <td class="num"><div class="actions" style="justify-content:flex-end">
        ${!p.admin ? `<button class="btn small" data-act="message" data-uid="${p.uid}">Message</button>` : ''}
        ${p.noSelfReset ? `<button class="btn small" data-act="approvereset" data-uid="${p.uid}">Approve reset</button>` : ''}
        <button class="btn small" data-act="pkremoveall" data-uid="${p.uid}">Remove passkeys</button>
        ${!p.admin ? `<button class="btn small danger" data-act="removeuser" data-uid="${p.uid}">Remove</button>` : ''}</div></td></tr>`;
    }).join('')}</tbody></table></div></div>`;
}

async function viewActivity() {
  const snap = await getDocs(query(collection(db, 'audit'), orderBy('seq', 'desc'), limit(300)));
  const rows = snap.docs.map((d) => d.data());
  return `<div class="head"><div><div class="eyebrow">Audit trail</div><h1>Activity log</h1>
    <p>Every sign-in, upload, download, permission change and automatic deletion. Each entry is chained to the one before, so a changed or removed entry is detected.</p></div>
    <div class="actions"><button class="btn" data-act="verifylog">Check the log</button><button class="btn" data-act="export"><svg class="icon"><use href="#i-down"/></svg>Export CSV</button></div></div>
    <div class="panel log">${rows.map(({ entry: e, seq }) => `<div class="log-row"><time>${fmtWhen(e.at)}</time><div class="what">
      <b${/bad|blocked|failed/.test(e.action) ? ' style="color:var(--bad)"' : ''}>${esc(e.actorEmail || e.actor)}</b> ${esc(describe(e))}
      <div class="ip mono">#${seq}${e.ip ? ' · ' + esc(e.ip) : ''}</div></div></div>`).join('') || '<div class="empty">Nothing yet.</div>'}</div>`;
}
function describe(e) {
  const folder = S.folders.find((f) => f.id === e.folder)?.name || '';
  const where = folder ? ` in “${folder}”` : '';
  const t = {
    signin: 'signed in', 'signin.blocked': 'was blocked from signing in', 'user.invite': `invited ${e.target}`, 'member.add': `gave ${e.target} access${where}`,
    'member.remove': `removed ${e.target}${where}`, 'member.change': `changed ${e.target}’s access${where}`, 'user.remove': `removed ${e.target}`,
    'folder.create': 'created a folder', 'request.create': 'requested files', 'folder.delete': 'deleted a folder', 'folder.change': `changed${where}`,
    'file.upload': `uploaded a file${where}`, 'file.download': `downloaded a file${where}`, 'file.delete': `deleted a file${where}`, 'file.share': `unlocked a file for ${e.note}${where}`,
    'message.post': `sent a message${where}`, 'dropoff.create': 'made a drop-off link', 'dropoff.upload': `sent a file by drop-off${where}`, 'dropoff.bad-code': 'entered a wrong drop-off code',
    cleanup: 'automatic deletion', 'settings.change': 'changed settings', 'recovery.set': 'set up the recovery key', 'log.export': 'exported the log',
    'key.replace': 'set up a new encryption key', 'user.reset-approved': `approved a password reset for ${e.target}`, 'thread.open': `started private messages with ${e.target}`,
    'passkey.add': 'added a passkey', 'passkey.remove': `removed passkeys for ${e.target}`, 'passkey.signin': 'signed in with a passkey', 'passkey.failed': 'failed a passkey sign-in',
  }[e.action] || e.action;
  return t + (e.note && !['file.share'].includes(e.action) ? ` (${e.note})` : '');
}

async function viewRules() {
  const s = (await getDoc(doc(db, 'settings/main'))).data() || { defaultDays: 7, maxDays: 90, removeUnusedDays: 90 };
  const rec = await getDoc(doc(db, 'settings/recovery'));
  const mail = await api.mailStatus({}).catch(() => ({ configured: false }));
  return `<div class="head"><div><div class="eyebrow">Settings</div><h1>Settings</h1><p>Files are removed for good when they reach their age. This keeps storage close to free and limits what could ever be exposed.</p></div></div>
    <div class="panel panel-b"><form class="form" id="rules-form" style="max-width:480px" novalidate>
      <div class="field"><label for="defaultDays">New folders delete files after</label>${daySelect('defaultDays', s.defaultDays)}<span class="hint">You can pick a different time for each folder.</span></div>
      <div class="field"><label for="maxDays">Longest anyone can keep a file</label>${daySelect('maxDays', s.maxDays)}<span class="hint">A storage rule also removes anything older than 180 days, as a backstop.</span></div>
      <div class="field"><label for="removeUnusedDays">Remove people who haven’t signed in for</label><select id="removeUnusedDays">
        ${[30, 60, 90, 180, 0].map((d) => `<option value="${d}"${d === s.removeUnusedDays ? ' selected' : ''}>${d ? d + ' days' : 'Never'}</option>`).join('')}</select></div>
      <div><button class="btn primary" type="submit">Save settings</button></div></form></div>
    <div class="panel panel-b secure-note"><svg class="icon" style="color:${rec.exists() ? 'var(--ok)' : 'var(--bad)'};width:20px;height:20px"><use href="#i-lock"/></svg>
      <div><b>Recovery key.</b> ${rec.exists() ? `Set up on ${fmtDate(rec.data().setAt)}. Fingerprint <span class="mono">${esc(await C.publicKeyFingerprint(rec.data().jwk))}</span>. Keep the printed copy and USB drive in the safe.`
        : 'Not set up yet. Nobody can upload until it is. <button class="btn small primary" data-act="makerecovery">Create the recovery key</button>'}</div></div>
    <div class="panel panel-b secure-note"><svg class="icon" style="color:${mail.configured ? 'var(--ok)' : 'var(--warn)'};width:20px;height:20px"><use href="#i-inbox"/></svg>
      <div><b>Email alerts.</b> ${mail.configured ? 'On: download receipts, new uploads and new-device sign-ins are emailed.' : 'Off until the mail account is connected.'}</div></div>
    <div class="panel panel-b secure-note"><svg class="icon" style="color:var(--gold);width:20px;height:20px"><use href="#i-clock"/></svg>
      <div><b>Records note.</b> Files here are temporary transfer copies. Keep the original of any official record wherever the commission normally keeps it.</div></div>`;
}

// ---------------------------------------------------------------- uploads
function wireDrop() {
  const d = $('#drop'), inp = $('#file-input');
  if (!d) return;
  inp.addEventListener('change', () => { const fl = [...inp.files]; inp.value = ''; uploadFiles(fl); });
  ['dragenter', 'dragover'].forEach((ev) => d.addEventListener(ev, (e) => { e.preventDefault(); d.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => d.addEventListener(ev, (e) => { e.preventDefault(); d.classList.remove('over'); }));
  d.addEventListener('drop', (e) => uploadFiles([...e.dataTransfer.files]));
  const mf = $('#msg-form');
  mf?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = $('#msg-text').value.trim();
    if (!text) return;
    const f = folderById(S.arg);
    try { const sealed = await sealText(f, text, 'message v1'); await api.postMessage({ folder: f.id, ...sealed }); await render(true); }
    catch (err) { toast('Message not sent: ' + errText(err)); }
  });
}
const MAX = 250 * 1024 * 1024;
const ALLOWED = ['txt', 'csv', 'tsv', 'json', 'xml', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'odt', 'ods', 'png', 'jpg', 'jpeg', 'gif', 'tif', 'tiff', 'heic', 'zip', 'geojson', 'kml', 'kmz', 'shp', 'dbf', 'prj', 'md'];
async function uploadFiles(list) {
  const f = folderById(S.arg);
  if (!f || !list.length) return;
  const bad = list.filter((x) => x.size > MAX || !ALLOWED.includes(extOf(x.name)));
  if (bad.length) { toast(`${bad.map((x) => x.name).join(', ')} can’t be sent: files must be under 250 MB and a document, spreadsheet, image, text or zip file.`); list = list.filter((x) => !bad.includes(x)); if (!list.length) return; }
  let opts = {};
  if (S.admin && (f.members || []).some((m) => m.perm !== 'upload')) {
    const readers = (f.members || []).filter((m) => m.perm !== 'upload');
    const r = await dialog({
      title: list.length === 1 ? `Send ${list[0].name}` : `Send ${list.length} files`, ok: 'Encrypt and upload',
      body: `<fieldset class="field" style="border:0;padding:0;margin:0"><legend style="font-weight:700;font-size:14px;margin-bottom:5px">Who can see ${list.length === 1 ? 'it' : 'them'}?</legend>
        <div class="radios">${readers.map((m) => `<label class="radio"><input type="checkbox" name="visibleTo" value="${m.uid}" checked><span><b>${esc(m.name || m.email)}</b><small>${esc(m.email)}</small></span></label>`).join('')}</div></fieldset>
        <div class="field"><label for="maxDownloads">Download limit</label><select name="maxDownloads" id="maxDownloads"><option value="0">No limit</option><option value="1">1 download per file</option><option value="3">3 downloads</option><option value="10">10 downloads</option></select></div>
        <label class="radio"><input type="checkbox" name="once" value="1"><span><b>Delete after it’s downloaded</b><small>Removed 10 minutes after the first download by someone other than you.</small></span></label>`,
    });
    if (!r) return;
    const all = r.visibleTo.length === readers.length;
    opts = { visibleTo: all ? [] : r.visibleTo, maxDownloads: Number(r.maxDownloads) || 0, deleteAfterDownload: r.once.length > 0 };
    if (!r.visibleTo.length) { toast('Pick at least one person, or nobody but administrators could open it.'); }
  }
  const status = $('#up-status');
  try {
    let { recipients } = await api.recipients({ folder: f.id });
    if (opts.visibleTo?.length) {
      const adminIds = new Set(S.people.filter((p) => p.admin).map((p) => p.uid));
      recipients = recipients.filter((r) => r.id === 'recovery' || r.id === S.user.uid || adminIds.has(r.id) || opts.visibleTo.includes(r.id));
    }
    for (const [i, file] of list.entries()) {
      const label = `${file.name} (${i + 1} of ${list.length})`;
      status.textContent = `Encrypting ${label}…`;
      const data = new Uint8Array(await file.arrayBuffer());
      const sealed = await C.sealFile(data, file.name, recipients, (p) => { status.textContent = `Encrypting ${label}: ${Math.round(p * 100)}%`; });
      const fileId = C.toB64(crypto.getRandomValues(new Uint8Array(15))).replace(/\+/g, '-').replace(/\//g, '_');
      const task = uploadBytesResumable(sref(storage, `folders/${f.id}/${S.user.uid}/${fileId}`), sealed.ciphertext, { contentType: 'application/octet-stream' });
      await new Promise((res, rej) => task.on('state_changed', (s) => { status.textContent = `Uploading ${label}: ${Math.round(100 * s.bytesTransferred / s.totalBytes)}%`; }, rej, res));
      await api.finalizeUpload({ folder: f.id, fileId, name: sealed.name, sha256: sealed.sha256, size: file.size, keys: sealed.keys, ext: extOf(file.name), options: opts });
    }
    status.textContent = '';
    toast(list.length === 1 ? 'File sent.' : `${list.length} files sent.`);
    await render(true);
  } catch (err) {
    status.textContent = '';
    toast('Upload stopped: ' + errText(err));
  }
}

async function downloadFile(id, recoveryKey = null) {
  const f = folderById(S.arg);
  const file = S.files[f.id]?.find((x) => x.id === id);
  try {
    toast('Downloading…');
    const r = await api.getDownload({ folder: f.id, file: id, useRecovery: !!recoveryKey });
    const res = await fetch(r.url, { referrerPolicy: 'no-referrer' });
    if (!res.ok) throw new Error('The download link expired. Try again.');
    const ct = new Uint8Array(await res.arrayBuffer());
    const sealed = { keys: r.keys, name: r.name, sha256: r.sha256, ciphertext: ct };
    const out = recoveryKey ? await C.openFile(sealed, 'recovery', recoveryKey) : await C.openFile(sealed, S.user.uid, S.privateKey);
    saveBlob(out.data, out.fileName);
    toast(`Saved ${out.fileName}. Fingerprint matches.`);
    if (file?.deleteAfterDownload || file?.maxDownloads) render(true);
  } catch (err) { toast('Download failed: ' + errText(err)); }
}

// ---------------------------------------------------------------- actions
document.addEventListener('click', async (e) => {
  const cp = e.target.closest('[data-copy]');
  if (cp) {
    const el = document.getElementById(cp.dataset.copy);
    try { await navigator.clipboard.writeText(el.value); toast('Copied.'); } catch { el.select(); }
    return;
  }
  const b = e.target.closest('[data-act]');
  if (!b || !S.user) return;
  const act = b.dataset.act;
  const f = folderById(S.arg);
  const s = (await getDoc(doc(db, 'settings/main')).catch(() => null))?.data?.() || { defaultDays: 7, maxDays: 90 };
  try {
    if (act === 'newfolder') {
      const r = await dialog({ title: 'New shared folder', sub: 'Files in this folder are deleted automatically when they reach the age you pick.', ok: 'Create folder',
        body: `<div class="field"><label for="name">Folder name</label><input name="name" id="name" required maxlength="100" placeholder="For example: Precinct boundary review"></div>
          <div class="field"><label for="days">Delete each file after</label>${daySelect('days', s.defaultDays, s.maxDays)}<span class="hint">Counted from when each file is uploaded.</span></div>` });
      if (!r) return;
      const { id } = await api.createFolder({ name: r.name, days: Number(r.days) });
      await loadFolders(); location.hash = 'folder-' + id; toast('Folder created.');
    } else if (act === 'request') {
      const r = await dialog({ title: 'Request files', sub: 'The person signs in and uploads into a folder only administrators can see.', ok: 'Send request',
        body: `<div class="field"><label for="email">Who should send files?</label><input name="email" id="email" type="email" required placeholder="name@agency.gov"></div>
          <div class="field"><label for="pname">Their name</label><input name="pname" id="pname" required></div>
          <div class="field"><label for="note">What do you need?</label><input name="note" id="note" required maxlength="300" placeholder="For example: Signed petition scans for District 4"></div>
          <div class="field"><label for="days">Delete received files after</label>${daySelect('days', s.defaultDays, s.maxDays)}</div>
          <div class="field"><label for="open">Request open for</label><select name="open" id="open"><option value="7">7 days</option><option value="14">14 days</option><option value="30" selected>30 days</option></select></div>` });
      if (!r) return;
      const { id } = await api.createFolder({ name: 'Request: ' + r.note.slice(0, 60), note: r.note, days: Number(r.days), kind: 'request' });
      await inviteTo(id, { email: r.email, name: r.pname, perm: 'upload', days: Number(r.open) });
      await loadFolders(); location.hash = 'requests'; await render(true);
    } else if (act === 'dropoff') {
      const r = await dialog({ title: 'New drop-off link', sub: 'Anyone with the link and the code can send files. Give the code separately, for example by phone.', ok: 'Create link',
        body: `<div class="field"><label for="label">What is it for?</label><input name="label" id="label" required maxlength="100" placeholder="For example: Candidate petition scans"></div>
          <div class="field"><label for="days">Delete received files after</label>${daySelect('days', s.defaultDays, s.maxDays)}</div>
          <div class="field"><label for="openDays">Link works for</label><select name="openDays" id="openDays"><option value="1">1 day</option><option value="7" selected>7 days</option><option value="30">30 days</option></select></div>` });
      if (!r) return;
      const d = await api.createDropoff({ label: r.label, days: Number(r.days), openDays: Number(r.openDays) });
      await loadFolders();
      await dialog({ title: 'Drop-off link ready', ok: 'Done', cancel: '', sub: 'The code is shown only once. Share it separately from the link.',
        body: `<div class="field"><label for="dl">Link</label><div class="linkbox"><input id="dl" readonly value="${esc(d.url)}"></div></div>
          <div class="field"><label for="dc">Code</label><div class="linkbox"><input id="dc" readonly value="${esc(d.code)}" class="mono" style="font-size:20px;letter-spacing:.1em"></div></div>` });
      await render(true);
    } else if (act === 'invite' || act === 'inviteperson') {
      const r = await dialog({ title: act === 'invite' ? `Add someone to “${f.name}”` : 'Invite someone', ok: 'Send invitation',
        sub: 'They get an email to set a password, then set up an authenticator app the first time they sign in.',
        body: `<div class="field"><label for="pname">Name</label><input name="pname" id="pname" required maxlength="80"></div>
          <div class="field"><label for="email">Email</label><input name="email" id="email" type="email" required placeholder="name@agency.gov"></div>
          <div class="field"><label for="org">Organization</label><input name="org" id="org" maxlength="80"></div>
          ${act === 'invite' ? `<fieldset class="field" style="border:0;padding:0;margin:0"><legend style="font-weight:700;font-size:14px;margin-bottom:5px">What can they do?</legend><div class="radios">
            <label class="radio"><input type="radio" name="perm" value="download" checked><span><b>Download only</b><small>See and download the files you put here.</small></span></label>
            <label class="radio"><input type="radio" name="perm" value="upload"><span><b>Upload only</b><small>Send files to you. They can’t see anyone else’s files.</small></span></label>
            <label class="radio"><input type="radio" name="perm" value="both"><span><b>Upload and download</b><small>Work back and forth with you in this folder.</small></span></label></div></fieldset>
          <div class="field"><label for="days">Access ends</label><select name="days" id="days"><option value="7">In 7 days</option><option value="30" selected>In 30 days</option><option value="90">In 90 days</option><option value="180">In 180 days</option></select></div>` : ''}
          <label class="radio"><input type="checkbox" name="noreset" value="1"><span><b>Turn off email password reset</b><small>If they forget their password, only an administrator can restore access.</small></span></label>` });
      if (!r) return;
      await inviteTo(act === 'invite' ? f.id : '', { email: r.email, name: r.pname, org: r.org, perm: r.perm, days: Number(r.days || 0), noSelfReset: r.noreset.length > 0 });
      await loadFolders(); await render(true);
    } else if (act === 'removemember') {
      const ok = await dialog({ title: 'Remove this person from the folder?', sub: 'They lose access right away. Files they already downloaded stay with them.', ok: 'Remove', danger: true });
      if (!ok) return;
      await api.updateMember({ folder: f.id, uid: b.dataset.uid, remove: true });
      await loadFolders(); await render(true); toast('Removed.');
    } else if (act === 'pkadd') {
      await addPasskey();
    } else if (act === 'pkremove') {
      if (!await dialog({ title: 'Remove this passkey?', sub: 'It will no longer sign you in. You may also want to delete it from the device or password manager that holds it.', ok: 'Remove', danger: true })) return;
      await api.passkeyDelete({ id: b.dataset.id }); await render(true); toast('Passkey removed.');
    } else if (act === 'pkremoveall') {
      if (!await dialog({ title: 'Remove all of their passkeys?', sub: 'Use this when someone loses a device. They can still sign in with their password and authenticator code.', ok: 'Remove passkeys', danger: true })) return;
      const r = await api.passkeyDelete({ uid: b.dataset.uid, all: true }); toast(`${r.removed} passkey${r.removed === 1 ? '' : 's'} removed.`);
    } else if (act === 'removeuser') {
      const ok = await dialog({ title: 'Remove this person everywhere?', sub: 'They are signed out of every device and lose access to all folders.', ok: 'Remove', danger: true });
      if (!ok) return;
      await api.removeUser({ uid: b.dataset.uid }); await loadFolders(); await render(true); toast('Removed.');
    } else if (act === 'approvereset') {
      const ok = await dialog({ title: 'Approve their password reset?', sub: 'Only do this after confirming with the person directly, for example by phone, that they reset it.', ok: 'Approve' });
      if (!ok) return;
      await api.approveReset({ uid: b.dataset.uid }); toast('Approved. They can sign in again.');
    } else if (act === 'message') {
      const { id } = await api.openThread({ uid: b.dataset.uid });
      await loadFolders(); location.hash = 'folder-' + id;
    } else if (act === 'pick') {
      $('#file-input')?.click();
    } else if (act === 'download') {
      await downloadFile(b.dataset.id);
    } else if (act === 'recover') {
      const r = await dialog({ title: 'Open with the recovery key', ok: 'Open file',
        sub: 'Use this for a records request, or when the person who could open it lost their password. The key file stays on this computer.',
        body: '<div class="field"><label for="rk">Recovery key file</label><input type="file" id="rk" name="rk" accept=".json,application/json" required></div>' });
      if (!r) return;
      const fileInput = document.getElementById('rk');
      const txt = await fileInput.files[0]?.text();
      const jwk = JSON.parse(txt || '{}').privateJwk;
      const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
      await downloadFile(b.dataset.id, key);
    } else if (act === 'delete') {
      const ok = await dialog({ title: 'Delete this file now?', sub: 'It will be removed for everyone. This can’t be undone.', ok: 'Delete now', danger: true });
      if (!ok) return;
      await api.deleteFile({ folder: f.id, file: b.dataset.id }); await render(true); toast('Deleted.');
    } else if (act === 'deletefolder') {
      const ok = await dialog({ title: `Delete “${f.name}”?`, sub: 'All its files and messages are removed for everyone, now. This can’t be undone.', ok: 'Delete folder', danger: true });
      if (!ok) return;
      await api.deleteFolder({ folder: f.id }); await loadFolders(); location.hash = 'overview'; toast('Folder deleted.');
    } else if (act === 'editnote') {
      const cur = await folderNote(f);
      const r = await dialog({ title: 'Folder note', sub: 'Everyone in the folder can read it. It’s encrypted like the files.', ok: 'Save',
        body: `<div class="field"><label for="note">Note</label><textarea name="note" id="note" rows="6" maxlength="4000" style="padding:8px 10px;border:1.5px solid var(--border);border-radius:var(--r-sm);background:var(--surface);font:inherit">${esc(cur)}</textarea></div>` });
      if (!r) return;
      await api.updateFolder({ folder: f.id, notes: await sealText(f, r.note, 'note v1') });
      await loadFolders(); await render(true); toast('Note saved.');
    } else if (act === 'export') {
      const r = await api.exportLog({});
      saveBlob(r.csv, `secure-transfer-activity-${new Date().toISOString().slice(0, 10)}.csv`, 'text/csv');
      toast(r.chain.ok ? 'Exported. The log checked out intact.' : `Exported, but entry ${r.chain.seq} failed the check (${r.chain.reason}).`);
    } else if (act === 'verifylog') {
      const r = await api.verifyLog({});
      toast(r.ok ? `All ${r.count} entries check out. Nothing was changed or removed.` : `Problem found${r.seq ? ' at entry ' + r.seq : ''}: ${r.reason}.`);
    } else if (act === 'newsend') {
      await newQuickSend(s);
    } else if (act === 'deletesend') {
      const ok = await dialog({ title: 'Delete this quick send now?', sub: 'The link stops working right away.', ok: 'Delete now', danger: true });
      if (!ok) return;
      await api.deleteSend({ id: b.dataset.id }); await render(true); toast('Deleted.');
    } else if (act === 'makerecovery') {
      await makeRecoveryKey();
    }
  } catch (err) { toast(errText(err)); }
});

async function inviteTo(folder, p) {
  const r = await api.invite({ folder, email: p.email, name: p.name, org: p.org || '', perm: p.perm, days: p.days, noSelfReset: !!p.noSelfReset });
  if (r.created) {
    // Firebase Auth sends the "set your password" email; the link verifies their address.
    await sendPasswordResetEmail(auth, p.email.trim().toLowerCase(), { url: PORTAL_URL });
    toast(`Invitation sent to ${p.email}.`);
  } else toast(`${p.email} now has access.`);
}

async function makeRecoveryKey() {
  const kp = await C.generateKeyPair();
  const priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const fp = await C.publicKeyFingerprint(kp.publicJwk);
  const text = JSON.stringify({ type: 'HCEC Secure Transfer recovery key', created: new Date().toISOString(), fingerprint: fp, privateJwk: priv }, null, 1);
  saveBlob(text, `SecureTransfer-recovery-key-${fp.replace(/ /g, '')}.json`, 'application/json');
  const r = await dialog({ title: 'Store the recovery key', ok: 'I stored it. Turn it on',
    sub: 'A file was just saved to your Downloads folder. It can open every file in the portal. It is never sent anywhere.',
    body: `<ol style="margin:0;padding-left:20px;display:grid;gap:6px"><li>Copy the file to a USB drive and print it.</li><li>Put both in the office safe.</li>
      <li>Delete it from Downloads and empty the Recycle Bin.</li></ol><p class="fine">Fingerprint: <span class="mono">${esc(fp)}</span></p>
      <label class="radio"><input type="checkbox" name="done" value="1" required><span><b>I copied, printed and stored it</b></span></label>` });
  if (!r) return toast('Not turned on. Run it again when you’re ready.');
  await api.setRecoveryKey({ jwk: kp.publicJwk });
  toast('Recovery key turned on.'); await render(true);
}

document.addEventListener('submit', async (e) => {
  if (e.target.id !== 'rules-form') return;
  e.preventDefault();
  try {
    await api.saveSettings({ defaultDays: Number($('#defaultDays').value), maxDays: Number($('#maxDays').value), removeUnusedDays: Number($('#removeUnusedDays').value) });
    toast('Settings saved.');
  } catch (err) { toast(errText(err)); }
});

// ---------------------------------------------------------------- drop-off (no account)
function showDropoff() {
  $('#app').hidden = true; $('#signin').hidden = true; $('#sendpage').hidden = true; $('#dropoff').hidden = false;
}
$('#f-drop').addEventListener('submit', async (e) => {
  e.preventDefault();
  const id = location.hash.replace('#dropoff-', '');
  const code = $('#dr-code').value, sender = $('#dr-from').value.trim();
  const files = [...$('#dr-files').files];
  const status = $('#drop-status'), err = $('#err-drop');
  err.textContent = '';
  if (!code || !sender || !files.length) { err.textContent = 'Enter the code, your name and email, and choose at least one file.'; return; }
  const bad = files.filter((x) => x.size > MAX || !ALLOWED.includes(extOf(x.name)));
  if (bad.length) { err.textContent = `${bad.map((x) => x.name).join(', ')}: files must be under 250 MB and a document, spreadsheet, image, text or zip file.`; return; }
  try {
    for (const [i, file] of files.entries()) {
      const label = `${file.name} (${i + 1} of ${files.length})`;
      status.textContent = `Preparing ${label}…`;
      const start = await api.dropoffStart({ id, code, ext: extOf(file.name) });
      const sealed = await C.sealFile(new Uint8Array(await file.arrayBuffer()), file.name, start.recipients,
        (p) => { status.textContent = `Encrypting ${label}: ${Math.round(p * 100)}%`; });
      status.textContent = `Sending ${label}…`;
      const put = await fetch(start.url, { method: 'PUT', body: sealed.ciphertext, headers: { 'Content-Type': 'application/octet-stream', 'x-goog-content-length-range': `0,${MAX + 1e6}` } });
      if (!put.ok) throw new Error('The upload was refused. Try again.');
      await api.dropoffFinish({ id, code, fileId: start.fileId, name: sealed.name, sha256: sealed.sha256, size: file.size, keys: sealed.keys, ext: extOf(file.name), sender });
    }
    status.textContent = `Sent ${files.length} file${files.length === 1 ? '' : 's'}. The Election Commission has been notified. You can close this page.`;
    $('#dr-files').value = '';
  } catch (ex) { status.textContent = ''; err.textContent = errText(ex); }
});

if (isPublicLink()) showPublicLink();

// ---------------------------------------------------------------- quick send: recipient page (no account)
let sendMeta = null;
async function showSendPage() {
  $('#app').hidden = true; $('#signin').hidden = true; $('#dropoff').hidden = true; $('#sendpage').hidden = false;
  const [id, secret] = location.hash.replace('#send-', '').split('.');
  if (!id || !secret) { $('#send-about').textContent = 'This link is not complete. Copy the whole link, including everything after the # sign.'; return; }
  try {
    sendMeta = await api.sendInfo({ id });
    $('#send-about').innerHTML = `${sendMeta.label ? `<b>${esc(sendMeta.label)}</b><br>` : ''}${fmtSize(sendMeta.size)} · ` +
      `${sendMeta.remaining === 1 ? 'can be downloaded once' : `${sendMeta.remaining} downloads left`} · available until ${fmtDate(sendMeta.expiresAt)}`;
    $('#send-pass-field').hidden = !sendMeta.hasPassword;
    $('#send-btn').disabled = false;
    if (sendMeta.hasPassword) $('#send-pass').focus();
  } catch (err) {
    $('#send-about').textContent = errText(err);
  }
}
$('#f-send').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!sendMeta) return;
  const [id, secret] = location.hash.replace('#send-', '').split('.');
  const pw = sendMeta.hasPassword ? $('#send-pass').value : '';
  const status = $('#send-status'), err = $('#err-send');
  err.textContent = '';
  if (sendMeta.hasPassword && !pw) { err.textContent = 'Enter the password.'; return; }
  try {
    $('#send-btn').disabled = true;
    status.textContent = 'Checking…';
    const access = await C.sendAccess(secret, pw, sendMeta.salt, sendMeta.iterations);
    const r = await api.sendOpen({ id, access });
    status.textContent = 'Downloading…';
    const res = await fetch(r.url, { referrerPolicy: 'no-referrer' });
    if (!res.ok) throw new Error('The download didn\u2019t finish. Reload the page and try again.');
    const ct = new Uint8Array(await res.arrayBuffer());
    status.textContent = 'Decrypting…';
    const out = await C.openSend(secret, pw, sendMeta.salt, sendMeta.iterations, { name: r.name, sha256: r.sha256, ciphertext: ct });
    saveBlob(out.data, out.fileName);
    status.innerHTML = `Saved <b>${esc(out.fileName)}</b>. Fingerprint <span class="mono">${out.sha256.slice(0, 16)}\u2026</span> matches what was sent.`;
    sendMeta.remaining -= 1;
    if (sendMeta.remaining > 0) $('#send-btn').disabled = false;
  } catch (ex) {
    $('#send-btn').disabled = false;
    status.textContent = '';
    err.textContent = errText(ex);
  }
});
