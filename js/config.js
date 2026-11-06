/**
 * Firebase web configuration. These values are public identifiers, not secrets: access is enforced by
 * sign-in (password + authenticator code), the security rules, the Cloud Functions and App Check.
 *
 * ?staging   use the test project instead of the live one.
 * ?emulator  on localhost, use the Firebase Emulator Suite.
 */
const PROD = {
  apiKey: 'AIzaSyAqJK0tVDt2nWlWcVFotIvXzx_h6vLwWig',
  authDomain: 'hcec--transfer.firebaseapp.com',
  projectId: 'hcec-secure-transfer',
  storageBucket: 'hcec-secure-transfer.firebasestorage.app',
  messagingSenderId: '1086361879095',
  appId: '1:1086361879095:web:7caeddb0dbb3b704dfb5b2',
  recaptchaKey: '', // App Check (reCAPTCHA Enterprise) site key, set at go-live
};
const STAGING = {
  apiKey: 'AIzaSyDaWSTpxRogZml7MQYc2wqEuWd8Iv_mShY',
  authDomain: 'hcec--transfer-staging.firebaseapp.com',
  projectId: 'hcec-secure-transfer-staging',
  storageBucket: 'hcec-secure-transfer-staging.firebasestorage.app',
  messagingSenderId: '603603538978',
  appId: '1:603603538978:web:02d1a7e4777f270400a67b',
  recaptchaKey: '',
};
const EMULATOR = {
  apiKey: 'demo-key', authDomain: 'demo-secure-transfer.firebaseapp.com', projectId: 'demo-secure-transfer',
  storageBucket: 'demo-secure-transfer.appspot.com', appId: 'demo-app', recaptchaKey: '',
};

const q = new URLSearchParams(location.search);
const local = ['localhost', '127.0.0.1'].includes(location.hostname);
export const MODE = local && q.has('emulator') ? 'emulator' : q.has('staging') ? 'staging' : 'prod';
export const CONFIG = MODE === 'emulator' ? EMULATOR : MODE === 'staging' ? STAGING : PROD;
export const FUNCTIONS_REGION = 'us-east1';
export const IDLE_MINUTES = 30;
export const PORTAL_URL = location.origin + location.pathname;
