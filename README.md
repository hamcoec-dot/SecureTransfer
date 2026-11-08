# HCEC Secure Transfer

Secure file sharing for the Hamilton County Election Commission, live at govotehamiltontn.gov/SecureTransfer/.
The commission shares files with outside people, and invited outside people send files to the commission.

Pages are static (GitHub Pages). Sign-in, permissions, file storage, automatic deletion and the activity log run
on Firebase. Files are encrypted in the browser before upload, with a commission-held recovery key.
Design and build plan: [plans/secure-transfer.md](plans/secure-transfer.md).

## Status

| Part | State |
|---|---|
| Design preview (`preview.html`, example data) | done |
| Firebase projects (test and live), sign-in with authenticator codes, rules | done, rules tested on emulators |
| Browser encryption (`js/crypto.js`), recovery key, fingerprints | done, tested |
| Cloud Functions (`functions/`): invitations, permissions, uploads/downloads, limits, drop-off, quick send, messages, notes, cleanup, chained activity log, email alerts | live on both projects, end-to-end tested on emulators |
| Portal (`index.html`, `js/app.js`) | live since 2026-11-07 |
| Passkeys (Windows Hello, iPhone/Android, Bitwarden) | live since 2026-11-08 |
| Signature requests on PDFs | dropped: most Tennessee government documents need physical signatures |

Tests: `npm test` (encryption), `npm test` in `functions/` (logic), `npm run test:rules` (rules on emulators),
`npm run test:flows` (every flow through the real functions on emulators).
Deploying: [docs/DEPLOY.md](docs/DEPLOY.md).
