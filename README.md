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
| Cloud Functions (`functions/`): invitations, permissions, uploads/downloads, limits, drop-off, messages, notes, cleanup, chained activity log, email alerts | written, logic tested; first deploy pending |
| Portal (`index.html`, `js/app.js`) | written; end-to-end test on the test project pending |
| Passkeys, signature requests | not started |

Tests: `npm test` (encryption), `npm test` in `functions/` (logic), `npm run test:rules` (rules on emulators).
Deploying: [docs/DEPLOY.md](docs/DEPLOY.md).
