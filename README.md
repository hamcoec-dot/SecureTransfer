# HCEC Secure Transfer

Secure file sharing for the Hamilton County Election Commission, live at govotehamiltontn.gov/SecureTransfer/.
The commission shares files with outside people, and invited outside people send files to the commission.

Pages are static (GitHub Pages). Sign-in, permissions, file storage, automatic deletion and the activity log run
on Firebase. Files are encrypted in the browser before upload, with a commission-held recovery key.
Design and build plan: [plans/secure-transfer.md](plans/secure-transfer.md).

## Status

| Part | State |
|---|---|
| Design preview (`index.html`, example data, nothing uploaded) | done |
| Firebase projects, sign-in with authenticator codes, rules | not started (Phase 2) |
| Browser encryption, upload and download | not started (Phase 3) |
| Invitations, file requests, permissions | not started (Phase 4) |
| Automatic deletion, activity log | not started (Phase 5) |
| Staging and production deploy, security review | not started (Phase 6) |
