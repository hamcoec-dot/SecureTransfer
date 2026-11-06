# Secure Transfer: design and build plan

Owner: Nate (Hamilton County Election Commission). Started 2026-11-06.

## Goal
- The commission shares files with outside people (download).
- Invited outside people send files to the commission (upload), and can see only what they sent.
- Strong security, near-zero cost, files deleted automatically after a period the commission sets.
- Files are small: text, CSV, PDF, spreadsheets; a few hundred MB stored at any one time.

## Ground rules
- **The repo is public. No secrets in git, ever.** That covers service-account keys, the recovery private key,
  `.env` files with real values, and emulator exports with real data (`.gitignore` blocks the usual names).
  Deploys from GitHub Actions use Workload Identity Federation, as Results does, so no keys are stored in GitHub.
  The Firebase web config (apiKey, projectId, appId) is public by design: it only identifies the project. Access
  is enforced by Auth, the security rules, the functions and App Check.
- Same shape as the Results repo: a production and a staging Firebase project, rules files in the repo, functions
  tested on the emulators, deploy by GitHub Actions.

## Architecture
| Piece | Service | Notes |
|---|---|---|
| Pages | GitHub Pages at `/SecureTransfer/` | static HTML/JS, CSP meta, `noindex` |
| Sign-in | Firebase Auth (Identity Platform) | email + password, **TOTP authenticator required** (no SMS, it costs money); self sign-up off; idle sign-out after 30 min; session persistence only |
| Bot protection | App Check (reCAPTCHA Enterprise) | free tier covers this volume |
| Folders, members, file records, requests, audit | Firestore (us-east1) | clients read only what rules allow; all writes that change access go through functions |
| File contents | Cloud Storage (default bucket, us-east1) | ciphertext only; direct client reads denied |
| Logic | Cloud Functions (2nd gen, Node 22) | invite, request, upload finalize, download URL, delete, daily cleanup |

Projects: `hcec-secure-transfer` and `hcec-secure-transfer-staging` (names to confirm when created).

## Roles and permissions
- **Administrator** (custom claim `admin`): Nate and anyone he names. Creates folders, invites, sets rules, reads the log.
- **Folder member**, one of: `download` (see and get admin-posted files), `upload` (send files; sees only own uploads),
  `both`. Each membership has an end date. Stored as `folders/{fid}.members.{uid} = {perm, until}`.
- A file request is a one-person folder with `upload` permission and a note saying what is wanted.

## Encryption (decided 2026-11-06: in the browser, plus a commission recovery key)
- Each user gets an ECDH P-256 key pair made in the browser (WebCrypto) at first sign-in. The private key is
  wrapped with AES-GCM under a key derived from their password (PBKDF2-SHA-256, 600k iterations) and stored in
  `keys/{uid}`. Google only ever holds the wrapped copy.
- Each file gets a random AES-256-GCM key; the file is encrypted in chunks before upload. The file key is wrapped
  for: the uploader, every folder member allowed to read it, and the **commission recovery public key**.
- The recovery private key is made once, offline, printed and stored on a USB drive in the office safe. It never
  goes to GitHub or Firebase. It is used only for records requests or a lost password, on a recovery page that
  works offline.
- Password reset: the user gets a new key pair; an admin (or the recovery key) re-wraps their files.
- Filenames are encrypted too; Firestore holds only size, dates, uploader and the wrapped keys.

## Upload and download
- Upload: browser encrypts → uploads ciphertext to `folders/{fid}/{fileId}` (storage rules check membership with
  `firestore.get`, size ≤ 250 MB, content type `application/octet-stream`) → callable `finalizeUpload` writes the
  file record with `expiresAt` and an audit entry.
- Download: callable `getDownload` checks permission, writes the audit entry, returns a 5-minute signed URL; the
  browser downloads and decrypts. Every download is logged because there is no other way to read a file.

## Automatic deletion
- Each folder has a period (1 to the max, default 7 days). Each file's `expiresAt = uploadedAt + period`.
- Scheduled function `cleanup` runs hourly: deletes expired objects and records, writes one audit entry per run.
- Backstops: a bucket lifecycle rule deletes any object older than the max period + 1 day; a Firestore TTL policy
  on `files.expiresAt`. Memberships past `until` are removed by the same job; unused accounts after 90 days.
- The audit log is kept (it is small) and can be exported as CSV; its own retention is a setting.

## Audit log
`audit/{id}`: time, actor uid/email, action, folder, file id, IP, user agent. Written only by functions; rules deny
client writes; nobody, admins included, can edit or delete entries from the app.

## Cost (expected about $0/month)
Blaze plan with free allowances: Storage 5 GB, Firestore 1 GiB and 50k reads/day, Functions 2M calls/month,
Auth up to 50k monthly users with TOTP, Cloud Scheduler 3 jobs, App Check reCAPTCHA 10k checks/month.
A $5 budget alert on each project.

## Phases
1. **Design preview** (done): `index.html` with example data, nothing uploaded.
2. Firebase projects, Auth with required TOTP, Firestore/Storage rules, emulator tests for every rule.
3. Browser encryption library + tests; upload and download end to end on the emulators.
4. Invitations (email from Firebase Auth's password-setup mail), file requests, member end dates.
5. Cleanup job, lifecycle and TTL backstops, activity log page and CSV export.
6. Staging deploy, security review, production deploy, root site 404 list and home page link.

## Additions from the Verifyle feature review (2026-11-06)
Full checklist: Claude Doc "Secure Transfer feature checklist". Added to the phases:
- Phase 2: passkeys (WebAuthn) as an alternative to password + TOTP; per-person "no self-service reset".
- Phase 3: immutable uploads (no overwrite), allowed file-type list, SHA-256 fingerprint per file.
- Phase 4: encrypted message thread per folder, private 1:1 threads, encrypted folder notes, per-file
  visibility checkboxes, optional public drop-off page gated by a code.
- Phase 5: hash-chained (tamper-evident) audit log, download receipts and new-upload emails, new-device
  sign-in alerts, download limits / delete-after-download.
- Phase 6: installable on phones (web app manifest), WCAG 2.1 AA check, HSTS check on the domain.
- Phase 7 (after go-live): signature requests on PDFs with a certificate page (who, when, fingerprint).
- Skipped: billing/payments, password vault, PDF editing.

## What Nate does
- Phase 2: create the two Firebase projects on his billing account (steps will be in docs/DEPLOY.md) or let the
  work run on his PC with his signed-in Firebase CLI from `C:\Projects\SecureTransfer`.
- Phase 6: make the recovery key offline and store it.
