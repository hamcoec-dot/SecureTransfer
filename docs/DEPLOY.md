# Deploying Secure Transfer

The pages deploy themselves: GitHub Pages serves `main` at govotehamiltontn.gov/SecureTransfer/.
Add `?staging` to the address to use the test project.

The back end (Cloud Functions, Firestore/Storage rules and indexes, bucket CORS and lifecycle) deploys from the
**deploy** workflow in the Actions tab: test project first, then the live one if *production* is ticked (that
job waits for approval on the `production` environment).

**Nothing secret goes in this repository.** Deploys use Workload Identity Federation (no key files); the mail
password lives in Secret Manager; the recovery key lives on paper and USB in the office safe.

## Projects
| | Test | Live |
|---|---|---|
| Project | `hcec-secure-transfer-staging` (603603538978) | `hcec-secure-transfer` (1086361879095) |
| Bucket | `hcec-secure-transfer-staging.firebasestorage.app` | `hcec-secure-transfer.firebasestorage.app` |
| Region | us-east1 | us-east1 |
| Budget alert | $5/month | $5/month |

Set up 2026-11-06 with gcloud and the Firebase REST APIs: Identity Platform with email/password, sign-up off,
TOTP multi-factor on (no SMS), authorized domains `govotehamiltontn.gov` and `localhost`, the Storage service agent
granted `roles/firebaserules.firestoreServiceAgent` (storage rules read Firestore), bucket lifecycle 181 days.

## One-time setup, per project (`P` = project id, `N` = project number)
```bash
# 1. Deploy service account for GitHub Actions
gcloud iam service-accounts create github-deploy --project=$P
SA=github-deploy@$P.iam.gserviceaccount.com
for role in roles/firebase.admin roles/cloudfunctions.admin roles/run.admin roles/iam.serviceAccountUser \
            roles/storage.admin roles/firebaserules.admin roles/cloudscheduler.admin roles/datastore.indexAdmin \
            roles/secretmanager.viewer roles/artifactregistry.admin roles/eventarc.admin roles/identityplatform.admin; do
  gcloud projects add-iam-policy-binding $P --member=serviceAccount:$SA --role=$role --condition=None
done

# 2. Workload Identity Federation for this repository only
gcloud iam workload-identity-pools create github --project=$P --location=global
gcloud iam workload-identity-pools providers create-oidc github --project=$P --location=global \
  --workload-identity-pool=github --issuer-uri=https://token.actions.githubusercontent.com \
  --attribute-mapping=google.subject=assertion.sub,attribute.repository=assertion.repository \
  --attribute-condition="assertion.repository == 'hamcoec-dot/SecureTransfer'"
gcloud iam service-accounts add-iam-policy-binding $SA --project=$P --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/$N/locations/global/workloadIdentityPools/github/attribute.repository/hamcoec-dot/SecureTransfer"

# 3. Functions sign short-lived download links and passkey sign-in tokens: the runtime account must be able to sign
#    as itself (and the IAM Service Account Credentials API must be on)
RUNTIME=$N-compute@developer.gserviceaccount.com
gcloud iam service-accounts add-iam-policy-binding $RUNTIME --project=$P \
  --member=serviceAccount:$RUNTIME --role=roles/iam.serviceAccountTokenCreator

# 3b. The org policy gives new projects' default compute account no roles. Functions build and run as it:
for role in roles/cloudbuild.builds.builder roles/logging.logWriter roles/artifactregistry.writer \
            roles/datastore.user roles/storage.objectAdmin roles/firebaseauth.admin; do
  gcloud projects add-iam-policy-binding $P --member=serviceAccount:$RUNTIME --role=$role --condition=None
done
# 3c. firebase deploy also needs these APIs on: firebaseextensions, cloudresourcemanager, pubsub, runtimeconfig,
#     logging, cloudbilling (done 2026-11-07).

# 3d. The org's "Domain restricted sharing" policy blocks allUsers, which callables and the sign-in hooks need
#     (each function checks sign-in itself). Override it on this project only (needs Org Policy Administrator):
printf 'constraint: constraints/iam.allowedPolicyMemberDomains\nlistPolicy:\n  allValues: ALLOW\n' > allow.yaml
gcloud resource-manager org-policies set-policy allow.yaml --project=$P

# 4. Mail for alerts (Secret Manager). "none" turns alerts off until a real account is connected:
printf none | gcloud secrets create SMTP_URL --project=$P --data-file=-
gcloud secrets add-iam-policy-binding SMTP_URL --project=$P --member=serviceAccount:$RUNTIME --role=roles/secretmanager.secretAccessor
#    later: printf 'smtps://USER:APP-PASSWORD@smtp.example.com:465' | gcloud secrets versions add SMTP_URL --data-file=-

# 5. Firestore TTL backstop on file and message records
gcloud firestore fields ttls update expiresAt --collection-group=files --enable-ttl --project=$P --async
gcloud firestore fields ttls update expiresAt --collection-group=messages --enable-ttl --project=$P --async
```

## GitHub settings (once)
- **Environments:** `staging` (no rules); `production` with *Required reviewers* = Nate, deployment branch `main`.
- **Repository variables:** `GCP_WIF_PROVIDER_STAGING`/`GCP_WIF_PROVIDER_PROD` =
  `projects/<N>/locations/global/workloadIdentityPools/github/providers/github`;
  `GCP_DEPLOY_SA_STAGING` / `GCP_DEPLOY_SA_PROD` = `github-deploy@<P>.iam.gserviceaccount.com`.

## First administrator (once per project)
Accounts come only from invitations, so the first one is made by hand:
1. Create the user (Identity Toolkit `projects/<P>/accounts` POST with the email), set custom claim
   `{"admin": true}` (`accounts:update` with `customAttributes`), and create Firestore `users/<uid>` with
   `{ email, name, admin: true, removed: false, createdAt }`.
2. Send the password-setup email (`accounts:sendOobCode`, `PASSWORD_RESET`).
3. The administrator sets a password, signs in, scans the authenticator QR code, signs in again with a code.
4. Settings → **Create the recovery key**. Print it, copy it to USB, store both in the safe. Uploads stay off
   until this is done.

## After a deploy
- Sign in on the test site (`?staging`), upload and download a small CSV, and check the Activity log shows both.
- Settings → Check the log reports every entry intact.

## One "api" function (2026-11-09)
Every portal action goes to the single callable `api` (`{ op, data }`), so one cold start per visit instead of one per
action; the page pings it (and the sign-in check) when it opens. No minimum instances: it still scales to zero, so
there is no added cost. The old one-function-per-action addresses are still deployed as thin wrappers, for pages
opened before the change and as a fallback the page uses automatically if a project has no `api` yet. Remove them
(the `legacy(...)` exports at the bottom of functions/src/index.js) once both projects have served `api` for a while.
