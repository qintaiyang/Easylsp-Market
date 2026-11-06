# Marketplace operations

Repository: https://github.com/qintaiyang/Easylsp-Market
Pages source: GitHub Actions. Publishing environment: `market-release`, required
reviewer qintaiyang (numeric ID 211089090). Candidate checks have read-only tokens,
checkout the base commit's scripts and never execute a candidate binary/script.
Signing credentials are used only by the protected workflow on main.

## Initial configuration

The bundled `market-2026` public key is in `market/keys/market-2026.pem`; the APK
contains its X.509 DER form. The private backup is outside the source workspace at
`/root/.local/share/easylsp-market/signing-2026.pem` (directory 0700, file 0600).
The GitHub Secret is `MARKET_SIGNING_KEY`. Preserve this backup before moving hosts.
No author token is included in source, APKs or release packages.

GitHub OAuth Apps cannot be created with the REST token used to create repositories.
The account owner creates an OAuth App in GitHub developer settings, enables Device
Flow, and copies its public Client ID into Easylsp's author screen. No client secret
is needed. Until configured, explicit encrypted author-token login is available.
Read-only clients do not need either method.

## Review and publish

1. Review numeric publisher and repository ownership registrations independently.
2. Check a submission PR's successful candidate workflow and its `review.json`.
   Record the Actions run ID and artifact ID; retained candidates expire after 30 days.
3. Inspect manifest, source commit, permissions/capabilities, README and license.
4. Merge the exact checked PR. Dispatch publish with its run and artifact IDs.
5. Approve the environment after confirming those IDs. The job signs/copies the
   immutable artifact into a new official Release, updates catalog and deploys Pages.
6. Verify the signed catalog and its fixed official asset using the public key.

Never edit a published release identity's payload. On a failed partial publish,
inspect the created official Release before rerunning; do not replace its assets.
A corrected payload needs a new releaseId and increasing versionCode.

## Withdrawal

Change the exact existing catalog record's state to WITHDRAWN and add a nonempty
withdrawalReason and withdrawnAt. Use the protected catalog workflow to regenerate,
sign and deploy. Preserve the old identity, URLs and Release assets. The client
blocks new installations but does not silently remove already installed plugins.

## Backup, restore and key rotation

Back up Git history, `market/catalog`, publishers, signed `market/public`, official
Release assets/signatures/review records, and the private key separately. Restoring
an existing signed catalog requires no private key: copy exact public files and
verify them with the retained public key, then deploy with the Pages workflow.
Restore tests must use a separate repository and keep original release identities.

For rotation create a new Ed25519 key outside Git, add its public key under a new
keyId to the client trust map first, release that client, then switch the protected
publisher to that keyId. Keep all retired public keys so older cached releases
remain verifiable. Restore the private backup only into a protected publishing
secret; never send it to a candidate job or model prompt.
