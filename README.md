# Easylsp Market

Official signed plugin catalog: https://qintaiyang.github.io/Easylsp-Market/catalog.json

Readers need no account. In Easylsp open **市场**, refresh, select a fixed release,
then install into its target project. Configure and explicitly enable it there.
Native changes take effect after restarting the target app.

Authors use a public repository with fixed source commits and a `plugin.zip`
GitHub Release asset. Easylsp's author screen or the authorized AI release tools
upload a prepared v3 package and create a submission PR. First register your
publisher identity using a maintainer-reviewed `market/publishers/<id>.json`:
`publisherId`, numeric `githubAccountId`, owned numeric `repositoryIds`, displayName.
Repository names are display information; ownership checks use numeric IDs.

A submission changes one `submissions/<releaseId>.json`. The read-only candidate
workflow checks the exact asset and source commit without executing plugin code,
then retains `plugin.zip`, `submission.json` and `review.json` in an immutable
Actions artifact. Review that run/artifact, merge its exact PR, dispatch the
**Publish reviewed immutable candidate** workflow using both numeric IDs, and
approve the protected **market-release** environment. The publisher signs bytes
from that artifact, creates an official Release, appends the signed catalog and
deploys Pages. It never downloads the author's asset again during publication.

An uploaded release, pending PR, merged PR and live catalog are separate states.
Rejected candidates do not enter the catalog. Report a release through Issues;
withdrawn records stay in catalog history and existing installations remain local.

See [protocol](market/PROTOCOL.md) and [operations](market/OPERATIONS.md).
Private signing keys and GitHub author credentials must never enter this repository.
