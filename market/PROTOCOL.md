# Offline release and catalog protocol (v3 draft)

This repository contains preparation tooling. No official marketplace, production
key or OAuth App is configured, and no public content is uploaded by these scripts.
The APK's release importer is local/offline; imported publisher IDs are unverified
claims and appear as `IMPORTED_RELEASE`, never as an authenticated marketplace author.

A ZIP contains `manifest.json`, `README.md`, `LICENSE`, one native
`native/arm64-v8a/plugin.so` or `java/main.java`, optional native `src/`/`include/`,
Java `java/lib/`, and optional Native-only `config.schema.json`. Java configuration is not implemented. See the schema and example. Android 14+
and arm64 remain the host baseline. A v3 native artifact's declared minApi must
match its Android ELF note and be <=34; the legacy v2 API34 contract is unchanged.

Each `(catalogPluginId, releaseId)` names immutable bytes. `versionCode` increases
for updates; explicit rollback selects a cached previous release. Local instance
UUID, configured values, scope and ordering survive updates. Local source edits
block an update until the user preserves a local copy or discards those edits.
A source-less native release imports a successful precompiled build; its editor
contains an explicit `#error` marker rather than fabricated source.

Required capabilities currently accepted: `native.symbol`, `native.elf-vaddr`,
`native.module-lifecycle`, `java.beanshell`. JNI registration and intercept are
not declared supported. Installation and publication are separate operations.

## Ed25519 envelope

Metadata has `schema=1`, `kind=release|catalog`, `keyId`, and Base64 `signature`.
Release metadata also has `catalogPluginId`, `publisherId`, `releaseId`,
`versionCode` (integer). Catalog metadata has `catalogRevision` (string).
The payload is the complete unchanged ZIP or complete catalog.json bytes.
No archive entry rewriting or JSON canonicalization occurs during signing.

Signature input, in order:

1. ASCII bytes `Easylsp-Signature-v1` followed by one zero byte.
2. For releases: `kind`, `keyId`, `catalogPluginId`, `publisherId`, `releaseId`,
   decimal `versionCode`. For catalogs: `kind`, `keyId`, `catalogRevision`.
   Each is a four-byte unsigned big-endian UTF-8 byte count and those exact bytes.
3. Eight-byte unsigned big-endian payload byte count, followed by payload bytes.

The envelope is detached. Verify using the configured trusted `keyId` before
parsing network data; bind the verified identity to the parsed manifest. A key
inside a downloaded package is never a trust anchor. Android uses X.509 DER public
keys; CLI uses OpenSSL PEM public keys. Keep retired public keys to verify cached
old releases. Never put private keys or author access tokens in APKs, prompts,
ZIPs, candidate checks or unprotected workflows.

```sh
python3 market/scripts/market.py check-release plugin.zip
python3 market/scripts/market.py sign plugin.zip --kind release --key-id test-1 \
  --context release-context.json --key test-private.pem --output plugin.signature.json
python3 market/scripts/market.py verify plugin.zip --metadata plugin.signature.json \
  --public-key test-public.pem
```

Only a protected production publication job may sign official releases, after
reviewing a fixed candidate Actions artifact ID and run ID. Copy those exact bytes
to a new official GitHub Release asset; never sign a fresh author URL after review.
Keep an ownership registry binding publisherId to numeric GitHub account ID and
repositoryId; renames do not change ownership. Retain withdrawal records when
rebuilding the catalog. No official source is enabled until real URLs and public
keys have been configured and the two-account flow has been accepted on devices.

## Current author/AI preparation flow

This is a local preparation interface, not GitHub publishing. In a project conversation
use its real plugin ID; in a global conversation supply a real existing plugin UUID
explicitly. `read_development_reference(document="plugin-release")` exposes this text.

1. Save the plugin source and attachments, including full license text in `LICENSE`.
2. For Native select an already accepted successful fixed `buildId`; source files
   from that build's `sourceRevision` are used. Precompiled imports can be re-exported
   without fabricated source. Java uses its saved revision.
3. Call `prepare_plugin_release` with `pluginId`, Native `buildId`, and full `manifest`.
   The existing conversation write authorization/preview applies.
4. Save the returned `preparationId`; use `get_plugin_release_status` to read its
   fixed receipt. `PREPARED_LOCAL` and a local archive path do not mean a Release,
   PR, review decision or catalog entry exists. There is no upload/submit tool yet.

Native manifest example (replace every author/target/version value with actual data):

```json
{
  "formatVersion": 3,
  "catalogPluginId": "author.plugin",
  "publisherId": "author",
  "releaseId": "unique-fixed-release-id",
  "versionCode": 1,
  "versionName": "1.0",
  "name": "Plugin name",
  "description": "What this fixed release does",
  "license": "MIT",
  "sourceUrl": "https://github.com/author/repository",
  "channel": "test",
  "changelog": "Initial release",
  "publishedAt": "2026-11-06T00:00:00Z",
  "runtime": "NATIVE",
  "pluginAbi": 1,
  "sdkVersion": "p0-v1",
  "minHostVersion": 9,
  "requiredCapabilities": ["native.symbol"],
  "artifacts": [{"abi":"arm64-v8a","minApi":34,"artifactPath":"native/arm64-v8a/plugin.so"}],
  "target": {"packageName":"actual.target.package","processScope":"main"}
}
```

For Java set runtime to `BEANSHELL`, capability `java.beanshell`, artifact ABI `any`
and artifact path `java/main.java`; omit Native `buildId`. `processScope` accepts
main/children/all/exact; exact also requires a processName belonging to the package.
Optional target minVersionCode/maxVersionCode bound compatible target versions.

Native config optionally declares `{"version":1,"schemaPath":"config.schema.json",
"defaults":{"amount":1}}`. The saved plugin schema is a flat object with fixed
boolean/number/integer/string fields, optional enum, numeric minimum/maximum or
string minLength/maxLength; nested objects, scripts and unknown constraints are
rejected. Configuration is at most 8 KiB. Users explicitly publish it for the next
process. An incompatible update is retained in cache and rejected for installation;
there is not yet a pending-update configuration migration screen.
