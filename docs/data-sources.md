# Real-world data sources and provenance

MVX separates three data planes:

1. `corpus/` contains safe synthetic fixtures for deterministic regression
   tests.
2. `intel/` contains real-world extension identifiers, labels, hashes, and
   provenance, but no executable packages.
3. `quarantine/` is ignored by Git and reserved for explicitly acquired,
   untrusted artifacts. Nothing in quarantine is used by ordinary tests.

## Pinned default sources

### MalExt Sentry

[MalExt Sentry](https://github.com/toborrm9/malicious_extension_sentry)
aggregates browser-extension reports into several threat-intelligence formats.
MVX imports its detailed CSV under the MIT license. The pinned snapshot has
3,775 input records and preserves labels such as malware, adware, policy
violation, unwanted software, search hijacking, and suspicious instead of
collapsing them into a binary verdict.

### Malicious Chrome Extension IOC Database

The Privacy Commons Institute's [Malicious Chrome Extension IOC
Database](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids)
provides source URLs, threat types, operator/researcher confirmation fields,
store state, ownership-transfer information, behavioral review, and selected
CRX hashes. It is licensed CC BY 4.0. MVX preserves the distinction between a
report, Google malware confirmation, and TPCI behavioral confirmation.

### MaliciousBrowserExtensions

[MaliciousBrowserExtensions](https://github.com/GherardoFiori/MaliciousBrowserExtensions)
is an MIT-licensed index and repository of reported malicious CRX packages.
The pinned Git tree has 525 CRX paths, of which 504 are non-empty, totaling
5,952,318,439 bytes. MVX stores only path, size, Git blob SHA, available
SHA-256, and provenance. The packages themselves are neither vendored nor
automatically downloaded because they are dangerous, large, and may have
separate third-party copyright constraints.

The provider's `database.json` associates hashes with extension IDs, not with
an explicit artifact path and version. Real validation found at least one stale
reported SHA-256 even though the pinned Git blob and byte size matched. MVX
therefore stores this field as `reportedSha256`; it never presents it as the
hash of the currently indexed file without checking the bytes.

## Opt-in artifact acquisition

Use `mvx sample plan <extension-id>` before downloading. `mvx sample fetch`
requires `--acknowledge-risk` and applies all of the following controls:

- immutable source revision and allowlisted HTTPS hosts;
- manual redirect validation;
- default 25 MB and hard 100 MB per-file limits;
- pinned size and Git blob SHA verification;
- locally computed SHA-256 content addressing;
- explicit reporting when a provider-reported SHA-256 belongs to another
  version;
- mode `0600` files in a non-symlink quarantine directory;
- no overwrite, extraction, import, browser loading, or execution.

`quarantine/` is excluded from Git and npm packages. It can still contain live
malware and should be handled inside a disposable analysis VM. A successful
download only proves artifact integrity, not malicious behavior.

## Additional research sources

- The [`tweb25`](https://github.com/its-not-easy/tweb25) artifact accompanies
  the peer-reviewed study “It's not Easy: Applying Supervised Machine Learning
  to Detect Malicious Extensions in the Chrome Web Store.” It describes 7,140
  malicious and 63,598 approximately benign labeled extensions and publishes
  ML-ready features under AGPL-3.0, but not the original extension source. It
  is suitable for concept-drift and classifier evaluation, not direct static
  scanning.
- Chrome-Stats exposes historical package and metadata access commercially.
  Its data must only be used through a user-supplied API credential and may not
  be redistributed without permission.
- VirusTotal can enrich known hashes when the user supplies an appropriately
  licensed API key. Its verdicts are supporting evidence, not ground truth,
  and file download requires eligible access.
- MalwareBazaar and VirusShare can be used to investigate a known hash, but
  their CRX coverage and labels must be verified before inclusion.

These sources are documented but are not silently queried by the CLI.

## Updating the snapshot

Every default input is pinned to an immutable commit. Files with a stable raw
representation also have a SHA-256 in `intel/sources.json`. To update:

1. Review upstream changes, license, schema, and record-count changes.
2. Replace each ref, URL, checksum, and `snapshotDate` together.
3. Run `npm run intel:update` and inspect label/count deltas.
4. Run `npm run intel:check`, `npm run intel:validate`, and the complete test
   suite.
5. Commit source locks and generated output atomically.

Do not point a committed source at a moving branch. Do not add a source whose
license forbids redistribution.

## Ground-truth limitations

The catalog is threat intelligence, not a perfect binary truth set. Reports
can be incomplete; store removals include non-malware policy violations; C2
infrastructure expires; and an ID can span benign and malicious versions.
Research results must state the provider, snapshot date, inclusion criteria,
artifact hash, and time-aware train/test split. A random split can leak nearly
identical campaign variants and produce misleadingly high accuracy.
