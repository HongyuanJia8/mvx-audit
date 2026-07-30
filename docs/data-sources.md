# Real-world data sources and provenance

MVX separates three data planes:

1. `corpus/` contains safe synthetic fixtures for deterministic regression
   tests.
2. `intel/` contains real-world extension identifiers, labels, hashes, and
   provenance, but no executable packages.
3. `quarantine/` is ignored by Git and reserved for explicitly acquired,
   untrusted artifacts. Nothing in quarantine is used by ordinary tests.

Analyst-supplied declarative rule packs form a separate local input plane. MVX
does not download or update them. Their exact raw-byte SHA-256 and descriptive
version are recorded in each audit, but their claims retain the trust and
licensing status assigned by the analyst who selected them.

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

### Awesome Lists Browser Extensions

The MIT-licensed [browser-extension indicator list](https://github.com/mthcht/awesome-lists/tree/6ec23d62f0e29574f0eb5fed3ee364baa8f0ecb3/Lists/Browser%20Extensions)
adds community-curated names, references, comments, and occasional CRX hashes.
MVX imports only rows explicitly marked `malicious`, validates extension IDs,
deduplicates repeated rows, and labels them `community-reported-malicious`.
These reports expand coverage but are deliberately not promoted to behavioral
or vendor-confirmed ground truth.

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

For reproducible batches, `sample plan-many` sorts strict behavioral
confirmations first, then explicit malware labels, then researcher reports. It
chooses one bounded artifact per extension ID and enforces count, per-file, and
total-byte budgets. `sample fetch-many` follows that exact plan sequentially,
preserves every individual failure, and never treats a partial batch as
complete.

`quarantine/` is excluded from Git and npm packages. It can still contain live
malware and should be handled inside a disposable analysis VM. A successful
download only proves artifact integrity, not malicious behavior.

`mvx sample unpack` supports CRX2, CRX3, and ordinary ZIP extension packages
with stored or deflated entries. It verifies bounded CRX2/CRX3 signature
proofs, derives the embedded developer extension ID, and validates central/local
header consistency, CRC-32, output size, compression ratio, entry count, path
depth, and destination safety. Individual
high-ratio assets up to 5 MB remain bounded by the per-entry and 250 MB total
expansion limits, avoiding false rejection of sparse images and source maps.
Zip64,
multi-disk, encrypted, linked, duplicate, absolute, parent-traversing, and
unknown-method entries are rejected. Extraction is written to a temporary
directory and renamed only after every entry passes. No extracted file is
loaded as code. Invalid signatures are reported for forensic workflows; use
`--require-valid-signature` to reject them before extraction. This verifies
integrity under the embedded key, not publisher identity or Web Store status.

`mvx audit <file.crx-or-zip> --acknowledge-risk` uses that extractor in a
private temporary workspace (mode 0700 on POSIX), runs only the static
analyzer, binds the exact parsed archive SHA-256 and extraction statistics into the report,
records a deterministic SHA-256 inventory for every extracted regular file,
and removes the workspace after a returned result or thrown error. Abrupt
process termination can bypass language-level cleanup. It is the preferred
triage path when researchers do not need to retain unpacked files.

`mvx benchmark static quarantine --acknowledge-risk` performs bounded extraction
and static audit across already downloaded samples. Its review-trigger rate is
a triage metric, not classifier accuracy or proof that the scanner understood
the reported malicious behavior. It recomputes and checks the filename
SHA-256, checks a verified CRX ID against the quarantine directory, and audits
a fresh temporary extraction instead of trusting an existing extraction cache.

## Additional research sources

- Monx Research's MIT-licensed [ShotBird extension malware report](https://github.com/monxresearch-sec/shotbird-extension-malware-report/tree/33ec31d39b7d1678045768e1326dcf31f3795845)
  publishes one real MV3 sample as a ZIP. MVX verified the pinned 4,620,273-byte
  package for `gengfhhkjekmlejbhmmopegofnoifnjp` as SHA-256
  `8ff88e6c824c3803ed5fd3b0b97d674824c8cfa539a12dd87efedd6f3d898d85`.
  It is not in the default CRX acquisition index because package formats and
  third-party redistribution rights must remain explicit.
- The SIGMETRICS 2023 `MalCryptoExt` repository exposes 116 Chrome CRX files,
  and the MADWeb 2024 `malicious_v2_v3_extensions` artifact exposes 517
  researcher-validated MV2 packages plus 517 mechanically converted MV3
  derivatives. Neither repository currently has a package license. MVX does
  not download or index those executable artifacts without written permission;
  public readability is not redistribution authorization, and converted
  derivatives are not counted as independent real-world samples.
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
