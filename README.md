# MVX Audit: Chrome Manifest V2 vs V3 Security

[![CI](https://github.com/hyj28/mvx-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/hyj28/mvx-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js 20+](https://img.shields.io/badge/node-%3E%3D20-339933.svg)](package.json)

MVX Audit is a deterministic, dependency-free security research toolkit for
Chrome extensions. It combines static auditing, MV2/MV3 capability comparison,
reproducible real-world threat intelligence, hash-verified quarantine,
real-sample triage benchmarking, and an optional networkless dynamic canary lab.

The repository combines a curated corpus of **17 threat scenarios and 34
paired MV2/MV3 fixtures** with a reproducible real-world intelligence snapshot
covering **5,122 unique extension IDs** and **504 indexed non-empty CRX
artifacts**. Live packages are never bundled or fetched by normal commands.

## Why this project exists

Manifest V3 improves important platform boundaries: extension service workers
replace persistent background pages, remotely hosted code is disallowed, and
most extensions use declarative network rules instead of blocking
`webRequest`. It does **not** make every granted permission safe. Capabilities
such as cookie access, broad content scripts, debugger access, history, proxy,
and native messaging still deserve review.

Chrome 138 was the final Chrome release with limited MV2 support; Chrome 139
removed it, and the remaining MV2 Web Store entries are scheduled for removal
on 31 August 2026. See the official [MV2 support
timeline](https://developer.chrome.com/docs/extensions/develop/migrate/mv2-deprecation-timeline)
and [MV3 overview](https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3).

## Quick start

Requirements: Node.js 20 or newer. There are no runtime dependencies and no
browser download.

```bash
git clone https://github.com/hyj28/mvx-audit.git
cd mvx-audit
npm ci

# Audit an unpacked extension directory
node bin/mvx.js audit /path/to/extension

# Audit a CRX/ZIP through a cleanup-enforced temporary extraction
node bin/mvx.js audit /path/to/extension.crx --acknowledge-risk

# Fail before extraction unless a CRX2/CRX3 developer signature verifies
node bin/mvx.js audit /path/to/extension.crx --acknowledge-risk \
  --require-valid-signature

# Bind the audit to identity values obtained from an independent trusted source
node bin/mvx.js audit /path/to/extension.crx --acknowledge-risk \
  --expected-archive-sha256 <sha256> --expected-extension-id <extension-id>

# Reproduce a retained static report against exact input and trusted identities
node bin/mvx.js audit verify report.json /path/to/extension \
  --acknowledge-risk --expected-report-sha256 <sha256> \
  --expected-package-sha256 <sha256>

# Fail CI when a high- or critical-severity finding exists
node bin/mvx.js audit /path/to/extension --format sarif \
  --output results.sarif --fail-on high

# Attach complete identity-bound review metadata without deleting raw findings
node bin/mvx.js dispositions validate examples/disposition-policy.json
node bin/mvx.js audit /path/to/extension \
  --disposition-policy review.json --fail-on-unreviewed high

# Compare a migration
node bin/mvx.js compare /path/to/mv2 /path/to/mv3 \
  --format markdown --output migration-review.md

# Compare two exact signed releases with developer-key continuity
node bin/mvx.js compare packed before.crx after.crx --acknowledge-risk \
  --require-valid-signature --require-same-extension-id \
  --before-archive-sha256 <sha256> --after-archive-sha256 <sha256>

# Reproduce a retained comparison and every derived delta
node bin/mvx.js compare verify comparison.json before.crx after.crx \
  --acknowledge-risk --require-valid-signature \
  --expected-report-sha256 <sha256> \
  --before-archive-sha256 <sha256> --after-archive-sha256 <sha256>

# Validate and apply local declarative campaign indicators
node bin/mvx.js rules validate examples/campaign-rule-pack.json
node bin/mvx.js audit /path/to/extension \
  --rule-pack examples/campaign-rule-pack.json

# Explore and validate the built-in research corpus
node bin/mvx.js corpus list
npm run corpus:validate

# Query real-world threat intelligence without downloading malware
node bin/mvx.js intel stats
node bin/mvx.js intel lookup <extension-id-or-sha256>
npm run intel:validate

# Inspect a live-artifact plan; this does not download anything
node bin/mvx.js sample plan <extension-id>
node bin/mvx.js sample plan-many --label behavior-confirmed-malicious --limit 100

# Explicit opt-in download to the Git-ignored quarantine
node bin/mvx.js sample fetch <extension-id> --acknowledge-risk
node bin/mvx.js sample fetch-many --acknowledge-risk \
  --label behavior-confirmed-malicious --limit 100 --max-total-bytes 250000000

# Bounded CRX2/CRX3 extraction for static analysis
node bin/mvx.js sample unpack quarantine/<id>/<sha256>.crx --acknowledge-risk
node bin/mvx.js audit quarantine/<id>/unpacked/<sha256>

# Re-evaluate and verify a retained isolated-lab evidence bundle offline
node bin/mvx.js lab verify results/report.json /path/to/exact-extension \
  results/scenario.json results/events.jsonl \
  --expected-report-sha256 <sha256> \
  --expected-package-sha256 <sha256> \
  --expected-events-sha256 <sha256> \
  --expected-image-id sha256:<independently-pinned-image-id>

# Benchmark quarantined real samples without executing extension code
node bin/mvx.js benchmark static quarantine --acknowledge-risk \
  --label behavior-confirmed-malicious --threshold high --format json
```

Use `npm link` if you want the equivalent `mvx` command during local
development.

## What an audit includes

- Manifest version and migration compatibility checks.
- Broad host, content-script, external messaging, and web-resource exposure.
- Sensitive permission review, including capability chains such as
  `cookies` + `<all_urls>`.
- Network-control review for blocking `webRequest` and MV3
  `declarativeNetRequest` header rules.
- Source indicators for dynamic evaluation, HTML injection, wildcard
  messaging, keystroke observation, cookie enumeration, insecure transport,
  downloads, clipboard reads, and unvalidated privileged message bridges.
- Remote iframe-based extension UI and sensitive capability delegation to
  framed origins.
- Stable evidence locations, risk summary, explicit assumptions, and SARIF
  2.1.0 suitable for GitHub code scanning.
- Stable finding keys and domain-separated SARIF finding/evidence fingerprints
  for reproducible deduplication without hiding the underlying findings.
- Strict disposition policies bound to finding, package, analysis semantics, and
  packed-artifact identity, with owner, justification, expiry, byte provenance,
  raw/unreviewed summaries, and explicit CI semantics.
- Path-independent analysis provenance in JSON and SARIF, with raw manifest and
  per-source SHA-256 values, a full-package digest, the effective scan limits,
  and one combined identity also shown in text and comparison output.
- A deterministic inventory of every in-scope regular file, including byte
  length and SHA-256, plus explicit review findings for packaged WebAssembly,
  PE/DOS, ELF, and Mach-O payloads that the text rules do not parse.
- Direct CRX/ZIP audit through a private, cleanup-enforced extraction,
  binding the exact archive SHA-256, byte length, format, version, and
  extraction statistics to the static report; cleanup failures are explicit.
- Bounded CRX2 RSA/SHA-1 and CRX3 RSA/ECDSA SHA-256 verification, including
  Chromium extension-ID derivation, per-proof digest metadata, an `MVX004`
  integrity finding on failure, and an optional fail-closed mode.
- Fail-closed external archive identity policy for expected SHA-256 and verified
  extension ID, recorded in JSON, text, and SARIF as reproducible evidence.
- Identity-aware CRX/ZIP comparison with both original archive hashes and
  signature records, optional verified developer-key continuity, side-specific
  external SHA-256 constraints, and deterministic added/removed/modified
  package-entry evidence.
- Strict, bounded declarative JSON rule packs for literal text, package path,
  regular-file SHA-256, and complete-package SHA-256 indicators. Packs are
  treated as untrusted data and their exact raw-byte provenance is included in
  the analysis identity.
- Bounded scanning of all packaged source (including vendored directories) that
  refuses a symlinked root, skips nested symlinks, and fails closed on file or
  byte limits.
- Tamper-evident isolated-lab reports bound to an immutable extension snapshot,
  package/analysis identities, exact scenario and event bytes, container image
  ID, browser version, and seccomp profile, with deterministic offline
  `lab verify` support.
- Independent identity assertions for retained lab evidence, covering exact
  report, package, analysis, scenario, event-stream, evaluation, seccomp, and
  container-image identities. Offline verification re-audits a private,
  cleanup-enforced snapshot rather than a changing source directory.
- Bounded offline static-report verification that replays exact tool semantics,
  package/analysis identities, rule packs, disposition policies, packed
  authenticity policy, and optional independently trusted identities, using
  private directory snapshots and pre-extraction packed identity gates.
- Bounded offline comparison-report verification that independently snapshots
  or extracts both sides, replays both complete audits, recomputes every
  finding/evidence/capability delta plus packed continuity and package changes,
  and supports independently trusted report and side identities.

See the complete [rule reference](docs/rule-reference.md), [declarative rule
pack guide](docs/rule-packs.md), [disposition-policy guide](docs/disposition-policies.md),
[audit-verification guide](docs/audit-verification.md),
[comparison-verification guide](docs/comparison-verification.md),
[packed comparison guide](docs/packed-comparison.md), and
[methodology](docs/methodology.md).

## Synthetic corpus and real-world intelligence

The old repository mixed copied proof-of-concept extensions, real public
endpoints, different browser versions, and hundreds of duplicate CSV files.
Those artifacts could not support a scientific MV2/MV3 conclusion and created
an unacceptable safety risk. They were removed in version 2.0.

The replacement [synthetic corpus](corpus/README.md) covers 17 distinct capability and
implementation patterns with a single machine-validated registry. Every entry
has paired manifests, an explicit MV3 effect classification, expected analyzer
findings, and links to primary Chrome documentation. The generated [capability
matrix](docs/research-report.md) is reproducible from the current source.

The separate [real-world intelligence catalog](intel/README.md) de-duplicates
three pinned open sources into 5,122 extension IDs. It retains provenance,
label type, verification level, store status, threat categories, SHA-256 values,
and external artifact availability. “Reported,” “policy violation,” and
“confirmed malware” remain separate states. See the [data-source and ground
truth methodology](docs/data-sources.md).

For indexed artifacts, `sample plan` shows the immutable source revision, size,
Git blob identity, and any provider-reported SHA-256. `sample fetch` is an
explicit opt-in operation that accepts only allowlisted HTTPS hosts, enforces a
size cap, verifies the Git content hash, computes the actual SHA-256, and stores
the file under `quarantine/`. It never unpacks, imports, or executes the CRX.

`sample unpack` is a separate explicit operation. The built-in extractor
rejects path traversal, links, encryption, unsupported methods, duplicate
paths, CRC failures, excessive expansion, and archive bombs before exposing an
unpacked directory to the static auditor. It still does not make live malware
safe to execute. CRX signature verification is recorded by default; add
`--require-valid-signature` to `sample unpack`, packed `audit`, or
`benchmark static` to reject unsigned, invalid, or ZIP input before extraction.

A verified CRX signature establishes that the archive bytes are consistent
with the embedded developer key and declared Chromium extension ID. It does
not authenticate a human or organization, prove Chrome Web Store publication
or authorization, or imply that the extension is benign. Ordinary ZIP files
have no CRX signature and are reported as `not-applicable`.

For static triage without retaining an unpacked copy, use
`audit <file.crx-or-zip> --acknowledge-risk`. It uses the same bounded
extractor inside a private temporary directory, records the SHA-256 of the
exact bytes parsed, runs the ordinary static analyzer, and removes the
extraction after a returned result or thrown error. Abrupt process termination
can bypass that cleanup. Use the persistent `sample unpack` workflow when a
later lab run needs the files.

`sample plan-many` and `sample fetch-many` add deterministic prioritization,
count limits, per-artifact limits, a total byte budget, and isolated failure
reporting. `benchmark static` safely unpacks quarantined CRXs, audits them, and
reports a **review-trigger rate**. It deliberately does not call that number
malware-classification accuracy because extension-ID labels can span versions.

## Result semantics

The risk score is a bounded review-priority score, not a probability or an
exploitability measurement. A finding means “review this capability or pattern,”
not “this extension is malicious.” Conversely, no static analyzer can prove an
extension safe.

The optional [dynamic canary lab](docs/dynamic-analysis.md) runs only inside a
read-only, non-root Docker container with `--network none`. It serves a virtual
HTTPS canary page through Chrome DevTools Protocol, blocks and records external
requests, denies downloads, and classifies exact canary leakage or protected
state changes as `confirmed_attack`. Ordinary CI tests the event oracle but
never executes a live extension. `no_trigger_observed` is not a benign verdict.

## Development

```bash
npm test                 # unit and integration tests
npm run test:coverage   # built-in Node coverage
npm run lint            # syntax and repository hygiene checks
npm run docs:generate   # regenerate the corpus report
npm run intel:validate  # validate real-world intelligence offline
npm run intel:check     # reproduce it from pinned upstream sources
npm run lab:build       # build the optional isolated Chromium image
npm run lab:smoke -- --acknowledge-risk  # real Docker/Chromium smoke test
npm run check           # all required checks
npm audit --omit=dev    # expected: zero dependencies, zero advisories
```

Public API:

```js
import {
  auditExtension, auditExtensionArchive, compareExtensionArchives, compareExtensions,
  evaluateLabFiles, loadDispositionPolicies, loadRulePacks, verifyAuditReport,
  verifyComparisonReport, verifyLabReport
} from 'mvx-audit';

const rulePacks = ['./team-iocs.json'];
await loadRulePacks(rulePacks); // standalone validation and provenance
const dispositionPolicies = ['./review.json'];
await loadDispositionPolicies(dispositionPolicies, {
  evaluationTime: '2026-07-30T12:00:00.000Z'
});
const audit = await auditExtension('/path/to/unpacked-extension', {
  rulePacks, dispositionPolicies
});
const packedAudit = await auditExtensionArchive('/path/to/extension.crx', {
  rulePacks,
  expectedArchiveSha256: '<lowercase-sha256>',
  expectedExtensionId: '<32-character-a-p-extension-id>'
});
const comparison = await compareExtensions('/path/to/mv2', '/path/to/mv3', { rulePacks });
const packedComparison = await compareExtensionArchives('before.crx', 'after.crx', {
  rulePacks,
  requireSameExtensionId: true,
  expectedBeforeArchiveSha256: '<lowercase-sha256>',
  expectedAfterArchiveSha256: '<lowercase-sha256>'
});
const auditVerification = await verifyAuditReport(
  './report.json', '/path/to/exact-extension',
  {
    rulePacks,
    dispositionPolicies,
    expectedReportSha256: '<lowercase-sha256>',
    expectedPackageSha256: '<lowercase-sha256>'
  }
);
const comparisonVerification = await verifyComparisonReport(
  './comparison.json', '/path/to/before', '/path/to/after',
  {
    expectedReportSha256: '<lowercase-sha256>',
    expectedBeforePackageSha256: '<lowercase-sha256>',
    expectedAfterPackageSha256: '<lowercase-sha256>'
  }
);
const labReport = await evaluateLabFiles('./scenario.json', './events.jsonl');
const labVerification = await verifyLabReport(
  './report.json', '/path/to/exact-extension', './scenario.json', './events.jsonl',
  {
    expectedReportSha256: '<lowercase-sha256>',
    expectedPackageSha256: '<lowercase-sha256>',
    expectedEventsSha256: '<lowercase-sha256>',
    expectedImageId: 'sha256:<independently-pinned-image-id>'
  }
);
```

Every successful audit includes `package.sha256` and `analysis.sha256`.
Matching package values mean the same `mvx-package-v1` profile inventoried the
same extension-relative entries and regular-file bytes, even when directories
differ. The analysis identity additionally binds the text-analysis profile,
effective limits, and exact declarative rule-pack provenance. Neither value is
a signature or a digest of the original CRX/ZIP container; retain
`artifact.sha256` or the quarantine SHA-256 for exact packed-artifact identity.
Packed results also include `artifact.authenticity`; this cryptographic status
has the narrower trust meaning described above. When supplied,
`artifact.identityPolicy` records the external expectations and confirms that
they matched before extraction.

## Security and responsible use

Only analyze extensions you are authorized to inspect. Treat unknown extension
packages as untrusted input and do not load them into your everyday browser.
MVX Audit does not execute extension files. Please read [SECURITY.md](SECURITY.md)
before reporting a sensitive issue and [CONTRIBUTING.md](CONTRIBUTING.md) before
adding a scenario.

Licensed under the [MIT License](LICENSE).
