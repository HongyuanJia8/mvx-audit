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

# Audit a CRX/ZIP through an automatically removed temporary extraction
node bin/mvx.js audit /path/to/extension.crx --acknowledge-risk

# Fail CI when a high- or critical-severity finding exists
node bin/mvx.js audit /path/to/extension --format sarif \
  --output results.sarif --fail-on high

# Compare a migration
node bin/mvx.js compare /path/to/mv2 /path/to/mv3 \
  --format markdown --output migration-review.md

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
- Path-independent analysis provenance in JSON and SARIF, with raw manifest and
  per-source SHA-256 values, a package-layout digest, the effective scan limits,
  and one combined identity also shown in text and comparison output.
- Direct CRX/ZIP audit through a private, automatically removed extraction,
  binding the exact archive SHA-256, byte length, format, version, and
  extraction statistics to the static report.
- Bounded scanning of all packaged source (including vendored directories) that
  refuses a symlinked root, skips nested symlinks, and fails closed on file or
  byte limits.

See the complete [rule reference](docs/rule-reference.md) and
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
safe to execute.

For static triage without retaining an unpacked copy, use
`audit <file.crx-or-zip> --acknowledge-risk`. It uses the same bounded
extractor inside a private temporary directory, records the SHA-256 of the
exact bytes parsed, runs the ordinary static analyzer, and removes the
extraction on both success and failure. Use the persistent `sample unpack`
workflow when a later lab run needs the files.

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
import { auditExtension, auditExtensionArchive, compareExtensions } from 'mvx-audit';

const audit = await auditExtension('/path/to/unpacked-extension');
const packedAudit = await auditExtensionArchive('/path/to/extension.crx');
const comparison = await compareExtensions('/path/to/mv2', '/path/to/mv3');
```

Every successful audit includes `analysis.sha256`. Matching values mean the
same static-analysis profile saw the same manifest bytes, scanned source bytes,
package layout, and limits, even when the extension directories differ. This
is an analysis identity, not a hash of every binary asset or of the original
CRX/ZIP container; retain the quarantine SHA-256 when exact artifact identity
is required.

## Security and responsible use

Only analyze extensions you are authorized to inspect. Treat unknown extension
packages as untrusted input and do not load them into your everyday browser.
MVX Audit does not execute extension files. Please read [SECURITY.md](SECURITY.md)
before reporting a sensitive issue and [CONTRIBUTING.md](CONTRIBUTING.md) before
adding a scenario.

Licensed under the [MIT License](LICENSE).
