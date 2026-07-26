# MVX Audit: Chrome Manifest V2 vs V3 Security

[![CI](https://github.com/HongyuanJia8/chrome-manifest-security-mv2-vs-mv3-bypass/actions/workflows/ci.yml/badge.svg)](https://github.com/HongyuanJia8/chrome-manifest-security-mv2-vs-mv3-bypass/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js 20+](https://img.shields.io/badge/node-%3E%3D20-339933.svg)](package.json)

MVX Audit is a deterministic, dependency-free static security auditor for
unpacked Chrome extensions. It explains risky capabilities, detects selected
source patterns, compares an MV2 extension with its MV3 migration, and produces
human-readable, JSON, or SARIF output for CI.

The repository combines a curated corpus of **17 threat scenarios and 34
paired MV2/MV3 fixtures** with a reproducible real-world intelligence snapshot
covering **4,716 unique extension IDs** and **504 indexed non-empty CRX
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
git clone https://github.com/HongyuanJia8/chrome-manifest-security-mv2-vs-mv3-bypass.git
cd chrome-manifest-security-mv2-vs-mv3-bypass
npm ci

# Audit an unpacked extension directory
node bin/mvx.js audit /path/to/extension

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

# Explicit opt-in download to the Git-ignored quarantine
node bin/mvx.js sample fetch <extension-id> --acknowledge-risk

# Bounded CRX2/CRX3 extraction for static analysis
node bin/mvx.js sample unpack quarantine/<id>/<sha256>.crx --acknowledge-risk
node bin/mvx.js audit quarantine/<id>/unpacked/<sha256>
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
- Stable evidence locations, risk summary, explicit assumptions, and SARIF
  2.1.0 suitable for GitHub code scanning.
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
three pinned open sources into 4,716 extension IDs. It retains provenance,
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

## Result semantics

The risk score is a bounded review-priority score, not a probability or an
exploitability measurement. A finding means “review this capability or pattern,”
not “this extension is malicious.” Conversely, no static analyzer can prove an
extension safe.

MVX Audit intentionally does not claim runtime attack success rates. A future
runtime experiment would require pinned browser builds, loopback-only origins,
synthetic data, isolated profiles, sandboxing, staged evidence, and a result
taxonomy that separates `blocked` from `infrastructure_error`. See
[methodology](docs/methodology.md#runtime-experiments) for that contract.

## Development

```bash
npm test                 # unit and integration tests
npm run test:coverage   # built-in Node coverage
npm run lint            # syntax and repository hygiene checks
npm run docs:generate   # regenerate the corpus report
npm run intel:validate  # validate real-world intelligence offline
npm run intel:check     # reproduce it from pinned upstream sources
npm run check           # all required checks
npm audit --omit=dev    # expected: zero dependencies, zero advisories
```

Public API:

```js
import { auditExtension, compareExtensions } from 'mvx-audit';

const audit = await auditExtension('/path/to/unpacked-extension');
const comparison = await compareExtensions('/path/to/mv2', '/path/to/mv3');
```

## Security and responsible use

Only analyze extensions you are authorized to inspect. Treat unknown extension
packages as untrusted input and do not load them into your everyday browser.
MVX Audit does not execute extension files. Please read [SECURITY.md](SECURITY.md)
before reporting a sensitive issue and [CONTRIBUTING.md](CONTRIBUTING.md) before
adding a scenario.

Licensed under the [MIT License](LICENSE).
