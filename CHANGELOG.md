# Changelog

All notable changes are documented here. The project follows semantic
versioning from the 2.0 reset onward.

## Unreleased

## 3.1.0 - 2026-08-01

### Added

- Strict, bounded inventory of manifest-declared static Declarative Net Request
  JSON under `mvx-dnr-static-v1`, covering all six action types, precise
  `modifyHeaders` and `redirect` evidence, disabled rulesets, duplicate-key and
  UTF-8 rejection, malformed/unverifiable-rule findings, deterministic
  text/SARIF/comparison output, offline replay, and fail-closed work limits.
  The combined provenance contract is now `mvx-static-v5` and binds the DNR
  profile, normalized limits, raw ruleset hashes, structural totals, and
  evidence inventory. A paired request-redirect scenario expands the validated
  research corpus to 18 scenarios and 36 fixtures.
- Bounded, non-executing analysis of direct literal Base64 `atob` payloads,
  including syntax-valid ECMAScript executable-context filtering with an exact
  bundled parser and published registry-integrity shrinkwrap, recursive strict-UTF-8
  rescanning by built-in and declarative rules, content-addressed inventory and
  hash-only decoded evidence, fail-closed attempt/work limits, SARIF/text/
  comparison reporting, offline-verification replay, and the encoded-payload
  analysis identity. JavaScript lexical goals, ASI, templates, additional arguments,
  HTML script end tags, and attribute character references retain bounded,
  source-mapped handling. Complete WHATWG JavaScript MIME selection, legacy
  `language`, modern `nomodule`, classic/module/function-body grammar, parser
  stack exhaustion, exact bundled HTML5 and namespace-aware XML parsing, a content-hashed generated
  Chromium-revision HTML/body/frameset/MathML/SVG event-handler profile with independent
  golden tests, namespace-specific SVG script/handler/CDATA grammars, inert-template,
  nested-`srcdoc`, standalone-SVG, bounded internal XML entities, and corrected-root handling, and construction-time
  ECMAScript/HTML/XML token, attribute, node, document-depth, tree-depth, and tree-work
  limits fail closed and participate in analysis identity.
  Malformed HTML, raw-text elements, duplicate and merged attributes, handler
  formal parameters, and tag-scoped SVG/SMIL handlers retain
  browser-aligned executable-context handling.
- Independent identity-bound isolated-lab verification for exact report,
  package, analysis, scenario, event-stream, deterministic evaluation, seccomp,
  and container-image identities, with private inode/device-anchored extension
  snapshots shared by live execution and offline verification, cleanup
  enforcement, CLI/API controls, and explicit self-consistency caveats.
- Bounded offline verification for directory and packed comparison reports,
  with isolated replay of both complete audits, deterministic finding/evidence
  and capability deltas, packed signature continuity and package-entry delta
  recomputation, independent report and side identities, strict untrusted JSON
  parsing, and CLI/API support.
- Bounded offline verification for schema-v1 directory and packed static audit
  reports, with deterministic tool/result replay, exact rule/disposition
  provenance, optional independent report/package/analysis/archive/extension
  identities, pre-parse depth and prototype-pollution defenses, private bounded
  directory snapshots, pre-extraction packed identity gates, strict report
  parsing, path relocation semantics, and CLI/API support.
- Identity-aware packed CRX/ZIP comparison with exact before/after archive
  constraints, verified extension/developer-key continuity, deterministic
  package-entry deltas, shared rule/policy evaluation, CLI/API support, and
  private sequential extraction cleanup. Strict continuity authenticates both
  identities and binds the second extension ID and full developer key before
  extracting it; cleanup failures are explicit.
- Content-bound isolated-lab evidence with private immutable input snapshots,
  exact package/analysis/scenario/event/image/seccomp identities,
  domain-separated deterministic evaluation hashes, retained scenarios, and an
  offline `lab verify` command that fails closed on drift or tampering.
- Strict external disposition policies bound to finding fingerprint and exact
  package, analysis, and packed-artifact identities, retaining raw findings
  while adding review metadata, expiry evaluation, validation CLI, and explicit
  unreviewed CI thresholds.
- Stable fingerprints on every finding plus canonical, domain-separated SARIF
  finding and evidence partial fingerprints.
- Fail-closed external archive identity policy for expected SHA-256 and verified
  extension ID, with CLI/API controls and JSON, text, and SARIF evidence.
- Bounded CRX2 RSA/SHA-1 and CRX3 RSA/ECDSA SHA-256 signature verification,
  Chromium extension-ID derivation, integrity metadata in reports, `MVX004`
  failure findings, and `--require-valid-signature` fail-closed extraction.
- Strict local declarative JSON rule packs for literal text, path, file digest,
  and complete-package digest indicators, with `any`/`all` composition,
  bounded deterministic matching, CLI validation, report integration, and
  raw-byte provenance bound into the new `mvx-static-v3` identity.
- Path-independent full-package inventory with per-file SHA-256 values, bounded
  hashing of unparsed assets, and review findings for WebAssembly, PE/DOS, ELF,
  and Mach-O magic signatures. The `mvx-static-v3` identity binds the complete
  `mvx-package-v1` digest.
- One-command CRX/ZIP static audit with explicit CLI risk acknowledgement,
  private temporary extraction and `finally`-based cleanup, plus exact archive
  SHA-256/size/format/version provenance in JSON, text, and SARIF reports.
- Path-independent static-analysis provenance: raw manifest and per-source
  SHA-256 values, package-layout identity, effective limits, and a combined
  digest. JSON and SARIF retain the full record; text and comparison reports
  expose its combined identity.
- Reproducible OrbStack/Docker smoke fixtures for benign behavior and synthetic
  credential exfiltration.
- A vendored Moby-default seccomp profile tailored to Chromium's unprivileged
  namespace sandbox.

### Changed

- Dynamic requests are now recorded with precise extension initiators and
  returned through stdout, leaving no writable host mount in the container.
- The lab image pins its base digest and Chromium package version.

### Fixed

- Lab snapshot failures now remain in the lab error domain, and a failed
  cleanup retains its managed capability so removal can be retried after the
  workspace path is restored.
- Strict CRX verification now rejects trailing bytes after the DER public-key
  sequence and malformed oversized protobuf fields inside unknown groups.
- Static benchmark binds actual archive SHA-256/verified extension ID to
  quarantine path identities and always audits a fresh private extraction
  instead of trusting persistent cached contents. Cleanup failures remain
  visible even when analysis also fails.
- Archive input now uses a bounded, no-follow file handle; custom extraction
  limits reject unknown or non-integer values instead of silently changing the
  parser contract.
- Directory entries now receive the same local-header/data/CRC validation as
  files, and packed-audit failures redact randomized temporary paths.
- Canonical validation of provenance scan limits, compatibility of exported
  reporters with earlier schema-v1 results, symlinked-manifest rejection, and
  bounded file-handle reads for manifest and source bytes.
- Chromium startup on read-only containers, DevTools pipe shutdown handling,
  same-origin extension exfiltration detection, and native Linux output
  permissions.

## 3.0.0 - 2026-07-26

### Added

- Reproducible real-world intelligence for 4,716 unique extension IDs from
  three pinned, licensed sources, including 504 indexed CRX artifacts.
- Hash-verified single and bounded batch acquisition into Git-ignored
  quarantine, with immutable Git blob verification and actual SHA-256.
- Defensive CRX2/CRX3 extraction and real-sample static triage benchmarking.
- Remote iframe and sensitive capability-delegation rules derived from real
  sample validation.
- Container-only dynamic canary lab and deterministic four-verdict event oracle.

### Security

- Live packages are never committed, installed, or executed by ordinary tests.
- The optional runner uses a non-root browser, networkless/read-only Docker
  isolation, synthetic data, denied downloads, and no `--no-sandbox` flag.
- Provider hash/version disagreement is retained as evidence instead of being
  silently trusted.

## 2.0.0 - 2026-07-26

### Added

- Dependency-free `mvx` CLI for audit, comparison, corpus exploration, and
  validation.
- Explainable manifest and source rules with text, JSON, Markdown, and SARIF
  output.
- 17 machine-validated scenarios with 34 paired MV2/MV3 static fixtures.
- Deterministic generated research report, Node test suite, CI, and project
  governance documentation.

### Removed

- Unsafe browser runner, copied proof-of-concept extensions, committed
  `node_modules`, bundled browser assumptions, and 461 invalid historical CSV
  result files.

### Changed

- Project scope is now static capability review. Runtime claims require the
  separate acceptance contract in `docs/methodology.md`.
