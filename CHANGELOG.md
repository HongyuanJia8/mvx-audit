# Changelog

All notable changes are documented here. The project follows semantic
versioning from the 2.0 reset onward.

## Unreleased

### Added

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
