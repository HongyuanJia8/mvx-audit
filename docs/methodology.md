# Methodology

## Scope

MVX Audit primarily performs deterministic static review of Chrome extensions.
It reads `manifest.json`, supported text source files, and declarative rule JSON
from an unpacked directory or a defensively extracted CRX/ZIP package.
Normal audit, corpus, intelligence, acquisition, extraction, and static
benchmark commands do not execute extension code, launch a browser, resolve
sample-discovered resources, or infer author intent. The separately gated
container lab is the only live-execution path.

The analyzer answers two practical questions:

1. What sensitive capabilities does the extension request?
2. Which selected implementation patterns warrant manual security review?

## Evidence model

Each finding contains a stable rule ID, severity, confidence, category,
description, remediation, primary references, and one or more file locations.
Manifest evidence includes a JSON field; source evidence includes a one-based
line number and a bounded snippet.

Findings are sorted by severity, rule ID, file, and line. Corpus traversal is
also sorted, making JSON, text, SARIF, and generated documentation reproducible
for identical inputs.

## Package inventory and analysis provenance

Every successful static audit records path-independent `package` and `analysis`
objects. The `mvx-package-v1` inventory includes:

- every traversed directory and every in-scope regular file;
- the relative path, byte length, and raw-byte SHA-256 of each regular file;
- a hash of the exact symlink target bytes without disclosing the target string;
- an explicit marker for skipped special filesystem entries;
- file and byte totals; and
- a combined SHA-256 over the canonical, sorted entry list.

The package digest therefore changes when an image, font, WebAssembly module,
source map, or other unparsed regular file changes. It deliberately describes
the unpacked tree rather than ZIP metadata, compression, or a CRX signature.
Use `artifact.sha256` for the exact packed bytes.

The `mvx-static-v2` analysis profile includes:

- the byte length and SHA-256 of the raw `manifest.json` bytes;
- the relative path, byte length, and raw-byte SHA-256 of every scanned source;
- a SHA-256 over the sorted relative package layout and entry types;
- the `mvx-package-v1` combined SHA-256;
- the effective file, entry, depth, and byte limits; and
- a combined SHA-256 over that canonical identity record.

The root directory is deliberately excluded, so copying identical input to a
different location preserves the combined digest. Source hashes are computed
before UTF-8 decoding. The profile name versions the digest contract, and any
future semantic change requires a new profile name.

Files are captured sequentially, so this is not an atomic filesystem snapshot
of a directory being modified concurrently. Use a fresh, immutable quarantine
extraction when the input may be adversarial or changing during analysis.

Packed audit hashes the exact bounded archive buffer used by the extractor and
records its byte length, format, CRX version, and extraction statistics. The
unpacked tree is created under a private temporary workspace (mode 0700 on
POSIX) and removed in a `finally` path after successful analysis or any error.
The CLI requires `--acknowledge-risk`; the library API remains non-interactive. No extension
code is imported or executed. Abrupt process or machine termination can bypass
language-level cleanup and leave a workspace under the operating system's
temporary directory; handle that directory according to quarantine policy.

`analysis.sha256` identifies the package content and configuration used by this
static analysis. It is not an archive or publisher signature. For an acquired
CRX, retain the hash-verified quarantine metadata as the authoritative packed-
artifact identity. Matching package or analysis hashes also do not imply that
two extensions are benign or equivalent at runtime.

## Severity and score

| Severity | Weight | Intended response |
|---|---:|---|
| Critical | 25 | Review before distributing or enabling the extension. |
| High | 12 | Require a documented need and a concrete mitigation. |
| Medium | 6 | Review scope, user gesture, and input validation. |
| Low | 2 | Improve defense in depth or migration hygiene. |
| Info | 0 | Context only. |

Weights are summed and capped at 100. Rating bands are `low` (1–19), `medium`
(20–39), `high` (40–69), and `critical` (70–100). Zero findings receives
`clean`, which means only that no supported pattern was found.

This is a triage score. It is not CVSS, attack probability, runtime success
rate, Chrome Web Store policy status, or proof of malicious behavior.

## Comparison semantics

`mvx compare` runs the same audit on both inputs and reports:

- introduced and resolved rule fingerprints;
- added and removed evidence locations, plus occurrence-count delta;
- permission and host additions/removals;
- before/after scores; and
- an explicit reminder that migration syntax is not the same as capability
  removal.

For example, replacing blocking `webRequest` with a declarative header rule
resolves one implementation finding and introduces another. Cookie access with
broad host permissions remains sensitive in both versions.

## Corpus taxonomy

Each catalog scenario declares one of five MV3 effects:

- `blocked`: MV3 rejects the represented implementation mechanism.
- `constrained`: MV3 narrows the capability but does not eliminate all risk.
- `changed`: MV3 replaces the mechanism with a different API or lifecycle.
- `unchanged`: the capability remains when permission is granted.
- `policy-dependent`: availability depends on installation or enterprise policy.

The classification is based on linked primary Chrome documentation. Fixture
risk scores demonstrate analyzer coverage, not empirical browser behavior.

## Input safety and limits

- The root and `manifest.json` must be real directory/file entries, not
  symlinks. Nested symlinks are skipped and reported.
- Manifest, source, and package inventory reads use bounded chunks through a regular-file handle;
  supported platforms also request no-follow opens to close file-symlink races.
- No directory name is globally ignored: `.git`, dependency, vendor, and
  `dist` subtrees are inventoried and their supported source files are scanned.
  Audit a built package when development metadata would exceed the hard limits.
- Defaults: 5,000 visited files, 10,000 filesystem entries, 64 directory
  levels, 10 MB per text file, 50 MB total scanned source, 100 MB per inventoried
  regular file, and 250 MB total inventoried regular-file content. Exceeding a
  hard limit fails the audit instead of silently truncating the extension.
- Custom limits accept only those seven names with positive safe-integer values.
  They are normalized into a fixed order before provenance hashing.
- Binary files are hashed but not parsed. Magic bytes identify WebAssembly,
  PE/DOS, ELF, and Mach-O payloads for manual review; a filename extension alone
  never creates that finding. Supported text extensions are JS-family files,
  HTML, and JSON.
- CRX/ZIP input defaults to a 100 MB archive, 10,000 entries, 50 MB per entry,
  250 MB total expansion, ratio 200 after 5 MB, and 64 path segments. Archive
  limits accept only the documented positive safe-integer fields.

## Known limitations

- Pattern matching is intentionally explainable and can produce false positives
  or miss obfuscated, bundled, aliased, or dynamically constructed behavior.
- Permissions may be justified by product requirements that static input does
  not contain.
- Data-flow, control-flow, publisher signature verification, and
  Chrome Web Store policy checks are outside the current scope.
- Declarative rules are recognized by selected structural strings, not a full
  Chrome ruleset schema implementation.
- Firefox and Safari extension semantics are not evaluated.

## Runtime experiments

Version 3.0 includes an experimental container-only canary runner. Accepted
runtime evidence must satisfy all of these requirements:

1. Use pinned browser artifacts with recorded versions and SHA-256 hashes.
2. Separate manifest version from browser version as independent variables.
3. Keep the browser sandbox enabled and use a fresh temporary profile.
4. Provide the test origin virtually through CDP without opening a host port.
5. Block all container egress and use only synthetic cookies, keystrokes, and
   unique assertion nonces.
6. Record `precondition`, `trigger`, `capability_invoked`, and `effect_observed`
   as separate evidence stages.
7. Use `confirmed_attack`, `suspicious_activity`, `no_trigger_observed`, and
   `inconclusive`; never count collection errors as blocked attacks.
8. Produce immutable run metadata containing git SHA, scenario hash, browser,
   operating system, Node version, configuration, seed, timings, and evidence.

The checked-in runner enforces networkless Docker isolation, a non-root browser,
read-only sample and scenario mounts, an ephemeral profile, resource limits,
and Chromium's user-namespace plus seccomp-BPF sandbox without `--no-sandbox`.
The setuid sandbox helper is not used because all container capabilities are
dropped. The evaluator is deterministic and can also process externally
captured JSONL. See [dynamic analysis](dynamic-analysis.md).

This remains an experimental behavioral observation tool, not an exploit-rate
benchmark. Dormant C2, environment gating, timing, region checks, and
anti-analysis behavior can all produce `no_trigger_observed`.
