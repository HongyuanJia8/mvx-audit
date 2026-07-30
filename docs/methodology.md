# Methodology

## Scope

MVX Audit primarily performs deterministic static review of an unpacked Chrome extension.
It reads `manifest.json`, supported text source files, and declarative rule JSON.
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

## Analysis provenance

Every successful static audit records a path-independent `analysis` object.
The `mvx-static-v1` profile includes:

- the byte length and SHA-256 of the raw `manifest.json` bytes;
- the relative path, byte length, and raw-byte SHA-256 of every scanned source;
- a SHA-256 over the sorted relative package layout and entry types;
- the effective file, entry, depth, and byte limits; and
- a combined SHA-256 over that canonical identity record.

The root directory is deliberately excluded, so copying identical input to a
different location preserves the combined digest. Source hashes are computed
before UTF-8 decoding. The profile name versions the digest contract, and any
future semantic change requires a new profile name.

`analysis.sha256` identifies the inputs that can affect this static analysis;
it is not an archive signature or a byte-for-byte digest of unparsed binary
assets. For an acquired CRX, retain the hash-verified quarantine metadata as
the authoritative packed-artifact identity. Matching analysis hashes also do
not imply that two extensions are benign or equivalent at runtime.

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

- The root must be a real directory or a real `manifest.json`, not a symlink.
- Nested symlinks are skipped and reported.
- `.git` metadata is not traversed. Packaged dependency, vendor, and `dist`
  directories are scanned because Chrome can execute code from them.
- Defaults: 5,000 visited files, 10,000 filesystem entries, 64 directory
  levels, 10 MB per text file, and 50 MB total scanned source. Exceeding a hard
  limit fails the audit instead of silently truncating the extension.
- Binary files are not parsed. Supported text extensions are JS-family files,
  HTML, and JSON.

## Known limitations

- Pattern matching is intentionally explainable and can produce false positives
  or miss obfuscated, bundled, aliased, or dynamically constructed behavior.
- Permissions may be justified by product requirements that static input does
  not contain.
- Data-flow, control-flow, package provenance, signature verification, and
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
