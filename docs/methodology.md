# Methodology

## Scope

MVX Audit performs deterministic static review of an unpacked Chrome extension.
It reads `manifest.json`, supported text source files, and declarative rule JSON.
It does not execute extension code, launch a browser, resolve remote resources,
or infer author intent.

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
  levels, 2 MB per text file, and 50 MB total scanned source. Exceeding a hard
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

Runtime MV2/MV3 research is intentionally outside version 2.0. Any future
runner must satisfy all of these requirements before its results are accepted:

1. Use pinned browser artifacts with recorded versions and SHA-256 hashes.
2. Separate manifest version from browser version as independent variables.
3. Keep the browser sandbox enabled and use a fresh temporary profile.
4. Bind test servers to `127.0.0.1` on an operating-system-assigned port.
5. Block non-loopback egress and use only synthetic cookies, keystrokes, and
   unique assertion nonces.
6. Record `precondition`, `trigger`, `capability_invoked`, and `effect_observed`
   as separate evidence stages.
7. Use `succeeded`, `blocked`, `inconclusive`, `infrastructure_error`, and
   `skipped`; never count infrastructure errors as blocked attacks.
8. Produce immutable run metadata containing git SHA, scenario hash, browser,
   operating system, Node version, configuration, seed, timings, and evidence.

Until such a runner exists, this project makes no measured exploit-rate claims.
