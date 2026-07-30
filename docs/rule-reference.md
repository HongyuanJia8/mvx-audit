# Rule reference

Rules identify review targets, not malicious intent. Severity and confidence can
be refined as the analyzer gains data-flow context, but rule IDs remain stable
within the 3.x release line.

## Manifest and declarative rules

| ID | Default severity | Detects |
|---|---|---|
| MVX001 | Critical | Missing or unsupported `manifest_version`. |
| MVX002 | High | Manifest references an absent file or unsafe parent path. |
| MVX003 | Medium | Packaged WebAssembly, PE/DOS, ELF, or Mach-O executable-format bytes not parsed by MVX. |
| MVX004 | High | A packed CRX has no valid developer-key signature proof for its declared extension ID. |
| MVX101 | High | Global host patterns such as `<all_urls>`. |
| MVX102 | Varies | Sensitive API permissions; one fingerprint per permission. |
| MVX103 | Critical | `cookies` combined with global host access. |
| MVX104 | High | Broadly matched content scripts. |
| MVX105 | Medium | Content scripts configured for every matching frame. |
| MVX106 | High | MV3 content scripts running in the page `MAIN` world. |
| MVX107 | Critical | Extension CSP with unsafe evaluation, inline, wildcard, or remote code sources. |
| MVX108 | High | Broad `externally_connectable` senders. |
| MVX109 | Medium | Wildcard web-accessible resources or global matches. |
| MVX110 | High/Critical | Blocking `webRequest`, including incompatible MV3 declarations. |
| MVX111 | Medium | Non-HTTPS host permissions. |
| MVX112 | High | MV2 `background.scripts` used in an MV3 manifest. |
| MVX113 | High | Declarative Net Request `modifyHeaders` rules. |

## Source rules

| ID | Severity | Confidence | Detects |
|---|---|---|---|
| MVX201 | Critical | High | `eval()` or `new Function()`. |
| MVX202 | Critical | High | Direct remote URL assignment to a resource `.src`. |
| MVX203 | High | Medium | HTML-interpreting DOM sinks. |
| MVX204 | High | High | `postMessage` with wildcard target origin. |
| MVX205 | High | High | Keyboard event observation. |
| MVX206 | High | High | Cookie-store enumeration. |
| MVX207 | High | High | Source fetch to a public unencrypted HTTP endpoint. |
| MVX208 | Medium | High | Programmatic download creation. |
| MVX209 | High | High | Clipboard read operations. |
| MVX210 | Critical | Medium | Privileged Chrome API use in a message handler without an apparent sender check in the same file. |
| MVX211 | High | Medium | A remote origin embedded as extension UI in an iframe. |
| MVX212 | High | High | Sensitive clipboard, camera, microphone, or geolocation delegation to an iframe. |

## Analyst-supplied declarative rules

Validated rule-pack findings use `RP:<namespace>:<rule-id>` as both the rule ID
and stable fingerprint. Their severity, confidence, category, explanation,
remediation, and HTTPS references come from the exact pack bytes recorded in
the report. Supported indicators are literal text, normalized regular-file
paths, regular-file SHA-256, and the complete `mvx-package-v1` SHA-256. See the
[rule-pack guide](rule-packs.md) for schema, limits, and interpretation.

These findings are local review indicators. MVX does not promote them to
malware verdicts, authenticate their publisher, or imply that the matched
package executed the represented behavior.

## Stable fingerprints

Every JSON finding includes a non-empty `fingerprint`. Rules with one semantic
finding use their stable rule ID; rules that can produce independently reviewed
variants add a deterministic scope, such as `MVX102:cookies`. SARIF results add
domain-separated SHA-256 `partialFingerprints` under `mvxFinding/v1` and
`mvxEvidence/v1`. The first hashes the finding fingerprint; the second hashes
that fingerprint together with the complete canonical evidence object. Their
exported domain profiles are `mvx-finding-v1` and `mvx-evidence-v1`. Object key
order and checkout location do not affect either value, while an evidence field
change does affect the evidence fingerprint. The exact input domain, resource
limits, canonical encoding, and fixed digest vectors are specified in the
[methodology](methodology.md#finding-and-evidence-fingerprints).

Finding fingerprints identify a review category, not package contents. A
disposition policy binds the fingerprint to the exact `mvx-package-v1` and
analysis SHA-256 values, plus `artifactSha256: null` for directory input or the
exact archive SHA-256 for packed input. It is never a global allowlist.

## Disposition policy

Version 3.0 supports external complete-identity-bound disposition policies.
They annotate rather than delete findings, retain the raw summary, and require
fingerprint, exact package/analysis/artifact identity, justification, owner,
and expiry. See the
[disposition-policy guide](disposition-policies.md). Inline suppression and bare
ignore comments remain unsupported.
