# Rule reference

Rules identify review targets, not malicious intent. Severity and confidence can
be refined as the analyzer gains data-flow context, but rule IDs remain stable
within the 3.x release line.

## Manifest and declarative rules

| ID | Default severity | Detects |
|---|---|---|
| MVX001 | Critical | Missing or unsupported `manifest_version`. |
| MVX002 | High | Manifest references an absent file or unsafe parent path. |
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

## Suppression policy

Version 3.0 does not support inline suppression. Security findings should remain
visible in machine output; projects can apply their own reviewed allowlist by
rule fingerprint outside the scanned extension. A future suppression format
must include justification, owner, and expiry rather than a bare ignore comment.
