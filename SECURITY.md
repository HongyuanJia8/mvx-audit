# Security policy

## Supported versions

Security fixes are provided for the latest 3.x release on `main`.

## Reporting a vulnerability

Please use GitHub's private security advisory feature for vulnerabilities that
could expose files outside the requested extension root, execute scanned input,
cause uncontrolled resource use, produce unsafe SARIF paths, or otherwise harm
users. Do not include real secrets, browsing data, or harmful payloads in a
public issue.

Include the affected commit/version, operating system and Node version, a
minimal synthetic reproducer, expected behavior, and impact. Maintainers should
acknowledge a report within seven days and coordinate disclosure after a fix.

## Safe operating assumptions

MVX Audit treats extension content as untrusted text and does not execute it.
Still, analyze only material you are authorized to possess. Do not load unknown
fixtures into a daily-use Chrome profile. Report parser escapes and filesystem
boundaries must be reviewed whenever a new format or archive reader is added.
The package inventory hashes bounded regular-file bytes and recognizes a small
set of executable magic signatures; recognition never imports, disassembles,
or executes those files. Inventory limits fail closed instead of silently
claiming a complete content identity.

Declarative rule packs are also untrusted input, not plugins. The loader uses
bounded no-follow regular-file reads, strict UTF-8 and schema validation,
duplicate-key rejection, normalized safe paths, literal rather than regular-
expression matching, bounded nesting and match counts, and escaped report
rendering. It never imports code or fetches pack references. A valid pack is not
trusted intelligence: operators remain responsible for its source, license,
expiry, integrity, and conclusions.

Encoded-payload analysis is static and never calls `eval`, `Function`, `atob`,
or extension code. A token-aware scanner recognizes direct, unescaped Base64
string literals in syntactic calls to bare `atob` or the `window`, `self`, and
`globalThis` member forms. It skips JavaScript comments and literal text, and
in HTML scans only executable script bodies and event-handler attributes.
This syntax does not prove the runtime binding of a bare or member call, so the
finding has medium confidence. Canonical decoded bytes are validated and only
strict UTF-8 text is rescanned. JSON data is never treated as executable.
Built-in findings supported only by decoded text are capped at medium
confidence because binding and runtime reachability were not established.
Binary payloads remain hash-only evidence. Candidate calls, payload count,
per-attempt and aggregate inspected literal characters, per-payload and aggregate decoded
bytes, minimum payload size, and recursive depth are fixed, recorded limits;
malformed and incomplete literal attempts consume the same work budgets, and
exceeding a safety bound fails closed. Decoded text is not copied into reports
or the inventory; decoded matches retain hash-only snippets.
Findings map back to the packaged source line and retain decoded-line and
content-hash provenance. Line provenance recognizes CRLF, CR, LF, U+2028, and
U+2029 terminators. This is review assistance, not a claim that encoded
content is malicious or that other obfuscation was recovered.

The optional sample fetcher writes live CRX files only after explicit risk
acknowledgement. Quarantine files are not safe merely because their hashes were
verified. Keep quarantine outside backups and shared folders, never open it
with a daily-use browser, and delete it according to your organization's
malware-handling policy.

Direct CRX/ZIP audit also requires explicit CLI risk acknowledgement. It uses
bounded parsing and an automatically removed private extraction, but the
original archive remains live malware and must stay under quarantine handling
controls. The library API is non-interactive and places that acknowledgement
responsibility on its caller.

CRX2/CRX3 verification establishes byte integrity only under the public key
embedded in the same archive and checks that a developer proof derives the
declared extension ID. It does not identify the publisher, consult a trust
store, establish Chrome Web Store authorization, or make signed content safe.
Use an independently trusted extension ID and archive digest when provenance
matters. `--require-valid-signature` rejects invalid CRX and unsigned ZIP input
before extraction; default mode retains invalid CRX content for forensic audit
and emits `MVX004`.

Use `--expected-archive-sha256` and `--expected-extension-id` when those values
come from an independent trusted channel. A requested extension ID can match
only a cryptographically verified CRX; MVX rejects invalid CRX and ZIP input as
unverifiable instead of comparing an untrusted self-declaration. Successful
reports retain the exact expectations and match state. These checks inherit the
trustworthiness and freshness of the external source that supplied the values.

Packed comparison applies the same extraction boundary independently to both
artifacts and requires CLI risk acknowledgement. Use side-specific trusted
archive digests when exact acquisition provenance matters. A
`verified-same` continuity result requires both the Chromium extension ID and
the complete developer-key SHA-256 to match; it proves neither publisher
identity nor benign evolution. ZIP or invalid-signature input is explicitly
`unverifiable`. Use `--require-same-extension-id` to fail closed rather than
accept that state. Strict continuity verifies and binds the second CRX's
extension ID and full developer key before extracting it. Temporary audits and
cleanup run sequentially, so a second-side failure cannot leave a first-side
task running after the comparison rejects. A cleanup failure is reported as
`TEMP_CLEANUP_FAILED`; treat any residual directory under the configured
temporary parent as quarantined extension content.

Treat disposition policies as privileged review inputs. Keep them outside the
extension package, review changes like code, and require exact package SHA-256,
analysis SHA-256, the exact archive SHA-256 for packed input (`null` for an
unpacked directory), owner, justification, and expiry. This prevents review
transfer across changed analyzer/rule-pack semantics or a different CRX/ZIP
wrapper with the same payload. MVX rejects ambiguous entries and never removes
the original finding or raw summary. Prefer `--fail-on` when policy provenance
is not independently trusted; `--fail-on-unreviewed` explicitly chooses to rely
on active external dispositions.

Retained static reports can be replayed with `mvx audit verify`. Verification
uses bounded, no-follow report reads, rejects ambiguous JSON and unsafe
location text, and recomputes the complete audit with the supplied rule packs
and disposition policies. It excludes only `target.root` and packed
`artifact.path` from semantic equality so identical content can move between
machines. Directory inputs are bounded into a private, cleanup-enforced
snapshot before analysis. The snapshot worker anchors each traversal level to
its current directory, validates device/inode identity across descent and
return, and opens files with `O_NOFOLLOW`; links are retained without following,
directory replacement races and special entries fail closed. Reports are
bounded by bytes and pre-parse JSON token/depth counts. Independently supplied packed hash/signature/ID
requirements apply to the exact archive buffer before ZIP entry parsing or
extraction. Use an independently obtained report, package, analysis, or archive
SHA-256 when provenance matters; self-consistent attacker-chosen inputs are not
trusted merely because they reproduce. An expected extension ID additionally
requires verified CRX authenticity, and unverified header-derived IDs never
appear as trusted verification identities. Verification is not a signature,
publisher identity, timestamp, safety verdict, or authorization to handle live
malware. The CLI always requires `--acknowledge-risk`, because an untrusted
report can select packed verification and temporary extraction.
Legacy packed schema-v1 reports that predate the recorded
`requireValidSignature` field replay the historical `false` default and return
an explicit unknown check plus caveat rather than silently claiming that the
requirement was recorded.

Retained comparison reports can be replayed with `mvx compare verify`. The
verifier applies the same bounded, strict report-reader and private snapshot or
extraction boundaries to both sides, waits for both cleanup paths before
returning a failure, and recomputes the complete comparison delta, packed
continuity, and package-entry changes with the same implementation used for
generation. Use independently obtained report and side package/analysis/archive
hashes whenever provenance matters. A shared expected extension ID or valid
signature must verify on both exact CRX buffers before extraction. Matching
developer keys establish only embedded-key continuity; successful replay is
not report authorship, acquisition trust, release-history completeness,
publisher identity, Web Store authorization, or a benign verdict.

Live browser analysis is accepted only through the documented container lab:
no public network, no host browser profile, no real user data, no writable
sample mount, and no sandbox-disabling Chromium flag. If Docker or the Chromium
sandbox cannot start under those controls, report `inconclusive`; weakening a
boundary to obtain a result is a security defect.

The lab wrapper copies the extension through an inode/device-anchored worker
and captures the scenario with one bounded no-follow read into a private
snapshot. It audits that snapshot and mounts only those stable bytes. Workspace
identity is revalidated before cleanup. A failed removal retains its managed
cleanup capability for a later retry. If workspace identity changed, the host
wrapper labels its recorded path as potentially stale instead of claiming it
locates the retained inode; investigate the private temporary parent before
removal. Published evidence should retain `scenario.json`, `events.jsonl`, and
`report.json` together. Use `mvx lab verify` with the exact extension and, when
available, independently pinned
report/package/evidence/seccomp hashes and Docker image ID. Verification
recomputes package, analysis, scenario, event-stream, evaluation, seccomp, and
tool-version identities. The extension is copied through an anchored private
snapshot worker and cleanup finishes before a result is returned; a mutable
source directory is never presented as one atomic analysis. Independent
expectations are checked against the bytes and identities actually consumed,
not against untrusted report fields. Verification detects drift and tampering;
it is not a digital signature and cannot make an attacker-chosen extension,
evidence bundle, or image ID trustworthy.
