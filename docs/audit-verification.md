# Offline static-audit verification

`mvx audit verify` re-runs the deterministic static analyzer and compares the
result with a retained schema-v1 JSON audit report. It supports unpacked
directories and CRX/ZIP artifacts, including rule-pack and disposition-policy
provenance.

## Command

```bash
mvx audit verify report.json /path/to/extension --acknowledge-risk \
  --expected-report-sha256 <sha256> \
  --expected-package-sha256 <sha256> \
  --expected-analysis-sha256 <sha256> \
  --format json

mvx audit verify packed-report.json /path/to/extension.crx \
  --acknowledge-risk --require-valid-signature \
  --expected-archive-sha256 <sha256> \
  --expected-extension-id <32-character-a-p-id>
```

Repeat every `--rule-pack` and `--disposition-policy` used by the original
audit. The verifier loads the current files, checks their raw-byte provenance
through the recomputed report, and derives the disposition evaluation instant
from `report.dispositionEvaluation.evaluatedAt`. Missing, changed, or additional
review data makes verification fail.

The CLI requires `--acknowledge-risk` for every verification. An untrusted
report selects the directory or packed verification path. Directory input is
copied through the analyzer's file, entry, depth, per-file, and total-byte
limits into a private snapshot before analysis. A dedicated snapshot process
anchors traversal to its current directory, validates device/inode identity
whenever it enters or returns from a directory, and opens regular files with
`O_NOFOLLOW`. Concurrent path replacement therefore cannot redirect traversal:
links are copied as links, directory races fail closed, and special filesystem
entries are rejected. Packed verification
may defensively extract live extension content into a separate private
temporary workspace. Both workspaces are cleanup-enforced. Library callers
make the same acknowledgement operationally.
The literal `audit verify` token is reserved for this subcommand. Use
`mvx audit ./verify` to audit an extension directory named `verify`.

## What is checked

The `mvx-audit-verification-v1` result is successful only when a fresh audit
matches the retained report:

- exact tool name and version, report schema, findings, summaries, capabilities,
  assumptions, scan metadata, package inventory, and analysis provenance;
- exact `mvx-encoded-payloads-v1` limits, parser work counters, candidates,
  content-addressed
  inventory, and built-in/declarative findings recovered from strict UTF-8
  payloads;
- exact raw-byte provenance and normalized limits for all rule packs;
- exact raw-byte provenance, fixed evaluation time, matches, and annotations
  for all disposition policies;
- exact packed archive metadata, signature record, extraction statistics, and
  recorded archive identity policy, including whether a valid signature was
  required; and
- all caller-supplied independent identities.

The report file is read as a bounded, non-symlinked regular file. Defaults are
25,000,000 bytes and 500,000 JSON value tokens (including object keys and
containers). A string-level token/depth scan runs before `JSON.parse`, so a
deep or very wide report cannot first consume an unbounded parser stack or
heap. Invalid UTF-8, invalid JSON, duplicate object keys, more than 128 JSON
nesting levels, missing schema-v1 fields, and unsafe control or bidirectional
characters in location fields are rejected. Parsed records and arrays are
converted to own-data, null-prototype containers before any schema or dispatch
read, preventing ambient prototype pollution from selecting a verification
path or executing an inherited getter.

Only `target.root` and, for packed input, `artifact.path` are normalized to
`<verified input>` during semantic comparison. They are local transport
metadata, so a byte-identical package copied elsewhere remains verifiable.
`checks.locationMetadataMatchesInput` records whether those fields happened to
match. No other report field is excluded. Supply `expectedReportSha256` when
the exact original JSON bytes, including these paths and JSON formatting, must
also be pinned.

Packed schema-v1 reports produced before `requireValidSignature` was added to
the identity-policy record remain verifiable. The missing field is normalized
to its historical default (`false`), while
`checks.recordedSignatureRequirement` is `null` and the result carries an
explicit caveat. A present field is always compared exactly.

## Independent trust

Reproduction answers “does this report match these inputs and this MVX
version?” It does not answer “who chose these inputs?” An attacker can produce
a self-consistent report for attacker-chosen content.

Use identities obtained through an independent trusted channel:

| Option | Binds |
|---|---|
| `expectedReportSha256` | Exact report bytes |
| `expectedPackageSha256` | Complete unpacked `mvx-package-v1` inventory |
| `expectedAnalysisSha256` | Static profile, package, limits, and rule packs |
| `expectedArchiveSha256` | Exact CRX/ZIP bytes |
| `expectedExtensionId` | ID derived from a verified CRX developer key |
| `requireValidSignature` | A cryptographically verified CRX signature |

Independent archive SHA-256, extension ID, and signature requirements are
non-report-mutating preconditions on the exact bounded archive buffer. They
fail before ZIP entry parsing, extraction, or static analysis. Package and
analysis identities are checked as soon as the private snapshot or packed
audit exists and before semantic report equality. A trusted identity mismatch
therefore cannot be hidden behind a report mismatch. An expected extension ID
is never compared with an unverified self-declaration. Verification results
expose an extension ID and developer-key digest only when authenticity status
is `verified`; invalid CRX header declarations are not trusted identities.

CRX verification proves archive integrity under the embedded developer key. It
does not authenticate a publisher, establish Chrome Web Store authorization,
or imply benign behavior. Audit verification is deterministic replay, not a
digital signature, transparency log, timestamp, or malware verdict.

## Public API

```js
import { verifyAuditReport } from 'mvx-audit';

const verification = await verifyAuditReport(
  './report.json',
  '/path/to/exact-extension',
  {
    rulePacks: ['./team-iocs.json'],
    dispositionPolicies: ['./review.json'],
    expectedReportSha256: '<lowercase-sha256>',
    expectedPackageSha256: '<lowercase-sha256>'
  }
);
```

Optional resource controls are `reportLimits`, `limits`, `rulePackLimits`,
`dispositionPolicyLimits`, `archiveLimits`, and `temporaryDirectory`.
Report-reader controls are `reportLimits.maxReportBytes` and
`reportLimits.maxReportValues`. Options are strict plain data: unknown fields,
proxies, accessors, symbols, malformed digests, and malformed nested limit
records are rejected. A custom `temporaryDirectory` must be outside the
directory extension being verified so the private snapshot cannot contain
itself.
