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
report selects the directory or packed verification path; packed verification
may defensively extract live extension content into a private temporary
workspace. Library callers make the same acknowledgement operationally.

## What is checked

The `mvx-audit-verification-v1` result is successful only when a fresh audit
matches the retained report:

- exact tool name and version, report schema, findings, summaries, capabilities,
  assumptions, scan metadata, package inventory, and analysis provenance;
- exact raw-byte provenance and normalized limits for all rule packs;
- exact raw-byte provenance, fixed evaluation time, matches, and annotations
  for all disposition policies;
- exact packed archive metadata, signature record, extraction statistics, and
  recorded archive identity policy; and
- all caller-supplied independent identities.

The report file is read as a bounded, non-symlinked regular file. The default
limit is 25,000,000 bytes. Invalid UTF-8, invalid JSON, duplicate object keys,
more than 128 JSON nesting levels, missing schema-v1 fields, and unsafe control
or bidirectional characters in location fields are rejected.

Only `target.root` and, for packed input, `artifact.path` are normalized to
`<verified input>` during semantic comparison. They are local transport
metadata, so a byte-identical package copied elsewhere remains verifiable.
`checks.locationMetadataMatchesInput` records whether those fields happened to
match. No other report field is excluded. Supply `expectedReportSha256` when
the exact original JSON bytes, including these paths and JSON formatting, must
also be pinned.

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

Independent input identities are checked before semantic report equality once
the fresh audit exists. A trusted identity mismatch therefore cannot be hidden
behind a report mismatch. An expected extension ID is never compared with an
unverified self-declaration.

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
`reportLimits.maxReportBytes` is the only report-reader limit. Options are
strict plain data: unknown fields, proxies, accessors, symbols, malformed
digests, and malformed nested limit records are rejected.
