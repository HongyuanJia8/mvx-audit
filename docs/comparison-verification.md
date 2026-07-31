# Offline comparison-report verification

`mvx compare verify` replays both sides of a retained schema-v1 comparison and
recomputes its complete delta. It supports unpacked directory comparisons and
packed CRX/ZIP comparisons, including signature continuity and package-entry
changes.

## Command

```bash
mvx compare verify comparison.json /path/to/before /path/to/after \
  --acknowledge-risk \
  --expected-report-sha256 <sha256> \
  --before-package-sha256 <sha256> \
  --after-package-sha256 <sha256>

mvx compare verify packed-comparison.json before.crx after.crx \
  --acknowledge-risk --require-valid-signature \
  --before-archive-sha256 <sha256> \
  --after-archive-sha256 <sha256> \
  --expected-extension-id <32-character-a-p-id>
```

Repeat every `--rule-pack` and `--disposition-policy` used to create the
comparison. The verifier derives the shared disposition evaluation instant
from the nested audit reports. It rejects `--disposition-at`, because allowing
the verifier to select a new instant would not reproduce expiry decisions.
Both nested reports must record identical pack and policy provenance. The
verifier reads each supplied review file exactly once, freezes the prepared
data, and shares that same instance across both replays so a concurrent path
replacement cannot create a cross-side configuration the generator could not
produce.

The CLI always requires `--acknowledge-risk`. Either side may be a live packed
extension selected by an untrusted report. Library callers are responsible for
the equivalent operational acknowledgement and quarantine controls.

## Verification contract

A successful `mvx-comparison-verification-v1` result proves that the current
MVX version reproduced:

- both complete static audits, including findings, evidence, summaries,
  capabilities, scan limits, package inventory, and analysis identity;
- exact rule-pack and disposition-policy byte provenance;
- every resolved or introduced finding and every added or removed evidence
  record;
- risk, permission, and host-permission deltas;
- for packed input, both authenticity and recorded identity policies,
  `mvx-archive-continuity-v1`, and the complete `mvx-package-delta-v1`; and
- all independently supplied identities.

Both sides must have the same input type. A report cannot mix a directory audit
with a packed audit. Packed sides must record consistent signature and shared
extension-ID policies. Their disposition evaluation timestamps must also
match, because the comparison generator uses one evaluation instant.

Only the nested `target.root` and packed `artifact.path` values are normalized
to `<verified input>` during semantic equality. These are local transport
metadata. Their literal equality with the supplied paths is retained under
`checks.locationMetadataMatchesInput`. No delta, identity, finding, evidence,
policy, or interpretation field is excluded. Pin `expectedReportSha256` to
bind the exact JSON bytes, formatting, and original paths.

## Untrusted input and isolation

The comparison JSON is read through a bounded, no-follow regular-file handle.
Defaults allow 50,000,000 bytes and 1,000,000 JSON values. A pre-parse scan
rejects more than 128 nesting levels or excessive values before `JSON.parse`.
Strict UTF-8, duplicate keys, malformed schemas, symlink reports, and unsafe
embedded location text are rejected.

Parsed objects and arrays are converted into own-data, null-prototype
containers before schema or dispatch reads. Options must be plain, non-proxy
data without accessors, symbols, sparse arrays, extra array fields, or unknown
names. This keeps report and option prototypes from influencing the selected
verification path.

Each directory side is captured into its own cleanup-enforced private snapshot.
The snapshot worker anchors traversal to device/inode identities, does not
follow links, rejects special entries and replacement races, and applies the
same entry, depth, per-file, and total-byte limits as analysis. Each packed side
uses a private bounded extraction. Verification waits for both side operations
to finish or clean up before returning any failure.

## Independent trust

Deterministic replay does not authenticate who supplied a self-consistent
report or its inputs. Prefer identities obtained from an independent trusted
channel:

| CLI option | Public API option | Binds |
|---|---|---|
| `--expected-report-sha256` | `expectedReportSha256` | Exact comparison JSON bytes |
| `--before-package-sha256` | `expectedBeforePackageSha256` | Before unpacked inventory |
| `--after-package-sha256` | `expectedAfterPackageSha256` | After unpacked inventory |
| `--before-analysis-sha256` | `expectedBeforeAnalysisSha256` | Before analysis semantics |
| `--after-analysis-sha256` | `expectedAfterAnalysisSha256` | After analysis semantics |
| `--before-archive-sha256` | `expectedBeforeArchiveSha256` | Exact before CRX/ZIP bytes |
| `--after-archive-sha256` | `expectedAfterArchiveSha256` | Exact after CRX/ZIP bytes |
| `--expected-extension-id` | `expectedExtensionId` | Verified CRX ID on both sides |
| `--require-valid-signature` | `requireValidSignature` | Verified CRX signatures on both sides |

Independent archive hashes, extension ID, and signature requirements are
non-report-mutating preconditions on each exact bounded archive buffer. They
fail before ZIP entry parsing or extraction. Package and analysis identities
are checked before top-level comparison equality.

CRX signatures prove integrity under embedded developer keys. Matching keys
and extension IDs do not prove publisher identity, Web Store authorization,
safe behavior, or a complete release history. A successful verification is not
a digital signature, timestamp, transparency proof, or malware verdict.

For older packed reports that omit `identityPolicy.requireValidSignature`, a
strict `archiveContinuity.required` record implies that both sides required
valid signatures; otherwise the historical default is `false`. The verification
result keeps `checks.recordedSignatureRequirement` unknown and emits a caveat,
because the side field itself was absent.

## Public API

```js
import { verifyComparisonReport } from 'mvx-audit';

const verification = await verifyComparisonReport(
  './comparison.json',
  '/path/to/before',
  '/path/to/after',
  {
    rulePacks: ['./team-iocs.json'],
    dispositionPolicies: ['./review.json'],
    expectedReportSha256: '<lowercase-sha256>',
    expectedBeforePackageSha256: '<lowercase-sha256>',
    expectedAfterPackageSha256: '<lowercase-sha256>'
  }
);
```

Library-only resource controls are `reportLimits`, `limits`, `archiveLimits`,
`rulePackLimits`, `dispositionPolicyLimits`, and `temporaryDirectory`.
`reportLimits` supports only `maxReportBytes` and `maxReportValues`.

Malformed arguments use `INVALID_ARGUMENT`. Report read, parsing, or semantic
failures use `COMPARISON_REPORT_*` codes. Independently trusted mismatches and
unverifiable signature identities use `COMPARISON_IDENTITY_MISMATCH` and
`COMPARISON_IDENTITY_UNVERIFIABLE`.
