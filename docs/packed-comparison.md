# Packed extension comparison

`mvx compare packed` compares two CRX/ZIP artifacts without trusting a
persistent extraction. Each side goes through the ordinary bounded packed
audit in its own private temporary workspace; the first workspace is removed
before the second audit begins, and every success or failure path removes its
workspace before returning.

```bash
mvx compare packed before.crx after.crx --acknowledge-risk \
  --require-valid-signature \
  --require-same-extension-id \
  --expected-extension-id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --before-archive-sha256 <trusted-before-sha256> \
  --after-archive-sha256 <trusted-after-sha256> \
  --format markdown --output version-diff.md
```

The CLI acknowledgement is mandatory because both artifacts are live extension
packages and are defensively extracted. The library API is non-interactive;
callers are responsible for applying the same authorization and malware-
handling controls.

## Evidence retained

The result embeds the complete packed audit for both sides, including:

- exact archive byte length and SHA-256;
- CRX version, bounded signature proofs, verified extension ID, and complete
  developer-key SHA-256 when available;
- external archive and extension-ID expectations and their match state;
- full extracted-package inventory and package SHA-256;
- static-analysis SHA-256, findings, rule-pack provenance, and disposition
  evaluation;
- manifest version, extension version, permissions, host permissions, and risk
  summaries.

Rule packs and disposition policies are loaded once before either extraction.
Both audits therefore use the same prepared rules and the same canonical
disposition evaluation time. Packed disposition entries remain bound to the
corresponding side's exact archive SHA-256.

## Archive continuity states

`archiveContinuity.profile` is `mvx-archive-continuity-v1`.

| Status | Meaning |
|---|---|
| `verified-same` | Both CRXs verify and have the same Chromium extension ID and full developer-key SHA-256. |
| `verified-different` | Both CRXs verify, but their extension ID or full developer key differs. |
| `unverifiable` | At least one side is ZIP or has no valid CRX developer proof. |

By default all three states are reportable for forensic comparison.
`--require-same-extension-id` fails with
`ARCHIVE_IDENTITY_UNVERIFIABLE` or `ARCHIVE_IDENTITY_MISMATCH` unless continuity
is `verified-same`. `--require-valid-signature` independently requires each
side to be a valid CRX. An externally trusted `--expected-extension-id` is
stronger still: it must verify against both artifacts before either contained
package is accepted.

Matching embedded keys establish package lineage under that key, not the
identity of a person or organization. They do not prove Web Store publication,
authorization, benign behavior, or that the newer version is safer. The
side-specific archive SHA options are trustworthy only to the extent that the
external channel supplying them is trustworthy and fresh.

## Package changes

`packageDelta.profile` is `mvx-package-delta-v1`. Paths are compared from the
deterministic package inventories, not from filesystem timestamps. The result
contains every added and removed entry, every modified entry with its before
and after metadata, unchanged-entry counts, regular-file counts, and total byte
delta.

For regular files, a content change is identified by exact byte length and
SHA-256. A path changing between a file and directory is reported as a `type`
change. Directory-only metadata is not treated as file content. The normal
finding/evidence, permission, host, risk, and unreviewed-risk deltas remain
available alongside the package changes.

## API

```js
import { compareExtensionArchives } from 'mvx-audit';

const comparison = await compareExtensionArchives('before.crx', 'after.crx', {
  requireValidSignature: true,
  requireSameExtensionId: true,
  expectedExtensionId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  expectedBeforeArchiveSha256: '<lowercase-sha256>',
  expectedAfterArchiveSha256: '<lowercase-sha256>',
  rulePacks: ['./campaign.json'],
  dispositionPolicies: ['./review.json'],
  dispositionAt: '2026-07-30T12:00:00.000Z'
});
```

Options are strict plain data. Unknown fields, top-level or nested accessors and
proxies, malformed digests, non-canonical extension IDs, and non-boolean
strictness flags are rejected before temporary extraction. Rule/policy path
lists and scan, archive, rule-pack, and disposition-policy limit objects are
snapshotted before asynchronous work, so a caller cannot change the second
side's analysis semantics while a comparison is running.
