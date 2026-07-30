# Auditable disposition policies

Disposition policies attach external review decisions to findings without
deleting findings or changing the raw risk summary. They are intended for
repeatable analyst review and CI triage, not for declaring an extension safe.

## Trust and binding

Every entry binds the stable finding `fingerprint` and exact `mvx-package-v1`
lowercase SHA-256. Changing any packaged byte invalidates that binding. A
fingerprint alone identifies a review category, not package contents. Policy
files remain external to the audited extension, and reports retain their exact
byte length and SHA-256 provenance.

## Schema

```json
{
  "schemaVersion": 1,
  "policyId": "team.review",
  "name": "Team security review",
  "version": "2026.07.30",
  "entries": [{
    "fingerprint": "MVX102:cookies",
    "packageSha256": "<64 lowercase hex characters>",
    "disposition": "accepted-risk",
    "owner": "extension-security@example.invalid",
    "justification": "Reviewed against the exact package and approved under ticket 123.",
    "expiresAt": "2026-12-31T23:59:59.000Z",
    "ticketUrl": "https://tracker.example.invalid/tickets/123"
  }]
}
```

Allowed dispositions are `accepted-risk`, `false-positive`, and
`compensating-control`. Owner, a justification of at least 20 characters, and a
canonical UTC expiry with milliseconds are required. `ticketUrl` is optional
and must be HTTPS without credentials. Duplicate JSON keys, unknown fields,
unsafe display controls, symlinks, non-UTF-8 files, and duplicate
package/fingerprint declarations across loaded policies are rejected.

An entry is active only when `expiresAt` is strictly later than the recorded
evaluation time. Equality is expired. Use `--disposition-at` to reproduce an
earlier evaluation; otherwise the current UTC evaluation time is recorded.

## Commands

```bash
mvx dispositions validate review.json \
  --disposition-at 2026-07-30T12:00:00.000Z --format json

mvx audit extension/ --disposition-policy review.json --format json

mvx compare before/ after/ --disposition-policy review.json --format markdown

# Existing raw threshold behavior is unchanged
mvx audit extension/ --disposition-policy review.json --fail-on high

# Explicitly gate only findings without an active disposition
mvx audit extension/ --disposition-policy review.json \
  --fail-on-unreviewed high
```

Multiple `--disposition-policy` flags are supported. `--fail-on` and
`--fail-on-unreviewed` are mutually exclusive. Expired findings count as
unreviewed.

## Report contract

All original findings remain. Matched findings gain a `disposition` object with
status `active` or `expired`, owner, justification, expiry, optional ticket,
policy ID/version, and exact policy SHA-256. Raw `summary` remains unchanged.
`reviewSummary` covers findings without an active disposition, while
`dispositionEvaluation` reports matched, active, expired, and unused counts.

Text prints both summaries and matched dispositions. SARIF keeps every result
and records disposition metadata in result properties; MVX deliberately does
not emit SARIF `suppressions`, because downstream tools may hide them by
default.

The [checked-in example](../examples/disposition-policy.json) uses an
intentionally non-matching zero package digest that must be replaced after
review.
