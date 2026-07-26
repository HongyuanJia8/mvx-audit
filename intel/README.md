# Real-world threat intelligence

This directory contains a normalized, reproducible snapshot of public reports
about real Chrome and Edge extensions. It is deliberately separate from the
synthetic `corpus/` fixtures.

The snapshot currently indexes 4,716 unique extension IDs. A record can carry
several kinds of evidence: a researcher report, a store/operator confirmation,
a static behavioral verdict, a policy or unwanted-software label, and an
available CRX hash. These signals are not interchangeable. In particular,
`unknown`, `policy-violation`, `adware`, and `suspicious` are not silently
promoted to confirmed malware.

Files:

- `sources.json` pins every upstream commit, input URL, checksum, license, and
  attribution.
- `catalog-meta.json` records snapshot-level counts and provenance.
- `catalog.jsonl` stores one normalized record per unique extension ID.

Useful commands:

```bash
mvx intel stats
mvx intel lookup acmnokigkgihogfbeooklgemindnbine
mvx intel validate
npm run intel:update
npm run intel:check
```

`intel:update` downloads only text metadata and a Git tree. It never downloads
a CRX. `intel:check` reconstructs the snapshot from immutable upstream commits
and fails if the checked-in output differs.

## Count semantics

An extension ID identifies a signing key, not one immutable package version.
An extension may be benign, become malicious after an ownership transfer, and
later be remediated under the same ID. For artifact-level research, use the
tuple `(extension ID, version, SHA-256)` whenever all fields are available.

The catalog reports input rows and unique normalized IDs separately. Counts
from different providers must never be added without de-duplication.

## Safety

No live extension package is committed here or included in the npm package.
The artifact index only describes files available from a third party. Treat
every referenced package as live malware, review its upstream terms, and use
the quarantine workflow described in `docs/data-sources.md`.
