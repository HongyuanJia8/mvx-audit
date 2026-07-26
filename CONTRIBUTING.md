# Contributing

Contributions are welcome for analyzer rules, synthetic scenarios, reporting,
threat-intelligence providers, documentation, and tests.

## Development workflow

1. Use Node.js 20 or newer and run `npm ci`.
2. Create a focused branch and add tests with every behavior change.
3. Run `npm run check` and `npm audit --omit=dev`.
4. Explain false-positive tradeoffs and cite primary platform documentation in
   a rule change.
5. Keep commits reviewable and use descriptive commit messages.

## Adding a scenario

- Add one MV2 and one MV3 fixture under `corpus/fixtures/<scenario-id>/`.
- Keep fixtures synthetic, minimal, and safe if accidentally loaded.
- Never include real credentials, user data, public data-collection endpoints,
  copied malware, browser binaries, or code of uncertain license.
- Add registry metadata, expected findings, an MV3 effect, and primary HTTPS
  references to `corpus/catalog.json`.
- Run `npm run corpus:validate` and `npm run docs:generate`.
- Add or update tests when the scenario introduces analyzer behavior.

## Adding a rule

Use the next stable ID in the manifest (`MVX1xx`) or source (`MVX2xx`) family.
Every rule needs a title, category, severity, confidence, concise description,
actionable remediation, primary reference, deterministic evidence, positive
test, and negative test. Avoid rules based only on suspicious words or filenames.

## Updating real-world intelligence

Do not commit CRX, ZIP, unpacked malware, or opaque binary samples. Provider
updates must pin immutable upstream revisions, document redistribution terms,
verify checksums, preserve source-specific labels, and retain provenance. Follow
the review procedure in `docs/data-sources.md` and commit the source lock with
its generated snapshot.

By participating, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
