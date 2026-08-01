# Declarative rule packs

Rule packs let researchers apply local campaign indicators and package hashes
without adding executable analyzer plugins. They are strict, bounded JSON data:
MVX never imports a pack as code, evaluates expressions, interprets regular
expressions, or follows references over the network.

Use the checked-in [synthetic example](../examples/campaign-rule-pack.json) as a
starting point:

```bash
node bin/mvx.js rules validate examples/campaign-rule-pack.json
node bin/mvx.js audit /path/to/extension \
  --rule-pack examples/campaign-rule-pack.json
node bin/mvx.js compare /path/to/before /path/to/after \
  --rule-pack team-iocs.json --rule-pack campaign-iocs.json
node bin/mvx.js benchmark static quarantine --acknowledge-risk \
  --rule-pack campaign-iocs.json
```

`--rule-pack` is repeatable. Comparison and benchmark commands load each pack
once and reuse the validated representation for every audit. Packed audit
validates packs before creating a temporary extraction workspace.

## Schema version 1

The top-level object accepts exactly these fields:

| Field | Type | Meaning |
|---|---|---|
| `schemaVersion` | integer | Must be `1`. |
| `namespace` | string | Stable lowercase namespace such as `team.campaign`; unique across the invocation. |
| `name` | string | Human-readable pack name. |
| `version` | string | Publisher-chosen version recorded in reports. |
| `rules` | array | One or more rule objects. |

A rule accepts `id`, `title`, `severity`, `confidence`, `category`,
`description`, `remediation`, `references`, `condition`, and `indicators`.
Unknown fields are rejected. `id` uses uppercase letters, digits, `_`, and `-`,
beginning with a letter. The emitted finding ID and stable fingerprint are
`RP:<namespace>:<id>`. IDs must be unique within a pack.

- `severity`: `critical`, `high`, `medium`, `low`, or `info`.
- `confidence`: `high`, `medium`, or `low`; defaults to `high`.
- `category`: a lowercase, hyphen-separated identifier.
- `references`: at most 20 absolute HTTPS URLs without embedded credentials.
- `condition`: `any` (default) or `all`.
- `indicators`: a non-empty array; exact duplicates within one rule are
  rejected.

With `any`, one matching indicator triggers the rule. With `all`, every
indicator must match somewhere in the package. `all` expresses co-occurrence,
not ordering, proximity, or data flow.

## Indicator types

| Type | Required fields | Optional fields | Behavior |
|---|---|---|---|
| `text` | `value` | `scope`, `caseSensitive` | Literal substring match in decoded text. Scope is `source`, `manifest`, or `all-text` (default). Case sensitivity defaults to `true`; insensitive literals must be ASCII. |
| `path` | `value` | `match` | Match a regular-file path by normalized extension-relative `exact` path (default) or by `basename`. |
| `file-sha256` | `value` | none | Match any inventoried regular file with the exact lowercase SHA-256. |
| `package-sha256` | `value` | none | Match the `mvx-package-v1` digest of the complete unpacked package inventory. |

Text indicators are literals, so characters such as `.*` and `[]` have no
special meaning. Source scope covers the same supported JS-family, HTML, and
JSON files as built-in source analysis, plus strict UTF-8 text recovered by the
bounded direct-literal `atob` decoder. Decoded matches retain the packaged file
and encoding line, decoded line, payload depth, parent/payload SHA-256, and
decoder profile rather than inventing a virtual package path. Manifest scope is
the raw decoded `manifest.json` text. One text evidence item is retained per
indicator, file, line, and decoded payload; path and hash evidence is retained
per matching file. A package hash uses package-level evidence without inventing
a filesystem location. Exceeding the global raw-match limit fails the audit
rather than truncating evidence, including when repeated occurrences would
otherwise collapse to one evidence line.

## Validation and provenance

Pack files must be real, non-symlinked regular files containing valid UTF-8
JSON. Duplicate JSON object keys, unknown fields, unsupported indicator types,
unsafe paths, invalid hashes, control or bidirectional display characters,
and more than 128 JSON nesting levels are rejected. Display values cannot have
surrounding whitespace. These constraints keep reports deterministic and safe
to render; they do not establish publisher trust.

Every report records each pack's namespace, name, version, exact raw byte
length, raw-byte SHA-256, rule count, and indicator count. Input filenames and
absolute paths are excluded. Packs are sorted by namespace, so identical pack
bytes and limits produce the same `mvx-static-v4` analysis identity regardless
of input order or local path. Reformatting JSON changes the pack and analysis
hashes, but not the package digest.

Default fail-closed limits are:

| Limit | Default |
|---|---:|
| Packs | 32 |
| Bytes per pack | 1,000,000 |
| Bytes across packs | 5,000,000 |
| Rules | 1,000 |
| Indicators | 5,000 |
| Bytes per text literal | 4,096 |
| Bytes across text literals | 1,000,000 |
| Raw text/path/hash matches | 10,000 |

Library callers can lower or raise these positive safe-integer limits with the
`rulePackLimits` option. The normalized effective limits participate in the
analysis identity.

```js
import { auditExtension, loadRulePacks } from 'mvx-audit';

const files = ['./team-iocs.json', './campaign-iocs.json'];
const validation = await loadRulePacks(files);
console.log(validation.provenance);

const result = await auditExtension('/path/to/extension', {
  rulePacks: files,
  rulePackLimits: { maxMatches: 2_000 }
});
```

## Interpretation and maintenance

A pack match is an analyst-supplied review indicator, not proof of malicious
intent, attribution, publisher identity, or runtime behavior. File and package
hashes identify exact bytes only; text and path indicators can collide or
become stale. Keep the source, license, collection date, confidence rationale,
and expiry policy for operational packs under review. MVX records pack bytes
but does not sign them, fetch updates, authenticate their publisher, or assign
ground-truth status.
