# Static Declarative Net Request analysis

MVX audits every [Chrome static Declarative Net Request
ruleset](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)
declared by
`manifest.declarative_net_request.rule_resources`. The analyzer does not load
the extension or ask Chrome to compile its rules. It creates a deterministic,
content-addressed `mvx-dnr-static-v1` inventory and emits review findings for
network-changing actions or input it cannot classify safely.

## Coverage

The inventory counts the six Chrome action types in a fixed order:
`allow`, `allowAllRequests`, `block`, `modifyHeaders`, `redirect`, and
`upgradeScheme`. It records precise evidence for:

- `MVX113`: valid structural `modifyHeaders` rules;
- `MVX114`: valid structural `redirect` rules; and
- `MVX115`: malformed or structurally unverifiable declarations, rulesets, or
  individual rules.

Every MVX113/MVX114 evidence item includes the normalized ruleset path,
one-based rule line, declared ruleset ID and enabled state, positive rule ID,
and action type. Reports do not copy redirect URLs, URL filters, header names,
header values, or other raw rule content. The ruleset raw-byte SHA-256 remains
available for exact review and reproduction.

Disabled declarations are intentionally included. Chrome exposes
[`updateEnabledRulesets()`](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest#method-updateEnabledRulesets), which
can change which declared static rulesets are enabled, so `enabled: false` is an
initial state rather than permanent absence of capability.

## Strict structural profile

A ruleset must be a strict-UTF-8 JSON array without duplicate object keys. Each
manifest `rule_resources` value must be an array of descriptors with a display-
safe ID, normalized extension-relative path, and Boolean enabled state. Each
rule must have a unique positive safe-integer ID, an optional positive
safe-integer priority, object-valued `action` and `condition`, and one of the
six known action types.

For `modifyHeaders`, MVX requires at least one structurally valid request or
response header operation. For `redirect`, it requires exactly one structural
destination selector and rejects a literal `javascript:` URL. Contradictory
redirect/header fields on other action types are unverifiable. A missing
declared file is handled by the package-integrity rule MVX002 rather than being
duplicated as MVX115.

This deliberately is not Chrome's complete rule compiler. MVX does not fully
validate conditions, version-specific header restrictions, redirect transforms,
rule precedence, regex support, or browser quotas. It does not inspect dynamic
or session rules created at runtime. A structurally valid rule may still be
rejected by a particular browser, and a declared rule is not proof of runtime
enablement, matching, or malicious intent.

## Determinism and provenance

Each audit publishes:

- normalized limits;
- ruleset ID, normalized path, initial enabled state, byte length, raw-byte
  SHA-256, and parse status;
- total/valid/invalid rule counts and fixed-order action counts;
- retained high-impact and invalid-rule evidence; and
- one SHA-256 over the complete canonical inventory.

The combined `mvx-static-v5` identity binds the DNR profile, normalized limits,
and inventory SHA-256. Identical package bytes and options therefore reproduce
the identity at another checkout path. A ruleset byte change, including JSON
formatting, changes both its raw digest and the combined DNR/analysis identities.
Static audit and comparison verification replay the same limits and reject any
report drift.

## Resource limits

Default fail-closed limits are:

| Limit | Default |
|---|---:|
| Declared static rulesets | 100 |
| Rules across parsed rulesets | 300,000 |
| Retained high-impact or invalid entries | 20,000 |
| JSON nesting depth | 128 |
| JSON values inspected | 5,000,000 |

These are analyzer work bounds, not claims about a specific Chrome version's
accepted quotas. Exceeding one raises `DNR_RULE_LIMIT`; the audit never silently
truncates a ruleset or returns a clean result. Library callers can supply a
plain object under `dnrRuleLimits` to lower or raise any positive safe-integer
bound:

```js
import { auditExtension, DNR_RULE_LIMITS, DNR_RULE_PROFILE } from 'mvx-audit';

const report = await auditExtension('/path/to/extension', {
  dnrRuleLimits: { maxRules: 50_000, maxTrackedRules: 5_000 }
});
```

The same option is propagated by packed audit, directory/packed comparison,
static benchmark, and offline audit/comparison verification APIs. The exported
constants let callers pin the public profile and defaults.
