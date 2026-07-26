# Threat-pattern corpus

This directory contains paired MV2/MV3 inputs for static analysis. They are
minimal synthetic examples, not collected malware and not runnable attack
packages. Project commands read the files but never launch a browser or execute
fixture source.

`catalog.json` is the single source of truth for scenario metadata, expected
findings, effect classification, and primary references. Run:

```bash
npm run corpus:validate
node bin/mvx.js corpus list
```

Do not add copied third-party malware. New fixtures must use synthetic data,
contain no public collection endpoint, cite primary platform documentation, and
include both manifest versions.

