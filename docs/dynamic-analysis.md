# Isolated dynamic canary lab

The optional lab observes whether an extension reaches a synthetic security
objective. It is intentionally separate from normal MVX commands because it
executes untrusted extension code in Chromium.

## Safety boundary

The host wrapper starts Docker with:

- `--network none`, so neither the public internet nor a host collection server
  is reachable;
- a read-only container root and read-only extension/scenario mounts;
- a non-root Chromium process, all Linux capabilities dropped,
  `no-new-privileges`, and no `--no-sandbox` flag;
- an ephemeral profile in a bounded tmpfs; and
- CPU, memory, process, and runtime limits.

The wrapper rejects symlinks and special files anywhere in the extension tree.
Only the result directory is writable. Do not weaken these flags to accommodate
an environment where Chromium cannot start; that run is `inconclusive`.

## Build and run

Docker is deliberately not downloaded or invoked by ordinary installation or
CI. On a dedicated disposable malware-analysis host:

```bash
npm run lab:build
npm run lab:run -- \
  --extension quarantine/<id>/unpacked/<sha256> \
  --scenario lab/scenarios/credential-exfiltration.json \
  --output results/local/lab-<id> \
  --acknowledge-risk
```

The run emits `events.jsonl` and a deterministic `report.json`. A captured event
stream can be reevaluated without a browser:

```bash
mvx lab evaluate lab/scenarios/credential-exfiltration.json \
  results/local/lab-<id>/events.jsonl --format json
```

## Oracle and containment

The runner fulfills one virtual HTTPS target page through Chrome DevTools
Protocol over anonymous parent/child pipes—no debuggable TCP port is exposed.
The page contains unique synthetic form, cookie, local-storage,
search, and document canaries. Every other HTTP(S) request is recorded and
aborted. Downloads are denied. Protected DOM state is checked after the trigger
window.

An exact canary observed in an external request, an extension-initiated
navigation away from the target, an unauthorized download, or a protected DOM
change is objective evidence. Because egress is blocked, a confirmed attempted
exfiltration can still be reported as contained.

Verdicts:

| Verdict | Meaning |
|---|---|
| `confirmed_attack` | A unique canary reached an observable sink or protected test state changed. |
| `suspicious_activity` | External activity occurred without enough evidence to bind it to a canary objective. |
| `no_trigger_observed` | Collection completed but no supported objective fired; this does not mean benign. |
| `inconclusive` | Browser, instrumentation, or collection failure prevents a behavioral conclusion. |

## Limits

The initial scenario does not simulate user gestures, OAuth, geographic
location, long dwell time, Chrome Web Store installation, enterprise policy,
or a live C2. Headless/browser-version differences and extension anti-analysis
can affect activation. Report the container image digest, Chromium version,
scenario hash, artifact SHA-256, run duration, and full event stream with any
published result.
