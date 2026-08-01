# Isolated dynamic canary lab

The optional lab observes whether an extension reaches a synthetic security
objective. It is intentionally separate from normal MVX commands because it
executes untrusted extension code in Chromium.

## Safety boundary

The host wrapper starts Docker with:

- `--network none`, so neither the public internet nor a host collection server
  is reachable;
- a read-only container root, read-only extension/scenario mounts, and no
  writable host bind mount; JSONL evidence returns through stdout for the host
  wrapper to persist;
- a non-root Chromium process, all Linux capabilities dropped,
  `no-new-privileges`, and no `--no-sandbox` flag;
- Chromium's unprivileged user/PID/network namespace sandbox and renderer
  seccomp-BPF filter. A vendored Moby-default seccomp profile permits only the
  additional `clone`, `unshare`, and `chroot` calls needed to enter that jail;
- an ephemeral profile in a bounded tmpfs; and
- CPU, memory, process, and runtime limits.

The wrapper rejects symlinks and special files anywhere in the extension tree.
An inode/device-anchored worker copies the tree into a mode-0700 private
workspace, verifies every directory handoff, opens files without following
links, audits the captured tree, and mounts only those stable bytes. Captured
files are read-only and directories are traversable by the container's fixed
non-root UID, while the inaccessible private parent prevents other host users
from reaching them. The scenario is copied from one bounded no-follow read into
the same workspace.
Later changes to the source tree cannot change the running sample. Cleanup
revalidates the private workspace and its parent before removal. The wrapper
requires a fresh, empty result directory; untrusted code cannot write there
directly. Do not weaken these flags to accommodate an environment where
Chromium cannot start; that run is `inconclusive`.

Snapshot resource failures remain in the lab error domain: missing temporary
parents use `LAB_INPUT_NOT_FOUND`, unsafe parents use `UNSAFE_LAB_INPUT`, and
tree limits use `LAB_LIMIT`. If cleanup fails, the snapshot capability remains
valid so an operator can restore the recorded workspace path and retry removal;
the host wrapper reports that recorded path as potentially stale rather than
claiming it is the confirmed location of the retained inode. Treat the
surrounding private temporary directory as requiring manual investigation.

The wrapper also snapshots the exact seccomp bytes after hashing them and runs
Docker by the inspected content-addressed image ID rather than the mutable image
tag. The requested tag is retained only as context.

## Build and run

Docker is deliberately not downloaded or invoked by ordinary installation or
CI. Docker Engine, Docker Desktop, and OrbStack are supported runtime options.
On a dedicated disposable malware-analysis host:

```bash
npm run lab:build
npm run lab:smoke -- --acknowledge-risk
npm run lab:run -- \
  --extension quarantine/<id>/unpacked/<sha256> \
  --scenario lab/scenarios/credential-exfiltration.json \
  --output results/local/lab-<id> \
  --acknowledge-risk
```

The run retains the exact `scenario.json`, raw `events.jsonl`, and deterministic
`report.json`. A captured event stream can be reevaluated without a browser:

```bash
mvx lab evaluate lab/scenarios/credential-exfiltration.json \
  results/local/lab-<id>/events.jsonl --format json
```

The report's `mvx-lab-evidence-v1` record hashes the exact scenario and event
bytes and a domain-separated deterministic evaluation. A profiled live run also
records the exact `mvx-package-v1` and `mvx-static-v4` identities of the mounted
snapshot, Chromium version, Docker image ID/reference, network mode, duration,
tool version, and seccomp SHA-256. Verify the retained bundle offline:

```bash
mvx lab verify results/local/lab-<id>/report.json \
  quarantine/<id>/unpacked/<sha256> \
  results/local/lab-<id>/scenario.json \
  results/local/lab-<id>/events.jsonl \
  --expected-report-sha256 <digest-from-an-independent-record> \
  --expected-package-sha256 <digest-from-an-independent-record> \
  --expected-events-sha256 <digest-from-an-independent-record> \
  --expected-image-id sha256:<digest-from-an-independent-build-record>
```

Verification uses bounded no-follow reads, strict UTF-8 and duplicate-key
checks, and re-evaluates every event. It copies the supplied extension through
an inode/device-anchored worker into a private workspace, audits only that
snapshot, waits for cleanup, and rejects directory replacement, unsafe
temporary parents, symlink roots, and special entries rather than treating a
changing tree as stable evidence.

The following optional assertions bind identities obtained independently of
the retained bundle:

| CLI option | Exact value checked |
|---|---|
| `--expected-report-sha256` | Raw `report.json` bytes. |
| `--expected-package-sha256` | Re-audited `mvx-package-v1` snapshot identity. |
| `--expected-analysis-sha256` | Re-audited `mvx-static-v4` snapshot identity. |
| `--expected-scenario-sha256` | Raw scenario bytes actually evaluated. |
| `--expected-events-sha256` | Raw JSONL bytes actually evaluated. |
| `--expected-evaluation-sha256` | Domain-separated deterministic evaluation identity. |
| `--expected-seccomp-sha256` | Verifier seccomp-profile bytes. |
| `--expected-image-id` | Content-addressed Docker image ID recorded by live execution. |

Every SHA-256 option requires a canonical lowercase digest; the image ID uses
`sha256:<digest>`. An independent mismatch is reported before bundle
self-consistency can be mistaken for trust. Without `--expected-image-id`, the
recorded content-addressed image ID remains visible but is explicitly reported
as not independently checked. With no expected identity at all, verification
also emits an explicit self-consistency caveat.

This verifies consistency and independently supplied identities, not
authorship: the report is not signed, and supplying attacker-chosen evidence
and expected values together does not create trust.

The host stops a run after 60 seconds and terminates streaming capture as soon
as raw JSONL exceeds 20 MB. Offline parsing also caps the stream at 100,000
events and rejects non-canonical or out-of-order lifecycle timestamps rather
than silently truncating evidence. Docker writes the exact container ID into
the private snapshot; after any failed, timed-out, or overflowing run, the host
explicitly force-removes that ID before deleting the mounted snapshot. If
Docker cannot confirm removal, the wrapper fails closed and reports the private
snapshot path instead of deleting potentially mounted evidence.

## Oracle and containment

The runner fulfills one virtual HTTPS target page through Chrome DevTools
Protocol over anonymous parent/child pipes—no debuggable TCP port is exposed.
The page contains unique synthetic form, cookie, local-storage, search, and
document canaries. Every other HTTP(S) attempt is recorded from the Network
domain with its initiator and body, while Docker's `network=none` boundary
prevents delivery. Downloads are denied. Protected DOM state is checked after
the trigger window.

`lab:smoke` executes a checked-in benign fixture and a synthetic credential
exfiltration fixture. It fails unless the former produces
`no_trigger_observed`, the latter produces `confirmed_attack`, both are
contained, and collection reports no errors. Evidence is retained in the
printed temporary directory.

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
can affect activation. Publish the complete retained bundle, exact extension
bytes, and the independent source of any expected image ID.
