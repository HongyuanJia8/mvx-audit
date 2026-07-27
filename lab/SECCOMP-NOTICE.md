# Chromium seccomp profile

`seccomp-chromium.json` is derived from the Moby project's default seccomp
profile, tag `seccomp/v0.2.1`, licensed under Apache License 2.0:

https://github.com/moby/profiles/blob/seccomp/v0.2.1/seccomp/default.json

The only policy change is an explicit allowance for `clone(2)`, `unshare(2)`,
and `chroot(2)`. Chromium uses these calls to create and enter its unprivileged
user, PID, and network namespaces and an empty-filesystem jail. MVX Audit runs
the container as a non-root user with all Linux capabilities dropped; Chromium
then applies its own seccomp-BPF filter to sandboxed child processes.
