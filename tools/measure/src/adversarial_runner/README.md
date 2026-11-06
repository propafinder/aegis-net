# Adversarial run orchestration

The parent adversarial_runner module delegates contract fixtures to contract.rs and optional command execution to execution.rs.

### Contracts and limits

On Unix, `run_live_command` invokes `sh -c` with an explicitly selected command
in its own process group. It concurrently drains both pipes, retains at most
64 KiB per stream and marks truncation. One original deadline covers execution
and pipe completion. Cleanup signals the owned group and polls for at most
250 ms; it never blocks waiting for pipe EOF or a child exit.

The unreaped leader reserves the group identity through cleanup. Darwin's
zombie-only group `EPERM` is accepted only after an owned exit observation and
a bounded group-membership check. Live members or failed checks remain errors.
Ordinary exit codes are preserved. Non-Unix live execution refuses until an
equivalent owned-process implementation exists.

This is not an untrusted-input sandbox: descendants can leave the process group.
The separate selected-profile command and aggregate matrix lifetime still need
their own output and execution bounds. These limits keep audit finding #65
partial even after the live-command regression passes.

### Entry points and maintenance

Use contract fixtures for schema checks. Any live command requires a separately reviewed operation and real controlled resources; avoid putting credentials in command strings or retained output.

### Local map

- [contract.rs](contract.rs)
- [execution.rs](execution.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
