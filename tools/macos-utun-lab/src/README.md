# utun descriptor and packet proof

[main.rs](main.rs) owns the Darwin control-socket setup, helper/main argument parsing and controlled ICMP/TCP checks. [fd_ipc.rs](fd_ipc.rs) owns kernel peer credentials, versioned Unix-domain descriptor transfer and immediate `OwnedFd` custody.

### Contracts and limits

Preserve the four-byte utun packet header, controlled route scope and separate result/event records. Descriptor IPC accepts one complete `SCM_RIGHTS` descriptor and an exact-length versioned `AEFD` interface frame. Refused metadata or excess rights must close every installed descriptor; accepted descriptors have close-on-exec set.

The helper requires explicit non-root `--main-uid` and positive actual `--main-pid` arguments. It verifies the connected peer's kernel UID/PID before utun creation or route changes and again before sending the descriptor. Main requires the sender's kernel UID to be root before receiving; this does not pin a particular helper PID or trusted executable.

Receive storage derives from the process's existing finite soft `RLIMIT_NOFILE`, including worst-case per-descriptor ancillary headers/alignment and framing. Checked arithmetic and an independent 32 MiB allocation ceiling bound this one-shot lab receive; retained descriptor ownership has a separate quota of 64. No process limit is changed. Unsupported limits or allocation failure refuse before `recvmsg`, so a pending transfer is not consumed. This policy assumes the OS enforces a stable process limit and native ancillary records; it is not a multi-session production allocator.

Audit #73 remains **PARTIAL**. Predictable executable fallback, private IPC directory/socket-path custody, trusted launch identity and privileged native lifecycle remain open. The code does not provide an accepted NetworkExtension, transparent coverage of all applications or an independent observer.

### Entry points and maintenance

Maintenance should inspect credential checks, descriptor custody, setup, packet wait and cleanup paths together. See the [parent guide's launch limitations](../README.md#entry-points-and-maintenance) before using existing wrappers: they now require the expected non-root caller and pass UID plus the direct child PID preserved by exec. The kernel peer check remains authoritative; this source repair does not establish executable/socket custody or privileged native acceptance.

The recorded final focused run (`evidence-archive/testing/2026-10-10/audit17-macos-helper-ipc-r1/green-r4/stdout.txt`) passed **16/16** tests, using real bounded unprivileged socketpairs plus capacity/argument checks. Coverage includes valid transfer, UID/PID mismatch refusal, root-UID admission refusal, close-on-exec, malformed/short metadata, excess rights, disconnect, unsupported-limit refusal before receive and actual cleanup of a 128-descriptor refused transfer. Strict scoped Clippy (`evidence-archive/testing/2026-10-10/audit17-macos-helper-ipc-r1/lint-r2/receipt.json`) passed. Audit evidence (`evidence-archive/testing/2026-10-10/audit17-macos-helper-ipc-r1/REPORT.md`) preserves the original RED and failed fixed-buffer attempts. These checks did not execute the privileged helper, utun, PF or route changes and do not establish native readiness or full-host acceptance.

Evidence paths above are workspace-local files and are not published with this guide. See the portable [tracked audit findings, row #73](../../../docs/operations/security-audit-2026-10-10-findings.md) for the recorded finding.

### Local map

- [main.rs](main.rs)
- [fd_ipc.rs](fd_ipc.rs)
- [fd_ipc_tests.rs](fd_ipc_tests.rs): unchanged original-backend comparison regressions
- [fd_ipc_peer_tests.rs](fd_ipc_peer_tests.rs): credential, capacity and installed-descriptor cleanup regressions

See the [parent guide](../README.md) for the enclosing component and runtime scope.
