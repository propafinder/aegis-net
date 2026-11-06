# Controlled macOS utun laboratory

A macOS-only helper/main executable that passes an owned utun descriptor over a Unix socket and records controlled packet/route evidence.

### Contracts and limits

This experimental laboratory has no accepted signed NetworkExtension or full-host client claim. Helper and main modes can create an interface and manipulate controlled network state; the source changes below do not establish privileged native acceptance. Non-macOS targets return explicit unsupported behavior.

Descriptor IPC in [src/fd_ipc.rs](src/fd_ipc.rs) verifies kernel peer credentials, accepts one versioned exact-length interface frame and one `SCM_RIGHTS` descriptor, and takes `OwnedFd` custody before fallible validation. Refused transfers close installed rights; accepted descriptors have close-on-exec set. Receive capacity comes from the unchanged finite soft `RLIMIT_NOFILE`, including per-descriptor ancillary header/alignment overhead, with checked arithmetic and a 32 MiB hard allocation ceiling. Unsupported limits or allocation failure refuse before receiving. This bounded one-shot policy retains OS/process-limit trust and an explicit availability tradeoff; it is not a production multi-session allocation policy.

Audit #73 remains **PARTIAL**. W0's automatic executable copy fallback is removed as described below; mutable executable/ancestor/link races, IPC parent/socket-path custody, root helper provenance, matching helper PID and authorized native lifecycle still need repair or acceptance. Main's root-UID admission does not pin a particular helper PID.

### Entry points and maintenance

See [src/main.rs](src/main.rs) for helper/main modes and exact arguments. Helper mode now requires `--main-uid UID --main-pid PID`, with a non-root UID and the actual positive main process PID. The connected peer's kernel UID/PID must match before any utun creation or route change and again before descriptor send. Main checks root kernel UID before descriptor receive.

These four wrappers now use a shared source-only launcher and pass the required
peer arguments. They require the invoking UID to equal the explicitly selected
non-root `AEGIS_USER` before any main spawn. Run them only within the separately
authorized native laboratory procedure; this source repair is not native readiness:

The account guard refuses option-like, empty, missing or extra account arguments
before invoking `id`; an account value cannot be interpreted as an `id` option.

- [run-macos-utun-helper-fd-loop-lab.sh](../../scripts/run-macos-utun-helper-fd-loop-lab.sh)
- [run-macos-utun-w1-controlled-route-proof.sh](../../scripts/run-macos-utun-w1-controlled-route-proof.sh)
- [run-macos-utun-w2-tcp-flow-adapter-proof.sh](../../scripts/run-macos-utun-w2-tcp-flow-adapter-proof.sh)
- [run-macos-utun-w2-stateful-tcp-edge-proof.sh](../../scripts/run-macos-utun-w2-stateful-tcp-edge-proof.sh)

W0's [helper-FD loop wrapper](../../scripts/run-macos-utun-helper-fd-loop-lab.sh)
requires an already installed helper: `AEGIS_MACOS_UTUN_HELPER`, or the default
`/usr/local/sbin/aegis-macos-utun-lab-w0`. The selected path must be absolute,
regular, executable and have no symlink at its final component. Missing or
unacceptable input exits with a fixed message and status 2 before Cargo or
output-directory creation. The automatic global `/tmp` executable fallback and
its copy/chmod are removed. These pathname checks do not authenticate code or
protect mutable executable contents, ancestors or a later path substitution.
The existing account/relay admission and native authorization remain required.

The [helper-selection inert fixture](../../scripts/test-macos-utun-helper-selection-inert.sh)
checks actual early-entry refusals and an absolute regular path containing
spaces that reaches an inert Cargo sentinel (status 97). It executes no helper,
sudo, VM, sockets, routes or capture. The frozen actual early-entry fixture
passed **6/6**: five inadmissible-helper cases and the regular-path positive.
Existing main-launch identity and shell syntax checks also passed.
The [relay-reference fixture](../../scripts/test-macos-relay-reference-contract.sh)
passed **114/114** using actual source copies, the real invoking account and
inert helper data. Its 112 address cases stop after the first output-directory
operation and reference witness; two separate complete controls consume synthetic
W3/W5 evidence. None executes the helper. Private final
receipt: `evidence-archive/testing/2026-10-12/macos-W0-entry-final-actual-qa-r2/complete-r2.json`.
Darwin CI now selects the six helper cases, main-launch and reference fixtures
in a one-minute early step; exact-commit CI completion is still pending.
Private evidence `evidence-archive/testing/2026-10-12/macos-W0-fallback-private-baseline-actual-r1/complete-r1.json`
preserves two RED controls against the original copy primitive and a fresh-file
positive control; it does not replay or accept the entire historical W0 runner.
Separately, `evidence-archive/testing/2026-10-12/macos-W0-entry-original-actual-r1/complete-r1.json`
retains five causal early-entry RED controls and one regular-path positive from
the original runner, stopped at inert Cargo without helper execution. These are
separate from the older copy-primitive controls. The earlier relay fixture's
50 PASS / 64 INVALID result lacked the launcher prerequisite; those 64 invalid
cases are not semantic RED evidence. The repaired current fixture supplies the
actual launcher and selected inert helper prerequisites.
This source change and fixture do not close Audit #73, signing, helper provenance
or macOS full-wide acceptance.

The [shared launcher](../../scripts/macos-utun-main-launch.sh) launches main as
a direct non-root child and replaces that child shell with `exec`; PID and UID
are preserved across exec. No sudo launcher, ancestry lookup or PID file is
used to select `--main-pid`. The elevated helper receives that PID and UID, and
its unchanged kernel peer check remains authoritative if exec fails or another
process connects. Native route/capture commands are unchanged. Executable and
socket custody, helper provenance, bounded native lifecycle and independent
acceptance remain open. The [inert regression](../../scripts/test-macos-utun-main-launch-inert.sh)
uses only a synthetic child for PID/UID and argument preservation; it does not
run Aegis, sudo, sockets, routes or capture. Root's frozen inert execution
passed in 0.041 seconds, and the selected shell syntax check passed in 0.037 seconds. Private
local receipts are `evidence-archive/testing/2026-10-11/reconciliation-verification-root-r1/o38-main-identity-inert-r4/receipt.json`
and `o38-launch-syntax-r4/receipt.json` in the same directory; both bind unchanged
source inputs and confirmed owned-process cleanup. This scoped result does not
close Audit #73 or accept executable/socket custody, helper provenance, native
lifecycle or full-wide operation. A self-check, build or socketpair fixture does not replace
authorized native readiness, capture and cleanup evidence.

The final focused suite (`evidence-archive/testing/2026-10-10/audit17-macos-helper-ipc-r1/green-r4/stdout.txt`) passed **16/16**, including real bounded unprivileged socketpair transfer/credential/cleanup regressions and pure capacity/argument checks. It preserves valid transfer, refuses mismatched UID/PID and malformed frames, and proves cleanup of a 128-descriptor refused transfer. Strict scoped Clippy (`evidence-archive/testing/2026-10-10/audit17-macos-helper-ipc-r1/lint-r2/receipt.json`) passed. See the [source map](src/README.md) and audit report (`evidence-archive/testing/2026-10-10/audit17-macos-helper-ipc-r1/REPORT.md`) for the preserved RED and failed attempts. No privileged helper, utun, PF, routes, NetworkExtension or full-host acceptance was exercised by these checks.

Evidence paths above are workspace-local files and are not published with this guide. See the portable [tracked audit findings, row #73](../../docs/operations/security-audit-2026-10-10-findings.md) for the recorded finding.

### Local map

- [Cargo.toml](Cargo.toml)
- [src/](src/README.md)

### Workspace build

From the repository root, with the locked dependencies and the required target toolchain available:

```bash
cargo build --locked -p macos-utun-lab --bin aegis-macos-utun-lab
```

A non-macOS build provides unsupported/help behavior. Building on macOS does not run the privileged helper or authorize route changes.
