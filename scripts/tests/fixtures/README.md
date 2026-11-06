# Public boot-assessment fixtures

[dracut-057](dracut-057/README.md) contains unmodified public AlmaLinux/dracut shell and rule files. The existing provenance README distinguishes the network-manager package inputs from later generic-cloud hooks and retains upstream references and license notices.

These files are inert parser inputs. Contracts compare or inspect their bytes; they must not execute, source, install or adapt these hooks on the host. The nested `03modsign`, `90crypt`, `90dm`, `95lunmask` and `95virtfs` directories are upstream data, not Aegis feature implementations. Their upstream content and licensing should remain intact rather than acquiring generated per-file documentation.

Boot assessment also checks host-specific integrity and bounded activation inputs. Recognizing these fixtures does not claim encrypted-root support or successful boot on another distribution. Begin with the parent [contract-support guide](../README.md) and the relevant dracut/device boot contract in `scripts/`; record a new package provenance and reviewed digest before accepting different input bytes.

## Local sink route JSON

`auto_sink_route_ipv4.json` and `auto_sink_route_ipv6.json` retain actual
`ip -j -4 route get 10.231.82.2` and
`ip -j -6 route get fd77:ae91:1::2` output captured on 18 October 2026 in the
existing offline Linux guard image, with an isolated container network.
Only those two fixture addresses were assigned to its loopback interface.
They demonstrate iproute2's `type: local`, `dst` and `dev: lo` representation;
there is no `local` object key. These are parser fixtures, not native AUTO
acceptance or an installed host routing claim.

## B+ shutdown classification readbacks (r20)

`auto_shutdown_nft_readbacks.json.gz` holds verbatim `nft --json list ruleset`
output for nft 1.0.9 (Ubuntu 24.04 image) and nft 1.0.6 (Debian 12 image).
Each guard batch was printed by the committed `render()` of
`scripts/aegis-device-egress-guard.sh` through `auto_guard_render_harness.py`
(its SHA-256 is recorded as `render_function_sha256` and checked by the test),
applied in a private network namespace of a disposable `--network none`
container, and read back. `pruned_*` readbacks were taken after the bound
cgroup was removed, so nft prints its id. `loose` readbacks add one foreign
change to the manager-only deny. Binding-marker comments use fixed inode
values so that variants compare; the real cgroup ids are in `cgroup_ids`.

`auto_shutdown_nft_readbacks_r26.json.gz` refreshes those same 14 variants and
12 negative controls on both real nft versions after the numeric TUN and DHCP
destination corrections. `scripts/qa/capture_shutdown_nft_readbacks.py` is the
reproducible collector; source and raw-receipt hashes are embedded in each
document. It renders a numeric capture predicate for comparison, without
claiming installed TUN ownership or packet acceptance. The earlier fixture is
retained for the historical source generation.

`auto_shutdown_pid1_readbacks.json.gz` holds `classifications`: every distinct
`systemctl` readback sequence (argv and stdout) that the B+ monitor read in the
r20 systemd 252/255 container rows, with the verdict derived from the strings
alone; and `unfiltered`: every distinct unfiltered `systemctl list-jobs`
listing with its `SystemState` from the earlier shutdown-redesign probes.

Both files are gzip (mtime 0) of compact JSON; the source custody paths and
hashes are in the archived change and incident log under the r20 B+ entry
(`docs/operations/evidence-archive.md`). They are parser fixtures, not installed or native acceptance.

## Rollback timer/service static-unit readbacks (r20, L-F1)

`rotation_static_pid1_readbacks.json` holds the verbatim `systemctl show`
stdout for the guardian's per-type property sets of
`aegis-auto-trace-rollback.timer` and `.service`, plus the `systemctl
list-jobs` stdout, in nine lifecycle states (never started, timer waiting,
service activating, elapsed, both stopped after firing, timer stopped before
elapse, `--no-block` start, unit files removed, not found after reload). They
were captured on real PID1 (systemd 255 Ubuntu 24.04, 252 Debian 12, 252
AlmaLinux 9) in disposable `--network none` containers by the r20 review of
`1db19afb`; each platform entry records its custody source path and SHA-256.
An inactive timer prints `NextElapseUSecMonotonic=infinity`, and after PID1
garbage-collects the inactive static timer the service prints an empty
`TriggeredBy`. These are parser fixtures, not installed acceptance.
