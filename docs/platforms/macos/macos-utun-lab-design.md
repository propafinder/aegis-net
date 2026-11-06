# macOS utun Lab Design

Status: LAB / EXPERIMENTAL.

This is not a NetworkExtension replacement, not product-ready, and not a broad
system-wide macOS capture claim.

> Current wrapper admission: the historical W0–W5 receipts below are not a
> runnable current ladder. Four helper-FD/W1/W2 wrappers now pass required
> `--main-uid` / `--main-pid` through a shared non-root direct-child exec launcher.
> Frozen source-only syntax and inert child identity/argument checks passed;
> no Aegis/helper, sudo, socket, VM, routes or capture were exercised. See the
> [current lab boundary and private receipt references](../../../tools/macos-utun-lab/README.md).
> Executable/socket custody, elevated-helper provenance, production PID lifecycle
> and new authorized native route/cleanup acceptance remain open. These scoped
> checks do not accept macOS full-wide operation.
> W0 now requires an installed helper at its absolute configured/default path,
> regular and executable with no final-component symlink, before Cargo/output
> writes. Automatic global `/tmp` executable copying is removed. These checks
> do not authenticate helper code or close ancestor/link races; the new inert
> selection fixture passed 6/6 early-entry cases; the source/reference fixture
> passed 114/114 with actual launcher/account prerequisites and inert helper
> data. No helper or native network lifecycle ran. Exact-commit CI is pending;
> Audit #73 remains PARTIAL.

The historical May 2026 lab milestones were:

- W0: helper opens utun, passes FD to non-root main process, and observes a
  controlled packet.
- W1: installs one controlled IPv4 `/32` route to utun and removes it during
  cleanup; the relay IP remains excluded.
- W2: parses a controlled TCP flow from utun.
- W2.1: writes a lab SYN-ACK back to utun and observes the client ACK.
- W3: proves a local AEGIS relay session is triggered in the lab after the W2.1
  stateful TCP edge proof.
- W4: records the explicit TCP/DNS/UDP/IPv6 policy boundary and cleanup matrix
  for the lab ladder.
- W5: proves one controlled external IPv4 `/32` route through the utun packet
  loop, keeps the relay IP excluded, and links that route proof to the existing
  external AEGIS `https_ws` relay path evidence.

W3 is `LAB_LOCAL_AEGIS_RELAY_TRIGGER`, not Cloudflare, not NetworkExtension, and
not a product-ready TCP bridge. W4 is `LAB_POLICY_BOUNDARY_AND_CLEANUP_MATRIX`;
it does not add DNS, UDP, IPv6, default-route, or broad system-wide capture.
W5 is `LAB_CONTROLLED_EXTERNAL_IPV4_32_ROUTE_PLUS_HTTPS_WS_RELAY_PATH`; it is
still a controlled lab path and is not a product-ready TCP bridge.

## Architecture

1. A privileged helper opens a macOS utun device.
2. The helper sends the utun file descriptor to the main process over an AEGIS
   Unix domain socket using `SCM_RIGHTS`.
3. The main process receives the FD, drops any helper-only privilege boundary,
   and reads/writes packets through that FD.
4. Every utun read/write accounts for the 4-byte address-family header that
   precedes the IP packet payload.
5. Cleanup closes the utun FD, removes only AEGIS-owned routes, removes the
   AEGIS Unix socket, and leaves non-AEGIS routes untouched.

## Privilege Model

Lab/dev path: sudo-run helper.

Future product path: launchd-installed privileged helper authorized through
ServiceManagement.

No setuid primary path is planned for W0. The normal AEGIS client process must
not become the privileged route/device owner.

## Routing Model

W0 uses one controlled IPv4 route only. The first proof must not install a
default route.

Required routing boundaries:

- add only one AEGIS-owned controlled IPv4 route;
- explicitly exclude the relay IP from utun routing;
- never claim DNS, UDP, IPv6, or full system-wide coverage in W0;
- cleanup must remove only AEGIS-owned route entries.

W4 policy classifications:

- controlled TCP IPv4 route/relay bridge: `CAPTURE`, limited to the controlled
  IPv4 `/32` lab route and local relay bridge proof;
- DNS: `OUT_OF_SCOPE`;
- UDP: `OUT_OF_SCOPE`;
- IPv6: `OUT_OF_SCOPE`.

Those `OUT_OF_SCOPE` entries are intentional non-claims, not silent PASS
results.

W5 routing stays within the same boundary: one controlled external IPv4 host
route only, explicit relay IP exclusion, no default route, and cleanup of only
AEGIS-owned route/interface state.

## Runtime Events

The proof runtime must emit:

- `macos_utun_helper_started`
- `macos_utun_fd_received`
- `macos_utun_packet_observed`
- `macos_utun_tcp_synack_lab_completed`
- `macos_utun_relay_bridge_session_succeeded`
- `macos_utun_policy_decision`
- `macos_utun_cleanup_matrix_completed`
- `macos_utun_external_relay_path_succeeded`
- `macos_utun_cleanup_completed`

## PASS Criteria

W0 can be marked PASS only if all conditions are true:

- helper creates a utun device;
- FD is passed to the non-root main process over `SCM_RIGHTS`;
- main process observes at least one packet or one controlled injected packet;
- cleanup succeeds;
- evidence contains no broad system-wide macOS claim.

Until a rooted run produces those events and route cleanup evidence, the status
remains `LAB_BLOCKED_BY_ROOTED_UTUN_PROOF_MISSING`.

## Historical evidence (3 May 2026)

- W0 helper/FD loop: `evidence-archive/live/2026-05-03/macos-utun-helper-fd-loop-lab/`
- W1 controlled IPv4 route: `evidence-archive/live/2026-05-03/macos-utun-w1-controlled-route-proof-lab/`
- W2 TCP header adapter: `evidence-archive/live/2026-05-03/macos-utun-w2-tcp-flow-adapter-proof-lab/`
- W2.1 stateful TCP edge: `evidence-archive/live/2026-05-03/macos-utun-w2-stateful-tcp-edge-proof-lab/`
- W3 local relay bridge: `evidence-archive/live/2026-05-03/macos-utun-w3-local-relay-bridge-proof-lab/`
- W4 policy cleanup matrix: `evidence-archive/live/2026-05-03/macos-utun-w4-policy-cleanup-matrix-lab/`
- W5 controlled external relay path: `evidence-archive/live/2026-05-03/macos-utun-w5-controlled-external-relay-path-lab/`

These artifacts keep `default_route_claim`, `broad_system_wide_claim`,
`dns_claimed`, `udp_claimed`, `ipv6_claimed`, and `network_extension_claimed`
false.
