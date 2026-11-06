# Owned WebRTC native transport

## 2 November 2026 — unified D1–D6 source candidate

Source `2160ab21` fast-forwards the owned Linux+D4–D6 union after merging
Claude's D1/D2/D3 line. The merge parent `a19c92ac` includes D1/D2. The
source-only independent review of `9c667215` checked the 16 mixed paths,
including D3 failover ticket and D4 per-channel credential/ECH isolation,
the TCP-only signed FrontedH2 datagram boundary, and combined H2 response
trailers plus receive-window policy. The child `2160ab21` changes only a
positive SFU test fixture to satisfy the previously added strict local ICE
preflight. Filtered source manifest SHA-256
`1cd5010d8dd273feda0816f55ace8cdb96999dccd76b6d7cce143d8b7e02766a`
is retained in private permanent text evidence. Exact Rust 1.97.1 workspace
format passed; local Cloudflare fake-API controls passed 6/6, and local SFU
fixture controls passed 12/12. An earlier full SFU-control attempt failed
one stale positive fixture and a sandbox loopback bind; both are retained,
and the corrected fixture suite passed with authorized local loopback.

The combined source has no Rust compile, installed artifact, real Cloudflare
deployment, successful LiveKit media session, restricted-network result or
exact-final CI. Earlier SFU R8/R9 failures remain failures. Native media,
package notices/SBOM and installed leak checks remain open.

The source-only Alma build batch for default D4/D5 client/server plus
`chrome-like-tls` is specified in the archived `scripts/qa/b08-alma-native-build.md`
(see `docs/operations/evidence-archive.md`).
It targets the reviewed coldboot union `5b477fe7`, retaining the old executable bytes before
reusing its compiler cache, and requires offline strict Clippy before release.
The old Alma cache has a different lockfile; no build or ABI claim follows
from its presence. Source preparation did not itself establish a build.

The first guarded Alma attempt failed at Clippy before compilation because
`rustup run 1.97.1` named a toolchain absent on that host. It left no release
binary or installed result. A source successor selects the exact installed
`stable-x86_64-unknown-linux-gnu` toolchain only with launcher/binary SHA and
full 1.97.1 release/host checks. The
unique failed attempt, old ELF backup and stopped/swap-off closure are retained.

R3 selected the exact toolchain but the offline cache refused locked `libc
0.2.190` before compilation. A full 436-package public-registry lock audit
found 242 archives missing, with zero existing checksum mismatch. The bounded
public-cache hydration operator is source only; it requires a target-filtered
fetch, actual offline all-features metadata and exact selected archive/index
checks before one later compiler attempt. No installed or media result follows.

## 1 November 2026 — native SFU version admission

Source `25ae5300` adds a build gate for the optional `sfu-media-vp8` feature:
`pkg-config --modversion vpx` must return exactly `1.17.0`. Default builds do
not probe libvpx. The intended upstream source is official WebM
[`v1.17.0`](https://chromium.googlesource.com/webm/libvpx.git/+/refs/tags/v1.17.0),
annotated tag `82615ff0733cd4063838c352bc2e2ab225f37ade`, commit
`6df3ec34557879fff673706f4a1d9fbd0f3a6f0e`. The version gate does not
attest the installed library's source commit or binary digest. No native
library is installed on this development Mac (`pkg-config vpx` refuses), and
no SFU Rust compile or media test ran. Packaging, source provenance, native
notice/SBOM and actual LiveKit acceptance remain open.

The bounded native recipe `scripts/qa/sfu-libvpx-native-r1.py` takes an
already obtained upstream Git repository, verifies the exact annotated tag,
commit and tree, builds static VP8 in a unique disposable execution directory,
and records SHA-256 for `libvpx.a`, `vpx.pc`, the public header, the upstream
LICENSE and command logs. It has no download or system install step, refuses
active timing locks and requires 35 GiB free before starting. The caller must
independently review the receipt and retain exact source/archive/package
evidence; the R2 native execution and independent review are recorded below.
The generated native prefix is execution storage, not retained QA evidence.
For a later Rust run, use `PKG_CONFIG_LIBDIR=<execution>/prefix/lib/pkgconfig`
with the optional Cargo feature and independently bind the linked library
digest.

The official tag objects were fetched into a private, disposable local Git
cache without compiling: annotated tag, commit and tree matched the pins;
the Git archive is 25,815,040 bytes, SHA-256
`d7f22e7ca80ba6cfbe16e867400e9cb28e7349efd1eb823836ab45c23a8ee0b1`.
The private hash-only fetch receipt SHA-256 is
`ec03ee074ad8d20e96a6d6b113e7847033e0a2c9ca4364f88a664015645d840e`.
It contains no native binary or test result.

The first native attempt, R1, configured, compiled and installed into its
private prefix, but sandbox `nice` could not set priority; its receipt SHA-256
`77d73bc6da3c61d82c275fcc89896eb9c8f96112824271cf251104aa782c23d5`
is retained without resource-compliant credit. Unique R2 used the same
checkpointed recipe at source `9a4c1a42` with working `nice -n 10 make -j2`.
Configure, make and install exited zero with empty stderr; `pkg-config`
reported 1.17.0. Its private static library is 942,920 bytes, SHA-256
`1f5efa56323f4ff401118bb136286f6448fe0363de65bb3580fba62f7607b8b6`.
Receipt `/private/tmp/aegis-b08-libvpx-native-9a4c1a42-r2.json` has SHA-256
`5c0522344c9a84ef7634e2ef51c5048bd428d030abf70dd27d6776a3bd50841b`.
Independent review `/private/tmp/aegis-libvpx-native-9a4c1a42-r2-independent-review-r1.json`
has SHA-256 `1a03fa9f132f882e74bd15f594c4064180930a2295017ab39e2ba231bc06b2c5`
and rehashed all four reported assets, all logs and the complete 13-file
prefix. The source archive SHA-256 remains
`d7f22e7ca80ba6cfbe16e867400e9cb28e7349efd1eb823836ab45c23a8ee0b1`.
This is a Darwin native component build only: no Rust link/test, LiveKit
session, shipped native notices/SBOM, installed SFU or restricted-network
acceptance follows.

The first optional Rust all-targets check exposed three source issues: both
the client media worker and server worker omitted the authenticated `Stale`
replay classification, and the VP8 decoder compared a `u32` frame dimension
to `usize`. Two `shared:` commits (`9698a52e`, `c00d870b`) fixed these without
changing admission or delivery of stale frames; both failed check receipts
are retained. The subsequent focused test build exposed a distinct native
link failure: pinned `vpx-rs 0.2.1` references the VP9 encoder and decoder
dispatch symbols even though the product selects VP8, while the reviewed R2
recipe had disabled VP9. It executed zero tests. QA-only `db30cc5d` enables
VP9 in the same exact upstream 1.17.0 static source build and requires the
four VP8/VP9 dispatch symbols in the private archive. Unique native R3
receipt SHA-256 `9fc5e10401ab90610f73d861be388c15e3ea09168e4690eaae3d7ad3599b92ec`
records successful configure/make/install/symbol checks and `libvpx.a`
SHA-256 `bea5d11baa7fe966c3776c29ace565ba7d89143fd929bd383d6985c726e51374`.
This corrected native receipt still needs independent review.

At clean source `db30cc5d`, offline Darwin arm64 `cargo check --all-targets`
for all three opt-in crates passed, and the focused tests executed WebRTC
15/15, client 1/1 and server 12/12. Receipt
`/private/tmp/aegis-b08-sfu-rust-db30cc5d-r4-result.json` SHA-256
`941d28d3f396020d269600aeff2f8507751aeeeba793fa70b97e3cc189e2547f`
binds the exact filtered source manifest, locked features, native R3, raw
logs and SHA-256 of three disposable Mach-O arm64 test binaries. The first
two compiler failures and VP8-only linker failure are retained under unique
attempt names. The Cargo target was retired after recording those hashes.
These tests are local component checks; no real LiveKit, installed SFU,
packaged native notice/SBOM, independent target network or final CI ran.

The LiveKit SDK extracts the remote track SID from the packed media stream ID
`publisher-identity|TR...` before falling back to the media track ID. Source
`b2143aa6` binds either form to the already authenticated opposite broker
identity and exact `TrackInfo.sid`; ambiguous/mismatched stream identities
refuse. The [primary SDK source](https://raw.githubusercontent.com/livekit/client-sdk-js/main/src/room/utils.ts)
defines that extraction. This is an interop source correction, pending a real
LiveKit RTP run. Source `b8766e53` adds a private manifest-driven local runner
that launches the public opt-in client/server and pinned LiveKit 1.13.9 binary,
checks a broker wrong key and one-use replay, a positive VP8/inner-TLS target
with 35 seconds of silence and FIN, plus separate wrong-key, revoked-device
and wrong-ICE client fixtures with zero target opens. At that checkpoint the
old verified LiveKit binary was absent and needed exact-SHA reacquisition.
Its three source controls passed only
after a first sandbox-blocked loopback attempt; **no real LiveKit or Rust test
ran**. The wrong-ICE fixture must cause a nominated-path failure while its
signaling endpoint remains permitted, or it is a configuration refusal only.

The later local-runner source `5f65d614` closes three evidence gaps before
execution. It starts an independent 180-second watchdog before listeners,
parks each child until its PID/start identity is in the rollback ledger, and
requires exact listener-owner and after-stop PID/port proofs for all children.
The private fixture must match the exact Git HEAD, `Cargo.lock`, changed-source
manifest, independently reviewed opt-in client/server binary digests and a
successful pinned native-libvpx receipt. The client emits only fixed refusal
stage tokens; the three negatives require their distinct broker, inner-device
TLS or media-negotiation stage along with zero target opens. Seven source-only
Python controls passed on macOS after checkpoint. No full LiveKit run, native
build or SFU Rust test was performed. The future fixture must supply a real
independent `aegis_sfu_local_build_review_r1` with `local_test_eligible=true`;
the runner's checks alone do not independently grant acceptance.

The later `sfu-livekit-fixture-r1.py` source prepares a fresh owner-only local
CA, product-issued normal and revoked device identities, broker role keys,
LiveKit API material and exact loopback client/server TOML only after the
independent native/build and Git-source pins pass. WSS binds an IPv6 loopback
socket and verified `localhost` certificate while ICE allows a separate IPv4
candidate. A wrong-ICE variant keeps the WSS endpoint valid but excludes that
candidate; a wrong-CA variant must refuse at the pre-JWT `sfu_signal` stage.
The old October LiveKit executable was removed. Official LiveKit v1.13.9
[release assets](https://github.com/livekit/livekit/releases/tag/v1.13.9)
provide Linux and Windows archives, no Darwin archive. The exact macOS binary
was recovered from the official Homebrew `1.13.9` arm64 Tahoe bottle at formula
commit `91fb23531243457e71c8ee36c036fbf1f904241e`. Bottle SHA-256
`187222af8a72c8d4c7c00134650a7c1d68b44be77d9078d6487a6f17f1cf1be9`
and extracted executable SHA-256
`fd1d383314bcca0f389d4e0edd1b882e1adec859b7fc2cdbcad5fd6b8429c48c`
were independently recomputed without running or installing it. The private
hash-only recovery receipt is `/private/tmp/aegis-livekit-bottle-20261101/recovery.json`
(SHA-256 `8a9a88677f0abd8471ae25118e94556e589dc4e23f97cefe5b5ea680a712f99f`).
The generator and all private fixture material remain unexecuted; the separate
native component result above gives no Rust or real SFU media PASS.

The fixture-only successor `5b017435` corrects a deterministic wrong-CA
SOCKS port mismatch. The rendered fifth client listened at `base+8`, which is
the LiveKit UDP port, while fixture metadata sent the runner to `base+9`.
One explicit per-label offset map now drives both rendered TOML and metadata;
wrong-CA uses `base+9` and LiveKit UDP retains `base+8`. A generated-config
control parses all five client TOMLs and compares each `listen` to the runner
address. The selected local module passed 10/10; a separately named complete
three-module source run passed 17/17 on exact checkpointed source. Source
manifest SHA-256 `5a02e852f17aa80cf2a84f145405c98dcf238c30384c83a2f1e215e394428aef`
and complete control receipt SHA-256
`dcfa7f1fc1c6192f2414674d1be2080ef258595ad0278973bde32228c4a3844e`
are retained outside Git. This fixes QA wiring only; no product Rust,
LiveKit process or installed path ran.

## 1 November 2026 — optional native SFU media source candidate

Isolated branch `degree/b14-sfu-worker-20261101` at `2cc74d0a` introduces
`sfu-media-vp8` as an opt-in native feature. The existing one-use broker
descriptor is consumed before the private self-hosted LiveKit token/Join;
the new server-internal worker drives VP8 RTP publisher and subscriber peers,
checks the selected numeric UDP path and exact opposite track, then feeds
authenticated bounded media bytes to the existing inner device TLS/lease and
target-policy handler. Lost frames retransmit the original sealed AEAD wire.
The one-use grant expires within 30 seconds for setup; a consumed media stream
has a distinct five-minute bound and emits authenticated two-second silence
frames so an idle application is not mistaken for a dead video publisher.
This branch has **zero executed Rust tests and no installed runtime**. Its
optional VP8 dependency entered an isolated metadata-only lockfile renewal at
`9af60592`, but not shipping notices. The
signaling wire still carries SDP rather than a client media descriptor, and
no installed client consumes the media grant. The internal worker has no
product dispatch caller; `SfuMedia` remains `UnsupportedSfu`. Real LiveKit
SDP/ICE/RTP and a greater-than-30-second silence run, native libvpx package
checks, independent review, restricted
network and exact-final CI remain open. B-08 **NO-GO**.

The later isolated `7f7f68b6` source adds a separate broker-TLS media
Begin/Claim/Take protocol. The legacy direct-WebRTC SDP listener rejects these
operations. Only the admitted client role receives a zeroizing one-use token
and media key; the server keeps its signing secret and claim custody. An
explicit `sfu-media-vp8` build/config path then joins both LiveKit media roles
and carries the client's existing inner device TLS through the shared VP8
worker. Ordinary product defaults and package features still leave
`SfuMedia` unsupported. The full successor has **zero executed Rust tests**,
no real LiveKit media session, no native libvpx package/notice evidence, no
installed probe and no independent restricted-network result. Source review,
compile/negative tests, wire cancellation, silence beyond 30 seconds and
packet admission remain required before any acceptance claim.

Build the explicit optional carrier in both peers:

```sh
cargo build --locked -p aegis-client -p aegis-server --features aegis-client/webrtc-carrier,aegis-server/webrtc-carrier
aegis-server webrtc --config /absolute/private/server-webrtc.toml
aegis-client webrtc --config /absolute/private/client-webrtc.toml
```

The native client offers a bounded loopback SOCKS TCP listener. It verifies the
signaling broker certificate and name before transmitting its separate admission
key, then negotiates a real ordered reliable ICE/UDP, DTLS and SCTP DataChannel.
The existing device mTLS, authorization lease, target policy and TCP forwarding
run inside that channel. A broker key or successful DTLS connection alone never
authorizes a target. SOCKS UDP ASSOCIATE is explicitly refused in this command.
The generic authenticated carrier seam can carry existing datagram framing.
The local listener requires an existing private RFC 1929 credential before
binding. Prepare the consumer separately from broker admission and device TLS;
see [local sidecar authentication](local-sidecar-auth.md).
Live revocation applies when a dynamic device registry is configured; a static
certificate pin list does not provide the dynamic registry's revoke mechanism.

This is an owned protocol inspired by temporary WebRTC intermediaries. It does
not interoperate with Tor Snowflake. The broker is bounded framed TLS RPC, not
an HTTPS website. The ordinary site and HTTPS transport are supplied separately
by the HTTPS bridge and web-response carrier. An operator must make signaling
and the selected intermediary reachable; rotation or WebRTC alone cannot create
reachability through an IP allowlist.

The server example references an existing exclusive relay TLS/device-policy
file with absolute certificate, key, CA and registry paths, empty bearer tokens,
closed fallback, disabled public bundles and `[transport] quic_required=false`.
Omit `quic_listen` and `https_bridge` in that separate policy file.

```toml
relay_config = "/absolute/private/aegis-server.toml"
signaling_listen = "127.0.0.1:8448"
client_key_file = "/absolute/private/broker-client.key"
intermediary_key_file = "/absolute/private/broker-intermediary.key"
max_sessions = 8

[runtime]
bind = "127.0.0.1:0"
connect_timeout_ms = 10000
stall_timeout_ms = 5000
max_lifetime_ms = 300000

[runtime.ice]
mode = "loopback"
```

Client configuration:

```toml
listen = "127.0.0.1:1088"
local_socks_auth_file = "/absolute/private/local-socks-auth.json"
signaling_addr = "127.0.0.1:8448"
signaling_name = "broker.example"
signaling_ca = "/absolute/private/broker-ca.pem"
signaling_key_file = "/absolute/private/broker-client.key"
idle_timeout_ms = 60000
max_sessions = 8

[inner_tls]
server_name = "inner.example"
server_ca = "/absolute/private/inner-ca.pem"
cert = "/absolute/private/device.pem"
key = "/absolute/private/device.key"

[runtime]
bind = "127.0.0.1:0"
connect_timeout_ms = 10000
stall_timeout_ms = 5000
max_lifetime_ms = 300000

[runtime.ice]
mode = "loopback"
```

These are inert illustrative addresses and file names. Both broker role keys
must be distinct nonzero 32-byte values stored as 64 hex characters in separate
private files. They must differ from TLS/device keys. Existing private-owner,
trusted-parent and Windows ACL readers enforce custody before dialing/binding.
No key or TURN credential is accepted as a command-line value. Credential/SDP
errors are redacted. Both peers require port-zero UDP binding for independent
concurrent sessions. Server signaling connections and device workers are capped,
admission expires, and Ctrl-C cancels owned sessions. Unix also supports SIGTERM.
These opt-in commands do not implement a Windows SCM service-stop consumer.

An exact ordered FIN authorizes a clean read EOF; an aborted channel never does.
Cancellation sends a best-effort terminal error before bounded cleanup. After
both halves finish normally, the driver remains alive for at most 500 ms (and
never beyond its remaining session lifetime) to service delayed SCTP
acknowledgements. This cleanup allowance does not guarantee delivery for
arbitrary network delay or loss. The send acknowledgement wait still has its
configured stall deadline; exceeding it fails the session.

`direct_intermediary` explicitly admits configured numeric `allowed_peer_ips`.
It reveals the peer address to the network. There is no automatic public STUN.
The selected direct ICE pair must also report the configured local bind IP;
the remote allowlist alone cannot admit a different local candidate. The focused
source test passed 1/1 on 2026-10-13. A full local suite attempt passed five
methods and failed three real UDP negotiations; an independent loopback UDP
bind probe returned `EPERM` in that sandbox. Keep those three failures as an
environment-limited attempt. A separate authorized local-UDP retry on source
`ab89c5b0111a53b4b6d9e150fc62085a828c523e` passed the full suite:
8/8 unit methods (including all three real UDP methods) and 2/2 integration
methods (including actual TURN-only relay bytes). This is a local carrier
check, not installed or independent SFU/serverless acceptance. The [failed
B-08 attempt](evidence-archive/testing/2026-10-13/B08-direct-ice-bind-r1/)
and successful retry (`evidence-archive/testing/2026-10-13/B08-direct-ice-bind-r3`)
retain distinct logs and source hashes.
`relay_only` instead requires an explicit set of numeric `allowed_relay_ips` and
one to four operator-provided UDP TURN servers; it forbids host/srflx fallback
and verifies the nominated pair before returning an application stream:

```toml
[runtime.ice]
mode = "relay_only"
allowed_relay_ips = ["192.0.2.10"]

[[runtime.ice.turn]]
endpoint = "192.0.2.10:3478"
username_file = "/absolute/private/turn-user"
password_file = "/absolute/private/turn-password"
```

The documentation address does not designate an active TURN provider. Its
credentials must be independently provisioned in separate private files; no
cloud resources or public relays are implicitly allocated. A TURN DataChannel
is not traffic embedded in a permitted media call. `sfu_media` rejects before
socket creation because a real provider media/codec adapter is still required.
Protozoa/SFU operation remains unimplemented until that adapter and actual
service-mediated traffic are verified.

For B-08, the owner requires nonproprietary services. A self-hosted open-source
SFU with real media tracks is under evaluation; managed proprietary call and
serverless services are outside the selected direction. `SfuMedia` currently
refuses before socket creation. An actual codec/media adapter and evidence that
Aegis bytes traverse those tracks are still required. The web-response carrier
now has an atomic session-ledger interface and a reviewed PostgreSQL adapter,
but no hosted restart/recovery acceptance. No service has been provisioned
and no independent restricted-network carrier has passed.

A 13 October B-08 provider pilot proposal (`evidence-archive/testing/2026-10-13/B08-provider-options-r1/receipt.md`)
included Cloud Run and Firestore. It is superseded by the nonproprietary service
requirement; no such cloud resources were created. Read-only inventory will
identify a suitable existing host before a self-hosted deployment or independent
restricted-network test. The
source review (`evidence-archive/testing/2026-10-13/B08-sfu-media-design-r1/receipt.md`)
found no local Opus encoder/decoder; current WebRTC RTP/Opus packetization
alone cannot prove that arbitrary Aegis bytes survive a lossy media track.
DataChannel traffic and synthetic framing do not count as SFU media PASS.

The open-source pilot inventory (`evidence-archive/testing/2026-10-13/B08-open-stack-selection-r1/receipt.md`)
proposes self-hosted LiveKit media, Knative/K3s request-driven web runtime,
PostgreSQL session fencing and Caddy public TLS. All six supplied VPS have one
vCPU and active Aegis/observer roles; none is an unused suitable combined pilot
host. Read-only SSH used existing keys, and no relay, DNS or firewall changed.
Dedicated capacity and independently verified direct DNS/TLS are still needed
for hosted acceptance. The PostgreSQL adapter receipt (`evidence-archive/testing/2026-10-13/B08-postgres-ledger-r1/receipt.md`)
binds a source-only implementation and three real disposable PostgreSQL 16
integration methods; it does not show a hosted ledger or carried media. The
SFU media codec remains unimplemented.

An isolated local LiveKit media-track smoke (`evidence-archive/testing/2026-10-13/B08-livekit-opus-local-r1/receipt.md`)
sent an unpredictable eight-byte binary payload between two participants
through a self-hosted loopback SFU and actual audio tracks. A blind sync,
length and CRC decoder recovered matching bytes and SHA-256; the receiver's
stats reported Opus at 48 kHz and PT111, with direct server version readback.
Source inspection found no DataChannel API in the harness. Its slow FSK prototype
lacks authenticated stream framing, reliable delivery and outage handling, and
is not connected to `sfu_media`. A hosted service and independent restricted
network test are still required.

A distinct native Rust SDK R3 on macOS ARM64 repeated the blind eight-byte
exchange using `NativeAudioSource` and `NativeAudioStream`. Its retained binary
hash matched the receipt; same-run track IDs, payload hashes and receiver
`audio/opus` 48 kHz/PT111 statistics matched. Failed Rust API and Objective-C
linker attempts remain retained, and an independent re-review found no P1/P2
for this local smoke. It does not implement Aegis `sfu_media` or prove a
reliable authenticated stream.

The later isolated R19 close-only fixture (`evidence-archive/testing/2026-10-13/B08-livekit-opus-r19/receipt.md`)
delivered one unpredictable authenticated byte through local LiveKit/Opus and
completed both FIN/ACK directions without injected loss. The separate
R20 first-ACK-loss run (`evidence-archive/testing/2026-10-13/B08-livekit-opus-r20/receipt.md`)
recovered a dropped DATA ACK through a retry and duplicate re-ACK with one
application delivery, but its final reverse FIN ACK did not assemble through
Opus before three retries; the process exited 1. Both outcomes remain
isolated from product `sfu_media`. R20 is a failed reliability test, and
hosted/independent restricted-network acceptance remains open.

The independently source-reviewed R21 salted-retry fixture (`evidence-archive/testing/2026-10-13/B08-livekit-opus-r21/receipt.md`)
passed 15/15 unit methods and strict Clippy, then completed the local
first-DATA-ACK-loss run: two DATA retries, duplicate re-ACK without duplicate
application delivery, both FIN ACKs authenticated, both workers `Ok(())`.
The byte and session identities matched. Salt changes the physical Opus
encoding of a repeated authenticated frame; R20's missing chunk supports,
but does not prove, that this was the causal fix. This one-byte fixture has
not been adopted into Aegis `sfu_media`, keyed from the real connection or
tested on an independent restricted network.

A reviewed R22 timing and ownership audit (`evidence-archive/testing/2026-10-13/B08-sfu-product-boundary-r22/receipt.md`)
found the current FSK/Opus modem cannot satisfy the canonical 30-second
connection cap: complete emission of a 53-byte authenticated DATA frame and
52-byte ACK totals 54.46 seconds, with a conservative causal floor above
54 seconds before inner mTLS. The one-byte R21 local run took roughly
405 seconds. No media-session descriptor/key owner or protected inner-mTLS
handoff is present. `sfu_media` must continue to refuse until a faster
measured modem and authenticated key/transport ownership exist.

An isolated R23–R25 local video-media fixture (`evidence-archive/testing/2026-10-13/B08-livekit-video-r23-r25/receipt.md`)
tested the faster LiveKit video-track route without changing Aegis source.
R23 delivered 64 fresh random bytes in one decoded frame with matching SHA-256
and 0.454 seconds total local elapsed time. R24 at 33 ms frame pacing failed:
15/17 packets in 15 seconds, missing indices 12 and 16. R25 at 100 ms
pacing recovered 17/17 distinct packets and 1,054 random useful bytes in
6.156 seconds total, including 5.773 seconds of media delivery; the exact
SHA-256 matched. A reviewer verified the byte accounting and found no P1 for
this best-effort local scope. The observed `video/VP8` codec record lacks an
inbound-RTP `codec_id` join, the absence of DataChannel calls is source
inspection, and frame repetition supplies no ACK or retransmission guarantee.
The high-contrast pixel grid is visibly data-like. AEAD, replay/loss handling,
real SFU descriptor and key owner, inner mTLS, product bridge, installed
behavior and independent restricted-network acceptance remain absent.
R22's Opus timing NO-GO remains valid for that modem, and product `sfu_media`
continues to refuse.

The independently reviewed R26 local video AEAD fixture (`evidence-archive/testing/2026-10-13/B08-livekit-video-aead-r26/receipt.md`)
then delivered 1,000 fresh random bytes in 23 authenticated DATA frames with
23/23 reverse ACK bitmap entries and exact SHA-256 in 4.213 seconds to the
last observed control. The first source pass skipped index 3, sent 7 before
6, and repeated 0; B observed 7 before 6, recovered 3 and deduplicated 0.
A separate wrong-key run produced 43 AEAD refusals, zero delivered chunks,
and no FIN or close. This is a **one-process fixture** with a fresh internal
key. A FIN, B FIN_ACK and A CLOSE_ACK were observed, but B sent no FIN and
A's close sender reads B's state from shared memory. The 30-second cap covers
setup/protocol loops, not stats and teardown; the 4.213 seconds is measured
to B's final observed control, not process completion. The `video/VP8`
record still lacks an inbound-RTP `codec_id` join. Review found no P1 for
the narrow local result and P2 claim/adoption limits for close/deadline and
reusable nonce/session lifetime. The high-contrast grid has no traffic
indistinguishability proof, and real key ownership, independent peers,
inner mTLS, product bridge, installed and restricted-network acceptance
remain absent. `sfu_media` stays fail-closed and B-08 **NO-GO**.

The R27 successor receipt (`evidence-archive/testing/2026-10-13/B08-livekit-video-r27/receipt.md`)
binds two independent local child processes to exact source, raw logs and
exits through a checked manifest. They delivered 1,000 random bytes with
23 authenticated reverse ACK entries and matching SHA. B actually received
index 7 before 6 after A waited for ACK7; a skipped first-pass index 3 was
recovered and duplicate indices were deduplicated. Both peers saw their
own FIN acknowledged, A saw B CLOSE_READY, and B saw A CLOSE_ACK. The
final positive ended child exits 0/0 in 4.699 seconds inclusive of stats,
disconnect and child exit; the final wrong-key run ended expected child
exits 1/1 with B's 50 AEAD refusals, zero delivery, in 6.782 seconds.
An earlier R27 attempt failed its receiver-order assertion and is retained.
Independent review found no P1/P2 for this exact narrow local fixture.
The soft 24-second process deadline and cleanup budget do not formally
watchdog all parent postprocessing within 30 seconds. A alone cannot know
B saw the final CLOSE_ACK; the combined child logs prove B did. Both
processes received key/room from one local orchestrator, without product
key exchange, inner mTLS, Aegis adapter, installed or independent network
acceptance. The visible grid and unbound codec record retain the earlier
traffic and codec evidence gaps. `sfu_media` stays fail-closed.

The isolated R30 media-codec receipt (`evidence-archive/testing/2026-10-13/B08-media-codec-r30/r30-prod-seam/receipt.md`)
preserves an inert Rust frame/pixel-grid proposal and earlier failed
R28 (`evidence-archive/testing/2026-10-13/B08-media-codec-r30/r28-prod-seam/receipt.md`)
and R29 (`evidence-archive/testing/2026-10-13/B08-media-codec-r30/r29-prod-seam/receipt.md`)
candidates. R28's repeatable constructor risked AEAD nonce reuse and optional
replay filtering; R29 consumed a role-bound descriptor into a single sender
and integrated replay classification into the receiver. R30 corrected
key-slice types, compiled the exact source in a **minimal dependency crate**,
and passed **4/4** codec unit methods. An independent narrow review found no
P1/P2 for that inert seam. The full `aegis-webrtc` crate and a Rust LiveKit
adapter did not compile or run for R30. There is no owned-broker unique
session/key/role issuer, room/token/track custody, checked media peer
identity, completed 30-second secure-connect integration or installed
acceptance. The proposal was **not adopted**; both runtime and ICE policy
still return `UnsupportedSfu`, and B-08 remains **NO-GO**.

The R31–R33 owned-broker successor (`evidence-archive/testing/2026-10-13/B08-owned-broker-r33/r33-owned-issuer/receipt.md`) is now applied to canonical source as an **inactive issuance seam**. R31 was held after review found that Poll could remove an accepted Answer before media reservation. R32 added a media-only broker transaction that reserves the role-bound descriptor before publishing Answer under the pending lock; direct WebRTC Answer is unchanged. R33 tests both Cancel→Poll and Poll→Cancel explicitly and refuses still-unissued descriptors after cancellation. Isolated full-crate focused broker **2/2** and codec/issuer **8/8** passed, with the initial low-disk interrupted build retained. Independent R33 review (`evidence-archive/testing/2026-10-13/B08-owned-broker-r33/r33-owned-issuer/independent-review.md`) found no P1/P2 for this inert source scope. A take that wins before Cancel remains issued until expiry; the tests do not prove a concurrent race or revoke issued keys. Broker restart uses a new CSPRNG master, and same-session reissue increments HKDF context, but no network route invokes the media transaction or distributes the descriptor. LiveKit room/token/track custody, peer identity, inner mTLS, a 30-second completed connection, installed outcome and independent network proof are absent. Canonical macOS arm64 focused R33 tests (`evidence-archive/testing/2026-10-13/B08-owned-broker-r33/canonical-r1/receipt.md`) passed broker **2/2** and codec/issuer **8/8** against exact source and lockfile hashes; exact successor CI remains pending. Both runtime and ICE policy still return `UnsupportedSfu`; B-08 remains **NO-GO**.

The canonical full-library retry (`evidence-archive/testing/2026-10-13/B08-owned-broker-r33/canonical-r1/receipt.md`) retained a sandbox-only **15/18** run with three UDP `Negotiation` failures. A separate authorized local-loopback run of the same binary passed **18/18**, covering the direct UDP methods without exercising product SFU signaling.

Optional identical `[privacy]` parameters at both peers activate the bounded
authenticated framing described in [traffic-privacy.md](traffic-privacy.md).
This does not establish whole-flow DP, browser indistinguishability or measured
DPI resistance. Run the native local fixture explicitly:

```sh
bash scripts/test-native-web-carrier-contract.sh webrtc
```

The fixture uses actual binaries and disposable loopback endpoints. Keep its
result separate from installed platform lifecycle, independent capture, target
network, production signing, uninterrupted day tests and final release acceptance.

## Exact 79b5 open-source carrier boundary

Commit `79b5d1b8613ccb6b3140b9cd28f323811a3a562a` includes the inactive owned-broker media issuance/codec seam. The R33 canonical receipt (private evidence path `evidence-archive/testing/2026-10-13/B08-owned-broker-r33/canonical-r1/receipt.md`) records focused 2/2 broker and 8/8 codec checks, and the same source-bound local loopback retry passed 18/18 library methods after a sandbox-only 15/18 failure. Self-hosted LiveKit remains local fixture and read-only product-boundary evidence. There is no product room/token/track authority, live `sfu_media` caller, deployed nonproprietary SFU, signed installed media path or independent restricted-network test. B-08 remains **NO-GO**.

## B-08 live fleet capacity recheck, 15 October

The bounded read-only SSH receipt (`evidence-archive/testing/2026-10-15/B08-live-capacity-r1/receipt.md`), SHA-256 `f04fe72900a233ef82b297e5a1307deec8f49ffb72554e9bacfbd617261a03ae`, reached all six supplied hosts using existing keys. Each still has one vCPU and an active Aegis relay/client/observer role; `relay-a` is an active direct relay with `aegis-server` and public 443/TCP plus 8443/UDP listeners. Memory and disk snapshots are not an isolation or throughput benchmark. No service or host was changed, and there is no proven spare capacity for a combined LiveKit/Knative/PostgreSQL pilot. Dedicated nonproduction capacity remains a dependency; B-08 **NO-GO**.

The later R2 point-in-time SSH receipt (`evidence-archive/testing/2026-10-16/B08-live-capacity-r2/receipt.md`), SHA-256 `90227b8be3e6f30c7f4e7f43caf6093d3fb70068ab62cbe701d1d29ddd3af0dc`, used existing key-only verified hosts. The first local command was sandbox denied before reaching a host; the first escalated command reached all six but shell expansion corrupted remote expressions, so only its CPU readback is usable. The correctly quoted retry returned exit 0 on all six. Every host has one vCPU and an active Aegis role; `relay-a` remains a direct relay with 443/TCP and 8443/UDP listeners, not spare capacity. Named LiveKit, K3s and PostgreSQL units were inactive, without proving other names absent. No pilot host/domain, direct DNS or restricted-network vantage was checked, and no service or configuration changed. A dedicated pilot host remains required; B-08 **NO-GO**.

The R2 local LiveKit signaling receipt (`evidence-archive/testing/2026-10-16/B08-livekit-real-join-local-r2/receipt.md`), SHA-256 `fa6d717f2152fa39ea2f5f397e1dddfee3a984395922b24ae9ad67e37d9b52d7`, establishes a separate **1/1** real JoinResponse against a disposable loopback LiveKit 1.13.9 instance, binary SHA-256 `fd1d383314bcca0f389d4e0edd1b882e1adec859b7fc2cdbcad5fd6b8429c48c`. Same-run process/listener readback tied PID 62666 to the binary and TCP 127.0.0.1:17880 before/after the test; the saved test log (`evidence-archive/testing/2026-10-16/B08-livekit-real-join-local-r2/test.log`), SHA-256 `e9d1c89858ab39d3dd03e44302acc2b0c3803dcc64f6e23f9a5a07c2eb970b3e`, records the identity-bound result and sanitized server event. The process was stopped and TCP/UDP test listeners closed. Independent review (`evidence-archive/testing/2026-10-16/B08-livekit-real-join-local-r2/independent-review-r2.md`), SHA-256 `053e9e77f5c31f09c2ce10822e99895f7a1a5cb4ae1c1e8dcc252eae01687f2b`, found no P1/P2 in this local signaling scope and closed R1's same-run process/binary custody P2. R1 (`evidence-archive/testing/2026-10-16/B08-livekit-real-join-local-r1/receipt.md`) remains a preserved, superseded attempt. The test used a local TLS termination/proxy and direct signal methods; it did not exercise installed direct WSS, full product `SfuMedia`, SDP/ICE, publication/subscription, device inner mTLS, deployment or independent restricted-network acceptance. B-08 **NO-GO**.

## B-08 open-source deployment readiness refresh, 15 October

The read-only refresh (`evidence-archive/testing/2026-10-15/B08-open-stack-readiness-r1/receipt.md`), SHA-256 `595c107dc1c17ba805f5d8349d7c846e4155fc9070c9978dd561e99fb1bc3262`, confirms the current runtime still returns `UnsupportedSfu`, while the web renderer emits a one-replica `Deployment` with `Recreate`; the PostgreSQL ledger does not move active H2/TLS sockets and response queues between processes. The prior six-VPS inventory found one vCPU and an active Aegis role per host; this refresh did not recheck live host availability. [Knative's installation guide](https://knative.dev/docs/install/) recommends 6 CPUs, 6 GB memory and 30 GB disk for one YAML/Operator node, or 2 CPUs per node for multiple nodes; these are recommendations rather than Aegis measurements. [LiveKit's token documentation](https://docs.livekit.io/home/server/generating-tokens/) says self-hosted deployments cannot revoke an issued token, so one-use broker issuance needs short JWT lifetime and replay testing. A coupled role-bound grant, real Rust media worker, two-process web ownership/migration, separate nonproduction capacity, direct TLS and independent restricted-network tests remain. No service was deployed or purchased; B-08 is **NO-GO**.

## B-08 PostgreSQL cross-process test source, 15 October

The canonical R4 addendum (`evidence-archive/testing/2026-10-15/B08-crossprocess-pg-r4-canonical-r1/canonical-addendum.md`) binds the **uncommitted** `aegis-web-carrier/tests/postgres_ledger.rs` bytes (SHA-256 `8619d30eeb15ccde3b8e96e57a33dbb9d34bdb5e63f6b28850fc4a0bb7a273cb`) to the independently reviewed R4 test patch. The test remains in the existing `two_connections_fence_claim_advance_and_recover_after_reconnect` method, preserving the workflow's exact three PostgreSQL test names. An **isolated** build listed those three methods, and that one method passed 1/1 on disposable local PostgreSQL with an injected schema name refused before SQL, two child-process sequence checks and zero test schemas left afterward. The matching source bytes are now in the canonical working tree; a distinct bounded Homebrew retry passed strict canonical all-target PostgreSQL-feature Clippy after the retained mixed-cache E0514 failure. Exact final-commit CI has not run. The ledger still fences IDs, owners and sequences without transferring active HTTPS/H2 connections, target sockets or response buffers. `SfuMedia` remains `UnsupportedSfu`; hosted multi-replica response, real SFU media and independent restricted-network acceptance remain open. B-08 is **NO-GO**.

## B-08 open-stack capacity and product boundary, 15 October

The prior open-source stack receipt (`evidence-archive/testing/2026-10-13/B08-open-stack-selection-r1/receipt.md`), SHA-256 `1d5ad7f1d2bb55f5c5b9f3db20a41a7ab9bafea9fd27c974737da55f081085ed`, remains a **read-only proposal** under the owner's nonproprietary-service requirement. Its six-VPS snapshot found one vCPU on each host and active Aegis relay/client/observer duties; the possible Ubuntu client host is committed to B-03 testing and is not free pilot capacity. Separate LiveKit media and Knative/K3s/PostgreSQL capacity estimates are not purchases, measured performance minima or a $10 cost cap. Neither managed proprietary services nor a self-hosted pilot were deployed. Current product `SfuMedia` returns `UnsupportedSfu`; local LiveKit fixtures and an inactive owned-broker source do not provide a real product room/token/track owner, installed media transport or independent restricted-network proof. B-08 remains **NO-GO**.

## B-08 product SFU wire boundary, 15 October

The read-only source audit (`evidence-archive/testing/2026-10-15/B08-sfu-wire-blocker-r1/receipt.md`), SHA-256 `a2fef1987f19bbe427414143a993624ed8bed8292841ae20993ffcb22f758968`, binds exact inspected `9b400512` source and the existing R33/R27/R22 evidence. The owned broker descriptor is private to the process: public signaling serializes SDP operations only, and runtime and ICE policy still refuse `SfuMedia`. Adding a wire response containing just a room and AEAD key would create a bearer credential without a role-specific LiveKit grant, protected issuer secret, pinned SFU TLS identity or Rust media consumer. No patch, service, credential or test was run for this audit. The next source boundary is a distinct authenticated, one-use media transaction and protected self-hosted SFU token owner, followed by a real Rust media worker and inner device mTLS. Until those are independently exercised, `SfuMedia` remains fail-closed and B-08 **NO-GO**.

The isolated R2 preflight receipt (`evidence-archive/testing/2026-10-15/B08-sfu-bootstrap-r2/receipt.md`) adds a bounded private-file reader under a trusted parent descriptor and checks an exact self-hosted SFU `wss` origin/TLS name without exporting credential bytes. Four private-file tests and strict Clippy passed, with an independent no-P1/P2 review limited to this inert preflight. No product token issuer, TLS connection, media worker, hosted service or external packet test ran. R2 is **NOT ADOPTED** into this CI repair source. Its `Cargo.lock` delta makes the prior R10 hash stale; the isolated renewal rehearsal (`evidence-archive/testing/2026-10-15/B08-r2-R10-renewal-r1/receipt.md`), SHA-256 `81b6a73100b39be84fcddfd2355df5a5aeb80eabc8dec958ca8f91f49e046149`, first refused the stale pin and then passed 29 modules/36 pins/39 selectors only when all six related custody files were updated with the source in one patch. Native dispatch stayed closed, 0/39. `SfuMedia` remains fail-closed and B-08 **NO-GO**.

The R3 exact-`7bd3df3` transaction design (`evidence-archive/testing/2026-10-15/B08-media-transaction-r3/receipt.md`), SHA-256 `9ee617a87c8a3cc45d3eed3e9b3614a74d410a4eb93f87a4bd33c333f5141813`, confirms the existing one-use private broker descriptor but no public role/claim-bound media operation or protected self-hosted LiveKit signing-secret owner. A token-only patch would issue grants before authenticated claim custody; a wire-only patch would expose descriptors without a valid SFU grant. R3 specifies a coupled one-use media start/take transaction, server secret custody, pinned TLS and negative cases, but has no code, issued token, live SFU or product media worker. The LiveKit JWT itself cannot be revoked after issuance, so one-use semantics must remain scoped to broker issuance and short-lived grants. No R3 source or R10 pin changed; `SfuMedia` remains fail-closed, B-08 **NO-GO**.

The R4 isolated proposal (`evidence-archive/testing/2026-10-15/B08-media-capability-r4/receipt.md`), SHA-256 `bda24f01f44a4f8c7a1537efa4df5dffa0b33847a4e50f6c0204df078911b33e`, adds server-internal role/claim-authenticated start/take and an opaque, consumed descriptor for an HS256 signer using the R2 protected private-file reader. Internal clock sampling and a 30-second maximum grant address the review's first time/TTL findings; final narrow independent review found no P1/P2 for this inert prerequisite. Formatting and offline locked metadata passed, but the included Rust tests and Clippy were **not executed** because local disk space was insufficient for another build. The R2/R4 `Cargo.lock` change failed old AUTO R10 hashes; an isolated six-file renewal passed the static validator in rehearsal only, with 0/39 native. None of R2/R4 or those pins entered canonical source. No wire operation, client token transport, LiveKit verification, media worker, mTLS or external packet witness exists; JWT replay until expiry remains. `SfuMedia` stays fail-closed and B-08 **NO-GO**.

### B-08 canonical protected media transaction candidate, 15 October

The older R4 paragraph records its historical uncompiled isolated attempt. R5 fixed the `Zeroizing<String>` token-format compile error and added a private `MediaTransaction` that couples the existing broker's exact intermediary key/session/claim reservation and role-specific one-use take with a protected self-hosted signer. A failed signer spends that broker descriptor; it cannot mint a second token by retrying. The R5 receipt (`evidence-archive/testing/2026-10-15/B08-media-transaction-r5/receipt.md`), SHA-256 `8753f303742053d5ab716225ae159a9879b6a73af41f079d40f140f648e897fb`, preserves the first compile failure, then exact isolated **6/6** focused tests and strict all-target server Clippy. Independent review (`evidence-archive/testing/2026-10-15/B08-media-transaction-r5/independent-review.md`), SHA-256 `eed9d6cc4957b3105b17de8d8bf0b3d51c26d4bac2134290c8788fe19acafc6b`, found no P1/P2 in this inert R5 delta.

R2, R4 and R5 patches applied cleanly in that order to the uncommitted canonical source, with matching tested source/lock hashes in the canonical addendum (`evidence-archive/testing/2026-10-15/B08-media-transaction-r5/canonical-addendum.md`). No current-source Rust build or final-commit CI has run after application; AUTO R10 pins must be regenerated for the final source/lock in the same commit. This module is private and has no signaling-wire token response or product caller. The `SfuMedia` runtime/policy branches remain `UnsupportedSfu`; no token or key is transported to a client, no actual self-hosted LiveKit verifier/join or pinned TLS media connection ran, and no media worker, inner mTLS, installed or independent restricted-network result exists. JWT replay remains possible until its short expiry. B-08 remains **NO-GO**.

The distinct R4 bounded compile receipt (`evidence-archive/testing/2026-10-15/B08-media-capability-r4/bounded-compile-r1.md`), SHA-256 `a7a9f15cac9f18708ab9c10cf8a6a6bf92514c94c6e2794d2ae3f948225a59cd`, preserves a first `E0514` mixed-compiler failure, then a matching-rustup retry stopped by its free-space watchdog at 12,836,720,640 bytes before the server method. Strict Clippy was refused at disk preflight. No Rust test or Clippy result was inferred from dependency compilation; no shared target was deleted.

### 2026-10-15 R6 pinned open-source SFU TLS prerequisite

R6 `sfu_bootstrap.rs` SHA-256 `ac41f26a1edaf6e7310d64423da29e0c6fe20b69363198999517e47c052d8231` is in the uncommitted candidate. The receipt (`evidence-archive/testing/2026-10-15/B08-pinned-sfu-tls-r6/receipt.md`) records the first explicit-rustls-provider failure, corrected isolated **7/7** tests, strict server Clippy and independent no-P1/P2 static review. A protected DER root and exact WSS DNS name authenticate a bounded direct TLS handshake; this is a future self-hosted SFU connection prerequisite, not a WebSocket, JWT handoff, LiveKit join or media track. `SfuMedia` remains `UnsupportedSfu`; no production SFU acceptance or independent restricted-network outcome follows. B-08 **NO-GO**.

### 2026-10-15 R7 broker-authorized direct WebSocket handshake

Reviewed R7 patch (`evidence-archive/testing/2026-10-15/B08-sfu-signal-r7/sfu_bootstrap-r7-reviewed.diff`), SHA-256 `898a0468325840434df99c32558738319004e9a7e46bc818fb6792759b6e42a3`, entered uncommitted `aegis-server/src/sfu_bootstrap.rs` SHA-256 `09a5df53911c3a6b9ebf42cecb981ce7644af5dc70dbbb52fcc19e2a1f8e648a`. It consumes a private broker-issued descriptor, checks issuer instance and monotonic expiry, connects with the R6 pinned root/DNS TLS identity, then sends an exact `/rtc?protocol=9` WebSocket upgrade with JWT only in `Authorization: Bearer`. TCP, TLS and upgrade each have a five-second bound. It returns an authenticated handshake capability while retaining descriptor/socket ownership; no token enters URI, Debug or returned error.

The isolated corrected receipt (`evidence-archive/testing/2026-10-15/B08-sfu-signal-r7/receipt-reviewed-r3.md`), SHA-256 `4d1a311140de6e72e0f8c0be2142029fa128b61a9d2534f1aa054f6a1ce6e09a`, preserves an initial Clippy `result_large_err` failure and an intermediate review finding that a test callback no longer inspected the server-received request. R3 restored exact received path/query/Bearer assertions and a test-only reasoned lint expectation required by the tungstenite callback API. Local fake TLS/WebSocket focused **1/1**, full `sfu_bootstrap::tests` **7/7**, strict all-target server Clippy and rustfmt passed in isolation; independent review (`evidence-archive/testing/2026-10-15/B08-sfu-signal-r7/independent-review-r3.md`), SHA-256 `4c6367b25470fd02ab49176a274585b1c5ec63a9148ad3e79f9f354a26c0f296`, found no P1/P2 in this limited scope. There is no separate negative HTTP response fixture, though invalid received request fields fail the positive test before 101. Fixed `protocol=9` remains unverified against a selected exact LiveKit build.

HTTP 101 does not parse or verify `JoinResponse`, prove room admission, ICE/track media, inner device mTLS, or enable the product `SfuMedia` path. No real LiveKit service, hosted client, restricted network or independent media capture was tested. B-08 remains **NO-GO**.

## B-08 R7 Windows ARM64 source compatibility, 15 October

The local cross receipt (`evidence-archive/testing/2026-10-15/CI-windows-R7-cross-r1/receipt.md`), SHA-256 `0830543b636735f1115e0efb1d9f7896e00e9383562f95a9f2a3efd9a1d3f4d9`, binds the uncommitted pinned-TLS/WebSocket handshake source to Windows ARM64 MSVC user-mode `cargo check`. Three local setup attempts failed before typechecking; after supplying the existing `clang-cl`, xwin SDK/CRT includes and Ninja generator, attempt 04 (`evidence-archive/testing/2026-10-15/CI-windows-R7-cross-r1/attempt04.log`), SHA-256 `c651cdcc046815d6a17f108903506e605812560c3bfb3d76d89ebd76fb207dea`, completed **exit 0** for client, server and winctl with the documented TLS/QUIC/WebRTC features. No Windows native execution, product `SfuMedia` dispatch, parsed `JoinResponse`, deployed SFU or hosted exact-final-commit CI follows. Windows product work remains frozen and B-08 **NO-GO**.

## B-08 R8 bounded JoinResponse source preflight, 15 October

The reviewed R8 patch (`evidence-archive/testing/2026-10-15/B08-join-r8-canonical-r1/B08-R8-join-response.patch`), SHA-256 `0160e94b4adfe2aed52cbe03dce55323587123fea4e6eda250788d00cebf8bad`, is applied to uncommitted canonical `aegis-server/src/sfu_bootstrap.rs` SHA-256 `bf23f7a78b39bf4b69b854d02c750d6f5a4ff2a27756b453f0bbfaec7552e85d`, with `Cargo.lock` SHA-256 `4d92846d169a0f476369f2f78ccb8db9d7430da39275cf86c9a8aaeb0ba10177` and locked `prost 0.14.4`. Independent review (`evidence-archive/testing/2026-10-15/B08-join-r8-canonical-r1/independent-review-r1.md`), SHA-256 `66cee4d24ba714384154fb00c61caddb94a835e3d305ea492026d5b8b3094dde`, found no P1/P2 for the inert parse/preflight. Official `livekit/protocol` commit `a9a1bffe6e5ba1465f9ff9bd2334368a9bff7cac` supplied `livekit_rtc.proto` SHA-256 `e152c51d036e06ef02076710ef75ecd6c0db98906ae28abfff152f5a99c1f94d` and `livekit_models.proto` SHA-256 `e91011464e2026276fccd4183dc27e9c11e94ad1a8803efca43725707b50e236`; the checked fields are `SignalResponse.join = 1`, `JoinResponse.room = 1`, `participant = 2`, `alternative_url = 7`, Room SID/name and ParticipantInfo SID/identity. The decoder rejects another oneof, second field, oversized/nonbinary frame, timeout, missing identities, broker mismatch and redirect URL. It applies a 64 KiB local join bound inside the existing 256 KiB WebSocket cap and a five-second first-read deadline. Bearer JWT stays in the authenticated request header; first-frame-only policy currently refuses server control/text before binary Join.

The isolated receipt (`evidence-archive/testing/2026-10-15/B08-join-r8-canonical-r1/receipt.md`), SHA-256 `c80fd15e99d62cc47b5f210ab55548ffeaf7a2432376dbcca8afddfbed69cd44`, retains a first Clippy failure on test-only `useless_conversion`, an initial formatting correction, and subsequent isolated **7/7** module/strict Clippy PASS. On canonical source, focused module (`evidence-archive/testing/2026-10-15/B08-join-r8-canonical-r1/focused-attempt-01.log`), SHA-256 `c429b9edf842ec7f7a812b8b1af6e6d04e2681aaf0fb84f7a13a30a8cfe052cb`, passed **7/7**; strict server Clippy (`evidence-archive/testing/2026-10-15/B08-join-r8-canonical-r1/clippy-attempt-01.log`), SHA-256 `38d91e57f493ca0a569535d660ef83698c4bbac59fde35e0f7c0b90374938e87`, and format passed. All six AUTO R10 source/lock pins were renewed in the uncommitted tree; static 39-selector custody passed with dispatch closed, **0/39 native**. A later Windows R8 cross-check (`evidence-archive/testing/2026-10-15/CI-windows-R8-cross-r1/receipt.md`), SHA-256 `bf5db89eaeec192974d868373eea08bf37c1264c6de3367076f527a3b08562be`, passed local Windows ARM64 MSVC user-mode `cargo check` exit 0 (raw log (`evidence-archive/testing/2026-10-15/CI-windows-R8-cross-r1/attempt01.log`), SHA-256 `d8b01d92046cfe3eafaeb51bb4cab5ad02123e26a2f3823f1dfed483d8ff0c04`); Windows link/native execution and exact-final-commit hosted CI remain open. The mock Join is not a real LiveKit room or media track, and the product `SfuMedia` path still refuses; no SFU deployment, inner device mTLS, packet witness or restricted-network acceptance exists. B-08 **NO-GO**.

The later local verification addendum (`evidence-archive/testing/2026-10-15/B08-join-r8-canonical-r1/verification-addendum.md`), SHA-256 `2623f768d0dc1c326c75c5ccf675d419f5337e3ba96db9d9ef859acc5e6b0f70`, binds full workspace Rust tests **exit 0** (raw SHA-256 `96acf7a0e4cf94304786fe89c20e4247b8196eb90286d2ad3f86f5154582c978`) and strict full workspace Clippy **exit 0** (raw SHA-256 `6fbf9a34c3dec2c324ace87f42e558f286b80c961c0c03aa1854edea84283f96`). The suite marked the two-replica PostgreSQL method ignored, so it was executed separately: attempt 01 failed **exit 101** because the socket output directory under world-writable `/private/tmp` violated the product directory guard (raw SHA-256 `605f8b4df593676d181446a5bc43bd1d5c74fb7b4468d030ddbcf5033c84b8d8`); attempt 02 used a private 0700 child socket directory and disposable database, passed **1/1 exit 0** (raw SHA-256 `2251e862caf9318d2344f0e7b026bea9f935c6e9d021055f4226d217c98880b9`), then stopped PostgreSQL and removed the socket directory. These are local uncommitted-source results; exact-final-commit hosted CI and real SFU acceptance remain open. B-08 **NO-GO**.
### 16 October SignalResponse R2 source-only review

Isolated R2 patch SHA-256 `69fa407742b2d29568e32ca435f01e4347eeb6bb1ad8fb3122039b76012015cf` passed 9/9 parser fixtures and Clippy. Independent review (`evidence-archive/testing/2026-10-16/B08-signal-response-r2/independent-review.md`), SHA-256 `da870a8b6e0947a52a59b08f91a75de41262380f93b7547aced2281a37693956`, found no P1/P2 in this source-only slice: R1's nested LeaveRequest P2 is closed by bounded parsing, duplicate rejection, terminal DISCONNECT handling and fail-closed reconnect hints. R2 is not in canonical source; no product `SfuMedia` SDK caller, applied SDP/ICE, media publication, deployment or restricted-network result followed. The local LiveKit Join R2 evidence above covers only loopback signaling. B-08 **NO-GO**.
### 16 October R4 canonical post-Join response boundary

The adoption addendum (`evidence-archive/testing/2026-10-16/B08-signal-next-r4/canonical-adoption-r1.md`), SHA-256 `5b072521f0391c3a9947d8beb72015fc0d8c3f048c00d28f439873e146bcbd40`, identifies reviewed R4 patch SHA-256 `4ae92c6ec042a4e7c6a4d94c7dc1b144af1d84fab7c42f0803883e749aa06e53` applied to uncommitted canonical `sfu_bootstrap.rs` SHA-256 `dc0a5a13ee48b79a5bb9733c57814d8975ef19cf44d6d2af36f93fa4370dee60`. Independent review (`evidence-archive/testing/2026-10-16/B08-signal-next-r4/independent-review-r1.md`), SHA-256 `d00ca73cca0bbc7f6f3ff15ee0f6898d6ee13487a987126d9bddb0948fb4f27a`, found no P1/P2 in bounded post-Join parsing and terminal socket drop; scratch R1/R2/R3 failures remain in their receipts. The first canonical test command exited 0 with **zero** selected methods because the feature was off. The corrected `webrtc-carrier` command passed **9/9**; isolated strict Clippy passed. R10 was renewed, dispatch remains closed at **0/39 native**. No product `SfuMedia` caller, SDK/room admission, applied SDP/ICE, encrypted media or deployed SFU followed. B-08 **NO-GO**.

### 16 October B-08 one-use signaling composition is source only

The canonical adoption receipt (`evidence-archive/testing/2026-10-16/B08-product-seam-r1/canonical-adoption.md`), SHA-256 `ee95eae08cbb904a1392fb7baae7492671796ef2e0ed1172d16139e403bd84bb`, binds reviewed `MediaTransaction::take_and_connect` to uncommitted `sfu_bootstrap.rs` SHA-256 `d9b39887b963eb4c2273b5e906dcf7f5b9134a86eab7b846cd85212d98a600af`. It consumes the broker role before direct pinned-TLS WebSocket/Join and returns only `AuthenticatedSignal`. Canonical real loopback TLS/WS/Join against a synthetic responder passed **1/1** after a retained sandbox bind `EPERM`; strict server Clippy and format passed. Independent review (`evidence-archive/testing/2026-10-16/B08-product-seam-r1/independent-review.md`), SHA-256 `d34d1664db9a6fb9f81172b02587fe49fb387534208754cbe4f454c09d6350ed`, found no P1/P2 in this inactive composition, while noting P2 for future product privacy: sensitive `HeaderValue` suppresses logging but does not guarantee bearer bytes are erased from memory. This method did not run against real LiveKit or a media track; there is no product caller, installed SFU, packet path or restricted-network witness. `SfuMedia` remains `UnsupportedSfu`, B-08 **NO-GO**.

### 16 October WSS request trace leaks a synthetic bearer under dependency Trace

The later privacy finding (`evidence-archive/testing/2026-10-16/B08-WSS-trace-privacy-r1/receipt.md`), SHA-256 `3185a7b4bc6138fc65d4d211b4b9518958098e7686d7b45d3fa91b84e9db492c`, supersedes any reading of the earlier `HeaderValue` sensitivity note as log protection. Locked tungstenite 0.24.0 serializes the raw HTTP upgrade, then traces the full request; the sensitive flag only redacts `HeaderValue` Debug. An isolated **1/1** test with a harmless sentinel confirmed it appears in the dependency Trace record. No real bearer was used. This is an open **P1 release privacy defect** in the adopted, inactive signaling path, separate from the P2 memory-zeroization limit. Proposed manual private-handshake R2 is scratch with no adoption or PASS; no real LiveKit, media, product caller or installed acceptance. B-08 **NO-GO**.

### 16 October R2 private WSS correction entered uncommitted source

The R2 receipt (`evidence-archive/testing/2026-10-16/B08-WSS-privacy-R2/receipt.md`), SHA-256 `b2323f20a6df15dae69585cd3746fc60d74aaa3fcefd0ed519e4641fcdb29ac3`, preserves an initial sandbox loopback refusal and unused archived-lock audit failure, then 12/12 local TLS/WebSocket and hostile synthetic Trace tests. Independent review (`evidence-archive/testing/2026-10-16/B08-WSS-privacy-R2/independent-review.md`), SHA-256 `08efefd84dd4affe149eb3f5c4bb6222a53526f580866d41a78e162430e0b5b9`, found no P1/P2 for the scoped Authorization/URI/frame log paths. The reviewed application/vendor bytes have been applied to uncommitted canonical source; `sfu_bootstrap.rs` SHA-256 `1ca9e2414395b1a0b33e28a9f27ee24f0df98666f8062d6bd711cb6a02857299`. It constructs a bounded zeroizing HTTP Upgrade over already pinned TLS and patches locked tungstenite Trace/Debug sites to avoid raw bearer/frame output. The canonical adoption receipt (`evidence-archive/testing/2026-10-16/B08-WSS-privacy-R2/canonical-adoption.md`), SHA-256 `b9fba1403e500ff408a46e5330788e2713d65ede3442d869f95ee1ebc9bd58d7`, records selected real-loopback/synthetic privacy tests **12/12**, strict server Clippy, active/vendor audits and R10 pin renewal/check PASS in the same uncommitted source batch. Exact-final-commit CI remains pending. R1's leak remains historical; R2 neither proves total TLS allocator zeroization nor runs real LiveKit media/product `SfuMedia`, installed SFU or restricted-network endurance. B-08 **NO-GO**.

### 16 October vendored tungstenite supply-chain audit is local only

The audit receipt (`evidence-archive/testing/2026-10-16/B08-vendored-supply-chain-audit-r1/receipt.md`), SHA-256 `eacccf2952befca4f64dfe9e810d9735d67513e51176141dac4cf8dd12a7fb04`, found no P1/P2 in the uncommitted B-08 vendor adoption. Offline Cargo metadata resolves both h2 and tungstenite as local patches; cached upstream tungstenite archive identity, 35 source files, four local patches, local license files and active lock/advisory checks passed. Full `cargo-deny`/SBOM tools were unavailable locally, and exact-final-commit CI plus shipping license review remain open. R2 privacy source correction does not activate product `SfuMedia` or prove real media/installed SFU; B-08 **NO-GO**.

### 2026-10-16 — R28/R9/B03 holds, R88 role diagnostic, B08 seam and CI local checks

B-08 [R1 scratch receipt](../../.scratch-b08-product-seam-r1/receipt.md), SHA-256 `907fdc99d719b12513defa290a742fd43e076654559211934105703d4cfcc238`, passed **1/1** real local TCP/rustls/WebSocket/Join with a synthetic responder plus strict server Clippy; first sandbox bind `EPERM` remains. Independent review (`evidence-archive/testing/2026-10-16/B08-product-seam-r1/independent-review.md`), SHA-256 `d34d1664db9a6fb9f81172b02587fe49fb387534208754cbe4f454c09d6350ed`, found no P1/P2 in the new one-use signaling composition but retained lower-path Authorization buffer zeroization P2 and B-08 product-media P1. This scratch method is **not canonical**; `SfuMedia` remains fail closed. No real media, installed SFU or endurance; B-08 **NO-GO**.

### 2026-10-16 — B-08 distinct H2+PostgreSQL network R1

Distinct B-08 H2+PostgreSQL network R1 receipt (`evidence-archive/testing/2026-10-16/B08-h2-postgres-network-r1/receipt.md`), SHA-256 `f9077b2a770bfae920b7016730b9577d09d786026ddacf1c5bcf4937e7791520`, records **1/1 local diagnostic PASS**: two separately owned HTTPS/H2 `Server` objects with separate PostgreSQL connections in **one OS process**, plus a third after stop. Loopback TLS/H2 and PostgreSQL fenced replay, foreign OPEN and stale sequence; this is not two deployed replicas or active stream migration. Earlier offline archive, shared-memory and sandbox socket failures remain distinct; final schema count was zero and disposable PostgreSQL stopped. Independent review (`evidence-archive/testing/2026-10-16/B08-h2-postgres-network-r1/independent-review-r1.md`), SHA-256 `7698b2380caf004683d1f82387bd808545f9e6b1091f999c674456eedaede576`, found **P1**: the enabled scratch test unconditionally needs `AEGIS_B08_DISPOSABLE_PG_DSN`, absent from CI, so verbatim adoption would break ordinary workspace tests; **P2**: panic/timeout can skip schema cleanup or leave tasks unjoined. No canonical adoption, cross-process live continuity, installed service, SFU media or exact-final CI; B-08 **NO-GO**.

### 2026-10-16 — Two-process H2/PostgreSQL R3 candidate

The R3 scratch receipt (`evidence-archive/testing/2026-10-16/B08-h2-postgres-process-r3/receipt.md`), SHA-256 `fef4f527d7291c3d88e708b0ea29d31ba87a5c225950524c74831d8adc64ff47`, and candidate review (`evidence-archive/testing/2026-10-16/B08-h2-postgres-process-r3/independent-review-r1.md`), SHA-256 `8dffee51437dca326635578bfc06cfd94fdd19271d53010d8a0a3237a0dc4c`, record **1/1 scratch** loopback HTTPS/H2 plus inner device mTLS across sequential distinct OS processes, with replay refusal. The injected post-ready failure remains separate **0/1** evidence. Exact patch adoption to uncommitted canonical `aegis-web-carrier/tests/postgres_ledger.rs` SHA-256 `42b581f7afa9a023c223356ba7cce82ff537d5fe569b3fc87be3bf9e3fa7034a` is bound by adoption receipt (`evidence-archive/testing/2026-10-16/B08-h2-postgres-process-r3/canonical-adoption-r1/receipt.md`), SHA-256 `26851354d8d3aa9c05327504e80bc2f0da2d9a208ad5c4ac2b0e005f68a12a95`, and independent review (`evidence-archive/testing/2026-10-16/B08-h2-postgres-process-r3/canonical-adoption-r1/independent-review-r1.md`), SHA-256 `fedf7bab46c3fe78fe93fd5a04e3ce5b803c9d76b6e2f300004dfeaabc9a50b2`. The existing PostgreSQL CI selector passed **3/3 locally**, with format, strict Clippy and R10 pin check PASS; schema/server cleanup passed. A separate sandbox process census failed, so process absence relies on bounded test child-reap checks. No exact-final-commit hosted CI, active-stream transfer, deployed replicas, SFU media or restricted-network proof. B-08 **NO-GO**.

### 1 November — source-bound local LiveKit component batch

The independent source/native R3 review `/private/tmp/aegis-sfu-db30cc5d-independent-source-native-r3-r1.json` (SHA-256 `5085d6033934bb7b3305f42bb6e9d330348b4e87d67556149ad9d4eb7ee9678a`) verifies the predecessor's 2,973 committed source blobs, pinned upstream libvpx 1.17.0 archive and four VP8/VP9 symbols, and the executed 15 WebRTC + 1 client + 12 server focused Rust tests. The exact LiveKit 1.13.9 binary SHA-256 is `fd1d383314bcca0f389d4e0edd1b882e1adec859b7fc2cdbcad5fd6b8429c48c`; it has not been run in this batch.

QA-only `022c21ad` prepares a local positive media/inner-TLS/FIN case and wrong broker key, revoked, wrong ICE, wrong CA, and same-issuer unlisted-device refusals. The new unlisted identity is issued under the same disposable CA into a separate registry; the running server uses only the original registry. Its filtered source manifest SHA-256 is `19d18319f998627d9e026e78e174a2d1e6a12b1df53f43ec122b9798a8b97def`, and source controls pass 17/17. A fresh client/server build and independent exact-source build review must precede fixture generation and full local execution. No full media component, installed, restricted-network, or final-CI PASS follows. Default `SfuMedia` remains Unsupported.

### 1 November — local SFU origin refusals and strict loopback dial

The first local component receipt SHA-256 `67a42379549f2dbf045879779903a544ca6d5aad196efddcf82b2de0eee88fa6` refused the operator's own timing lock before any child. Unique r2 SHA-256 `cd46788f2a2390863d333d4c687a7755e18f7d818ee5445a84a6d90adfcdac4c` ran the exact reviewed LiveKit binary, but the server exited before signaling because the fixture's SFU bootstrap used `localhost` while production admission requires a dotted DNS authority. The watchdog reaped both children and all fixture ports closed; no media path or target was exercised.

Product source `c96c4000` retains the dotted WSS origin and CA/SNI verification while allowing an **optional numeric loopback dial** at the same origin port. It refuses nonloopback addresses and port mismatch. QA `b7c49004` renders `sfu.local.test` in the proxy certificate, WSS origin and client/server TLS name, with `[::1]` as the separately configured dial address. The filtered source manifest SHA-256 is `592e32d5b5f77288077209528190c683664a81eea580c53ce52b8007ae4324e2`; Python source controls pass 17/17. Product Rust tests, a new exact-source CLI build and independent build review, and a unique full local component run remain required. Default SFU remains Unsupported; no installed, CI or restricted-network credit follows.

### 1 November — local LiveKit r3–r5 failures and negotiation diagnostics

Unique r3 (receipt SHA-256 `5f9a467cca8827bd95e08fd06272aca86f7ee9b3c99e41771ab01a4dc5c03259`) refused before client media because its fixture omitted the required `[transport] quic_required=false`. QA-only `75055f8c` renders this exact policy; source controls passed 17/17 and independent QA/binary parity review SHA-256 `dfa537bde17d60d9fd95ff651c1865925a5861071b64cac73f017a54dfc99586` bound the reused `5c9f3f82` binaries. The focused server SFU Rust cohort passed 13/13 and its exact CLI build was independently reviewed (SHA-256 `ed816dabbbc9f8064a48eb142c5dbc8a76af2d83c439db833e432ffa42a9ae26`).

Unique r4 (SHA-256 `be1995f78caad30e2d89b1daade44cc80dc85a7744ca01a1932f1862bef1b586`) reached LiveKit signaling but the first positive client refused before any target open. Static source showed the fixture had bound the server's WSS TCP peer to `::1` while permitting only `127.0.0.1` in its server allowlist; QA-only `4efd818b` admits these two exact local addresses for the distinct WSS and ICE checks. The wrong-ICE negative remains restricted to `127.0.0.2`. Its independent binary/QA parity review is SHA-256 `6d3e22b64e2f36e18a3cfe55c5272ad6398536b87c3601c15b54128c94c72f8c`.

Unique r5 (SHA-256 `c8122d1aff652b8bd308c80ca18b25f1f13ab5b6a9bbc7301660cd0fb6274935`) joined both LiveKit participants, then refused within media negotiation before any target open. Both participants closed almost immediately after the server created a local offer. The exact failed substep is not yet established. In all three attempts, the watchdog reaped all owned children and every fixture listener closed; no positive media packet, full negative suite, installed or restricted-network PASS follows. Clean source `310d61a78e8e8179665d4e1104330a915f6b5b89` adds only fixed, bounded client/server negotiation and peer-offer refusal labels; its 2,973-file filtered Git source manifest SHA-256 is `f1e039d4e30776dd61661dbb9eb1991e7b8f1cd62913997706c49ed40e4fe763`. Rust and real LiveKit execution on that successor remain zero until independent source review and a new binary build. Default SFU remains Unsupported.

## 2 November 2026 — LiveKit field-16 signaling diagnostic

R7c on exact `017480c0` product binaries and pinned LiveKit 1.13.9 observed
outer protobuf field 16, wire type 2, immediately after Join in both WSS
connections. The [official pinned schema](https://github.com/livekit/protocol/blob/a935cd67c29a/protobufs/livekit_rtc.proto#L69-L103)
names it `SignalResponse.refresh_token`. The product accepted only answer,
offer, trickle, participant update, track published and terminal Leave; it
rejected the refresh notice as `unknown` before media negotiation. R7c
component receipt SHA-256 is
`5a81a8878040da29eb9ea874656a77c720d979824aaea027ce974cef76f24e91`;
numeric-only signal receipt SHA-256 is
`449c7403d69136381ead2c10f8b9754bf45c32658b2504cc3d4576e028ec633b`.
Zero target hits, no negative cases reached, all three actors reaped, watchdog
owner completion and closed listeners were observed. Earlier R6 and R7
failures remain retained.

An isolated source successor validates and consumes only the bounded field-16
control notice in client and server; it does not store/use its bearer or renew
the one-use descriptor and deadline. The [field-by-field audit](sfu-livekit-signal-response-audit.md)
records decisions for all official response fields 1–31. Parser tests are
written but unexecuted. No Rust build, subsequent media result, installed
acceptance, independent restricted-network result or CI is claimed.

## 2 November — local R8b and R9 trickle refusals

The R7c field-16 observation led to bounded refresh-token handling in source
`628b41c2`. Its exact VP8 client/server build and client/server parser tests
passed, and an independent build review admitted the new R8b fixture. A prior
R8 fixture was refused at sandbox loopback bind before actors. R8b reached
both LiveKit signaling roles but failed the first positive SOCKS admission:
fixed client and server labels both ended at `step=trickle`, with zero target
opens. Receipt SHA-256:
`4611fdfd85e606cd959c0504093c6e1535a0cd393cd73185fba93520838ae04d`.

The exact RTC dependency returns `ErrNoRemoteDescription` for early ICE
candidates. A source-bound real-peer test reproduced that typed refusal with
an allowlisted numeric UDP candidate. Source `5ae80ad1` queues at most 16
prevalidated zeroizing candidates until their target's remote SDP is set; it
does not relax JSON, numeric UDP, allowed-IP, deadline or selected-ICE checks.
The real-peer queue negatives (wrong IP, TCP, mDNS and excess count), both
refresh-token parser tests, exact VP8 CLI build and independent source/build
binding passed. R9 on a fresh fixture nevertheless failed the same first
positive `trickle` step, zero target opens. Receipt SHA-256:
`5fd502a5c40d74d9ce525bf126deb270170820a673c74994544e2cb165390ffb`.
Both attempts reaped all children, closed ten ports, and completed watchdog
cleanup. No negative media case ran. Early SDP ordering is therefore a real
dependency constraint but not proven to explain the observed LiveKit failure.

LiveKit's local protocol types use candidate JSON with camelCase
`candidate`, `sdpMid` and `sdpMLineIndex`, target 0/1 and an optional final
marker. Static source audit found these names and target values match the
current decoder. Candidate policy still rejects nonnumeric, non-UDP and
non-allowlisted addresses; the actual R9 candidate bytes were not retained.
Source-only `89e48668` adds six finite refusal phase labels and a differential
JSON test for the next local batch. It has no Rust build or runtime result.
The R7c/R8b/R9 receipts and private logs are preserved through separate
SHA-verified permanent custody maps; the public map SHA-256 is
`4ed46ad1377e6f5f81d302dd3e0e7c4c064a8ebb3b9dc5f235f8a9f3950f4265`.
The local attempt budget is exhausted. Default SFU remains Unsupported;
installed media, restricted-network and final CI remain OPEN.

## 2 November — strict loopback LiveKit fixture source

The R9 local fixture allowed only `127.0.0.1` at the client and loopback
addresses at the server but did not request LiveKit to collect loopback ICE
candidates or limit interface IPs. The pinned LiveKit 1.13.9
[configuration sample](https://github.com/livekit/livekit/blob/v1.13.9/config-sample.yaml)
documents both controls independently. QA-only `f7a095b0` renders
`rtc.enable_loopback_candidate: true` and `rtc.ips.includes: 127.0.0.0/8` in
the private local fixture, while preserving the negative wrong-ICE profile.
It changes neither product ICE policy nor any live deployment. The exact
generated-fixture check and all 10 Python controls pass on `f7a095b0`; the
unsandboxed control log SHA-256 is
`84aedaca8b58a083779c1b6599b879636bdc2f9e90d757b4edcd948487808f8d`.
An earlier sandboxed control run failed only at a local loopback bind.

No R9 ICE candidate bytes were retained. The fixture mismatch is a concrete
source inconsistency and a plausible cause, not a proved explanation of the
R8b/R9 runtime refusals. The local LiveKit attempt budget remains exhausted;
source `89e48668`'s finite diagnostic labels and QA `f7a095b0` require a
separately authorized later media window for runtime qualification. Default
SFU remains Unsupported, and installed/restricted-network/CI acceptance
remains OPEN.

QA-only `93cacd93` also rejects a stale local fixture before any LiveKit,
broker or client process starts. Its runner checks the exact loopback
collection and `127.0.0.0/8` rendering against the pinned UDP port and both
roles' numeric SFU allowlists. The retained R9 fixture is refused with the
fixed `local_ice_fixture_refusal` label; a generated current fixture passes.
A focused post-checkpoint Python control passed 2/2 on the two-file source
manifest SHA-256 `695b9b5821283550bf4034eca89a8a94fc1e0a937265dc644ba3c1e8f09d1a8a`.
Independent source review found no product ICE-policy change or private config
output. This closes only fixture admission drift; R9's actual trickle subcause
and all media, installed, CI and restricted-network checks remain OPEN.

Follow-up QA test `8521d321` exercises the public `load_fixture` boundary
with a sanitized full fixture: the historical committed `0c1dee18` runner
admitted the stale R9 YAML, yielding the expected 1/1 red assertion failure
(`ValueError not raised`, receipt SHA-256
`103bdd6d5169f4952070f106c8225c8e9856808e113d0af96a121b5f65d71bbf`).
The corrected runner refuses it and admits the current loopback YAML; three
post-checkpoint focused Python controls pass on source manifest SHA-256
`ab5beb79b2012a971874abb9644de4cf997fc952f848244996c044b344e6398a`.
