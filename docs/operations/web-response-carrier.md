# Owned HTTPS web-response carrier

## D6 simultaneous replica and database outage component

Source `e7c09c27` keeps two real carrier processes alive during the existing
TLS/H2/PostgreSQL integration method; `2e188652` adds a live-database positive
control requiring HTTP 200 and the exact 45-byte OPEN acknowledgment before
the database-stop refusal. The optional cycle then stops the owned database
container at PID 0, requires a fresh valid OPEN to receive the ordinary
private 404 cover, and restarts PostgreSQL only for cleanup. The other three
selected tests cover shared capacity, owner release and sequence fencing.
This tests simultaneous processes, not simultaneous open streams or hosted
replica continuity.

The source-owned operator at `005d9915` pins the clean Git source, filtered
manifest and PostgreSQL image; it requires 42 GiB free to start and 35 GiB
throughout. An independent source review accepted its exact-CID cleanup,
detached guard and process-group closure. It also verifies the complete source
roster again after the tests before reporting a pass. Six inert Python checks passed,
including leader exit with a surviving child and a live TERM-ignoring leader.
The earlier sandbox-only process check failed with `EPERM` on `/bin/ps`; its
authorized local repeat passed. No PostgreSQL container, Cargo build, focused
Rust test, hosted process or deployment was run for this candidate. The
four-test component and installed acceptance remain OPEN.

## 2 November — D6 local PostgreSQL restart and replica component

The first actual component run on clean source `332f4031` passed three of
four selected PostgreSQL methods. The fourth kept two carrier server processes
alive, observed a valid HTTP 200 OPEN before database stop and the private
HTTP 404 cover during the outage, but failed its fresh schema-cleanup connection
after restart. The QA operator had published PostgreSQL on a Docker-assigned
host port that could change on restart; its failed test log SHA-256 is
`765ae328ddb8e2b84c63b31686f24202793d75a7f7dcd55e4e20db19fa555ce0`.
The R1 container stopped at PID zero, the detached guard disarmed and the
timing lock was removed; the failed attempt remains retained.

Test-only commit `eb11d38b` first added an inert stable-port control, and
QA-only `ba363ec4` fixed one explicit loopback host port across container
restart with exact before/after Docker binding checks. The seven-test inert
suite passed, and independent source review returned GO (receipt SHA-256
`e774b47a7a81a3577ff49eac112b4ef7cbd2fc1adf387f738384d7f21147ed96`).
The unique actual R2 on `ba363ec4` then passed all four selected methods
once, including the two-process TLS/H2 witness, valid 200 OPEN, database-stop
404 refusal, restart and explicit schema cleanup. Its result SHA-256 is
`0aa88c9664b52c25429ab4f23c14b07b963e0801e09f88df92c6565952ef4a3e`,
test ELF SHA-256 `5cbb74f1bf5f248ba302c5d314bf8c965aa79ccb81aba27b8ed1df2c395c6dee`,
and private text custody SHA-256
`a1c7498f21fe45bf33da8fdecc3d356aa13c3ef4c2fccf7bef961e6c820f2a46`.
Independent closure checked the owned PostgreSQL container at PID zero,
stopped process groups, absent watchdog and removed timing lock. This is a
local component run, without installed traffic, hosted continuity, media,
restricted-network witness or exact-final-commit CI acceptance.

## Signed installed TCP fallback (source integration)

An enrolled four-member public device profile can declare `web_response` as
the last TCP route after a direct H2, own HTTPS bridge, or authenticated WS
route. The signed `carrier_program.web_response` declaration contains the
bootstrap TLS authority, descriptor path, and one to sixteen permitted ingress
IP addresses. Its route's `endpoint_index` selects the exact numeric bootstrap
socket from `relay_endpoints`. The private identity directory separately holds
`web-response.toml` with the same public fields and an absolute
`credential_file` path. The admission key remains a distinct private 64-hex
file; neither it nor its path belongs in the public profile. Missing, changed,
or aliased private fields refuse before dialing. A discovered descriptor may
redirect only to a signed ingress IP.

The installed secure client uses the existing `aegis-web-carrier` descriptor
and stream, then performs the same inner device TLS, PolicyAck, target request,
and live target authorization as the other authenticated TCP routes. Carrier
failure may advance to the next signed route only before device authentication;
target or payload failure cannot replay. The existing `aegis-server carrier`
command is the server-side endpoint and must be configured with its separate
admission key plus the existing device and target policy. This route carries
TCP only. UDP remains on admitted direct H2/bridge routes or fails closed.

This is source integration. Clean `b83356ad` passed four focused macOS ARM64
Rust tests with `--locked --offline`: signed descriptor admission, private
credential separation, issued-profile Rustls admission and an authenticated
client-to-server device TLS loopback with reverse half-close. The earlier
compile and test-fixture failures remain retained in the private receipt.
Installed Linux and macOS packages, physical leak checks, hosted replica
operation, and independent multi-vantage acceptance remain open. A signed
declaration does not deploy a server or
make any endpoint reachable. Cloudflare is not the field-test test route.

`aegis-web-carrier` carries an ordered duplex byte stream in bounded HTTPS
request/reply exchanges. The public root remains an ordinary inline HTML page
over HTTP/1.1 or HTTP/2. Exact authorized POSTs retrieve a private ingress
descriptor or use its temporary response path. Rejected private requests get
the same 404 body as unknown paths; GET and HEAD never disclose descriptors.

This is an Aegis wire protocol. The deferred response design is inspired by
[Huma's primary paper](https://cs.uwaterloo.ca/~dbarrada/papers/kamali-ndss26.pdf):
the current request returns bytes prepared by earlier work, and its upload is
processed asynchronously for later requests. Rotation takes inspiration from
[CensorLess's primary paper](https://people.cs.umass.edu/~pdatta/publication/censorless/censorless.pdf).
It does not implement either paper's wire protocol, traffic embedding,
browser behavior, serverless deployment or live migration. There is no Balboa
compatibility, cloud cost, MEC distribution or censorship-resistance guarantee.
The request schedule and response sizes remain observable to traffic analysis.

## Authentication and custody

Outer TLS verifies the configured authority and trust roots before the admission
key is sent. The native client uses TLS 1.3, disables resumption and early data,
and disables key logging. A descriptor contains the authority, concrete ingress
address, random response path, generation, expiration and frame limit. It has
no admission key. The client validates its authority, expiry and frame limit;
the native client also admits its IP against a private local allowlist.

The admission key is a separate private file containing 64 lowercase hex bytes
representing a nonzero random 32-byte value, optionally followed by one newline.
It must never be a device key, certificate key, command-line value or public
bundle member. The native loaders use the existing trusted-parent and
private-owner/ACL readers before binding or dialing. `ClientSettings::load_with`
accepts that platform reader for both sidecar and credential; the callback must
enforce custody, not just read an arbitrary file. Config and credential loading
must complete before starting a listener. Never log request headers or session
identifiers; the key header is sensitive and its Debug representation redacted.

Admission creates only an opaque carrier. Every accepted stream must enter
`secure_channel::Server::accept_with_lease`. Call its authentication handle only
after that operation succeeds, then use the existing typed target request,
target policy, failure rate limiter and live authorization lease. Possession of
the admission key alone cannot authorize TCP/UDP egress. Enrollment and renewal
retain their existing separately configured authority; this descriptor endpoint
is not an enrollment API.

## Native entry points

The explicit commands are:

```sh
aegis-server carrier --config /absolute/private/server-carrier.toml
aegis-client carrier --config /absolute/private/client-carrier.toml
```

They use private TOML files and prepared device identities. The client exposes a
bounded loopback SOCKS TCP listener. Its current native command refuses SOCKS
UDP ASSOCIATE; the carrier library itself supplies a duplex stream that can
carry the existing authenticated datagram framing through another caller.
There is one establishment attempt per local session. Errors never reconnect
an application, reopen a target or fall back to another carrier.

The local listener requires an existing private RFC 1929 credential before
binding. Prepare the consumer and credential separately from carrier admission
and device TLS; see [local sidecar authentication](local-sidecar-auth.md).

A server configuration uses the existing relay TLS/device/target policy file:

```toml
relay_config = "/absolute/private/aegis-server.toml"
max_sessions = 16
rotate_descriptor_ms = 60000

[web]
site_html = "<!doctype html><title>Ordinary site</title><p>Welcome.</p>"

[web.client]
authority = "carrier.example"
descriptor_path = "/private/descriptor"
credential_file = "/absolute/private/web-admission.key"
```

For explicitly configured colocated carrier replicas, use the same dedicated
Unix-socket PostgreSQL database and `max_sessions` on every instance. The database
must be reachable through a Unix socket in a directory owned by the service
user or root, with no group/other write access throughout its ancestry (apart
from a root-owned sticky temporary root). PostgreSQL peer authentication
and the service account are provisioned separately; the carrier config contains
no database password or network DSN. The listener is not opened if connection
or ledger initialization fails. A replica count above one without this ledger
is rejected at startup.

```toml
replicas = 2

[ledger]
mode = "postgres"
socket_directory = "/run/aegis-postgres"
port = 5432
database = "aegis_web_ledger"
user = "aegis-carrier"
operation_timeout_ms = 2000
```

The ledger stores only random session identifiers, owner tokens, sequence
numbers and expiry. It fences duplicate claims and sequence advances between
processes. Each process still owns its descriptor, live session and application
stream. A load balancer must keep requests for a session on that process;
this configuration does not migrate an active stream or supply a serverless
runtime. PostgreSQL failure makes subsequent ledger operations refuse.

The relay must supply outer TLS and inner device TLS, no legacy bearer tokens,
closed fallback and no public bundle endpoint. The native command requires a
concrete listener address and advertises that exact bound endpoint; it has no
separate NAT advertisement setting. The library's Rust `serve_at` API can map an
already bound wildcard/private listener to
an operator-provided advertised address. It does not discover NAT mappings or
provision external addresses. The advertised endpoint must actually reach that
listener with the same verified authority.

Set `[transport] quic_required = false` in that separate relay file; its legacy
default is true. Omit `quic_listen` and `https_bridge`. All outer/inner certificate,
private-key, CA and optional registry paths must be absolute. These requirements
are checked before binding; another transport configuration is not silently ignored.

A client configuration has no plaintext admission key:

```toml
listen = "127.0.0.1:1089"
local_socks_auth_file = "/absolute/private/local-socks-auth.json"
bootstrap = "127.0.0.1:8449"
allowed_ingress_ips = ["127.0.0.1"]
outer_ca = "/absolute/private/outer-ca.pem"
connect_timeout_ms = 10000
idle_timeout_ms = 60000
max_sessions = 16

[web]
authority = "carrier.example"
descriptor_path = "/private/descriptor"
credential_file = "/absolute/private/web-admission.key"

[inner_tls]
server_name = "inner.example"
server_ca = "/absolute/private/inner-ca.pem"
cert = "/absolute/private/device.pem"
key = "/absolute/private/device.key"
```

These are illustrative local addresses and file names, not active endpoints or
credentials. Configure real endpoints, matching certificates and the intended
target policy through the existing provisioning process.

## Ordering, limits and rotation

Version 1 frames contain a random session nonce, a monotonically increasing
sequence, acknowledgement of the previous sequence, bounded data and FIN/CANCEL
flags. Only the immediately preceding identical request can receive its cached
reply. A conflicting duplicate, skipped sequence, stale acknowledgement or
session nonce on another connection is rejected without submitting application
data again. No application session migrates to another outer connection.

By default frames are at most 16 KiB, each direction has two queued frames,
and each application direction has a 32 KiB duplex buffer. One bounded reply is
cached per session. There are 64 carrier sessions, 32 outer connections,
128 requests globally and four concurrent requests per connection. Headers
are capped at 8 KiB. Request-body collection, TLS establishment and blocked
response flow control have a five-second limit. A zero-window receiver cannot
hold a response task indefinitely and incomplete replies are not success.

An unauthenticated session expires after five seconds from open; successful
polls and public site requests cannot renew it. Inner authentication extends
admission only while the application owns the accepted stream. Dropping that
stream starts a fixed five-second drain for already prepared final TLS bytes;
polls cannot extend the drain. Sessions also have a 60-second idle timeout and
one-hour absolute maximum lifetime. Configurable library limits have finite
upper bounds. Closing a client stream cancels its owned request pump and H2
driver. Server cancellation aborts and joins listener children; session removal
cancels the owned preparation worker and closes the application's carrier.

Bind a new owned listener before publishing its descriptor. `rotate_ingress`
instantly stops new opens on the previous descriptor; existing streams retain
their original listener, route and state until normal completion or their
bounded expiry. Keep the old listener owned and running until its sessions
drain, then cancel it. Periodic native descriptor rotation changes the response
path on an existing bound listener; it does not allocate a new IP or cloud
function. The library's network regression also rotates between two actual
ephemeral TCP listeners and verifies continuity of an existing stream.

## Verification

```sh
cargo test --locked -p aegis-web-carrier
```

Tests bind disposable loopback sockets, use real verified outer TLS and H2/H1,
and exercise deferred ordered transfer, duplicate idempotency, half-close,
quotas, cancellation, pre-auth expiry and ingress rotation. Inner-device tests
use the actual core mTLS and authorization lease: an allowed device reaches a
real local TCP echo target; a same-CA unpinned device with the correct bridge
key receives no application acceptance and never connects that target. They
do not establish installed platform acceptance, transport invisibility or
production endpoint readiness. Preserve exact build/CI, installed lifecycle,
capture-readiness and rollback receipts separately before operational rollout.

For a no-provider serverless deployment readiness check, run the two focused
real-network instance tests:

```sh
cargo test --locked --offline -p aegis-web-carrier --test network independent_instance_ -- --test-threads=1
```

They create two independently owned loopback HTTPS/H2 listeners with the same
synthetic admission credential. One closes the first instance and sends an old
session sequence to the replacement; the other sends an in-flight sequence to
a second live instance. Both require a private 404 refusal and zero accepted
application sessions on the receiving instance, then admit a new session. This
is a local deployment-behavior harness, not a deployable serverless adapter:
session state still lives in each process, so requests cannot migrate between
instances or survive restart. A serverless implementation needs an authenticated
external session store, strict replay/ordering, ownership and recovery before
actual independent service acceptance.

The source now exposes `Server::with_ledger` for atomic opaque session claims,
sequence verification and advance. `Server::new` continues to use a bounded
process-local ledger. A shared ledger can refuse replay across local instances,
but it does not move an authenticated application stream or its buffers to
another instance. Each awaited ledger acknowledgment is followed by a local
deadline and session-state recheck; a late committed operation may strand that
session and must fail closed. The first proposal omitted these late checks and
failed independent review. A later local repair passed delayed-ack tests and
real HTTPS/H2 loopback tests; no hosted backend has passed. A reviewed
`PostgresSessionLedger` now implements bounded claims across connections,
conditional owner/sequence advancement and expiry using the database clock.
Three parallel methods passed on disposable PostgreSQL 16, including capacity,
replay/reconnect and timeout refusal. Its first silent-skip test attempt and
destructive table-drop draft are retained in the receipt (`evidence-archive/testing/2026-10-13/B08-postgres-ledger-r1/receipt.md`).
The production `aegis-server carrier` command now selects that ledger only when
`[ledger] mode = "postgres"` is explicitly configured; `replicas > 1` without it
refuses startup, and a bad or unreachable database refuses before listener bind.
The Unix socket ancestry is checked through the existing trusted-parent policy
before connection. The first runtime proposal checked only the leaf directory
and failed independent review because a writable ancestor could replace it;
the R2 runtime receipt (`evidence-archive/testing/2026-10-13/B08-postgres-runtime-r2/receipt.md`)
retains that failure and reports four passing local startup/ledger methods,
including a real disposable PostgreSQL socket and a writable-ancestor refusal.
`Server::new` remains process-local for the default one-replica mode. No actual
multi-replica HTTPS/H2 run, remote PostgreSQL TLS, hosted restart/migration or
independent restricted-network behavior has passed.

A reviewed [self-hosted pilot renderer](k8s-web-carrier-pilot.md) now emits a
single-node, single-replica, digest-pinned Kubernetes manifest for direct TLS
and an optional PostgreSQL socket mount. Its first proposal accepted unsafe
node addresses and broad host mounts; the repaired source passed four inert
tests. No Kubernetes API or schema validation, owned node/path inspection,
cluster deployment, live TLS, restart migration or restricted-network test
has run. The manifest is deployment preparation, not serverless or carrier
acceptance.

## B-08 nonproprietary hosted pilot boundary, 15 October

The read-only open-stack selection (`evidence-archive/testing/2026-10-13/B08-open-stack-selection-r1/receipt.md`) SHA-256 `1d5ad7f1d2bb55f5c5b9f3db20a41a7ab9bafea9fd27c974737da55f081085ed` proposes self-hosted Knative/K3s with PostgreSQL and direct Caddy TLS, but all six known VPS had one vCPU and active Aegis roles at inventory; no safe unused combined pilot host was selected. Dedicated-capacity figures are planning estimates only. The source PostgreSQL ledger fences session IDs and sequences; it does not move live descriptors or response buffers across replicas. The inert single-replica manifest is not a Knative or multi-replica deployment. No DNS, host, cluster, database, direct TLS, spend or independent network check followed; B-08 hosted web-response acceptance remains **NO-GO**.

## 28 October 2026 — owner-scoped ledger release and replay fence

The first capacity repair (`d611fcca`) deleted owner-matched claims when a session closed. Its focused local capacity and PostgreSQL methods passed, but the full HTTPS/H2 suite exposed a replay regression: after release, another replica could reopen the old ID. This failed result remains retained. The successor `d4e227db` keeps a released-ID tombstone until the original expiry, excludes released rows from active-capacity accounting, caps retained IDs at 1,048,576 and refuses claim/verify/advance for released IDs. `07e4cd38` serializes PostgreSQL integration methods that intentionally contend on a database-wide advisory lock; the prior parallel test run failed from fixture contention. `42d1204b` reconnects the capacity fixture after each closed H2 owner, preserving its real-socket assertion; its first parallel run failed on a closed TLS connection. The final local suite passed 22 library, 21 HTTPS/H2 and four disposable PostgreSQL methods with default parallelism. Source manifest: `/private/tmp/aegis-b08-ledger-42d-r1/source-sha256.txt` (SHA-256 `984a5b912179dc9a7b2f63dc82d836585fef467b9edaf89ebf68a264c32dff55`, 2,532 filtered tracked paths). No hosted multi-replica stream transfer, installed check or exact-final CI is claimed.
