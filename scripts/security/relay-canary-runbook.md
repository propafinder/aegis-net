# Legacy relay canary credential: preparation only

`prepare_relay_canary.py` creates a proposed config containing one new
`[[legacy_auth_tokens]]` entry. It does not install the config, restart a
service, verify a remote relay or revoke a deployed credential.

## Preconditions

- Use Linux root with a trusted, local filesystem. The source config and its
  direct parent must be root-owned and mode 0600/0700 respectively. Confirm
  protected ancestry and **no extended ACL** on the source, output parent or
  output directory independently. The helper rejects Linux POSIX access and
  default ACL xattrs; it cannot establish every mount or non-POSIX ACL policy.
- Pin the exact deployed signed server binary, machine identity, current
  config SHA-256, service PID/start and listener before preparing anything.
  Confirm that the active authority uses legacy shared-token mode; inner TLS
  requires the separate device enrollment procedure.
- Prepare one root-owned mode-0700 output parent, one unique `canary-*` ID,
  and a TTL of 60–900 seconds. Keep the output directory outside Git and
  backup/snapshot systems that are not authorized for access secrets.
- Invoke a SHA-pinned reviewed helper by absolute path using
  `/usr/bin/python3 -I -S -B`. Do not use shell tracing or print the generated
  `client-token`, `candidate.toml` or `rollback.toml`.

The helper takes `--config`, `--out-dir`, `--id`, `--ttl-secs` and
`--expected-config-sha256`. It fails if the current config digest changed.
The private output contains an exact copy of the original as `rollback.toml`,
the proposed `candidate.toml`, `client-token`, and a digest-only `receipt.json`.
Partial output after an error is intentionally retained inside the 0700
directory: treat it as an incident, inspect exact ownership/inodes/modes and
remove only after no helper or deployment process still references it. Never
blindly rerun with the same output path or unlink a live writer's file.

## Separate deployment and authentication gate

The helper is a source-only proposal. Before using its output on a relay,
an independent reviewer must accept the source and check the exact candidate
with the **same signed server build** via `aegis-server --config
<candidate.toml> config-check`. Keep that binary and source/config hashes in
the private receipt. The checked config is still only a candidate.

A future live procedure needs a proven traffic drain and inverse restore,
independent health witness, bounded service restart, exact pre/post config and
PID pins, and an emergency rollback controller separate from the modifying
session. Do not apply on r77 while it serves a single-homed client.

For the actual canary, run a signed client in a fresh disposable Linux guest
with only this new key, relay-c's pinned authority, loopback SOCKS and no wide/TUN
mode. Capture independent network state before and after. One controlled SOCKS
request must receive Aegis **authenticated tunnel acceptance** and an owned
target witness. A TLS handshake alone does not prove this. Stop and remove
the guest after checked cleanup.

## Revocation and rollback

Early revocation means replacing the live candidate with the exact saved
rollback config **only if** the live config still matches the candidate SHA,
followed by the separately reviewed bounded restart and authenticated denial
readback. If the live config differs, stop: a blind restore could erase other
authorized changes. Independently observe service health and client traffic.
The `not_after_unix_secs` deadline is a fail-closed backstop, not a substitute
for early revocation or cleanup. Preserve the private output and failed
receipts until a custodian confirms no active session and no dependent use.
