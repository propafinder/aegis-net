# Seizure resistance (journalist / at-risk deployments)

This guide hardens an AEGIS deployment against **physical seizure or takeover**
of a user's machine or a relay server. It is written for the threat model where
the adversary can obtain the disk and wants to (a) learn what a user did, or
(b) learn who used a relay.

Status legend: **built** = shipped in the binary/repo; **operator** = a config
step you apply; **architecture** = already true by design.

## What the architecture already protects (architecture)

- **A forced Cloudflare-fronted TCP path hides the direct client peer from the
  origin connection.** For example, `relay.example.org` can proxy gRPC to an
  operator-controlled origin; the socket peer is an edge. A configured trusted
  proxy can supply `CF-Connecting-IP` to relay rate-limit identity handling, so
  the application can still learn the client IP. Cloudflare and
  a compromised client remain separate observers. Direct fallback or direct
  MASQUE exposes the client/origin relationship and is outside this protection.
  The checked-in `aegis-origin-guard.sh` contains TCP and UDP `:443` accept
  rules for the pinned Cloudflare ranges and drop rules for other sources, plus
  an earlier established/related exception. It is not an unconditional UDP drop
  or proof that UDP is supplied by a fronted service. An ordinary direct MASQUE
  client outside those ranges cannot establish that guarded path. Choose and
  verify the intended topology and actual host rules explicitly.
- **Authentication depends on the selected profile.** The shared AEAD/token
  credential is legacy. Enrolled profiles use individual device certificates
  and authenticated inner TLS; they do not inherit shared-token fallback.

## Client machine (user side)

### 1. Forensic-safe mode — reduce newly written private evidence (built + operator)

Current default private logging keeps event/error codes, not destination text or
hashes. The installer normally requests an event-code JSONL file. Detailed logs
and direct/auto disk learning are separate opt-ins:

| Trail | Current source contents | Control |
|---|---|---|
| `<log-dir>/runtime-events.jsonl` | bounded event/error codes normally; detailed fields only with `--diagnostic-logs` | installer `--no-runtime-events`, or forensic policy |
| configured Brain snapshot | opt-in direct/auto learning may contain target history; relay mode stays in RAM | `[direct] persist_state = true`; forensic policy overrides it |
| old logs/state/backups | bytes from an earlier installation or session | explicit operator retention/erasure decision |

Enable it (either):

```bash
aegis-client --forensic-safe ...
# or, as a service, install the drop-in:
sudo install -Dm0644 packaging/systemd/aegis-client.service.d/forensic.conf \
  /etc/systemd/system/aegis-client.service.d/forensic.conf
sudo systemctl daemon-reload && sudo systemctl restart aegis-client
```

With `AEGIS_FORENSIC_SAFE=1`, the client disables its JSONL sink and keeps new
Brain state in RAM. Emitted failures retain only structural event/error codes;
forensic output contains neither destination text nor destination hashes. A hash
would not be a non-reversible browsing-history guarantee. This does not erase
old files, backups, OS metadata or a running machine's memory. See
[private diagnostics](../operations/private-diagnostics.md).

### 2. Volatile journal — bounded retention (operator)

Normal private tracing omits hostnames but still reveals service events. An
explicit diagnostic session may log sensitive destinations. An operator may
choose volatile journald storage:

```bash
sudo install -Dm0644 packaging/journald/forensic.conf \
  /etc/systemd/journald.conf.d/aegis-forensic.conf
sudo systemctl restart systemd-journald
```

This changes system-wide journal storage and does not delete pre-existing logs
or administrator backups. Review the host's operational logging needs first.

### 3. Full-disk encryption (operator, strongest)

Application-level redaction cannot protect a *running* machine's RAM. For real
at-rest protection use **LUKS full-disk encryption** with a passphrase not
stored on the device. Forensic-safe mode + volatile journal minimise what exists
to seize; LUKS protects whatever remains when the machine is off.

## Relay server (operator side)

### 4. Remove the Relay CA private key from the relay (audit F3)

`/etc/aegis/server/certs/ca-key.pem` (the AEGIS Relay CA) is only needed to
**mint** client/server certs at install/rotation time — it is **not** read by
the running relay, which serves with `server.pem`/`server-key.pem`. Leaving it
on the relay means a seizure yields a 10-year CA that can forge relay certs and
MITM the pinned client bundle. **Move it offline** after issuance:

```bash
# on a trusted offline machine, keep the CA key; on the relay:
sudo shred -u /etc/aegis/server/certs/ca-key.pem   # after backing it up offline
```

Verify the relay still runs and reissues nothing at runtime before shredding.

### 5. Volatile journal on the relay (audit F2)

Apply the same `packaging/journald/forensic.conf` on relays. Behind Cloudflare
this reduces newly retained journal evidence for that selected topology. It
does not erase existing disk metadata or guarantee that the box is unattributable.

### 6. Full-disk encryption + minimal secrets

The daemon needs its configured legacy token (for a legacy profile), relay TLS
private key, trust certificates and device policy/verification records. A device
private key belongs on its client; an offline issuer/CA signing private key is
not required by the relay daemon. Do not copy it to the relay for convenience.
These distinct secrets and public verification records must not be grouped as
"issuer material readable by the daemon". Host disk encryption can protect
retained bytes at rest, but not an unlocked running host or copied backups. Keep
the box minimal and rotate exposed legacy credentials; enrolled credentials
require their own revocation and recovery procedure.

## Quick checklist

- [ ] Client: `AEGIS_FORENSIC_SAFE=1` drop-in installed
- [ ] Client + relay: journald `Storage=volatile` drop-in installed
- [ ] Relay: `ca-key.pem` moved offline
- [ ] Client + relay: LUKS full-disk encryption
- [ ] Relay: verify forced fronted TCP plus origin guard when that is the selected
      topology; verify UDP accepts/exceptions rather than assuming an unconditional drop
