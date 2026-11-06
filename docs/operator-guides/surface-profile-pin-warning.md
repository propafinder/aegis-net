# Operator warning — `relay.policy.surface_profile_id` pinning

**Severity:** `OPERATOR_HARDENING`
**Not a beta blocker** under the current shared-relay topology.
**Origin:** Drill J stable-wire-identity audit
(`evidence-archive/live/2026-05-31/stable-wire-identity-audit/`).

## What `surface_profile_id` is

`relay.policy.surface_profile_id` lets an operator pin the relay session to
one named morphology/surface profile (e.g. `cli_https_compact`,
`realtime_websocket`). When **unset** (the default), AEGIS samples a
surface profile per `(relay, target, drift_epoch)` window (default
`drift_epoch_secs = 900`, i.e. 15 minutes) and resamples per-session
dynamics (chunk size, inter-write delay, jitter) on every session.

## The risk

A pinned `surface_profile_id`:

1. **Removes the per-epoch morphology drift.** The chosen profile no
   longer rotates every 15 minutes — it is fixed for the lifetime of the
   install.
2. **Can become a stable per-user wire-correlatable marker** if the same
   pin is unique per user/device/install. Combined with a
   private-VPS-per-user deployment (where `relay.server` is already
   user-unique), a fixed profile makes the user's traffic shape
   consistent across sessions, networks, and restarts.

This is the same *class* of risk as Telegram's `auth_key_id` — a stable
attribute that survives IP and network changes — except here it is a
shape/morphology marker rather than an explicit identifier, and it only
materialises under specific operator configurations.

## What is acceptable

- A pinned `surface_profile_id` shared by **many** users of the same
  deployment is a *family* marker, not a per-user identifier. That is
  acceptable (all users look alike).
- Using `surface_profile_id` in **lab / diagnostic / test** runs to make
  a measurement reproducible is fine.

## What to avoid in production

- **Do not** pin a `surface_profile_id` uniquely per user/device/install
  in production bundles.
- **Never** use `surface_profile_id` as a user/customer identifier.
- Prefer letting the Brain / adaptive morphology layer sample profiles.
- Rotate or omit explicit `surface_profile_id` unless you are testing.

## Runtime signal

Since v0.3.14+, aegis-client emits a one-time startup runtime event when a
pin is present:

```json
{
  "event_code": "surface_profile_id_pinned_warning",
  "fields": {
    "surface_profile_id": "<pinned id>",
    "severity": "operator_hardening",
    "behavior_changed": false,
    "guidance": "prefer adaptive morphology sampling; do not use surface_profile_id as a user/customer identifier"
  }
}
```

The warning is **advisory only** — it does not fail startup, does not
change transport selection, and does not alter Brain behavior. No warning
is emitted for the default (unset / adaptively-sampled) configuration.

Verified live (`evidence-archive/live/2026-05-31/surface-profile-id-hardening/`):
pinned config → exactly one warning + unchanged SOCKS egress; unset
config → zero warnings + unchanged egress.

## Cross-references

- `docs/security/22-threat-model.md` — "Linkability minimization" section
- `evidence-archive/live/2026-05-31/stable-wire-identity-audit/captures/p3-surface-profile/result.json`
- `aegis-client/src/relay/policy.rs` — `session_seed` / `build_session_profile`
