# Replica policy sync cadence

`onboarding.conf` overrides the existing replica sync timer. It clears `OnUnitActiveSec`, starts two seconds after activation, repeats ten seconds after completion and adds up to one second of randomized delay. Completion-relative scheduling preserves a new opportunity after a slow synchronization operation.

This is a replica role: a successful pull does not renew the authoritative snapshot's lifetime. The corresponding service, pinned authority configuration, protected state paths and runtime adoption checks must already be provisioned. Install only on the selected role and review the effective timer after reloading systemd.

Use the parent [inner-TLS runbook](../README.md) for activation and drift checks and [device-policy operations](../../../../../docs/operations/device-policy-ssh-pull.md) for authority boundaries. Source timer tests are not an observation of a live host's current lease, generation or service health. Preserve all monotonic timer semantics when changing the override.
