# Authority staging cadence

`onboarding.conf` adjusts the existing enrollment policy-stage timer: it clears `OnUnitActiveSec`, starts two seconds after activation, repeats fifteen seconds after completion and randomizes by up to one second. This applies to the authority staging role, not replica relays.

The enrollment-owned staging service, protected transfer inbox and root-owned publication service must already be configured. This timer does not create those accounts or files and does not itself prove successful publication or runtime policy adoption. Review the combined base timer and drop-in before activation.

The [inner-TLS runbook](../README.md) gives selected installation/rollback procedures. [Enrollment operations](../../../../../docs/operations/device-online-enrollment.md) explains the independent identity and authorization lifecycle. A source comparison or timer contract pass is separate from current authoritative generation, freshness and live fleet ACKs. Do not replace completion-relative repeat scheduling with an empty reset alone.
