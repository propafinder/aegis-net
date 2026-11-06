# Ingress dispatch dependency recovery

`ingress-recovery.conf` binds the existing dispatch service to both `aegis-front-v3.service` and `aegis-server-v3.service`, makes it part of the online target, removes start limiting and sets failure restart delay to five seconds. Dependency loss can withdraw dispatch; the active target supplies the intended recovery relationship.

This is an overlay on an already provisioned dispatch service. It creates neither the listener nor its forwarding/authentication configuration. It requires the complete target/frontend/relay topology and systemd support described in the [parent runbook](../README.md).

For explicit rollback, stop `aegis-v3-online.target` along with the dispatcher and frontend. The [native recovery contract](../../../../../scripts/test-ingress-recovery-native.sh) uses isolated dummy units to test crash/stop semantics. Successful source checks or a prepared unit tree do not establish public cutover, actual traffic authorization, independent packet capture or beta readiness.
