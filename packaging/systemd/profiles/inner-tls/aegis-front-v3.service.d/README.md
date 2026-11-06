# Frontend membership in the ingress target

`ingress-recovery.conf` makes the existing frontend part of `aegis-v3-online.target` and disables the unit's start-limit interval. The target is responsible for upholding the frontend and dispatch services. This drop-in supplies no executable, listener, certificate or provider configuration.

It requires the existing frontend and the parent target on a systemd version supporting `Upholds`. An explicit stop or rollback must stop the online target as well as the frontend/dispatch units; stopping an upheld unit alone does not express a lasting shutdown intent.

Follow the [parent profile runbook](../README.md) and the paired [dispatch guide](../aegis-v3-dispatch.service.d/README.md). The disposable [native recovery test](../../../../../scripts/test-ingress-recovery-native.sh) exercises isolated dummy units, not public ingress. Passing that test or copying this file is not evidence of deployed frontend health or accepted public cutover.
