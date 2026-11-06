# Inner relay retry policy

`recovery.conf` removes the existing inner relay service's start-limit interval and sets `RestartSec=30s`. It lets a configured service continue retrying after an extended dependency or policy outage. It does not change the service's authentication rules, binary path, listener or private configuration.

The base `aegis-server-v3.service` must already exist. Review its effective restart mode and the loaded drop-in before enabling the selected deployment role. Repeated retries must not be interpreted as permission to accept clients with expired authorization; policy validity remains a runtime requirement.

See the [inner-TLS profile](../README.md) for selected installation and drift checks and the [systemd unit guide](../../../README.md) for related policy services. Source/native dummy-service tests demonstrate their stated recovery behavior only. They do not prove another relay's loaded state, current policy ACK, endpoint availability or public traffic acceptance.
