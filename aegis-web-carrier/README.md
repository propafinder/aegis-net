# aegis-web-carrier

Owned HTTPS deferred request/reply byte carrier for an existing independent device channel.

## Contract

This unpublished library uses verified outer TLS and HTTP/2. Its credential is an additional admission gate, never egress authorization. Every accepted stream must enter existing inner device mTLS and lease checks. It does not claim Huma wire compatibility, browser unobservability, censorship resistance or field acceptance.

## Key files

- [Cargo.toml](Cargo.toml)
- [src/lib.rs](src/lib.rs)
- [src/settings.rs](src/settings.rs)
- [src/server.rs](src/server.rs)
- [src/ledger.rs](src/ledger.rs)
- [src/postgres_ledger.rs](src/postgres_ledger.rs)
- [src/client.rs](src/client.rs)

## Session fencing

`Server::new` uses a process-local ledger. `Server::with_ledger` accepts a shared
`SessionLedger`; the backend must make claim, verify and sequence advance
linearizable for each opaque session ID. Claims retain their owner and next
sequence through expiry even when a connection or instance disappears. The
local ledger caps claims at 4096 by default and rejects fresh sessions while
full. An
unavailable store returns an error and the request is rejected. A timed out
transaction with an uncertain result may strand the session until expiry; it
must never be guessed successful or replayed with a second owner.

The ledger stores fencing metadata only. The application stream, inner device
authentication and payload buffers remain process-local. A different instance
rejects old-session requests and a client must establish a fresh OPEN with a
new ID; this interface does not provide live session migration. No hosted
hosted deployment is included. `PostgresSessionLedger` is a durable adapter
for a dedicated PostgreSQL database. It creates two metadata tables, locks
claim admission across replicas, persists one capacity and TTL configuration,
and uses PostgreSQL's clock for expiry. Pass a connected
`tokio_postgres::Client` to `PostgresSessionLedger::new`, keep its connection
future running, and give the ledger to `Server::with_ledger`. Remote database
connections require caller-provided TLS; the adapter does not create a
connection or read database credentials.

## Directories

| Directory | Responsibility |
| --- | --- |
| [src/](src/README.md) | Client/server byte-stream adapters, bounded request/reply protocol and explicit carrier settings. |
| [tests/](tests/README.md) | Real loopback TCP, verified outer TLS and HTTP/2 carrier tests. |

## Dependencies

Depends on Tokio, rustls, H2/HTTP and bounded protocol utilities. aegis-core is a development dependency used to verify the separate device channel. It has no binary target.

## Development

```sh
cargo test --locked -p aegis-web-carrier
```

The PostgreSQL integration suite requires an isolated test database whose
role can create schemas. It creates and removes only randomly named test
schemas. Set `AEGIS_TEST_POSTGRES_DSN`, then run:

```sh
cargo test --locked -p aegis-web-carrier --test postgres_ledger --features postgres-integration
```

Run from the repository root. Integrate via the `carrier` command paths in [aegis-client](../aegis-client/README.md) and [aegis-server](../aegis-server/README.md), with explicitly prepared carrier settings and an independent inner identity. This crate does not launch a service by itself. Review [research composition](../docs/research/implementation-and-composition.md) for acceptance boundaries.

[Repository overview](../README.md)

## Documentation responsibility

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/operations/web-response-carrier.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.
