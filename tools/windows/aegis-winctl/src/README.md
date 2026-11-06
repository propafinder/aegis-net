# winctl commands and native lifecycle

main.rs parses package/client/tunnel/service/WFP/proof/artifact commands and reports results. package.rs is reusable validation; Windows-gated install.rs, service.rs and tunnel.rs own native actions.

### Contracts and limits

Service or tunnel commands can change SCM, routes and policy. Preserve original process ownership, finite waits and separate operation-versus-recovery status; successful metadata validation is not completed installation or safe reboot proof.

### Entry points and maintenance

Read nested install/package contracts first. install_native_tests.rs contains platform-specific lifecycle tests; ordinary parser/fixture checks do not replace them.

### Local map

- [install.rs](install.rs)
- [install_native_tests.rs](install_native_tests.rs)
- [main.rs](main.rs)
- [package.rs](package.rs)
- [service.rs](service.rs)
- [tunnel.rs](tunnel.rs)
- [install/](install/README.md)
- [package/](package/README.md)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
