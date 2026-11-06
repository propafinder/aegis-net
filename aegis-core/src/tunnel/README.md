# Legacy tunnel protocol modules

This directory holds the [fresh legacy protocol module](fresh_legacy.rs)
under the enclosing [tunnel implementation](../tunnel.rs). Its nested
[fixture directory](fresh_legacy/README.md) belongs to that protocol owner.
The device-enrolled inner-TLS channel has a separate owner in
[secure_channel](../secure_channel/README.md).

Use [the core source guide](../README.md) and [crate guide](../../README.md)
for module and build context. This navigation record inventories source paths;
it does not claim fixture execution, native interoperability or release acceptance.
