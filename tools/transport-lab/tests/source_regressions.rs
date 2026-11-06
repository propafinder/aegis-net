//! Exercise the actual production source without rebuilding unrelated native
//! ingress/TLS backends. Full product CI remains required before merging.
#[allow(dead_code)]
#[path = "../../../aegis-client/src/relay/policy.rs"]
mod relay_policy;

#[allow(dead_code)]
#[path = "../../measure/src/traffic_shape.rs"]
mod traffic_shape;
