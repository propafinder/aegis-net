//! Actual shared packet engine mechanics; OS capture and identity/renewal
//! admission remain independently owned by callers. No provider factory here.
extern crate self as aegis_client;
pub mod capture_lease_gate;
pub mod device_bundle_profile;
pub mod issuance_binding;
pub mod macos_relay_pins;
pub mod observed_policy_ack;
pub mod online_ack_observation;
pub mod online_expectation;
pub mod online_renewal_monitor;
pub mod online_renewal_plan;
pub mod online_session_observation;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod packet_engine;
pub mod packet_engine_io;
pub mod policy_ack_binding;
pub mod policy_ack_exchange;
pub mod prepared_enrolled_quic;
pub mod prepared_outer_tls;
pub mod protected_identity_file;
#[cfg(unix)]
pub mod protected_identity_store;
#[cfg(unix)]
pub mod protected_online_expectation;
pub mod public_profile_file;
pub mod relay_endpoint_policy;
pub mod relay_runtime_types;
pub mod relay_session_control;
pub mod runtime_errors;
pub use packet_engine_io::{PacketIo, TunnelStats};

pub mod brain_state;
pub mod credential_path_policy;
pub mod device_web_response;
pub mod ech_policy;
pub mod mimicry_runtime_surface;
pub mod runtime_event_stream;
pub mod runtime_events;
pub mod runtime_paths;
