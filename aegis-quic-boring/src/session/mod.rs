//! Handshake session: the quinn `Session`/`ClientConfig` implementations and
//! the state they share with the BoringSSL callbacks.
//!
//! [`state`] holds no BoringSSL types and is unit-tested on its own; the rest
//! needs the `boring` feature.

pub mod state;

#[cfg(feature = "boring")]
pub mod client_config;
#[cfg(feature = "boring")]
pub mod handshake_data;
#[cfg(feature = "boring")]
pub mod tls_session;
