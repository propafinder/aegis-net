//! Raw BoringSSL (AWS-LC) interop, confined to this module.
//!
//! - [`quic_method`] — the `SSL_QUIC_METHOD` hook table.
//! - [`ex_data`]     — attaching our session state to an `SSL`.
//! - [`ssl`]         — RAII wrapper driving one QUIC handshake.

pub mod ex_data;
pub mod quic_method;
pub mod ssl;
