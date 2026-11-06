//! The Chrome-class QUIC ClientHello.
//!
//! This is the only fingerprint-visible part of the crate; the RFC 9001 key
//! schedule in [`crate::crypto`] is identical for every implementation.
//!
//! - [`ciphers`]           — TLS 1.3 suite order.
//! - [`groups`]            — supported groups / key shares.
//! - [`extensions`]        — OCSP, SCT, signature algorithms, cert compression.
//! - [`cert_compression`]  — brotli certificate decompression (RFC 8879).
//! - [`ctx`]               — assembles them into an `SSL_CTX`.

pub mod cert_compression;
pub mod ciphers;
pub mod ctx;
pub mod extensions;
pub mod groups;
#[cfg(windows)]
pub mod trust_anchor_hint;
#[cfg(windows)]
pub mod windows_trust;
