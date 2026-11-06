//! # aegis-quic-boring
//!
//! Chrome-fingerprint QUIC crypto provider for [`quinn`], backed by
//! AWS-LC/BoringSSL. Split deliberately into small, single-responsibility
//! modules so the crypto primitives can be unit-tested in isolation and the
//! BoringSSL handshake driver can evolve without touching them:
//!
//! - [`crypto`] — the RFC 9001 key schedule (initial secrets, packet keys,
//!   header protection). Fingerprint-INVISIBLE and identical for every QUIC
//!   stack, so it uses a standard AEAD/HKDF backend and is verified against the
//!   RFC 9001 Appendix A test vectors. No BoringSSL needed to build or test it.
//! - [`config`] — the Chrome QUIC ClientHello configuration (the actual
//!   fingerprint). Mirrors the TCP `aws_lc.rs` backend: GREASE, permuted
//!   extensions, X25519MLKEM768, ALPS, over `SSL_set_quic_method`. (feature `boring`)
//! - [`session`] — the [`quinn_proto::crypto::Session`] state machine that
//!   drives the BoringSSL handshake and feeds/collects QUIC crypto data. (feature `boring`)
//! - [`ffi`] — the raw `SSL_QUIC_METHOD` callbacks + any bindings not surfaced
//!   by `aws-lc-sys`. (feature `boring`)
//!
//! Milestone status: M1.1 = crypto key schedule (this file + `crypto/`) —
//! implemented + RFC-vector-tested. M1.2/M1.3 = session + config over BoringSSL
//! (feature `boring`) — in progress. DONE-gate = on-wire QUIC JA4 == Chrome q13.

pub mod crypto;
pub mod error;
pub mod fingerprint;
pub mod level;
pub mod session;

#[cfg(feature = "boring")]
pub mod config;
#[cfg(feature = "boring")]
pub(crate) mod ffi;

pub use error::Error;
