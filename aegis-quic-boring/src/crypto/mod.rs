//! RFC 9001 QUIC key schedule.
//!
//! This layer is intentionally **independent of BoringSSL**: the QUIC key
//! schedule is identical for every RFC 9001 implementation and is NOT part of
//! the on-wire fingerprint, so it uses a standard HKDF/AEAD backend (`ring`)
//! and is verified against the RFC 9001 Appendix A test vectors. The Chrome
//! *fingerprint* lives entirely in the TLS ClientHello (see [`crate::config`]),
//! not here.
//!
//! Split by concern:
//! - [`hkdf`]     — TLS 1.3 `HKDF-Expand-Label` (RFC 8446 §7.1).
//! - [`initial`]  — RFC 9001 §5.2 Initial secrets/keys (from the client DCID).
//! - [`packet`]   — AEAD packet protection (`quic key` / `quic iv`).
//! - [`header`]   — header protection mask (`quic hp`).

pub mod header;
pub mod hkdf;
pub mod initial;
pub mod keys;
pub mod packet;
pub mod retry;
pub mod secrets;
pub mod suite;
