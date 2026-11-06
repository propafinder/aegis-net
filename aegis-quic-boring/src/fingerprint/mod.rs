//! Self-fingerprinting: parse the ClientHello we emit and score it, so the
//! crate can prove its own Chrome-shape in tests without external capture
//! tooling.
//!
//! - [`clienthello`] — minimal, panic-free ClientHello parser.
//! - [`ja4`]         — the JA4 client fingerprint over a parsed hello.

pub mod clienthello;
pub mod initial_packet;
pub mod ja4;
