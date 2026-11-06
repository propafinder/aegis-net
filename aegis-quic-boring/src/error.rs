//! Crate error type. Kept tiny and dependency-free.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// A BoringSSL/AWS-LC FFI call failed.
    Ssl(&'static str),
    /// The peer sent malformed or unexpected crypto data.
    Crypto(&'static str),
    /// A key-derivation / AEAD operation failed.
    KeySchedule(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Ssl(m) => write!(f, "boringssl: {m}"),
            Error::Crypto(m) => write!(f, "crypto: {m}"),
            Error::KeySchedule(m) => write!(f, "key schedule: {m}"),
        }
    }
}

impl std::error::Error for Error {}
