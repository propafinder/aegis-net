//! QUIC encryption levels (`ssl_encryption_level_t`).
//!
//! Kept out of [`crate::ffi`] and free of any BoringSSL types so the level
//! bookkeeping — which drives when keys are handed to quinn — is unit-testable
//! on any platform, with or without the `boring` feature.

/// A QUIC encryption level. The discriminants match BoringSSL's
/// `ssl_encryption_level_t`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Level {
    #[default]
    Initial = 0,
    EarlyData = 1,
    Handshake = 2,
    Application = 3,
}

pub const LEVELS: usize = 4;

impl Level {
    /// Convert from BoringSSL's `ssl_encryption_level_t`.
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Level::Initial),
            1 => Some(Level::EarlyData),
            2 => Some(Level::Handshake),
            3 => Some(Level::Application),
            _ => None,
        }
    }

    pub fn as_raw(self) -> u32 {
        self as u32
    }

    /// Bindgen uses a signed C enum on Windows and an unsigned one on Unix.
    #[cfg(feature = "boring")]
    pub(crate) fn from_native(raw: aws_lc_sys::ssl_encryption_level_t) -> Option<Self> {
        match raw {
            0 => Some(Self::Initial),
            1 => Some(Self::EarlyData),
            2 => Some(Self::Handshake),
            3 => Some(Self::Application),
            _ => None,
        }
    }

    #[cfg(feature = "boring")]
    pub(crate) fn as_native(self) -> aws_lc_sys::ssl_encryption_level_t {
        match self {
            Self::Initial => 0,
            Self::EarlyData => 1,
            Self::Handshake => 2,
            Self::Application => 3,
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }

    /// The next level in the handshake *key* progression, skipping 0-RTT.
    ///
    /// quinn is handed keys for Handshake and then 1-RTT; 0-RTT keys are
    /// surfaced separately via `Session::early_crypto`, so `EarlyData` is not
    /// part of this chain.
    pub fn next_handshake_level(self) -> Option<Level> {
        match self {
            Level::Initial | Level::EarlyData => Some(Level::Handshake),
            Level::Handshake => Some(Level::Application),
            Level::Application => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_round_trip() {
        for l in [
            Level::Initial,
            Level::EarlyData,
            Level::Handshake,
            Level::Application,
        ] {
            assert_eq!(Level::from_raw(l.as_raw()), Some(l));
        }
        assert_eq!(Level::from_raw(4), None);
    }

    #[test]
    fn key_progression_skips_zero_rtt() {
        assert_eq!(
            Level::Initial.next_handshake_level(),
            Some(Level::Handshake)
        );
        assert_eq!(
            Level::Handshake.next_handshake_level(),
            Some(Level::Application)
        );
        assert_eq!(Level::Application.next_handshake_level(), None);
    }

    #[test]
    fn levels_are_ordered() {
        assert!(Level::Initial < Level::Handshake);
        assert!(Level::Handshake < Level::Application);
    }
}
