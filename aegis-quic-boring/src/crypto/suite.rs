//! Cipher-suite descriptor: maps a negotiated TLS 1.3 suite to the AEAD, the
//! HKDF hash, and the key lengths RFC 9001 §5.1 needs to derive packet keys
//! from a traffic secret.

use ring::{aead, hkdf};

/// The TLS 1.3 suites QUIC uses (RFC 9001 §5.1). Chrome offers all three; the
/// server picks, so all three must work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Suite {
    /// Map a TLS cipher-suite wire code point (as returned by
    /// `SSL_CIPHER_get_protocol_id`) to a suite.
    pub fn from_protocol_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Suite::Aes128Gcm),
            0x1302 => Some(Suite::Aes256Gcm),
            0x1303 => Some(Suite::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn aead(self) -> &'static aead::Algorithm {
        match self {
            Suite::Aes128Gcm => &aead::AES_128_GCM,
            Suite::Aes256Gcm => &aead::AES_256_GCM,
            Suite::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    /// HKDF hash bound to the suite (SHA-384 for AES-256, SHA-256 otherwise).
    pub fn hkdf(self) -> hkdf::Algorithm {
        match self {
            Suite::Aes256Gcm => hkdf::HKDF_SHA384,
            _ => hkdf::HKDF_SHA256,
        }
    }

    /// AEAD key length in bytes.
    pub fn key_len(self) -> usize {
        self.aead().key_len()
    }

    /// Header-protection key length — same as the AEAD key length (RFC 9001
    /// §5.4.3/§5.4.4).
    pub fn hp_len(self) -> usize {
        self.key_len()
    }

    pub fn is_chacha(self) -> bool {
        matches!(self, Suite::ChaCha20Poly1305)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_ids_map_to_suites() {
        assert_eq!(Suite::from_protocol_id(0x1301), Some(Suite::Aes128Gcm));
        assert_eq!(Suite::from_protocol_id(0x1302), Some(Suite::Aes256Gcm));
        assert_eq!(
            Suite::from_protocol_id(0x1303),
            Some(Suite::ChaCha20Poly1305)
        );
        assert_eq!(Suite::from_protocol_id(0x009c), None);
    }

    #[test]
    fn key_lengths_match_rfc9001() {
        assert_eq!(Suite::Aes128Gcm.key_len(), 16);
        assert_eq!(Suite::Aes256Gcm.key_len(), 32);
        assert_eq!(Suite::ChaCha20Poly1305.key_len(), 32);
        // hp key length always equals the AEAD key length
        for s in [Suite::Aes128Gcm, Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
            assert_eq!(s.hp_len(), s.key_len());
        }
    }
}
