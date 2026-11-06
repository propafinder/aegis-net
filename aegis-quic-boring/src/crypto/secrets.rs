//! Derive packet-protection material from a TLS traffic secret (RFC 9001 §5.1).
//!
//! BoringSSL hands us the traffic secret per encryption level through the
//! `SSL_QUIC_METHOD` callbacks; QUIC then derives `quic key`, `quic iv` and
//! `quic hp` from it with `HKDF-Expand-Label`.

use ring::hkdf::Prk;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::hkdf::expand_label;
use super::suite::Suite;

/// Packet-protection material for one direction at one encryption level.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PacketSecrets {
    pub key: Vec<u8>,
    pub iv: [u8; 12],
    pub hp: Vec<u8>,
}

/// Derive `quic key` / `quic iv` / `quic hp` from a TLS traffic `secret`.
pub fn derive(suite: Suite, secret: &[u8]) -> PacketSecrets {
    let prk = Prk::new_less_safe(suite.hkdf(), secret);

    let mut key = vec![0u8; suite.key_len()];
    expand_label(&prk, b"quic key", &[], &mut key);

    let mut iv = [0u8; 12];
    expand_label(&prk, b"quic iv", &[], &mut iv);

    let mut hp = vec![0u8; suite.hp_len()];
    expand_label(&prk, b"quic hp", &[], &mut hp);

    PacketSecrets { key, iv, hp }
}

/// Key update (RFC 9001 §6): `secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length)`.
pub fn next_secret(suite: Suite, secret: &[u8]) -> Zeroizing<Vec<u8>> {
    let prk = Prk::new_less_safe(suite.hkdf(), secret);
    let mut out = Zeroizing::new(vec![0u8; secret.len()]);
    expand_label(&prk, b"quic ku", &[], &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_expected_lengths() {
        let secret = [0x42u8; 32];
        let s = derive(Suite::Aes128Gcm, &secret);
        assert_eq!(s.key.len(), 16);
        assert_eq!(s.hp.len(), 16);
        assert_eq!(s.iv.len(), 12);

        let secret384 = [0x42u8; 48];
        let s = derive(Suite::Aes256Gcm, &secret384);
        assert_eq!(s.key.len(), 32);
        assert_eq!(s.hp.len(), 32);
    }

    #[test]
    fn key_update_changes_secret_and_keeps_length() {
        let secret = [0x11u8; 32];
        let next = next_secret(Suite::Aes128Gcm, &secret);
        assert_eq!(next.len(), 32);
        assert_ne!(&next[..], &secret[..]);
        // deterministic
        assert_eq!(next, next_secret(Suite::Aes128Gcm, &secret));
    }

    #[test]
    fn different_labels_give_different_material() {
        let s = derive(Suite::Aes128Gcm, &[0x42u8; 32]);
        assert_ne!(s.key, s.hp);
    }
}
