//! RFC 9001 §5.2 — Initial packet protection.
//!
//! The Initial secrets are derived from the client's Destination Connection ID
//! with a version-specific salt, using HKDF. The AEAD is always AES-128-GCM and
//! header protection is AES-128 for Initial packets (RFC 9001 §5.2).
//!
//! Verified against the RFC 9001 Appendix A.1 test vectors (see `tests` below).

use ring::hkdf::{Prk, Salt, HKDF_SHA256};

use super::hkdf::expand_label_n;

/// QUIC v1 Initial salt (RFC 9001 §5.2).
pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// The three per-direction Initial secrets, expanded into the AES-128-GCM +
/// AES-128-HP material. Sizes are fixed by the Initial cipher suite.
#[derive(Clone)]
pub struct InitialKeyMaterial {
    /// AEAD key (AES-128-GCM → 16 bytes).
    pub key: [u8; 16],
    /// AEAD IV (12 bytes).
    pub iv: [u8; 12],
    /// Header-protection key (AES-128 → 16 bytes).
    pub hp: [u8; 16],
}

/// `initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)`.
fn initial_prk(dcid: &[u8]) -> Prk {
    Salt::new(HKDF_SHA256, &INITIAL_SALT_V1).extract(dcid)
}

/// Derive one direction's Initial key material.
///
/// `side_label` is `"client in"` or `"server in"` (RFC 9001 §5.2).
fn derive(side_label: &[u8], dcid: &[u8]) -> InitialKeyMaterial {
    let iprk = initial_prk(dcid);
    // <side>_initial_secret = HKDF-Expand-Label(initial_secret, side_label, "", 32)
    let secret: [u8; 32] = expand_label_n(&iprk, side_label, b"");
    let sprk = Prk::new_less_safe(HKDF_SHA256, &secret);
    InitialKeyMaterial {
        key: expand_label_n(&sprk, b"quic key", b""),
        iv: expand_label_n(&sprk, b"quic iv", b""),
        hp: expand_label_n(&sprk, b"quic hp", b""),
    }
}

/// Client-side Initial key material for a given Destination Connection ID.
pub fn client_initial(dcid: &[u8]) -> InitialKeyMaterial {
    derive(b"client in", dcid)
}

/// Server-side Initial key material for a given Destination Connection ID.
pub fn server_initial(dcid: &[u8]) -> InitialKeyMaterial {
    derive(b"server in", dcid)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9001 Appendix A.1: DCID = 0x8394c8f03e515708.
    const DCID: &str = "8394c8f03e515708";

    #[test]
    fn rfc9001_a1_client_initial() {
        let dcid = hex::decode(DCID).unwrap();
        let k = client_initial(&dcid);
        assert_eq!(
            hex::encode(k.key),
            "1f369613dd76d5467730efcbe3b1a22d",
            "client key"
        );
        assert_eq!(hex::encode(k.iv), "fa044b2f42a3fd3b46fb255c", "client iv");
        assert_eq!(
            hex::encode(k.hp),
            "9f50449e04a0e810283a1e9933adedd2",
            "client hp"
        );
    }

    #[test]
    fn rfc9001_a1_server_initial() {
        let dcid = hex::decode(DCID).unwrap();
        let k = server_initial(&dcid);
        assert_eq!(
            hex::encode(k.key),
            "cf3a5331653c364c88f0f379b6067e37",
            "server key"
        );
        assert_eq!(hex::encode(k.iv), "0ac1493ca1905853b0bba03e", "server iv");
        assert_eq!(
            hex::encode(k.hp),
            "c206b8d9b9f0f37644430b490eeaa314",
            "server hp"
        );
    }
}
