//! Retry packet integrity (RFC 9001 §5.8).
//!
//! The 16-byte Retry Integrity Tag is `AEAD_AES_128_GCM` over an empty
//! plaintext, with the Retry Pseudo-Packet as associated data and fixed
//! version-specific key/nonce. This lets a client reject forged Retry packets —
//! an off-path injection an in-network censor could otherwise use to break the
//! connection.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};

/// QUIC v1 Retry integrity key (RFC 9001 §5.8).
const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
/// QUIC v1 Retry integrity nonce.
const RETRY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

pub const TAG_LEN: usize = 16;

/// Compute the Retry Integrity Tag for a Retry packet whose bytes (excluding
/// the tag) are `retry_without_tag`, given the original destination CID.
pub fn integrity_tag(orig_dst_cid: &[u8], retry_without_tag: &[u8]) -> [u8; TAG_LEN] {
    // Retry Pseudo-Packet = ODCID Len (1 byte) || ODCID || Retry packet w/o tag
    let mut pseudo = Vec::with_capacity(1 + orig_dst_cid.len() + retry_without_tag.len());
    pseudo.push(orig_dst_cid.len() as u8);
    pseudo.extend_from_slice(orig_dst_cid);
    pseudo.extend_from_slice(retry_without_tag);

    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &RETRY_KEY_V1).expect("16-byte key"));
    let nonce = Nonce::assume_unique_for_key(RETRY_NONCE_V1);
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(&pseudo), &mut [])
        .expect("aead seal over empty plaintext");

    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Verify a Retry packet. `header` and `payload` are as quinn splits them; the
/// last [`TAG_LEN`] bytes of `payload` are the integrity tag.
pub fn is_valid(orig_dst_cid: &[u8], header: &[u8], payload: &[u8]) -> bool {
    if payload.len() < TAG_LEN {
        return false;
    }
    let (body, tag) = payload.split_at(payload.len() - TAG_LEN);
    let mut without_tag = Vec::with_capacity(header.len() + body.len());
    without_tag.extend_from_slice(header);
    without_tag.extend_from_slice(body);

    let expected = integrity_tag(orig_dst_cid, &without_tag);
    // Constant-time compare: a timing oracle here would leak the tag.
    constant_time_eq(&expected, tag)
}

/// Length-checked, branch-free byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9001 Appendix A.4.
    const RETRY_PACKET: &str =
        "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";
    const ODCID: &str = "8394c8f03e515708";

    #[test]
    fn rfc9001_a4_retry_tag() {
        let packet = hex::decode(RETRY_PACKET).unwrap();
        let odcid = hex::decode(ODCID).unwrap();
        let (without_tag, tag) = packet.split_at(packet.len() - TAG_LEN);
        assert_eq!(
            hex::encode(integrity_tag(&odcid, without_tag)),
            hex::encode(tag)
        );
    }

    #[test]
    fn accepts_genuine_retry_and_rejects_forged() {
        let packet = hex::decode(RETRY_PACKET).unwrap();
        let odcid = hex::decode(ODCID).unwrap();
        // Split arbitrarily into "header" + "payload"; only the concatenation matters.
        let (header, payload) = packet.split_at(5);
        assert!(is_valid(&odcid, header, payload));

        // Forged: a censor injecting a Retry it cannot authenticate.
        let mut forged = payload.to_vec();
        forged[0] ^= 0x01;
        assert!(!is_valid(&odcid, header, &forged));

        // Wrong original DCID (replayed Retry from another connection).
        assert!(!is_valid(
            &hex::decode("0011223344556677").unwrap(),
            header,
            payload
        ));

        // Truncated.
        assert!(!is_valid(&odcid, header, &payload[..TAG_LEN - 1]));
    }
}
