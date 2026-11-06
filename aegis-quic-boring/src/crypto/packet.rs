//! AEAD packet protection helpers (RFC 9001 §5.3).
//!
//! The per-packet AEAD nonce is the static IV XOR'd with the (left-padded)
//! packet number. The actual seal/open is wired into the `quinn_proto`
//! `PacketKey` impl (M1.2) over this primitive; kept here so the nonce
//! construction is unit-testable on its own.

/// Construct the 12-byte AEAD nonce for `packet_number` from the static `iv`
/// (RFC 9001 §5.3): the 62-bit packet number is encoded as a big-endian
/// integer, left-padded to the IV length, then XOR'd with the IV.
pub fn nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn = packet_number.to_be_bytes(); // 8 bytes
    for (n, p) in nonce[4..].iter_mut().zip(pn.iter()) {
        *n ^= *p;
    }
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_xor_low_bytes() {
        let iv = [0u8; 12];
        // pn=1 lands in the last byte.
        assert_eq!(nonce(&iv, 1), {
            let mut e = [0u8; 12];
            e[11] = 1;
            e
        });
        // pn spanning two bytes.
        assert_eq!(nonce(&iv, 0x0102)[10..], [0x01, 0x02]);
    }

    #[test]
    fn nonce_preserves_iv_high_bytes() {
        let mut iv = [0u8; 12];
        iv[0] = 0xaa;
        assert_eq!(nonce(&iv, 0)[0], 0xaa);
    }
}
