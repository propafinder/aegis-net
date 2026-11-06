//! Header protection (RFC 9001 §5.4).
//!
//! For the AES suites the mask is `AES-ECB(hp_key, sample)` truncated to 5
//! bytes (§5.4.3); for ChaCha20-Poly1305 it is 5 bytes of ChaCha20 keystream
//! with the counter and nonce taken from the sample (§5.4.4). `ring` exposes
//! neither raw AES-ECB nor raw ChaCha20, so we use the pure-Rust `aes` and
//! `chacha20` crates here. This is transport crypto, not fingerprint-visible.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek};
use aes::{Aes128, Aes256};
use chacha20::ChaCha20;

/// Compute the 5-byte header-protection mask for a 16-byte `sample` using an
/// AES-128 `hp_key` (RFC 9001 §5.4.3).
pub fn aes_hp_mask(hp_key: &[u8; 16], sample: &[u8; 16]) -> [u8; 5] {
    let cipher = Aes128::new(hp_key.into());
    let mut block = *sample;
    cipher.encrypt_block((&mut block).into());
    [block[0], block[1], block[2], block[3], block[4]]
}

/// AES-256 variant of [`aes_hp_mask`] (used with `TLS_AES_256_GCM_SHA384`).
pub fn aes256_hp_mask(hp_key: &[u8; 32], sample: &[u8; 16]) -> [u8; 5] {
    let cipher = Aes256::new(hp_key.into());
    let mut block = *sample;
    cipher.encrypt_block((&mut block).into());
    [block[0], block[1], block[2], block[3], block[4]]
}

/// ChaCha20 header protection (RFC 9001 §5.4.4): the first 4 bytes of the
/// sample are the little-endian block counter, the remaining 12 the nonce; the
/// mask is the first 5 bytes of keystream.
pub fn chacha_hp_mask(hp_key: &[u8; 32], sample: &[u8; 16]) -> [u8; 5] {
    let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
    let nonce = GenericArray::from_slice(&sample[4..16]);
    let mut cipher = ChaCha20::new(GenericArray::from_slice(hp_key), nonce);
    cipher.seek(u64::from(counter) * 64);
    let mut mask = [0u8; 5];
    cipher.apply_keystream(&mut mask);
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9001 Appendix A.2: client Initial hp key + sample -> mask.
    #[test]
    fn rfc9001_a2_header_mask() {
        // hp key from the A.1 client Initial secret.
        let hp = hex::decode("9f50449e04a0e810283a1e9933adedd2").unwrap();
        let sample = hex::decode("d1b1c98dd7689fb8ec11d242b123dc9b").unwrap();
        let mut hp_arr = [0u8; 16];
        hp_arr.copy_from_slice(&hp);
        let mut s_arr = [0u8; 16];
        s_arr.copy_from_slice(&sample);
        let mask = aes_hp_mask(&hp_arr, &s_arr);
        assert_eq!(hex::encode(mask), "437b9aec36");
    }

    // RFC 9001 Appendix A.5: ChaCha20 header protection vector.
    #[test]
    fn rfc9001_a5_chacha_header_mask() {
        let hp = hex::decode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
            .unwrap();
        let sample = hex::decode("5e5cd55c41f69080575d7999c25a5bfb").unwrap();
        let mut hp_arr = [0u8; 32];
        hp_arr.copy_from_slice(&hp);
        let mut s_arr = [0u8; 16];
        s_arr.copy_from_slice(&sample);
        assert_eq!(hex::encode(chacha_hp_mask(&hp_arr, &s_arr)), "aefefe7d03");
    }
}
