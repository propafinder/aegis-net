//! `quinn_proto::crypto::{PacketKey, HeaderKey}` implementations over a standard
//! AEAD (`ring`) + AES/ChaCha header protection. These are the transport-crypto
//! objects quinn drives per packet; they are cipher-suite-generic and carry no
//! fingerprint (the fingerprint is the TLS ClientHello, see [`crate::config`]).

use bytes::BytesMut;
use quinn_proto::crypto::{CryptoError, HeaderKey, KeyPair, Keys, PacketKey};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::header::{aes256_hp_mask, aes_hp_mask, chacha_hp_mask};
use super::initial::{client_initial, server_initial, InitialKeyMaterial};
use super::packet;
use super::secrets;
use super::suite::Suite;

/// AEAD packet-protection key.
pub struct AeadPacketKey {
    key: LessSafeKey,
    iv: [u8; 12],
    tag_len: usize,
    suite: Suite,
}

impl AeadPacketKey {
    pub fn new(suite: Suite, key_bytes: &[u8], iv: [u8; 12]) -> Self {
        let algo = suite.aead();
        let key = LessSafeKey::new(
            UnboundKey::new(algo, key_bytes).expect("aead key length matches suite"),
        );
        AeadPacketKey {
            key,
            iv,
            tag_len: algo.tag_len(),
            suite,
        }
    }
}

impl PacketKey for AeadPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let split = payload_tag.len() - self.tag_len;
        let (payload, tag_out) = payload_tag.split_at_mut(split);
        let nonce = Nonce::assume_unique_for_key(packet::nonce(&self.iv, packet));
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(&*header), payload)
            .expect("aead seal");
        tag_out.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let nonce = Nonce::assume_unique_for_key(packet::nonce(&self.iv, packet));
        let plain_len = self
            .key
            .open_in_place(nonce, Aad::from(header), payload.as_mut())
            .map_err(|_| CryptoError)?
            .len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.tag_len
    }

    // RFC 9001 §6.6 AEAD usage limits.
    fn confidentiality_limit(&self) -> u64 {
        if self.suite.is_chacha() {
            1 << 62
        } else {
            1 << 23
        }
    }

    fn integrity_limit(&self) -> u64 {
        if self.suite.is_chacha() {
            1 << 36
        } else {
            1 << 52
        }
    }
}

/// Header-protection key material, per suite (RFC 9001 §5.4.3/§5.4.4).
#[derive(Zeroize, ZeroizeOnDrop)]
enum HpMaterial {
    Aes128([u8; 16]),
    Aes256([u8; 32]),
    ChaCha([u8; 32]),
}

/// Header-protection key.
pub struct QuicHeaderKey {
    hp: HpMaterial,
}

impl QuicHeaderKey {
    pub fn new(suite: Suite, hp: &[u8]) -> Self {
        let material = match suite {
            Suite::Aes128Gcm => {
                let mut k = [0u8; 16];
                k.copy_from_slice(hp);
                HpMaterial::Aes128(k)
            }
            Suite::Aes256Gcm => {
                let mut k = [0u8; 32];
                k.copy_from_slice(hp);
                HpMaterial::Aes256(k)
            }
            Suite::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(hp);
                HpMaterial::ChaCha(k)
            }
        };
        QuicHeaderKey { hp: material }
    }

    fn mask(&self, sample: &[u8; 16]) -> [u8; 5] {
        match &self.hp {
            HpMaterial::Aes128(k) => aes_hp_mask(k, sample),
            HpMaterial::Aes256(k) => aes256_hp_mask(k, sample),
            HpMaterial::ChaCha(k) => chacha_hp_mask(k, sample),
        }
    }

    /// Apply the header-protection mask in place. `encrypt` and `decrypt` differ
    /// only in whether the packet-number length is read before or after the
    /// first byte is (un)masked.
    fn apply(&self, pn_offset: usize, packet: &mut [u8], decrypt: bool) {
        // Defence in depth: quinn rejects packets too short to carry a header-
        // protection sample before it ever calls us, but this type is also reachable
        // from the offline fingerprint decoder, which is fed hostile captures by
        // design. Indexing unchecked here turned a 10-byte datagram into a panic —
        // and the workspace builds with `panic = "abort"`, so that is a process kill.
        // A packet this short cannot be valid, and the AEAD below would reject it
        // anyway, so leaving it untouched is the correct no-op.
        let Some(sample_end) = pn_offset.checked_add(4).and_then(|o| o.checked_add(16)) else {
            return;
        };
        if packet.len() < sample_end {
            return;
        }
        let sample_off = pn_offset + 4;
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&packet[sample_off..sample_off + 16]);
        let mask = self.mask(&sample);

        // Long-header packets mask the low 4 bits of the first byte, short
        // headers the low 5 bits (RFC 9001 §5.4.1).
        let long = packet[0] & 0x80 != 0;
        let first_mask = if long { 0x0f } else { 0x1f };

        if decrypt {
            packet[0] ^= mask[0] & first_mask;
        }
        let pn_len = ((packet[0] & 0x03) + 1) as usize;
        if !decrypt {
            packet[0] ^= mask[0] & first_mask;
        }
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
    }
}

impl HeaderKey for QuicHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(pn_offset, packet, true);
    }
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(pn_offset, packet, false);
    }
    fn sample_size(&self) -> usize {
        16
    }
}

/// Build the packet + header key for one direction from a TLS traffic secret.
pub fn keys_from_secret(suite: Suite, secret: &[u8]) -> (AeadPacketKey, QuicHeaderKey) {
    let material = secrets::derive(suite, secret);
    (
        AeadPacketKey::new(suite, &material.key, material.iv),
        QuicHeaderKey::new(suite, &material.hp),
    )
}

/// Build only the packet key (used on key update, where header keys are reused).
pub fn packet_key_from_secret(suite: Suite, secret: &[u8]) -> AeadPacketKey {
    let material = secrets::derive(suite, secret);
    AeadPacketKey::new(suite, &material.key, material.iv)
}

fn material_to_keys(local: &InitialKeyMaterial, remote: &InitialKeyMaterial) -> Keys {
    Keys {
        header: KeyPair {
            local: Box::new(QuicHeaderKey::new(Suite::Aes128Gcm, &local.hp)),
            remote: Box::new(QuicHeaderKey::new(Suite::Aes128Gcm, &remote.hp)),
        },
        packet: KeyPair {
            local: Box::new(AeadPacketKey::new(Suite::Aes128Gcm, &local.key, local.iv)),
            remote: Box::new(AeadPacketKey::new(Suite::Aes128Gcm, &remote.key, remote.iv)),
        },
    }
}

/// Build the RFC 9001 Initial `Keys` for the given DCID and side.
pub fn initial_keys(dcid: &[u8], side: quinn_proto::Side) -> Keys {
    let client = client_initial(dcid);
    let server = server_initial(dcid);
    match side {
        quinn_proto::Side::Client => material_to_keys(&client, &server),
        quinn_proto::Side::Server => material_to_keys(&server, &client),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_round_trip() {
        let km = client_initial(&hex::decode("8394c8f03e515708").unwrap());
        let pk = AeadPacketKey::new(Suite::Aes128Gcm, &km.key, km.iv);
        let header = [0xc3u8, 0, 0, 0, 1];
        let plaintext = b"hello quic";
        let mut buf = Vec::new();
        buf.extend_from_slice(&header);
        buf.extend_from_slice(plaintext);
        buf.extend_from_slice(&[0u8; 16]); // tag space
        pk.encrypt(0, &mut buf, header.len());
        let mut payload = BytesMut::from(&buf[header.len()..]);
        pk.decrypt(0, &header, &mut payload).unwrap();
        assert_eq!(&payload[..], plaintext);
    }

    #[test]
    fn aead_rejects_tampered_payload() {
        let km = client_initial(&hex::decode("8394c8f03e515708").unwrap());
        let pk = AeadPacketKey::new(Suite::Aes128Gcm, &km.key, km.iv);
        let header = [0xc3u8, 0, 0, 0, 1];
        let mut buf = header.to_vec();
        buf.extend_from_slice(b"hello quic");
        buf.extend_from_slice(&[0u8; 16]);
        pk.encrypt(0, &mut buf, header.len());
        buf[header.len()] ^= 0xff;
        let mut payload = BytesMut::from(&buf[header.len()..]);
        assert!(pk.decrypt(0, &header, &mut payload).is_err());
    }

    #[test]
    fn header_protection_round_trip_all_suites() {
        for (suite, hp) in [
            (Suite::Aes128Gcm, vec![7u8; 16]),
            (Suite::Aes256Gcm, vec![7u8; 32]),
            (Suite::ChaCha20Poly1305, vec![7u8; 32]),
        ] {
            let hk = QuicHeaderKey::new(suite, &hp);
            // short header, pn_len=2 (low bits = 01)
            let mut packet = vec![0x41u8, 0xaa, 0xbb];
            packet.extend_from_slice(&[0x11u8; 20]);
            let orig = packet.clone();
            hk.encrypt(1, &mut packet);
            assert_ne!(packet[..3], orig[..3], "{suite:?} did not mask");
            hk.decrypt(1, &mut packet);
            assert_eq!(packet[..3], orig[..3], "{suite:?} round-trip failed");
        }
    }

    #[test]
    fn traffic_secret_produces_working_keys() {
        for suite in [Suite::Aes128Gcm, Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
            let secret = vec![0x5au8; if suite == Suite::Aes256Gcm { 48 } else { 32 }];
            let (pk, _hk) = keys_from_secret(suite, &secret);
            let header = [0x41u8, 0, 1];
            let mut buf = header.to_vec();
            buf.extend_from_slice(b"payload");
            buf.extend_from_slice(&[0u8; 16]);
            pk.encrypt(3, &mut buf, header.len());
            let mut payload = BytesMut::from(&buf[header.len()..]);
            pk.decrypt(3, &header, &mut payload).unwrap();
            assert_eq!(&payload[..], b"payload");
        }
    }
}
