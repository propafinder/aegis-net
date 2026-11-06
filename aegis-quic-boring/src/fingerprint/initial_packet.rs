//! Decode a QUIC Initial packet far enough to recover the ClientHello.
//!
//! Initial packets are encrypted, but with keys derived from the destination
//! connection ID that is in the clear (RFC 9001 §5.2) — so anyone on the path,
//! including a censor, can read them. That is exactly why the QUIC ClientHello
//! is fingerprintable, and it is what lets us measure a real browser's hello
//! with nothing but a UDP socket: no packet capture, no root.

use crate::crypto::header::aes_hp_mask;
use crate::crypto::initial::client_initial;
use crate::crypto::keys::{AeadPacketKey, QuicHeaderKey};
use crate::crypto::suite::Suite;
use crate::Error;

use bytes::BytesMut;
use quinn_proto::crypto::{HeaderKey, PacketKey};

/// One CRYPTO frame's contribution to the handshake byte stream.
#[derive(Debug, Clone)]
pub struct CryptoFragment {
    pub offset: usize,
    pub data: Vec<u8>,
}

/// The parts of a long-header packet we need.
#[derive(Debug)]
pub struct InitialPacket {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    /// CRYPTO fragments carried by this packet, with their stream offsets.
    pub crypto_fragments: Vec<CryptoFragment>,
    /// The fragments laid out contiguously from offset 0 — valid only when this
    /// single packet carries the whole message (see [`CryptoStream`] otherwise).
    pub crypto: Vec<u8>,
}

/// Upper bound on a reassembled handshake message.
///
/// A TLS handshake message carries a 3-byte length, so 16 MiB is the protocol
/// ceiling; a ClientHello is a few kilobytes. This exists to bound what an
/// attacker-supplied CRYPTO offset can make us allocate.
const MAX_HANDSHAKE_BYTES: usize = 1 << 24;

/// Reassembles the CRYPTO byte stream across several Initial packets.
///
/// A Chrome ClientHello does not fit in one datagram — the post-quantum key
/// share alone is over a kilobyte — so the hello arrives split across two or
/// more Initial packets that may also be reordered or retransmitted.
#[derive(Default)]
pub struct CryptoStream {
    buf: Vec<u8>,
    filled: Vec<bool>,
}

impl CryptoStream {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, fragment: &CryptoFragment) {
        // `offset` is an attacker-controlled 62-bit varint off the wire. Resizing to
        // it unchecked let a single CRYPTO frame ask for gigabytes (or, at 2^62-1,
        // exabytes) and abort the process on allocation failure. A TLS handshake
        // message cannot exceed MAX_HANDSHAKE_BYTES, so anything beyond that is not a
        // hello we could ever parse — drop the fragment instead of allocating for it.
        let Some(end) = fragment.offset.checked_add(fragment.data.len()) else {
            return;
        };
        if end > MAX_HANDSHAKE_BYTES {
            return;
        }
        if self.buf.len() < end {
            self.buf.resize(end, 0);
            self.filled.resize(end, false);
        }
        self.buf[fragment.offset..end].copy_from_slice(&fragment.data);
        for f in &mut self.filled[fragment.offset..end] {
            *f = true;
        }
    }

    pub fn push_packet(&mut self, packet: &InitialPacket) {
        for fragment in &packet.crypto_fragments {
            self.push(fragment);
        }
    }

    /// The complete handshake message, if every byte of it has arrived.
    ///
    /// The message length comes from the 4-byte handshake header, so this
    /// returns `None` until both the header and the whole body are present.
    pub fn complete_message(&self) -> Option<&[u8]> {
        if self.filled.len() < 4 || !self.filled[..4].iter().all(|f| *f) {
            return None;
        }
        let body_len = u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]]) as usize;
        let total = 4 + body_len;
        if self.filled.len() < total || !self.filled[..total].iter().all(|f| *f) {
            return None;
        }
        Some(&self.buf[..total])
    }
}

fn varint(buf: &[u8], pos: &mut usize) -> Result<u64, Error> {
    let first = *buf.get(*pos).ok_or(Error::Crypto("varint truncated"))?;
    let len = 1usize << (first >> 6);
    if *pos + len > buf.len() {
        return Err(Error::Crypto("varint truncated"));
    }
    let mut value = u64::from(first & 0x3f);
    for i in 1..len {
        value = (value << 8) | u64::from(buf[*pos + i]);
    }
    *pos += len;
    Ok(value)
}

/// Decrypt a client Initial packet from `datagram` and return its contents.
pub fn decode_client_initial(datagram: &[u8]) -> Result<InitialPacket, Error> {
    if datagram.len() < 7 {
        return Err(Error::Crypto("datagram too short"));
    }
    // Long header, type Initial (0b1100_xxxx), fixed bit set.
    if datagram[0] & 0xf0 != 0xc0 {
        return Err(Error::Crypto("not a long-header Initial packet"));
    }

    let mut pos = 1;
    let version = u32::from_be_bytes([
        datagram[pos],
        datagram[pos + 1],
        datagram[pos + 2],
        datagram[pos + 3],
    ]);
    pos += 4;

    let dcid_len = datagram[pos] as usize;
    pos += 1;
    let dcid = datagram
        .get(pos..pos + dcid_len)
        .ok_or(Error::Crypto("DCID truncated"))?
        .to_vec();
    pos += dcid_len;

    let scid_len = *datagram.get(pos).ok_or(Error::Crypto("SCID truncated"))? as usize;
    pos += 1;
    let scid = datagram
        .get(pos..pos + scid_len)
        .ok_or(Error::Crypto("SCID truncated"))?
        .to_vec();
    pos += scid_len;

    let token_len = varint(datagram, &mut pos)? as usize;
    pos += token_len;

    let length = varint(datagram, &mut pos)? as usize;
    let pn_offset = pos;
    let packet_end = pn_offset
        .checked_add(length)
        .filter(|e| *e <= datagram.len())
        .ok_or(Error::Crypto("length field past end of datagram"))?;

    // A real Initial carries a packet number (1-4 bytes) followed by at least a
    // 16-byte header-protection sample. Without this check a truncated `length`
    // (e.g. the 10-byte datagram `c0 00000001 00 00 00 01 00`) indexed past the
    // buffer both in header-protection removal and in the packet-number read below.
    // This decoder is fed hostile captures by design, and the workspace builds with
    // `panic = "abort"`, so an out-of-bounds index here is a process kill.
    if packet_end < pn_offset.saturating_add(4).saturating_add(16) {
        return Err(Error::Crypto(
            "Initial packet too short for header protection",
        ));
    }

    // Undo header protection with the client Initial keys derived from the DCID.
    let km = client_initial(&dcid);
    let mut packet = datagram[..packet_end].to_vec();
    let header_key = QuicHeaderKey::new(Suite::Aes128Gcm, &km.hp);
    header_key.decrypt(pn_offset, &mut packet);

    let pn_len = ((packet[0] & 0x03) + 1) as usize;
    let mut packet_number = 0u64;
    for i in 0..pn_len {
        packet_number = (packet_number << 8) | u64::from(packet[pn_offset + i]);
    }

    let header_len = pn_offset + pn_len;
    let header = packet[..header_len].to_vec();
    let mut payload = BytesMut::from(&packet[header_len..]);

    let packet_key = AeadPacketKey::new(Suite::Aes128Gcm, &km.key, km.iv);
    packet_key
        .decrypt(packet_number, &header, &mut payload)
        .map_err(|_| Error::Crypto("Initial packet failed to decrypt"))?;

    let crypto_fragments = collect_crypto_frames(&payload)?;
    let mut stream = CryptoStream::new();
    for fragment in &crypto_fragments {
        stream.push(fragment);
    }

    Ok(InitialPacket {
        version,
        dcid,
        scid,
        crypto: stream.buf.clone(),
        crypto_fragments,
    })
}

/// Walk the frames in a decrypted Initial payload and collect CRYPTO fragments.
fn collect_crypto_frames(payload: &[u8]) -> Result<Vec<CryptoFragment>, Error> {
    let mut out: Vec<CryptoFragment> = Vec::new();
    let mut pos = 0usize;

    while pos < payload.len() {
        let frame_type = payload[pos];
        pos += 1;
        match frame_type {
            0x00 => {} // PADDING
            0x01 => {} // PING
            0x02 | 0x03 => {
                // ACK: largest, delay, range count, first range, then ranges
                let _largest = varint(payload, &mut pos)?;
                let _delay = varint(payload, &mut pos)?;
                let count = varint(payload, &mut pos)?;
                let _first = varint(payload, &mut pos)?;
                for _ in 0..count {
                    let _gap = varint(payload, &mut pos)?;
                    let _len = varint(payload, &mut pos)?;
                }
                if frame_type == 0x03 {
                    for _ in 0..3 {
                        let _ecn = varint(payload, &mut pos)?;
                    }
                }
            }
            0x06 => {
                // CRYPTO
                let offset = varint(payload, &mut pos)? as usize;
                let len = varint(payload, &mut pos)? as usize;
                let data = payload
                    .get(pos..pos + len)
                    .ok_or(Error::Crypto("CRYPTO frame truncated"))?;
                pos += len;
                out.push(CryptoFragment {
                    offset,
                    data: data.to_vec(),
                });
            }
            _ => {
                // Any other frame type in an Initial packet means we can no
                // longer reliably find frame boundaries; stop rather than
                // misparse.
                break;
            }
        }
    }

    if out.is_empty() {
        return Err(Error::Crypto("no CRYPTO frames in Initial packet"));
    }
    Ok(out)
}

/// Exposed for tests: the header-protection mask helper this module relies on.
pub fn hp_mask(hp_key: &[u8; 16], sample: &[u8; 16]) -> [u8; 5] {
    aes_hp_mask(hp_key, sample)
}

#[cfg(test)]
mod tests {
    use super::*;

    // REGRESSION: this decoder is fed hostile captures by design (an operator points
    // it at "a suspicious client"), and the workspace builds with `panic = "abort"`,
    // so an out-of-bounds index is a process kill rather than a catchable error.
    // A 10-byte datagram used to index packet[13..29] during header-protection
    // removal, before any AEAD ran.
    #[test]
    fn short_datagram_is_rejected_not_panicking() {
        // c0 | version 00000001 | dcid_len 00 | scid_len 00 | token_len 00 |
        // length 01 | 1 body byte  -> pn_offset = 9, datagram.len() = 10
        let poc = [0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert!(decode_client_initial(&poc).is_err());

        // Every truncation of a real Initial must also be refused rather than panic.
        for len in 0..64 {
            let _ = decode_client_initial(&vec![0xc0; len]);
        }
    }

    // REGRESSION: `offset` is an attacker-controlled 62-bit varint. Reassembly used
    // to resize to it unchecked, so one frame could request exabytes and abort on
    // allocation failure. Oversized fragments must be dropped, not allocated for.
    #[test]
    fn absurd_crypto_offset_does_not_allocate() {
        let mut stream = CryptoStream::new();
        stream.push(&CryptoFragment {
            offset: usize::MAX - 8,
            data: vec![0u8; 4],
        });
        stream.push(&CryptoFragment {
            offset: MAX_HANDSHAKE_BYTES,
            data: vec![0u8; 1],
        });
        assert!(stream.buf.is_empty(), "oversized fragment was buffered");

        // A legitimately-offset fragment still reassembles.
        stream.push(&CryptoFragment {
            offset: 4,
            data: vec![7u8; 4],
        });
        assert_eq!(stream.buf.len(), 8);
    }

    /// RFC 9001 Appendix A.2: the full protected client Initial packet, which
    /// must decode back to a ClientHello.
    #[test]
    fn decodes_rfc9001_a2_client_initial() {
        let hex = concat!(
            "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
            "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
            "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
            "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212",
            "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
            "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
            "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec",
            "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3",
            "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
            "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
            "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8",
            "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
            "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74",
            "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a",
            "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
            "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632",
            "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964",
            "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
            "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff",
            "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
            "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
            "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73",
            "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f",
            "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
            "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
            "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047",
            "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
            "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4",
            "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0",
            "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
            "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0",
            "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400",
            "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
            "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9",
            "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
            "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
            "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241",
            "e221af44860018ab0856972e194cd934"
        );
        let datagram = hex::decode(hex).unwrap();
        let pkt = decode_client_initial(&datagram).expect("decrypt RFC 9001 A.2 Initial");
        assert_eq!(pkt.version, 1);
        assert_eq!(hex::encode(&pkt.dcid), "8394c8f03e515708");
        // The CRYPTO payload is the ClientHello handshake message.
        assert_eq!(pkt.crypto[0], 1, "first CRYPTO byte must be ClientHello");

        let hello = crate::fingerprint::clienthello::parse(&pkt.crypto)
            .expect("parse the recovered ClientHello");
        assert_eq!(hello.max_version(), 0x0304);
        assert_eq!(hello.server_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn rejects_non_initial_and_short_input() {
        assert!(decode_client_initial(&[]).is_err());
        assert!(decode_client_initial(&[0x40; 32]).is_err()); // short header
    }
}
