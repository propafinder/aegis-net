//! Bounded packet bytes for a future authenticated provider/child XPC channel.
//! A frame is never evidence of peer identity, ACK, a packet lease or FACTORY.
//! The caller must supply the *actual* XPC peer UID from its audit token and
//! bind this session to an independently verified signed peer and live owner.
use crate::{bridge::validate_packet, intent_wire::decode_public_intent};
use sha2::{Digest, Sha256};
use std::io;
use subtle::ConstantTimeEq;

const MAGIC: &[u8] = b"AEGIS-PACKET-V1\0";
pub(crate) const MAX_PACKET: usize = u16::MAX as usize;
const HEADER_BYTES: usize = MAGIC.len() + 8 + 4 + 16 + 32 + 1 + 8 + 1 + 2;
pub(crate) const MAX_FRAME: usize = HEADER_BYTES + MAX_PACKET;

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "packet frame refused")
}

#[derive(Clone)]
pub(crate) struct FrameBinding {
    epoch: u64,
    uid: u32,
    nonce: [u8; 16],
    intent_sha256: [u8; 32],
}
impl FrameBinding {
    /// The digest is made only from R68's canonical, bounded public intent.
    /// Neither this constructor nor the supplied nonce authenticates an XPC
    /// peer; that admission belongs to the signed helper/child connection.
    pub(crate) fn from_public_intent(
        epoch: u64,
        uid: u32,
        nonce: [u8; 16],
        canonical_intent: &[u8],
    ) -> io::Result<Self> {
        if epoch == 0
            || uid == 0
            || nonce == [0; 16]
            || decode_public_intent(canonical_intent).is_err()
        {
            return Err(denied());
        }
        Ok(Self {
            epoch,
            uid,
            nonce,
            intent_sha256: Sha256::digest(canonical_intent).into(),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    ProviderToChild = 1,
    ChildToProvider = 2,
}

pub(crate) struct PacketFrameWriter {
    binding: FrameBinding,
    direction: Direction,
    last_sequence: u64,
}
impl PacketFrameWriter {
    pub(crate) fn new(binding: FrameBinding, direction: Direction) -> Self {
        Self {
            binding,
            direction,
            last_sequence: 0,
        }
    }
    pub(crate) fn encode(&mut self, packet: &[u8]) -> io::Result<Vec<u8>> {
        validate_packet(packet)?;
        let length = u16::try_from(packet.len()).map_err(|_| denied())?;
        let sequence = self.last_sequence.checked_add(1).ok_or_else(denied)?;
        let mut frame = Vec::with_capacity(HEADER_BYTES + packet.len());
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&self.binding.epoch.to_be_bytes());
        frame.extend_from_slice(&self.binding.uid.to_be_bytes());
        frame.extend_from_slice(&self.binding.nonce);
        frame.extend_from_slice(&self.binding.intent_sha256);
        frame.push(self.direction as u8);
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.push(packet[0] >> 4);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(packet);
        self.last_sequence = sequence;
        Ok(frame)
    }
}

pub(crate) struct PacketFrameReader {
    binding: FrameBinding,
    direction: Direction,
    last_sequence: u64,
    closed: bool,
}
impl PacketFrameReader {
    pub(crate) fn new(binding: FrameBinding, direction: Direction) -> Self {
        Self {
            binding,
            direction,
            last_sequence: 0,
            closed: false,
        }
    }
    /// One malformed, replayed or wrongly sourced frame permanently closes
    /// this reader. Return only borrowed packet bytes; no queue is touched.
    pub(crate) fn decode<'a>(
        &mut self,
        frame: &'a [u8],
        actual_peer_uid: u32,
    ) -> io::Result<&'a [u8]> {
        if self.closed {
            return Err(denied());
        }
        match self.decode_checked(frame, actual_peer_uid) {
            Ok(packet) => {
                self.last_sequence += 1;
                Ok(packet)
            }
            Err(_) => {
                self.closed = true;
                Err(denied())
            }
        }
    }
    /// Validate the exact next frame without advancing its sequence. This is
    /// used before queue backpressure so invalid frames still seal the reader
    /// while a valid frame remains retryable after a queue slot is released.
    pub(crate) fn peek<'a>(
        &mut self,
        frame: &'a [u8],
        actual_peer_uid: u32,
    ) -> io::Result<&'a [u8]> {
        if self.closed {
            return Err(denied());
        }
        match self.decode_checked(frame, actual_peer_uid) {
            Ok(packet) => Ok(packet),
            Err(_) => {
                self.closed = true;
                Err(denied())
            }
        }
    }
    fn decode_checked<'a>(&self, frame: &'a [u8], actual_peer_uid: u32) -> io::Result<&'a [u8]> {
        if frame.len() < HEADER_BYTES
            || frame.len() > MAX_FRAME
            || actual_peer_uid != self.binding.uid
        {
            return Err(denied());
        }
        let mut offset = 0;
        let magic = take(frame, &mut offset, MAGIC.len())?;
        let epoch = u64::from_be_bytes(
            take(frame, &mut offset, 8)?
                .try_into()
                .map_err(|_| denied())?,
        );
        let claimed_uid = u32::from_be_bytes(
            take(frame, &mut offset, 4)?
                .try_into()
                .map_err(|_| denied())?,
        );
        let nonce = take(frame, &mut offset, 16)?;
        let intent = take(frame, &mut offset, 32)?;
        let direction = take(frame, &mut offset, 1)?[0];
        let sequence = u64::from_be_bytes(
            take(frame, &mut offset, 8)?
                .try_into()
                .map_err(|_| denied())?,
        );
        let family = take(frame, &mut offset, 1)?[0];
        let length = usize::from(u16::from_be_bytes(
            take(frame, &mut offset, 2)?
                .try_into()
                .map_err(|_| denied())?,
        ));
        let packet = frame.get(offset..).ok_or_else(denied)?;
        let next = self.last_sequence.checked_add(1).ok_or_else(denied)?;
        if magic != MAGIC
            || epoch != self.binding.epoch
            || claimed_uid != self.binding.uid
            || !bool::from(nonce.ct_eq(&self.binding.nonce))
            || !bool::from(intent.ct_eq(&self.binding.intent_sha256))
            || direction != self.direction as u8
            || sequence != next
            || length != packet.len()
            || !matches!(family, 4 | 6)
            || packet.first().map(|byte| byte >> 4) != Some(family)
        {
            return Err(denied());
        }
        validate_packet(packet).map_err(|_| denied())?;
        Ok(packet)
    }
}

fn take<'a>(frame: &'a [u8], offset: &mut usize, length: usize) -> io::Result<&'a [u8]> {
    let end = offset.checked_add(length).ok_or_else(denied)?;
    let slice = frame.get(*offset..end).ok_or_else(denied)?;
    *offset = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{intent_wire::encode_public_intent, policy::FullWide};

    const UID: u32 = 501;
    fn intent() -> Vec<u8> {
        let policy = FullWide::new(
            "192.0.2.1".parse().unwrap(),
            vec!["198.51.100.53".parse().unwrap()],
            1280,
        )
        .unwrap();
        encode_public_intent("generation-1", &policy).unwrap()
    }
    fn binding() -> FrameBinding {
        FrameBinding::from_public_intent(7, UID, [9; 16], &intent()).unwrap()
    }
    fn ipv4() -> Vec<u8> {
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet
    }
    fn ipv6() -> Vec<u8> {
        let mut packet = vec![0; 40];
        packet[0] = 0x60;
        packet
    }
    fn frame() -> Vec<u8> {
        PacketFrameWriter::new(binding(), Direction::ProviderToChild)
            .encode(&ipv4())
            .unwrap()
    }

    #[test]
    fn public_intent_digest_has_independent_stable_vector() {
        // Computed independently from the five-field R68 byte format.
        assert_eq!(
            binding().intent_sha256,
            [
                0x64, 0xee, 0x5e, 0x2c, 0x13, 0xeb, 0x3c, 0x67, 0xfd, 0x4f, 0x67, 0x0e, 0x6f, 0x66,
                0x21, 0x90, 0xdf, 0x61, 0x77, 0x46, 0x31, 0x13, 0x05, 0x43, 0xa3, 0x78, 0x14, 0x41,
                0x99, 0x22, 0x4c, 0x62,
            ]
        );
    }

    #[test]
    fn exact_bounded_roundtrip_in_both_directions_and_families() {
        for (direction, packet) in [
            (Direction::ProviderToChild, ipv4()),
            (Direction::ChildToProvider, ipv6()),
        ] {
            let mut writer = PacketFrameWriter::new(binding(), direction);
            let mut reader = PacketFrameReader::new(binding(), direction);
            let first = writer.encode(&packet).unwrap();
            assert_eq!(reader.decode(&first, UID).unwrap(), packet);
            let second = writer.encode(&packet).unwrap();
            assert_eq!(reader.decode(&second, UID).unwrap(), packet);
            assert_eq!(first.len(), HEADER_BYTES + packet.len());
        }
    }

    #[test]
    fn tampered_binding_direction_sequence_length_and_packet_seal_reader() {
        let original = frame();
        let epoch = MAGIC.len();
        let uid = epoch + 8;
        let nonce = uid + 4;
        let digest = nonce + 16;
        let direction = digest + 32;
        let sequence = direction + 1;
        let family = sequence + 8;
        let length = family + 1;
        for index in [
            0,
            epoch,
            uid,
            nonce,
            digest,
            direction,
            sequence + 7,
            family,
            length + 1,
            HEADER_BYTES + 2,
        ] {
            let mut tampered = original.clone();
            tampered[index] ^= 1;
            let mut reader = PacketFrameReader::new(binding(), Direction::ProviderToChild);
            assert!(reader.decode(&tampered, UID).is_err(), "offset {index}");
            assert!(
                reader.decode(&original, UID).is_err(),
                "reader reopened after offset {index}"
            );
        }
        let mut reader = PacketFrameReader::new(binding(), Direction::ProviderToChild);
        assert!(reader.decode(&original[..original.len() - 1], UID).is_err());
        assert!(reader.decode(&original, UID).is_err());
        let mut reader = PacketFrameReader::new(binding(), Direction::ProviderToChild);
        assert!(reader
            .decode(&[original.as_slice(), b"x"].concat(), UID)
            .is_err());
        let mut reader = PacketFrameReader::new(binding(), Direction::ProviderToChild);
        assert!(reader.decode(&original, UID + 1).is_err());
        assert!(reader.decode(&original, UID).is_err());
        let mut reader = PacketFrameReader::new(binding(), Direction::ChildToProvider);
        assert!(reader.decode(&original, UID).is_err());
        let mut reader = PacketFrameReader::new(binding(), Direction::ProviderToChild);
        assert!(reader.decode(&vec![0; MAX_FRAME + 1], UID).is_err());
    }

    #[test]
    fn replay_gap_and_sequence_exhaustion_refuse_without_packet_delivery() {
        let mut writer = PacketFrameWriter::new(binding(), Direction::ProviderToChild);
        let first = writer.encode(&ipv4()).unwrap();
        let second = writer.encode(&ipv4()).unwrap();
        let mut reader = PacketFrameReader::new(binding(), Direction::ProviderToChild);
        assert_eq!(reader.decode(&first, UID).unwrap(), ipv4());
        assert!(reader.decode(&first, UID).is_err());
        assert!(reader.decode(&second, UID).is_err());
        let mut reader = PacketFrameReader::new(binding(), Direction::ProviderToChild);
        assert!(reader.decode(&second, UID).is_err());
        writer.last_sequence = u64::MAX;
        assert!(writer.encode(&ipv4()).is_err());
        reader.last_sequence = u64::MAX;
        assert!(reader.decode(&first, UID).is_err());
    }

    #[test]
    fn canonical_intent_and_packet_bounds_are_required() {
        assert!(FrameBinding::from_public_intent(0, UID, [9; 16], &intent()).is_err());
        assert!(FrameBinding::from_public_intent(7, 0, [9; 16], &intent()).is_err());
        assert!(FrameBinding::from_public_intent(7, UID, [0; 16], &intent()).is_err());
        assert!(FrameBinding::from_public_intent(7, UID, [9; 16], b"bad").is_err());
        let mut writer = PacketFrameWriter::new(binding(), Direction::ProviderToChild);
        assert!(writer.encode(&[0u8; 20]).is_err());
        assert!(writer.encode(&vec![0x45; MAX_PACKET + 1]).is_err());
        assert_eq!(writer.encode(&ipv4()).unwrap().len(), HEADER_BYTES + 20);
    }

    #[test]
    fn changed_canonical_intent_digest_refuses_frame() {
        let policy = FullWide::new(
            "192.0.2.2".parse().unwrap(),
            vec!["198.51.100.53".parse().unwrap()],
            1280,
        )
        .unwrap();
        let changed = encode_public_intent("generation-1", &policy).unwrap();
        let other = FrameBinding::from_public_intent(7, UID, [9; 16], &changed).unwrap();
        let mut reader = PacketFrameReader::new(other, Direction::ProviderToChild);
        assert!(reader.decode(&frame(), UID).is_err());
    }
}
