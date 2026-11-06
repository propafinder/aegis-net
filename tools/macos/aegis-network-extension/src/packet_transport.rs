//! Bounded packet admission for a future signed XPC connection.
//! The R66 gate must already have installed its exact peer code requirement
//! before the connection is resumed. This module neither installs that
//! requirement nor treats frames as Store, packet-flow, or FACTORY grants.
use crate::packet_frame::{
    Direction, FrameBinding, PacketFrameReader, PacketFrameWriter, MAX_FRAME, MAX_PACKET,
};
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, ffi::c_void, io, ptr::NonNull};
use subtle::ConstantTimeEq;

const NONCE_DOMAIN: &[u8] = b"AEGIS-NE-XPC-PACKET-SESSION-V1\0";
const MAX_QUEUED_FRAMES: usize = 8;
const MAX_QUEUED_BYTES: usize = MAX_QUEUED_FRAMES * MAX_PACKET;

extern "C" {
    fn xpc_connection_get_euid(connection: *mut c_void) -> libc::uid_t;
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "XPC packet admission refused",
    )
}

/// The exact fields already agreed by the signed R66/R67 start/ready exchange.
pub(crate) struct ReadyEvidence {
    pub(crate) epoch: u64,
    pub(crate) uid: u32,
    pub(crate) intent_digest: [u8; 32],
    pub(crate) request_nonce: [u8; 32],
    pub(crate) helper_nonce: [u8; 32],
}

fn binding(evidence: &ReadyEvidence, intent: &[u8]) -> io::Result<FrameBinding> {
    if evidence.epoch == 0
        || evidence.uid == 0
        || evidence.request_nonce == [0; 32]
        || evidence.helper_nonce == [0; 32]
        || !bool::from(
            Sha256::digest(intent)
                .as_slice()
                .ct_eq(&evidence.intent_digest),
        )
    {
        return Err(denied());
    }
    let mut hasher = Sha256::new();
    hasher.update(NONCE_DOMAIN);
    hasher.update(evidence.epoch.to_be_bytes());
    hasher.update(evidence.uid.to_be_bytes());
    hasher.update(evidence.intent_digest);
    hasher.update(evidence.request_nonce);
    hasher.update(evidence.helper_nonce);
    let digest = hasher.finalize();
    let mut nonce = [0; 16];
    nonce.copy_from_slice(&digest[..16]);
    FrameBinding::from_public_intent(evidence.epoch, evidence.uid, nonce, intent)
}

/// One serial XPC callback owner; its queue contains validated packet bytes only.
/// No Clone/Send/Sync: the caller must serialize message and dequeue handling.
pub(crate) struct BoundedPacketIngress {
    peer: NonNull<c_void>,
    uid: u32,
    reader: PacketFrameReader,
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    closed: bool,
}

impl BoundedPacketIngress {
    /// # Safety
    /// `peer` must remain a live, retained XPC connection for this object's
    /// lifetime, with the exact R66/R67 peer code-signing requirement already
    /// installed before resume. `evidence` must come from that connection's
    /// validated ready message and physical child owner, not frame claims.
    pub(crate) unsafe fn new(
        peer: NonNull<c_void>,
        evidence: &ReadyEvidence,
        canonical_intent: &[u8],
        direction: Direction,
    ) -> io::Result<Self> {
        if unsafe { xpc_connection_get_euid(peer.as_ptr()) } != evidence.uid {
            return Err(denied());
        }
        Ok(Self {
            peer,
            uid: evidence.uid,
            reader: PacketFrameReader::new(binding(evidence, canonical_intent)?, direction),
            pending: VecDeque::new(),
            pending_bytes: 0,
            closed: false,
        })
    }

    /// # Safety
    /// `source` must be the connection associated with `frame` by the XPC
    /// callback. The caller must check the XPC value type and data length
    /// before constructing the borrowed slice; this method also checks length
    /// before copying or decoding. The XPC data must stay live for this call.
    pub(crate) unsafe fn enqueue_from_xpc(
        &mut self,
        source: NonNull<c_void>,
        frame: &[u8],
    ) -> io::Result<()> {
        if source != self.peer {
            self.close();
            return Err(denied());
        }
        let observed_uid = unsafe { xpc_connection_get_euid(source.as_ptr()) };
        self.enqueue_observed(frame, observed_uid)
    }

    fn enqueue_observed(&mut self, frame: &[u8], observed_uid: u32) -> io::Result<()> {
        if self.closed || frame.len() > MAX_FRAME || frame.len() < MAX_FRAME - MAX_PACKET {
            self.close();
            return Err(denied());
        }
        let prospective_packet_bytes = frame.len() - (MAX_FRAME - MAX_PACKET);
        // Validate identity, binding, packet contents and the expected next
        // sequence even when full. peek seals invalid frames without consuming
        // the sequence of a valid frame that needs retry after backpressure.
        if observed_uid != self.uid || self.reader.peek(frame, observed_uid).is_err() {
            self.close();
            return Err(denied());
        }
        if self.pending.len() >= MAX_QUEUED_FRAMES
            || self.pending_bytes + prospective_packet_bytes > MAX_QUEUED_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "XPC packet queue full",
            ));
        }
        match self.reader.decode(frame, observed_uid) {
            Ok(packet) if observed_uid == self.uid => {
                self.pending_bytes += packet.len();
                self.pending.push_back(packet.to_vec());
                Ok(())
            }
            _ => {
                self.close();
                Err(denied())
            }
        }
    }

    pub(crate) fn pop(&mut self) -> Option<Vec<u8>> {
        let packet = self.pending.pop_front()?;
        self.pending_bytes -= packet.len();
        Some(packet)
    }

    pub(crate) fn close(&mut self) {
        self.closed = true;
        self.pending.clear();
        self.pending_bytes = 0;
    }
}

/// Uses the same evidence to send the opposite-direction packet stream.
pub(crate) fn writer(
    evidence: &ReadyEvidence,
    canonical_intent: &[u8],
    direction: Direction,
) -> io::Result<PacketFrameWriter> {
    Ok(PacketFrameWriter::new(
        binding(evidence, canonical_intent)?,
        direction,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{intent_wire::encode_public_intent, policy::FullWide};

    fn intent() -> Vec<u8> {
        let policy = FullWide::new(
            "192.0.2.1".parse().unwrap(),
            vec!["198.51.100.53".parse().unwrap()],
            1280,
        )
        .unwrap();
        encode_public_intent("generation-1", &policy).unwrap()
    }
    fn test_evidence(intent: &[u8]) -> ReadyEvidence {
        ReadyEvidence {
            epoch: 7,
            uid: 501,
            intent_digest: Sha256::digest(intent).into(),
            request_nonce: [0x52; 32],
            helper_nonce: [0x53; 32],
        }
    }
    fn packet() -> Vec<u8> {
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet
    }
    fn ingress(evidence: &ReadyEvidence, intent: &[u8]) -> BoundedPacketIngress {
        BoundedPacketIngress {
            peer: NonNull::dangling(),
            uid: evidence.uid,
            reader: PacketFrameReader::new(
                binding(evidence, intent).unwrap(),
                Direction::ProviderToChild,
            ),
            pending: VecDeque::new(),
            pending_bytes: 0,
            closed: false,
        }
    }
    fn full_queue(
        evidence: &ReadyEvidence,
        intent: &[u8],
    ) -> (BoundedPacketIngress, Vec<u8>, Vec<u8>) {
        let mut sender = writer(evidence, intent, Direction::ProviderToChild).unwrap();
        let mut rx = ingress(evidence, intent);
        let first = sender.encode(&packet()).unwrap();
        rx.enqueue_observed(&first, evidence.uid).unwrap();
        for _ in 1..MAX_QUEUED_FRAMES {
            rx.enqueue_observed(&sender.encode(&packet()).unwrap(), evidence.uid)
                .unwrap();
        }
        let next = sender.encode(&packet()).unwrap();
        (rx, first, next)
    }

    #[test]
    fn both_ready_nonces_and_canonical_intent_bind_frame() {
        let intent = intent();
        let evidence = test_evidence(&intent);
        let frame = writer(&evidence, &intent, Direction::ProviderToChild)
            .unwrap()
            .encode(&packet())
            .unwrap();
        let mut rx = ingress(&evidence, &intent);
        rx.enqueue_observed(&frame, 501).unwrap();
        assert_eq!(rx.pop(), Some(packet()));
        for altered in [
            ReadyEvidence {
                request_nonce: [0x54; 32],
                ..test_evidence(&intent)
            },
            ReadyEvidence {
                helper_nonce: [0x54; 32],
                ..test_evidence(&intent)
            },
            ReadyEvidence {
                epoch: 8,
                ..test_evidence(&intent)
            },
        ] {
            let mut wrong = ingress(&altered, &intent);
            assert!(wrong.enqueue_observed(&frame, 501).is_err());
            assert!(wrong.closed);
        }
        let mut wrong_digest = test_evidence(&intent);
        wrong_digest.intent_digest[0] ^= 1;
        assert!(binding(&wrong_digest, &intent).is_err());
    }

    #[test]
    fn uid_spoof_replay_and_bad_length_close_and_drop_pending() {
        let intent = intent();
        let evidence = test_evidence(&intent);
        let frame = writer(&evidence, &intent, Direction::ProviderToChild)
            .unwrap()
            .encode(&packet())
            .unwrap();
        let mut rx = ingress(&evidence, &intent);
        assert!(rx.enqueue_observed(&frame, 502).is_err());
        assert!(rx.closed);
        assert!(rx.pop().is_none());
        let mut rx = ingress(&evidence, &intent);
        rx.enqueue_observed(&frame, 501).unwrap();
        assert!(rx.enqueue_observed(&frame, 501).is_err());
        assert!(rx.pop().is_none());
        let mut rx = ingress(&evidence, &intent);
        assert!(rx.enqueue_observed(&vec![0; MAX_FRAME + 1], 501).is_err());
        assert!(rx.closed);
    }

    #[test]
    fn distinct_xpc_source_is_refused_before_peer_uid_lookup() {
        let intent = intent();
        let evidence = test_evidence(&intent);
        let mut rx = ingress(&evidence, &intent);
        let different_source = NonNull::new(2usize as *mut c_void).unwrap();
        // No live XPC handle exists in this unit test. The mismatched source
        // must be rejected before the system peer-EUID function is called.
        assert!(unsafe { rx.enqueue_from_xpc(different_source, &[]) }.is_err());
        assert!(rx.closed);
    }

    #[test]
    fn missing_ready_nonce_and_opposite_direction_are_refused() {
        let intent = intent();
        let mut missing_nonce = test_evidence(&intent);
        missing_nonce.request_nonce = [0; 32];
        assert!(binding(&missing_nonce, &intent).is_err());
        missing_nonce = test_evidence(&intent);
        missing_nonce.helper_nonce = [0; 32];
        assert!(binding(&missing_nonce, &intent).is_err());
        let evidence = test_evidence(&intent);
        let frame = writer(&evidence, &intent, Direction::ChildToProvider)
            .unwrap()
            .encode(&packet())
            .unwrap();
        let mut rx = ingress(&evidence, &intent);
        assert!(rx.enqueue_observed(&frame, 501).is_err());
        assert!(rx.closed);
    }

    #[test]
    fn queue_pressure_rejects_before_sequence_consumption() {
        let intent = intent();
        let evidence = test_evidence(&intent);
        let mut writer = writer(&evidence, &intent, Direction::ProviderToChild).unwrap();
        let mut ingress = ingress(&evidence, &intent);
        for _ in 0..MAX_QUEUED_FRAMES {
            ingress
                .enqueue_observed(&writer.encode(&packet()).unwrap(), 501)
                .unwrap();
        }
        let ninth = writer.encode(&packet()).unwrap();
        assert_eq!(
            ingress.enqueue_observed(&ninth, 501).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(ingress.pop(), Some(packet()));
        ingress.enqueue_observed(&ninth, 501).unwrap();
        assert_eq!(ingress.pending.len(), MAX_QUEUED_FRAMES);
    }

    #[test]
    fn full_queue_still_seals_malformed_replayed_and_wrong_uid_frames() {
        let intent = intent();
        let evidence = test_evidence(&intent);
        let (mut rx, _, mut next) = full_queue(&evidence, &intent);
        next[0] ^= 1;
        assert_eq!(
            rx.enqueue_observed(&next, 501).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(rx.closed && rx.pending.is_empty());

        let (mut rx, first, _) = full_queue(&evidence, &intent);
        assert_eq!(
            rx.enqueue_observed(&first, 501).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(rx.closed && rx.pending.is_empty());

        let (mut rx, _, next) = full_queue(&evidence, &intent);
        assert_eq!(
            rx.enqueue_observed(&next, 502).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(rx.closed && rx.pending.is_empty());
    }
}
