//! Bounded parent packet forwarding. The caller owns policy and worker admission.
//! PacketPort acceptance is queueing, never a relay/delivery acknowledgement.
use super::worker_ipc::PacketPort;
use crate::ingress::wide::ip_tunnel::PacketIo;
use std::io;

const MAX_PACKET: usize = 65_535;

pub(super) struct PacketPump {
    to_worker: Option<Vec<u8>>,
    to_device: Option<Vec<u8>>,
    stopped: bool,
}

impl PacketPump {
    pub(super) fn new() -> Self {
        Self {
            to_worker: None,
            to_device: None,
            stopped: false,
        }
    }

    fn admit(packet: Vec<u8>) -> io::Result<Vec<u8>> {
        let minimum = match packet.first().map(|v| v >> 4) {
            Some(4) => 20,
            Some(6) => 40,
            _ => usize::MAX,
        };
        if !(minimum..=MAX_PACKET).contains(&packet.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "parent packet frame rejected",
            ));
        }
        Ok(packet)
    }

    /// One read and one attempted send per direction, plus bounded IPC flush.
    /// Retain at most one additional packet per direction during backpressure.
    /// Do not hold a borrow of the worker across policy/control admission calls.
    #[cfg(test)]
    pub(super) fn step<D: PacketIo>(
        &mut self,
        device: &mut D,
        port: &mut PacketPort,
    ) -> io::Result<()> {
        self.step_admitted(device, port, || Ok(()))
    }

    /// Recheck cooperative admission before each device or IPC operation.
    /// The caller still owns the exact worker and native policy. This does not
    /// impose an atomic kernel deadline inside a synchronous syscall.
    pub(super) fn step_admitted<D: PacketIo>(
        &mut self,
        device: &mut D,
        port: &mut PacketPort,
        mut permitted: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.stopped {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let result = self.progress(device, port, &mut permitted);
        if result.is_err() {
            self.stop();
        }
        result
    }

    fn progress<D: PacketIo>(
        &mut self,
        device: &mut D,
        port: &mut PacketPort,
        permitted: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        permitted()?;
        port.flush_pending()?;
        if self.to_worker.is_none() {
            permitted()?;
            self.to_worker = device.receive()?.map(Self::admit).transpose()?;
        }
        if let Some(packet) = &self.to_worker {
            permitted()?;
            match port.send(packet) {
                Ok(()) => self.to_worker = None,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        if self.to_device.is_none() {
            permitted()?;
            self.to_device = port.receive()?.map(Self::admit).transpose()?;
        }
        if let Some(packet) = &self.to_device {
            permitted()?;
            match device.send(packet) {
                Ok(()) => self.to_device = None,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Discard only this pump's pending packets. The caller still confirms
    /// owned child exit and retains its PF guard before any rollback.
    pub(super) fn stop(&mut self) {
        self.stopped = true;
        self.to_worker = None;
        self.to_device = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos_tunnel::worker_ipc::{Limits, Role};
    use std::{collections::VecDeque, os::unix::net::UnixStream};

    #[derive(Default)]
    struct Device {
        incoming: VecDeque<Vec<u8>>,
        outgoing: Vec<Vec<u8>>,
        blocked: bool,
        reads: usize,
    }
    impl PacketIo for Device {
        fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
            self.reads += 1;
            Ok(self.incoming.pop_front())
        }
        fn send(&mut self, packet: &[u8]) -> io::Result<()> {
            if self.blocked {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.outgoing.push(packet.to_vec());
            Ok(())
        }
    }
    fn ports(limits: Limits) -> (PacketPort, PacketPort) {
        let (a, b) = UnixStream::pair().unwrap();
        (
            PacketPort::new(a, Role::Parent, limits).unwrap().0,
            PacketPort::new(b, Role::Worker, limits).unwrap().0,
        )
    }
    fn packet(version: u8, tag: u8) -> Vec<u8> {
        let mut packet = vec![tag; if version == 4 { 20 } else { 40 }];
        packet[0] = version << 4;
        packet
    }

    #[test]
    fn per_io_refusal_seals_queued_real_peer_response_before_device_delivery() {
        let (mut parent, mut worker) = ports(Limits::default());
        worker.send(&packet(6, 9)).unwrap();
        let mut device = Device::default();
        let mut pump = PacketPump::new();
        let mut boundaries = 0;
        let error = pump
            .step_admitted(&mut device, &mut parent, || {
                boundaries += 1;
                if boundaries == 4 {
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(boundaries, 4);
        assert!(device.outgoing.is_empty());
        assert!(pump.stopped && pump.to_device.is_none() && pump.to_worker.is_none());
    }

    #[test]
    fn actual_unix_bidirectional_frames_forward_once_and_device_backpressure_preserves_fifo() {
        let (mut parent, mut worker) = ports(Limits::default());
        let a = packet(4, 1);
        let b = packet(6, 2);
        worker.send(&a).unwrap();
        worker.send(&b).unwrap();
        let mut device = Device {
            incoming: VecDeque::from([b.clone()]),
            blocked: true,
            ..Default::default()
        };
        let mut pump = PacketPump::new();
        pump.step(&mut device, &mut parent).unwrap();
        assert_eq!(worker.receive().unwrap(), Some(b.clone()));
        for _ in 0..3 {
            pump.step(&mut device, &mut parent).unwrap();
        }
        assert_eq!(pump.to_device, Some(a.clone()));
        assert!(device.outgoing.is_empty());
        device.blocked = false;
        pump.step(&mut device, &mut parent).unwrap();
        pump.step(&mut device, &mut parent).unwrap();
        assert_eq!(device.outgoing, vec![a, b]);
        assert!(pump.to_worker.is_none() && pump.to_device.is_none());
        assert!(worker.receive().unwrap().is_none());
    }

    #[test]
    fn actual_unix_queue_refusal_retains_one_packet_without_reading_another() {
        let limits = Limits {
            max_packet_bytes: MAX_PACKET,
            max_queued_packets: 1,
            max_queued_bytes: MAX_PACKET + 8,
            max_io_ops: 1,
        };
        let (mut parent, mut worker) = ports(limits);
        let mut large = vec![0; MAX_PACKET];
        large[0] = 0x40;
        // Fill an actual Unix socket plus PacketPort's single-frame queue.
        for _ in 0..256 {
            if parent.send(&large).is_err() {
                break;
            }
        }
        assert_eq!(
            parent.send(&large).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let mut device = Device {
            incoming: VecDeque::from([packet(4, 7), packet(6, 8)]),
            ..Default::default()
        };
        let mut pump = PacketPump::new();
        pump.step(&mut device, &mut parent).unwrap();
        assert_eq!(pump.to_worker, Some(packet(4, 7)));
        let reads = device.reads;
        pump.step(&mut device, &mut parent).unwrap();
        assert_eq!(device.reads, reads);
        assert_eq!(device.incoming.len(), 1);
        // Drain the actual peer; the held frame must eventually be accepted.
        for _ in 0..4096 {
            let _ = worker.receive().unwrap();
            pump.step(&mut device, &mut parent).unwrap();
            if pump.to_worker.is_none() && device.incoming.is_empty() {
                break;
            }
        }
        assert!(pump.to_worker.is_none() && device.incoming.is_empty());
    }

    #[test]
    fn actual_peer_eof_seals_pending_pump_without_touching_foreign_capabilities() {
        let (mut parent, worker) = ports(Limits::default());
        let (mut foreign_parent, mut foreign_worker) = ports(Limits::default());
        drop(worker);
        let mut pump = PacketPump::new();
        let mut device = Device::default();
        assert!(pump.step(&mut device, &mut parent).is_err());
        assert!(pump.stopped);
        assert_eq!(
            pump.step(&mut device, &mut parent).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        foreign_parent.send(&packet(6, 9)).unwrap();
        assert_eq!(foreign_worker.receive().unwrap(), Some(packet(6, 9)));
    }

    #[test]
    fn invalid_or_oversized_device_frame_refuses_before_forwarding_and_stop_clears_only_owned_slots(
    ) {
        for data in [vec![0x40; 19], vec![0x60; MAX_PACKET + 1], vec![0; 40]] {
            let (mut parent, mut worker) = ports(Limits::default());
            let mut device = Device {
                incoming: VecDeque::from([data]),
                ..Default::default()
            };
            let mut pump = PacketPump::new();
            assert_eq!(
                pump.step(&mut device, &mut parent).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(pump.stopped && pump.to_worker.is_none() && pump.to_device.is_none());
            assert!(worker.receive().unwrap().is_none());
        }
    }
}
