//! Bounded, nonblocking packet transport for an owned Unix IPC capability.
//! This is packet IPC, not identity authentication or capture readiness. In
//! particular, a root-created socketpair cannot prove a later child's UID.
#[path = "launch_contract.rs"]
pub(crate) mod launch_contract;
use crate::ingress::wide::ip_tunnel::PacketIo;
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const HEADER: usize = 8;
const VERSION: u8 = 1;
const MAX_PACKET: usize = 65536;
const MAX_QUEUE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Role {
    Parent,
    Worker,
}
impl Role {
    fn outbound(self) -> u8 {
        match self {
            Self::Parent => 1,
            Self::Worker => 2,
        }
    }
    fn inbound(self) -> u8 {
        match self {
            Self::Parent => 2,
            Self::Worker => 1,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub max_packet_bytes: usize,
    pub max_queued_packets: usize,
    pub max_queued_bytes: usize,
    pub max_io_ops: usize,
}
impl Limits {
    fn validate(self) -> io::Result<Self> {
        if !(40..=MAX_PACKET).contains(&self.max_packet_bytes)
            || !(1..=512).contains(&self.max_queued_packets)
            || !(self.max_packet_bytes + HEADER..=MAX_QUEUE_BYTES).contains(&self.max_queued_bytes)
            || !(1..=64).contains(&self.max_io_ops)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPC limits rejected",
            ));
        }
        Ok(self)
    }
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_packet_bytes: MAX_PACKET,
            max_queued_packets: 64,
            max_queued_bytes: 4 * 1024 * 1024,
            max_io_ops: 16,
        }
    }
}

pub(crate) struct CancelHandle {
    socket: UnixStream,
    cancelled: Arc<AtomicBool>,
}
impl CancelHandle {
    /// Only shuts down the capability cloned from this adapter's owned socket.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}
struct Pending {
    bytes: Vec<u8>,
    written: usize,
}
pub(crate) struct PacketPort {
    socket: UnixStream,
    role: Role,
    limits: Limits,
    cancelled: Arc<AtomicBool>,
    terminal: Option<io::ErrorKind>,
    prefix: [u8; HEADER],
    prefix_read: usize,
    payload: Vec<u8>,
    payload_read: usize,
    output: VecDeque<Pending>,
    queued_bytes: usize,
}
impl PacketPort {
    pub fn new(socket: UnixStream, role: Role, limits: Limits) -> io::Result<(Self, CancelHandle)> {
        let limits = limits.validate()?;
        socket.set_nonblocking(true)?;
        let handle = CancelHandle {
            socket: socket.try_clone()?,
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let port = Self {
            socket,
            role,
            limits,
            cancelled: handle.cancelled.clone(),
            terminal: None,
            prefix: [0; HEADER],
            prefix_read: 0,
            payload: Vec::new(),
            payload_read: 0,
            output: VecDeque::new(),
            queued_bytes: 0,
        };
        Ok((port, handle))
    }
    pub fn queued(&self) -> (usize, usize) {
        (self.output.len(), self.queued_bytes)
    }
    fn check(&mut self) -> io::Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(self.seal(io::ErrorKind::Interrupted));
        }
        if let Some(kind) = self.terminal {
            return Err(io::Error::new(kind, "IPC closed"));
        }
        Ok(())
    }
    fn seal(&mut self, kind: io::ErrorKind) -> io::Error {
        self.terminal.get_or_insert(kind);
        self.output.clear();
        self.queued_bytes = 0;
        self.payload.clear();
        self.payload_read = 0;
        let _ = self.socket.shutdown(Shutdown::Both);
        io::Error::new(kind, "IPC closed")
    }
    /// Progress pending writes with a fixed syscall budget, even during a quiet
    /// receive poll. Ok means queued acceptance, not delivery to the OS/relay.
    pub fn flush_pending(&mut self) -> io::Result<()> {
        let mut remaining = self.limits.max_io_ops;
        self.flush_budget(&mut remaining)
    }
    fn flush_budget(&mut self, remaining: &mut usize) -> io::Result<()> {
        while *remaining > 0 {
            self.check()?;
            let Some(frame) = self.output.front_mut() else {
                return Ok(());
            };
            *remaining -= 1;
            match self.socket.write(&frame.bytes[frame.written..]) {
                Ok(0) => return Err(self.seal(io::ErrorKind::WriteZero)),
                Ok(n) => {
                    frame.written += n;
                    if frame.written == frame.bytes.len() {
                        self.queued_bytes -= frame.bytes.len();
                        self.output.pop_front();
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(self.seal(e.kind())),
            }
        }
        Ok(())
    }
    fn validate_packet(packet: &[u8], max: usize) -> io::Result<()> {
        let min = match packet.first().map(|b| b >> 4) {
            Some(4) => 20,
            Some(6) => 40,
            _ => usize::MAX,
        };
        if packet.len() < min || packet.len() > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPC packet rejected",
            ));
        }
        Ok(())
    }
    fn enqueue(&mut self, packet: &[u8]) -> io::Result<()> {
        self.check()?;
        Self::validate_packet(packet, self.limits.max_packet_bytes)?;
        let bytes = packet.len() + HEADER;
        if self.output.len() >= self.limits.max_queued_packets
            || self
                .queued_bytes
                .checked_add(bytes)
                .is_none_or(|n| n > self.limits.max_queued_bytes)
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut frame = Vec::with_capacity(bytes);
        frame.extend_from_slice(&[b'A', b'P', VERSION, self.role.outbound()]);
        frame.extend_from_slice(&(packet.len() as u32).to_be_bytes());
        frame.extend_from_slice(packet);
        self.output.push_back(Pending {
            bytes: frame,
            written: 0,
        });
        self.queued_bytes += bytes;
        Ok(())
    }
    fn read_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.check()?;
        for _ in 0..self.limits.max_io_ops {
            self.check()?;
            let header = self.prefix_read < HEADER;
            let result = if header {
                self.socket.read(&mut self.prefix[self.prefix_read..])
            } else {
                self.socket.read(&mut self.payload[self.payload_read..])
            };
            match result {
                Ok(0) => return Err(self.seal(io::ErrorKind::UnexpectedEof)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(self.seal(e.kind())),
                Ok(n) if header => {
                    self.prefix_read += n;
                    if self.prefix_read == HEADER {
                        let len = u32::from_be_bytes(self.prefix[4..].try_into().unwrap()) as usize;
                        if self.prefix[..2] != *b"AP"
                            || self.prefix[2] != VERSION
                            || self.prefix[3] != self.role.inbound()
                            || !(20..=self.limits.max_packet_bytes).contains(&len)
                        {
                            return Err(self.seal(io::ErrorKind::InvalidData));
                        }
                        self.payload = vec![0; len];
                    }
                }
                Ok(n) => {
                    self.payload_read += n;
                    if self.payload_read == self.payload.len() {
                        if Self::validate_packet(&self.payload, self.limits.max_packet_bytes)
                            .is_err()
                        {
                            return Err(self.seal(io::ErrorKind::InvalidData));
                        }
                        self.prefix_read = 0;
                        self.payload_read = 0;
                        return Ok(Some(std::mem::take(&mut self.payload)));
                    }
                }
            }
        }
        Ok(None)
    }
}
impl PacketIo for PacketPort {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.flush_pending()?;
        self.read_packet()
    }
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        let mut remaining = self.limits.max_io_ops;
        self.flush_budget(&mut remaining)?;
        self.enqueue(packet)?;
        self.flush_budget(&mut remaining)
    }
}
impl Drop for PacketPort {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

#[cfg(test)]
#[path = "worker_ipc_tests.rs"]
mod tests;
