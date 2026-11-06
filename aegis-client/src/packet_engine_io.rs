//! The exact existing shared engine packet contract and statistics.
//! Implementations must obey their separately admitted OS/identity lifetime.
use std::io;

pub trait PacketIo {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>>;
    fn send(&mut self, packet: &[u8]) -> io::Result<()>;
}
#[cfg(windows)]
impl PacketIo for aegis_core::windows_tunnel::wintun::Wintun {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.receive()
    }
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.send(packet)
    }
}
#[derive(Default, Debug, serde::Serialize)]
pub struct TunnelStats {
    pub tcp_flows_opened: u64,
    pub udp_sessions_opened: u64,
    pub tcp_egress_bytes: u64,
    pub udp_egress_bytes: u64,
    pub packets_received: u64,
    pub packets_sent: u64,
    pub packets_dropped: u64,
}
