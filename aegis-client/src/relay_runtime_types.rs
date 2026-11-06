//! One actual relay target/packet type owner shared by the engine and binary.
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
}

impl ConnectTarget {
    pub async fn resolve(&self) -> std::io::Result<SocketAddr> {
        tokio::net::lookup_host((self.host.as_str(), self.port))
            .await?
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "resolve"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    pub target: ConnectTarget,
    pub payload: Vec<u8>,
}
