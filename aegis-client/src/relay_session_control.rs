//! Actual UDP session lifetime owner, shared by ingress and relay.
//! Detached has no control socket; this grants no identity or policy authority.
use tokio::net::TcpStream;

#[derive(Debug)]
pub enum UdpSessionControl {
    SocksControl(TcpStream),
    // Native wide UDP/DNS ingress will not have a SOCKS control socket, so keep
    // a detached lifetime shape in the ingress contract already now.
    Detached,
}

impl UdpSessionControl {
    pub fn as_socks_stream_mut(&mut self) -> Option<&mut TcpStream> {
        match self {
            Self::SocksControl(stream) => Some(stream),
            Self::Detached => None,
        }
    }
}
