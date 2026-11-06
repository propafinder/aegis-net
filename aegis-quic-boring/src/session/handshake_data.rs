//! What quinn surfaces to the application once the handshake data is ready.

/// Negotiated ALPN protocol and the SNI we sent, mirroring the shape quinn's
/// rustls session exposes.
#[derive(Clone, Debug)]
pub struct HandshakeData {
    pub protocol: Option<Vec<u8>>,
    pub server_name: Option<String>,
}
