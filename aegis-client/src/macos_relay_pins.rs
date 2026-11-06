//! Read-only physical H2 relay endpoint admission shared by the existing Mac
//! worker and a future NetworkExtension owner. Pins are not an ACK, credential,
//! permission grant or proof that a transport has been opened.
use aegis_core::{tunnel_policy::WindowsTunnelSettings, RelaySettings, TunnelTransportFamily};
use std::net::SocketAddr;

/// The VM guard may bypass only endpoints actually used by the admitted
/// device-authenticated gRPC stream/datagram transport. MASQUE metadata is
/// deliberately excluded from the physical exception set.
pub fn admitted_relay_pins(
    tunnel: &WindowsTunnelSettings,
    relay: &RelaySettings,
) -> Result<Vec<SocketAddr>, String> {
    if relay.inner_tls.is_none() {
        return Err("macOS packet tunnel requires device inner TLS over gRPC/H2".into());
    }
    relay.validate_inner_tls_transport()?;
    if relay.udp_transport_priority.as_deref()
        != Some([TunnelTransportFamily::GrpcDatagram].as_slice())
    {
        return Err("macOS full packet tunnel requires only grpc_datagram for UDP".into());
    }
    // The common Windows intent supports QUIC and therefore includes MASQUE
    // addresses. They are unused under stricter Mac admission. Preserve
    // common numeric-address, bounded-count and dedup validation for H2.
    let mut h2 = relay.clone();
    h2.masque_server = None;
    for endpoint in &mut h2.endpoints {
        endpoint.masque_server = None;
    }
    tunnel.relay_pins(&h2)
}
