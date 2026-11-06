//! Shared broker regression. The predecessor differs only by a neutral
//! extraction of its unchanged production broker constructor plus this module.
//! NUL forces the original resolver to fail locally; no external DNS is needed.

use super::*;
use crate::ingress::{
    IngressKind, IngressResponse, IngressSessionIntent, IngressTransport, TcpConnectIntent,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

async fn normalize(
    mode: Mode,
    host: &str,
) -> Result<BrokeredSession, crate::ingress::broker::BrokerError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _peer = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (captured, peer) = listener.accept().await.unwrap();
    let intent = IngressSessionIntent {
        kind: IngressKind::WidePrimary,
        peer,
        transport: IngressTransport::TcpConnect(TcpConnectIntent {
            client: captured,
            target: crate::socks5::ConnectTarget {
                host: host.to_owned(),
                port: 443,
            },
            response: IngressResponse::None,
            target_lease: None,
        }),
    };
    timeout(
        Duration::from_secs(1),
        session_broker_for_mode(&mode).normalize(intent),
    )
    .await
    .expect("broker fixture watchdog")
}

#[tokio::test]
async fn auto_broker_defers_target_lookup_to_route_owner() {
    let session = normalize(Mode::Auto, "invalid\0name.invalid")
        .await
        .expect("Auto must preserve the name for route-specific resolution");
    let BrokeredSession::TcpConnect(session) = session else {
        panic!("TCP session expected")
    };
    assert_eq!(session.target.host, "invalid\0name.invalid");
    assert!(session.dst.ip().is_unspecified());
    assert_eq!(session.dst.port(), 443);
}

#[tokio::test]
async fn relay_broker_still_defers_and_direct_still_refuses_failed_lookup() {
    let session = normalize(Mode::Relay, "invalid\0name.invalid")
        .await
        .unwrap();
    let BrokeredSession::TcpConnect(session) = session else {
        panic!("TCP session expected")
    };
    assert!(session.dst.ip().is_unspecified());
    let error = normalize(Mode::Direct, "invalid\0name.invalid")
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), "resolve_failed");
}

#[tokio::test]
async fn auto_broker_preserves_ip_literal_without_dns() {
    let session = normalize(Mode::Auto, "127.0.0.1").await.unwrap();
    let BrokeredSession::TcpConnect(session) = session else {
        panic!("TCP session expected")
    };
    assert_eq!(
        session.dst,
        "127.0.0.1:443".parse::<std::net::SocketAddr>().unwrap()
    );
}
