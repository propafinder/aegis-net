//! Shared R2-to-R3 route-admission fixtures. The comparison keeps route
//! selection unchanged and only replaces the product read owner with R2's
//! immediate None handoff. Loopback callbacks observe handoff/bytes, not relay
//! TLS, credential verification, target-open policy or native DNS traffic.

use super::*;
use aegis_core::{AsyncStateStore, TunnelTransportFamily};
use std::cell::Cell;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingress = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (captured, _) = listener.accept().await.unwrap();
    (ingress, captured)
}

async fn required_relay_route(direct: &DirectSettings, dns_calls: &Cell<usize>) {
    let relay = RelaySettings {
        auth_token: "controlled-fixture-credential".into(),
        transport_priority: vec![TunnelTransportFamily::GrpcStream],
        ..RelaySettings::default()
    };
    let brain = Brain::new(0.0, vec!["geneva".into()], AsyncStateStore::ephemeral());
    let target = ConnectTarget {
        host: "route-owner.example".into(),
        port: 443,
    };
    let route = select_auto_target_route_with(
        &target,
        "0.0.0.0:443".parse().unwrap(),
        &brain,
        direct,
        &DirectFallbackContext {
            relay: &relay,
            terminal_policy: DirectTerminalPolicy::HybridRelayOrFailClosed,
        },
        false,
        || {
            dns_calls.set(dns_calls.get() + 1);
            std::future::ready(Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unexpected resolver call",
            )))
        },
    )
    .await
    .unwrap();
    assert_eq!(
        route,
        AutoTargetRoute::RelayByName {
            reason_code: "direct_capability_unavailable"
        }
    );
}

fn direct(timeout_ms: u64) -> DirectSettings {
    DirectSettings {
        hybrid_geneva: true,
        first_chunk_timeout_ms: timeout_ms,
        ..DirectSettings::default()
    }
}

#[tokio::test]
async fn silent_required_relay_is_bounded_without_dns_or_handoff_dial() {
    let (mut ingress, captured) = tcp_pair().await;
    let relay_sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_sink.local_addr().unwrap();
    let dns_calls = Cell::new(0);
    let handoffs = Cell::new(0);
    let handoff_count = &handoffs;
    let direct = direct(25);
    required_relay_route(&direct, &dns_calls).await;
    let result = timeout(
        Duration::from_secs(1),
        with_auto_relay_initial_payload(captured, &direct, |_, _| async move {
            handoff_count.set(handoff_count.get() + 1);
            let _stream = TcpStream::connect(relay_addr).await?;
            Ok(())
        }),
    )
    .await
    .expect("fixture watchdog is not the product deadline");
    let error = result.expect_err("silent Auto must refuse before relay handoff");
    assert!(
        error
            .to_string()
            .starts_with("direct_initial_read_timeout:"),
        "wrong stage: {error}"
    );
    assert_eq!((dns_calls.get(), handoffs.get()), (0, 0));
    let mut byte = [0u8; 1];
    assert_eq!(
        timeout(Duration::from_millis(200), ingress.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(
        timeout(Duration::from_millis(50), relay_sink.accept())
            .await
            .is_err(),
        "silent Auto dialled a relay"
    );
}

#[tokio::test]
async fn preobserved_eof_before_payload_skips_relay_and_dns() {
    let (ingress, captured) = tcp_pair().await;
    drop(ingress);
    let mut byte = [0u8; 1];
    assert_eq!(
        timeout(Duration::from_millis(200), captured.peek(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0,
        "fixture must establish actual ingress EOF before product invocation"
    );
    let relay_sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_sink.local_addr().unwrap();
    let dns_calls = Cell::new(0);
    let handoffs = Cell::new(0);
    let handoff_count = &handoffs;
    let direct = direct(500);
    required_relay_route(&direct, &dns_calls).await;
    timeout(
        Duration::from_secs(1),
        with_auto_relay_initial_payload(captured, &direct, |_, _| async move {
            handoff_count.set(handoff_count.get() + 1);
            let _stream = TcpStream::connect(relay_addr).await?;
            Ok(())
        }),
    )
    .await
    .expect("EOF fixture watchdog")
    .expect("EOF is not a timeout");
    assert_eq!((dns_calls.get(), handoffs.get()), (0, 0));
    assert!(
        timeout(Duration::from_millis(50), relay_sink.accept())
            .await
            .is_err(),
        "EOF Auto dialled relay"
    );
}

#[tokio::test]
async fn genuine_initial_payload_is_handed_off_once_and_reply_survives() {
    let (mut ingress, captured) = tcp_pair().await;
    let relay_sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_sink.local_addr().unwrap();
    let dns_calls = Cell::new(0);
    let handoffs = Cell::new(0);
    let handoff_count = &handoffs;
    let direct = direct(500);
    required_relay_route(&direct, &dns_calls).await;
    let (_handled, received, reply) = timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            with_auto_relay_initial_payload(captured, &direct, |mut client, payload| async move {
                handoff_count.set(handoff_count.get() + 1);
                let payload = payload.expect("ordinary Auto requires actual first bytes");
                assert_eq!(payload, b"payload");
                let mut wire = TcpStream::connect(relay_addr).await?;
                wire.write_all(&payload).await?;
                tokio::io::copy_bidirectional(&mut client, &mut wire).await?;
                Ok(())
            }),
            async {
                let (mut peer, _) = relay_sink.accept().await?;
                let mut received = Vec::new();
                peer.read_to_end(&mut received).await?;
                peer.write_all(b"actual-reply").await?;
                peer.shutdown().await?;
                Ok::<_, anyhow::Error>(received)
            },
            async {
                ingress.write_all(b"payload").await?;
                ingress.shutdown().await?;
                let mut reply = Vec::new();
                ingress.read_to_end(&mut reply).await?;
                Ok::<_, anyhow::Error>(reply)
            }
        )
    })
    .await
    .expect("payload fixture watchdog")
    .expect("actual payload route refused");
    assert_eq!(received, b"payload");
    assert_eq!(reply, b"actual-reply");
    assert_eq!((dns_calls.get(), handoffs.get()), (0, 1));
}

#[tokio::test]
async fn cancelling_pending_relay_admission_drops_ingress_without_handoff() {
    let (mut ingress, captured) = tcp_pair().await;
    let relay_sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_sink.local_addr().unwrap();
    let dns_calls = Cell::new(0);
    let handoffs = Cell::new(0);
    let handoff_count = &handoffs;
    let direct = direct(1000);
    required_relay_route(&direct, &dns_calls).await;
    let mut owner = Box::pin(with_auto_relay_initial_payload(
        captured,
        &direct,
        |_, _| async move {
            handoff_count.set(handoff_count.get() + 1);
            let _stream = TcpStream::connect(relay_addr).await?;
            Ok(())
        },
    ));
    tokio::select! {
        result = &mut owner => panic!("actual initial read was not pending: {result:?}"),
        _ = tokio::time::sleep(Duration::from_millis(10)) => {}
    }
    drop(owner);
    assert_eq!((dns_calls.get(), handoffs.get()), (0, 0));
    let mut byte = [0u8; 1];
    assert_eq!(
        timeout(Duration::from_millis(200), ingress.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(
        timeout(Duration::from_millis(50), relay_sink.accept())
            .await
            .is_err(),
        "cancelled Auto dialled relay"
    );
}
