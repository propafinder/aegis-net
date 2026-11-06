//! Shared actual-TCP first-read regression. The predecessor receives only this
//! test module and its module declaration, retaining the old production read.

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

fn fixture_brain() -> Arc<Brain> {
    Arc::new(Brain::new(
        0.0,
        vec!["passthrough".into()],
        aegis_core::AsyncStateStore::ephemeral(),
    ))
}

async fn fixture_tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingress = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (captured, _) = listener.accept().await.unwrap();
    (ingress, captured)
}

async fn idle_read_is_bounded(policy: DirectTerminalPolicy) {
    let (mut ingress, captured) = fixture_tcp_pair().await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let direct = DirectSettings {
        first_chunk_timeout_ms: 25,
        ..DirectSettings::default()
    };
    let brain = fixture_brain();
    let relay = RelaySettings::default();
    // The outer watchdog only bounds the fixture. The product's unchanged
    // configured budget is 25 ms; the watchdog is not credited as its timeout.
    let result = timeout(
        Duration::from_secs(1),
        handle_direct(
            captured,
            ConnectTarget {
                host: "localhost".into(),
                port: dst.port(),
            },
            dst,
            brain,
            &direct,
            DirectFallbackContext {
                relay: &relay,
                terminal_policy: policy,
            },
            None,
        ),
    )
    .await;
    assert!(
        result.is_ok(),
        "original first read remained pending until the fixture watchdog"
    );
    let error = result.unwrap().expect_err("silent first-read must refuse");
    assert!(
        error
            .to_string()
            .starts_with("direct_initial_read_timeout:"),
        "unexpected phase: {error}"
    );
    let mut byte = [0u8; 1];
    assert_eq!(
        timeout(Duration::from_millis(200), ingress.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(
        timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err(),
        "initial-read refusal dialled the target"
    );
}

#[tokio::test]
async fn client_first_initial_read_is_bounded_in_direct() {
    idle_read_is_bounded(DirectTerminalPolicy::PreserveDirectFailure).await;
}

#[tokio::test]
async fn client_first_initial_read_is_bounded_in_auto() {
    idle_read_is_bounded(DirectTerminalPolicy::RelayOrFailClosed).await;
}

#[tokio::test]
async fn initial_read_preserves_real_payload_and_response() {
    let (mut ingress, captured) = fixture_tcp_pair().await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let direct = DirectSettings {
        strategies: vec!["passthrough".into()],
        first_chunk_timeout_ms: 500,
        ..DirectSettings::default()
    };
    let brain = fixture_brain();
    let relay = RelaySettings::default();
    // All three futures and sockets are owned by this scope, without spawned
    // children. Dropping the watchdog future drops them on either source.
    let (handled, target_result, ingress_result) = timeout(Duration::from_secs(2), async {
        tokio::join!(
            handle_direct(
                captured,
                ConnectTarget {
                    host: "localhost".into(),
                    port: dst.port()
                },
                dst,
                brain,
                &direct,
                DirectFallbackContext {
                    relay: &relay,
                    terminal_policy: DirectTerminalPolicy::PreserveDirectFailure
                },
                None,
            ),
            async {
                let (mut remote, _) = target.accept().await?;
                let mut payload = [0u8; 7];
                remote.read_exact(&mut payload).await?;
                remote.write_all(b"greeting").await?;
                remote.shutdown().await?;
                let mut remainder = Vec::new();
                remote.read_to_end(&mut remainder).await?;
                Ok::<_, std::io::Error>((payload, remainder))
            },
            async {
                ingress.write_all(b"payload").await?;
                ingress.shutdown().await?;
                let mut response = Vec::new();
                ingress.read_to_end(&mut response).await?;
                Ok::<_, std::io::Error>(response)
            },
        )
    })
    .await
    .expect("actual TCP fixture exceeded outer watchdog");
    assert!(handled.is_ok(), "real payload route failed: {handled:?}");
    let (payload, remainder) = target_result.unwrap();
    assert_eq!(payload, *b"payload");
    assert!(remainder.is_empty(), "unexpected extra upstream bytes");
    assert_eq!(ingress_result.unwrap(), b"greeting");
}

#[tokio::test]
async fn cancelled_initial_read_closes_owned_ingress_without_dial() {
    let (mut ingress, captured) = fixture_tcp_pair().await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dst = target.local_addr().unwrap();
    let direct = DirectSettings {
        first_chunk_timeout_ms: 500,
        ..DirectSettings::default()
    };
    let brain = fixture_brain();
    let relay = RelaySettings::default();
    let mut handler = Box::pin(handle_direct(
        captured,
        ConnectTarget {
            host: "localhost".into(),
            port: dst.port(),
        },
        dst,
        brain,
        &direct,
        DirectFallbackContext {
            relay: &relay,
            terminal_policy: DirectTerminalPolicy::PreserveDirectFailure,
        },
        None,
    ));
    tokio::select! {
        result = &mut handler => panic!("idle read ended before cancellation: {result:?}"),
        _ = tokio::time::sleep(Duration::from_millis(10)) => {},
    }
    drop(handler);
    let mut byte = [0u8; 1];
    assert_eq!(
        timeout(Duration::from_millis(200), ingress.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(
        timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err(),
        "cancelled first read dialled target"
    );
}
