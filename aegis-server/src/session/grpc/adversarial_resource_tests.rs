//! Raw framing deliberately bypasses the h2 client's SETTINGS admission.
//! This is an in-memory production-handler regression, not an RSS measurement.
use super::*;
use crate::phase_witness::ServerPhaseWitness;
use std::time::Duration;
use tokio::io::DuplexStream;

const STAGE: Duration = Duration::from_secs(3);

struct Task<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn frame(io: &mut DuplexStream, kind: u8, flags: u8, stream: u32, body: &[u8]) {
    assert!(body.len() <= 16_384);
    let length = (body.len() as u32).to_be_bytes();
    let mut header = Vec::from(&length[1..]);
    header.extend([kind, flags]);
    header.extend(stream.to_be_bytes());
    tokio::time::timeout(STAGE, async {
        io.write_all(&header).await.unwrap();
        io.write_all(body).await.unwrap();
        io.flush().await.unwrap();
    })
    .await
    .expect("bounded raw frame write");
}

async fn receive(io: &mut DuplexStream) -> (u8, u8, u32, Vec<u8>) {
    tokio::time::timeout(STAGE, async {
        let mut header = [0; 9];
        io.read_exact(&mut header).await.unwrap();
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        assert!(length <= 16_384, "bounded frame payload");
        let stream = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
        let mut body = vec![0; length];
        io.read_exact(&mut body).await.unwrap();
        (header[3], header[4], stream, body)
    })
    .await
    .expect("bounded raw frame receive")
}

fn headers(path: &str) -> Vec<u8> {
    // HPACK static indexed POST and https, then literals without indexing.
    // No compression state is shared between these requests.
    let mut bytes = vec![0x83, 0x87, 0x04];
    assert!(path.len() < 127);
    bytes.push(path.len() as u8);
    bytes.extend(path.as_bytes());
    bytes.extend([0x01, 9]);
    bytes.extend(b"localhost");
    // Indexed name 31 (content-type), encoded using the four-bit prefix.
    bytes.extend([0x0f, 16, 16]);
    bytes.extend(b"application/grpc");
    bytes
}

async fn barrier(io: &mut DuplexStream, nonce: [u8; 8]) {
    frame(io, 6, 0, 0, &nonce).await;
    loop {
        let (kind, flags, stream, body) = receive(io).await;
        if kind == 6 && flags == 1 && stream == 0 && body == nonce {
            return;
        }
        assert_ne!(kind, 7, "unexpected GOAWAY before barrier");
    }
}

#[tokio::test]
async fn raw_h2_peer_ignoring_settings_cannot_open_a_33rd_preauth_stream() {
    tokio::time::timeout(Duration::from_secs(10), malicious_concurrency_attempt(32))
        .await
        .expect("bounded complete malicious-stream scenario");
}

#[tokio::test]
async fn raw_h2_configured_128_stream_limit_is_advertised_and_enforced() {
    tokio::time::timeout(Duration::from_secs(10), malicious_concurrency_attempt(128))
        .await
        .expect("bounded configured-stream scenario");
}

async fn malicious_concurrency_attempt(maximum: u32) {
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let mut owner = crate::lifecycle::TaskGroupRegistryOwner::new(Default::default());
    let registry = owner.registry();
    let witness = ServerPhaseWitness::default();
    let observed = witness.clone();
    let transport = TransportConfig {
        h2_max_concurrent_streams: maximum,
        ..Default::default()
    };
    let request = headers(&transport.grpc_path);
    let mut server = Task(tokio::spawn(async move {
        let auth = TunnelAuthKeyring {
            keys: Vec::new().into(),
            operational_log: Default::default(),
            inner_tls: None,
            https_bridge: None,
            fronted_origin: None,
            relay_training: None,
        };
        handle_grpc_session_with_owner(
            server_io,
            &auth,
            &transport,
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            "192.0.2.10:443".parse().unwrap(),
            None,
            &registry,
            Some(&observed),
        )
        .await
    }));
    client
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    frame(&mut client, 4, 0, 0, &[]).await;
    // Complete SETTINGS before injecting requests, avoiding the initial
    // handshake's temporarily unacknowledged concurrency limit.
    loop {
        let (kind, flags, _, _) = receive(&mut client).await;
        if kind == 4 && flags == 0 {
            frame(&mut client, 4, 1, 0, &[]).await;
            break;
        }
    }
    barrier(&mut client, *b"settings").await;
    for stream in (1..maximum * 2).step_by(2) {
        frame(&mut client, 1, 4, stream, &request).await;
    }
    barrier(&mut client, *b"held0032").await;
    assert_eq!(
        witness.transport_snapshot().h2_accept.requests,
        u64::from(maximum)
    );
    // Raw framing bypasses the advertised SETTINGS admission.
    frame(&mut client, 1, 4, maximum * 2 + 1, &request).await;
    loop {
        let (kind, _, stream, body) = receive(&mut client).await;
        assert_ne!(
            kind, 7,
            "connection closed instead of refusing excess stream"
        );
        if kind == 3 && stream == maximum * 2 + 1 {
            assert_eq!(body, u32::from(h2::Reason::REFUSED_STREAM).to_be_bytes());
            break;
        }
    }
    barrier(&mut client, *b"refused!").await;
    assert_eq!(
        witness.transport_snapshot().h2_accept.requests,
        u64::from(maximum)
    );
    // A reset releases an actual server slot, not just the client's slot.
    frame(
        &mut client,
        3,
        0,
        1,
        &u32::from(h2::Reason::CANCEL).to_be_bytes(),
    )
    .await;
    barrier(&mut client, *b"released").await;
    frame(&mut client, 1, 4, maximum * 2 + 3, &request).await;
    barrier(&mut client, *b"reused!!").await;
    assert_eq!(
        witness.transport_snapshot().h2_accept.requests,
        u64::from(maximum) + 1
    );
    drop(client);
    tokio::time::timeout(STAGE, &mut server.0)
        .await
        .expect("bounded connection cleanup")
        .expect("server task joined")
        .expect("production handler exited cleanly");
    owner.shutdown().await;
}

#[tokio::test]
async fn raw_h2_batched_reset_flood_is_closed_at_pending_accept_budget() {
    tokio::time::timeout(
        Duration::from_secs(10),
        malicious_control_flood_attempt(true),
    )
    .await
    .expect("bounded reset-flood scenario");
}

#[tokio::test]
async fn raw_h2_unfinished_continuation_flood_is_closed() {
    tokio::time::timeout(
        Duration::from_secs(10),
        malicious_control_flood_attempt(false),
    )
    .await
    .expect("bounded continuation-flood scenario");
}

async fn malicious_control_flood_attempt(reset_flood: bool) {
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let mut owner = crate::lifecycle::TaskGroupRegistryOwner::new(Default::default());
    let registry = owner.registry();
    let transport = TransportConfig::default();
    let request = headers(&transport.grpc_path);
    let mut server = Task(tokio::spawn(async move {
        let auth = TunnelAuthKeyring {
            keys: Vec::new().into(),
            operational_log: Default::default(),
            inner_tls: None,
            https_bridge: None,
            fronted_origin: None,
            relay_training: None,
        };
        handle_grpc_session_with_owner(
            server_io,
            &auth,
            &transport,
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            "192.0.2.10:443".parse().unwrap(),
            None,
            &registry,
            None,
        )
        .await
    }));
    client
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    frame(&mut client, 4, 0, 0, &[]).await;
    loop {
        let (kind, flags, _, _) = receive(&mut client).await;
        if kind == 4 && flags == 0 {
            frame(&mut client, 4, 1, 0, &[]).await;
            break;
        }
    }
    barrier(&mut client, *b"settings").await;
    // Buffer the malicious frames in one burst so the parser, rather than
    // application scheduling or the ordinary client library, owns the boundary.
    let mut burst = Vec::new();
    let mut push_frame = |kind: u8, flags: u8, stream: u32, body: &[u8]| {
        let length = (body.len() as u32).to_be_bytes();
        burst.extend_from_slice(&length[1..]);
        burst.extend([kind, flags]);
        burst.extend(stream.to_be_bytes());
        burst.extend(body);
    };
    if reset_flood {
        // RST removes streams from the concurrency count, but not the pending
        // accept queue. The ninth reset must hit its separate budget of eight.
        for stream in (1u32..18).step_by(2) {
            push_frame(1, 4, stream, &request);
            push_frame(3, 0, stream, &[0, 0, 0, 8]);
        }
    } else {
        // No END_HEADERS: six empty CONTINUATIONs exceed h2's derived limit
        // of five for the production 8192-byte header-list / 16384 frame cap.
        push_frame(1, 0, 1, &request);
        for _ in 0..6 {
            push_frame(9, 0, 1, &[]);
        }
    }
    tokio::time::timeout(STAGE, client.write_all(&burst))
        .await
        .unwrap()
        .unwrap();
    loop {
        let (kind, _, stream, body) = receive(&mut client).await;
        if kind == 7 {
            assert_eq!(stream, 0);
            assert!(body.len() >= 8);
            assert_eq!(
                &body[4..8],
                &u32::from(h2::Reason::ENHANCE_YOUR_CALM).to_be_bytes()
            );
            break;
        }
    }
    drop(client);
    let error = tokio::time::timeout(STAGE, &mut server.0)
        .await
        .expect("bounded reset-flood cleanup")
        .expect("server joined")
        .expect_err("production handler must reject control-frame flood");
    assert!(error.chain().any(|cause| cause
        .downcast_ref::<h2::Error>()
        .is_some_and(|error| error.reason() == Some(h2::Reason::ENHANCE_YOUR_CALM))));
    owner.shutdown().await;
}

async fn raw_default_connection() -> (
    DuplexStream,
    Task<anyhow::Result<()>>,
    crate::lifecycle::TaskGroupRegistryOwner,
    u32,
) {
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let owner = crate::lifecycle::TaskGroupRegistryOwner::new(Default::default());
    let registry = owner.registry();
    let server = Task(tokio::spawn(async move {
        let auth = TunnelAuthKeyring {
            keys: Vec::new().into(),
            operational_log: Default::default(),
            inner_tls: None,
            https_bridge: None,
            fronted_origin: None,
            relay_training: None,
        };
        handle_grpc_session_with_owner(
            server_io,
            &auth,
            &TransportConfig::default(),
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            "192.0.2.10:443".parse().unwrap(),
            None,
            &registry,
            None,
        )
        .await
    }));
    client
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    frame(&mut client, 4, 0, 0, &[]).await;
    let mut settings = false;
    let mut connection_credit = 0;
    while !settings || connection_credit == 0 {
        let (kind, flags, stream, body) = receive(&mut client).await;
        assert_ne!(kind, 7);
        if kind == 4 && flags == 0 {
            frame(&mut client, 4, 1, 0, &[]).await;
            settings = true;
        }
        if kind == 8 && stream == 0 {
            connection_credit += u32::from_be_bytes(body.try_into().unwrap());
        }
    }
    barrier(&mut client, *b"settings").await;
    (client, server, owner, connection_credit)
}

#[tokio::test]
async fn raw_h2_local_resets_keep_connection_and_retained_history_beyond_eight() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (mut client, mut server, mut owner, _) = raw_default_connection().await;
        for stream in (1..32).step_by(2) {
            // Complete HPACK, but missing :path causes a local protocol-error reset.
            frame(&mut client, 1, 4, stream, &[0x83, 0x87]).await;
            loop {
                let (kind, _, reset_stream, _) = receive(&mut client).await;
                assert_ne!(
                    kind, 7,
                    "local-error reset budget exhausted before h2 default"
                );
                if kind == 3 && reset_stream == stream {
                    break;
                }
            }
        }
        // Retained reset state must absorb late DATA on the first reset stream.
        frame(&mut client, 0, 0, 1, b"late").await;
        barrier(&mut client, *b"retained").await;
        drop(client);
        tokio::time::timeout(STAGE, &mut server.0)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        owner.shutdown().await;
    })
    .await
    .expect("bounded local-reset regression");
}

#[tokio::test]
async fn raw_h2_connection_receive_window_grants_four_mib() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, mut server, mut owner, credit) = raw_default_connection().await;
        // HTTP/2 starts at65535; the connection WINDOW_UPDATE grants the rest.
        assert_eq!(credit + 65_535, 4 * 1024 * 1024);
        drop(client);
        tokio::time::timeout(STAGE, &mut server.0)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        owner.shutdown().await;
    })
    .await
    .expect("bounded receive-window regression");
}
