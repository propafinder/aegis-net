use super::*;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};

fn key(byte: u8) -> AdmissionKey {
    AdmissionKey::from_bytes([byte; 32]).unwrap()
}
fn broker() -> Arc<OwnedBroker> {
    Arc::new(OwnedBroker::new(key(1), key(2), BrokerLimits::default()).unwrap())
}
async fn pair() -> (WebRtcStream, WebRtcStream) {
    let broker = broker();
    let (client, server) = tokio::join!(
        connect(
            CarrierConfig::loopback(),
            broker.clone(),
            key(1),
            Cancellation::new()
        ),
        accept(
            CarrierConfig::loopback(),
            broker,
            key(2),
            Cancellation::new()
        )
    );
    (
        client.expect("loopback client"),
        server.expect("loopback intermediary"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_udp_ordered_stream_preserves_tail_after_shutdown_and_immediate_drop() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut client, mut server) = pair().await;
        assert!(client.path_evidence().nominated_pair_checked);
        assert_eq!(client.path_evidence().local_type, "host");
        assert!(!client.path_evidence().relay_only);
        assert!(!client.path_evidence().media_session_verified);
        let payload: Vec<u8> = (0..600_000).map(|n| (n % 251) as u8).collect();
        let expected = payload.clone();
        let sender = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
            drop(client);
        });
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, expected);
        sender.await.unwrap();
        server.close().await;
    })
    .await
    .expect("bounded real UDP test");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_udp_bidirectional_echo_with_half_close() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut client, mut server) = pair().await;
        let server_task = tokio::spawn(async move {
            let mut data = Vec::new();
            server.read_to_end(&mut data).await.unwrap();
            server.write_all(&data).await.unwrap();
            server.shutdown().await.unwrap();
            data
        });
        let data = b"owned-real-UDP-DTLS-SCTP".repeat(15_000);
        client.write_all(&data).await.unwrap();
        client.shutdown().await.unwrap();
        let mut echo = Vec::new();
        client.read_to_end(&mut echo).await.unwrap();
        assert_eq!(data, echo);
        assert_eq!(server_task.await.unwrap(), data);
        client.close().await;
    })
    .await
    .expect("bounded echo");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_udp_peer_drop_without_fin_is_never_clean_eof() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut client, mut server) = pair().await;
        client.write_all(b"partial").await.unwrap();
        let mut partial = [0; 7];
        server.read_exact(&mut partial).await.unwrap();
        assert_eq!(&partial, b"partial");
        // Abort the actual remote DataChannel without its application FIN.
        client.close().await;
        let mut tail = Vec::new();
        let error = server
            .read_to_end(&mut tail)
            .await
            .expect_err("truncation must not become EOF");
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionAborted
        ));
        server.close().await;
    })
    .await
    .expect("bounded real truncation");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_direct_policy_disjoint_peer_ips() {
    let own_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let peer_ip: std::net::IpAddr = "127.0.0.2".parse().unwrap();
    // Linux provides the loopback /8 range. A missing socket is a failure,
    // never a successful test with an unmeasured network assertion. Darwin
    // does not provision this address; its policy coverage is the pure test below.
    drop(
        tokio::net::UdpSocket::bind((peer_ip, 0))
            .await
            .expect("Linux distinct loopback bind"),
    );
    tokio::time::timeout(Duration::from_secs(15), async {
        let broker = broker();
        let mut client_config = CarrierConfig::loopback();
        client_config.bind = (own_ip, 0).into();
        client_config.ice = IcePolicy::DirectIntermediary {
            allowed_peer_ips: vec![peer_ip],
        };
        let mut server_config = CarrierConfig::loopback();
        server_config.bind = (peer_ip, 0).into();
        server_config.ice = IcePolicy::DirectIntermediary {
            allowed_peer_ips: vec![own_ip],
        };
        let (client, server) = tokio::join!(
            connect(client_config, broker.clone(), key(1), Cancellation::new()),
            accept(server_config, broker, key(2), Cancellation::new())
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        assert_eq!(client.peer_ip(), peer_ip);
        assert_eq!(server.peer_ip(), own_ip);
        client.write_all(b"disjoint-policy").await.unwrap();
        let mut received = [0; 15];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"disjoint-policy");
        client.close().await;
        server.close().await;
    })
    .await
    .expect("bounded distinct peer test");
}

#[test]
fn local_direct_candidate_validation_is_independent_of_remote_allowlist() {
    let bind = "127.0.0.1:0".parse().unwrap();
    let policy = IcePolicy::DirectIntermediary {
        allowed_peer_ips: vec!["127.0.0.2".parse().unwrap()],
    };
    let local = "a=candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host\r\n";
    let remote = "a=candidate:1 1 udp 2130706431 127.0.0.2 5001 typ host\r\n";
    assert!(policy.check_local_sdp(local, bind).is_ok());
    assert!(policy.check_sdp(remote).is_ok());
    assert!(policy.check_sdp(local).is_err());
    assert!(policy.check_local_sdp(remote, bind).is_err());
    assert!(policy.validate("0.0.0.0:0".parse().unwrap()).is_err());
}

#[test]
fn direct_nominated_pair_must_use_configured_local_bind() {
    use webrtc::peer_connection::{RTCIceCandidate, RTCIceCandidateType};

    let bind = "127.0.0.1:0".parse().unwrap();
    let policy = IcePolicy::DirectIntermediary {
        allowed_peer_ips: vec!["127.0.0.2".parse().unwrap()],
    };
    let local = RTCIceCandidate {
        address: "127.0.0.1".into(),
        typ: RTCIceCandidateType::Host,
        ..Default::default()
    };
    let remote = RTCIceCandidate {
        address: "127.0.0.2".into(),
        typ: RTCIceCandidateType::Host,
        ..Default::default()
    };
    assert!(policy.selected(&local, &remote, bind).is_ok());
    let wrong_local = RTCIceCandidate {
        address: "127.0.0.3".into(),
        ..local
    };
    assert!(matches!(
        policy.selected(&wrong_local, &remote, bind),
        Err(Error::Path)
    ));
}

#[tokio::test]
async fn role_gate_capacity_claim_replay_and_expiry_are_enforced() {
    let broker = OwnedBroker::new(
        key(1),
        key(2),
        BrokerLimits {
            max_sessions: 1,
            session_ttl: Duration::from_millis(80),
        },
    )
    .unwrap();
    let deadline = || Instant::now() + Duration::from_secs(1);
    for (role, k, op) in [
        (Role::Client, key(3), Operation::Probe),
        (Role::Intermediary, key(1), Operation::Take),
        (Role::Client, key(1), Operation::Take),
    ] {
        assert!(matches!(
            broker
                .exchange(SignalingRequest::new(role, k, op), deadline())
                .await,
            Err(Error::Admission)
        ));
    }
    let SignalingReply::Submitted(session) = broker
        .exchange(
            SignalingRequest::new(
                Role::Client,
                key(1),
                Operation::Submit(Signal::offer("v=0\r\n".into()).unwrap()),
            ),
            deadline(),
        )
        .await
        .unwrap()
    else {
        panic!("submit")
    };
    assert!(matches!(
        broker
            .exchange(
                SignalingRequest::new(
                    Role::Client,
                    key(1),
                    Operation::Submit(Signal::offer("v=0\r\n".into()).unwrap())
                ),
                deadline()
            )
            .await,
        Err(Error::Capacity)
    ));
    let SignalingReply::Offer { claim, .. } = broker
        .exchange(
            SignalingRequest::new(Role::Intermediary, key(2), Operation::Take),
            deadline(),
        )
        .await
        .unwrap()
    else {
        panic!("take")
    };
    broker
        .exchange(
            SignalingRequest::new(
                Role::Intermediary,
                key(2),
                Operation::Answer {
                    session,
                    claim,
                    signal: Signal::answer("v=0\r\n".into()).unwrap(),
                },
            ),
            deadline(),
        )
        .await
        .unwrap();
    assert!(matches!(
        broker
            .exchange(
                SignalingRequest::new(
                    Role::Intermediary,
                    key(2),
                    Operation::Answer {
                        session,
                        claim,
                        signal: Signal::answer("v=0\r\n".into()).unwrap()
                    }
                ),
                deadline()
            )
            .await,
        Err(Error::Session)
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(matches!(
        broker
            .exchange(
                SignalingRequest::new(Role::Client, key(1), Operation::Poll(session)),
                deadline()
            )
            .await,
        Err(Error::Session)
    ));
    assert!(matches!(
        broker
            .exchange(
                SignalingRequest::new(Role::Intermediary, key(2), Operation::Take),
                Instant::now() + Duration::from_millis(30)
            )
            .await,
        Err(Error::Deadline)
    ));
}

#[tokio::test]
async fn cancelled_or_unauthorized_setup_never_establishes_a_carrier() {
    let cancel = Cancellation::new();
    cancel.cancel();
    assert!(matches!(
        connect(CarrierConfig::loopback(), broker(), key(1), cancel).await,
        Err(Error::Cancelled)
    ));
    assert!(matches!(
        connect(
            CarrierConfig::loopback(),
            broker(),
            key(9),
            Cancellation::new()
        )
        .await,
        Err(Error::Admission)
    ));
    let mut config = CarrierConfig::loopback();
    config.ice = IcePolicy::SfuMedia;
    assert!(matches!(
        connect(config, broker(), key(1), Cancellation::new()).await,
        Err(Error::UnsupportedSfu)
    ));
}

#[test]
fn relay_policy_rejects_host_candidates_and_requires_explicit_turn() {
    let turn = TurnServer::udp(
        "127.0.0.1:3478".parse().unwrap(),
        "fixture-user".into(),
        "fixture-password".into(),
    )
    .unwrap();
    let policy = IcePolicy::RelayOnly {
        servers: vec![turn],
        allowed_relay_ips: vec!["127.0.0.1".parse().unwrap()],
    };
    assert!(matches!(
        policy.check_sdp("a=candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host\r\n"),
        Err(Error::Path)
    ));
    assert!(policy
        .check_sdp("a=candidate:1 1 udp 2130706431 127.0.0.1 5000 typ relay\r\n")
        .is_ok());
    assert!(matches!(
        policy.check_sdp("a=candidate:1 1 udp 2130706431 192.0.2.8 5000 typ relay\r\n"),
        Err(Error::Path)
    ));
    assert!(matches!(
        policy.check_sdp("a=candidate:1 1 udp 2130706431 private.local 5000 typ relay\r\n"),
        Err(Error::Path)
    ));
    let (transport, servers) = policy.rtc();
    assert_eq!(
        transport,
        webrtc::peer_connection::RTCIceTransportPolicy::Relay
    );
    assert_eq!(servers.len(), 1);
    assert!(matches!(
        IcePolicy::RelayOnly {
            servers: vec![],
            allowed_relay_ips: vec!["127.0.0.1".parse().unwrap()]
        }
        .validate("127.0.0.1:0".parse().unwrap()),
        Err(Error::Configuration)
    ));
}
