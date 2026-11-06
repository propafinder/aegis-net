use super::*;
use crate::secure_channel::{policy_ack, write_open, OpenRequest, Transport};
use std::time::Duration;

fn profile() -> PrivacySettings {
    PrivacySettings {
        payload_bytes: 32,
        cadence_ms: 1,
        buffer_bytes: 64,
        max_wire_bytes: 16_384,
        io_timeout_ms: 5,
        session_timeout_ms: 500,
        max_queue_delay_ms: 20,
        poisson_pacing: None,
        net_shaper: None,
        adaptive_channel: None,
        arrival_envelope: None,
        cover_stream: None,
        bit_traps: None,
        liu_channel: None,
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_millis(100)
}

fn request() -> OpenRequest {
    OpenRequest {
        version: 1,
        transport: Transport::Tcp,
        host: "target.test".into(),
        port: 443,
    }
}

#[tokio::test]
async fn absent_profile_preserves_literal_open_wire_at_both_peers() {
    let mut expected = Vec::new();
    write_open(&mut expected, &request()).await.unwrap();
    for is_client in [true, false] {
        let (stream, mut peer) = tokio::io::duplex(2048);
        let mut stream = if is_client {
            client(stream, None, deadline()).await.unwrap()
        } else {
            server(stream, None, deadline()).await.unwrap()
        };
        write_open(&mut stream, &request()).await.unwrap();
        let mut actual = vec![0; expected.len()];
        peer.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        drop(stream);
        assert_eq!(
            peer.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}

#[tokio::test(start_paused = true)]
async fn matched_profiles_preserve_data_and_bidirectional_half_close() {
    let settings = profile();
    let (a, b) = tokio::io::duplex(4096);
    let end = deadline();
    let (a, b) = tokio::join!(
        client(a, Some(&settings), end),
        server(b, Some(&settings), end)
    );
    let mut a = a.unwrap();
    let mut b = b.unwrap();
    let ((), ()) = tokio::join!(
        async {
            a.write_all(b"request-before-half-close").await.unwrap();
            a.shutdown().await.unwrap();
            let mut reply = Vec::new();
            a.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"reply-after-half-close");
        },
        async {
            let mut request = Vec::new();
            b.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request-before-half-close");
            b.write_all(b"reply-after-half-close").await.unwrap();
            b.shutdown().await.unwrap();
        }
    );
}

#[tokio::test]
async fn mismatched_profiles_are_rejected_before_framed_stream_exists() {
    let expected = profile();
    let mut offered = expected.clone();
    offered.max_wire_bytes += 34;
    let (a, b) = tokio::io::duplex(4096);
    let end = deadline();
    let (a, b) = tokio::join!(
        client(a, Some(&offered), end),
        server(b, Some(&expected), end)
    );
    assert!(a.is_err());
    assert_eq!(b.err().unwrap().kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn opt_in_client_is_rejected_by_legacy_open_schema_without_downgrade() {
    let settings = profile();
    let (a, mut b) = tokio::io::duplex(4096);
    let (a, ()) = tokio::join!(client(a, Some(&settings), deadline()), async {
        assert!(policy_ack::read_request(&mut b).await.is_err());
        drop(b);
    });
    assert!(a.is_err());
}

#[tokio::test]
async fn opt_in_server_rejects_legacy_open_and_policy_ack() {
    let settings = profile();
    for ack in [false, true] {
        let (mut a, b) = tokio::io::duplex(4096);
        let ((), b) = tokio::join!(
            async {
                if ack {
                    policy_ack::write_request(&mut a, &policy_ack::PolicyAckRequest::new())
                        .await
                        .unwrap();
                } else {
                    write_open(&mut a, &request()).await.unwrap();
                }
            },
            server(b, Some(&settings), deadline())
        );
        assert_eq!(b.err().unwrap().kind(), io::ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn invalid_local_profile_closes_without_emitting_control_bytes() {
    let mut settings = profile();
    settings.max_wire_bytes = 1;
    for is_client in [true, false] {
        let (stream, mut peer) = tokio::io::duplex(2048);
        let error = if is_client {
            client(stream, Some(&settings), deadline())
                .await
                .err()
                .unwrap()
        } else {
            server(stream, Some(&settings), deadline())
                .await
                .err()
                .unwrap()
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn agreement_deadline_cancels_owned_io_without_peer_reply() {
    let settings = profile();
    for is_client in [true, false] {
        let (stream, mut peer) = tokio::io::duplex(2048);
        let start = Instant::now();
        let end = start + Duration::from_millis(5);
        let error = if is_client {
            client(stream, Some(&settings), end).await.err().unwrap()
        } else {
            server(stream, Some(&settings), end).await.err().unwrap()
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(start.elapsed(), Duration::from_millis(5));
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes.is_empty(), !is_client);
    }
}

#[tokio::test(start_paused = true)]
async fn delayed_agreement_does_not_restart_constant_or_poisson_session_clock() {
    for poisson in [false, true] {
        for delayed_client in [false, true] {
            let mut settings = if poisson {
                poisson_profile()
            } else {
                profile()
            };
            settings.session_timeout_ms = 500;
            settings.max_wire_bytes = 1_048_576;
            let (a, b) = tokio::io::duplex(4096);
            let origin = Instant::now();
            let end = origin + Duration::from_secs(1);
            let (a, b) = tokio::join!(
                async {
                    if delayed_client {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                    client(a, Some(&settings), end).await
                },
                async {
                    if !delayed_client {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                    server(b, Some(&settings), end).await
                }
            );
            let (mut a, mut b) = (a.unwrap(), b.unwrap());
            // Observe the peer whose agreement clock started before the delay.
            // Both transports remain owned and exchange valid idle frames.
            let error = if delayed_client {
                b.read_u8().await.unwrap_err()
            } else {
                a.read_u8().await.unwrap_err()
            };
            assert_eq!(origin.elapsed(), Duration::from_millis(500));
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
    }
}

#[tokio::test]
async fn strict_control_bounds_and_schema_reject_before_framing() {
    let settings = profile();
    let valid = serde_json::to_value(Agreement {
        version: 1,
        operation: Operation::RelayShaping,
        profile: settings.clone(),
    })
    .unwrap();
    let mut unknown = valid.clone();
    unknown["extra"] = serde_json::json!(true);
    let mut unsupported = valid;
    unsupported["version"] = serde_json::json!(2);
    for value in [unknown, unsupported] {
        let (mut a, b) = tokio::io::duplex(2048);
        let bytes = serde_json::to_vec(&value).unwrap();
        a.write_u16(bytes.len() as u16).await.unwrap();
        a.write_all(&bytes).await.unwrap();
        assert_eq!(
            server(b, Some(&settings), deadline())
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
    let (mut a, b) = tokio::io::duplex(2048);
    a.write_u16((MAX_CONTROL_BYTES + 1) as u16).await.unwrap();
    assert_eq!(
        server(b, Some(&settings), deadline())
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

fn poisson_profile() -> PrivacySettings {
    let mut p = profile();
    p.cadence_ms = 1_000;
    p.io_timeout_ms = 1_000;
    p.max_queue_delay_ms = 20_000;
    p.session_timeout_ms = 5_000;
    p.poisson_pacing = Some(crate::traffic_privacy::poisson::PoissonPacing {
        mean_interval_us: 1_000,
        max_gap_us: 1_000_000,
    });
    p
}
#[tokio::test]
async fn poisson_paired_agreement_delivers_and_preserves_half_close() {
    let p = poisson_profile();
    let (a, b) = tokio::io::duplex(4096);
    let end = Instant::now() + Duration::from_secs(2);
    let (a, b) = tokio::join!(client(a, Some(&p), end), server(b, Some(&p), end));
    let mut a = a.unwrap();
    let mut b = b.unwrap();
    let ((), ()) = tokio::join!(
        async {
            a.write_all(b"packet").await.unwrap();
            a.shutdown().await.unwrap();
            let mut result = Vec::new();
            a.read_to_end(&mut result).await.unwrap();
            assert_eq!(result, b"reply");
        },
        async {
            let mut result = Vec::new();
            b.read_to_end(&mut result).await.unwrap();
            assert_eq!(result, b"packet");
            b.write_all(b"reply").await.unwrap();
            b.shutdown().await.unwrap();
        }
    );
}
#[tokio::test]
async fn poisson_peer_profile_mismatch_refuses_before_target_open() {
    let p = poisson_profile();
    let mut q = p.clone();
    q.poisson_pacing.as_mut().unwrap().mean_interval_us = 2_000;
    let (a, b) = tokio::io::duplex(4096);
    let end = Instant::now() + Duration::from_secs(2);
    let (a, b) = tokio::join!(client(a, Some(&q), end), server(b, Some(&p), end));
    assert!(a.is_err());
    assert_eq!(b.err().unwrap().kind(), io::ErrorKind::InvalidData);
}
#[test]
fn legacy_profile_serialization_omits_new_pacing_field() {
    let json = serde_json::to_string(&profile()).unwrap();
    assert!(!json.contains("poisson"));
    assert!(!json.contains("net_shaper"));
    assert!(serde_json::from_str::<PrivacySettings>(&json)
        .unwrap()
        .poisson_pacing
        .is_none());
    let mut p = poisson_profile();
    p.cadence_ms = 999;
    assert!(p.validate().is_err());
}

fn net_profile() -> PrivacySettings {
    let mut p = profile();
    p.payload_bytes = 64;
    p.buffer_bytes = 64;
    p.cadence_ms = 10;
    p.io_timeout_ms = 10;
    p.session_timeout_ms = 1000;
    p.max_queue_delay_ms = 200;
    p.net_shaper = Some(crate::traffic_privacy::netshaper::NetShaperConfig {
        slots: 16,
        cadence_ms: 10,
        window_ms: 200,
        io_timeout_ms: 10,
        queue_cap: 64,
        release_cap: 64,
        sigma_bytes: 32,
        rho_limit_n: "32".into(),
        rho_limit_d: "1".into(),
    });
    p
}

#[tokio::test]
async fn final_synchronous_poll_cannot_promote_a_late_establishment() {
    let deadline = Instant::now() + Duration::from_millis(2);
    let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    struct Owned(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let result = within_establishment(deadline, async {
        // Exactly one poll, with no await at which Tokio can interrupt it.
        std::thread::sleep(Duration::from_millis(10));
        Ok(Owned(drops.clone()))
    })
    .await;
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::TimedOut);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn netshaper_exact_agreement_precedes_fresh_material_and_refuses_mismatch() {
    let p = net_profile();
    p.validate().unwrap();
    let mut q = p.clone();
    q.net_shaper.as_mut().unwrap().sigma_bytes = 33;
    let (a, b) = tokio::io::duplex(4096);
    let end = Instant::now() + Duration::from_secs(1);
    let (a, b) = tokio::join!(client(a, Some(&q), end), server(b, Some(&p), end));
    assert!(a.is_err());
    assert_eq!(b.err().unwrap().kind(), io::ErrorKind::InvalidData);
    // Opaque paths cannot accidentally bypass fresh directional custody.
    let (a, _) = tokio::io::duplex(4096);
    assert!(shape_authenticated(a, Some(&p)).is_err());
    let mut mixed = p;
    mixed.poisson_pacing = Some(crate::traffic_privacy::poisson::PoissonPacing {
        mean_interval_us: 1000,
        max_gap_us: 10_000,
    });
    assert!(mixed.validate().is_err());
}

#[tokio::test(start_paused = true)]
async fn netshaper_agreed_live_peers_receive_directional_data_and_enforce_epoch_custody() {
    // This is an in-memory codec/custody contract, not an OS timer-resolution
    // measurement. Real TCP and deliberate synchronous overruns are separate.
    let p = net_profile();
    let (a, b) = tokio::io::duplex(8192);
    let end = Instant::now() + Duration::from_secs(1);
    let (a, b) = tokio::join!(client(a, Some(&p), end), server(b, Some(&p), end));
    let (mut a, mut b) = (a.unwrap(), b.unwrap());
    let both = async {
        a.write_all(b"client").await.unwrap();
        b.write_all(b"server").await.unwrap();
        let (mut from_a, mut from_b) = ([0u8; 6], [0u8; 6]);
        tokio::try_join!(a.read_exact(&mut from_b), b.read_exact(&mut from_a)).unwrap();
        assert_eq!(&from_a, b"client");
        assert_eq!(&from_b, b"server");
        // Open app sources may not become a clean EOF at the public epoch end.
        let (ea, eb) = tokio::join!(a.read_u8(), b.read_u8());
        assert!(ea.is_err() && eb.is_err());
    };
    tokio::time::timeout(Duration::from_secs(2), both)
        .await
        .unwrap();
}

fn adaptive_profile() -> PrivacySettings {
    use crate::traffic_privacy::adaptive_channel::{Action, AdaptiveSettings};
    let mut p = profile();
    p.max_wire_bytes = 100_000;
    p.io_timeout_ms = 300;
    p.session_timeout_ms = 2000;
    p.max_queue_delay_ms = 30_000;
    p.adaptive_channel = Some(AdaptiveSettings {
        objective: None,
        joint_counts: vec![vec![10, 0], vec![0, 10]],
        length_bin_upper: vec![16, 32],
        actions: vec![
            Action {
                padded_bytes: 16,
                delay_ms: 1,
            },
            Action {
                padded_bytes: 32,
                delay_ms: 1,
            },
        ],
        delay_cost_per_ms: 0,
        cost_budget: 32,
        optimizer_iterations: 1000,
        optimizer_gap_millibits: 1,
        optimizer_timeout_ms: 1000,
        buffer_bytes: 64,
        max_wire_bytes: 100_000,
        io_timeout_ms: 300,
        session_timeout_ms: 2000,
        max_queue_delay_ms: 30_000,
    });
    p
}

#[tokio::test]
async fn causal_adaptive_profile_agreement_preserves_live_request_and_reply() {
    let p = adaptive_profile();
    p.validate().unwrap();
    let (a, b) = tokio::io::duplex(4096);
    let end = Instant::now() + Duration::from_secs(2);
    let (a, b) = tokio::join!(client(a, Some(&p), end), server(b, Some(&p), end));
    let (mut a, mut b) = (a.unwrap(), b.unwrap());
    let ((), ()) = tokio::join!(
        async {
            a.write_all(b"request").await.unwrap();
            a.shutdown().await.unwrap();
            let mut response = Vec::new();
            a.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"response");
        },
        async {
            let mut request = Vec::new();
            b.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request");
            b.write_all(b"response").await.unwrap();
            b.shutdown().await.unwrap();
        }
    );
}

// The real TCP relay copies both directions at once. A request/reply protocol
// can leave both application write halves open while each peer awaits its next
// message; neither shaping sender may hold up the other shaping receiver.
async fn relay_request_reply_with_open_application_sources(p: &PrivacySettings) {
    let (client_wire, server_wire) = tokio::io::duplex(16_384);
    let deadline = Instant::now() + Duration::from_secs(2);
    let (client, server) = tokio::join!(
        client(client_wire, Some(p), deadline),
        server(server_wire, Some(p), deadline)
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    let (mut client_app, mut client_bridge) = tokio::io::duplex(1024);
    let (mut target_app, mut target_bridge) = tokio::io::duplex(1024);
    tokio::time::timeout(Duration::from_millis(1500), async {
        let client_copy = crate::secure_channel::copy_with_idle_timeout(
            &mut client_bridge,
            &mut client,
            Duration::from_millis(1200),
        );
        let server_copy = crate::secure_channel::copy_with_idle_timeout(
            &mut server,
            &mut target_bridge,
            Duration::from_millis(1200),
        );
        let exchange = async {
            client_app.write_all(b"ping").await?;
            let mut request = [0; 4];
            target_app.read_exact(&mut request).await?;
            assert_eq!(&request, b"ping");
            // Both sources are still open while the response crosses the relay.
            target_app.write_all(b"pong").await?;
            let mut response = [0; 4];
            client_app.read_exact(&mut response).await?;
            assert_eq!(&response, b"pong");
            client_app.shutdown().await?;
            target_app.shutdown().await?;
            io::Result::Ok(())
        };
        tokio::try_join!(client_copy, server_copy, exchange)
    })
    .await
    .expect("request/reply must complete before either session cutoff")
    .unwrap();
}

#[tokio::test]
async fn adaptive_relay_consumer_delivers_reply_while_request_source_stays_open() {
    let p = adaptive_profile();
    p.validate().unwrap();
    relay_request_reply_with_open_application_sources(&p).await;
}

#[tokio::test]
async fn adaptive_training_mismatch_or_expired_original_clock_never_opens_target() {
    let p = adaptive_profile();
    let mut q = p.clone();
    q.adaptive_channel.as_mut().unwrap().cost_budget += 1;
    let (a, b) = tokio::io::duplex(4096);
    let end = Instant::now() + Duration::from_secs(2);
    let (a, b) = tokio::join!(client(a, Some(&q), end), server(b, Some(&p), end));
    assert!(a.is_err() && b.is_err());
    let (a, mut observer) = tokio::io::duplex(4096);
    assert!(
        client(a, Some(&p), Instant::now() - Duration::from_millis(1))
            .await
            .is_err()
    );
    assert_eq!(
        observer.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    let mut mixed = p;
    mixed.net_shaper = net_profile().net_shaper;
    assert!(mixed.validate().is_err());
}

// This in-memory agreement/FIFO contract uses virtual time; native 10 ms
// scheduling viability remains a separate, unaccepted Windows gate.
#[tokio::test(start_paused = true)]
async fn independent_bittraps_service_uses_agreed_fresh_keys_and_live_fifo() {
    let mut p = net_profile();
    p.net_shaper = None;
    p.bit_traps = Some(crate::traffic_privacy::bittraps::BitTrapsSettings {
        slots: 16,
        cadence_ms: 10,
        io_timeout_ms: 10,
        queue_cap: 64,
        service: vec![(16, 1), (32, 2), (64, 1)],
    });
    p.validate().unwrap();
    let (a, b) = tokio::io::duplex(8192);
    let end = Instant::now() + Duration::from_secs(1);
    let (a, b) = tokio::join!(client(a, Some(&p), end), server(b, Some(&p), end));
    let (mut a, mut b) = (a.unwrap(), b.unwrap());
    a.write_all(b"client").await.unwrap();
    b.write_all(b"server").await.unwrap();
    let (mut request, mut response) = ([0u8; 6], [0u8; 6]);
    tokio::try_join!(a.read_exact(&mut response), b.read_exact(&mut request)).unwrap();
    assert_eq!(&request, b"client");
    assert_eq!(&response, b"server");
    let (a, b) = tokio::join!(a.read_u8(), b.read_u8());
    assert!(a.is_err() && b.is_err());
}

#[tokio::test]
async fn general_mec_stream_agrees_profile_and_preserves_full_request_reply() {
    let mut p = profile();
    p.io_timeout_ms = 1000;
    p.session_timeout_ms = 2000;
    p.max_queue_delay_ms = 10_000;
    p.cover_stream = Some(crate::traffic_privacy::cover_stream::CoverStreamSettings {
        tokens: vec![vec![65], vec![66], vec![67]],
        weights: vec![4, 2, 1],
        conditional_model: None,
        capacity: 9,
        horizon: 512,
        max_records: 16,
        buffer_bytes: 64,
        max_wire_bytes: 8192,
        io_timeout_ms: 1000,
        session_timeout_ms: 2000,
    });
    p.validate().unwrap();
    let (a, b) = tokio::io::duplex(4096);
    let end = Instant::now() + Duration::from_secs(2);
    let (a, b) = tokio::join!(client(a, Some(&p), end), server(b, Some(&p), end));
    let (mut a, mut b) = (a.unwrap(), b.unwrap());
    let ((), ()) = tokio::join!(
        async {
            a.write_all(b"request").await.unwrap();
            a.shutdown().await.unwrap();
            let mut response = Vec::new();
            a.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"response");
        },
        async {
            let mut request = Vec::new();
            b.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request");
            b.write_all(b"response").await.unwrap();
            b.shutdown().await.unwrap();
        }
    );
}

#[tokio::test]
async fn cover_relay_consumer_delivers_reply_while_request_source_stays_open() {
    let mut p = profile();
    p.io_timeout_ms = 1000;
    p.session_timeout_ms = 2000;
    p.max_queue_delay_ms = 10_000;
    p.cover_stream = Some(crate::traffic_privacy::cover_stream::CoverStreamSettings {
        tokens: vec![vec![65], vec![66], vec![67]],
        weights: vec![4, 2, 1],
        conditional_model: None,
        capacity: 9,
        horizon: 512,
        max_records: 16,
        buffer_bytes: 64,
        max_wire_bytes: 8192,
        io_timeout_ms: 1000,
        session_timeout_ms: 2000,
    });
    p.validate().unwrap();
    relay_request_reply_with_open_application_sources(&p).await;
}

// Keep paused Tokio time under explicit control while real blocking optimizer
// work completes. This does not replace the production optimizer or transport.
struct ManualAgreementClock(tokio::task::JoinHandle<()>);
impl ManualAgreementClock {
    fn new() -> Self {
        Self(tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        }))
    }
}
impl Drop for ManualAgreementClock {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct DelayedAgreementRead {
    inner: tokio::io::DuplexStream,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
    gate: std::pin::Pin<Box<tokio::time::Sleep>>,
}
impl tokio::io::AsyncRead for DelayedAgreementRead {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if let Some(ready) = self.ready.take() {
            let _ = ready.send(());
        }
        if std::future::Future::poll(self.gate.as_mut(), cx).is_pending() {
            return std::task::Poll::Pending;
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, out)
    }
}
impl tokio::io::AsyncWrite for DelayedAgreementRead {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
fn delay_reads(
    inner: tokio::io::DuplexStream,
    end: Instant,
) -> (DelayedAgreementRead, tokio::sync::oneshot::Receiver<()>) {
    let (ready, receive) = tokio::sync::oneshot::channel();
    (
        DelayedAgreementRead {
            inner,
            ready: Some(ready),
            gate: Box::pin(tokio::time::sleep_until(end)),
        },
        receive,
    )
}
fn short_inner_clock_profiles() -> Vec<PrivacySettings> {
    use crate::traffic_privacy::{
        adaptive_channel::AdaptiveObjective, cover_stream::CoverStreamSettings,
        general_coupling::ConditionalCoverSettings,
    };
    let mut mean = adaptive_profile();
    mean.session_timeout_ms = 3000;
    mean.io_timeout_ms = 1000;
    mean.max_queue_delay_ms = 100_000;
    let a = mean.adaptive_channel.as_mut().unwrap();
    a.session_timeout_ms = 500;
    a.io_timeout_ms = 1000;
    a.max_queue_delay_ms = 100_000;
    let mut maximum = mean.clone();
    maximum.adaptive_channel.as_mut().unwrap().objective =
        Some(AdaptiveObjective::MaximumInformation {
            leakage_cap_millibits: 500,
            cost_gap: 1,
        });
    let mut minimax = mean.clone();
    minimax.adaptive_channel.as_mut().unwrap().objective =
        Some(AdaptiveObjective::MinimaxInformation {
            leakage_gap_millibits: 100,
            cost_gap: 1,
            cap_programs: 8,
        });
    let mut cover = profile();
    cover.session_timeout_ms = 3000;
    cover.io_timeout_ms = 1000;
    cover.max_queue_delay_ms = 100_000;
    cover.cover_stream = Some(CoverStreamSettings {
        tokens: vec![vec![65], vec![66], vec![67]],
        weights: vec![2, 1, 1],
        conditional_model: None,
        capacity: 9,
        horizon: 512,
        max_records: 16,
        buffer_bytes: 64,
        max_wire_bytes: 8192,
        io_timeout_ms: 1000,
        session_timeout_ms: 500,
    });
    let mut conditional = cover.clone();
    conditional.cover_stream.as_mut().unwrap().conditional_model = Some(ConditionalCoverSettings {
        initial_state: 0,
        state_weights: vec![vec![2, 1, 1], vec![1, 2, 1]],
        next_states: vec![vec![0, 1, 0], vec![0, 1, 0]],
    });
    vec![mean, maximum, minimax, cover, conditional]
}

#[tokio::test(start_paused = true)]
async fn generic_original_session_cutoff_bounds_blocked_agreement() {
    let _manual = ManualAgreementClock::new();
    let mut cases = short_inner_clock_profiles();
    let mut outer = profile();
    outer.session_timeout_ms = 500;
    cases.push(outer);
    for (index, p) in cases.into_iter().enumerate() {
        p.validate().unwrap();
        for is_client in [true, false] {
            let (wire, mut peer) = tokio::io::duplex(65536);
            let origin = Instant::now();
            let (wire, reached_read) = delay_reads(wire, origin + Duration::from_secs(10));
            let expected = p.clone();
            let owned = p.clone();
            let task = tokio::spawn(async move {
                if is_client {
                    client(wire, Some(&owned), origin + Duration::from_secs(3)).await
                } else {
                    server(wire, Some(&owned), origin + Duration::from_secs(3)).await
                }
            });
            reached_read.await.unwrap(); // real preparation finished, actual agreement awaits read
            tokio::time::advance(Duration::from_millis(501)).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(
                task.is_finished(),
                "profile {index}, client={is_client}: expired session still owns agreement"
            );
            assert_eq!(
                task.await.unwrap().err().unwrap().kind(),
                io::ErrorKind::TimedOut
            );
            if is_client {
                read(&mut peer, Operation::RelayShaping, &expected)
                    .await
                    .unwrap();
            }
            // No fresh key exchange or installed worker may follow the hello.
            assert_eq!(
                peer.read_u8().await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn generic_original_session_cutoff_short_nested_owner_is_not_renewed() {
    let _manual = ManualAgreementClock::new();
    for (index, p) in short_inner_clock_profiles().into_iter().enumerate() {
        p.validate().unwrap();
        let origin = Instant::now();
        let (a, b) = tokio::io::duplex(65536);
        let (a, reached_a) = delay_reads(a, origin + Duration::from_millis(300));
        let (b, reached_b) = delay_reads(b, origin + Duration::from_millis(300));
        let other = p.clone();
        let ca =
            tokio::spawn(async move { client(a, Some(&p), origin + Duration::from_secs(3)).await });
        let cb =
            tokio::spawn(
                async move { server(b, Some(&other), origin + Duration::from_secs(3)).await },
            );
        reached_a.await.unwrap();
        reached_b.await.unwrap();
        tokio::time::advance(Duration::from_millis(300)).await;
        let (a, b) = tokio::join!(ca, cb);
        let (mut a, mut b) = (a.unwrap().unwrap(), b.unwrap().unwrap());
        assert_eq!(Instant::now() - origin, Duration::from_millis(300));
        tokio::time::advance(Duration::from_millis(201)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        for (role, carrier) in [("client", &mut a), ("server", &mut b)] {
            let mut byte = [0];
            let mut output = tokio::io::ReadBuf::new(&mut byte);
            let poll = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(
                    std::pin::Pin::new(&mut **carrier).poll_read(cx, &mut output),
                )
            })
            .await;
            assert!(
                matches!(poll, std::task::Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::TimedOut),
                "profile {index} {role}: nested lifetime restarted after agreement: {poll:?}"
            );
            assert!(output.filled().is_empty());
        }
    }
}
