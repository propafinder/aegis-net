use super::*;
use tokio::time::timeout;

fn settings() -> LiuSettings {
    LiuSettings {
        class_weights: vec![1, 3],
        client_to_server_counts: vec![vec![3, 1], vec![1, 3]],
        server_to_client_counts: vec![vec![3, 1], vec![1, 3]],
        target_classes: vec![ClassMapping {
            host: "target.test".into(),
            port: 443,
            transport: TrafficTransport::Tcp,
            class: 0,
        }],
        unmatched_traffic_class: Some(1),
        policy_ack_class: 1,
        distortion_microunits: 125_000,
        optimizer_iterations: 2000,
        optimizer_gap_millibits: 1,
        optimizer_timeout_ms: 3000,
        buffer_bytes: 1024,
        wire_batch_bytes: 1024,
        max_wire_bytes: 100_000,
        io_timeout_ms: 300,
        session_timeout_ms: 3000,
        max_queue_delay_ms: 400_000,
    }
}
fn context() -> BoundContext {
    settings()
        .traffic_context("target.test", 443, crate::secure_channel::Transport::Tcp)
        .unwrap()
}
async fn prepared() -> PreparedChannel {
    prepare(settings(), Instant::now() + Duration::from_secs(3))
        .await
        .unwrap()
}
#[tokio::test]
async fn exact_unchanged_nonconstant_kernel_has_exact_zero_forbidden_mass() {
    let p = prepared().await;
    for dir in 0..2 {
        let k = p.probabilities(dir).unwrap();
        assert_eq!(&k[2..4], &[0.0, 1.0]);
        assert_eq!(&k[4..8], &[1.0, 0.0, 0.0, 1.0]);
        assert!((k[0] - 1.0 / 3.0).abs() < 1e-14);
        assert!((k[1] - 2.0 / 3.0).abs() < 1e-14);
        let c = p.certificates()[dir];
        assert!(c.leakage_bits <= 1e-12);
        assert!(c.expected_cost <= 0.125 + 1e-12);
    }
}
#[tokio::test]
async fn opposite_majority_exact_solver_shrink_support_refuses_without_trimming() {
    let mut s = settings();
    s.class_weights = vec![3, 1];
    assert!(prepare(s, Instant::now() + Duration::from_secs(3))
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("physically impossible"));
}
#[test]
fn model_mapping_schema_and_numerical_support_are_strict() {
    let s = settings();
    s.validate().unwrap();
    assert!(canonical_host(&"x".repeat(254)).is_err());
    assert!(canonical_host("").is_err());
    assert_eq!(canonical_host("TARGET.test").unwrap(), "target.test");
    let mut changed = s.clone();
    changed.client_to_server_counts[0][0] = 0;
    assert!(changed.validate().is_err());
    let mut changed = s.clone();
    changed
        .target_classes
        .push(changed.target_classes[0].clone());
    assert!(changed.validate().is_err());
    let mut changed = s.clone();
    changed.target_classes[0].host = "TARGET.test".into();
    assert!(changed.validate().is_err());
    let mut changed = s.clone();
    changed.unmatched_traffic_class = None;
    assert!(changed
        .traffic_context("unknown.test", 443, crate::secure_channel::Transport::Tcp)
        .is_err());
    let mut v = serde_json::to_value(&s).unwrap();
    v["unmatched_traffic_class"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<LiuSettings>(v).is_err());
    let mut v = serde_json::to_value(s).unwrap();
    v["private_key"] = true.into();
    assert!(serde_json::from_value::<LiuSettings>(v).is_err());
}
#[test]
fn actual_target_transport_and_policy_purpose_cannot_be_substituted() {
    let c = context();
    let mut o = crate::secure_channel::OpenRequest {
        version: 1,
        host: "target.test".into(),
        port: 443,
        transport: crate::secure_channel::Transport::Tcp,
    };
    c.check_open(&o).unwrap();
    o.port = 444;
    assert!(c.check_open(&o).is_err());
    o.port = 443;
    o.transport = crate::secure_channel::Transport::Udp;
    assert!(c.check_open(&o).is_err());
    assert!(c.check_policy_ack().is_err());
    assert!(settings().policy_context().unwrap().check_open(&o).is_err());
    let mut c = context();
    if let BoundContext::Traffic { class, .. } = &mut c {
        *class = 1;
    }
    assert!(settings().validate_context(&c).is_err());
}
#[tokio::test]
async fn actual_nonconstant_duplex_fifo_bidirectional_half_close() {
    let p = prepared().await;
    let q = prepared().await;
    let (a, b) = tokio::io::duplex(512);
    let due = Instant::now() + Duration::from_secs(3);
    let mut a = attach_authenticated(a, p, context(), Zeroizing::new([7; 32]), true, due).unwrap();
    let mut b = attach_authenticated(b, q, context(), Zeroizing::new([7; 32]), false, due).unwrap();
    timeout(Duration::from_secs(2), async {
        tokio::join!(
            async {
                a.write_all(b"causal-payload").await.unwrap();
                a.shutdown().await.unwrap();
                let mut x = Vec::new();
                a.read_to_end(&mut x).await.unwrap();
                assert_eq!(x, b"response-after-halfclose");
            },
            async {
                let mut x = Vec::new();
                b.read_to_end(&mut x).await.unwrap();
                assert_eq!(x, b"causal-payload");
                b.write_all(b"response-after-halfclose").await.unwrap();
                b.shutdown().await.unwrap();
            }
        );
    })
    .await
    .unwrap();
    let (a, b) = tokio::join!(a.finish(), b.finish());
    assert!(a.unwrap().sent.frames > 1);
    assert!(b.unwrap().received.frames > 1);
}
#[tokio::test]
async fn complete_frame_consistency_precedes_any_plaintext_and_drop_closes_owner() {
    let p = prepared().await;
    let (a, mut wire) = tokio::io::duplex(512);
    let due = Instant::now() + Duration::from_secs(2);
    let mut app =
        attach_authenticated(a, p, context(), Zeroizing::new([8; 32]), true, due).unwrap();
    let mut h = [0; HEADER];
    h[..4].copy_from_slice(MAGIC);
    h[14..16].copy_from_slice(&1u16.to_be_bytes());
    wire.write_all(&h).await.unwrap();
    let e = timeout(Duration::from_secs(1), app.read_u8())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    drop(app);
    assert!(wire.read_u8().await.is_err());
}
#[tokio::test]
async fn actual_backpressure_original_lifetime_sticky_refusal_and_redacted_debug() {
    let mut s = settings();
    s.session_timeout_ms = 60;
    s.io_timeout_ms = 20;
    let p = prepare(s, Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let (a, _held) = tokio::io::duplex(1);
    let mut app = attach_authenticated(
        a,
        p,
        context(),
        Zeroizing::new([9; 32]),
        true,
        Instant::now() + Duration::from_millis(60),
    )
    .unwrap();
    app.write_all(b"private-marker").await.unwrap();
    assert!(!format!("{app:?}").contains("private-marker"));
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert_eq!(
        app.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        app.write(b"x").await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}
#[tokio::test]
async fn entered_blocking_preparation_cancellation_retains_owner_until_actual_exit() {
    struct Lifetime(Arc<AtomicBool>);
    impl Drop for Lifetime {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let done = Arc::new(AtomicBool::new(false));
    let observed = done.clone();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    let task = tokio::spawn(prepare_with_owner(
        settings(),
        Instant::now() + Duration::from_secs(3),
        move || {
            let owner = Lifetime(observed);
            entered.send(()).unwrap();
            let _ = gate.recv_timeout(Duration::from_secs(1));
            owner
        },
    ));
    timeout(Duration::from_secs(1), ready)
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(matches!(task.await,Err(e) if e.is_cancelled()));
    assert!(!done.load(Ordering::Acquire));
    release.send(()).unwrap();
    timeout(Duration::from_secs(1), async {
        while !done.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn digest_mutation_after_valid_header_never_releases_partial_application_bytes() {
    let p = prepared().await;
    let profile = p.settings.descriptor().unwrap();
    let mut info = b"AEGIS-Liu-fresh-context-direction-v1/".to_vec();
    info.extend(serde_json::to_vec(&context()).unwrap());
    info.extend(p.kernel_descriptor());
    info.push(1);
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&profile), &[10; 32]);
    let mut descriptor = [0; 32];
    hk.expand(&info, &mut descriptor).unwrap();
    let [_, channel] = prepared().await.channels;
    let direction = PreparedDirection {
        settings: settings(),
        descriptor,
        channel,
        class: 0,
    };
    let h = header(&direction, 0, 1, 1, false);
    let body = [65, 66];
    let mut d = digest(&h, &body);
    d[0] ^= 1;
    let (a, mut wire) = tokio::io::duplex(512);
    let mut app = attach_authenticated(
        a,
        p,
        context(),
        Zeroizing::new([10; 32]),
        true,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    wire.write_all(&h).await.unwrap();
    wire.write_all(&body).await.unwrap();
    wire.write_all(&d).await.unwrap();
    assert_eq!(
        app.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}
#[tokio::test]
async fn raw_transport_error_text_is_not_retained_in_sticky_public_failure() {
    struct Broken;
    impl AsyncRead for Broken {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "PRIVATE-INPUT-ERROR-123",
            )))
        }
    }
    impl AsyncWrite for Broken {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            x: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(x.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let mut app = attach_authenticated(
        Broken,
        prepared().await,
        context(),
        Zeroizing::new([11; 32]),
        true,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    let e = app.read_u8().await.unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::ConnectionReset);
    assert!(!e.to_string().contains("PRIVATE"));
    let e = app.write(b"x").await.unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::ConnectionReset);
    assert!(!e.to_string().contains("PRIVATE"));
}

#[tokio::test]
async fn pending_short_request_flushes_without_eof_or_future_input() {
    let (a, b) = tokio::io::duplex(4096);
    let due = Instant::now() + Duration::from_secs(2);
    let mut a = attach_authenticated(
        a,
        prepared().await,
        context(),
        Zeroizing::new([12; 32]),
        true,
        due,
    )
    .unwrap();
    let mut b = attach_authenticated(
        b,
        prepared().await,
        context(),
        Zeroizing::new([12; 32]),
        false,
        due,
    )
    .unwrap();
    timeout(Duration::from_millis(500), async {
        a.write_all(b"x").await.unwrap();
        assert_eq!(b.read_u8().await.unwrap(), b'x');
        b.write_all(b"y").await.unwrap();
        assert_eq!(a.read_u8().await.unwrap(), b'y');
    })
    .await
    .unwrap();
    drop(a);
    drop(b);
}
#[tokio::test]
async fn sustained_ready_input_flushes_at_public_cap_and_partial_writer_preserves_records() {
    #[derive(Clone)]
    struct Capture(Arc<Mutex<(Vec<u8>, Vec<usize>)>>, usize);
    impl AsyncWrite for Capture {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            let n = b.len().min(self.1);
            let mut x = self.0.lock().unwrap();
            x.0.extend_from_slice(&b[..n]);
            x.1.push(n);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    for limit in [usize::MAX, 13] {
        let p = prepared().await;
        let [c, _] = p.channels;
        let d = PreparedDirection {
            settings: settings(),
            descriptor: [13; 32],
            channel: c,
            class: 0,
        };
        let input = vec![65u8; 200];
        let capture = Arc::new(Mutex::new((Vec::new(), Vec::new())));
        let stats = send_frames(
            &input[..],
            Capture(capture.clone(), limit),
            &d,
            Instant::now() + Duration::from_secs(2),
            Arc::new(Completion::default()),
        )
        .await
        .unwrap();
        let x = capture.lock().unwrap();
        assert_eq!(stats.data_bytes, 200);
        assert_eq!(stats.frames, 101);
        assert_eq!(x.0.len() as u64, stats.wire_bytes);
        assert!(x.1.iter().all(|n| *n <= 1024));
        if limit == usize::MAX {
            assert!(x.1.len() < 20);
            assert!(x.1.iter().any(|n| *n > OVERHEAD + 2));
        }
        let mut cursor = 0;
        let mut recovered = Vec::new();
        while cursor < x.0.len() {
            let h = &x.0[cursor..cursor + HEADER];
            let length = u16::from_be_bytes([h[14], h[15]]) as usize;
            let body = if h[4] == 1 { 0 } else { usize::from(h[5]) + 1 };
            recovered.extend_from_slice(&x.0[cursor + HEADER..cursor + HEADER + length]);
            cursor += OVERHEAD + body;
        }
        assert_eq!(recovered, input);
    }
}
#[tokio::test]
async fn synchronous_late_batch_write_cannot_be_promoted_success() {
    struct Late;
    impl AsyncWrite for Late {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            std::thread::sleep(Duration::from_millis(35));
            Poll::Ready(Ok(b.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let mut s = settings();
    s.io_timeout_ms = 10;
    let p = prepare(s, Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let [c, _] = p.channels;
    let d = PreparedDirection {
        settings: p.settings,
        descriptor: [14; 32],
        channel: c,
        class: 0,
    };
    let r = send_frames(
        &b"x"[..],
        Late,
        &d,
        Instant::now() + Duration::from_secs(2),
        Arc::new(Completion::default()),
    )
    .await;
    assert!(matches!(r,Err(e)if e.kind()==io::ErrorKind::TimedOut));
}
#[tokio::test]
async fn cancellation_inside_actual_optimizer_callback_exits_owned_blocking_worker() {
    struct Lifetime(Arc<AtomicBool>);
    impl Drop for Lifetime {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let done = Arc::new(AtomicBool::new(false));
    let observed = done.clone();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let mut entered = Some(entered);
    let (release, gate) = std::sync::mpsc::channel();
    let task = tokio::spawn(prepare_with_probes(
        settings(),
        Instant::now() + Duration::from_secs(3),
        move || Lifetime(observed),
        move |flag| {
            if let Some(entered) = entered.take() {
                entered.send(()).unwrap();
                let _ = gate.recv_timeout(Duration::from_secs(1));
            }
            flag.load(Ordering::Acquire)
        },
    ));
    timeout(Duration::from_secs(1), ready)
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(matches!(task.await,Err(e)if e.is_cancelled()));
    assert!(!done.load(Ordering::Acquire));
    release.send(()).unwrap();
    timeout(Duration::from_secs(1), async {
        while !done.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn fixed_public_kernel_ieee_digest_interoperability_fixture() {
    let p = prepared().await;
    assert_eq!(
        hex::encode(p.kernel_descriptor()),
        "de49e4feaa61b5d67d31cb9c269bb5456bd5a280b6c55c44e6ded00b8dc95351"
    );
    assert_eq!(
        p.channels[0]
            .probabilities()
            .iter()
            .map(|v| v.to_bits())
            .collect::<Vec<_>>(),
        vec![
            4599676419421066582,
            4604180019048437077,
            0,
            4607182418800017408,
            4607182418800017408,
            0,
            0,
            4607182418800017408
        ]
    );
    assert_eq!(p.channels[0].probabilities(), p.channels[1].probabilities());
}

#[tokio::test]
async fn repeated_complete_valid_record_is_rejected_before_second_plaintext() {
    let p = prepared().await;
    let profile = p.settings.descriptor().unwrap();
    let mut info = b"AEGIS-Liu-fresh-context-direction-v1/".to_vec();
    info.extend(serde_json::to_vec(&context()).unwrap());
    info.extend(p.kernel_descriptor());
    info.push(1);
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&profile), &[19; 32]);
    let mut descriptor = [0; 32];
    hk.expand(&info, &mut descriptor).unwrap();
    let [_, channel] = prepared().await.channels;
    let direction = PreparedDirection {
        settings: settings(),
        descriptor,
        channel,
        class: 0,
    };
    let h = header(&direction, 0, 1, 1, false);
    let body = [65, 66];
    let mut frame = h.to_vec();
    frame.extend(body);
    frame.extend(digest(&h, &body));
    let (a, mut wire) = tokio::io::duplex(512);
    let mut app = attach_authenticated(
        a,
        p,
        context(),
        Zeroizing::new([19; 32]),
        true,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    wire.write_all(&frame).await.unwrap();
    assert_eq!(app.read_u8().await.unwrap(), 65);
    wire.write_all(&frame).await.unwrap();
    assert_eq!(
        app.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}
#[tokio::test]
async fn terminal_record_budget_exhaustion_is_failure_not_clean_eof() {
    let mut s = settings();
    s.max_wire_bytes = 164; // two 82-byte data records fit, required END cannot.
    let p = prepare(s, Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let [c, _] = p.channels;
    let direction = PreparedDirection {
        settings: p.settings,
        descriptor: [20; 32],
        channel: c,
        class: 0,
    };
    let end = Arc::new(Completion::default());
    let (writer, mut reader) = tokio::io::duplex(512);
    let result = send_frames(
        &b"abcd"[..],
        writer,
        &direction,
        Instant::now() + Duration::from_secs(2),
        end.clone(),
    )
    .await;
    assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::InvalidData));
    assert!(!end.done.load(Ordering::Acquire));
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty(), "uncompleted batch must not be emitted");
}

#[tokio::test]
async fn truncated_authenticated_record_body_never_releases_partial_application_bytes() {
    let p = prepared().await;
    let profile = p.settings.descriptor().unwrap();
    let mut info = b"AEGIS-Liu-fresh-context-direction-v1/".to_vec();
    info.extend(serde_json::to_vec(&context()).unwrap());
    info.extend(p.kernel_descriptor());
    info.push(1);
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&profile), &[21; 32]);
    let mut descriptor = [0; 32];
    hk.expand(&info, &mut descriptor).unwrap();
    let [_, channel] = prepared().await.channels;
    let direction = PreparedDirection {
        settings: settings(),
        descriptor,
        channel,
        class: 0,
    };
    let h = header(&direction, 0, 1, 1, false);
    let (a, mut wire) = tokio::io::duplex(512);
    let mut app = attach_authenticated(
        a,
        p,
        context(),
        Zeroizing::new([21; 32]),
        true,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    wire.write_all(&h).await.unwrap();
    wire.write_u8(65).await.unwrap();
    wire.shutdown().await.unwrap();
    assert_eq!(
        app.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}
