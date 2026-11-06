use super::*;
use tokio::time::timeout;

fn settings() -> AdaptiveSettings {
    AdaptiveSettings {
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
        cost_budget: 19,
        optimizer_iterations: 1000,
        optimizer_gap_millibits: 1,
        optimizer_timeout_ms: 1000,
        buffer_bytes: 64,
        max_wire_bytes: 100_000,
        io_timeout_ms: 300,
        session_timeout_ms: 2000,
        max_queue_delay_ms: 30_000,
    }
}
async fn prepared() -> PreparedChannel {
    prepare(settings(), Instant::now() + Duration::from_secs(2))
        .await
        .unwrap()
}

#[test]
fn full_descriptor_binds_counts_actions_cost_and_all_lifetime_caps() {
    let s = settings();
    s.validate().unwrap();
    let encoded = serde_json::to_vec(&s).unwrap();
    assert_eq!(
        serde_json::from_slice::<AdaptiveSettings>(&encoded).unwrap(),
        s
    );
    let descriptor = s.descriptor().unwrap();
    let mut changed = s.clone();
    changed.actions[0].delay_ms = 2;
    assert_ne!(descriptor, changed.descriptor().unwrap());
    let mut changed = s.clone();
    changed.joint_counts[0][0] += 1;
    assert_ne!(descriptor, changed.descriptor().unwrap());
    let mut changed = s.clone();
    changed.max_wire_bytes += 1;
    assert_ne!(descriptor, changed.descriptor().unwrap());
    let mut changed = s.clone();
    changed.session_timeout_ms -= 1;
    assert_ne!(descriptor, changed.descriptor().unwrap());
    let mut value = serde_json::to_value(&s).unwrap();
    value["unknown"] = true.into();
    assert!(serde_json::from_value::<AdaptiveSettings>(value).is_err());
}

#[test]
fn physical_infeasibility_and_count_memory_work_bounds_refuse() {
    let mut s = settings();
    s.actions[1].padded_bytes = 31;
    assert!(s.validate().is_err());
    let mut s = settings();
    s.length_bin_upper = vec![32, 16];
    assert!(s.validate().is_err());
    let mut s = settings();
    s.joint_counts[0][0] = u64::MAX;
    assert!(s.validate().is_err());
    let mut s = settings();
    s.joint_counts[1][1] = 0;
    assert!(s.validate().is_err());
    let mut s = settings();
    s.max_queue_delay_ms = 1;
    assert!(s.validate().is_err());
    let mut s = settings();
    s.buffer_bytes = 1_048_577;
    assert!(s.validate().is_err());
    let mut s = settings();
    s.cost_budget = 14;
    assert!(s.validate().is_err());
    let mut s = settings();
    s.max_wire_bytes = u64::MAX;
    assert!(s.validate().is_err());
}

#[tokio::test]
async fn actual_duplex_fifo_bidirectional_half_close_and_complete_stats() {
    let p = prepared().await;
    let original = Instant::now() + Duration::from_secs(2);
    let (left, right) = tokio::io::duplex(256);
    let mut a = attach_authenticated(left, p.clone(), original).unwrap();
    let mut b = attach_authenticated(right, p, original).unwrap();
    let input: Vec<_> = (0_u8..=255).cycle().take(257).collect();
    let outgoing = input.clone();
    let sender = tokio::spawn(async move {
        for chunk in outgoing.chunks(7) {
            a.write_all(chunk).await.unwrap();
        }
        a.shutdown().await.unwrap();
        let mut response = Vec::new();
        a.read_to_end(&mut response).await.unwrap();
        (response, a.finish().await.unwrap())
    });
    let mut received = Vec::new();
    b.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, input);
    b.write_all(&received).await.unwrap();
    b.shutdown().await.unwrap();
    let (response, a_stats) = sender.await.unwrap();
    let b_stats = b.finish().await.unwrap();
    assert_eq!(response, input);
    assert_eq!(a_stats.sent.data_bytes, 257);
    assert_eq!(b_stats.received.data_bytes, 257);
    assert_eq!(a_stats.sent.wire_bytes, b_stats.received.wire_bytes);
    assert!(a_stats.sent.padding_bytes > 0);
    assert_eq!(
        a_stats.sent.wire_bytes,
        a_stats.sent.data_bytes
            + a_stats.sent.padding_bytes
            + a_stats.sent.frames * OVERHEAD as u64
    );
}

#[test]
fn absent_objective_keeps_legacy_serialization_and_new_fields_are_strict_and_bound() {
    let s = settings();
    let legacy = serde_json::to_vec(&s).unwrap();
    // Frozen pre-objective public JSON of this original fixture, not a new
    // serializer-generated expected value: omission must preserve exact bytes.
    let legacy_hash: [u8; 32] = Sha256::digest(&legacy).into();
    assert_eq!(
        legacy_hash,
        [
            22, 135, 171, 226, 27, 153, 47, 199, 151, 120, 227, 0, 127, 27, 12, 111, 39, 188, 206,
            60, 152, 107, 59, 69, 44, 20, 210, 148, 52, 22, 133, 175
        ]
    );
    assert!(!String::from_utf8(legacy.clone())
        .unwrap()
        .contains("objective"));
    assert_eq!(
        serde_json::from_slice::<AdaptiveSettings>(&legacy).unwrap(),
        s
    );
    let mut maximum = s.clone();
    maximum.cost_budget = 32;
    maximum.objective = Some(AdaptiveObjective::MaximumInformation {
        leakage_cap_millibits: 500,
        cost_gap: 1,
    });
    assert_ne!(s.descriptor().unwrap(), maximum.descriptor().unwrap());
    let encoded = serde_json::to_vec(&maximum).unwrap();
    assert_eq!(
        serde_json::from_slice::<AdaptiveSettings>(&encoded).unwrap(),
        maximum
    );
    let mut json = serde_json::to_value(&s).unwrap();
    json["objective"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<AdaptiveSettings>(json).is_err());
    let mut json = serde_json::to_value(&maximum).unwrap();
    json["objective"]["unknown"] = true.into();
    assert!(serde_json::from_value::<AdaptiveSettings>(json).is_err());
    maximum.objective = Some(AdaptiveObjective::MinimaxInformation {
        leakage_gap_millibits: 1,
        cost_gap: 1,
        cap_programs: 32,
    });
    assert!(maximum.validate().is_err()); // one total iteration ledger, not 32 refreshed allowances
}

#[tokio::test]
async fn selected_maximum_and_minimax_channels_actuate_real_fifo_without_secret_labels() {
    for objective in [
        AdaptiveObjective::MaximumInformation {
            leakage_cap_millibits: 500,
            cost_gap: 1,
        },
        AdaptiveObjective::MinimaxInformation {
            leakage_gap_millibits: 100,
            cost_gap: 1,
            cap_programs: 8,
        },
    ] {
        let mut s = settings();
        s.cost_budget = 32;
        s.objective = Some(objective);
        let original = Instant::now() + Duration::from_secs(2);
        let p = prepare(s, original).await.unwrap();
        let certificate = p.certificate().maximum_information.as_ref().unwrap();
        assert!(certificate.worst_output_entropy_reduction_bits <= certificate.cap_bits);
        assert!(certificate.cost_gap_bound <= 1.0);
        let (left, right) = tokio::io::duplex(1024);
        let mut a = attach_authenticated(left, p.clone(), original).unwrap();
        let mut b = attach_authenticated(right, p, original).unwrap();
        let a_task = tokio::spawn(async move {
            a.write_all(b"actual request").await.unwrap();
            a.shutdown().await.unwrap();
            let mut reply = Vec::new();
            a.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"actual reply");
            a.finish().await.unwrap()
        });
        let mut request = Vec::new();
        b.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"actual request");
        b.write_all(b"actual reply").await.unwrap();
        b.shutdown().await.unwrap();
        let b_stats = b.finish().await.unwrap();
        let a_stats = a_task.await.unwrap();
        assert_eq!(a_stats.sent.data_bytes, 14);
        assert_eq!(b_stats.received.data_bytes, 14);
    }
}

#[tokio::test]
async fn causal_sender_releases_first_record_before_future_input_or_eof() {
    let mut s = settings();
    s.actions = vec![Action {
        padded_bytes: 64,
        delay_ms: 20,
    }];
    s.cost_budget = 100;
    let p = prepare(s, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let (mut input, input_worker) = tokio::io::duplex(64);
    let (wire, mut observer) = tokio::io::duplex(256);
    let end = Arc::new(Completion::default());
    let original = Instant::now() + Duration::from_secs(1);
    let worker =
        tokio::spawn(async move { send_frames(input_worker, wire, &p, original, end).await });
    let start = Instant::now();
    input.write_all(b"first").await.unwrap();
    let mut record = vec![0; OVERHEAD + 64];
    timeout(Duration::from_millis(300), observer.read_exact(&mut record))
        .await
        .unwrap()
        .unwrap();
    assert!(Instant::now().duration_since(start) >= Duration::from_millis(20));
    assert_eq!(&record[HEADER..HEADER + 5], b"first");
    assert_eq!(u16::from_be_bytes([record[14], record[15]]), 5);
    assert_eq!(
        &record[HEADER + 64..],
        &digest(&record[..HEADER], &record[HEADER..HEADER + 64])
    );
    // No future bytes or EOF had been provided at the first-record observation.
    input.shutdown().await.unwrap();
    let mut end_record = [0; OVERHEAD];
    observer.read_exact(&mut end_record).await.unwrap();
    assert_eq!(end_record[4], 1);
    assert_eq!(worker.await.unwrap().unwrap().data_bytes, 5);
}

#[tokio::test]
async fn receiver_never_exposes_partial_unverified_record_then_delivers_verified_payload() {
    let p = prepared().await;
    let (wire, mut remote) = tokio::io::duplex(256);
    let mut app =
        attach_authenticated(wire, p.clone(), Instant::now() + Duration::from_secs(1)).unwrap();
    let h = header(&p, 0, 5, 0, false);
    let body = [7_u8; 16];
    let d = digest(&h, &body);
    remote.write_all(&h).await.unwrap();
    remote.write_all(&body).await.unwrap();
    let mut decoded = [0; 5];
    assert!(
        timeout(Duration::from_millis(15), app.read_exact(&mut decoded))
            .await
            .is_err()
    );
    assert_eq!(decoded, [0; 5]);
    remote.write_all(&d).await.unwrap();
    app.read_exact(&mut decoded).await.unwrap();
    assert_eq!(decoded, [7; 5]);
    drop(app);
}

#[tokio::test]
async fn corruption_profile_mismatch_and_illegal_shrink_are_sticky_failures() {
    for mode in 0..3 {
        let p = prepared().await;
        let (wire, mut remote) = tokio::io::duplex(256);
        let mut app =
            attach_authenticated(wire, p.clone(), Instant::now() + Duration::from_secs(1)).unwrap();
        let mut h = header(&p, 0, if mode == 2 { 20 } else { 5 }, 0, false);
        if mode == 1 {
            h[16] ^= 1;
        }
        let body = [9_u8; 16];
        let mut d = digest(&h, &body);
        if mode == 0 {
            d[0] ^= 1;
        }
        remote.write_all(&h).await.unwrap();
        remote.write_all(&body).await.unwrap();
        remote.write_all(&d).await.unwrap();
        let mut byte = [0];
        assert_eq!(
            app.read(&mut byte).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(byte, [0]);
        assert_eq!(
            app.write_all(b"late").await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            app.read(&mut byte).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[tokio::test]
async fn original_deadline_and_truncated_frame_refuse_instead_of_clean_eof() {
    let p = prepared().await;
    assert!(prepare(settings(), Instant::now()).await.is_err());
    let (wire, _remote) = tokio::io::duplex(128);
    assert!(attach_authenticated(wire, p.clone(), Instant::now()).is_err());
    let (wire, mut remote) = tokio::io::duplex(128);
    let mut app =
        attach_authenticated(wire, p.clone(), Instant::now() + Duration::from_millis(35)).unwrap();
    remote.write_all(&header(&p, 0, 5, 0, false)).await.unwrap();
    assert_eq!(
        app.read(&mut [0]).await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    let (wire, mut remote) = tokio::io::duplex(128);
    let mut app =
        attach_authenticated(wire, p.clone(), Instant::now() + Duration::from_secs(1)).unwrap();
    remote
        .write_all(&header(&p, 0, 5, 0, false)[..20])
        .await
        .unwrap();
    remote.shutdown().await.unwrap();
    assert_eq!(
        app.read(&mut [0]).await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn stalled_wire_backpressure_fails_with_bounded_owner_and_sticky_error() {
    let mut s = settings();
    s.io_timeout_ms = 40;
    let p = prepare(s, Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let (wire, _remote) = tokio::io::duplex(1);
    let mut app =
        attach_authenticated(wire, p, Instant::now() + Duration::from_millis(150)).unwrap();
    app.write_all(&[1; 32]).await.unwrap();
    assert_eq!(
        timeout(Duration::from_millis(300), app.shutdown())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        app.write_all(b"later").await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

#[tokio::test]
async fn dropping_stream_closes_owned_transport_without_disturbing_spectator() {
    let p = prepared().await;
    let (wire, mut remote) = tokio::io::duplex(128);
    let app = attach_authenticated(wire, p, Instant::now() + Duration::from_secs(1)).unwrap();
    let (mut spectator_a, mut spectator_b) = tokio::io::duplex(8);
    spectator_a.write_all(b"live").await.unwrap();
    let mut proof = [0; 4];
    spectator_b.read_exact(&mut proof).await.unwrap();
    drop(app);
    assert_eq!(
        timeout(Duration::from_millis(100), remote.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    spectator_b.write_all(&proof).await.unwrap();
    spectator_a.read_exact(&mut proof).await.unwrap();
    assert_eq!(&proof, b"live");
}

#[tokio::test]
async fn wire_budget_exhaustion_never_publishes_green_finish() {
    let mut s = settings();
    s.max_wire_bytes = (OVERHEAD * 2 + 32) as u64;
    let p = prepare(s, Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let (left, right) = tokio::io::duplex(512);
    let mut a =
        attach_authenticated(left, p.clone(), Instant::now() + Duration::from_secs(1)).unwrap();
    let mut b = attach_authenticated(right, p, Instant::now() + Duration::from_secs(1)).unwrap();
    let writer = tokio::spawn(async move {
        let _ = a.write_all(&[3; 96]).await;
        a.finish().await
    });
    let mut received = Vec::new();
    assert!(b.read_to_end(&mut received).await.is_err());
    assert!(received.len() <= 64);
    assert!(writer.await.unwrap().is_err());
}
