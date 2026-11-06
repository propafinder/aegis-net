use super::*;
fn settings() -> Settings {
    Settings {
        lambda_pps: 200,
        delta_pps: 20,
        reference_epsilon_milli: 500,
        service_mu_pps: 2000,
        buffering_ms: 200,
        block_ms: 100,
        bits_per_block: 6,
        payload_capacity: 1,
        max_word_events: 128,
        fifo_packets: 2048,
        total_packets: 8192,
        packet_bytes: 128,
        ready_lead_ms: 200,
        clock_uncertainty_us: 10_000,
        release_lateness_us: 10_000,
        drain_ms: 200,
        finalize_ms: 1000,
        precision_poll_budget: 2_000_000,
    }
}
#[test]
fn authenticated_fixed_record_fresh_material_and_no_double_encoding() {
    let end = Instant::now() + Duration::from_secs(10);
    let a = Prepared::new(settings(), Zeroizing::new([1; 32]), end).unwrap();
    let b = Prepared::new(settings(), Zeroizing::new([1; 32]), end).unwrap();
    let words = a.encode(b"x").unwrap();
    assert!(a.encode(b"y").is_err());
    assert_eq!(b.decode_record(&words).unwrap().as_slice(), b"x");
    let c = Prepared::new(settings(), Zeroizing::new([2; 32]), end).unwrap();
    assert_ne!(a.digest(), c.digest());
    assert!(c.decode_record(&words).is_err());
    let mut altered = words;
    altered[0] ^= 1;
    assert!(b.decode_record(&altered).is_err());
}
#[test]
fn caps_unstable_service_and_modeled_rate_refuse() {
    let mut s = settings();
    s.service_mu_pps = s.lambda_pps;
    assert!(s.validate().is_err());
    s = settings();
    s.bits_per_block = 7;
    assert!(s.validate().is_err());
    s = settings();
    s.block_ms = 10;
    s.service_mu_pps = s.lambda_pps + 1;
    assert!(s.validate().is_err());
    s = settings();
    s.delta_pps = 199;
    assert!(s.validate().is_err());
    let mut v = serde_json::to_value(settings()).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("legitimate".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<Settings>(v).is_err());
}
#[test]
fn actual_observations_required_and_impossible_order_refused() {
    let p = Prepared::new(
        settings(),
        Zeroizing::new([3; 32]),
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap();
    let (word, points) = p
        .book(0)
        .unwrap()
        .iter()
        .enumerate()
        .find(|(_, p)| p.len() > 1)
        .unwrap();
    let observed: Vec<_> = points.iter().map(|t| t + 1).collect();
    assert_eq!(p.decode_arrivals(0, &observed, 0, 0).unwrap(), word);
    let mut wrong = observed;
    wrong.swap(0, 1);
    assert!(p.decode_arrivals(0, &wrong, 0, 0).is_err());
    assert!(p
        .decode_arrivals(
            0,
            &vec![0; usize::from(settings().max_word_events) + 1],
            0,
            0
        )
        .is_err());
    assert!(Prepared::new(settings(), Zeroizing::new([1; 32]), Instant::now()).is_err());
}
async fn pair() -> (UdpSocket, UdpSocket) {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.connect(b.local_addr().unwrap()).await.unwrap();
    b.connect(a.local_addr().unwrap()).await.unwrap();
    (a, b)
}

#[tokio::test]
async fn actual_collector_error_survives_failure_wait_checkpoint_and_terminal_join() {
    let (wire, collector) = pair().await;
    let (delivery, app) = pair().await;
    let end = Instant::now() + Duration::from_secs(2);
    let start = end + Duration::from_secs(1);
    let mut receiver = Receiver::new(collector, delivery, settings(), start, end).unwrap();
    wire.send(b"before origin").await.unwrap();
    let first = receiver.wait_failure(end).await.unwrap_err();
    let checkpoint = Checkpoint {
        ordinal: 0,
        hashes: vec![Sha256::digest(b"before origin").into()],
    };
    let second = receiver.checkpoint(&checkpoint, 1, end).await.unwrap_err();
    let terminal = receiver.finish(end).await.unwrap_err();
    for error in [first, second, terminal] {
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.get_ref().unwrap().downcast_ref::<Phase>().unwrap().0,
            "clock_before_origin"
        );
    }
    assert!(receiver.observer.snapshot().collector_joined);
    assert_eq!(receiver.observer.snapshot().delivered_packets, 0);
    assert!(app.try_recv(&mut [0; 32]).is_err());
}
#[tokio::test]
async fn actual_owned_udp_original_bytes_fifo_and_arrival_observation() {
    let (ingress, app) = pair().await;
    let (wire, collector) = pair().await;
    let (delivery, receiver_app) = pair().await;
    let s = settings();
    let start = Instant::now();
    let end = start + Duration::from_secs(2);
    let mut sender = Sender::new(ingress, wire).unwrap();
    let mut receiver = Receiver::new(collector, delivery, s.clone(), start, end).unwrap();
    app.send(b"first original").await.unwrap();
    app.send(b"second original").await.unwrap();
    let checkpoint = sender
        .block(start, &[20_000_000, 40_000_000], &s, 1, end)
        .await
        .unwrap();
    let stamps = receiver.checkpoint(&checkpoint, 128, end).await.unwrap();
    assert_eq!(checkpoint.hashes.len(), 2);
    assert!(stamps[0] >= 20_000_000);
    assert!(stamps[1] >= 40_000_000);
    assert!(stamps[0] < stamps[1]);
    let mut buf = [0; 128];
    let n = receiver_app.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"first original");
    let n = receiver_app.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"second original");
    receiver.finish(end).await.unwrap();
    assert_eq!(sender.observations.accepted_packets, 2);
    assert_eq!(sender.observations.sent_packets, 2);
    assert_eq!(sender.observations.retained_packets, 0);
    assert_eq!(receiver.observations.delivered_packets, 2);
}
#[tokio::test]
async fn starvation_preserves_sent_prefix_and_never_fills() {
    let (ingress, app) = pair().await;
    let (wire, peer) = pair().await;
    let s = settings();
    let start = Instant::now();
    let end = start + Duration::from_secs(1);
    let mut sender = Sender::new(ingress, wire).unwrap();
    let observer = Observer::default();
    sender.observe(observer.clone());
    app.send(b"one real").await.unwrap();
    assert!(sender
        .block(start, &[10_000_000, 20_000_000], &s, 1, end)
        .await
        .is_err());
    assert_eq!(observer.snapshot().sent_packets, 1);
    assert_eq!(observer.snapshot().accepted_packets, 1);
    let mut buf = [0; 128];
    let n = peer.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"one real");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), peer.recv(&mut buf))
            .await
            .is_err()
    );
}
#[tokio::test]
async fn wrong_payload_hash_refuses_before_application_and_drop_aborts_only_owned_collector() {
    let (wire, collector) = pair().await;
    let (delivery, app) = pair().await;
    let saved = collector.local_addr().unwrap();
    let observer = Observer::default();
    let start = Instant::now();
    let end = start + Duration::from_secs(1);
    let mut receiver = Receiver::new_observed(
        collector,
        delivery,
        settings(),
        start,
        end,
        observer.clone(),
    )
    .unwrap();
    wire.send(b"foreign bytes").await.unwrap();
    assert!(receiver
        .checkpoint(
            &Checkpoint {
                ordinal: 1,
                hashes: vec![Sha256::digest(b"expected").into()]
            },
            1,
            end
        )
        .await
        .is_err());
    assert_eq!(observer.snapshot().received_packets, 1);
    assert_eq!(observer.snapshot().delivered_packets, 0);
    drop(receiver);
    assert!(observer.snapshot().collector_abort_requested);
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        if UdpSocket::bind(saved).await.is_ok() {
            break;
        }
        live(until).unwrap();
        tokio::task::yield_now().await;
    }
    let mut buf = [0; 128];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), app.recv(&mut buf))
            .await
            .is_err()
    );
    let (a, b) = pair().await;
    a.send(b"unrelated remains live").await.unwrap();
    let n = b.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"unrelated remains live");
}
#[tokio::test]
async fn source_capacity_reports_owned_pending_and_no_late_replay() {
    let (ingress, app) = pair().await;
    let (wire, peer) = pair().await;
    let mut s = settings();
    s.fifo_packets = 1;
    let start = Instant::now();
    let end = start + Duration::from_secs(1);
    let mut sender = Sender::new(ingress, wire).unwrap();
    let observer = Observer::default();
    sender.observe(observer.clone());
    app.send(b"one").await.unwrap();
    app.send(b"two").await.unwrap();
    assert!(sender
        .block(start, &[30_000_000], &s, 1, end)
        .await
        .is_err());
    assert_eq!(observer.snapshot().accepted_packets, 2);
    assert_eq!(observer.snapshot().sent_packets, 0);
    assert_eq!(observer.snapshot().retained_packets, 2);
    let mut buf = [0; 128];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), peer.recv(&mut buf))
            .await
            .is_err()
    );
    assert!(sender
        .block(Instant::now() - Duration::from_secs(1), &[0], &s, 2, end)
        .await
        .is_err());
    assert_eq!(observer.snapshot().sent_packets, 0);
}

#[test]
fn finite_kl_reference_uses_slowed_rate_and_never_certifies_actual_models() {
    let s = settings();
    let r = s.conditional_reference().unwrap();
    assert!((r.finite_kl_upper_approx_nats - 400. * 0.2 / (2. * 180.)).abs() < 1e-12);
    assert!(r.pinsker_upper_approx <= 0.5);
    assert!(r.integer_kl_admission_checked);
    assert!(!r.actual_poisson_process_verified && !r.actual_mm1_service_verified);
    let mut tight = s;
    tight.reference_epsilon_milli = 300;
    assert!(tight.validate().is_err());
}
#[tokio::test]
async fn actual_missing_packet_deadline_never_delivers_or_fakes_terminal_collector() {
    let (wire, collector) = pair().await;
    let (delivery, app) = pair().await;
    let start = Instant::now();
    let end = start + Duration::from_millis(40);
    let mut receiver = Receiver::new(collector, delivery, settings(), start, end).unwrap();
    let observed = receiver.observer.clone();
    let c = Checkpoint {
        ordinal: 1,
        hashes: vec![Sha256::digest(b"absent original").into()],
    };
    let error = receiver.checkpoint(&c, 1, end).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(receiver.observations.delivered_packets, 0);
    drop(receiver);
    assert!(observed.snapshot().collector_abort_requested);
    assert!(!observed.snapshot().collector_joined);
    let mut bytes = [0; 128];
    assert!(app.try_recv(&mut bytes).is_err());
    assert!(wire.local_addr().is_ok());
}

#[tokio::test]
async fn abort_with_expired_original_deadline_never_claims_joined_collector() {
    let (_wire, collector) = pair().await;
    let (delivery, _app) = pair().await;
    let start = Instant::now();
    let mut receiver = Receiver::new(
        collector,
        delivery,
        settings(),
        start,
        start + Duration::from_secs(10),
    )
    .unwrap();
    let observed = receiver.observer.clone();
    let error = receiver
        .abort_and_join_until(start - Duration::from_nanos(1))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(observed.snapshot().collector_abort_requested);
    assert!(!observed.snapshot().collector_joined);
    // Even if cancellation later completes, this receipt must not invent an
    // observed join or renew the original operation's clock.
    tokio::task::yield_now().await;
    assert!(!observed.snapshot().collector_joined);
}

#[tokio::test]
async fn failed_finish_observes_cancelled_terminal_without_polling_handle_twice() {
    let (_wire, collector) = pair().await;
    let (delivery, _app) = pair().await;
    let start = Instant::now();
    let end = start + Duration::from_secs(10);
    let mut receiver = Receiver::new(collector, delivery, settings(), start, end).unwrap();
    receiver.task.as_ref().unwrap().abort();
    let error = receiver.finish(end).await.unwrap_err();
    assert_eq!(
        error.get_ref().unwrap().downcast_ref::<Phase>().unwrap().0,
        "collector_terminal"
    );
    assert!(receiver.observer.snapshot().collector_joined);
    assert!(receiver.task.is_none());
    // SDK error retirement is safe after a failed finish; a completed handle
    // must never be polled twice or turn cancellation into successful delivery.
    receiver.abort_and_join_until(end).await.unwrap();
    assert_eq!(receiver.observer.snapshot().delivered_packets, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_prior_seed_actual_sdk_udp_codebooks_decode_authenticated_record() {
    // This seed is fixed before this test's first run. It is not selected by
    // observed scheduler outcomes and does not change production sampling.
    let mut s = settings();
    s.lambda_pps = 20;
    s.delta_pps = 1;
    s.block_ms = 1000;
    let origin = Instant::now();
    let end = origin + Duration::from_secs(40);
    let prepared = Prepared::new(s.clone(), Zeroizing::new([3; 32]), end).unwrap();
    let words = prepared.encode(b"x").unwrap();
    let preparation_complete_ns = origin.elapsed().as_nanos();
    let count: usize = words
        .iter()
        .enumerate()
        .map(|(i, &w)| prepared.book(i).unwrap()[w].len())
        .sum();
    let (ingress, source) = pair().await;
    let (wire, collector) = pair().await;
    let (delivery, app) = pair().await;
    let mut sender = Sender::new(ingress, wire).unwrap();
    let observer = Observer::default();
    sender.observe(observer.clone());
    // Actual cooperative application source. Preload via real socket receives,
    // one packet at a time; this is controlled fixture service, not M/M/1.
    let setup_end = origin + Duration::from_secs(2);
    for n in 0..count {
        source.send(&(n as u64).to_be_bytes()).await.unwrap();
        sender
            .gather(setup_end, origin, &s, end, true)
            .await
            .unwrap();
    }
    let source_setup_complete_ns = origin.elapsed().as_nanos();
    let start = Instant::now() + Duration::from_millis(100);
    let mut receiver = Receiver::new(collector, delivery, s.clone(), start, end).unwrap();
    let mut decoded = Vec::new();
    let mut delivered = 0u64;
    let mut previous = 0u64;
    let spawn_entered_ns = origin.elapsed().as_nanos();
    let mut owner = OwnedSender::spawn_blocks(sender, &prepared, &words, start, end).unwrap();
    let spawn_returned_ns = origin.elapsed().as_nanos();
    owner.ready(end).await.unwrap();
    let ready_returned_ns = origin.elapsed().as_nanos();
    let released = owner.finish(end).await;
    let release_returned_ns = origin.elapsed().as_nanos();
    println!(
        "poisson_original_release_phase={}",
        serde_json::json!({
            "clock":"original_fixture_tokio_instant_unpaused",
            "original_caller_budget_ns":40_000_000_000u64,
            "original_release_lateness_ns":u64::from(s.release_lateness_us)*1000,
            "preparation_complete_ns":preparation_complete_ns,
            "source_setup_complete_ns":source_setup_complete_ns,
            "original_start_ns":start.duration_since(origin).as_nanos(),
            "spawn_entered_ns":spawn_entered_ns,"spawn_returned_ns":spawn_returned_ns,
            "ready_returned_ns":ready_returned_ns,"release_returned_ns":release_returned_ns,
            "original_source_packets":count,"selected_blocks":words.len(),
            "release_failed":released.is_err(),"diagnostic_only":true,
            "native_scheduler_cause_proven":false
        })
    );
    if let Err(error) = &released {
        println!(
            "owned_positive_refusal={} kind={:?} observations={:?}",
            error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<Phase>())
                .map_or("non_owned_error", |phase| phase.0),
            error.kind(),
            observer.snapshot()
        );
    }
    let released = released.unwrap();
    println!("owned_positive_observations={:?}", released.observations);
    for block in 0..words.len() {
        let checkpoint = &released.checkpoints[block + 1];
        let stamps = receiver
            .checkpoint(checkpoint, usize::from(s.max_word_events), end)
            .await
            .unwrap();
        let block_ns = block as u64 * u64::from(s.block_ms) * 1_000_000;
        let actual: Vec<_> = stamps
            .iter()
            .map(|&d| d.checked_sub(block_ns).unwrap())
            .collect();
        decoded.push(
            prepared
                .decode_arrivals(block, &actual, previous.saturating_sub(block_ns), 0)
                .unwrap(),
        );
        if let Some(&last) = stamps.last() {
            previous = last;
        }
        for _ in &stamps {
            let mut bytes = [0; 8];
            let n = tokio::time::timeout_at(end, app.recv(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(n, 8);
            assert_eq!(u64::from_be_bytes(bytes), delivered);
            delivered += 1;
        }
    }
    assert_eq!(prepared.decode_record(&decoded).unwrap().as_slice(), b"x");
    receiver.finish(end).await.unwrap();
    assert_eq!(count, delivered as usize);
    assert_eq!(released.observations.accepted_packets, count);
    assert_eq!(released.observations.sent_packets, count);
    assert_eq!(released.observations.retained_packets, 0);
    assert!(!receiver.observations.service_model_verified);
    assert!(released.observations.release_thread_joined);
    assert!(released.observations.service_queue_contract_v2);
}

#[tokio::test(start_paused = true)]
async fn paused_original_target_tolerance_never_allows_overlap_or_budget_extension() {
    let (ingress, _app) = pair().await;
    let (wire, _peer) = pair().await;
    let mut sender = Sender::new(ingress, wire).unwrap();
    let s = settings();
    let origin = Instant::now();
    let end = origin + Duration::from_secs(1);
    let target = origin + Duration::from_millis(20);
    tokio::time::advance(Duration::from_millis(22)).await;
    sender.check_public_target(target, &s, 1, end).unwrap();
    assert_eq!(sender.observations.observed_point_lateness_ns, 2_000_000);
    assert!(
        !sender
            .observations
            .prior_completed_write_reached_missed_target
    );
    sender.last_completed_write = Some(target);
    assert_eq!(
        sender
            .check_public_target(target, &s, 1, end)
            .unwrap_err()
            .get_ref()
            .unwrap()
            .downcast_ref::<Phase>()
            .unwrap()
            .0,
        "public_point_prior_write_overlap"
    );
    sender.last_completed_write = None;
    tokio::time::advance(Duration::from_millis(9)).await;
    assert_eq!(
        sender
            .check_public_target(target, &s, 1, end)
            .unwrap_err()
            .get_ref()
            .unwrap()
            .downcast_ref::<Phase>()
            .unwrap()
            .0,
        "public_point_delivery_cutoff"
    );
    assert_eq!(sender.observations.sent_packets, 0);
}
#[tokio::test]
async fn real_original_target_small_lateness_delivers_one_original_without_overlap() {
    let (ingress, app) = pair().await;
    let (wire, peer) = pair().await;
    let s = settings();
    let mut sender = Sender::new(ingress, wire).unwrap();
    let origin = Instant::now();
    let end = origin + Duration::from_secs(1);
    app.send(b"one original").await.unwrap();
    sender
        .gather(origin + Duration::from_millis(50), origin, &s, end, true)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1)).await;
    let target = Instant::now() - Duration::from_micros(100);
    sender.check_public_target(target, &s, 1, end).unwrap();
    sender.release(target, &s, end).await.unwrap();
    let mut bytes = [0; 128];
    let n = tokio::time::timeout_at(end, peer.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], b"one original");
    assert_eq!(sender.observations.sent_packets, 1);
    assert_eq!(sender.observations.retained_packets, 0);
    assert!(sender.check_public_target(target, &s, 2, end).is_err());
}
#[tokio::test]
async fn actual_send_crossing_original_cutoff_retains_confirmed_sent_prefix() {
    let (ingress, app) = pair().await;
    let (wire, peer) = pair().await;
    let mut s = settings();
    s.release_lateness_us = 1_000;
    let mut sender = Sender::new(ingress, wire).unwrap();
    let observer = Observer::default();
    sender.observe(observer.clone());
    let origin = Instant::now();
    let end = origin + Duration::from_secs(1);
    app.send(b"physical original").await.unwrap();
    sender
        .gather(origin + Duration::from_millis(50), origin, &s, end, true)
        .await
        .unwrap();
    sender.completion_observation_delay = Some(Duration::from_millis(10));
    let error = sender.release(Instant::now(), &s, end).await.unwrap_err();
    assert_eq!(
        error.get_ref().unwrap().downcast_ref::<Phase>().unwrap().0,
        "packet_write_delivery_cutoff"
    );
    let mut bytes = [0; 128];
    let n = tokio::time::timeout_at(end, peer.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], b"physical original");
    assert_eq!(observer.snapshot().accepted_packets, 1);
    assert_eq!(observer.snapshot().sent_packets, 1);
    assert_eq!(observer.snapshot().retained_packets, 0);
}

#[test]
fn unchanged_prior_seed_selected_schedule_gap_observation() {
    let mut s = settings();
    s.lambda_pps = 20;
    s.delta_pps = 1;
    s.block_ms = 1000;
    let prepared = Prepared::new(
        s.clone(),
        Zeroizing::new([3; 32]),
        Instant::now() + Duration::from_secs(40),
    )
    .unwrap();
    let words = prepared.encode(b"x").unwrap();
    let mut prior = None;
    let mut minimum = u64::MAX;
    let mut events = 0;
    for (block, &word) in words.iter().enumerate() {
        for &point in &prepared.book(block).unwrap()[word] {
            let at = block as u64 * 1_000_000_000 + point;
            if let Some(last) = prior {
                minimum = minimum.min(at - last);
            }
            prior = Some(at);
            events += 1;
        }
    }
    println!(
        "fixed_public_fixture_selected_event_count={events} minimum_original_gap_ns={minimum}"
    );
    assert!(minimum > 0);
}
// Test-only clock custody for the actual native UDP arrival setup. In the
// locked Tokio test-util runtime, a scheduled blocking task inhibits paused
// clock auto-advance until it terminates. The native wait has one real-wall
// bound and is released/awaited before the original overlap exercise.
struct CoincidentArrivalClockHold {
    stop: Option<std::sync::mpsc::Sender<()>>,
    task: Option<tokio::task::JoinHandle<bool>>,
}
impl CoincidentArrivalClockHold {
    fn new() -> Self {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let (stop, stopped) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            stopped
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .is_ok()
        });
        Self {
            stop: Some(stop),
            task: Some(task),
        }
    }
    async fn finish(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let released = self
            .task
            .take()
            .unwrap()
            .await
            .expect("owned arrival clock hold panicked");
        assert!(
            released,
            "actual UDP arrival setup exceeded real wall bound"
        );
    }
}
impl Drop for CoincidentArrivalClockHold {
    fn drop(&mut self) {
        // Dropping only this sender wakes its own blocking receive. Abort
        // cancels a queued task; an already running task observes disconnect.
        self.stop.take();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[tokio::test(start_paused = true)]
async fn actual_phase_one_coincident_arrivals_refuse_prior_completed_write_overlap() {
    let (ingress, app) = pair().await;
    let (wire, peer) = pair().await;
    let s = settings();
    let mut arrival_clock_hold = CoincidentArrivalClockHold::new();
    let origin = Instant::now();
    let end = origin + Duration::from_secs(1);
    let mut sender = Sender::new(ingress, wire).unwrap();
    app.send(b"first phase original").await.unwrap();
    app.send(b"second phase original").await.unwrap();
    sender.source.as_ref().unwrap().readable().await.unwrap();
    sender
        .gather(origin + Duration::from_millis(50), origin, &s, end, true)
        .await
        .unwrap();
    sender
        .gather(origin + Duration::from_millis(50), origin, &s, end, true)
        .await
        .unwrap();
    assert_eq!(sender.queue[0].arrived, sender.queue[1].arrived);
    // These are equal read observations under the synthetic paused clock,
    // not a claim of physically simultaneous source arrivals. The native
    // release owner uses real time; resume without resetting origin or END.
    arrival_clock_hold.finish().await;
    tokio::time::resume();
    let result = sender.buffering(origin, &s, end).await;
    assert!(
        result.is_err(),
        "phase one must not release a second nominal point crossed by the first actual completion"
    );
    assert_eq!(sender.observations.sent_packets, 1);
    assert_eq!(sender.observations.retained_packets, 1);
    let mut bytes = [0; 128];
    let n = peer.recv(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..n], b"first phase original");
    assert!(peer.try_recv(&mut bytes).is_err());
}

#[tokio::test]
async fn public_sdk_invalid_rates_refuse_before_any_original_read_or_send() {
    for delta in [settings().lambda_pps, settings().lambda_pps + 1] {
        for mode in 0..3 {
            let (ingress, app) = pair().await;
            let (wire, peer) = pair().await;
            let mut s = settings();
            s.delta_pps = delta;
            let mut sender = Sender::new(ingress, wire).unwrap();
            let origin = Instant::now();
            let end = origin + Duration::from_secs(1);
            app.send(b"untouched original").await.unwrap();
            sender.source.as_ref().unwrap().readable().await.unwrap();
            let result = match mode {
                0 => sender.block(origin, &[10_000_000], &s, 1, end).await,
                1 => sender.buffering(origin, &s, end).await,
                _ => sender.drain(&s, 1, end).await,
            };
            assert!(
                result.is_err(),
                "invalid public rate must refuse before packet custody"
            );
            assert_eq!(sender.observations.accepted_packets, 0);
            assert_eq!(sender.observations.sent_packets, 0);
            let mut bytes = [0; 128];
            let n = sender
                .source
                .as_ref()
                .unwrap()
                .try_recv(&mut bytes)
                .unwrap();
            assert_eq!(&bytes[..n], b"untouched original");
            assert!(peer.try_recv(&mut bytes).is_err());
        }
    }
}

#[tokio::test]
async fn public_actual_write_independent_of_tokio_repolls() {
    use std::{future::Future, task::Poll};
    let (ingress, app) = pair().await;
    let (wire, peer) = pair().await;
    let peer = peer.into_std().unwrap();
    peer.set_nonblocking(true).unwrap();
    let s = settings();
    let origin = Instant::now();
    let end = origin + Duration::from_secs(2);
    let mut sender = Sender::new(ingress, wire).unwrap();
    app.send(b"actual executor-independent write")
        .await
        .unwrap();
    sender
        .gather(origin + Duration::from_millis(100), origin, &s, end, true)
        .await
        .unwrap();
    let start = Instant::now();
    let mut command = Box::pin(sender.block(start, &[20_000_000], &s, 1, end));
    std::future::poll_fn(|cx| {
        assert!(command.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    // The original deadline remains20ms+10ms. Do not repoll Tokio while
    // observing a real native UDP receive after this controlled stall.
    std::thread::sleep(Duration::from_millis(60));
    let mut bytes = [0; 128];
    let n = peer.recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..n], b"actual executor-independent write");
    assert_eq!(command.await.unwrap().hashes.len(), 1);
    assert_eq!(sender.observations.sent_packets, 1);
}

#[test]
fn absent_service_cutoff_preserves_original_serialized_observation_value() {
    let actual = serde_json::to_value(Observations::default()).unwrap();
    let original: serde_json::Value = serde_json::from_str(
        r#"{"accepted_packets":0,"collector_abort_requested":false,"collector_joined":false,"collector_started":false,"delivered_packets":0,"maximum_admission_lateness_ns":0,"maximum_service_duration_ns":0,"maximum_service_wait_ns":0,"missed_public_block_ordinal":null,"missed_public_points":0,"native_absolute_coarse_wait_calls":0,"native_absolute_fine_wait_calls":0,"native_clock_polls":0,"native_fine_sleep_calls":0,"native_park_calls":0,"native_recv_attempts":0,"native_send_attempts":0,"native_source_reads_completed":0,"native_spin_steps":0,"native_work_steps":0,"observed_point_lateness_ns":0,"pending_service_packets":0,"precision_polls":0,"preparation_work_steps":0,"prior_completed_write_reached_missed_target":false,"received_packets":0,"release_cancel_requested":false,"release_thread_joined":false,"release_thread_started":false,"release_thread_terminal":false,"retained_packets":0,"sent_packets":0,"service_model_verified":false,"service_queue_admissions":0,"service_queue_contract_v2":false,"strict_command_buffers_discarded":false,"strict_command_custody_consumed":false,"strict_command_custody_restored":false,"strict_command_preparation_failed":false,"warden_packetization_verified":false}"#,
    )
    .unwrap();
    assert!(actual.get("service_cutoff").is_none());
    assert_eq!(actual, original);
}

#[test]
fn darwin_first_miss_serializes_only_relative_bounded_shape() {
    let miss = DarwinAdmissionMissObservation {
        event_ordinal: 502,
        block_ordinal: 4,
        original_allowance_ns: 10_000_000,
        observed_lateness_ns: 25_940_083,
        cutoff_excess_ns: 15_940_083,
        qos_requested_class: Some(0x19),
        qos_readback_matched: true,
        mach_policy_readback_matched: true,
        last_wait_present: true,
        last_wait_point_matches_admission: true,
        no_intervening_io_attempt: true,
        gather_point_matches_admission: true,
        last_wait_coarse: Some(true),
        last_wait_call_interval_ns: Some(23_000_000),
        last_wait_wake_overshoot_ns: Some(22_000_000),
        last_wait_return_to_gather_ns: Some(1_000_000),
        gather_to_admission_ns: Some(940_083),
        last_wait_return_to_admission_ns: Some(1_940_083),
    };
    let value = serde_json::to_value(&miss).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 18);
    assert_eq!(value["cutoff_excess_ns"], 15_940_083);
    for forbidden in [
        "raw_point",
        "timestamp",
        "schedule",
        "payload",
        "address",
        "secret",
    ] {
        assert!(value.get(forbidden).is_none());
    }
}
