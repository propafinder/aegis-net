use super::*;
use std::{future::Future, task::Poll};

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
async fn pair() -> (UdpSocket, UdpSocket) {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.connect(b.local_addr().unwrap()).await.unwrap();
    b.connect(a.local_addr().unwrap()).await.unwrap();
    (a, b)
}
async fn until_started(observer: &Observer, end: Instant) {
    while !observer.snapshot().release_thread_started {
        assert!(Instant::now() < end);
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn strict_native_command_sends_while_original_runtime_is_blocked() {
    let (input, application) = pair().await;
    let (output, recipient) = pair().await;
    let mut sender = Sender::new(input, output).unwrap();
    let recipient = recipient.into_std().unwrap();
    recipient.set_nonblocking(true).unwrap();
    let s = settings();
    let origin = Instant::now();
    let end = origin + Duration::from_secs(2);
    application.send(b"actual original").await.unwrap();
    sender
        .gather(origin + Duration::from_millis(100), origin, &s, end, true)
        .await
        .unwrap();
    let observer = sender.observer.clone();
    // Give native thread creation and platform priority preparation time before
    // the original public point. The 10 ms delivery cutoff stays unchanged.
    let start = Instant::now() + Duration::from_millis(300);
    let mut command = Box::pin(sender.block(start, &[20_000_000], &s, 1, end));
    std::future::poll_fn(|cx| {
        assert!(command.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    until_started(&observer, end).await;
    // No Tokio timer/send future can be re-polled during this interval.
    // The native actor must perform the original-point write itself.
    thread::sleep(Duration::from_millis(400));
    let mut bytes = [0u8; 128];
    // Preserve the one original on-time receive snapshot. A later successful
    // command cannot substitute for it, and this fixture never receives again.
    let receive_result = recipient.recv(&mut bytes);
    // Observe the existing actor's typed result and join under its original END
    // before either original success assertion can terminate the fixture.
    let command_result = command.await;
    #[cfg(windows)]
    {
        let observed = observer.snapshot();
        let (receive_kind, receive_os_code) = match &receive_result {
            Ok(_) => (None, None),
            Err(error) => (Some(format!("{:?}", error.kind())), error.raw_os_error()),
        };
        let (command_kind, command_phase) = match &command_result {
            Ok(_) => (None, None),
            Err(error) => (
                Some(format!("{:?}", error.kind())),
                error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<Phase>())
                    .map(|phase| phase.0),
            ),
        };
        let (preparation_api_attempts, preparation_readback_present) = {
            let preparation = sender
                .strict_thread_preparation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                preparation.native_api_attempts,
                preparation.requested_priority_readback_present,
            )
        };
        // Static categories and finite numerical ownership facts only: never
        // format the error chain, socket, payload, source epoch or packet bytes.
        eprintln!(
            "strict_command_receive_terminal_observation={}",
            serde_json::json!({
                "original_single_receive_ok": receive_result.is_ok(),
                "original_single_receive_length": receive_result.as_ref().ok(),
                "original_single_receive_error_kind": receive_kind,
                "original_single_receive_os_code": receive_os_code,
                "original_command_ok": command_result.is_ok(),
                "original_command_error_kind": command_kind,
                "original_command_phase": command_phase,
                "release_thread_started": observed.release_thread_started,
                "release_thread_terminal": observed.release_thread_terminal,
                "release_thread_joined": observed.release_thread_joined,
                "release_cancel_requested": observed.release_cancel_requested,
                "strict_command_custody_consumed": observed.strict_command_custody_consumed,
                "strict_command_custody_restored": observed.strict_command_custody_restored,
                "strict_command_buffers_discarded": observed.strict_command_buffers_discarded,
                "strict_command_preparation_failed": observed.strict_command_preparation_failed,
                "native_work_steps": observed.native_work_steps,
                "native_recv_attempts": observed.native_recv_attempts,
                "native_send_attempts": observed.native_send_attempts,
                "sent_packets": observed.sent_packets,
                "preparation_native_api_attempts": preparation_api_attempts,
                "preparation_requested_priority_readback_present": preparation_readback_present,
            })
        );
    }
    let n = receive_result.unwrap();
    assert_eq!(&bytes[..n], b"actual original");
    let checkpoint = command_result.unwrap();
    assert_eq!(checkpoint.hashes.len(), 1);
    assert!(sender.source.is_some() && sender.sink.is_some());
    assert_eq!(sender.observations.sent_packets, 1);
    assert!(sender.observations.release_thread_joined);
    assert!(!sender.observations.service_queue_contract_v2);
}

#[tokio::test]
async fn cancelled_command_never_restores_or_replays_sender_custody() {
    let (input, _) = pair().await;
    let (output, recipient) = pair().await;
    let (foreign, foreign_peer) = pair().await;
    let mut sender = Sender::new(input, output).unwrap();
    let s = settings();
    let observer = sender.observer.clone();
    let start = Instant::now() + Duration::from_millis(200);
    let end = Instant::now() + Duration::from_secs(2);
    let mut command = Box::pin(sender.block(start, &[20_000_000], &s, 1, end));
    std::future::poll_fn(|cx| {
        assert!(command.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    until_started(&observer, end).await;
    drop(command);
    assert!(sender.source.is_none() && sender.sink.is_none());
    assert!(sender.observations.release_cancel_requested);
    assert!(!sender.observations.release_thread_joined);
    while !observer.snapshot().release_thread_terminal {
        assert!(Instant::now() < end);
        tokio::task::yield_now().await;
    }
    assert_eq!(observer.snapshot().sent_packets, 0);
    assert!(!observer.snapshot().release_thread_joined);
    let error = sender
        .block(start, &[20_000_000], &s, 1, end)
        .await
        .err()
        .expect("expected refusal");
    assert!(error.to_string().contains("strict_sender_consumed"));
    let mut byte = [0u8; 128];
    assert_eq!(
        recipient
            .try_recv(&mut byte)
            .expect_err("expected refusal")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    foreign.send(b"spectator").await.unwrap();
    assert_eq!(foreign_peer.recv(&mut byte).await.unwrap(), 9);
    assert_eq!(&byte[..9], b"spectator");
}

#[tokio::test]
async fn actual_previous_write_gate_survives_native_custody_roundtrip() {
    let (input, application) = pair().await;
    let (output, recipient) = pair().await;
    let mut sender = Sender::new(input, output).unwrap();
    let s = settings();
    let origin = Instant::now();
    let end = origin + Duration::from_secs(2);
    application.send(b"first").await.unwrap();
    application.send(b"retained").await.unwrap();
    sender
        .gather(origin + Duration::from_millis(100), origin, &s, end, true)
        .await
        .unwrap();
    sender
        .gather(origin + Duration::from_millis(100), origin, &s, end, true)
        .await
        .unwrap();
    sender
        .block(Instant::now(), &[20_000_000], &s, 1, end)
        .await
        .unwrap();
    let actual_completed = sender.last_completed_write.unwrap();
    // The public target is the actual previous completion, not an invented
    // timestamp or a permissive overlapping service-contract admission.
    let error = sender
        .block(actual_completed, &[0], &s, 2, end)
        .await
        .err()
        .expect("expected refusal");
    assert!(error
        .to_string()
        .contains("public_point_prior_write_overlap"));
    assert_eq!(sender.observations.sent_packets, 1);
    assert_eq!(sender.observations.retained_packets, 1);
    assert!(
        sender
            .observations
            .prior_completed_write_reached_missed_target
    );
    assert!(sender.observations.release_thread_joined);
    assert!(sender.source.is_none() && sender.sink.is_none());
    let mut bytes = [0u8; 128];
    assert_eq!(recipient.recv(&mut bytes).await.unwrap(), 5);
    assert_eq!(
        recipient
            .try_recv(&mut bytes)
            .expect_err("expected refusal")
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn strict_failed_postwrite_keeps_known_send_prefix_and_never_reuses_sockets() {
    // A Windows timer can refuse before the write if an actual native wait
    // crosses the unchanged 10 ms cutoff. Such an attempt is a valid safety
    // refusal, but it cannot prove the post-write prefix under test. Retry
    // with fresh sockets only after proving that the failed attempt sent zero
    // packets and permanently consumed its own custody.
    let attempts = if cfg!(windows) { 8 } else { 1 };
    for attempt in 0..attempts {
        let (input, application) = pair().await;
        let (output, recipient) = pair().await;
        let mut sender = Sender::new(input, output).unwrap();
        let s = settings();
        let origin = Instant::now();
        let end = origin + Duration::from_secs(2);
        application.send(b"known write").await.unwrap();
        sender
            .gather(origin + Duration::from_millis(100), origin, &s, end, true)
            .await
            .unwrap();
        sender.completion_observation_delay = Some(Duration::from_millis(20));
        let error = sender
            .block(Instant::now(), &[20_000_000], &s, 1, end)
            .await
            .err()
            .expect("expected refusal");
        if cfg!(windows)
            && error
                .to_string()
                .contains("windows_timer_after_wait_cutoff")
        {
            assert_eq!(sender.observations.accepted_packets, 1);
            assert_eq!(sender.observations.sent_packets, 0);
            assert_eq!(sender.observations.retained_packets, 1);
            assert!(sender.observations.release_thread_joined);
            assert!(sender.source.is_none() && sender.sink.is_none());
            let mut bytes = [0u8; 128];
            assert_eq!(
                recipient
                    .try_recv(&mut bytes)
                    .expect_err("pre-write refusal cannot deliver")
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            assert!(sender
                .drain(&s, 2, end)
                .await
                .err()
                .expect("expected refusal")
                .to_string()
                .contains("strict_sender_consumed"));
            assert!(
                attempt + 1 < attempts,
                "no attempt reached the post-write path"
            );
            continue;
        }
        assert!(error.to_string().contains("packet_write_delivery_cutoff"));
        assert_eq!(sender.observations.accepted_packets, 1);
        assert_eq!(sender.observations.sent_packets, 1);
        assert_eq!(sender.observations.retained_packets, 0);
        assert!(sender.observations.release_thread_joined);
        assert!(sender.source.is_none() && sender.sink.is_none());
        let mut bytes = [0u8; 128];
        let n = recipient.recv(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..n], b"known write");
        assert!(sender
            .drain(&s, 2, end)
            .await
            .err()
            .expect("expected refusal")
            .to_string()
            .contains("strict_sender_consumed"));
        return;
    }
    unreachable!("the final attempt fails before continuing");
}

#[tokio::test]
async fn successful_strict_commands_keep_source_epoch_fifo_and_counters() {
    let (input, application) = pair().await;
    let (output, recipient) = pair().await;
    let mut sender = Sender::new(input, output).unwrap();
    let s = settings();
    let origin = Instant::now();
    let end = origin + Duration::from_secs(2);
    for bytes in [b"one".as_slice(), b"two".as_slice()] {
        application.send(bytes).await.unwrap();
    }
    sender
        .gather(origin + Duration::from_millis(100), origin, &s, end, true)
        .await
        .unwrap();
    sender
        .gather(origin + Duration::from_millis(100), origin, &s, end, true)
        .await
        .unwrap();
    let actual_origin = sender.origin.unwrap();
    sender
        .block(Instant::now(), &[20_000_000], &s, 1, end)
        .await
        .unwrap();
    let work = sender.observations.native_work_steps;
    sender
        .block(Instant::now(), &[20_000_000], &s, 2, end)
        .await
        .unwrap();
    assert_eq!(sender.origin, Some(actual_origin));
    assert_eq!(sender.observations.accepted_packets, 2);
    assert_eq!(sender.observations.sent_packets, 2);
    assert_eq!(sender.observations.retained_packets, 0);
    assert!(sender.observations.native_work_steps > work);
    let mut bytes = [0u8; 128];
    for expected in [b"one".as_slice(), b"two".as_slice()] {
        let n = recipient.recv(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..n], expected);
    }
}

#[tokio::test]
async fn invalid_command_validation_keeps_original_custody_and_starts_no_actor() {
    let (input, application) = pair().await;
    let (output, recipient) = pair().await;
    let mut sender = Sender::new(input, output).unwrap();
    let original_source = sender.source.as_ref().unwrap().local_addr().unwrap();
    let original_sink = sender.sink.as_ref().unwrap().local_addr().unwrap();
    application.send(b"not consumed").await.unwrap();
    sender.source.as_ref().unwrap().readable().await.unwrap();
    let mut invalid = settings();
    invalid.delta_pps = invalid.lambda_pps;
    let end = Instant::now() + Duration::from_secs(2);
    assert!(sender
        .block(Instant::now(), &[20_000_000], &invalid, 1, end)
        .await
        .is_err());
    assert_eq!(
        sender.source.as_ref().unwrap().local_addr().unwrap(),
        original_source
    );
    assert_eq!(
        sender.sink.as_ref().unwrap().local_addr().unwrap(),
        original_sink
    );
    assert!(!sender.observations.release_thread_started);
    assert!(!sender.observations.release_thread_terminal);
    assert!(!sender.observations.release_thread_joined);
    assert!(!sender.observations.strict_command_custody_consumed);
    assert!(!sender.observations.strict_command_buffers_discarded);
    assert_eq!(sender.observations.accepted_packets, 0);
    let mut bytes = [0u8; 128];
    let n = sender
        .source
        .as_ref()
        .unwrap()
        .try_recv(&mut bytes)
        .unwrap();
    assert_eq!(&bytes[..n], b"not consumed");
    assert_eq!(
        recipient
            .try_recv(&mut bytes)
            .expect_err("expected refusal")
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn saturated_preparation_refuses_before_spawn_and_discards_known_custody() {
    let (input, application) = pair().await;
    let (output, recipient) = pair().await;
    let mut sender = Sender::new(input, output).unwrap();
    let s = settings();
    let origin = Instant::now();
    let end = origin + Duration::from_secs(2);
    application.send(b"already sent").await.unwrap();
    application.send(b"known retained original").await.unwrap();
    sender
        .gather(origin + Duration::from_millis(100), origin, &s, end, true)
        .await
        .unwrap();
    sender
        .gather(origin + Duration::from_millis(100), origin, &s, end, true)
        .await
        .unwrap();
    sender
        .block(Instant::now(), &[20_000_000], &s, 1, end)
        .await
        .unwrap();
    assert!(sender.observations.release_thread_started);
    assert!(sender.observations.release_thread_joined);
    assert_eq!(sender.observations.accepted_packets, 2);
    assert_eq!(sender.observations.sent_packets, 1);
    assert_eq!(sender.observations.retained_packets, 1);
    // Seed the explicit public observation to its declared work limit. This
    // is a deterministic budget-boundary fault injection, not a measurement
    // claiming that this fixture actually executed four million operations.
    sender.observations.native_work_steps = MAX_WORK;
    let error = sender
        .block(Instant::now(), &[20_000_000], &s, 2, end)
        .await
        .err()
        .expect("expected refusal");
    assert!(error.to_string().contains("owned_preparation_budget"));
    assert!(!sender.observations.release_thread_started);
    assert!(!sender.observations.release_thread_terminal);
    assert!(!sender.observations.release_thread_joined);
    assert!(!sender.observations.release_cancel_requested);
    assert!(sender.observations.strict_command_custody_consumed);
    assert!(!sender.observations.strict_command_custody_restored);
    assert!(sender.observations.strict_command_preparation_failed);
    assert!(sender.observations.strict_command_buffers_discarded);
    assert_eq!(sender.observations.accepted_packets, 2);
    assert_eq!(sender.observations.sent_packets, 1);
    // Historical retained-count prefix, explicitly NOT recoverable buffers.
    assert_eq!(sender.observations.retained_packets, 1);
    assert_eq!(sender.observations.native_work_steps, MAX_WORK);
    assert!(sender.queue.is_empty());
    assert!(sender.source.is_none() && sender.sink.is_none());
    let mut bytes = [0u8; 128];
    let n = recipient.recv(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..n], b"already sent");
    assert_eq!(
        recipient
            .try_recv(&mut bytes)
            .expect_err("expected refusal")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(sender
        .drain(&s, 3, end)
        .await
        .err()
        .expect("expected refusal")
        .to_string()
        .contains("strict_sender_consumed"));
}

#[tokio::test]
async fn strict_to_schedule_total_work_refuses_before_new_actor_and_preserves_prefix() {
    let s = settings();
    let end = Instant::now() + Duration::from_secs(10);
    let prepared = Prepared::new(s.clone(), Zeroizing::new([3; 32]), end).unwrap();
    let words = prepared.encode(b"x").unwrap();
    let (input, application) = pair().await;
    let (output, recipient) = pair().await;
    let mut sender = Sender::new(input, output).unwrap();
    let origin = Instant::now();
    application.send(b"previous real write").await.unwrap();
    sender
        .gather(origin + Duration::from_millis(100), origin, &s, end, true)
        .await
        .unwrap();
    sender
        .block(Instant::now(), &[20_000_000], &s, 1, end)
        .await
        .unwrap();
    assert!(sender.observations.release_thread_joined);
    // Explicit boundary injection; do not present this as measured work.
    sender.observations.native_work_steps = MAX_WORK - prepared.preparation_work_steps() + 1;
    sender.observer.update(&sender.observations);
    let observer = sender.observer.clone();
    let before = serde_json::to_value(observer.snapshot()).unwrap();
    let error = OwnedSender::spawn_blocks(
        sender,
        &prepared,
        &words,
        Instant::now() + Duration::from_millis(500),
        end,
    )
    .err()
    .expect("cumulative work must refuse before a second actor");
    assert!(error.to_string().contains("owned_preparation_budget"));
    // Historical completed strict-command flags stay exactly historical;
    // no schedule actor was admitted or marked ready by this rejected call.
    assert_eq!(serde_json::to_value(observer.snapshot()).unwrap(), before);
    let mut bytes = [0u8; 128];
    let n = recipient.recv(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..n], b"previous real write");
    assert_eq!(
        recipient
            .try_recv(&mut bytes)
            .expect_err("no second write")
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn strict_to_schedule_ready_preserves_cumulative_work_and_resets_current_thread_flags() {
    let s = settings();
    let end = Instant::now() + Duration::from_secs(10);
    let prepared = Prepared::new(s.clone(), Zeroizing::new([3; 32]), end).unwrap();
    let words = prepared.encode(b"x").unwrap();
    let (input, application) = pair().await;
    let (output, _recipient) = pair().await;
    let mut sender = Sender::new(input, output).unwrap();
    let origin = Instant::now();
    application.send(b"first").await.unwrap();
    application.send(b"queued").await.unwrap();
    sender
        .gather(origin + Duration::from_millis(100), origin, &s, end, true)
        .await
        .unwrap();
    sender
        .gather(origin + Duration::from_millis(100), origin, &s, end, true)
        .await
        .unwrap();
    sender
        .block(Instant::now(), &[20_000_000], &s, 1, end)
        .await
        .unwrap();
    let prior_work = sender.observations.native_work_steps;
    let prior_preparation = sender.observations.preparation_work_steps;
    assert!(prior_work > prior_preparation);
    let copying: usize = words
        .iter()
        .enumerate()
        .map(|(block, &word)| prepared.book(block).unwrap()[word].len() * 2)
        .sum::<usize>()
        + sender.queue.len() * 2;
    let expected_work = prior_work + prepared.preparation_work_steps() + copying;
    let expected_preparation = prior_preparation + prepared.preparation_work_steps() + copying;
    let observer = sender.observer.clone();
    let mut owned = OwnedSender::spawn_blocks(
        sender,
        &prepared,
        &words,
        Instant::now() + Duration::from_millis(500),
        end,
    )
    .unwrap();
    owned.ready(end).await.unwrap();
    let snapshot = observer.snapshot();
    assert!(snapshot.native_work_steps >= expected_work);
    assert_eq!(snapshot.preparation_work_steps, expected_preparation);
    assert!(snapshot.release_thread_started);
    assert!(!snapshot.release_thread_terminal);
    assert!(!snapshot.release_thread_joined);
    assert_eq!(snapshot.sent_packets, 1);
    drop(owned);
    while !observer.snapshot().release_thread_terminal {
        assert!(Instant::now() < end);
        tokio::task::yield_now().await;
    }
    assert!(observer.snapshot().release_cancel_requested);
    assert!(!observer.snapshot().release_thread_joined);
    assert_eq!(observer.snapshot().sent_packets, 1);
}

#[tokio::test]
async fn empty_strict_drain_preserves_missing_source_epoch() {
    let (input, _application) = pair().await;
    let (output, _recipient) = pair().await;
    let mut sender = Sender::new(input, output).unwrap();
    let s = settings();
    let end = Instant::now() + Duration::from_secs(2);
    let result = sender.drain(&s, 1, end).await.unwrap();
    assert!(result.hashes.is_empty());
    assert_eq!(
        sender.origin, None,
        "no gather must not initialize the source epoch"
    );
    assert_eq!(sender.observations.native_source_reads_completed, 0);
    assert_eq!(sender.observations.accepted_packets, 0);
    assert_eq!(sender.observations.sent_packets, 0);
    assert!(sender.observations.release_thread_joined);
    assert!(sender.observations.strict_command_custody_restored);
}

#[tokio::test]
async fn already_ended_buffering_preserves_missing_epoch_and_unread_original() {
    let (input, application) = pair().await;
    let (output, _recipient) = pair().await;
    let mut sender = Sender::new(input, output).unwrap();
    let s = settings();
    let end = Instant::now() + Duration::from_secs(2);
    application.send(b"never gathered").await.unwrap();
    let past_start = Instant::now()
        .checked_sub(Duration::from_millis(u64::from(s.buffering_ms) + 1))
        .unwrap();
    let result = sender.buffering(past_start, &s, end).await.unwrap();
    assert!(result.hashes.is_empty());
    assert_eq!(sender.origin, None, "ended phase did not enter gather");
    assert_eq!(sender.observations.native_source_reads_completed, 0);
    assert_eq!(sender.observations.accepted_packets, 0);
    assert_eq!(sender.observations.sent_packets, 0);
    assert!(sender.observations.release_thread_joined);
    sender.source.as_ref().unwrap().readable().await.unwrap();
    let mut bytes = [0u8; 128];
    let n = sender
        .source
        .as_ref()
        .unwrap()
        .try_recv(&mut bytes)
        .unwrap();
    assert_eq!(&bytes[..n], b"never gathered");
}

#[tokio::test]
async fn genuine_first_source_after_noop_uses_its_original_first_block_epoch() {
    for ended_buffering in [false, true] {
        let (input, application) = pair().await;
        let (output, recipient) = pair().await;
        let mut sender = Sender::new(input, output).unwrap();
        let s = settings();
        let end = Instant::now() + Duration::from_secs(2);
        if ended_buffering {
            let past = Instant::now()
                .checked_sub(Duration::from_millis(u64::from(s.buffering_ms) + 1))
                .unwrap();
            sender.buffering(past, &s, end).await.unwrap();
        } else {
            sender.drain(&s, 1, end).await.unwrap();
        }
        assert_eq!(sender.origin, None);
        let original_first_block = Instant::now();
        application.send(b"genuine first source").await.unwrap();
        let result = sender
            .block(original_first_block, &[20_000_000], &s, 2, end)
            .await
            .unwrap();
        assert_eq!(sender.origin, Some(original_first_block));
        assert_eq!(result.hashes.len(), 1);
        assert_eq!(sender.observations.native_source_reads_completed, 1);
        assert_eq!(sender.observations.accepted_packets, 1);
        assert_eq!(sender.observations.sent_packets, 1);
        assert_eq!(sender.observations.retained_packets, 0);
        assert!(sender.observations.release_thread_joined);
        let mut bytes = [0u8; 128];
        let n = recipient.recv(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..n], b"genuine first source");
    }
}

#[cfg(windows)]
#[tokio::test]
async fn actual_empty_strict_drain_prepares_owned_windows_thread_before_noop() {
    let (input, _application) = pair().await;
    let (output, _recipient) = pair().await;
    let mut sender = Sender::new(input, output).unwrap();
    let s = settings();
    let end = Instant::now() + Duration::from_secs(2);
    // No application payload is sent. Empty Drain exercises execute_strict's
    // actual owned thread without any timed packet release or native wait.
    let result = sender.drain(&s, 1, end).await.unwrap();
    assert_eq!(result.ordinal, 1);
    assert!(result.hashes.is_empty());
    assert_eq!(sender.origin, None);
    assert_eq!(sender.observations.accepted_packets, 0);
    assert_eq!(sender.observations.sent_packets, 0);
    assert_eq!(sender.observations.retained_packets, 0);
    assert_eq!(sender.observations.native_recv_attempts, 0);
    assert_eq!(sender.observations.native_send_attempts, 0);
    assert!(sender.observations.release_thread_started);
    assert!(sender.observations.release_thread_terminal);
    assert!(sender.observations.release_thread_joined);
    assert!(sender.observations.strict_command_custody_restored);
    assert!(sender.source.is_some() && sender.sink.is_some());
    let preparation = sender
        .strict_thread_preparation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Actual initializer: six read/query APIs plus at most one setter. This
    // readback is requested priority, not effective priority or latency proof.
    assert!(matches!(preparation.native_api_attempts, 6 | 7));
    assert!(preparation.requested_priority_readback_present);
}
