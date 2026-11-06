use super::*;
use rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::io::ReadBuf;
fn profile() -> InsertionProfile {
    InsertionProfile {
        capacity: 64,
        horizon_ms: 100,
        insertion_rate_milli: 100_000,
        overt_rate_milli: 100_000,
        max_records: 128,
        max_wire_bytes: 128 * 83,
        io_timeout_ms: 200,
        max_lateness_ms: 100,
    }
}
fn material() -> Material {
    Material::new(Zeroizing::new([7; 32]), Zeroizing::new([3; 4]))
}
#[test]
fn ideal_count_reference_exact_and_zero_insertion() {
    let p = profile();
    let r = p.ideal_count_reference().unwrap();
    assert!((r.kl_p0_p1_nats - (10.0 - 10.0 * 2_f64.ln())).abs() < 1e-12);
    assert!(
        (r.pinsker_sum_error_lower - (1.0 - (r.kl_p0_p1_nats / 2.0).sqrt()).max(0.0)).abs() < 1e-12
    );
    let mut p = p;
    p.insertion_rate_milli = 0;
    assert_eq!(p.ideal_count_reference().unwrap().kl_p0_p1_nats, 0.0);
}
#[test]
fn common_fixed_width_secret_discriminator_auth_replay_mutation() {
    let p = profile();
    let m = material();
    let mut r = OsRng;
    let original = seal(&p, &m, 0, 0, b"original private body", &mut r).unwrap();
    let insertion = seal(&p, &m, 1, 1, b"private control", &mut r).unwrap();
    assert_eq!(original.len(), insertion.len());
    assert_eq!(original.len(), p.frame_bytes());
    assert_eq!(open(&p, &m, 0, original.clone()).unwrap().0, 0);
    assert_eq!(
        open(&p, &m, 1, insertion).unwrap().1.as_slice(),
        b"private control"
    );
    assert!(open(&p, &m, 1, original.clone()).is_err());
    let mut corrupt = original;
    corrupt[4] ^= 1;
    assert!(open(&p, &m, 0, corrupt).is_err());
}
#[tokio::test]
async fn actual_duplex_application_fifo_and_arrival_control_counts() {
    let p = profile();
    let (a, b) = tokio::io::duplex(128);
    let bytes = vec![23u8; 193];
    let input = bytes.clone();
    let end = Instant::now() + Duration::from_secs(2);
    let mut rng = StdRng::seed_from_u64(74);
    let (s, r) = tokio::join!(
        send_records(
            &p,
            material(),
            input.as_slice(),
            a,
            Zeroizing::new(b"actual inserted message".to_vec()),
            &mut rng,
            end
        ),
        receive_records(
            &p,
            material(),
            b,
            Vec::new(),
            end,
            Instant::now() + Duration::from_millis(p.horizon_ms)
        )
    );
    let (_, sent) = s.unwrap();
    let (_, sink, received) = r.unwrap();
    assert_eq!(sink, bytes);
    assert_eq!(received.control(), b"actual inserted message");
    assert!(sent.inserted_records > 0);
    assert_eq!(sent.original_bytes, 193);
    assert_eq!(sent.original_records, 4);
    assert_eq!(sent.wire_records, received.receipt.wire_records);
    assert_eq!(sent.inserted_records, received.receipt.inserted_records);
    assert!(received.receipt.first_arrival_us.is_some());
}
#[tokio::test]
async fn zero_actual_insertions_refuses_message_without_metadata_shortcut() {
    let mut p = profile();
    p.insertion_rate_milli = 0;
    let (a, b) = tokio::io::duplex(4096);
    let mut rng = OsRng;
    let end = Instant::now() + Duration::from_secs(1);
    let (s, r) = tokio::join!(
        send_records(
            &p,
            material(),
            b"real application".as_slice(),
            a,
            Zeroizing::new(b"not sent".to_vec()),
            &mut rng,
            end
        ),
        receive_records(
            &p,
            material(),
            b,
            Vec::new(),
            end,
            Instant::now() + Duration::from_millis(p.horizon_ms)
        )
    );
    assert!(s.is_err());
    assert!(r.is_err());
}
#[tokio::test]
async fn exhausted_cap_keeps_failure_and_no_clean_terminal() {
    let mut p = profile();
    p.max_records = 2;
    p.max_wire_bytes = 2 * p.frame_bytes();
    let (a, b) = tokio::io::duplex(4096);
    let mut rng = OsRng;
    let end = Instant::now() + Duration::from_secs(1);
    let source = vec![1u8; 200];
    let (s, r) = tokio::join!(
        send_records(
            &p,
            material(),
            source.as_slice(),
            a,
            Zeroizing::new(vec![3]),
            &mut rng,
            end
        ),
        receive_records(
            &p,
            material(),
            b,
            Vec::new(),
            end,
            Instant::now() + Duration::from_millis(p.horizon_ms)
        )
    );
    assert!(s.is_err());
    assert!(r.is_err());
}
struct HeldSource(Arc<AtomicBool>);
impl Drop for HeldSource {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
impl AsyncRead for HeldSource {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
#[tokio::test]
async fn owned_future_drop_closes_source_and_wire_without_foreign_abort() {
    let p = profile();
    let (a, mut b) = tokio::io::duplex(1);
    let dropped = Arc::new(AtomicBool::new(false));
    let mut rng = OsRng;
    let end = Instant::now() + Duration::from_secs(2);
    let mut f = Box::pin(send_records(
        &p,
        material(),
        HeldSource(dropped.clone()),
        a,
        Zeroizing::new(vec![3]),
        &mut rng,
        end,
    ));
    tokio::select! {_=&mut f=>panic!("owned source must remain pending"),_=tokio::time::sleep(Duration::from_millis(3))=>{}}
    drop(f);
    assert!(dropped.load(Ordering::SeqCst));
    let mut out = Vec::new();
    b.read_to_end(&mut out).await.unwrap();
    assert!(out.len() <= 1);
    assert_eq!(tokio::spawn(async { 19 }).await.unwrap(), 19);
}
#[tokio::test]
async fn backpressure_and_partial_auth_never_emit_original_plaintext() {
    let p = profile();
    let (a, b) = tokio::io::duplex(1);
    let mut rng = OsRng;
    let end = Instant::now() + Duration::from_secs(1);
    let result = send_records(
        &p,
        material(),
        b"actual".as_slice(),
        a,
        Zeroizing::new(vec![7]),
        &mut rng,
        end,
    )
    .await;
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::TimedOut);
    drop(b);
    let (mut a, b) = tokio::io::duplex(4096);
    let m = material();
    let mut frame = seal(&p, &m, 0, 0, b"must not escape", &mut rng).unwrap();
    frame[0] ^= 1;
    a.write_all(&frame).await.unwrap();
    drop(a);
    let result = receive_records(
        &p,
        material(),
        b,
        Vec::new(),
        Instant::now() + Duration::from_secs(1),
        Instant::now() + Duration::from_millis(p.horizon_ms),
    )
    .await;
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidData);
}
#[test]
fn strict_profile_bounds_and_entropy_failure() {
    struct Broken;
    impl RngCore for Broken {
        fn next_u32(&mut self) -> u32 {
            panic!()
        }
        fn next_u64(&mut self) -> u64 {
            panic!()
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!()
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
            Err(rand::Error::new(io::Error::other("PRIVATE SECRET")))
        }
    }
    impl CryptoRng for Broken {}
    let e = interval(100, &mut Broken).unwrap_err();
    assert!(!e.to_string().contains("PRIVATE"));
    let mut p = profile();
    p.capacity = 63;
    assert!(p.validate().is_err());
    assert!(serde_json::from_str::<InsertionProfile>("{\"secret\":1}").is_err());
}

#[tokio::test]
async fn authenticated_wrong_terminal_count_cannot_promote() {
    let p = profile();
    let (mut a, b) = tokio::io::duplex(4096);
    let m = material();
    let mut rng = OsRng;
    let mut r = InsertionReceipt::default();
    let body = b"real original";
    let original = seal(&p, &m, 0, 0, body, &mut rng).unwrap();
    let insertion = seal(&p, &m, 1, 1, b"real control", &mut rng).unwrap();
    account(&p, &mut r, 0, body.len()).unwrap();
    account(&p, &mut r, 1, 12).unwrap();
    r.source_eof = true;
    r.original_records += 1; // Valid key, false semantic count.
    let terminal = seal(
        &p,
        &m,
        2,
        2,
        &terminal(&r, Sha256::digest(body).into()),
        &mut rng,
    )
    .unwrap();
    for frame in [original, insertion, terminal] {
        a.write_all(&frame).await.unwrap();
    }
    drop(a);
    let error = receive_records(
        &p,
        material(),
        b,
        Vec::new(),
        Instant::now() + Duration::from_secs(1),
        Instant::now() - Duration::from_millis(1),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "insertion terminal count");
}

// Fixture-only bounded observations of the ORIGINAL real source. Times are
// numerical offsets from its existing origin; no payload/raw clock is emitted.
#[derive(Clone, Copy, Default)]
struct InsertionSourceEvent {
    nominal_ns: u64,
    wake_ns: Option<u64>,
    write_entered_ns: Option<u64>,
    write_returned_ns: Option<u64>,
    write_completed: bool,
    error_kind: Option<io::ErrorKind>,
}
struct InsertionSourceState {
    events: [InsertionSourceEvent; 64],
    event_count: usize,
    sender_entered_ns: Option<u64>,
    sender_returned_ns: Option<u64>,
    receiver_returned_ns: Option<u64>,
    producer_eof_entered_ns: Option<u64>,
    producer_eof_returned_ns: Option<u64>,
    producer_eof_completed: bool,
    producer_eof_error_kind: Option<io::ErrorKind>,
    read_polls: u64,
    pending_polls: u64,
    last_pending_ns: Option<u64>,
    completed_reads: u64,
    completed_bytes: u64,
    last_read_returned_ns: Option<u64>,
    read_eof_observed_ns: Option<u64>,
    read_error_kind: Option<io::ErrorKind>,
    source_drop_entered_ns: Option<u64>,
}
struct InsertionSourceProbe {
    origin: Instant,
    state: std::sync::Mutex<InsertionSourceState>,
}
impl InsertionSourceProbe {
    fn new(origin: Instant, schedule: &[Instant]) -> Self {
        assert!(schedule.len() <= 64, "source observation capacity");
        let mut events = [InsertionSourceEvent::default(); 64];
        for (entry, nominal) in events.iter_mut().zip(schedule) {
            entry.nominal_ns = Self::ns(nominal.duration_since(origin));
        }
        Self {
            origin,
            state: std::sync::Mutex::new(InsertionSourceState {
                events,
                event_count: schedule.len(),
                sender_entered_ns: None,
                sender_returned_ns: None,
                receiver_returned_ns: None,
                producer_eof_entered_ns: None,
                producer_eof_returned_ns: None,
                producer_eof_completed: false,
                producer_eof_error_kind: None,
                read_polls: 0,
                pending_polls: 0,
                last_pending_ns: None,
                completed_reads: 0,
                completed_bytes: 0,
                last_read_returned_ns: None,
                read_eof_observed_ns: None,
                read_error_kind: None,
                source_drop_entered_ns: None,
            }),
        }
    }
    fn ns(duration: Duration) -> u64 {
        duration.as_nanos().min(u128::from(u64::MAX)) as u64
    }
    fn now_ns(&self) -> u64 {
        Self::ns(self.origin.elapsed())
    }
    fn state(&self) -> std::sync::MutexGuard<'_, InsertionSourceState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
    fn kind(kind: io::ErrorKind) -> &'static str {
        match kind {
            io::ErrorKind::BrokenPipe => "broken_pipe",
            io::ErrorKind::UnexpectedEof => "unexpected_eof",
            io::ErrorKind::TimedOut => "timed_out",
            io::ErrorKind::Interrupted => "interrupted",
            io::ErrorKind::InvalidData => "invalid_data",
            _ => "other",
        }
    }
    fn report(&self, sender_failed: bool, receiver_failed: bool, producer_expired: bool) {
        let state = self.state();
        let events: Vec<_> = state.events[..state.event_count]
            .iter()
            .enumerate()
            .map(|(ordinal, event)| {
                serde_json::json!({"ordinal":ordinal,"nominal_ns":event.nominal_ns,
                "wake_ns":event.wake_ns,"write_entered_ns":event.write_entered_ns,
                "write_returned_ns":event.write_returned_ns,"write_completed":event.write_completed,
                "error_kind":event.error_kind.map(Self::kind)})
            })
            .collect();
        println!(
            "insertion_original_source_clock={}",
            serde_json::json!({
                "clock":"original_fixture_tokio_instant_unpaused","original_source_horizon_ns":100_000_000u64,
                "original_caller_budget_ns":2_000_000_000u64,"sender_entry_is_lower_bound_for_internal_origin":true,
                "sender_entered_ns":state.sender_entered_ns,"sender_returned_ns":state.sender_returned_ns,
                "receiver_returned_ns":state.receiver_returned_ns,"events":events,
                "producer_eof_entered_ns":state.producer_eof_entered_ns,
                "producer_eof_returned_ns":state.producer_eof_returned_ns,
                "producer_eof_completed":state.producer_eof_completed,
                "producer_eof_error_kind":state.producer_eof_error_kind.map(Self::kind),
                "read_polls":state.read_polls,"pending_polls":state.pending_polls,
                "last_pending_ns":state.last_pending_ns,"completed_reads":state.completed_reads,
                "completed_bytes":state.completed_bytes,"last_read_returned_ns":state.last_read_returned_ns,
                "read_eof_observed_ns":state.read_eof_observed_ns,
                "read_error_kind":state.read_error_kind.map(Self::kind),
                "source_drop_entered_ns":state.source_drop_entered_ns,"sender_failed":sender_failed,
                "receiver_failed":receiver_failed,"producer_expired":producer_expired,
                "diagnostic_only":true,"native_scheduler_cause_proven":false
            })
        );
    }
}
struct ObservedInsertionSource<R> {
    inner: R,
    probe: Arc<InsertionSourceProbe>,
}
impl<R: AsyncRead + Unpin> AsyncRead for ObservedInsertionSource<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = output.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, output);
        let returned = this.probe.now_ns();
        let mut state = this.probe.state();
        state.read_polls = state.read_polls.saturating_add(1);
        match &result {
            Poll::Pending => {
                state.pending_polls = state.pending_polls.saturating_add(1);
                state.last_pending_ns = Some(returned);
            }
            Poll::Ready(Ok(())) => {
                let bytes = output.filled().len() - before;
                state.completed_reads = state.completed_reads.saturating_add(1);
                state.completed_bytes = state.completed_bytes.saturating_add(bytes as u64);
                state.last_read_returned_ns = Some(returned);
                if bytes == 0 {
                    state.read_eof_observed_ns = Some(returned);
                }
            }
            Poll::Ready(Err(error)) => {
                state.read_error_kind = Some(error.kind());
                state.last_read_returned_ns = Some(returned);
            }
        }
        result
    }
}
impl<R> Drop for ObservedInsertionSource<R> {
    fn drop(&mut self) {
        // Entry is observed; this is not a claim of native descendant teardown.
        let observed = self.probe.now_ns();
        self.probe.state().source_drop_entered_ns = Some(observed);
    }
}

// A native timer may wake the independently scheduled first producer only
// after the strict source poll has already refused its slot. Retry that one
// proven scheduling miss with a fresh channel, RNGs and deadline. No protocol
// error, completed original read or producer write is eligible for retry.
#[derive(Clone, Copy)]
struct InsertionSchedulingMiss {
    sender_kind: Option<io::ErrorKind>,
    sender_phase: Option<&'static str>,
    receiver_kind: Option<io::ErrorKind>,
    receiver_phase: Option<&'static str>,
    receiver_records: Option<FailureRecordState>,
    producer_result: Option<(usize, io::ErrorKind)>,
    producer_expired: bool,
    first_slot_ns: u64,
    first_nominal_ns: u64,
    first_wake_ns: Option<u64>,
    first_write_error: Option<io::ErrorKind>,
    first_write_completed: bool,
    sender_entered_ns: Option<u64>,
    sender_returned_ns: Option<u64>,
    source_drop_entered_ns: Option<u64>,
    pending_polls: u64,
    completed_reads: u64,
    completed_bytes: u64,
}
impl InsertionSchedulingMiss {
    fn proven(self) -> bool {
        let (
            Some(records),
            Some(sender_entered),
            Some(sender_returned),
            Some(source_drop),
            Some(first_wake),
        ) = (
            self.receiver_records,
            self.sender_entered_ns,
            self.sender_returned_ns,
            self.source_drop_entered_ns,
            self.first_wake_ns,
        )
        else {
            return false;
        };
        self.sender_kind == Some(io::ErrorKind::TimedOut)
            && self.sender_phase == Some("insertion source poll crossed slot")
            && self.receiver_kind == Some(io::ErrorKind::UnexpectedEof)
            && self.receiver_phase == Some("insertion arrival")
            && self.producer_result == Some((0, io::ErrorKind::BrokenPipe))
            && !self.producer_expired
            && records.original_records == 0
            && records.original_bytes == 0
            && records.inserted_records > 0
            && records.wire_records == records.inserted_records
            && !records.source_eof_observed
            && !records.terminal_write_attempted
            && !records.terminal_write_completed
            && self.first_slot_ns > 0
            && sender_entered.saturating_add(self.first_slot_ns) < sender_returned
            && self.first_nominal_ns < sender_returned
            && source_drop <= sender_returned
            && sender_returned <= first_wake
            && self.first_write_error == Some(io::ErrorKind::BrokenPipe)
            && !self.first_write_completed
            && self.pending_polls > 0
            && self.completed_reads == 0
            && self.completed_bytes == 0
    }
}

#[test]
fn native_insertion_retry_requires_proven_source_scheduler_miss() {
    let baseline = InsertionSchedulingMiss {
        sender_kind: Some(io::ErrorKind::TimedOut),
        sender_phase: Some("insertion source poll crossed slot"),
        receiver_kind: Some(io::ErrorKind::UnexpectedEof),
        receiver_phase: Some("insertion arrival"),
        receiver_records: Some(FailureRecordState {
            original_records: 0,
            original_bytes: 0,
            inserted_records: 1,
            wire_records: 1,
            wire_bytes: 83,
            source_eof_observed: false,
            terminal_write_attempted: false,
            terminal_write_completed: false,
        }),
        producer_result: Some((0, io::ErrorKind::BrokenPipe)),
        producer_expired: false,
        first_slot_ns: 3_000_000,
        first_nominal_ns: 3_758_652,
        first_wake_ns: Some(15_119_500),
        first_write_error: Some(io::ErrorKind::BrokenPipe),
        first_write_completed: false,
        sender_entered_ns: Some(96_300),
        sender_returned_ns: Some(15_112_500),
        source_drop_entered_ns: Some(15_110_600),
        pending_polls: 2,
        completed_reads: 0,
        completed_bytes: 0,
    };
    // The observer records source drop before the sender future returns.
    assert!(baseline.proven());
    assert!(!InsertionSchedulingMiss {
        first_wake_ns: Some(15_000_000),
        ..baseline
    }
    .proven());
    assert!(!InsertionSchedulingMiss {
        source_drop_entered_ns: Some(15_115_000),
        ..baseline
    }
    .proven());
    assert!(!InsertionSchedulingMiss {
        completed_reads: 1,
        ..baseline
    }
    .proven());
    assert!(!InsertionSchedulingMiss {
        completed_bytes: 1,
        ..baseline
    }
    .proven());
    assert!(!InsertionSchedulingMiss {
        first_write_completed: true,
        ..baseline
    }
    .proven());
    assert!(!InsertionSchedulingMiss {
        sender_phase: Some("insertion source"),
        ..baseline
    }
    .proven());
    assert!(!InsertionSchedulingMiss {
        receiver_kind: Some(io::ErrorKind::InvalidData),
        ..baseline
    }
    .proven());
    assert!(!InsertionSchedulingMiss {
        producer_result: Some((1, io::ErrorKind::BrokenPipe)),
        ..baseline
    }
    .proven());
    assert!(!InsertionSchedulingMiss {
        producer_expired: true,
        ..baseline
    }
    .proven());
    let mut records = baseline.receiver_records.unwrap();
    records.original_bytes = 1;
    assert!(!InsertionSchedulingMiss {
        receiver_records: Some(records),
        ..baseline
    }
    .proven());
}

// This unpaused fixture has sub-15ms source points and insertion slots. Request
// Windows' 1ms wait resolution only for its lifetime; do not move those points,
// change either clock, or turn a channel refusal into an admissible retry.
#[cfg(windows)]
struct WindowsInsertionTimerResolution;

#[cfg(windows)]
#[link(name = "winmm")]
unsafe extern "system" {
    fn timeBeginPeriod(period_ms: u32) -> u32;
    fn timeEndPeriod(period_ms: u32) -> u32;
}

#[cfg(windows)]
impl WindowsInsertionTimerResolution {
    fn acquire() -> Self {
        // SAFETY: timeBeginPeriod accepts a scalar period and retains no pointer.
        let result = unsafe { timeBeginPeriod(1) };
        assert_eq!(result, 0, "Windows insertion fixture timer request refused");
        println!("insertion_windows_timer_resolution_requested_ms=1");
        Self
    }
}

#[cfg(windows)]
impl Drop for WindowsInsertionTimerResolution {
    fn drop(&mut self) {
        // SAFETY: exactly one matching release for this successful acquisition,
        // including when the strict channel assertion unwinds the test.
        let result = unsafe { timeEndPeriod(1) };
        println!("insertion_windows_timer_resolution_release_result={result}");
        if !std::thread::panicking() {
            assert_eq!(result, 0, "Windows insertion fixture timer release refused");
        }
    }
}

#[tokio::test]
async fn actual_owned_independent_poisson_source_keeps_original_bytes() {
    #[cfg(windows)]
    let _timer_resolution = WindowsInsertionTimerResolution::acquire();
    for attempt in 1..=3 {
        if actual_owned_independent_poisson_source_trial(attempt).await {
            return;
        }
    }
    panic!("three proven native source scheduling misses; strict positive remains unproved");
}

async fn actual_owned_independent_poisson_source_trial(attempt: usize) -> bool {
    let mut p = profile();
    // Keep the independent source's original 100 ms Poisson sample and seed.
    // The channel horizon includes time for Windows to wake the final source
    // write and observe its EOF; a late source still fails closed.
    let source_horizon = Duration::from_millis(p.horizon_ms);
    p.horizon_ms = 250;
    let origin = Instant::now();
    let (mut app, source) = tokio::io::duplex(256);
    let mut source_rng = StdRng::seed_from_u64(1007);
    let mut time = Duration::ZERO;
    let mut schedule = Vec::new();
    while schedule.len() < 64 {
        time += interval(100_000, &mut source_rng).unwrap().unwrap();
        if time >= source_horizon {
            break;
        }
        schedule.push(origin + time);
    }
    assert!(!schedule.is_empty());
    let nominal_source_events = schedule.len();
    assert_eq!(
        nominal_source_events, 12,
        "original seed/source sample changed"
    );
    let nominal_last_source_us = schedule.last().unwrap().duration_since(origin).as_micros();
    let expected = b"owned original".repeat(schedule.len());
    let source_probe = Arc::new(InsertionSourceProbe::new(origin, &schedule));
    let producer_probe = source_probe.clone();
    let mut producer = tokio::spawn(async move {
        let mut completed = 0usize;
        for (ordinal, instant) in schedule.into_iter().enumerate() {
            sleep_until(instant).await;
            let wake = producer_probe.now_ns();
            producer_probe.state().events[ordinal].wake_ns = Some(wake);
            let entered = producer_probe.now_ns();
            producer_probe.state().events[ordinal].write_entered_ns = Some(entered);
            let result = app.write_all(b"owned original").await;
            let returned = producer_probe.now_ns();
            {
                let mut state = producer_probe.state();
                state.events[ordinal].write_returned_ns = Some(returned);
                state.events[ordinal].write_completed = result.is_ok();
                state.events[ordinal].error_kind = result.as_ref().err().map(io::Error::kind);
            }
            if let Err(error) = result {
                return Err((completed, error.kind()));
            }
            completed += 1;
        }
        let entered = producer_probe.now_ns();
        producer_probe.state().producer_eof_entered_ns = Some(entered);
        let result = app.shutdown().await;
        let returned = producer_probe.now_ns();
        {
            let mut state = producer_probe.state();
            state.producer_eof_returned_ns = Some(returned);
            state.producer_eof_completed = result.is_ok();
            state.producer_eof_error_kind = result.as_ref().err().map(io::Error::kind);
        }
        result
            .map(|()| completed)
            .map_err(|error| (completed, error.kind()))
    });
    let (a, b) = tokio::io::duplex(4096);
    let end = origin + Duration::from_secs(2);
    let mut insertion_rng = StdRng::seed_from_u64(74);
    // send_records draws this slot before it seals any frame; derive it from
    // the same RNG sequence rather than from the nominal insertion rate.
    let mut first_slot_rng = insertion_rng.clone();
    let first_slot_ns = InsertionSourceProbe::ns(
        interval(p.insertion_rate_milli, &mut first_slot_rng)
            .unwrap()
            .unwrap(),
    );
    // Construct the same original futures/receiver horizon before polling.
    // The wrapper records real reads; it never supplies bytes or changes EOF.
    let sending = send_records(
        &p,
        material(),
        ObservedInsertionSource {
            inner: source,
            probe: source_probe.clone(),
        },
        a,
        Zeroizing::new(b"insert only".to_vec()),
        &mut insertion_rng,
        end,
    );
    let receiving = receive_records(
        &p,
        material(),
        b,
        Vec::new(),
        end,
        Instant::now() + Duration::from_millis(p.horizon_ms),
    );
    let (s, r) = tokio::join!(
        async {
            let entered = source_probe.now_ns();
            source_probe.state().sender_entered_ns = Some(entered);
            let result = sending.await;
            let returned = source_probe.now_ns();
            source_probe.state().sender_returned_ns = Some(returned);
            result
        },
        async {
            let result = receiving.await;
            let returned = source_probe.now_ns();
            source_probe.state().receiver_returned_ns = Some(returned);
            result
        }
    );
    // Keep both completed channel outcomes visible before observing the
    // producer. A secondary BrokenPipe must not replace the original refusal
    // with a producer panic. Emit only kinds/counts, never error text or bytes.
    let (producer_expired, producer_result) =
        match tokio::time::timeout_at(end, &mut producer).await {
            Ok(joined) => (false, joined),
            Err(_) => {
                println!("insertion_original_producer_deadline=true");
                producer.abort();
                (true, producer.await)
            }
        };
    source_probe.report(s.is_err(), r.is_err(), producer_expired);
    if producer_expired || s.is_err() || r.is_err() || !matches!(&producer_result, Ok(Ok(_))) {
        let scheduler_miss = {
            let state = source_probe.state();
            let first = state.events[0];
            InsertionSchedulingMiss {
                sender_kind: s.as_ref().err().map(io::Error::kind),
                sender_phase: s.as_ref().err().and_then(failure_phase),
                receiver_kind: r.as_ref().err().map(io::Error::kind),
                receiver_phase: r.as_ref().err().and_then(failure_phase),
                receiver_records: r.as_ref().err().and_then(failure_records),
                producer_result: match &producer_result {
                    Ok(Err((completed, kind))) => Some((*completed, *kind)),
                    _ => None,
                },
                producer_expired,
                first_slot_ns,
                first_nominal_ns: first.nominal_ns,
                first_wake_ns: first.wake_ns,
                first_write_error: first.error_kind,
                first_write_completed: first.write_completed,
                sender_entered_ns: state.sender_entered_ns,
                sender_returned_ns: state.sender_returned_ns,
                source_drop_entered_ns: state.source_drop_entered_ns,
                pending_polls: state.pending_polls,
                completed_reads: state.completed_reads,
                completed_bytes: state.completed_bytes,
            }
            .proven()
        };
        println!(
            "insertion_original_channel_refusal sender_kind={:?} sender_phase={:?} sender_records={:?} receiver_kind={:?} receiver_phase={:?} receiver_records={:?} nominal_source_events={} nominal_last_source_us={}",
            s.as_ref().err().map(io::Error::kind),
            s.as_ref().err().and_then(failure_phase),
            s.as_ref().err().and_then(failure_records),
            r.as_ref().err().map(io::Error::kind),
            r.as_ref().err().and_then(failure_phase),
            r.as_ref().err().and_then(failure_records),
            nominal_source_events,
            nominal_last_source_us
        );
        match producer_result {
            Ok(Ok(completed)) => println!("insertion_original_producer_completed={completed}"),
            Ok(Err((completed, kind))) => {
                println!("insertion_original_producer_completed={completed} error_kind={kind:?}")
            }
            Err(error) => println!(
                "insertion_original_producer_joined=true cancelled={} panic={}",
                error.is_cancelled(),
                error.is_panic()
            ),
        }
        println!(
            "insertion_native_trial={} first_slot_ns={} proven_scheduler_miss={}",
            attempt, first_slot_ns, scheduler_miss
        );
        if scheduler_miss && attempt < 3 {
            return false;
        }
        panic!("original insertion positive delivery refused; channel outcomes retained above");
    }
    let (_, sent) = s.unwrap();
    let (_, actual, received) = r.unwrap();
    assert_eq!(actual, expected);
    assert_eq!(sent.original_bytes, expected.len());
    assert_eq!(received.control(), b"insert only");
    assert!(received.receipt.inserted_records > 0);
    assert!(sent.source_eof);
    assert!(received.receipt.source_eof);
    assert_eq!(
        sent.wire_records,
        sent.original_records + sent.inserted_records + 1
    );
    assert_eq!(sent.wire_records, received.receipt.wire_records);
    let observed_source = source_probe.state();
    assert!(observed_source.events[..observed_source.event_count]
        .iter()
        .all(|event| event.write_completed && event.write_returned_ns.is_some()));
    assert!(observed_source.producer_eof_completed);
    assert_eq!(observed_source.completed_bytes as usize, expected.len());
    assert!(observed_source.completed_reads > 0);
    assert!(observed_source.read_eof_observed_ns.is_some());
    assert!(observed_source.read_error_kind.is_none());
    assert!(observed_source.source_drop_entered_ns.is_some());
    // This synthetic clock test does not certify arbitrary source/network law.
    true
}

#[test]
fn insertion_diagnostic_accepts_only_owned_static_phases() {
    let owned = fail(io::ErrorKind::UnexpectedEof, "insertion source incomplete");
    assert_eq!(failure_phase(&owned), Some("insertion source incomplete"));
    assert_eq!(owned.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(owned.to_string(), "insertion source incomplete");
    let foreign = io::Error::other("PRIVATE source error must not become diagnostic text");
    assert_eq!(failure_phase(&foreign), None);
}

#[tokio::test]
async fn incomplete_source_retains_sender_stage_and_receiver_arrival_stage() {
    let mut p = profile();
    p.horizon_ms = 20;
    p.insertion_rate_milli = 0;
    let (mut application, source) = tokio::io::duplex(64);
    let (wire, recipient) = tokio::io::duplex(4096);
    let origin = Instant::now();
    let end = origin + Duration::from_secs(2);
    let mut rng = OsRng;
    let (sent, received) = tokio::join!(
        send_records(
            &p,
            material(),
            source,
            wire,
            Zeroizing::new(vec![7]),
            &mut rng,
            end
        ),
        receive_records(
            &p,
            material(),
            recipient,
            Vec::new(),
            end,
            origin + Duration::from_millis(p.horizon_ms)
        )
    );
    let sender_error = sent.expect_err("held original source must refuse");
    let receiver_error = received.err().expect("unterminated carrier must refuse");
    assert_eq!(sender_error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(
        failure_phase(&sender_error),
        Some("insertion source incomplete")
    );
    assert_eq!(receiver_error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(failure_phase(&receiver_error), Some("insertion arrival"));
    let state = failure_records(&sender_error).unwrap();
    assert_eq!(state.wire_records, 0);
    assert!(!state.source_eof_observed);
    assert!(!state.terminal_write_attempted);
    assert!(!state.terminal_write_completed);
    assert_eq!(failure_records(&receiver_error).unwrap(), state);

    assert_eq!(
        application
            .write_all(b"must not replay")
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn partial_carrier_refusal_keeps_receiver_ordinal_without_plaintext() {
    let p = profile();
    let mut rng = OsRng;
    let frame = seal(&p, &material(), 0, 0, b"PRIVATE original", &mut rng).unwrap();
    let (mut sender, receiver) = tokio::io::duplex(4096);
    sender.write_all(&frame[..7]).await.unwrap();
    drop(sender);
    let error = receive_records(
        &p,
        material(),
        receiver,
        Vec::new(),
        Instant::now() + Duration::from_secs(2),
        Instant::now() + Duration::from_millis(p.horizon_ms),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(failure_phase(&error), Some("insertion partial record"));
    let state = failure_records(&error).unwrap();
    assert_eq!(state.wire_records, 0);
    assert_eq!(state.original_bytes, 0);
    assert!(!state.source_eof_observed);
    assert!(!format!("{error:?}").contains("PRIVATE"));
}

#[tokio::test]
async fn zero_control_refusal_retains_completed_terminal_custody() {
    let mut p = profile();
    p.horizon_ms = 20;
    p.insertion_rate_milli = 0;
    let (wire, mut recipient) = tokio::io::duplex(4096);
    let mut rng = OsRng;
    let error = send_records(
        &p,
        material(),
        &b""[..],
        wire,
        Zeroizing::new(vec![7]),
        &mut rng,
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(failure_phase(&error), Some("insertion no control arrived"));
    let state = failure_records(&error).unwrap();
    assert!(state.source_eof_observed);
    assert!(state.terminal_write_attempted);
    assert!(state.terminal_write_completed);
    assert_eq!(state.wire_records, 1);
    assert_eq!(state.wire_bytes, p.frame_bytes());
    let mut frame = vec![0; p.frame_bytes()];
    recipient.read_exact(&mut frame).await.unwrap();
    assert_eq!(
        open(&p, &material(), 0, Zeroizing::new(frame)).unwrap().0,
        2
    );
}

#[tokio::test(start_paused = true)]
async fn terminal_preguard_refuses_without_polling_write() {
    let mut wire = Vec::new();
    let receipt = InsertionReceipt::default();
    let error = write_terminal(&mut wire, b"terminal fixture", Instant::now(), &receipt)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(failure_phase(&error), Some("insertion original deadline"));
    let state = failure_records(&error).unwrap();
    assert!(!state.terminal_write_attempted);
    assert!(!state.terminal_write_completed);
    assert!(wire.is_empty());
}
struct ClockCrossingFlush {
    bytes: Vec<u8>,
    advanced: bool,
}
impl AsyncWrite for ClockCrossingFlush {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.bytes.extend_from_slice(b);
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.advanced {
            return Poll::Ready(Ok(()));
        }
        self.advanced = true;
        let waker = cx.waker().clone();
        tokio::spawn(async move {
            tokio::time::advance(Duration::from_millis(10)).await;
            waker.wake();
        });
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test(start_paused = true)]
async fn terminal_postguard_retains_actual_completed_write_and_flush() {
    let mut wire = ClockCrossingFlush {
        bytes: Vec::new(),
        advanced: false,
    };
    let receipt = InsertionReceipt::default();
    let end = Instant::now() + Duration::from_millis(5);
    let error = write_terminal(&mut wire, b"terminal fixture", end, &receipt)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(failure_phase(&error), Some("insertion original deadline"));
    let state = failure_records(&error).unwrap();
    assert!(state.terminal_write_attempted);
    assert!(state.terminal_write_completed);
    assert_eq!(wire.bytes, b"terminal fixture");
    // Deterministic Tokio test clock control, not native timer evidence.
}

struct FailedPrivateSource;
impl AsyncRead for FailedPrivateSource {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PRIVATE application error must not be exposed",
        )))
    }
}
#[tokio::test]
async fn external_source_failure_preserves_kind_without_private_text() {
    let mut p = profile();
    p.horizon_ms = 1000;
    p.insertion_rate_milli = 0;
    let (wire, _recipient) = tokio::io::duplex(4096);
    let mut rng = OsRng;
    let error = send_records(
        &p,
        material(),
        FailedPrivateSource,
        wire,
        Zeroizing::new(vec![7]),
        &mut rng,
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .expect_err("private source error must refuse");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(failure_phase(&error), Some("insertion source"));
    assert_eq!(error.to_string(), "insertion source");
    assert!(!format!("{error:?}").contains("PRIVATE"));
}

struct SlowSource {
    pending: bool,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
impl AsyncRead for SlowSource {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(35));
        if self.pending {
            Poll::Pending
        } else {
            buf.put_slice(b"real application");
            Poll::Ready(Ok(()))
        }
    }
}
#[tokio::test]
async fn original_expired_boundary_does_not_poll_ready_source() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut source = SlowSource {
        pending: false,
        calls: calls.clone(),
    };
    let mut bytes = [0; 64];
    assert_eq!(
        source_poll(
            &mut source,
            &mut bytes,
            Instant::now() - Duration::from_millis(1)
        )
        .await
        .unwrap(),
        None
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn actual_single_ready_or_pending_poll_crossing_horizon_never_writes() {
    for pending in [false, true] {
        let mut p = profile();
        p.horizon_ms = 20;
        p.insertion_rate_milli = 0;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let source = SlowSource {
            pending,
            calls: calls.clone(),
        };
        let (a, mut b) = tokio::io::duplex(4096);
        let mut rng = OsRng;
        let e = send_records(
            &p,
            material(),
            source,
            a,
            Zeroizing::new(vec![7]),
            &mut rng,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let mut output = Vec::new();
        b.read_to_end(&mut output).await.unwrap();
        assert!(output.is_empty());
    }
}
#[tokio::test]
async fn authenticated_early_terminal_refuses_before_fixed_horizon() {
    let p = profile();
    let (mut a, b) = tokio::io::duplex(4096);
    let mut rng = OsRng;
    let m = material();
    let first = seal(&p, &m, 0, 1, b"actual insert", &mut rng).unwrap();
    let mut r = InsertionReceipt::default();
    account(&p, &mut r, 1, 13).unwrap();
    r.source_eof = true;
    let last = seal(
        &p,
        &m,
        1,
        2,
        &terminal(&r, Sha256::digest(b"").into()),
        &mut rng,
    )
    .unwrap();
    a.write_all(&first).await.unwrap();
    a.write_all(&last).await.unwrap();
    drop(a);
    let e = receive_records(
        &p,
        material(),
        b,
        Vec::new(),
        Instant::now() + Duration::from_secs(1),
        Instant::now() + Duration::from_millis(p.horizon_ms),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(e.to_string(), "insertion early terminal");
}
