//! Directly owned, nonblocking UDP release thread. Ordinary Darwin requested
//! QoS only on dedicated threads; no realtime/effective-priority guarantee. Public points/books/bounds remain unchanged.
use super::*;
use std::{net::UdpSocket as NativeSocket, sync::atomic::AtomicUsize, thread};
static RELEASES: AtomicUsize = AtomicUsize::new(0);
const MAX_RELEASES: usize = 16;
#[cfg(any(not(any(target_os = "macos", windows)), test))]
fn park_duration(remaining: Duration) -> Option<Duration> {
    if remaining > Duration::from_millis(2) {
        Some((remaining - Duration::from_millis(2)).min(Duration::from_millis(1)))
    } else {
        // A relative park may return after the original point. Use only the
        // fine-wait strategy inside this guard, with unchanged work charges.
        // OS preemption can still cause a strict refusal; this is not realtime.
        None
    }
}
#[cfg(any(not(any(target_os = "macos", windows)), test))]
fn fine_sleep_duration(remaining: Duration) -> Option<Duration> {
    // Avoid a hot yield/poll loop for dense schedules. This is a bounded
    // requested sleep, not an OS wake-time guarantee or a shifted deadline.
    // Keep only the last 20us for active observation of the original point.
    if remaining > Duration::from_micros(20) && remaining <= Duration::from_millis(2) {
        Some((remaining - Duration::from_micros(20)).min(Duration::from_micros(50)))
    } else {
        None
    }
}
struct Admission;
impl Admission {
    fn acquire() -> io::Result<Self> {
        RELEASES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_RELEASES).then_some(n + 1)
            })
            .map_err(|_| refused("owned_release_capacity"))?;
        Ok(Self)
    }
}
impl Drop for Admission {
    fn drop(&mut self) {
        RELEASES.fetch_sub(1, Ordering::AcqRel);
    }
}
struct Queued {
    packet: Packet,
    digest: [u8; 32],
}
pub struct OwnedScheduleReceipt {
    pub checkpoints: Vec<Checkpoint>,
    pub observations: Observations,
}
/// Dropping requests cancellation/unparks only this owned thread. It does not
/// pretend that the thread has already terminated or been joined.
pub struct OwnedSender {
    cancel: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    ready: Option<oneshot::Receiver<()>>,
    result: Option<oneshot::Receiver<io::Result<Vec<Checkpoint>>>>,
    observer: Observer,
}
impl Drop for OwnedSender {
    fn drop(&mut self) {
        if let Some(handle) = &self.thread {
            self.cancel.store(true, Ordering::Release);
            self.observer.edit(|s| s.release_cancel_requested = true);
            handle.thread().unpark();
        }
    }
}
impl OwnedSender {
    pub fn spawn_blocks(
        sender: Sender,
        prepared: &Prepared,
        words: &[usize],
        start: Instant,
        end: Instant,
    ) -> io::Result<Self> {
        Self::spawn(
            sender,
            prepared,
            words,
            start,
            end,
            false,
            #[cfg(test)]
            false,
        )
    }
    pub fn spawn_timing(
        sender: Sender,
        prepared: &Prepared,
        words: &[usize],
        start: Instant,
        end: Instant,
    ) -> io::Result<Self> {
        Self::spawn(
            sender,
            prepared,
            words,
            start,
            end,
            true,
            #[cfg(test)]
            false,
        )
    }
    // Per-actor test fault: exercise the real owned thread's preparation guard.
    // No global setting, wire/native success override or production API.
    #[cfg(test)]
    pub(crate) fn spawn_timing_cancelled_at_start(
        sender: Sender,
        prepared: &Prepared,
        words: &[usize],
        start: Instant,
        end: Instant,
    ) -> io::Result<Self> {
        Self::spawn(sender, prepared, words, start, end, true, true)
    }
    fn spawn(
        mut sender: Sender,
        prepared: &Prepared,
        words: &[usize],
        start: Instant,
        end: Instant,
        buffer: bool,
        #[cfg(test)] startup_cancel: bool,
    ) -> io::Result<Self> {
        live(end)?;
        let settings = prepared.settings().clone();
        settings.validate()?;
        if words.len() != settings.blocks() {
            return Err(refused("owned_schedule_size"));
        }
        let mut work = sender
            .observations
            .native_work_steps
            .checked_add(prepared.preparation_work_steps())
            .filter(|&n| n <= MAX_WORK)
            .ok_or_else(|| refused("owned_preparation_budget"))?;
        let mut preparation_work = sender
            .observations
            .preparation_work_steps
            .checked_add(prepared.preparation_work_steps())
            .filter(|&n| n <= MAX_WORK)
            .ok_or_else(|| refused("owned_preparation_budget"))?;
        let mut schedule = Zeroizing::new(Vec::with_capacity(words.len()));
        for (block, &word) in words.iter().enumerate() {
            live(end)?;
            let points = prepared
                .book(block)?
                .get(word)
                .ok_or_else(|| refused("owned_word_range"))?;
            let mut copied = Zeroizing::new(Vec::with_capacity(points.len()));
            for &point in points {
                live(end)?;
                if work + 2 > MAX_WORK {
                    return Err(refused("owned_preparation_budget"));
                }
                work += 2;
                preparation_work = preparation_work
                    .checked_add(2)
                    .filter(|&n| n <= MAX_WORK)
                    .ok_or_else(|| refused("owned_preparation_budget"))?;
                copied.push(point);
            }
            schedule.push(std::mem::take(&mut *copied));
        }
        let expected_end = start
            .checked_add(if buffer {
                settings.horizon()
            } else {
                Duration::from_millis(settings.blocks() as u64 * u64::from(settings.block_ms))
            })
            .and_then(|t| t.checked_add(Duration::from_millis(u64::from(settings.drain_ms))))
            .ok_or_else(|| refused("owned_schedule_clock"))?;
        if expected_end >= end {
            return Err(refused("owned_schedule_runway"));
        }
        let admission = Admission::acquire()?;
        let observer = sender.observer.clone();
        observer.update(&sender.observations);
        let mut queue = VecDeque::with_capacity(sender.queue.len());
        for packet in std::mem::take(&mut sender.queue) {
            live(end)?;
            if work + 2 > MAX_WORK {
                return Err(refused("owned_preparation_budget"));
            }
            work += 2;
            preparation_work = preparation_work
                .checked_add(2)
                .filter(|&n| n <= MAX_WORK)
                .ok_or_else(|| refused("owned_preparation_budget"))?;
            queue.push_back(Queued {
                digest: Sha256::digest(&packet.bytes).into(),
                packet,
            });
        }
        let source = sender
            .source
            .take()
            .ok_or_else(|| refused("strict_sender_consumed"))?
            .into_std()?;
        let sink = sender
            .sink
            .take()
            .ok_or_else(|| refused("strict_sender_consumed"))?
            .into_std()?;
        source.set_nonblocking(true)?;
        sink.set_nonblocking(true)?;
        let cancel = Arc::new(AtomicBool::new(false));
        #[cfg(test)]
        cancel.store(startup_cancel, Ordering::Release);
        let (ready_tx, ready) = oneshot::channel();
        let (result_tx, result) = oneshot::channel();
        let owned_observer = observer.clone();
        let signal = cancel.clone();
        let mut initial_stats = sender.observations;
        initial_stats.native_work_steps = work;
        initial_stats.preparation_work_steps = preparation_work;
        initial_stats.release_thread_started = false;
        initial_stats.release_thread_terminal = false;
        initial_stats.release_thread_joined = false;
        initial_stats.release_cancel_requested = false;
        #[cfg(test)]
        if startup_cancel {
            initial_stats.release_cancel_requested = true;
        }
        initial_stats.service_queue_contract_v2 = true;
        observer.update(&initial_stats);
        let mut worker = Worker {
            #[cfg(target_os = "macos")]
            native_wait: None,
            #[cfg(windows)]
            windows_wait: None,
            source,
            sink,
            queue,
            settings,
            schedule,
            start: start.into_std(),
            origin: sender.origin.unwrap_or(start).into_std(),
            end: end.into_std(),
            buffer,
            last: sender.last_completed_write.map(Instant::into_std),
            stats: initial_stats,
            #[cfg(target_os = "macos")]
            diagnostics: WaitDiagnostics::default(),
            #[cfg(all(test, windows))]
            windows_diagnostics: WindowsWaitDiagnostics::default(),
            #[cfg(all(test, target_os = "macos"))]
            diagnostic_publish_entered: None,
            observer: owned_observer.clone(),
            cancel: signal,
            buffer_bytes: Zeroizing::new(Vec::new()),
            pending: VecDeque::new(),
            next_event: 0,
            checkpoints: Vec::new(),
            #[cfg(test)]
            completion_delay: sender.completion_observation_delay,
        };
        worker
            .buffer_bytes
            .resize(usize::from(worker.settings.packet_bytes) + 1, 0);
        live(end)?;
        let handle = thread::Builder::new()
            .name("aegis-poisson-release".into())
            .spawn(move || {
                let _admission = admission;
                owned_observer.edit(|s| s.release_thread_started = true);
                let output = match worker.prepare_owned_thread() {
                    Ok(()) => {
                        if ready_tx.send(()).is_err() {
                            Err(refused("owned_ready_abandoned"))
                        } else {
                            worker.run()
                        }
                    }
                    Err(error) => Err(error),
                };
                worker.publish();
                #[cfg(all(test, target_os = "macos"))]
                worker.print_wait_diagnostics(output.is_err());
                #[cfg(all(test, windows))]
                worker.print_windows_wait_diagnostics(output.is_err());
                drop(worker);
                owned_observer.edit(|s| s.release_thread_terminal = true);
                let _ = result_tx.send(output);
            })?;
        Ok(Self {
            cancel,
            thread: Some(handle),
            ready: Some(ready),
            result: Some(result),
            observer,
        })
    }
    pub async fn ready(&mut self, end: Instant) -> io::Result<()> {
        live(end)?;
        let ready = self
            .ready
            .take()
            .ok_or_else(|| refused("owned_ready_consumed"))?;
        tokio::time::timeout_at(end, ready)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, Phase("owned_ready_clock")))?
            .map_err(|_| refused("owned_ready_terminal"))?;
        live(end)
    }
    pub async fn finish(mut self, end: Instant) -> io::Result<OwnedScheduleReceipt> {
        live(end)?;
        let result = self
            .result
            .take()
            .ok_or_else(|| refused("owned_result_consumed"))?;
        let output = tokio::time::timeout_at(end, result)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, Phase("owned_result_clock")))?
            .map_err(|_| refused("owned_release_panicked"))?;
        while !self
            .thread
            .as_ref()
            .ok_or_else(|| refused("owned_thread_missing"))?
            .is_finished()
        {
            live(end)?;
            tokio::task::yield_now().await;
        }
        let handle = self
            .thread
            .take()
            .ok_or_else(|| refused("owned_thread_missing"))?;
        handle
            .join()
            .map_err(|_| refused("owned_release_panicked"))?;
        self.observer.edit(|s| s.release_thread_joined = true);
        live(end)?;
        Ok(OwnedScheduleReceipt {
            checkpoints: output?,
            observations: self.observer.snapshot(),
        })
    }
}
#[cfg(target_os = "macos")]
#[derive(Default)]
struct WaitDiagnostics {
    requested_qos: Option<owned_qos::Observation>,
    mach_policy_readback_matched: bool,
    #[cfg(test)]
    qos_api_attempts: u64,
    #[cfg(test)]
    wait_attempts: u64,
    #[cfg(test)]
    waits_observed: u64,
    #[cfg(test)]
    partial_waits: u64,
    #[cfg(test)]
    maximum_call_interval_ns: u64,
    #[cfg(test)]
    maximum_wake_overshoot_ns: u64,
    #[cfg(test)]
    maximum_publish_interval_ns: u64,
    #[cfg(test)]
    publications_observed: u64,
    #[cfg(test)]
    publication_conflicts: u64,
    last_wait: Option<native_wait::WaitObservation>,
    last_wait_io: (usize, usize),
    last_gather: Option<(std::time::Instant, std::time::Instant, (usize, usize))>,
    #[cfg(test)]
    first_miss: Option<serde_json::Value>,
}
#[cfg(target_os = "macos")]
fn diagnostic_ns(later: std::time::Instant, earlier: std::time::Instant) -> u64 {
    later
        .saturating_duration_since(earlier)
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX)
}
#[cfg(all(test, windows))]
#[derive(Default)]
struct WindowsWaitDiagnostics {
    requested_priority: Option<owned_windows_priority::Observation>,
    priority_api_attempts: u64,
    attempts: u64,
    entered: u64,
    returned: u64,
    last_wait: Option<native_wait::WindowsWaitObservation>,
    last_io: (usize, usize),
    first_miss: Option<serde_json::Value>,
}
struct Worker {
    #[cfg(target_os = "macos")]
    native_wait: Option<native_wait::DarwinAbsoluteWait>,
    #[cfg(windows)]
    windows_wait: Option<native_wait::WindowsHighResolutionWait>,
    source: NativeSocket,
    sink: NativeSocket,
    queue: VecDeque<Queued>,
    settings: Settings,
    schedule: Zeroizing<Vec<Vec<u64>>>,
    start: std::time::Instant,
    origin: std::time::Instant,
    end: std::time::Instant,
    buffer: bool,
    last: Option<std::time::Instant>,
    stats: Observations,
    #[cfg(target_os = "macos")]
    diagnostics: WaitDiagnostics,
    #[cfg(all(test, windows))]
    windows_diagnostics: WindowsWaitDiagnostics,
    #[cfg(all(test, target_os = "macos"))]
    diagnostic_publish_entered: Option<std::sync::mpsc::SyncSender<()>>,
    observer: Observer,
    cancel: Arc<AtomicBool>,
    buffer_bytes: Zeroizing<Vec<u8>>,
    pending: VecDeque<Service>,
    next_event: usize,
    checkpoints: Vec<Checkpoint>,
    #[cfg(test)]
    completion_delay: Option<Duration>,
}
struct Service {
    queued: Queued,
    nominal: std::time::Instant,
    admitted: std::time::Instant,
    ordinal: u16,
    event: usize,
}
// Pure same-event arithmetic after refusal. No new clock read or work charge.
fn service_cutoff_observation(
    service: &Service,
    started: std::time::Instant,
    completed: std::time::Instant,
    allowance: Duration,
) -> Option<ServiceCutoffObservation> {
    let ns = |later: std::time::Instant, earlier: std::time::Instant| {
        u64::try_from(later.checked_duration_since(earlier)?.as_nanos()).ok()
    };
    let admission_lateness_ns = ns(service.admitted, service.nominal)?;
    let pending_wait_ns = ns(started, service.admitted)?;
    let write_observation_bracket_ns = ns(completed, started)?;
    let completion_lateness_ns = ns(completed, service.nominal)?;
    let original_allowance_ns = u64::try_from(allowance.as_nanos()).ok()?;
    let sum = admission_lateness_ns
        .checked_add(pending_wait_ns)?
        .checked_add(write_observation_bracket_ns)?;
    if sum != completion_lateness_ns || completion_lateness_ns <= original_allowance_ns {
        return None;
    }
    Some(ServiceCutoffObservation {
        event_ordinal: u64::try_from(service.event).ok()?,
        admission_lateness_ns,
        pending_wait_ns,
        write_observation_bracket_ns,
        completion_lateness_ns,
        original_allowance_ns,
    })
}

impl Worker {
    fn replace_stats(old: &mut Observations, mut stats: Observations) {
        // Preserve concurrently published cancellation/terminal facts under
        // the same lock as the statistics replacement; no snapshot/update gap.
        stats.release_thread_started = old.release_thread_started;
        stats.release_thread_terminal = old.release_thread_terminal;
        stats.release_thread_joined = old.release_thread_joined;
        stats.release_cancel_requested = old.release_cancel_requested;
        *old = stats;
    }
    fn publish(&self) {
        let stats = self.stats.clone();
        self.observer.edit(|old| Self::replace_stats(old, stats));
    }
    fn publish_progress(&self) -> bool {
        let stats = self.stats.clone();
        self.observer
            .try_edit(|old| Self::replace_stats(old, stats))
    }
    // Failure in charge uses the ORIGINAL unmeasured publish. Never reserve
    // clocks while holding the observer mutex; no recursive measurement path.
    fn publish_measured(&mut self) -> io::Result<()> {
        #[cfg(all(test, target_os = "macos"))]
        {
            self.charge(0)?;
            self.charge(0)?;
            let entered = std::time::Instant::now();
            if let Some(signal) = self.diagnostic_publish_entered.take() {
                signal
                    .try_send(())
                    .map_err(|_| refused("diagnostic_publish_signal"))?;
            }
            let published = self.publish_progress();
            let returned = std::time::Instant::now();
            if published {
                self.diagnostics.publications_observed += 1;
            } else {
                self.diagnostics.publication_conflicts += 1;
            }
            self.diagnostics.maximum_publish_interval_ns = self
                .diagnostics
                .maximum_publish_interval_ns
                .max(diagnostic_ns(returned, entered));
        }
        #[cfg(not(all(test, target_os = "macos")))]
        self.publish_progress();
        Ok(())
    }
    #[cfg(all(test, target_os = "macos"))]
    fn print_wait_diagnostics(&self, failed: bool) {
        if failed {
            let d = &self.diagnostics;
            // Owned numerical metadata only: no original timestamps, payload,
            // schedule, secret, address or raw native clock is serialized.
            eprintln!(
                "owned_darwin_wait_diagnostics={}",
                serde_json::json!({
                    "wait_attempts": d.wait_attempts,
                "waits_observed": d.waits_observed,
                    "partial_waits": d.partial_waits,
                    "maximum_call_interval_ns": d.maximum_call_interval_ns,
                    "maximum_wake_overshoot_ns": d.maximum_wake_overshoot_ns,
                    "publications_observed": d.publications_observed,
                    "publication_conflicts": d.publication_conflicts,
                    "maximum_publish_interval_ns": d.maximum_publish_interval_ns,
                    "first_miss": d.first_miss,
                    "requested_qos": d.requested_qos,
                    "qos_api_attempts": d.qos_api_attempts,
                    "effective_qos_verified": false,
                    "kernel_only_latency_proven": false,
                    "measurement_clocks_use_original_budget": true,
                })
            );
        }
    }
    #[cfg(target_os = "macos")]
    fn record_admission_diagnostics(
        &mut self,
        target: std::time::Instant,
        ordinal: u16,
        event: usize,
        observed: std::time::Instant,
    ) {
        if self.stats.darwin_admission_miss.is_some()
            || observed
                <= target + Duration::from_micros(u64::from(self.settings.release_lateness_us))
        {
            return;
        }
        let d = &mut self.diagnostics;
        let wait = d.last_wait;
        let io_unchanged = d.last_wait_io
            == (
                self.stats.native_recv_attempts,
                self.stats.native_send_attempts,
            );
        let point_matches = wait.is_some_and(|w| w.point == target);
        let gather = d.last_gather;
        // idle can wait for a pending service cutoff, not this admission point.
        // Retain that mismatch explicitly; never infer causal ownership.
        {
            let allowance_ns = u64::from(self.settings.release_lateness_us) * 1_000;
            let observed_lateness_ns = diagnostic_ns(observed, target);
            self.stats.darwin_admission_miss = Some(DarwinAdmissionMissObservation {
                event_ordinal: event.try_into().unwrap_or(u64::MAX),
                block_ordinal: ordinal,
                original_allowance_ns: allowance_ns,
                observed_lateness_ns,
                cutoff_excess_ns: observed_lateness_ns.saturating_sub(allowance_ns),
                qos_requested_class: d.requested_qos.map(|q| q.requested_class),
                qos_readback_matched: d.requested_qos.is_some(),
                mach_policy_readback_matched: d.mach_policy_readback_matched,
                last_wait_present: wait.is_some(),
                last_wait_point_matches_admission: point_matches,
                no_intervening_io_attempt: io_unchanged,
                gather_point_matches_admission: gather.is_some_and(|(p, _, _)| p == target),
                last_wait_coarse: wait.map(|w| w.coarse),
                last_wait_call_interval_ns: wait
                    .and_then(|w| w.returned.map(|r| diagnostic_ns(r, w.entered))),
                last_wait_wake_overshoot_ns: wait
                    .and_then(|w| w.returned.map(|r| diagnostic_ns(r, w.wake))),
                last_wait_return_to_gather_ns: wait
                    .and_then(|w| w.returned)
                    .zip(gather)
                    .map(|(r, (_, g, _))| diagnostic_ns(g, r)),
                gather_to_admission_ns: gather.map(|(_, g, _)| diagnostic_ns(observed, g)),
                last_wait_return_to_admission_ns: wait
                    .and_then(|w| w.returned.map(|r| diagnostic_ns(observed, r))),
            });
        }
        #[cfg(test)]
        {
            d.first_miss = Some(serde_json::json!({
                "block_ordinal": ordinal, "event_ordinal": event,
                "requested_qos": d.requested_qos,
                        "qos_api_attempts": d.qos_api_attempts,
                "effective_qos_verified": false,
                "observed_admission_lateness_ns": diagnostic_ns(observed, target),
                "last_wait_present": wait.is_some(),
                "last_wait_point_matches_admission": point_matches,
                "no_intervening_io_attempt": io_unchanged,
                "direct_wait_attribution_admitted": point_matches && io_unchanged,
                "last_wait_coarse": wait.map(|w| w.coarse),
                "last_wait_status": wait.and_then(|w| w.status),
                "last_wait_backend": wait.map(|w| w.backend),
                "last_wait_status_semantics": "kevent64_event_count_or_minus_one",
                "last_wait_requested_ns": wait.map(|w| diagnostic_ns(w.wake, w.entered)),
                "last_wait_request_already_expired": wait.map(|w| w.entered >= w.wake),
                "last_wait_call_interval_ns": wait.and_then(|w| w.returned.map(|r| diagnostic_ns(r, w.entered))),
                "last_wait_wake_overshoot_ns": wait.and_then(|w| w.returned.map(|r| diagnostic_ns(r, w.wake))),
                "last_wait_return_to_admission_ns": wait.and_then(|w| w.returned.map(|r| diagnostic_ns(observed, r))),
                "gather_point_matches_admission": gather.is_some_and(|(p, _, _)| p == target),
                "gather_io_matches_wait_return": gather.is_some_and(|(_, _, io)| io == d.last_wait_io),
                "last_wait_return_to_gather_ns": wait.and_then(|w| w.returned).zip(gather)
                    .map(|(r, (_, g, _))| diagnostic_ns(g, r)),
                "gather_to_admission_ns": gather.map(|(_, g, _)| diagnostic_ns(observed, g)),
                "maximum_publish_interval_before_admission_ns": d.maximum_publish_interval_ns,
            }));
        }
    }
    #[cfg(all(test, windows))]
    fn print_windows_wait_diagnostics(&self, failed: bool) {
        if failed {
            let d = &self.windows_diagnostics;
            eprintln!(
                "owned_windows_wait_diagnostics={}",
                serde_json::json!({
                    "requested_priority": d.requested_priority,
                    "priority_api_attempts": d.priority_api_attempts,
                    "effective_priority_verified": false,
                    "attempts": d.attempts, "native_entered": d.entered,
                    "native_returned": d.returned,
                    "last_wait": d.last_wait.map(|w| w.metadata()),
                    "first_miss": d.first_miss,
                    "measurement_clocks_use_original_budget": true,
                    "native_only_latency_cause_proven": false,
                })
            );
        }
    }
    #[cfg(all(test, windows))]
    fn record_windows_admission_diagnostics(
        &mut self,
        target: std::time::Instant,
        ordinal: u16,
        event: usize,
        observed: std::time::Instant,
    ) {
        let d = &mut self.windows_diagnostics;
        if d.first_miss.is_some()
            || observed
                <= target + Duration::from_micros(u64::from(self.settings.release_lateness_us))
        {
            return;
        }
        let same_io = d.last_io
            == (
                self.stats.native_recv_attempts,
                self.stats.native_send_attempts,
            );
        let same_point = d.last_wait.is_some_and(|w| w.point == target);
        d.first_miss = Some(serde_json::json!({
            "block_ordinal": ordinal, "event_ordinal": event,
            "observed_admission_lateness_ns": observed.saturating_duration_since(target)
                .as_nanos().min(u128::from(u64::MAX)) as u64,
            "last_wait": d.last_wait.map(|w| w.metadata()),
            "last_wait_point_matches_admission": same_point,
            "no_intervening_io_attempt": same_io,
            "ownership_premises_match": same_point && same_io,
            "native_only_latency_cause_proven": false,
        }));
    }
    fn charge(&mut self, kind: u8) -> io::Result<()> {
        if self.stats.native_work_steps >= MAX_WORK
            || (kind == 0
                && self.stats.precision_polls >= self.settings.precision_poll_budget as usize)
        {
            self.publish();
            return Err(refused("owned_work_budget"));
        }
        self.stats.native_work_steps += 1;
        match kind {
            0 => {
                self.stats.native_clock_polls += 1;
                self.stats.precision_polls += 1;
            }
            1 => self.stats.native_recv_attempts += 1,
            2 => self.stats.native_send_attempts += 1,
            3 => self.stats.native_park_calls += 1,
            4 => self.stats.native_spin_steps += 1,
            6 => self.stats.native_fine_sleep_calls += 1,
            7 => self.stats.native_absolute_coarse_wait_calls += 1,
            8 => self.stats.native_absolute_fine_wait_calls += 1,
            _ => {}
        }
        Ok(())
    }
    fn now(&mut self) -> io::Result<std::time::Instant> {
        self.charge(0)?;
        Ok(std::time::Instant::now())
    }
    fn ensure_now(&mut self) -> io::Result<std::time::Instant> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                Phase("owned_release_cancelled"),
            ));
        }
        let now = self.now()?;
        if now >= self.end {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                Phase("owned_release_original_clock"),
            ));
        }
        Ok(now)
    }
    fn ensure(&mut self) -> io::Result<()> {
        self.ensure_now().map(|_| ())
    }
    // Called only inside a newly spawned dedicated native thread before work.
    fn prepare_owned_thread(&mut self) -> io::Result<()> {
        self.ensure()?;
        #[cfg(target_os = "linux")]
        {
            owned_linux_timer::initialize(&mut || {
                self.charge(5)?;
                self.ensure()
            })?;
            self.ensure()?;
        }
        #[cfg(windows)]
        {
            let observed = owned_windows_priority::initialize(&mut |boundary| {
                if matches!(boundary, owned_windows_priority::Boundary::BeforeNative) {
                    self.charge(5)?;
                }
                self.ensure()?;
                #[cfg(test)]
                if matches!(boundary, owned_windows_priority::Boundary::BeforeNative) {
                    self.windows_diagnostics.priority_api_attempts += 1;
                }
                Ok(())
            })?;
            #[cfg(test)]
            {
                self.windows_diagnostics.requested_priority = Some(observed);
            }
            #[cfg(not(test))]
            let _ = observed;
            self.ensure()?;
        }
        #[cfg(target_os = "macos")]
        {
            let observed = owned_qos::initialize(&mut |boundary| {
                if matches!(boundary, owned_qos::Boundary::BeforeNative) {
                    self.charge(5)?;
                }
                self.ensure()?;
                #[cfg(test)]
                if matches!(boundary, owned_qos::Boundary::BeforeNative) {
                    self.diagnostics.qos_api_attempts += 1;
                }
                Ok(())
            })?;
            #[cfg(target_os = "macos")]
            {
                self.diagnostics.requested_qos = Some(observed);
            }
            #[cfg(not(test))]
            let _ = observed;
            self.ensure()?;
            // The owned release thread requests the same bounded Mach policy
            // validated by the opt-in diagnostic. A rejected policy refuses
            // startup; it never relaxes an original release deadline.
            owned_qos::initialize_time_constraint(&mut |boundary| {
                if matches!(boundary, owned_qos::Boundary::BeforeNative) {
                    self.charge(5)?;
                }
                self.ensure()
            })?;
            #[cfg(target_os = "macos")]
            {
                self.diagnostics.mach_policy_readback_matched = true;
            }
            self.ensure()?;
        }
        Ok(())
    }
    fn idle(&mut self, point: std::time::Instant) -> io::Result<()> {
        self.idle_with(point, Self::wait_owned)
    }
    // Production supplies the owned native wait. Tests can observe its exact
    // arguments without depending on a host wake-time outcome.
    fn idle_with(
        &mut self,
        point: std::time::Instant,
        wait: impl FnOnce(&mut Self, std::time::Instant, Option<std::time::Instant>) -> io::Result<()>,
    ) -> io::Result<()> {
        let latest_return = self
            .pending
            .front()
            .map(|pending| {
                pending
                    .nominal
                    .checked_add(Duration::from_micros(u64::from(
                        self.settings.release_lateness_us,
                    )))
                    .ok_or_else(|| refused("owned_schedule_clock"))
            })
            .transpose()?;
        if let Some(limit) = latest_return {
            self.pending_idle_live(limit)?;
        }
        let result = wait(self, point, latest_return);
        let after = latest_return.map_or(Ok(()), |limit| self.pending_idle_live(limit));
        // Preserve the first native refusal while still observing the same
        // original pending-service cutoff after the wait.
        result?;
        after
    }
    fn pending_idle_live(&mut self, latest_return: std::time::Instant) -> io::Result<()> {
        if self.ensure_now()? > latest_return {
            Err(refused("service_original_delivery_cutoff"))
        } else {
            Ok(())
        }
    }
    fn wait_owned(
        &mut self,
        point: std::time::Instant,
        latest_return: Option<std::time::Instant>,
    ) -> io::Result<()> {
        #[cfg(not(windows))]
        let _ = latest_return;
        #[cfg(target_os = "macos")]
        {
            self.absolute_wait(point)
        }
        #[cfg(windows)]
        {
            self.windows_high_resolution_wait_bound(point, latest_return)
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            let now = self.now()?;
            if now >= point {
                return Ok(());
            }
            let remaining = point.duration_since(now);
            if let Some(duration) = park_duration(remaining) {
                self.charge(3)?;
                thread::park_timeout(duration);
            } else if let Some(duration) = fine_sleep_duration(remaining) {
                self.fine_sleep_once(duration)?;
            } else {
                self.charge(4)?;
                std::hint::spin_loop();
            }
            Ok(())
        }
    }
    #[cfg(all(windows, test))]
    fn windows_high_resolution_wait(&mut self, point: std::time::Instant) -> io::Result<()> {
        self.windows_high_resolution_wait_bound(point, None)
    }
    #[cfg(windows)]
    fn windows_high_resolution_wait_bound(
        &mut self,
        point: std::time::Instant,
        latest_return: Option<std::time::Instant>,
    ) -> io::Result<()> {
        use native_wait::{WindowsCharge, WindowsHighResolutionWait};
        let charge = |worker: &mut Self, kind| match kind {
            WindowsCharge::ClockRead => worker.charge(0),
            // Explicit create/rearm/wait each consumes existing aggregate work.
            // These are not parks, Mach absolute calls, or new wire counters.
            WindowsCharge::TimerCreate | WindowsCharge::TimerArm | WindowsCharge::TimerWait => {
                worker.charge(5)
            }
        };
        #[cfg(test)]
        {
            // Every attempt invalidates previous point attribution even when
            // this attempt expires/returns ActiveTail without a native call.
            self.windows_diagnostics.attempts += 1;
            self.windows_diagnostics.last_wait = None;
            self.windows_diagnostics.last_io = (
                self.stats.native_recv_attempts,
                self.stats.native_send_attempts,
            );
        }
        self.ensure()?;
        let mut waiter = match self.windows_wait.take() {
            Some(waiter) => waiter,
            None => WindowsHighResolutionWait::new(|kind| charge(self, kind))?,
        };
        self.ensure()?; // creation cannot extend the original clock
        let end = self.end;
        let allowance = Duration::from_micros(u64::from(self.settings.release_lateness_us));
        let result = waiter.wait_bounded(point, end, allowance, latest_return, |kind| {
            charge(self, kind)
        });
        #[cfg(test)]
        if let Some(mut w) = waiter.last_observation {
            // Capture the actual returned refusal kind before the original
            // post-wait ensure. No native error text or first-error override.
            w.refusal_kind = result.as_ref().err().map(io::Error::kind);
            self.windows_diagnostics.entered += u64::from(w.entered.is_some());
            self.windows_diagnostics.returned += u64::from(w.returned.is_some());
            self.windows_diagnostics.last_wait = Some(w);
        }
        // Observe cancellation/end even on native refusal; preserve first error.
        // The non-clone owned handle drops on refusal and restores only on Ok.
        let after = self.ensure();
        let outcome = result?;
        after?;
        self.windows_wait = Some(waiter);
        if outcome == native_wait::Outcome::ActiveTail {
            self.charge(4)?;
            std::hint::spin_loop();
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    fn absolute_wait(&mut self, point: std::time::Instant) -> io::Result<()> {
        self.absolute_wait_with(point, Self::absolute_wait_native)
    }
    #[cfg(target_os = "macos")]
    fn absolute_wait_with(
        &mut self,
        point: std::time::Instant,
        native: impl FnOnce(&mut Self, std::time::Instant) -> io::Result<()>,
    ) -> io::Result<()> {
        // Reuse the original charged guard's observation for this decision.
        // No second clock, deadline or allowance is created.
        let observed = self.ensure_now()?;
        self.absolute_wait_observed(point, observed, native)
    }
    #[cfg(target_os = "macos")]
    fn absolute_wait_observed(
        &mut self,
        point: std::time::Instant,
        observed: std::time::Instant,
        native: impl FnOnce(&mut Self, std::time::Instant) -> io::Result<()>,
    ) -> io::Result<()> {
        if native_wait::darwin_active_tail(observed, point) {
            #[cfg(target_os = "macos")]
            {
                #[cfg(test)]
                {
                    self.diagnostics.wait_attempts += 1;
                }
                self.diagnostics.last_wait = None;
                self.diagnostics.last_gather = None;
                self.diagnostics.last_wait_io = (
                    self.stats.native_recv_attempts,
                    self.stats.native_send_attempts,
                );
            }
            // One original charged active step, followed by the existing
            // outer gather clock/I/O/cancellation/end/service guards.
            self.charge(4)?;
            std::hint::spin_loop();
            return Ok(());
        }
        native(self, point)
    }
    #[cfg(target_os = "macos")]
    fn absolute_wait_native(&mut self, point: std::time::Instant) -> io::Result<()> {
        use native_wait::{Charge, DarwinAbsoluteWait};
        let charge = |worker: &mut Self, kind| {
            match kind {
                Charge::InstantClockRead | Charge::MachClockRead => worker.charge(0),
                Charge::TimebaseRead | Charge::TimerCreate => worker.charge(5),
                Charge::AbsoluteCoarseWait => worker.charge(7),
                Charge::AbsoluteFineWait => worker.charge(8),
            }?;
            // Original cancellation/end check and its charged clock immediately
            // before each native operation. No reset or new allowance.
            worker.ensure()
        };
        let mut waiter = match self.native_wait.take() {
            Some(waiter) => waiter,
            None => DarwinAbsoluteWait::new(|kind| charge(self, kind))?,
        };
        self.ensure()?; // Creation cannot extend the original session clock.
        #[cfg(target_os = "macos")]
        {
            // Each attempt gets fresh attribution, even an expired/active-tail
            // point with no kernel call. This deliberately discards earlier
            // attribution for ALL attempts, including any changed purpose.
            // Aggregate real-call observations remain untouched.
            #[cfg(test)]
            {
                self.diagnostics.wait_attempts += 1;
            }
            self.diagnostics.last_wait = None;
            self.diagnostics.last_gather = None;
            self.diagnostics.last_wait_io = (
                self.stats.native_recv_attempts,
                self.stats.native_send_attempts,
            );
        }
        let result = waiter.wait_owned_bounded(point, |kind| charge(self, kind));
        #[cfg(target_os = "macos")]
        if let Some(w) = waiter.last_observation {
            #[cfg(test)]
            {
                self.diagnostics.waits_observed += 1;
                if let Some(returned) = w.returned {
                    self.diagnostics.maximum_call_interval_ns = self
                        .diagnostics
                        .maximum_call_interval_ns
                        .max(diagnostic_ns(returned, w.entered));
                    self.diagnostics.maximum_wake_overshoot_ns = self
                        .diagnostics
                        .maximum_wake_overshoot_ns
                        .max(diagnostic_ns(returned, w.wake));
                } else {
                    self.diagnostics.partial_waits += 1;
                }
            }
            self.diagnostics.last_wait = Some(w);
            self.diagnostics.last_wait_io = (
                self.stats.native_recv_attempts,
                self.stats.native_send_attempts,
            );
        }
        let after = self.ensure();
        let outcome = result?;
        after?;
        self.native_wait = Some(waiter);
        if outcome == native_wait::Outcome::ActiveTail {
            self.charge(4)?;
            std::hint::spin_loop();
        }
        Ok(())
    }
    #[cfg(any(not(any(target_os = "macos", windows)), test))]
    fn fine_sleep_once(&mut self, duration: Duration) -> io::Result<()> {
        self.charge(6)?;
        // Charge the Rust native-wait call before execution. Platform-internal
        // retries are not separately counted; cancellation and the original
        // absolute clock are checked on return by the owned loop.
        thread::sleep(duration);
        Ok(())
    }
    fn update_pending(&mut self) {
        self.stats.pending_service_packets = self.pending.len();
        self.stats.retained_packets = self.queue.len() + self.pending.len();
    }
    fn read_one(&mut self) -> io::Result<bool> {
        self.charge(1)?;
        match self.source.recv(&mut self.buffer_bytes) {
            Ok(n) => {
                self.stats.native_source_reads_completed += 1;
                self.publish_measured()?;
                let observed = self.now()?;
                if n > usize::from(self.settings.packet_bytes) {
                    self.publish();
                    return Err(refused("source_packet_capacity"));
                }
                let arrived: u64 = observed
                    .checked_duration_since(self.origin)
                    .ok_or_else(|| refused("source_origin_order"))?
                    .as_nanos()
                    .try_into()
                    .map_err(|_| refused("source_clock"))?;
                self.charge(5)?;
                let bytes = Zeroizing::new(self.buffer_bytes[..n].to_vec());
                let digest = Sha256::digest(&bytes).into();
                self.queue.push_back(Queued {
                    packet: Packet { bytes, arrived },
                    digest,
                });
                self.stats.accepted_packets += 1;
                self.update_pending();
                self.publish_measured()?;
                self.ensure()?;
                if self.stats.retained_packets > usize::from(self.settings.fifo_packets)
                    || self.stats.accepted_packets > usize::from(self.settings.total_packets)
                {
                    return Err(refused("source_fifo_capacity"));
                }
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(e),
        }
    }
    fn service_one(&mut self) -> io::Result<bool> {
        if self.pending.is_empty() {
            return Ok(false);
        }
        self.ensure()?;
        let started = self.now()?;
        let deadline = self
            .pending
            .front()
            .ok_or_else(|| refused("owned_service_missing"))?
            .nominal
            + Duration::from_micros(u64::from(self.settings.release_lateness_us));
        if started > deadline {
            return Err(refused("service_original_delivery_cutoff"));
        }
        // Reserve the post-write observation before the syscall. Nothing can
        // erase a known write if that observation crosses a clock/work limit.
        if self.stats.native_work_steps + 2 > MAX_WORK
            || self.stats.precision_polls >= self.settings.precision_poll_budget as usize
        {
            return Err(refused("owned_work_budget"));
        }
        self.charge(2)?;
        let item = self
            .pending
            .front()
            .ok_or_else(|| refused("owned_service_missing"))?;
        let outcome = self.sink.send(&item.queued.packet.bytes);
        #[cfg(test)]
        if outcome.is_ok() {
            if let Some(delay) = self.completion_delay {
                thread::sleep(delay);
            }
        }
        let completed = std::time::Instant::now();
        self.charge(0)?;
        match outcome {
            Ok(n) => {
                let item = self
                    .pending
                    .pop_front()
                    .ok_or_else(|| refused("owned_service_missing"))?;
                if n != item.queued.packet.bytes.len() {
                    return Err(refused("packet_write_partial"));
                }
                if item.event != self.stats.sent_packets {
                    return Err(refused("owned_service_fifo_sequence"));
                }
                self.last = Some(completed);
                self.stats.sent_packets += 1;
                self.update_pending();
                self.stats.maximum_service_wait_ns = self.stats.maximum_service_wait_ns.max(
                    started
                        .duration_since(item.admitted)
                        .as_nanos()
                        .try_into()
                        .unwrap_or(u64::MAX),
                );
                self.stats.maximum_service_duration_ns =
                    self.stats.maximum_service_duration_ns.max(
                        completed
                            .duration_since(started)
                            .as_nanos()
                            .try_into()
                            .unwrap_or(u64::MAX),
                    );
                self.checkpoints
                    .get_mut(usize::from(item.ordinal))
                    .ok_or_else(|| refused("owned_checkpoint_slot"))?
                    .hashes
                    .push(item.queued.digest);
                self.publish_measured()?;
                self.ensure()?;
                if completed > deadline {
                    // Existing terminal worker.publish carries this one record.
                    // No additional clock, I/O, publication or work charge.
                    self.stats.service_cutoff = service_cutoff_observation(
                        &item,
                        started,
                        completed,
                        Duration::from_micros(u64::from(self.settings.release_lateness_us)),
                    );
                    return Err(refused("service_completed_after_original_cutoff"));
                }
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(e),
        }
    }
    fn gather(&mut self, until: std::time::Instant, first: bool, read: bool) -> io::Result<()> {
        loop {
            // One actual charged observation checks the adjacent original
            // end/until boundaries before any I/O. Read/service/idle keep
            // their own observations after intervening work.
            let observed = self.ensure_now()?;
            if observed >= until {
                #[cfg(target_os = "macos")]
                {
                    self.diagnostics.last_gather = Some((
                        until,
                        observed,
                        (
                            self.stats.native_recv_attempts,
                            self.stats.native_send_attempts,
                        ),
                    ));
                }
                return Ok(());
            }
            self.service_one()?;
            let observed = self.now()?;
            if observed >= until {
                #[cfg(target_os = "macos")]
                {
                    self.diagnostics.last_gather = Some((
                        until,
                        observed,
                        (
                            self.stats.native_recv_attempts,
                            self.stats.native_send_attempts,
                        ),
                    ));
                }
                return Ok(());
            }
            if read && self.read_one()? {
                if first {
                    return Ok(());
                }
                continue;
            }
            let wake = self
                .pending
                .front()
                .map(|p| {
                    (p.nominal
                        + Duration::from_micros(u64::from(self.settings.release_lateness_us)))
                    .min(until)
                })
                .unwrap_or(until);
            self.idle(wake)?;
        }
    }
    fn admit(
        &mut self,
        target: std::time::Instant,
        window_end: std::time::Instant,
        ordinal: u16,
        event: usize,
    ) -> io::Result<()> {
        let result = self.admit_checked(target, window_end, ordinal, event);
        if result.is_err() {
            self.stats.missed_public_points += 1;
            self.stats.missed_public_block_ordinal = Some(ordinal);
            self.publish();
        }
        result
    }
    fn admit_checked(
        &mut self,
        target: std::time::Instant,
        window_end: std::time::Instant,
        ordinal: u16,
        event: usize,
    ) -> io::Result<()> {
        self.ensure()?;
        let now = self.now()?;
        #[cfg(target_os = "macos")]
        self.record_admission_diagnostics(target, ordinal, event, now);
        #[cfg(all(test, windows))]
        self.record_windows_admission_diagnostics(target, ordinal, event, now);
        self.admit_observed(target, window_end, ordinal, event, now)
    }
    // The live caller supplies its just-charged actual clock observation.
    // Separating that observation from the decision also lets unit tests
    // isolate causality and clock refusal without another scheduling race.
    fn admit_observed(
        &mut self,
        target: std::time::Instant,
        window_end: std::time::Instant,
        ordinal: u16,
        event: usize,
        now: std::time::Instant,
    ) -> io::Result<()> {
        if event != self.next_event {
            return Err(refused("duplicate_or_reordered_owned_event"));
        }
        let late = now
            .saturating_duration_since(target)
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX);
        self.stats.observed_point_lateness_ns = late;
        self.stats.maximum_admission_lateness_ns =
            self.stats.maximum_admission_lateness_ns.max(late);
        self.publish_progress();
        if target >= window_end {
            return Err(refused("original_point_outside_public_window"));
        }
        if now >= window_end + Duration::from_micros(u64::from(self.settings.release_lateness_us)) {
            return Err(refused("missed_original_public_window"));
        }
        if now > target + Duration::from_micros(u64::from(self.settings.release_lateness_us)) {
            return Err(refused("service_arrival_original_cutoff"));
        }
        let target_ns: u64 = target
            .checked_duration_since(self.origin)
            .ok_or_else(|| refused("source_origin_order"))?
            .as_nanos()
            .try_into()
            .map_err(|_| refused("source_clock"))?;
        let packet = self
            .queue
            .front()
            .ok_or_else(|| refused("source_starvation"))?;
        if packet.packet.arrived > target_ns {
            return Err(refused("source_unavailable_at_original_point"));
        }
        if self.pending.len() >= usize::from(self.settings.fifo_packets) {
            return Err(refused("service_queue_capacity"));
        }
        let queued = self
            .queue
            .pop_front()
            .ok_or_else(|| refused("source_starvation"))?;
        self.pending.push_back(Service {
            queued,
            nominal: target,
            admitted: now,
            ordinal,
            event,
        });
        self.next_event += 1;
        self.stats.service_queue_admissions += 1;
        self.stats.maximum_admission_lateness_ns =
            self.stats.maximum_admission_lateness_ns.max(late);
        self.update_pending();
        self.publish_progress();
        Ok(())
    }
    fn phase_one(&mut self) -> io::Result<()> {
        let cutoff = self.start + Duration::from_millis(u64::from(self.settings.buffering_ms));
        while self.now()? < cutoff {
            self.ensure()?;
            let empty = self.queue.is_empty();
            let next = match self.queue.front() {
                Some(q) => {
                    let scaled = u128::from(q.packet.arrived)
                        * u128::from(self.settings.lambda_pps)
                        / u128::from(self.settings.lambda_pps - self.settings.delta_pps);
                    self.start
                        + Duration::from_nanos(
                            scaled.try_into().map_err(|_| refused("buffering_clock"))?,
                        )
                }
                None => cutoff,
            }
            .min(cutoff);
            self.gather(next, empty, true)?;
            if empty && self.now()? < cutoff {
                continue;
            }
            if next == cutoff {
                break;
            }
            self.admit(next, cutoff, 0, self.next_event)?;
            self.service_one()?;
        }
        Ok(())
    }
    fn run(&mut self) -> io::Result<Vec<Checkpoint>> {
        self.checkpoints = (0..self.schedule.len() + 2)
            .map(|ordinal| Checkpoint {
                ordinal: ordinal as u16,
                hashes: Vec::new(),
            })
            .collect();
        self.gather(self.start, false, false)?;
        let base = if self.buffer {
            self.phase_one()?;
            self.start + Duration::from_millis(u64::from(self.settings.buffering_ms))
        } else {
            self.start
        };
        for block in 0..self.schedule.len() {
            let at = base + Duration::from_millis(block as u64 * u64::from(self.settings.block_ms));
            let cutoff = at + Duration::from_millis(u64::from(self.settings.block_ms));
            for i in 0..self.schedule[block].len() {
                let target = at + Duration::from_nanos(self.schedule[block][i]);
                self.gather(target, false, true)?;
                self.admit(target, cutoff, (block + 1) as u16, self.next_event)?;
                self.service_one()?;
            }
            self.gather(cutoff, false, true)?;
        }
        let coded_end = base
            + Duration::from_millis(self.schedule.len() as u64 * u64::from(self.settings.block_ms));
        let drain_end =
            (coded_end + Duration::from_millis(u64::from(self.settings.drain_ms))).min(self.end);
        while !self.queue.is_empty() || !self.pending.is_empty() {
            self.ensure()?;
            let now = self.now()?;
            if now >= drain_end {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    Phase("owned_drain_original_clock"),
                ));
            }
            if !self.queue.is_empty() {
                self.admit(
                    now,
                    drain_end,
                    (self.schedule.len() + 1) as u16,
                    self.next_event,
                )?;
            }
            if !self.service_one()? {
                self.idle(drain_end)?;
            }
        }
        self.ensure()?;
        Ok(std::mem::take(&mut self.checkpoints))
    }
}

#[cfg(test)]
mod tests {
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
    pub(super) fn fixture() -> (Worker, NativeSocket, NativeSocket) {
        let source = NativeSocket::bind("127.0.0.1:0").unwrap();
        let app = NativeSocket::bind("127.0.0.1:0").unwrap();
        source.connect(app.local_addr().unwrap()).unwrap();
        app.connect(source.local_addr().unwrap()).unwrap();
        let sink = NativeSocket::bind("127.0.0.1:0").unwrap();
        let peer = NativeSocket::bind("127.0.0.1:0").unwrap();
        sink.connect(peer.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        source.set_nonblocking(true).unwrap();
        sink.set_nonblocking(true).unwrap();
        let start = std::time::Instant::now() - Duration::from_millis(1);
        let worker = Worker {
            #[cfg(target_os = "macos")]
            native_wait: None,
            #[cfg(windows)]
            windows_wait: None,
            source,
            sink,
            queue: VecDeque::new(),
            settings: settings(),
            schedule: Zeroizing::new(vec![]),
            start,
            origin: start,
            end: start + Duration::from_secs(2),
            buffer: true,
            last: None,
            stats: Observations::default(),
            #[cfg(all(test, target_os = "macos"))]
            diagnostics: WaitDiagnostics::default(),
            #[cfg(all(test, windows))]
            windows_diagnostics: WindowsWaitDiagnostics::default(),
            #[cfg(all(test, target_os = "macos"))]
            diagnostic_publish_entered: None,
            observer: Observer::default(),
            cancel: Arc::new(AtomicBool::new(false)),
            buffer_bytes: Zeroizing::new(vec![0; 129]),
            pending: VecDeque::new(),
            next_event: 0,
            checkpoints: vec![
                Checkpoint {
                    ordinal: 0,
                    hashes: vec![],
                },
                Checkpoint {
                    ordinal: 1,
                    hashes: vec![],
                },
            ],
            completion_delay: None,
        };
        (worker, app, peer)
    }
    fn read_original(worker: &mut Worker, app: &NativeSocket, bytes: &[u8]) {
        app.send(bytes).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_millis(100);
        while !worker.read_one().unwrap() {
            assert!(
                std::time::Instant::now() < deadline,
                "owned original receive phase"
            );
            thread::yield_now();
        }
    }
    #[test]
    fn actual_admission_does_not_wait_for_observer_and_final_snapshot_is_complete() {
        let (mut worker, app, peer) = fixture();
        read_original(&mut worker, &app, b"owned packet");
        let observer = worker.observer.clone();
        let mut held = observer.0.lock().unwrap();
        held.release_cancel_requested = true;
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (admitted_tx, admitted_rx) = std::sync::mpsc::sync_channel(1);
        let original_end = std::time::Instant::now() + Duration::from_secs(2);
        let child = thread::spawn(move || {
            started_tx.send(()).unwrap();
            // Supply the observed decision clock explicitly: this regression
            // checks lock dependence, not the host's wake-time performance.
            let at = std::time::Instant::now();
            let result = worker.admit_observed(at, at + Duration::from_millis(100), 0, 0, at);
            admitted_tx.send(result.is_ok()).unwrap();
            // Terminal publication remains complete and preserves concurrent
            // custody facts after the observer releases its own snapshot.
            worker.publish();
            (worker, result)
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let without_unlock = admitted_rx.recv_timeout(Duration::from_millis(200));
        drop(held);
        while !child.is_finished() && std::time::Instant::now() < original_end {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            child.is_finished(),
            "owned admission regression cleanup exceeded original end"
        );
        let (worker, result) = child.join().unwrap();
        result.unwrap();
        assert_eq!(
            without_unlock.ok(),
            Some(true),
            "admission waited for the observer mutex"
        );
        let final_stats = observer.snapshot();
        assert_eq!(final_stats.service_queue_admissions, 1);
        assert_eq!(final_stats.pending_service_packets, 1);
        assert_eq!(final_stats.retained_packets, 1);
        assert!(final_stats.release_cancel_requested);
        assert_eq!(worker.stats.sent_packets, 0);
        peer.set_nonblocking(true).unwrap();
        assert!(peer.recv(&mut [0; 32]).is_err());
    }
    fn phase(error: io::Error) -> &'static str {
        error.get_ref().unwrap().downcast_ref::<Phase>().unwrap().0
    }
    #[cfg(any(target_os = "macos", windows))]
    fn check_prepare_refusal_on_owned_thread(
        case: u8,
        expected_phase: &'static str,
        expected_kind: io::ErrorKind,
    ) {
        let original_test_end = std::time::Instant::now() + Duration::from_secs(2);
        let (mut w, app, _peer) = fixture();
        // Actual source custody exists before setup; refusal may not discard it
        // while returning the private fixture for inspection after real join.
        read_original(&mut w, &app, b"owned refusal prefix");
        let accepted = w.stats.accepted_packets;
        let retained = w.stats.retained_packets;
        let receives = w.stats.native_recv_attempts;
        let sends = w.stats.native_send_attempts;
        match case {
            0 => w.end = std::time::Instant::now() - Duration::from_millis(1),
            1 => w.cancel.store(true, Ordering::Release),
            2 => w.stats.native_work_steps = MAX_WORK,
            _ => panic!("invalid test gate"),
        }
        // Even if this regression is broken, a scheduling setter can ONLY reach this
        // dedicated child, never the main/test-harness thread.
        let child = thread::spawn(move || {
            let error = w.prepare_owned_thread().unwrap_err();
            let kind = error.kind();
            let error_phase = phase(error);
            (w, kind, error_phase)
        });
        while !child.is_finished() && std::time::Instant::now() < original_test_end {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(std::time::Instant::now() < original_test_end);
        let finished = child.is_finished();
        assert!(std::time::Instant::now() < original_test_end);
        assert!(
            finished,
            "owned prepare-refusal thread not terminal within original test cutoff"
        );
        assert!(std::time::Instant::now() < original_test_end);
        let (w, kind, error_phase) = child.join().unwrap();
        assert!(std::time::Instant::now() < original_test_end);
        assert_eq!(kind, expected_kind);
        assert_eq!(error_phase, expected_phase);
        #[cfg(target_os = "macos")]
        {
            assert_eq!(w.diagnostics.qos_api_attempts, 0);
            assert!(w.diagnostics.requested_qos.is_none());
        }
        #[cfg(windows)]
        {
            assert_eq!(w.windows_diagnostics.priority_api_attempts, 0);
            assert!(w.windows_diagnostics.requested_priority.is_none());
        }
        assert_eq!(w.stats.accepted_packets, accepted);
        assert_eq!(w.stats.retained_packets, retained);
        assert_eq!(w.stats.native_recv_attempts, receives);
        assert_eq!(w.stats.native_send_attempts, sends);
        assert_eq!(w.queue.len(), 1);
        assert!(w.pending.is_empty());
        assert!(std::time::Instant::now() < original_test_end);
    }
    #[cfg(windows)]
    #[test]
    fn actual_worker_windows_priority_prepare_original_guards_preserve_source_custody() {
        check_prepare_refusal_on_owned_thread(
            0,
            "owned_release_original_clock",
            io::ErrorKind::TimedOut,
        );
        check_prepare_refusal_on_owned_thread(
            1,
            "owned_release_cancelled",
            io::ErrorKind::Interrupted,
        );
        check_prepare_refusal_on_owned_thread(2, "owned_work_budget", io::ErrorKind::InvalidData);
    }
    #[cfg(windows)]
    #[test]
    fn windows_budget_refusal_invalidates_older_wait_before_any_native_creation() {
        let (mut w, _producer, _peer) = fixture();
        let old_point = w.end - Duration::from_millis(10);
        w.windows_diagnostics.last_wait =
            Some(native_wait::WindowsWaitObservation::new(old_point, w.end));
        w.stats.native_work_steps = MAX_WORK;
        let before_clock = w.stats.precision_polls;
        let before_io = (w.stats.native_recv_attempts, w.stats.native_send_attempts);
        let changed_point = old_point - Duration::from_millis(1);
        assert_eq!(
            w.windows_high_resolution_wait(changed_point)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(w.stats.native_work_steps, MAX_WORK);
        assert_eq!(w.stats.precision_polls, before_clock);
        assert_eq!(
            (w.stats.native_recv_attempts, w.stats.native_send_attempts),
            before_io
        );
        assert!(w.windows_wait.is_none());
        assert!(w.windows_diagnostics.last_wait.is_none());
        assert_eq!(w.windows_diagnostics.attempts, 1);
        assert_eq!(w.windows_diagnostics.entered, 0);
        assert_eq!(w.windows_diagnostics.returned, 0);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn actual_worker_qos_prepare_spent_original_end_refuses_before_native_api() {
        check_prepare_refusal_on_owned_thread(
            0,
            "owned_release_original_clock",
            io::ErrorKind::TimedOut,
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn actual_worker_qos_prepare_cancel_refuses_before_native_api() {
        check_prepare_refusal_on_owned_thread(
            1,
            "owned_release_cancelled",
            io::ErrorKind::Interrupted,
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn actual_worker_qos_prepare_exhausted_work_refuses_before_native_api() {
        check_prepare_refusal_on_owned_thread(2, "owned_work_budget", io::ErrorKind::InvalidData);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn diagnostic_publish_reservation_refuses_before_measured_lock_and_clock() {
        let (mut w, _app, _peer) = fixture();
        w.stats.native_work_steps = MAX_WORK - 1;
        assert_eq!(
            phase(w.publish_measured().unwrap_err()),
            "owned_work_budget"
        );
        assert_eq!(w.diagnostics.publications_observed, 0);
        assert_eq!(w.stats.native_work_steps, MAX_WORK);
        assert_eq!(w.stats.native_clock_polls, 1);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn diagnostic_first_miss_is_immutable_and_absent_wait_is_not_attributed() {
        let (mut w, _app, _peer) = fixture();
        let point = std::time::Instant::now();
        w.record_admission_diagnostics(point, 1, 2, point + Duration::from_millis(11));
        let first = w.diagnostics.first_miss.clone().unwrap();
        assert_eq!(first["direct_wait_attribution_admitted"], false);
        assert_eq!(first["last_wait_present"], false);
        {
            let miss = w.stats.darwin_admission_miss.as_ref().unwrap();
            assert_eq!(miss.event_ordinal, 2);
            assert_eq!(miss.original_allowance_ns, 10_000_000);
            assert_eq!(miss.observed_lateness_ns, 11_000_000);
            assert_eq!(miss.cutoff_excess_ns, 1_000_000);
            assert!(!miss.last_wait_present);
        }
        w.record_admission_diagnostics(point, 7, 8, point + Duration::from_millis(12));
        assert_eq!(w.diagnostics.first_miss.as_ref(), Some(&first));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn diagnostic_actual_wait_preserves_original_point_and_charges_extra_clocks() {
        let (mut w, _app, _peer) = fixture();
        let point = std::time::Instant::now() + Duration::from_millis(50);
        w.absolute_wait(point).unwrap();
        let witness = w
            .diagnostics
            .last_wait
            .expect("real owned critical kernel timer call");
        assert_eq!(witness.point, point);
        assert!(witness.returned.unwrap() >= witness.entered);
        assert!(matches!(witness.status, Some(0 | 1)));
        assert_eq!(witness.backend, "darwin_kevent64_critical_absolute");
        assert!(w.stats.native_clock_polls >= 5);
        assert_eq!(w.diagnostics.waits_observed, 1);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn diagnostic_unrelated_expired_attempt_invalidates_actual_prior_wait_attribution() {
        let (mut w, _app, _peer) = fixture();
        let original = std::time::Instant::now() + Duration::from_millis(50);
        w.absolute_wait(original).unwrap();
        assert!(w.diagnostics.last_wait.is_some());
        assert_eq!(w.diagnostics.waits_observed, 1);
        let unrelated = std::time::Instant::now() - Duration::from_millis(1);
        w.absolute_wait(unrelated).unwrap();
        assert!(w.diagnostics.last_wait.is_none());
        assert_eq!(w.diagnostics.wait_attempts, 2);
        assert_eq!(w.diagnostics.waits_observed, 1);
        // Logical decision check after two actual native-path attempts. This
        // supplied observation is not a claim of an actual scheduled miss.
        w.record_admission_diagnostics(original, 1, 0, original + Duration::from_millis(11));
        let first = w.diagnostics.first_miss.as_ref().unwrap();
        assert_eq!(first["direct_wait_attribution_admitted"], false);
        assert_eq!(first["last_wait_present"], false);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn diagnostic_actual_observer_lock_delay_is_separate_from_native_wait() {
        let (mut w, _app, _peer) = fixture();
        let observer = w.observer.clone();
        let (held_tx, held_rx) = std::sync::mpsc::sync_channel(1);
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let holder = thread::spawn(move || {
            let guard = observer.0.lock().unwrap();
            held_tx.send(()).unwrap();
            entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            release_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            drop(guard);
        });
        held_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        w.diagnostic_publish_entered = Some(entered_tx);
        w.publish_measured().unwrap();
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert_eq!(w.diagnostics.waits_observed, 0);
        assert_eq!(w.diagnostics.publications_observed, 0);
        assert_eq!(w.diagnostics.publication_conflicts, 1);
        assert_eq!(w.stats.native_clock_polls, 2);
    }
    #[test]
    fn owned_fine_sleep_is_charged_before_the_native_call_at_the_original_budget() {
        let (mut worker, _app, _peer) = fixture();
        worker.stats.native_work_steps = MAX_WORK - 1;
        worker.fine_sleep_once(Duration::from_micros(50)).unwrap();
        assert_eq!(worker.stats.native_work_steps, MAX_WORK);
        assert_eq!(worker.stats.native_fine_sleep_calls, 1);
        assert_eq!(
            phase(
                worker
                    .fine_sleep_once(Duration::from_micros(50))
                    .unwrap_err()
            ),
            "owned_work_budget"
        );
        assert_eq!(worker.stats.native_work_steps, MAX_WORK);
        assert_eq!(worker.stats.native_fine_sleep_calls, 1);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn actual_darwin_expired_absolute_wait_charges_clock_without_sleep_or_io() {
        let (mut worker, _app, _peer) = fixture();
        let point = std::time::Instant::now();
        worker.absolute_wait(point).unwrap();
        assert_eq!(worker.stats.native_fine_sleep_calls, 0);
        assert_eq!(worker.stats.native_recv_attempts, 0);
        assert_eq!(worker.stats.native_send_attempts, 0);
        let clocks = worker.stats.native_clock_polls;
        let coarse = worker.stats.native_absolute_coarse_wait_calls;
        let fine = worker.stats.native_absolute_fine_wait_calls;
        worker.stats.native_work_steps = MAX_WORK - 1;
        // Even an expired point cannot bypass the original end/cancel guards.
        // The last work slot pays one clock; the next reservation must refuse.
        assert_eq!(
            phase(worker.absolute_wait(point).unwrap_err()),
            "owned_work_budget"
        );
        assert_eq!(worker.stats.native_work_steps, MAX_WORK);
        assert_eq!(worker.stats.native_clock_polls, clocks + 1);
        assert_eq!(worker.stats.native_absolute_coarse_wait_calls, coarse);
        assert_eq!(worker.stats.native_absolute_fine_wait_calls, fine);
        assert_eq!(worker.stats.native_recv_attempts, 0);
        assert_eq!(worker.stats.native_send_attempts, 0);
        assert_eq!(worker.stats.native_fine_sleep_calls, 0);
    }
    #[test]
    fn fine_sleep_requests_are_bounded_and_keep_original_point_guard() {
        assert_eq!(fine_sleep_duration(Duration::from_micros(20)), None);
        assert_eq!(
            fine_sleep_duration(Duration::from_micros(30)),
            Some(Duration::from_micros(10))
        );
        assert_eq!(
            fine_sleep_duration(Duration::from_millis(2)),
            Some(Duration::from_micros(50))
        );
        assert_eq!(fine_sleep_duration(Duration::from_millis(3)), None);
    }
    #[test]
    fn completed_gather_uses_one_charged_clock_before_any_io() {
        let (mut worker, _app, peer) = fixture();
        worker.stats.precision_polls = worker.settings.precision_poll_budget as usize - 1;
        let clock_calls = worker.stats.native_clock_polls;
        worker
            .gather(std::time::Instant::now(), false, true)
            .unwrap();
        assert_eq!(worker.stats.native_clock_polls, clock_calls + 1);
        assert_eq!(worker.stats.native_recv_attempts, 0);
        assert_eq!(worker.stats.native_send_attempts, 0);
        assert_eq!(worker.stats.native_work_steps, 1);
        assert_eq!(phase(worker.ensure().unwrap_err()), "owned_work_budget");
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.recv(&mut [0; 16]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn pending_service_idle_passes_original_cutoff_without_second_allowance() {
        let (mut worker, app, peer) = fixture();
        read_original(&mut worker, &app, b"pending original");
        let nominal = std::time::Instant::now();
        worker
            .admit_observed(nominal, nominal + Duration::from_secs(1), 0, 0, nominal)
            .unwrap();
        let allowance = Duration::from_micros(u64::from(worker.settings.release_lateness_us));
        assert_eq!(allowance, Duration::from_millis(10));
        let original_cutoff = nominal + allowance;
        let original_end = worker.end;
        let before_send = worker.stats.native_send_attempts;
        // Actual idle entry used by gather and drain. Intercept the native
        // boundary instead of duplicating its cutoff arithmetic in a test.
        worker
            .idle_with(original_cutoff, |worker, wake, latest_return| {
                assert_eq!(wake, original_cutoff);
                assert_eq!(worker.end, original_end);
                assert_eq!(latest_return, Some(original_cutoff));
                assert_eq!(worker.pending.len(), 1);
                assert_eq!(worker.pending.front().unwrap().nominal, nominal);
                assert_eq!(worker.stats.native_send_attempts, before_send);
                Ok(())
            })
            .unwrap();
        assert_eq!(worker.stats.sent_packets, 0);
        assert_eq!(worker.stats.retained_packets, 1);
        assert_eq!(
            worker
                .pending
                .front()
                .unwrap()
                .queued
                .packet
                .bytes
                .as_slice(),
            b"pending original"
        );
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.recv(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn pending_service_idle_empty_queue_keeps_original_wait_arguments() {
        let (mut worker, _app, _peer) = fixture();
        let original_end = worker.end;
        let point = std::time::Instant::now() + Duration::from_millis(100);
        let clocks = worker.stats.native_clock_polls;
        worker
            .idle_with(point, |worker, wake, latest_return| {
                assert_eq!(wake, point);
                assert_eq!(latest_return, None);
                assert_eq!(worker.end, original_end);
                Ok(())
            })
            .unwrap();
        assert_eq!(worker.stats.native_clock_polls, clocks);
    }
    #[test]
    fn pending_service_idle_expired_original_cutoff_never_enters_wait() {
        let (mut worker, app, peer) = fixture();
        read_original(&mut worker, &app, b"expired pending");
        let nominal = std::time::Instant::now();
        worker
            .admit_observed(nominal, nominal + Duration::from_secs(1), 0, 0, nominal)
            .unwrap();
        let original_cutoff = nominal + Duration::from_millis(10);
        let original_end = worker.end;
        let reads = worker.stats.native_recv_attempts;
        let sends = worker.stats.native_send_attempts;
        while std::time::Instant::now() <= original_cutoff {
            std::hint::spin_loop();
        }
        let error = worker
            .idle_with(original_cutoff, |_, _, _| {
                panic!("expired pending wait entered")
            })
            .unwrap_err();
        assert_eq!(phase(error), "service_original_delivery_cutoff");
        assert_eq!(worker.end, original_end);
        assert_eq!(worker.stats.native_recv_attempts, reads);
        assert_eq!(worker.stats.native_send_attempts, sends);
        assert_eq!(worker.stats.sent_packets, 0);
        assert_eq!(worker.stats.retained_packets, 1);
        assert_eq!(worker.pending.len(), 1);
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.recv(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn pending_service_idle_late_return_refuses_with_original_unsent_custody() {
        let (mut worker, app, peer) = fixture();
        read_original(&mut worker, &app, b"late return pending");
        let nominal = std::time::Instant::now();
        worker
            .admit_observed(nominal, nominal + Duration::from_secs(1), 0, 0, nominal)
            .unwrap();
        let original_cutoff = nominal + Duration::from_millis(10);
        let original_end = worker.end;
        let reads = worker.stats.native_recv_attempts;
        let sends = worker.stats.native_send_attempts;
        let error = worker
            .idle_with(original_cutoff, |worker, wake, latest_return| {
                assert_eq!(wake, original_cutoff);
                assert_eq!(latest_return, Some(original_cutoff));
                assert_eq!(worker.end, original_end);
                // Controlled boundary return beyond the unchanged original
                // allowance; no assertion about a kernel wake-time cause.
                while std::time::Instant::now() <= original_cutoff {
                    std::hint::spin_loop();
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(phase(error), "service_original_delivery_cutoff");
        assert_eq!(worker.end, original_end);
        assert_eq!(worker.stats.native_recv_attempts, reads);
        assert_eq!(worker.stats.native_send_attempts, sends);
        assert_eq!(worker.stats.sent_packets, 0);
        assert_eq!(worker.stats.retained_packets, 1);
        assert_eq!(worker.pending.len(), 1);
        assert_eq!(
            worker
                .pending
                .front()
                .unwrap()
                .queued
                .packet
                .bytes
                .as_slice(),
            b"late return pending"
        );
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.recv(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn owned_precision_guard_never_parks_in_last_two_milliseconds() {
        assert_eq!(park_duration(Duration::from_micros(200)), None);
        assert_eq!(park_duration(Duration::from_millis(2)), None);
        assert_eq!(
            park_duration(Duration::from_millis(3)),
            Some(Duration::from_millis(1))
        );
    }
    #[test]
    fn actual_fifo_service_allows_overlapping_nominal_arrivals_without_replay() {
        let (mut w, app, peer) = fixture();
        read_original(&mut w, &app, b"first");
        read_original(&mut w, &app, b"second");
        let target = std::time::Instant::now();
        let cutoff = target + Duration::from_millis(100);
        w.admit(target, cutoff, 0, 0).unwrap();
        w.service_one().unwrap();
        assert!(w.last.unwrap() >= target);
        // A second nominal arrival can precede the first completion; this is
        // a queued service contract, not a fabricated exact physical schedule.
        w.admit(target, cutoff, 0, 1).unwrap();
        w.service_one().unwrap();
        let mut b = [0; 32];
        let n = peer.recv(&mut b).unwrap();
        assert_eq!(&b[..n], b"first");
        let n = peer.recv(&mut b).unwrap();
        assert_eq!(&b[..n], b"second");
        assert_eq!(w.stats.sent_packets, 2);
        assert_eq!(w.stats.service_queue_admissions, 2);
        assert_eq!(w.stats.retained_packets, 0);
        assert_eq!(
            phase(w.admit(target, cutoff, 0, 1).unwrap_err()),
            "duplicate_or_reordered_owned_event"
        );
    }
    #[test]
    fn actual_phase_one_service_retains_original_source_causality_and_fifo() {
        let (mut w, app, peer) = fixture();
        read_original(&mut w, &app, b"one");
        read_original(&mut w, &app, b"two");
        w.phase_one().unwrap();
        assert_eq!(w.stats.sent_packets, 2);
        assert_eq!(w.stats.retained_packets, 0);
        let mut b = [0; 32];
        let n = peer.recv(&mut b).unwrap();
        assert_eq!(&b[..n], b"one");
        let n = peer.recv(&mut b).unwrap();
        assert_eq!(&b[..n], b"two");
    }
    #[test]
    fn observed_late_source_missed_window_and_late_admission_never_send() {
        let (mut w, app, peer) = fixture();
        read_original(&mut w, &app, b"late original");
        // This is the genuine read observation recorded by the worker. The
        // selected original point precedes it by one nanosecond. Do not mutate
        // a packet's source timestamp or allow a real late live admission.
        let now = w.origin + Duration::from_nanos(w.queue.front().unwrap().packet.arrived);
        let before = now - Duration::from_nanos(1);
        let cutoff = now + Duration::from_millis(100);
        assert_eq!(
            phase(w.admit_observed(before, cutoff, 0, 0, now).unwrap_err()),
            "source_unavailable_at_original_point"
        );
        assert_eq!(
            phase(
                w.admit_observed(
                    now - Duration::from_millis(20),
                    now - Duration::from_millis(11),
                    0,
                    0,
                    now
                )
                .unwrap_err()
            ),
            "missed_original_public_window"
        );
        assert_eq!(
            phase(
                w.admit_observed(now - Duration::from_millis(11), cutoff, 0, 0, now)
                    .unwrap_err()
            ),
            "service_arrival_original_cutoff"
        );
        assert_eq!(w.stats.sent_packets, 0);
        assert_eq!(w.stats.retained_packets, 1);
        peer.set_nonblocking(true).unwrap();
        let mut b = [0; 32];
        assert!(peer.recv(&mut b).is_err());
    }
    #[test]
    fn actual_pending_capacity_refuses_without_discarding_owned_prefix() {
        let (mut w, app, peer) = fixture();
        read_original(&mut w, &app, b"one");
        read_original(&mut w, &app, b"two");
        w.settings.fifo_packets = 1;
        let at = std::time::Instant::now();
        let cutoff = at + Duration::from_millis(100);
        w.admit(at, cutoff, 0, 0).unwrap();
        assert_eq!(
            phase(w.admit(at, cutoff, 0, 1).unwrap_err()),
            "service_queue_capacity"
        );
        assert_eq!(w.pending.len(), 1);
        assert_eq!(w.queue.len(), 1);
        assert_eq!(w.stats.sent_packets, 0);
        peer.set_nonblocking(true).unwrap();
        let mut b = [0; 32];
        assert!(peer.recv(&mut b).is_err());
    }
    #[test]
    fn actual_service_write_crossing_original_ten_ms_counts_sent_before_refusal() {
        let (mut w, app, peer) = fixture();
        read_original(&mut w, &app, b"actually sent");
        let at = std::time::Instant::now();
        w.admit(at, at + Duration::from_millis(100), 0, 0).unwrap();
        w.completion_delay = Some(Duration::from_millis(35));
        assert_eq!(
            phase(w.service_one().unwrap_err()),
            "service_completed_after_original_cutoff"
        );
        let mut b = [0; 32];
        let n = peer.recv(&mut b).unwrap();
        assert_eq!(&b[..n], b"actually sent");
        assert_eq!(w.stats.sent_packets, 1);
        assert_eq!(w.stats.retained_packets, 0);
        assert!(w.stats.maximum_service_duration_ns >= 35_000_000);
    }
    #[test]
    fn actual_original_clock_work_and_cancellation_refuse_before_io() {
        let (mut w, app, peer) = fixture();
        read_original(&mut w, &app, b"held");
        w.end = std::time::Instant::now();
        let at = w.end;
        assert_eq!(
            phase(
                w.admit(at, at + Duration::from_millis(100), 0, 0)
                    .unwrap_err()
            ),
            "owned_release_original_clock"
        );
        w.end = at + Duration::from_secs(1);
        w.cancel.store(true, Ordering::Release);
        assert_eq!(
            phase(w.admit(at, w.end, 0, 0).unwrap_err()),
            "owned_release_cancelled"
        );
        w.cancel.store(false, Ordering::Release);
        w.stats.native_work_steps = MAX_WORK;
        assert_eq!(
            phase(w.admit(at, w.end, 0, 0).unwrap_err()),
            "owned_work_budget"
        );
        assert_eq!(w.stats.sent_packets, 0);
        peer.set_nonblocking(true).unwrap();
        let mut b = [0; 32];
        assert!(peer.recv(&mut b).is_err());
    }
    #[tokio::test]
    async fn actual_owned_thread_drop_requests_then_observes_terminal_without_claiming_join() {
        let s = settings();
        let end = Instant::now() + Duration::from_secs(5);
        let prepared = Prepared::new(s, Zeroizing::new([2; 32]), end).unwrap();
        let words = prepared.encode(b"x").unwrap();
        let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        source.connect(app.local_addr().unwrap()).await.unwrap();
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sink.connect(app.local_addr().unwrap()).await.unwrap();
        let mut sender = Sender::new(source, sink).unwrap();
        let observer = Observer::default();
        sender.observe(observer.clone());
        let mut owned = OwnedSender::spawn_blocks(
            sender,
            &prepared,
            &words,
            Instant::now() + Duration::from_millis(200),
            end,
        )
        .unwrap();
        owned.ready(end).await.unwrap();
        drop(owned);
        assert!(observer.snapshot().release_cancel_requested);
        assert!(!observer.snapshot().release_thread_joined);
        tokio::time::timeout_at(end, async {
            while !observer.snapshot().release_thread_terminal {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(observer.snapshot().release_thread_terminal);
        assert!(!observer.snapshot().release_thread_joined);
        // The unrelated explicitly owned application socket remains useful.
        assert!(app.local_addr().is_ok());
    }
    #[test]
    fn actual_last_point_with_surviving_delivery_allowance_crosses_boundary_without_reset() {
        let mut overslept: Vec<(&'static str, u64)> = Vec::new();
        let assert_unsent = |w: &Worker, peer: &NativeSocket| {
            assert_eq!(w.stats.native_send_attempts, 0);
            assert_eq!(w.stats.sent_packets, 0);
            assert_eq!(w.stats.retained_packets, 1);
            assert_eq!(w.stats.service_queue_admissions, 0);
            assert!(w.pending.is_empty());
            assert_eq!(w.queue.len(), 1);
            assert_eq!(
                w.queue.front().unwrap().packet.bytes.as_slice(),
                b"boundary original"
            );
            peer.set_nonblocking(true).unwrap();
            assert_eq!(
                peer.recv(&mut [0; 32]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        };
        for _attempt in 0..3 {
            let (mut w, app, peer) = fixture();
            read_original(&mut w, &app, b"boundary original");
            let target = std::time::Instant::now();
            let block_end = target + Duration::from_micros(250);
            thread::sleep(Duration::from_micros(500));
            let observed = w.now().unwrap();
            let source_ns: u64 = target
                .duration_since(w.origin)
                .as_nanos()
                .try_into()
                .unwrap();
            assert!(w.queue.front().unwrap().packet.arrived <= source_ns);
            let original_cutoff =
                target + Duration::from_micros(u64::from(w.settings.release_lateness_us));
            if observed > original_cutoff {
                // This attempt never entered admission or service. The host
                // consumed its unchanged allowance before the fixture could
                // exercise the positive path; discard only this fresh owner.
                assert_unsent(&w, &peer);
                overslept.push((
                    "pre_admission",
                    observed
                        .duration_since(target)
                        .as_nanos()
                        .try_into()
                        .unwrap_or(u64::MAX),
                ));
                continue;
            }
            assert!(observed > block_end);
            if let Err(error) = w.admit(target, block_end, 1, 0) {
                let code = error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<Phase>())
                    .map(|typed| typed.0);
                if matches!(
                    code,
                    Some("service_arrival_original_cutoff" | "missed_original_public_window")
                ) {
                    let lateness = w.stats.observed_point_lateness_ns;
                    assert!(lateness > u64::from(w.settings.release_lateness_us) * 1_000);
                    assert_unsent(&w, &peer);
                    overslept.push((code.unwrap(), lateness));
                    continue;
                }
                panic!("unexpected original-point admission refusal: {code:?}");
            }
            w.service_one().unwrap();
            assert_eq!(w.stats.missed_public_block_ordinal, None);
            assert!(w.stats.observed_point_lateness_ns >= 500_000);
            assert_eq!(w.stats.sent_packets, 1);
            assert_eq!(w.stats.retained_packets, 0);
            let mut bytes = [0; 32];
            let n = peer.recv(&mut bytes).unwrap();
            assert_eq!(&bytes[..n], b"boundary original");
            return;
        }
        panic!("all 3 fresh original-point fixtures overslept the unchanged 10 ms cutoff before or during admission: {overslept:?}");
    }
    #[tokio::test]
    async fn actual_partial_schedule_work_refusal_starts_no_owned_thread() {
        let end = Instant::now() + Duration::from_secs(5);
        let mut prepared = Prepared::new(settings(), Zeroizing::new([2; 32]), end).unwrap();
        let words = prepared.encode(b"x").unwrap();
        assert!(prepared.book(0).unwrap()[words[0]].len() >= 2);
        // Inject an already consumed accounted-work prefix: the first selected
        // point is copied and the second refuses. The temporary's Zeroizing
        // ownership also covers this pre-push early return.
        prepared.preparation_work_steps = MAX_WORK - 3;
        let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        source.connect(app.local_addr().unwrap()).await.unwrap();
        sink.connect(app.local_addr().unwrap()).await.unwrap();
        let mut sender = Sender::new(source, sink).unwrap();
        let observer = Observer::default();
        sender.observe(observer.clone());
        let error = OwnedSender::spawn_blocks(
            sender,
            &prepared,
            &words,
            Instant::now() + Duration::from_millis(200),
            end,
        )
        .err()
        .unwrap();
        assert_eq!(phase(error), "owned_preparation_budget");
        assert!(!observer.snapshot().release_thread_started);
        assert_eq!(observer.snapshot().native_send_attempts, 0);
        assert!(app.local_addr().is_ok());
    }
    #[test]
    fn actual_post_send_cutoff_records_one_service_not_cross_event_maxima() {
        let (mut w, app, peer) = fixture();
        read_original(&mut w, &app, b"one original service");
        // Unrelated telemetry sentinels only, not simulated native packets.
        // These exceed the original whole fixture horizon. The required
        // completed < w.end and clock order keep this event below that horizon.
        let horizon_ns = u64::try_from(w.end.duration_since(w.origin).as_nanos()).unwrap();
        w.stats.maximum_admission_lateness_ns = horizon_ns.checked_add(3).unwrap();
        w.stats.maximum_service_wait_ns = horizon_ns.checked_add(2).unwrap();
        w.stats.maximum_service_duration_ns = horizon_ns.checked_add(1).unwrap();
        let nominal = std::time::Instant::now();
        w.admit(nominal, nominal + Duration::from_millis(100), 0, 0)
            .unwrap();
        let admitted = w.pending.front().unwrap().admitted;
        w.completion_delay = Some(Duration::from_millis(35));
        assert_eq!(
            phase(w.service_one().unwrap_err()),
            "service_completed_after_original_cutoff"
        );
        let completed = w.last.expect("actual successful send completion");
        let mut bytes = [0; 64];
        let n = peer.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..n], b"one original service");
        assert_eq!(w.stats.sent_packets, 1);
        assert_eq!(w.stats.native_send_attempts, 1);
        assert_eq!(w.stats.retained_packets, 0);
        assert!(w.pending.is_empty());
        assert!(completed > nominal + Duration::from_millis(10));
        assert!(completed < w.end);
        eprintln!("poisson_same_service_cutoff_validity actual_send=1 receipt=1 original_typed_refusal=1 event=0 unrelated_extrema_sentinels=1");
        let actual = w
            .stats
            .service_cutoff
            .as_ref()
            .expect("post_send_cutoff_same_event_tuple_missing");
        assert_eq!(actual.event_ordinal, 0);
        assert_eq!(actual.original_allowance_ns, 10_000_000);
        assert_eq!(
            actual.admission_lateness_ns,
            u64::try_from(admitted.duration_since(nominal).as_nanos()).unwrap()
        );
        assert_eq!(
            actual.completion_lateness_ns,
            u64::try_from(completed.duration_since(nominal).as_nanos()).unwrap()
        );
        assert_eq!(
            actual.pending_wait_ns + actual.write_observation_bracket_ns,
            u64::try_from(completed.duration_since(admitted).as_nanos()).unwrap()
        );
        assert_eq!(
            actual.admission_lateness_ns
                + actual.pending_wait_ns
                + actual.write_observation_bracket_ns,
            actual.completion_lateness_ns
        );
        assert!(actual.completion_lateness_ns > actual.original_allowance_ns);
        assert_ne!(
            actual.admission_lateness_ns,
            w.stats.maximum_admission_lateness_ns
        );
        assert_ne!(actual.pending_wait_ns, w.stats.maximum_service_wait_ns);
        assert_ne!(
            actual.write_observation_bracket_ns,
            w.stats.maximum_service_duration_ns
        );
        // Existing publication, not a simulated spawned-thread join.
        let expected = actual.clone();
        w.publish();
        assert_eq!(w.observer.snapshot().service_cutoff, Some(expected));
    }

    #[test]
    fn same_service_cutoff_arithmetic_refuses_order_overflow_and_nonrefusal() {
        let (mut w, app, _peer) = fixture();
        read_original(&mut w, &app, b"arithmetic original");
        let origin = std::time::Instant::now();
        w.admit(origin, origin + Duration::from_millis(100), 0, 0)
            .unwrap();
        let service = w.pending.front_mut().unwrap();
        // Hypothetical helper inputs; no live admission/write accepts them.
        service.nominal = origin;
        service.admitted = origin + Duration::from_millis(1);
        service.event = 7;
        let started = origin + Duration::from_millis(2);
        let completed = origin + Duration::from_millis(15);
        let allowance = Duration::from_millis(10);
        assert_eq!(
            service_cutoff_observation(service, started, completed, allowance),
            Some(ServiceCutoffObservation {
                event_ordinal: 7,
                admission_lateness_ns: 1_000_000,
                pending_wait_ns: 1_000_000,
                write_observation_bracket_ns: 13_000_000,
                completion_lateness_ns: 15_000_000,
                original_allowance_ns: 10_000_000,
            })
        );
        assert!(
            service_cutoff_observation(service, started, origin + allowance, allowance).is_none()
        );
        assert!(service_cutoff_observation(service, origin, completed, allowance).is_none());
        assert!(service_cutoff_observation(service, started, origin, allowance).is_none());
        assert!(service_cutoff_observation(service, started, completed, Duration::MAX).is_none());
    }
}

#[path = "poisson_channel_command.rs"]
mod command;
pub(super) use command::{execute_strict, StrictCommand};

#[cfg(all(test, target_os = "macos"))]
#[path = "poisson_darwin_fine_wait_tests.rs"]
mod darwin_fine_wait_tests;
