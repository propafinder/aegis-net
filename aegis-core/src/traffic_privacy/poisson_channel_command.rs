//! One strict public command per directly owned native release thread.
//! This is not the overlapping service-queue contract used by OwnedSender.
use super::*;

pub(in crate::traffic_privacy::poisson_channel) enum StrictCommand {
    Buffering {
        start: Instant,
    },
    Block {
        start: Instant,
        points: Zeroizing<Vec<u64>>,
        ordinal: u16,
    },
    Drain {
        ordinal: u16,
        drain_end: Instant,
    },
}
impl StrictCommand {
    fn start(&self) -> Instant {
        match self {
            Self::Buffering { start } | Self::Block { start, .. } => *start,
            Self::Drain { .. } => Instant::now(),
        }
    }
}

/// Custody is consumed before spawn. Only a successful, actually joined command
/// restores it. Drop requests cancellation; it never claims that a thread was
/// joined. The mutable Sender remains poisoned even if that thread later ends.
struct CommandOwner<'a> {
    sender: &'a mut Sender,
    cancel: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    // Own both original Tokio sockets throughout fallible conversion/prep.
    // Converted native locals and Worker are declared after this guard and
    // consequently dropped before the guard publishes preparation disposal.
    source: Option<UdpSocket>,
    sink: Option<UdpSocket>,
}
impl Drop for CommandOwner<'_> {
    fn drop(&mut self) {
        drop(self.source.take());
        drop(self.sink.take());
        if let Some(handle) = &self.thread {
            self.cancel.store(true, Ordering::Release);
            self.sender
                .observer
                .edit(|s| s.release_cancel_requested = true);
            handle.thread().unpark();
            // A still-running actor owns its buffers. No disposal/join proof
            // is manufactured here; its error/abandoned-result path observes
            // actual Worker destruction independently.
        } else if self.sender.source.is_none() || self.sender.sink.is_none() {
            self.sender.queue.clear();
            self.sender.observer.edit(|s| {
                s.strict_command_buffers_discarded = true;
                s.strict_command_custody_restored = false;
                s.strict_command_preparation_failed = !s.release_thread_started;
            });
        }
        self.sender.observations = self.sender.observer.snapshot();
    }
}

struct ReturnedCommand {
    checkpoint: Option<Checkpoint>,
    worker: Option<Worker>,
    observer: Observer,
    restored_origin: Option<Instant>,
}
impl Drop for ReturnedCommand {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            drop(worker);
            self.observer
                .edit(|s| s.strict_command_buffers_discarded = true);
        }
    }
}

pub(in crate::traffic_privacy::poisson_channel) async fn execute_strict(
    sender: &mut Sender,
    command: StrictCommand,
    settings: &Settings,
    end: Instant,
) -> io::Result<Checkpoint> {
    settings.validate()?;
    live(end)?;
    // Refuse a consumed/cancelled/failed Sender before any new thread or I/O.
    if sender.source.is_none() || sender.sink.is_none() {
        sender.observations = sender.observer.snapshot();
        return Err(refused("strict_sender_consumed"));
    }
    let admission = Admission::acquire()?;
    let start = command.start();
    let original_origin = sender.origin;
    let origin = original_origin.unwrap_or(start);
    let cancel = Arc::new(AtomicBool::new(false));
    let observer = sender.observer.clone();
    let source = sender
        .source
        .take()
        .ok_or_else(|| refused("strict_sender_consumed"))?;
    // The guard exists from the first consumed socket. No second fallible
    // take/conversion or queue preparation precedes it or its status reset.
    let mut guard = CommandOwner {
        sender,
        cancel: cancel.clone(),
        thread: None,
        source: Some(source),
        sink: None,
    };
    let mut stats = guard.sender.observations.clone();
    stats.release_thread_started = false;
    stats.release_thread_terminal = false;
    stats.release_thread_joined = false;
    stats.release_cancel_requested = false;
    stats.service_queue_contract_v2 = false;
    stats.strict_command_custody_consumed = true;
    stats.strict_command_custody_restored = false;
    stats.strict_command_buffers_discarded = false;
    stats.strict_command_preparation_failed = false;
    observer.update(&stats);
    guard.sink = Some(
        guard
            .sender
            .sink
            .take()
            .ok_or_else(|| refused("strict_sender_consumed"))?,
    );
    let source = guard
        .source
        .take()
        .ok_or_else(|| refused("strict_sender_consumed"))?
        .into_std()?;
    let sink = guard
        .sink
        .take()
        .ok_or_else(|| refused("strict_sender_consumed"))?
        .into_std()?;
    source.set_nonblocking(true)?;
    sink.set_nonblocking(true)?;
    let mut queue = VecDeque::with_capacity(guard.sender.queue.len());
    for packet in std::mem::take(&mut guard.sender.queue) {
        live(end)?;
        if stats.native_work_steps >= MAX_WORK {
            return Err(refused("owned_preparation_budget"));
        }
        let next_preparation = stats
            .preparation_work_steps
            .checked_add(1)
            .filter(|&n| n <= MAX_WORK)
            .ok_or_else(|| refused("owned_preparation_budget"))?;
        stats.native_work_steps += 1;
        stats.preparation_work_steps = next_preparation;
        observer.update(&stats);
        queue.push_back(Queued {
            digest: Sha256::digest(&packet.bytes).into(),
            packet,
        });
    }
    let mut worker = Worker {
        #[cfg(target_os = "macos")]
        native_wait: None,
        #[cfg(windows)]
        windows_wait: None,
        source,
        sink,
        queue,
        settings: settings.clone(),
        schedule: Zeroizing::new(Vec::new()),
        start: start.into_std(),
        origin: origin.into_std(),
        end: end.into_std(),
        buffer: false,
        last: guard.sender.last_completed_write.map(Instant::into_std),
        stats,
        #[cfg(target_os = "macos")]
        diagnostics: WaitDiagnostics::default(),
        #[cfg(all(test, windows))]
        windows_diagnostics: WindowsWaitDiagnostics::default(),
        #[cfg(all(test, target_os = "macos"))]
        diagnostic_publish_entered: None,
        observer: observer.clone(),
        cancel,
        buffer_bytes: Zeroizing::new(vec![0; usize::from(settings.packet_bytes) + 1]),
        pending: VecDeque::new(),
        next_event: 0,
        checkpoints: Vec::new(),
        #[cfg(test)]
        completion_delay: guard.sender.completion_observation_delay,
    };
    #[cfg(all(test, windows))]
    let strict_thread_preparation = guard.sender.strict_thread_preparation.clone();
    #[cfg(all(test, windows))]
    {
        *strict_thread_preparation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            StrictThreadPreparationObservation::default();
    }
    let (tx, rx) = oneshot::channel();
    guard.thread = Some(
        thread::Builder::new()
            .name("aegis-poisson-strict".into())
            .spawn(move || {
                let _admission = admission;
                observer.edit(|s| s.release_thread_started = true);
                #[cfg(any(target_os = "macos", windows))]
                let result = worker
                    .prepare_owned_thread()
                    .and_then(|()| worker.run_strict(command));
                #[cfg(not(any(target_os = "macos", windows)))]
                let result = worker.run_strict(command);
                worker.publish();
                #[cfg(all(test, windows))]
                {
                    *strict_thread_preparation
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        StrictThreadPreparationObservation {
                            native_api_attempts: worker.windows_diagnostics.priority_api_attempts,
                            requested_priority_readback_present: worker
                                .windows_diagnostics
                                .requested_priority
                                .is_some(),
                        };
                }
                #[cfg(all(test, target_os = "macos"))]
                worker.print_wait_diagnostics(result.is_err());
                #[cfg(all(test, windows))]
                worker.print_windows_wait_diagnostics(result.is_err());
                let output = match result {
                    Ok((checkpoint, initialized_origin)) => Ok(ReturnedCommand {
                        checkpoint: Some(checkpoint),
                        worker: Some(worker),
                        observer: observer.clone(),
                        restored_origin: original_origin
                            .or_else(|| initialized_origin.map(Instant::from_std)),
                    }),
                    Err(error) => {
                        let kind = error.kind();
                        let phase = error
                            .get_ref()
                            .and_then(|e| e.downcast_ref::<Phase>())
                            .map_or("strict_source_io", |phase| phase.0);
                        drop(worker);
                        observer.edit(|s| s.strict_command_buffers_discarded = true);
                        Err(io::Error::new(kind, Phase(phase)))
                    }
                };
                observer.edit(|s| s.release_thread_terminal = true);
                // If the future was dropped, any successful returned sockets/queue
                // are dropped here. They cannot be restored by an abandoned command.
                if let Err(abandoned) = tx.send(output) {
                    drop(abandoned);
                    observer.edit(|s| s.strict_command_buffers_discarded = true);
                }
            })?,
    );
    let output = tokio::time::timeout_at(end, rx)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                Phase("strict_command_result_clock"),
            )
        })?
        .map_err(|_| refused("strict_command_terminal"))?;
    while !guard
        .thread
        .as_ref()
        .ok_or_else(|| refused("strict_command_thread_missing"))?
        .is_finished()
    {
        live(end)?;
        tokio::task::yield_now().await;
    }
    guard
        .thread
        .take()
        .ok_or_else(|| refused("strict_command_thread_missing"))?
        .join()
        .map_err(|_| refused("strict_command_panicked"))?;
    guard
        .sender
        .observer
        .edit(|s| s.release_thread_joined = true);
    guard.sender.observations = guard.sender.observer.snapshot();
    live(end)?;
    let mut returned = output?;
    let checkpoint = returned
        .checkpoint
        .take()
        .ok_or_else(|| refused("strict_command_checkpoint_missing"))?;
    let restored_origin = returned.restored_origin;
    let worker = returned
        .worker
        .take()
        .ok_or_else(|| refused("strict_command_worker_missing"))?;
    // Convert both before restoring either: errors keep the Sender poisoned.
    let Worker {
        source,
        sink,
        queue,
        last,
        ..
    } = worker;
    let source = UdpSocket::from_std(source)?;
    let sink = UdpSocket::from_std(sink)?;
    let queue = queue.into_iter().map(|q| q.packet).collect();
    live(end)?;
    guard.sender.source = Some(source);
    guard.sender.sink = Some(sink);
    guard.sender.queue = queue;
    guard.sender.origin = restored_origin;
    guard.sender.last_completed_write = last.map(Instant::from_std);
    if let Err(error) = live(end) {
        // A synchronous restoration crossing END cannot manufacture success.
        drop(guard.sender.source.take());
        drop(guard.sender.sink.take());
        guard.sender.queue.clear();
        return Err(error);
    }
    guard
        .sender
        .observer
        .edit(|s| s.strict_command_custody_restored = true);
    if let Err(error) = live(end) {
        drop(guard.sender.source.take());
        drop(guard.sender.sink.take());
        guard.sender.queue.clear();
        return Err(error);
    }
    Ok(checkpoint)
}

impl Worker {
    fn strict_target(&mut self, target: std::time::Instant, ordinal: u16) -> io::Result<()> {
        let observed = self.ensure_now()?;
        if observed >= target {
            self.stats.missed_public_points += 1;
            self.stats.observed_point_lateness_ns = observed
                .duration_since(target)
                .as_nanos()
                .try_into()
                .unwrap_or(u64::MAX);
            self.stats.missed_public_block_ordinal = Some(ordinal);
            self.stats.prior_completed_write_reached_missed_target =
                self.last.is_some_and(|t| t >= target);
            self.publish();
        }
        if self.last.is_some_and(|t| t >= target) {
            return Err(refused("public_point_prior_write_overlap"));
        }
        if observed
            > target
                .checked_add(Duration::from_micros(u64::from(
                    self.settings.release_lateness_us,
                )))
                .ok_or_else(|| refused("public_point_clock"))?
        {
            return Err(refused("public_point_delivery_cutoff"));
        }
        Ok(())
    }
    fn strict_release(&mut self, target: std::time::Instant) -> io::Result<[u8; 32]> {
        let cutoff = target
            .checked_add(Duration::from_micros(u64::from(
                self.settings.release_lateness_us,
            )))
            .ok_or_else(|| refused("public_point_clock"))?;
        loop {
            if self.ensure_now()? > cutoff {
                return Err(refused("release_late"));
            }
            let target_ns: u64 = target
                .checked_duration_since(self.origin)
                .ok_or_else(|| refused("source_origin_order"))?
                .as_nanos()
                .try_into()
                .map_err(|_| refused("source_clock"))?;
            let front = self
                .queue
                .front()
                .ok_or_else(|| refused("source_starvation"))?;
            if front.packet.arrived > target_ns {
                return Err(refused("source_unavailable_at_public_point"));
            }
            // Reserve a post-write observation, exactly as in the existing
            // owner. A known write remains counted even on a later refusal.
            if self.stats.native_work_steps + 2 > MAX_WORK
                || self.stats.precision_polls >= self.settings.precision_poll_budget as usize
            {
                return Err(refused("owned_work_budget"));
            }
            self.charge(2)?;
            let front = self
                .queue
                .front()
                .ok_or_else(|| refused("source_starvation"))?;
            let outcome = self.sink.send(&front.packet.bytes);
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
                        .queue
                        .pop_front()
                        .ok_or_else(|| refused("source_starvation"))?;
                    if n != item.packet.bytes.len() {
                        return Err(refused("packet_write_partial"));
                    }
                    self.last = Some(completed);
                    self.stats.sent_packets += 1;
                    self.update_pending();
                    self.publish();
                    self.ensure()?;
                    if completed > cutoff {
                        return Err(refused("packet_write_delivery_cutoff"));
                    }
                    return Ok(item.digest);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.idle(cutoff.min(self.end))?
                }
                Err(error) => {
                    return Err(io::Error::new(error.kind(), Phase("strict_packet_write")));
                }
            }
        }
    }
    fn run_strict(
        &mut self,
        command: StrictCommand,
    ) -> io::Result<(Checkpoint, Option<std::time::Instant>)> {
        self.ensure()?;
        match command {
            StrictCommand::Block {
                start,
                points,
                ordinal,
            } => {
                let start = start.into_std();
                let mut hashes = Vec::with_capacity(points.len());
                for &point in points.iter() {
                    let target = start
                        .checked_add(Duration::from_nanos(point))
                        .ok_or_else(|| refused("public_point_clock"))?;
                    self.strict_target(target, ordinal)?;
                    self.gather(target, false, true)?;
                    hashes.push(self.strict_release(target)?);
                }
                let cutoff = start
                    .checked_add(Duration::from_millis(u64::from(self.settings.block_ms)))
                    .ok_or_else(|| refused("public_point_clock"))?;
                self.gather(cutoff, false, true)?;
                self.ensure()?;
                Ok((Checkpoint { ordinal, hashes }, Some(self.origin)))
            }
            StrictCommand::Buffering { start } => {
                let start = start.into_std();
                let cutoff = start
                    .checked_add(Duration::from_millis(u64::from(self.settings.buffering_ms)))
                    .ok_or_else(|| refused("buffering_clock"))?;
                let mut hashes = Vec::new();
                let mut initialized_origin = None;
                while self.ensure_now()? < cutoff {
                    let next = match self.queue.front() {
                        Some(q) => {
                            let scaled = u128::from(q.packet.arrived)
                                * u128::from(self.settings.lambda_pps)
                                / u128::from(self.settings.lambda_pps - self.settings.delta_pps);
                            start
                                .checked_add(Duration::from_nanos(
                                    scaled.try_into().map_err(|_| refused("buffering_clock"))?,
                                ))
                                .ok_or_else(|| refused("buffering_clock"))?
                        }
                        None => cutoff,
                    }
                    .min(cutoff);
                    let empty = self.queue.is_empty();
                    // Match Sender.gather's original get_or_insert, even if
                    // it finishes without receiving an original packet.
                    initialized_origin = Some(self.origin);
                    self.gather(next, empty, true)?;
                    if empty && self.now()? < cutoff {
                        continue;
                    }
                    if next == cutoff {
                        break;
                    }
                    self.strict_target(next, 0)?;
                    hashes.push(self.strict_release(next)?);
                }
                self.ensure()?;
                Ok((Checkpoint { ordinal: 0, hashes }, initialized_origin))
            }
            StrictCommand::Drain { ordinal, drain_end } => {
                let old_end = self.end;
                self.end = self.end.min(drain_end.into_std());
                let mut hashes = Vec::new();
                while !self.queue.is_empty() {
                    let target = self.ensure_now()?;
                    hashes.push(self.strict_release(target)?);
                }
                self.end = old_end;
                self.ensure()?;
                Ok((Checkpoint { ordinal, hashes }, None))
            }
        }
    }
}

#[cfg(test)]
#[path = "poisson_channel_command_tests.rs"]
mod tests;
