//! Owned cooperative packet timing CONTROL channel. Original packet bytes are
//! unchanged. Packetization, Poisson legitimacy and M/M/1 service are external
//! premises, not properties certified by this runtime or its localhost tests.
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{oneshot, Notify},
    task::JoinHandle,
    time::{sleep_until, Instant},
};
use zeroize::Zeroizing;

#[cfg(any(target_os = "macos", windows, test))]
#[path = "poisson_native_wait.rs"]
mod native_wait;
#[cfg(target_os = "linux")]
#[path = "poisson_owned_linux_timer.rs"]
mod owned_linux_timer;
#[cfg(any(target_os = "macos", test))]
#[path = "poisson_owned_qos.rs"]
mod owned_qos;
#[cfg(any(windows, test))]
#[path = "poisson_owned_windows_priority.rs"]
mod owned_windows_priority;
#[path = "poisson_channel_owner.rs"]
mod owner;
pub use owner::{OwnedScheduleReceipt, OwnedSender};

const DOMAIN: &[u8] = b"aegis.poisson-packet-control.v1";
const MAX_WORK: usize = 4_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub lambda_pps: u32,
    pub delta_pps: u32,
    pub reference_epsilon_milli: u16,
    pub service_mu_pps: u32,
    pub buffering_ms: u32,
    pub block_ms: u32,
    pub bits_per_block: u8,
    pub payload_capacity: u8,
    pub max_word_events: u16,
    pub fifo_packets: u16,
    pub total_packets: u16,
    pub packet_bytes: u16,
    pub ready_lead_ms: u32,
    pub clock_uncertainty_us: u32,
    pub release_lateness_us: u32,
    pub drain_ms: u32,
    pub finalize_ms: u32,
    pub precision_poll_budget: u32,
}
#[derive(Debug, Serialize)]
pub struct ConditionalReference {
    pub finite_kl_upper_approx_nats: f64,
    pub pinsker_upper_approx: f64,
    pub nominal_capacity_approx_nats_per_second: f64,
    pub integer_kl_admission_checked: bool,
    pub actual_poisson_process_verified: bool,
    pub actual_mm1_service_verified: bool,
}
impl Settings {
    pub fn blocks(&self) -> usize {
        ((usize::from(self.payload_capacity) + 18) * 8)
            .div_ceil(usize::from(self.bits_per_block.max(1)))
    }
    pub fn horizon(&self) -> Duration {
        Duration::from_millis(
            u64::from(self.buffering_ms) + self.blocks() as u64 * u64::from(self.block_ms),
        )
    }
    pub fn validate(&self) -> io::Result<()> {
        let work = self
            .blocks()
            .checked_mul(1usize << self.bits_per_block.min(7))
            .and_then(|n| n.checked_mul(usize::from(self.max_word_events)));
        if !(2..=10_000).contains(&self.lambda_pps)
            || self.delta_pps == 0
            || self.delta_pps >= self.lambda_pps
            || !(1..=1_000).contains(&self.reference_epsilon_milli)
            || !(1_000..=2_000_000).contains(&self.precision_poll_budget)
            || self.service_mu_pps <= self.lambda_pps
            || self.service_mu_pps > 1_000_000
            || !(10..=5_000).contains(&self.buffering_ms)
            || !(10..=1_000).contains(&self.block_ms)
            || !(1..=6).contains(&self.bits_per_block)
            || self.payload_capacity > 16
            || self.blocks() > 128
            || !(1..=512).contains(&self.max_word_events)
            || !(1..=2_048).contains(&self.fifo_packets)
            || self.total_packets < self.fifo_packets
            || self.total_packets > 8_192
            || !(1..=1_024).contains(&self.packet_bytes)
            || !(10..=5_000).contains(&self.ready_lead_ms)
            || self.clock_uncertainty_us == 0
            || self.clock_uncertainty_us > 20_000
            || self.release_lateness_us == 0
            || self.release_lateness_us > 20_000
            || self.drain_ms == 0
            || self.drain_ms > 2_000
            || !(100..=5_000).contains(&self.finalize_ms)
            || self.horizon() > Duration::from_secs(50)
            || work.is_none_or(|n| n > MAX_WORK)
        {
            return Err(refused("public_profile"));
        }
        // Conservative finite KL upper bound, exact integer admission:
        // D(P(lambda-delta)||P(lambda)) <= delta^2*T/(2*(lambda-delta)).
        // Pinsker requires KL <= 2*epsilon^2. This is conditional on a
        // genuine Poisson slowing process; actual failures/wire are NOT certified.
        if u128::from(self.delta_pps).pow(2) * u128::from(self.buffering_ms) * 1_000_000
            > 4 * u128::from(self.lambda_pps - self.delta_pps)
                * 1_000
                * u128::from(self.reference_epsilon_milli).pow(2)
        {
            return Err(refused("buffering_reference"));
        }
        let finite_rate = f64::from(self.bits_per_block) * std::f64::consts::LN_2 * 1_000.
            / f64::from(self.block_ms);
        let reference_capacity = f64::from(self.lambda_pps)
            * (f64::from(self.service_mu_pps) / f64::from(self.lambda_pps)).ln();
        if finite_rate >= reference_capacity {
            return Err(refused("declared_service_reference_capacity"));
        }
        Ok(())
    }
    pub fn conditional_reference(&self) -> io::Result<ConditionalReference> {
        self.validate()?;
        let delta = f64::from(self.delta_pps);
        let upper = delta * delta * f64::from(self.buffering_ms)
            / (2_000. * f64::from(self.lambda_pps - self.delta_pps));
        Ok(ConditionalReference {
            finite_kl_upper_approx_nats: upper,
            pinsker_upper_approx: (upper / 2.).sqrt(),
            nominal_capacity_approx_nats_per_second: f64::from(self.lambda_pps)
                * (f64::from(self.service_mu_pps) / f64::from(self.lambda_pps)).ln(),
            integer_kl_admission_checked: true,
            actual_poisson_process_verified: false,
            actual_mm1_service_verified: false,
        })
    }
    pub fn descriptor(&self) -> io::Result<[u8; 32]> {
        self.validate()?;
        Ok(Sha256::digest(serde_json::to_vec(self).map_err(|_| refused("public_profile"))?).into())
    }
}
#[derive(Debug)]
pub(crate) struct Phase(pub(crate) &'static str);
impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Phase {}
pub(crate) fn refused(phase: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, Phase(phase))
}
pub(crate) fn live(end: Instant) -> io::Result<()> {
    if Instant::now() >= end {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "poisson_original_clock",
        ))
    } else {
        Ok(())
    }
}
pub(crate) fn ns(start: Instant) -> io::Result<u64> {
    Instant::now()
        .checked_duration_since(start)
        .ok_or_else(|| refused("clock_before_origin"))?
        .as_nanos()
        .try_into()
        .map_err(|_| refused("clock_overflow"))
}

/// Fresh exporter material is consumed by one operation. No Clone/Debug.
pub struct Prepared {
    settings: Settings,
    key: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 12]>,
    padding: Zeroizing<Vec<u8>>,
    books: Zeroizing<Vec<Vec<Vec<u64>>>>,
    encoded: AtomicBool,
    digest: [u8; 32],
    preparation_work_steps: usize,
}
impl Prepared {
    pub fn new(settings: Settings, seed: Zeroizing<[u8; 32]>, end: Instant) -> io::Result<Self> {
        live(end)?;
        settings.validate()?;
        let descriptor = settings.descriptor()?;
        let kdf = Hkdf::<Sha256>::new(Some(&descriptor), seed.as_ref());
        let mut key = Zeroizing::new([0; 32]);
        let mut nonce = Zeroizing::new([0; 12]);
        kdf.expand(b"poisson.control.record.key.v1", key.as_mut())
            .map_err(|_| refused("material"))?;
        kdf.expand(b"poisson.control.record.nonce.v1", nonce.as_mut())
            .map_err(|_| refused("material"))?;
        let mut padding = Zeroizing::new(vec![0; usize::from(settings.payload_capacity) + 1]);
        kdf.expand(b"poisson.control.record.padding.v1", &mut padding)
            .map_err(|_| refused("material"))?;
        let mut preparation_work_steps = 0usize;
        let mut charge = || -> io::Result<()> {
            if preparation_work_steps >= MAX_WORK {
                return Err(refused("preparation_work_budget"));
            }
            preparation_work_steps += 1;
            Ok(())
        };
        let mut books = Zeroizing::new(Vec::with_capacity(settings.blocks()));
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(descriptor);
        for block in 0..settings.blocks() {
            let mut book = Zeroizing::new(Vec::new());
            for word in 0..1usize << settings.bits_per_block {
                charge()?;
                live(end)?;
                let mut info = b"poisson.control.codeword.v1".to_vec();
                info.extend_from_slice(&(block as u32).to_be_bytes());
                info.extend_from_slice(&(word as u32).to_be_bytes());
                let mut draws =
                    Zeroizing::new(vec![0; (usize::from(settings.max_word_events) + 1) * 8]);
                charge()?;
                kdf.expand(&info, &mut draws)
                    .map_err(|_| refused("material"))?;
                let mut draw_index = 0;
                let mut points = Zeroizing::new(Vec::new());
                let mut t = 0u64;
                loop {
                    charge()?;
                    live(end)?;
                    charge()?;
                    // Finite PRF draw + nanosecond ceil; this is computational,
                    // quantized Poisson, not an exact continuous random law.
                    let draw = u64::from_be_bytes(
                        draws[draw_index * 8..(draw_index + 1) * 8]
                            .try_into()
                            .map_err(|_| refused("draw_capacity"))?,
                    );
                    draw_index += 1;
                    let u = ((draw >> 12) as f64 + 0.5) / ((1u64 << 52) as f64);
                    let gap =
                        ((-u.ln() * 1e9 / f64::from(settings.lambda_pps)).ceil() as u64).max(1);
                    t = t
                        .checked_add(gap)
                        .ok_or_else(|| refused("codeword_clock"))?;
                    if t >= u64::from(settings.block_ms) * 1_000_000 {
                        break;
                    }
                    if points.len() == usize::from(settings.max_word_events) {
                        return Err(refused("codeword_capacity"));
                    }
                    points.push(t);
                }
                charge()?;
                digest.update((points.len() as u16).to_be_bytes());
                for t in points.iter() {
                    charge()?;
                    digest.update(t.to_be_bytes());
                }
                book.push(std::mem::take(&mut *points));
            }
            books.push(std::mem::take(&mut *book));
        }
        live(end)?;
        Ok(Self {
            settings,
            key,
            nonce,
            padding,
            books,
            encoded: AtomicBool::new(false),
            digest: digest.finalize().into(),
            preparation_work_steps,
        })
    }
    pub fn preparation_work_steps(&self) -> usize {
        self.preparation_work_steps
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn settings(&self) -> &Settings {
        &self.settings
    }
    pub fn encode(&self, input: &[u8]) -> io::Result<Zeroizing<Vec<usize>>> {
        if self.encoded.swap(true, Ordering::AcqRel) {
            return Err(refused("record_material_already_used"));
        }
        if input.len() > usize::from(self.settings.payload_capacity) {
            return Err(refused("input_capacity"));
        }
        let mut plain = Zeroizing::new(vec![0; usize::from(self.settings.payload_capacity) + 2]);
        plain[..2].copy_from_slice(&(input.len() as u16).to_be_bytes());
        plain[2..2 + input.len()].copy_from_slice(input);
        plain[2 + input.len()..].copy_from_slice(
            &self.padding[..usize::from(self.settings.payload_capacity) - input.len()],
        );
        let aad = self.settings.descriptor()?;
        let mut ciphertext = Zeroizing::new(
            ChaCha20Poly1305::new((&*self.key).into())
                .encrypt(
                    (&*self.nonce).into(),
                    Payload {
                        msg: &plain,
                        aad: &aad,
                    },
                )
                .map_err(|_| refused("record_encrypt"))?,
        );
        ciphertext.push(self.padding[usize::from(self.settings.payload_capacity)]);
        let bits = usize::from(self.settings.bits_per_block);
        Ok(Zeroizing::new(
            (0..self.settings.blocks())
                .map(|block| {
                    (0..bits).fold(0usize, |v, bit| {
                        let i = block * bits + bit;
                        (v << 1) | usize::from((ciphertext[i / 8] >> (7 - i % 8)) & 1)
                    })
                })
                .collect(),
        ))
    }
    pub fn decode_record(&self, words: &[usize]) -> io::Result<Zeroizing<Vec<u8>>> {
        if words.len() != self.settings.blocks()
            || words
                .iter()
                .any(|w| *w >= 1usize << self.settings.bits_per_block)
        {
            return Err(refused("decoded_word_range"));
        }
        let size = usize::from(self.settings.payload_capacity) + 18;
        let mut cipher = Zeroizing::new(vec![0; size]);
        let bits = usize::from(self.settings.bits_per_block);
        for (block, word) in words.iter().enumerate() {
            for bit in 0..bits {
                let i = block * bits + bit;
                if i < size * 8 {
                    cipher[i / 8] |= (((word >> (bits - 1 - bit)) & 1) as u8) << (7 - i % 8);
                }
            }
        }
        let aad = self.settings.descriptor()?;
        let plain = Zeroizing::new(
            ChaCha20Poly1305::new((&*self.key).into())
                .decrypt(
                    (&*self.nonce).into(),
                    Payload {
                        msg: &cipher,
                        aad: &aad,
                    },
                )
                .map_err(|_| refused("decoded_record_authentication"))?,
        );
        let n = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
        if n > usize::from(self.settings.payload_capacity) {
            return Err(refused("decoded_record_length"));
        }
        Ok(Zeroizing::new(plain[2..2 + n].to_vec()))
    }
    pub fn book(&self, block: usize) -> io::Result<&[Vec<u64>]> {
        self.books
            .get(block)
            .map(Vec::as_slice)
            .ok_or_else(|| refused("block_range"))
    }
    /// Conditional service-likelihood reference. With nonzero uncertainty,
    /// upper-endpoint scoring is an approximation, NOT exact marginalized ML.
    /// Actual timestamps are inputs, never synthetic M/M/1 departures. The
    /// caller must authenticate the assembled record before exposing any hint.
    pub fn decode_arrivals(
        &self,
        block: usize,
        departures: &[u64],
        previous: u64,
        uncertainty: u64,
    ) -> io::Result<usize> {
        if departures.len() > usize::from(self.settings.max_word_events)
            || departures.windows(2).any(|w| w[0] > w[1])
        {
            return Err(refused("arrival_order"));
        }
        let mut best = None;
        let mut tied = false;
        for (word, arrivals) in self.book(block)?.iter().enumerate() {
            if arrivals.len() != departures.len() {
                continue;
            }
            let mut prev = previous;
            let mut score = 0.;
            let mut possible = true;
            for (&a, &d) in arrivals.iter().zip(departures) {
                let upper = d
                    .checked_add(uncertainty)
                    .ok_or_else(|| refused("arrival_clock"))?;
                let earliest = prev.max(a);
                if upper < earliest {
                    possible = false;
                    break;
                }
                score -= f64::from(self.settings.service_mu_pps) * (upper - earliest) as f64 / 1e9;
                prev = d;
            }
            if possible {
                match best {
                    None => {
                        best = Some((word, score));
                        tied = false;
                    }
                    Some((_, old)) if score > old => {
                        best = Some((word, score));
                        tied = false;
                    }
                    Some((_, old)) if score == old => tied = true,
                    _ => {}
                }
            }
        }
        if tied {
            return Err(refused("arrival_decode_ambiguous"));
        }
        best.map(|(w, _)| w)
            .ok_or_else(|| refused("arrival_decode_impossible"))
    }
}

/// One original post-send refusal: numeric intervals from the same Service.
/// No absolute timestamp, payload, address, seed or receiver-delivery ACK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceCutoffObservation {
    pub event_ordinal: u64,
    pub admission_lateness_ns: u64,
    pub pending_wait_ns: u64,
    pub write_observation_bracket_ns: u64,
    pub completion_lateness_ns: u64,
    pub original_allowance_ns: u64,
}

/// First Darwin admission refusal in the real owned macOS release thread.
/// All clocks are intervals around the original point; no absolute Instant,
/// codebook point, address, packet, payload or secret enters the receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DarwinAdmissionMissObservation {
    pub event_ordinal: u64,
    pub block_ordinal: u16,
    pub original_allowance_ns: u64,
    pub observed_lateness_ns: u64,
    pub cutoff_excess_ns: u64,
    pub qos_requested_class: Option<u32>,
    pub qos_readback_matched: bool,
    pub mach_policy_readback_matched: bool,
    pub last_wait_present: bool,
    pub last_wait_point_matches_admission: bool,
    pub no_intervening_io_attempt: bool,
    pub gather_point_matches_admission: bool,
    pub last_wait_coarse: Option<bool>,
    pub last_wait_call_interval_ns: Option<u64>,
    pub last_wait_wake_overshoot_ns: Option<u64>,
    pub last_wait_return_to_gather_ns: Option<u64>,
    pub gather_to_admission_ns: Option<u64>,
    pub last_wait_return_to_admission_ns: Option<u64>,
}

#[derive(Clone, Default, Debug, Serialize)]
pub struct Observations {
    pub accepted_packets: usize,
    pub sent_packets: usize,
    pub received_packets: usize,
    pub delivered_packets: usize,
    pub retained_packets: usize,
    pub precision_polls: usize,
    pub missed_public_points: usize,
    pub observed_point_lateness_ns: u64,
    pub missed_public_block_ordinal: Option<u16>,
    pub prior_completed_write_reached_missed_target: bool,
    pub native_work_steps: usize,
    pub preparation_work_steps: usize,
    pub service_queue_admissions: usize,
    pub pending_service_packets: usize,
    pub maximum_admission_lateness_ns: u64,
    pub maximum_service_wait_ns: u64,
    pub maximum_service_duration_ns: u64,
    pub service_queue_contract_v2: bool,
    pub native_clock_polls: usize,
    pub native_recv_attempts: usize,
    pub native_send_attempts: usize,
    pub native_source_reads_completed: usize,
    pub native_park_calls: usize,
    pub native_fine_sleep_calls: usize,
    pub native_absolute_coarse_wait_calls: usize,
    pub native_absolute_fine_wait_calls: usize,
    pub native_spin_steps: usize,
    pub release_thread_started: bool,
    pub release_thread_terminal: bool,
    pub release_thread_joined: bool,
    pub release_cancel_requested: bool,
    /// Command-local custody facts; packet counters above remain historical
    /// observations, not a claim that discarded buffers can be recovered.
    pub strict_command_custody_consumed: bool,
    pub strict_command_custody_restored: bool,
    pub strict_command_buffers_discarded: bool,
    pub strict_command_preparation_failed: bool,
    pub collector_started: bool,
    pub collector_joined: bool,
    pub collector_abort_requested: bool,
    pub service_model_verified: bool,
    pub warden_packetization_verified: bool,
    /// Omitted when absent; Observations remains Serialize-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_cutoff: Option<ServiceCutoffObservation>,
    #[cfg(target_os = "macos")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub darwin_admission_miss: Option<DarwinAdmissionMissObservation>,
}
#[derive(Clone, Default)]
pub(crate) struct Observer(Arc<Mutex<Observations>>);
impl Observer {
    pub(crate) fn snapshot(&self) -> Observations {
        self.0.lock().map(|s| s.clone()).unwrap_or_default()
    }
    fn update(&self, stats: &Observations) {
        if let Ok(mut s) = self.0.lock() {
            *s = stats.clone();
        }
    }
    fn edit(&self, f: impl FnOnce(&mut Observations)) {
        if let Ok(mut s) = self.0.lock() {
            f(&mut s);
        }
    }
    // Intermediate telemetry must never make the owned release thread wait
    // for a reader. The worker retains its authoritative counters and uses
    // the complete blocking publication after packet processing terminates.
    fn try_edit(&self, f: impl FnOnce(&mut Observations)) -> bool {
        if let Ok(mut s) = self.0.try_lock() {
            f(&mut s);
            true
        } else {
            false
        }
    }
}
/// Authenticated metadata only; never word index, plaintext or ciphertext.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub ordinal: u16,
    pub hashes: Vec<[u8; 32]>,
}
// Wake before the public point, then yield cooperatively. This is bounded work,
// not a real-time scheduler guarantee. A genuinely expired next point still fails.
#[cfg(test)]
async fn precise_wait(point: Instant, end: Instant, work: &mut usize, cap: u32) -> io::Result<()> {
    let early = point.checked_sub(Duration::from_millis(2)).unwrap_or(point);
    if Instant::now() < early {
        sleep_until(early.min(end)).await;
    }
    while Instant::now() < point {
        live(end)?;
        if *work >= cap as usize {
            return Err(refused("precision_work_budget"));
        }
        *work += 1;
        tokio::task::yield_now().await;
    }
    live(end)
}

struct Packet {
    bytes: Zeroizing<Vec<u8>>,
    arrived: u64,
}
// Per-Sender test witness only; never part of public wire observations.
#[cfg(all(test, windows))]
#[derive(Default)]
struct StrictThreadPreparationObservation {
    native_api_attempts: u64,
    requested_priority_readback_present: bool,
}

pub struct Sender {
    source: Option<UdpSocket>,
    sink: Option<UdpSocket>,
    queue: VecDeque<Packet>,
    observer: Observer,
    origin: Option<Instant>,
    last_completed_write: Option<Instant>,
    #[cfg(test)]
    completion_observation_delay: Option<Duration>,
    #[cfg(all(test, windows))]
    strict_thread_preparation: Arc<Mutex<StrictThreadPreparationObservation>>,
    pub observations: Observations,
}
impl Sender {
    pub fn new(source: UdpSocket, sink: UdpSocket) -> io::Result<Self> {
        source.peer_addr()?;
        sink.peer_addr()?;
        Ok(Self {
            source: Some(source),
            sink: Some(sink),
            queue: VecDeque::new(),
            observer: Observer::default(),
            origin: None,
            last_completed_write: None,
            #[cfg(test)]
            completion_observation_delay: None,
            #[cfg(all(test, windows))]
            strict_thread_preparation: Arc::new(Mutex::new(
                StrictThreadPreparationObservation::default(),
            )),
            observations: Observations::default(),
        })
    }
    pub(crate) fn observe(&mut self, observer: Observer) {
        self.observer = observer;
    }
    #[cfg(test)]
    async fn gather(
        &mut self,
        until: Instant,
        origin: Instant,
        s: &Settings,
        end: Instant,
        first_only: bool,
    ) -> io::Result<()> {
        let packet_origin = *self.origin.get_or_insert(origin);
        let mut bytes = Zeroizing::new(vec![0; usize::from(s.packet_bytes) + 1]);
        loop {
            live(end)?;
            if Instant::now() >= until {
                return Ok(());
            }
            tokio::select! {biased;
                wait=precise_wait(until,end,&mut self.observations.precision_polls,s.precision_poll_budget)=>{self.observer.update(&self.observations);wait?;return Ok(());},
                received=self.source.as_ref().ok_or_else(|| refused("strict_sender_consumed"))?.recv(&mut bytes)=>{
                    let n=received?;live(end)?;
                    if n>usize::from(s.packet_bytes){return Err(refused("source_packet_capacity"));}
                    let arrived=ns(packet_origin)?;
                    self.queue.push_back(Packet{bytes:Zeroizing::new(bytes[..n].to_vec()),arrived});
                    self.observations.accepted_packets+=1; self.observations.retained_packets=self.queue.len();self.observer.update(&self.observations);
                    if self.queue.len()>usize::from(s.fifo_packets)||self.observations.accepted_packets>usize::from(s.total_packets){return Err(refused("source_fifo_capacity"));}
                    if first_only { return Ok(()); }
                }
            }
        }
    }
    #[cfg(test)]
    fn check_public_target(
        &mut self,
        target: Instant,
        s: &Settings,
        ordinal: u16,
        end: Instant,
    ) -> io::Result<()> {
        live(end)?;
        let observed = Instant::now();
        if observed >= target {
            self.observations.missed_public_points += 1;
            self.observations.observed_point_lateness_ns = observed
                .duration_since(target)
                .as_nanos()
                .try_into()
                .unwrap_or(u64::MAX);
            self.observations.missed_public_block_ordinal = Some(ordinal);
            self.observations
                .prior_completed_write_reached_missed_target = self
                .last_completed_write
                .is_some_and(|completed| completed >= target);
            self.observer.update(&self.observations);
        }
        if self
            .last_completed_write
            .is_some_and(|completed| completed >= target)
        {
            return Err(refused("public_point_prior_write_overlap"));
        }
        if observed
            > target
                .checked_add(Duration::from_micros(u64::from(s.release_lateness_us)))
                .ok_or_else(|| refused("public_point_clock"))?
        {
            return Err(refused("public_point_delivery_cutoff"));
        }
        Ok(())
    }
    #[cfg(test)]
    async fn release(
        &mut self,
        target: Instant,
        s: &Settings,
        end: Instant,
    ) -> io::Result<[u8; 32]> {
        live(end)?;
        if Instant::now()
            .checked_duration_since(target)
            .is_some_and(|d| d > Duration::from_micros(u64::from(s.release_lateness_us)))
        {
            return Err(refused("release_late"));
        }
        let packet = self
            .queue
            .front()
            .ok_or_else(|| refused("source_starvation"))?;
        let origin = self
            .origin
            .ok_or_else(|| refused("source_origin_missing"))?;
        let target_ns: u64 = target
            .checked_duration_since(origin)
            .ok_or_else(|| refused("source_origin_order"))?
            .as_nanos()
            .try_into()
            .map_err(|_| refused("source_clock"))?;
        if packet.arrived > target_ns {
            return Err(refused("source_unavailable_at_public_point"));
        }
        let digest: [u8; 32] = Sha256::digest(&packet.bytes).into();
        let n = tokio::time::timeout_at(
            end,
            self.sink
                .as_ref()
                .ok_or_else(|| refused("strict_sender_consumed"))?
                .send(&packet.bytes),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "packet_write"))??;
        if n != packet.bytes.len() {
            return Err(refused("packet_write_partial"));
        }
        #[cfg(test)]
        if let Some(delay) = self.completion_observation_delay {
            std::thread::sleep(delay);
        }
        self.last_completed_write = Some(Instant::now());
        self.queue.pop_front();
        self.observations.sent_packets += 1;
        self.observations.retained_packets = self.queue.len();
        self.observer.update(&self.observations);
        live(end)?;
        if self.last_completed_write.is_some_and(|completed| {
            completed > target + Duration::from_micros(u64::from(s.release_lateness_us))
        }) {
            return Err(refused("packet_write_delivery_cutoff"));
        }
        Ok(digest)
    }
    pub async fn buffering(
        &mut self,
        start: Instant,
        s: &Settings,
        end: Instant,
    ) -> io::Result<Checkpoint> {
        s.validate()?;
        live(end)?;
        owner::execute_strict(self, owner::StrictCommand::Buffering { start }, s, end).await
    }
    pub async fn block(
        &mut self,
        start: Instant,
        points: &[u64],
        s: &Settings,
        ordinal: u16,
        end: Instant,
    ) -> io::Result<Checkpoint> {
        s.validate()?;
        live(end)?;
        if points.len() > usize::from(s.max_word_events)
            || points.windows(2).any(|p| p[0] >= p[1])
            || points
                .iter()
                .any(|&p| p >= u64::from(s.block_ms) * 1_000_000)
        {
            return Err(refused("public_schedule_capacity_or_order"));
        }
        owner::execute_strict(
            self,
            owner::StrictCommand::Block {
                start,
                points: Zeroizing::new(points.to_vec()),
                ordinal,
            },
            s,
            end,
        )
        .await
    }
    pub async fn drain(
        &mut self,
        s: &Settings,
        ordinal: u16,
        end: Instant,
    ) -> io::Result<Checkpoint> {
        s.validate()?;
        live(end)?;
        let drain_end = (Instant::now() + Duration::from_millis(u64::from(s.drain_ms))).min(end);
        owner::execute_strict(
            self,
            owner::StrictCommand::Drain { ordinal, drain_end },
            s,
            end,
        )
        .await
    }
}

struct Arrival {
    bytes: Zeroizing<Vec<u8>>,
    ns: u64,
}
struct Collected {
    packets: VecDeque<Arrival>,
    count: usize,
    error: Option<CollectorFailure>,
}

// Preserve a closed protocol phase and the original I/O kind, never arbitrary
// error text. A collector refusal remains observable while TLS awaits metadata.
struct CollectorFailure {
    kind: io::ErrorKind,
    phase: Option<&'static str>,
}
impl CollectorFailure {
    fn capture(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            phase: error
                .get_ref()
                .and_then(|e| e.downcast_ref::<Phase>())
                .map(|p| p.0),
        }
    }
    fn error(&self) -> io::Error {
        match self.phase {
            Some(phase) => io::Error::new(self.kind, Phase(phase)),
            None => io::Error::new(self.kind, "collector_failed"),
        }
    }
}
/// Owns exactly one UDP collector task. Drop aborts that task, never a flow or
/// process by name. Successful stop waits for its real terminal result.
pub struct Receiver {
    observer: Observer,
    state: Arc<Mutex<Collected>>,
    notify: Arc<Notify>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    sink: UdpSocket,
    pub observations: Observations,
}
impl Drop for Receiver {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            self.observer.edit(|s| s.collector_abort_requested = true);
            task.abort();
        }
    }
}
impl Receiver {
    pub fn new(
        source: UdpSocket,
        sink: UdpSocket,
        s: Settings,
        origin: Instant,
        end: Instant,
    ) -> io::Result<Self> {
        Self::new_observed(source, sink, s, origin, end, Observer::default())
    }
    pub(crate) fn new_observed(
        source: UdpSocket,
        sink: UdpSocket,
        s: Settings,
        origin: Instant,
        end: Instant,
        observer: Observer,
    ) -> io::Result<Self> {
        s.validate()?;
        live(end)?;
        s.validate()?;
        source.peer_addr()?;
        sink.peer_addr()?;
        live(end)?;
        let state = Arc::new(Mutex::new(Collected {
            packets: VecDeque::new(),
            count: 0,
            error: None,
        }));
        let notify = Arc::new(Notify::new());
        let (stop_tx, mut stop_rx) = oneshot::channel();
        observer.edit(|s| s.collector_started = true);
        let saved = state.clone();
        let ready = notify.clone();
        let observed = observer.clone();
        let task = tokio::spawn(async move {
            let mut bytes = Zeroizing::new(vec![0; usize::from(s.packet_bytes) + 1]);
            loop {
                tokio::select! {biased;
                    _=&mut stop_rx=>break,
                    _=sleep_until(end)=>{if let Ok(mut q)=saved.lock(){q.error=Some(CollectorFailure::capture(io::Error::from(io::ErrorKind::TimedOut)));}ready.notify_one();break;},
                    result=source.recv(&mut bytes)=>{
                        // After the first awaited arrival, drain a bounded
                        // ready batch without yielding to the reactor for each
                        // datagram. Every packet keeps its own real receive
                        // timestamp, capacity check and original end guard.
                        // The next outer select observes stop/deadline again.
                        let mut first=Some(result);
                        for _ in 0..usize::from(s.fifo_packets).min(256) {
                            let result=match first.take(){
                                Some(result)=>result,
                                None=>match source.try_recv(&mut bytes){
                                    Err(e) if e.kind()==io::ErrorKind::WouldBlock=>break,
                                    other=>other,
                                },
                            };
                            let result=result.and_then(|n|{live(end)?;if n>usize::from(s.packet_bytes){return Err(refused("receiver_packet_capacity"));}Ok((n,ns(origin)?))});
                            let Ok(mut q)=saved.lock()else{return;};
                            match result{Ok((n,stamp))if q.count<usize::from(s.total_packets)=>{q.packets.push_back(Arrival{bytes:Zeroizing::new(bytes[..n].to_vec()),ns:stamp});q.count+=1;observed.edit(|s|{s.received_packets+=1;s.retained_packets=q.packets.len();});},Ok(_)=>q.error=Some(CollectorFailure::capture(io::Error::from(io::ErrorKind::OutOfMemory))),Err(e)=>q.error=Some(CollectorFailure::capture(e))};
                            let failed=q.error.is_some();drop(q);ready.notify_one();if failed{return;}
                        }
                    }
                }
            }
        });
        Ok(Self {
            observer,
            state,
            notify,
            stop: Some(stop_tx),
            task: Some(task),
            sink,
            observations: Observations::default(),
        })
    }
    pub async fn checkpoint(
        &mut self,
        c: &Checkpoint,
        max: usize,
        end: Instant,
    ) -> io::Result<Vec<u64>> {
        if c.hashes.len() > max {
            return Err(refused("checkpoint_capacity"));
        }
        let mut stamps = Vec::with_capacity(c.hashes.len());
        for expected in &c.hashes {
            let packet = loop {
                live(end)?;
                let notified = self.notify.notified();
                {
                    let mut q = self.state.lock().map_err(|_| refused("collector_lock"))?;
                    if let Some(error) = &q.error {
                        return Err(error.error());
                    }
                    if let Some(packet) = q.packets.pop_front() {
                        break packet;
                    }
                }
                tokio::time::timeout_at(end, notified)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "packet_missing"))?;
            };
            self.observations.received_packets += 1;
            let actual: [u8; 32] = Sha256::digest(&packet.bytes).into();
            if actual != *expected {
                return Err(refused("original_packet_identity"));
            }
            let n = tokio::time::timeout_at(end, self.sink.send(&packet.bytes))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "application_write"))??;
            if n != packet.bytes.len() {
                return Err(refused("application_write_partial"));
            }
            self.observations.delivered_packets += 1;
            self.observer.edit(|s| {
                s.delivered_packets += 1;
                s.retained_packets = s.retained_packets.saturating_sub(1);
            });
            stamps.push(packet.ns);
            live(end)?;
        }
        live(end)?;
        Ok(stamps)
    }
    /// Observe failure without consuming it or borrowing a fresh clock. This
    /// is used only while the protocol awaits its metadata, before checkpoints.
    pub(crate) async fn wait_failure(&self, end: Instant) -> io::Result<()> {
        loop {
            live(end)?;
            let notified = self.notify.notified();
            {
                let q = self.state.lock().map_err(|_| refused("collector_lock"))?;
                if let Some(error) = &q.error {
                    return Err(error.error());
                }
            }
            tokio::time::timeout_at(end, notified)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "poisson_original_clock"))?;
        }
    }
    /// Retire a failed operation within its original deadline. Requesting abort
    /// alone is not proof of termination; only awaiting the handle supplies it.
    pub(crate) async fn abort_and_join_until(&mut self, end: Instant) -> io::Result<()> {
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        self.observer.edit(|s| s.collector_abort_requested = true);
        task.abort();
        live(end)?;
        let terminal = tokio::time::timeout_at(end, task)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "collector_join"))?;
        self.task.take();
        self.observer.edit(|s| s.collector_joined = true);
        match terminal {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(_) => Err(refused("collector_terminal")),
        }
    }
    pub async fn finish(&mut self, end: Instant) -> io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let task = self
            .task
            .as_mut()
            .ok_or_else(|| refused("collector_already_joined"))?;
        let terminal = tokio::time::timeout_at(end, task)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "collector_join"))?;
        self.task.take();
        self.observer.edit(|s| s.collector_joined = true);
        terminal.map_err(|_| refused("collector_terminal"))?;
        live(end)?;
        let q = self.state.lock().map_err(|_| refused("collector_lock"))?;
        if let Some(error) = &q.error {
            return Err(error.error());
        }
        if !q.packets.is_empty() {
            return Err(refused("collector_extra_or_failed"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "poisson_channel_tests.rs"]
mod tests;
