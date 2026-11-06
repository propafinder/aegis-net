//! Separate paired control operation over explicitly owned cooperative UDP.
//! TLS metadata has fixed public lengths/timing and never carries the encoded
//! message/index. Only actual UDP arrivals reconstruct the authenticated hint.
use super::{Client, Server};
use crate::{
    carrier_runtime::PrivacySettings,
    traffic_privacy::poisson_channel::{
        self as timing, Checkpoint, Observations, OwnedSender, Prepared, Receiver, Sender, Settings,
    },
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    time::{sleep_until, timeout_at, Instant},
};
use zeroize::Zeroizing;
// v3 peers must roll out together: a v2 admission is refused before any UDP
// operation. The selected bound assumes negligible relative monotonic clock
// drift between this handshake and the public start; it is not a drift proof.
const ADMISSION: &[u8; 8] = b"APCT\x03\0\0\0";
const CLOCK_SYNC_ROUNDS: usize = 5;
const EXPORTER_LABEL: &[u8] = b"aegis.poisson.control.seed.v3";
const ACCEPT: u8 = 0xa1;
const ARMED: u8 = 0xa2;
const DECODED: u8 = 0xa3;
const MAX_METADATA: usize = 4 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub resource_sha256: [u8; 32],
    pub sender_application_bind: SocketAddr,
    pub sender_application_peer: SocketAddr,
    pub sender_packet_bind: SocketAddr,
    pub receiver_packet_bind: SocketAddr,
    pub receiver_application_bind: SocketAddr,
    pub receiver_application_peer: SocketAddr,
    pub timing: Settings,
}
impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PoissonControlProfile([redacted application resources])")
    }
}
impl Profile {
    pub fn validate(&self) -> io::Result<()> {
        self.timing.validate()?;
        let app = [
            self.sender_application_bind,
            self.sender_application_peer,
            self.receiver_application_bind,
            self.receiver_application_peer,
        ];
        let all = [
            self.sender_application_bind,
            self.sender_application_peer,
            self.sender_packet_bind,
            self.receiver_packet_bind,
            self.receiver_application_bind,
            self.receiver_application_peer,
        ];
        if self.resource_sha256 == [0; 32]
            || app.iter().any(|a| !a.ip().is_loopback())
            || all
                .iter()
                .any(|a| a.port() == 0 || a.ip().is_unspecified() || a.ip().is_multicast())
            || all.iter().enumerate().any(|(i, a)| all[..i].contains(a))
        {
            return Err(timing::refused("application_resource_profile"));
        }
        self.metadata_size()?;
        Ok(())
    }
    pub fn descriptor(&self) -> io::Result<[u8; 32]> {
        self.validate()?;
        Ok(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| timing::refused("profile_serialize"))?,
        )
        .into())
    }
    fn metadata_size(&self) -> io::Result<usize> {
        let size = (usize::from(self.timing.total_packets) * 2
            + usize::from(self.timing.max_word_events) * self.timing.blocks())
        .checked_mul(32)
        .and_then(|n| n.checked_add((self.timing.blocks() + 2) * 4 + 8))
        .ok_or_else(|| timing::refused("metadata_capacity"))?;
        if size > MAX_METADATA {
            return Err(timing::refused("metadata_capacity"));
        }
        Ok(size)
    }
    fn capacity(&self, slot: usize) -> usize {
        if slot == 0 || slot == self.timing.blocks() + 1 {
            usize::from(self.timing.total_packets)
        } else {
            usize::from(self.timing.max_word_events)
        }
    }
}
/// No new operation reads/binds sockets without an explicit validated profile.
pub async fn sender_plane(p: &Profile, end: Instant) -> io::Result<Sender> {
    p.validate()?;
    timing::live(end)?;
    let source = UdpSocket::bind(p.sender_application_bind).await?;
    source.connect(p.sender_application_peer).await?;
    let sink = UdpSocket::bind(p.sender_packet_bind).await?;
    sink.connect(p.receiver_packet_bind).await?;
    timing::live(end)?;
    Sender::new(source, sink)
}
pub async fn receiver_plane(p: &Profile, start: Instant, end: Instant) -> io::Result<Receiver> {
    p.validate()?;
    timing::live(end)?;
    let source = UdpSocket::bind(p.receiver_packet_bind).await?;
    source.connect(p.sender_packet_bind).await?;
    let sink = UdpSocket::bind(p.receiver_application_bind).await?;
    sink.connect(p.receiver_application_peer).await?;
    timing::live(end)?;
    Receiver::new(source, sink, p.timing.clone(), start, end)
}
#[derive(Debug, Serialize)]
pub struct Receipt {
    pub timing_control_authenticated: bool,
    pub conditional_reference: timing::ConditionalReference,
    pub observations: Observations,
    pub logical_packets_preserved: bool,
    pub authenticated_payload_digest_sequence_matched: bool,
    pub application_origin_and_unique_sequence_verified: bool,
    pub installed_full_wide: bool,
    pub collector_terminal: bool,
}
#[derive(Debug, Serialize)]
pub struct Failure {
    pub error_kind: String,
    pub phase: &'static str,
    pub confirmed_prefix: Observations,
    pub accepted_delivery_complete: bool,
    pub packet_io_outcome_may_be_unknown: bool,
    pub owned_pending_disposition: &'static str,
}
impl Failure {
    fn capture(error: io::Error, observer: &timing::Observer) -> Self {
        let phase = error
            .get_ref()
            .and_then(|e| e.downcast_ref::<timing::Phase>())
            .map_or("external_io", |p| p.0);
        let confirmed_prefix = observer.snapshot();
        let owned_pending_disposition = if confirmed_prefix.release_thread_started
            && !confirmed_prefix.release_thread_terminal
        {
            "cancellation_requested_terminal_unobserved"
        } else if confirmed_prefix.collector_started && !confirmed_prefix.collector_joined {
            "collector_abort_requested_terminal_unobserved"
        } else {
            "owned_terminal_drop_zeroizes_pending_bytes"
        };
        Self {
            error_kind: format!("{:?}", error.kind()),
            phase,
            confirmed_prefix,
            accepted_delivery_complete: false,
            packet_io_outcome_may_be_unknown: true,
            owned_pending_disposition,
        }
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "poisson control refused at {} ({})",
            self.phase, self.error_kind
        )
    }
}
impl std::error::Error for Failure {}
pub struct Received {
    pub payload: Zeroizing<Vec<u8>>,
    pub receipt: Receipt,
}
fn preflight(
    p: &Profile,
    shaping: &Option<PrivacySettings>,
    origin: Instant,
    end: Instant,
) -> io::Result<()> {
    p.validate()?;
    timing::live(end)?;
    if shaping.is_some()
        || origin > Instant::now()
        || end
            .checked_duration_since(origin)
            .is_none_or(|d| d > Duration::from_secs(60))
    {
        return Err(timing::refused("exclusive_owner_or_clock"));
    }
    Ok(())
}
fn elapsed(origin: Instant) -> io::Result<u64> {
    timing::ns(origin)
}
// A single delayed scheduler wakeup must not turn an otherwise viable,
// authenticated operation into a false clock refusal. Every public v3
// exchange performs the same fixed number of rounds. The minimum uncertainty
// is the tightest valid bound; a malformed timestamp still fails closed.
fn clock_sample(t0: u64, b1: u64, b2: u64, t3: u64) -> io::Result<(u64, i128)> {
    let remote = b2
        .checked_sub(b1)
        .ok_or_else(|| timing::refused("clock_sync_order"))?;
    let roundtrip = t3
        .checked_sub(t0)
        .ok_or_else(|| timing::refused("clock_sync_order"))?;
    let uncertainty = roundtrip
        .checked_sub(remote)
        .ok_or_else(|| timing::refused("clock_sync_order"))?
        .div_ceil(2);
    let offset = (i128::from(b1) - i128::from(t0) + i128::from(b2) - i128::from(t3)) / 2;
    Ok((uncertainty, offset))
}
fn choose_clock_sample(best: Option<(u64, i128)>, sample: (u64, i128)) -> Option<(u64, i128)> {
    match best {
        Some(prior) if prior.0 <= sample.0 => Some(prior),
        _ => Some(sample),
    }
}
async fn sender_clock_sync<S, F>(stream: &mut S, mut now: F, cap_ns: u64) -> io::Result<(u64, i128)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> io::Result<u64>,
{
    let mut best = None;
    for _ in 0..CLOCK_SYNC_ROUNDS {
        let t0 = now()?;
        stream.write_u64(t0).await?;
        stream.flush().await?;
        let b1 = stream.read_u64().await?;
        let b2 = stream.read_u64().await?;
        let t3 = now()?;
        best = choose_clock_sample(best, clock_sample(t0, b1, b2, t3)?);
    }
    let selected = best.ok_or_else(|| timing::refused("clock_sync_order"))?;
    if selected.0 > cap_ns {
        return Err(timing::refused("clock_sync_uncertainty"));
    }
    Ok(selected)
}
fn metadata(p: &Profile, checkpoints: &[Checkpoint]) -> io::Result<Zeroizing<Vec<u8>>> {
    if checkpoints.len() != p.timing.blocks() + 2 {
        return Err(timing::refused("checkpoint_count"));
    }
    let mut bytes = Zeroizing::new(vec![0; p.metadata_size()?]);
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| timing::refused("metadata_entropy"))?;
    bytes[..8].copy_from_slice(ADMISSION);
    let mut offset = 8;
    for (slot, c) in checkpoints.iter().enumerate() {
        let cap = p.capacity(slot);
        if usize::from(c.ordinal) != slot || c.hashes.len() > cap {
            return Err(timing::refused("checkpoint_count"));
        }
        bytes[offset..offset + 2].copy_from_slice(&c.ordinal.to_be_bytes());
        bytes[offset + 2..offset + 4].copy_from_slice(&(c.hashes.len() as u16).to_be_bytes());
        offset += 4;
        for (i, hash) in c.hashes.iter().enumerate() {
            bytes[offset + i * 32..offset + (i + 1) * 32].copy_from_slice(hash);
        }
        offset += cap * 32;
    }
    Ok(bytes)
}
fn parse_metadata(p: &Profile, bytes: &[u8]) -> io::Result<Vec<Checkpoint>> {
    if bytes.len() != p.metadata_size()? || &bytes[..8] != ADMISSION {
        return Err(timing::refused("metadata_frame"));
    }
    let mut offset = 8;
    let mut checkpoints = Vec::new();
    let mut count = 0usize;
    for slot in 0..p.timing.blocks() + 2 {
        let ordinal = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let n = usize::from(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]));
        offset += 4;
        let cap = p.capacity(slot);
        if usize::from(ordinal) != slot || n > cap {
            return Err(timing::refused("metadata_count"));
        }
        count = count
            .checked_add(n)
            .ok_or_else(|| timing::refused("metadata_count"))?;
        if count > usize::from(p.timing.total_packets) {
            return Err(timing::refused("metadata_total"));
        }
        let hashes = (0..n)
            .map(|i| {
                bytes[offset + i * 32..offset + (i + 1) * 32]
                    .try_into()
                    .map_err(|_| timing::refused("metadata_digest"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        checkpoints.push(Checkpoint { ordinal, hashes });
        offset += cap * 32;
    }
    Ok(checkpoints)
}
/// Genuine admission/UDP binding/peer ARMED event for the cooperating app.
/// These times share the original operation clock; they are not a cover-law proof.
pub struct ApplicationReady {
    pub start: Instant,
    pub covers_until: Instant,
}
pub struct ApplicationControl {
    pub origin: Instant,
    pub end: Instant,
    pub ready: Option<Box<dyn FnOnce(ApplicationReady) + Send>>,
}
async fn ready_owner(
    mut owner: OwnedSender,
    end: Instant,
    on_ready: impl FnOnce(),
) -> io::Result<OwnedSender> {
    if let Err(ready_error) = owner.ready(end).await {
        // READY closure alone loses the release actor's preparation error.
        // Retire that same owned actor with the same original deadline so its
        // typed terminal error and any actually observed join remain visible.
        // A successful terminal result cannot validate failed readiness.
        return Err(match owner.finish(end).await {
            Err(terminal_error) => terminal_error,
            Ok(_) => ready_error,
        });
    }
    on_ready();
    Ok(owner)
}
async fn send_operation<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut tokio_rustls::client::TlsStream<S>,
    p: &Profile,
    input: &[u8],
    origin: Instant,
    end: Instant,
    observer: timing::Observer,
    on_ready: Option<Box<dyn FnOnce(ApplicationReady) + Send>>,
) -> io::Result<Receipt> {
    if stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(timing::refused("tls_version"));
    }
    let descriptor = p.descriptor()?;
    stream.write_all(ADMISSION).await?;
    stream.write_all(&descriptor).await?;
    stream.flush().await?;
    if stream.read_u8().await? != ACCEPT {
        return Err(timing::refused("paired_admission"));
    }
    let seed = stream
        .get_ref()
        .1
        .export_keying_material(Zeroizing::new([0; 32]), EXPORTER_LABEL, Some(&descriptor))
        .map_err(|_| timing::refused("exporter"))?;
    let prepared = Prepared::new(p.timing.clone(), seed, end)?;
    stream.write_all(&prepared.digest()).await?;
    stream.flush().await?;
    if stream.read_u8().await? != ACCEPT {
        return Err(timing::refused("paired_codebook"));
    }
    // Authenticated fixed-count timestamps bound offset and uncertainty. No
    // hidden message or variable round count influences public start selection.
    let (uncertainty, offset) = sender_clock_sync(
        stream,
        || elapsed(origin),
        u64::from(p.timing.clock_uncertainty_us) * 1_000,
    )
    .await?;
    let mut plane = sender_plane(p, end).await?;
    plane.observe(observer);
    let start = Instant::now() + Duration::from_millis(u64::from(p.timing.ready_lead_ms));
    let start_ns: u64 = start
        .duration_since(origin)
        .as_nanos()
        .try_into()
        .map_err(|_| timing::refused("clock_sync_overflow"))?;
    let translated: u64 = (i128::from(start_ns) + offset)
        .try_into()
        .map_err(|_| timing::refused("clock_sync_overflow"))?;
    stream.write_u64(start_ns).await?;
    stream.write_u64(translated).await?;
    stream.write_u64(uncertainty).await?;
    stream.flush().await?;
    if stream.read_u8().await? != ARMED || Instant::now() >= start {
        return Err(timing::refused("receiver_not_armed"));
    }
    let final_at = start
        + p.timing.horizon()
        + Duration::from_millis(u64::from(p.timing.drain_ms + p.timing.finalize_ms));
    if final_at >= end {
        return Err(timing::refused("original_clock_runway"));
    }
    let words = prepared.encode(input)?;
    timing::live(end)?;
    let owner = OwnedSender::spawn_timing(plane, &prepared, &words, start, end)?;
    let owner = ready_owner(owner, end, || {
        if let Some(callback) = on_ready {
            callback(ApplicationReady {
                start,
                covers_until: start + p.timing.horizon(),
            });
        }
    })
    .await?;
    if Instant::now() >= start {
        return Err(timing::refused("application_ready_callback_late"));
    }
    // The TLS lease remains observed while this owned release actor runs.
    // No unexpected byte or EOF is a timing message or a retry permission.
    let completed = tokio::select! { biased;
        peer = stream.read_u8() => {
            peer?;
            return Err(timing::refused("unexpected_peer_during_owned_release"));
        }
        result = owner.finish(end) => result?,
    };
    let checkpoints = completed.checkpoints;
    let wire = metadata(p, &checkpoints)?;
    // Fixed public timing and size, independent of selected word/count/length.
    let metadata_at = final_at - Duration::from_millis(u64::from(p.timing.finalize_ms));
    if Instant::now() >= metadata_at {
        return Err(timing::refused("metadata_public_slot_late"));
    }
    sleep_until(metadata_at).await;
    timing::live(end)?;
    stream.write_all(&wire).await?;
    stream.flush().await?;
    if stream.read_u8().await? != DECODED {
        return Err(timing::refused("peer_decoded_record"));
    }
    timing::live(end)?;
    Ok(Receipt {
        timing_control_authenticated: true,
        conditional_reference: p.timing.conditional_reference()?,
        observations: completed.observations,
        logical_packets_preserved: true,
        authenticated_payload_digest_sequence_matched: true,
        application_origin_and_unique_sequence_verified: false,
        installed_full_wide: false,
        collector_terminal: true,
    })
}
pub async fn send_once<S: AsyncRead + AsyncWrite + Unpin>(
    client: &Client,
    shaping: &Option<PrivacySettings>,
    carrier: S,
    p: Profile,
    input: Zeroizing<Vec<u8>>,
    origin: Instant,
    end: Instant,
) -> Result<Receipt, Failure> {
    send_once_with_ready(
        client,
        shaping,
        carrier,
        p,
        input,
        ApplicationControl {
            origin,
            end,
            ready: None,
        },
    )
    .await
}
pub async fn send_once_with_ready<S: AsyncRead + AsyncWrite + Unpin>(
    client: &Client,
    shaping: &Option<PrivacySettings>,
    carrier: S,
    p: Profile,
    input: Zeroizing<Vec<u8>>,
    control: ApplicationControl,
) -> Result<Receipt, Failure> {
    let ApplicationControl { origin, end, ready } = control;
    let observer = timing::Observer::default();
    let result = async {
        preflight(&p, shaping, origin, end)?;
        if input.len() > usize::from(p.timing.payload_capacity) {
            return Err(timing::refused("input_capacity"));
        }
        let value = timeout_at(end, async {
            let mut stream = client.connect(carrier).await?;
            send_operation(
                &mut stream,
                &p,
                &input,
                origin,
                end,
                observer.clone(),
                ready,
            )
            .await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "poisson_original_clock"))??;
        timing::live(end)?;
        Ok(value)
    }
    .await;
    result.map_err(|error| Failure::capture(error, &observer))
}
async fn receive_operation<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut tokio_rustls::server::TlsStream<S>,
    p: &Profile,
    origin: Instant,
    end: Instant,
    observer: timing::Observer,
    receiver: &mut Option<Receiver>,
) -> io::Result<Received> {
    if stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(timing::refused("tls_version"));
    }
    let mut admission = [0; 8];
    stream.read_exact(&mut admission).await?;
    let mut descriptor = [0; 32];
    stream.read_exact(&mut descriptor).await?;
    if &admission != ADMISSION || descriptor != p.descriptor()? {
        return Err(timing::refused("paired_admission"));
    }
    stream.write_u8(ACCEPT).await?;
    stream.flush().await?;
    let seed = stream
        .get_ref()
        .1
        .export_keying_material(Zeroizing::new([0; 32]), EXPORTER_LABEL, Some(&descriptor))
        .map_err(|_| timing::refused("exporter"))?;
    let prepared = Prepared::new(p.timing.clone(), seed, end)?;
    let mut digest = [0; 32];
    stream.read_exact(&mut digest).await?;
    if digest != prepared.digest() {
        return Err(timing::refused("paired_codebook"));
    }
    stream.write_u8(ACCEPT).await?;
    stream.flush().await?;
    for _ in 0..CLOCK_SYNC_ROUNDS {
        let _t0 = stream.read_u64().await?;
        let b1 = elapsed(origin)?;
        stream.write_u64(b1).await?;
        let b2 = elapsed(origin)?;
        stream.write_u64(b2).await?;
        stream.flush().await?;
    }
    let _start_client = stream.read_u64().await?;
    let start_ns = stream.read_u64().await?;
    let uncertainty = stream.read_u64().await?;
    if uncertainty > u64::from(p.timing.clock_uncertainty_us) * 1_000 {
        return Err(timing::refused("clock_sync_uncertainty"));
    }
    let start = origin + Duration::from_nanos(start_ns);
    if Instant::now() + Duration::from_nanos(uncertainty) >= start {
        return Err(timing::refused("clock_sync_late"));
    }
    let final_at = start
        + p.timing.horizon()
        + Duration::from_millis(u64::from(p.timing.drain_ms + p.timing.finalize_ms));
    if final_at >= end {
        return Err(timing::refused("original_clock_runway"));
    }
    // Real bound UDP collector exists before ARMED. It never fabricates arrivals.
    p.validate()?;
    let source = UdpSocket::bind(p.receiver_packet_bind).await?;
    source.connect(p.sender_packet_bind).await?;
    let sink = UdpSocket::bind(p.receiver_application_bind).await?;
    sink.connect(p.receiver_application_peer).await?;
    *receiver = Some(Receiver::new_observed(
        source,
        sink,
        p.timing.clone(),
        start,
        end,
        observer.clone(),
    )?);
    let plane = receiver.as_mut().expect("receiver was just initialized");
    stream.write_u8(ARMED).await?;
    stream.flush().await?;
    let mut bytes = Zeroizing::new(vec![0; p.metadata_size()?]);
    tokio::select! { biased;
        result = plane.wait_failure(end) => result?,
        result = stream.read_exact(&mut bytes) => { result?; },
    }
    timing::live(end)?;
    let checkpoints = parse_metadata(p, &bytes)?;
    let first = plane
        .checkpoint(&checkpoints[0], p.capacity(0), end)
        .await?;
    let phase_one = u64::from(p.timing.buffering_ms) * 1_000_000;
    let mut previous = first.last().copied().unwrap_or(0);
    let mut words = Zeroizing::new(Vec::new());
    for block in 0..p.timing.blocks() {
        let stamps = plane
            .checkpoint(&checkpoints[block + 1], p.capacity(block + 1), end)
            .await?;
        let block_origin = phase_one + block as u64 * u64::from(p.timing.block_ms) * 1_000_000;
        let relative: Vec<u64> = stamps
            .iter()
            .map(|d| {
                d.checked_sub(block_origin)
                    .ok_or_else(|| timing::refused("arrival_before_phase_origin"))
            })
            .collect::<io::Result<_>>()?;
        // A previously completed packet before this block has no residual
        // service in the nonnegative block-relative coordinate. Current
        // arrivals before the origin are refused above, never clamped.
        let previous_relative = previous.saturating_sub(block_origin);
        let word = prepared.decode_arrivals(block, &relative, previous_relative, uncertainty)?;
        previous = stamps.last().copied().unwrap_or(previous);
        words.push(word);
    }
    plane
        .checkpoint(
            checkpoints
                .last()
                .ok_or_else(|| timing::refused("metadata_count"))?,
            p.capacity(checkpoints.len() - 1),
            end,
        )
        .await?;
    plane.finish(end).await?;
    let payload = prepared.decode_record(&words)?;
    if Instant::now() >= final_at {
        return Err(timing::refused("final_public_slot_late"));
    }
    sleep_until(final_at).await;
    timing::live(end)?;
    stream.write_u8(DECODED).await?;
    stream.flush().await?;
    timing::live(end)?;
    Ok(Received {
        payload,
        receipt: Receipt {
            timing_control_authenticated: true,
            conditional_reference: p.timing.conditional_reference()?,
            observations: observer.snapshot(),
            logical_packets_preserved: true,
            authenticated_payload_digest_sequence_matched: true,
            application_origin_and_unique_sequence_verified: false,
            installed_full_wide: false,
            collector_terminal: true,
        },
    })
}
pub async fn receive_once<S: AsyncRead + AsyncWrite + Unpin>(
    server: &Server,
    shaping: &Option<PrivacySettings>,
    carrier: S,
    p: Profile,
    origin: Instant,
    end: Instant,
) -> Result<Received, Failure> {
    let observer = timing::Observer::default();
    // Custody survives cancellation of the TLS operation by lease revocation or
    // the original timeout. Dropping the entire SDK future still only requests
    // abort; no asynchronous destructor can promise a joined task.
    let mut receiver = None;
    let result=async {
        preflight(&p,shaping,origin,end)?;let _permit=server.try_acquire()?;
        let value=timeout_at(end,async{let(mut stream,lease)=server.accept_with_lease(carrier).await?;
            tokio::select!{biased;error=lease.revoked()=>Err(error),result=receive_operation(&mut stream,&p,origin,end,observer.clone(), &mut receiver)=>result}
        }).await.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"poisson_original_clock"))??;
        timing::live(end)?;Ok(value)
    }.await;
    if result.is_err() {
        if let Some(plane) = receiver.as_mut() {
            // Preserve the first protocol/I/O error even if cleanup cannot
            // finish. Cleanup gets no fresh clock or allowance.
            let _ = plane.abort_and_join_until(end).await;
        }
    }
    drop(receiver);
    result.map_err(|error| Failure::capture(error, &observer))
}
#[cfg(test)]
#[path = "poisson_control_tests.rs"]
mod tests;
