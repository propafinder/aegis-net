//! Bounded private operator control exchange. Exporter-derived material is
//! computational, not an ideal OTP. Inner records do not camouflage outer TLS.
use super::{Client, Server};
use crate::{
    carrier_runtime::PrivacySettings,
    secret_file,
    traffic_privacy::{
        cover_control::{ControlRecord, CoverModel, OneTimeMaterial},
        schedule_emission::{
            BatchMaterial, ScheduleBatch, ScheduleProfile, SendFailure, SendReceipt,
        },
    },
};
use rand::rngs::OsRng;
use std::{io, path::Path, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{timeout_at, Instant},
};
use zeroize::Zeroizing;

const MAX_BYTES: usize = 16 * 1024;
const ADMISSION_BYTES: usize = 36;
const ACCEPT: u8 = 0xa1;
const DECODED: u8 = 0xa2;

/// Independently supplied public profile, never negotiated from untrusted sizes.
pub enum ControlProfile {
    Cover(CoverModel),
    BinarySchedule(ScheduleProfile),
}
impl ControlProfile {
    fn admission(&self) -> [u8; ADMISSION_BYTES] {
        let mut bytes = [0; ADMISSION_BYTES];
        bytes[..3].copy_from_slice(b"AC\x01");
        let (mode, descriptor) = match self {
            Self::Cover(p) => (1, p.descriptor_sha256()),
            Self::BinarySchedule(p) => (2, p.descriptor_sha256()),
        };
        bytes[3] = mode;
        bytes[4..].copy_from_slice(&descriptor);
        bytes
    }
    pub fn possible_schedule_releases(&self) -> Option<usize> {
        match self {
            Self::BinarySchedule(p) => Some(p.slots()),
            _ => None,
        }
    }
    fn capacity(&self) -> usize {
        match self {
            Self::Cover(p) => p.capacity(),
            Self::BinarySchedule(p) => p.capacity(),
        }
    }
    pub fn validate(&self) -> io::Result<()> {
        let bytes = match self {
            Self::Cover(p) => p.wire_bytes(),
            Self::BinarySchedule(p) => p
                .frame_bytes(1)?
                .checked_mul(p.slots())
                .ok_or_else(invalid)?,
        };
        if bytes + ADMISSION_BYTES + 2 > MAX_BYTES {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Owns private input; no Clone/Debug or plaintext argv/stdout path.
pub struct ControlInput(Vec<Zeroizing<Vec<u8>>>);
impl ControlInput {
    fn validate(&self, profile: &ControlProfile) -> io::Result<()> {
        let count = profile.possible_schedule_releases().unwrap_or(1);
        if self.0.len() != count || self.0.iter().any(|p| p.len() > profile.capacity()) {
            return Err(invalid());
        }
        Ok(())
    }
    /// Cover input is raw bytes. Schedule input is exactly public slots of
    /// big-endian u16 length + payload; zero length is a dummy cell.
    pub fn read_private(profile: &ControlProfile, path: &Path) -> io::Result<Self> {
        profile.validate()?;
        let bytes = secret_file::read(path, MAX_BYTES as u64)?;
        let cells = match profile {
            ControlProfile::Cover(_) => vec![bytes],
            ControlProfile::BinarySchedule(p) => {
                let mut offset = 0;
                let mut cells = Vec::with_capacity(p.slots());
                for _ in 0..p.slots() {
                    let header = bytes.get(offset..offset + 2).ok_or_else(invalid)?;
                    let count = usize::from(u16::from_be_bytes([header[0], header[1]]));
                    offset += 2;
                    let cell = bytes.get(offset..offset + count).ok_or_else(invalid)?;
                    cells.push(Zeroizing::new(cell.to_vec()));
                    offset += count;
                }
                if offset != bytes.len() {
                    return Err(invalid());
                }
                cells
            }
        };
        let input = Self(cells);
        input.validate(profile)?;
        Ok(input)
    }
}

/// Public receipt only; ACK means peer authenticated the complete record/batch,
/// not output persistence, application delivery, or installed full-wide use.
#[derive(Debug)]
pub struct ControlReceipt {
    pub peer_decoded: bool,
    pub schedule: Option<SendReceipt>,
}
#[derive(Debug)]
pub struct ControlFailure {
    pub kind: io::ErrorKind,
    /// A discarded in-progress future cannot return its accountant. This is
    /// unknown, never zero, and no same-owner retry/composition reset exists.
    pub schedule_accounting_unknown: bool,
    pub schedule: Option<SendFailure>,
    /// Actual completed spending retained if the final peer ACK fails.
    pub completed_schedule: Option<SendReceipt>,
}
impl std::fmt::Display for ControlFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "private control failed: {:?}", self.kind)
    }
}
impl std::error::Error for ControlFailure {}
impl From<io::Error> for ControlFailure {
    fn from(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            schedule_accounting_unknown: false,
            schedule: None,
            completed_schedule: None,
        }
    }
}
pub struct ReceivedControl {
    payloads: Vec<Zeroizing<Vec<u8>>>,
    schedule: bool,
}
impl ReceivedControl {
    /// Exclusive private output. Failure retains any partial file, never erases
    /// or overwrites a previous attempt. Output is not included in ACK semantics.
    pub fn save_private_new(self, path: &Path) -> io::Result<()> {
        let mut bytes = Zeroizing::new(Vec::new());
        for payload in self.payloads {
            if self.schedule {
                bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
            bytes.extend_from_slice(&payload);
        }
        secret_file::write_private_new(path, &bytes)
    }
    pub fn cells(&self) -> usize {
        self.payloads.len()
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "private control refused")
}
fn timed_out(schedule: bool) -> ControlFailure {
    let mut failure: ControlFailure =
        io::Error::new(io::ErrorKind::TimedOut, "private control deadline").into();
    failure.schedule_accounting_unknown = schedule;
    failure
}
fn preflight(
    profile: &ControlProfile,
    shaping: &Option<PrivacySettings>,
    deadline: Duration,
) -> io::Result<()> {
    if shaping.is_some() || deadline.is_zero() || deadline > Duration::from_secs(60) {
        return Err(invalid());
    }
    profile.validate()
}

enum Codec {
    Cover(ControlRecord),
    Schedule(ScheduleBatch),
}
fn codec<F>(profile: ControlProfile, mut export: F) -> io::Result<Codec>
where
    F: FnMut(&[u8], usize) -> io::Result<Zeroizing<Vec<u8>>>,
{
    // Distinct labels avoid prefix overlap between key, nonce and full OTP pad.
    // Context includes version, mode, exact profile, direction and ordinal 0.
    let key_label: &[u8] = match profile {
        ControlProfile::Cover(_) => b"aegis.control.cover.key.v1",
        _ => b"aegis.control.schedule.key.v1",
    };
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&export(key_label, 32)?);
    match profile {
        ControlProfile::Cover(p) => {
            let mut nonce = Zeroizing::new([0; 12]);
            nonce.copy_from_slice(&export(b"aegis.control.cover.nonce.v1", 12)?);
            let pad = export(b"aegis.control.cover.pad.v1", p.pad_bytes())?;
            Ok(Codec::Cover(ControlRecord::new(
                p,
                OneTimeMaterial::from_preprovisioned(key, *nonce, pad)?,
            )?))
        }
        ControlProfile::BinarySchedule(p) => {
            let mut prefix = Zeroizing::new([0; 8]);
            prefix.copy_from_slice(&export(b"aegis.control.schedule.prefix.v1", 8)?);
            Ok(Codec::Schedule(ScheduleBatch::new(
                p,
                BatchMaterial::from_preprovisioned(key, *prefix),
            )?))
        }
    }
}
fn context(admission: &[u8; ADMISSION_BYTES]) -> Vec<u8> {
    let mut context = b"aegis.private-control.c2s.ordinal-0.v1".to_vec();
    context.extend_from_slice(admission);
    context
}
fn require_before(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "private control original cutoff",
        ))
    } else {
        Ok(())
    }
}
fn preflight_until(
    profile: &ControlProfile,
    shaping: &Option<PrivacySettings>,
    end: Instant,
) -> io::Result<()> {
    let remaining = end
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::TimedOut, "private control original cutoff")
        })?;
    preflight(profile, shaping, remaining)
}

// These private functions own TLS, never expose a material/session constructor.
// Each entrypoint creates one fresh TLS connection, consumes one exchange and
// drops the entire connection on any partial/error/cancellation path.
/// Fresh exchange with a duration counted from entry, including admission.
pub async fn send_once<S>(
    client: &Client,
    shaping: &Option<PrivacySettings>,
    carrier: S,
    profile: ControlProfile,
    input: ControlInput,
    deadline: Duration,
) -> Result<ControlReceipt, ControlFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    preflight(&profile, shaping, deadline)?;
    let end = start + deadline;
    send_once_until(client, shaping, carrier, profile, input, end).await
}
/// Use the caller's original cutoff, including any prior TCP establishment.
/// Late-ready ACK cannot establish success; actual completed spending survives.
pub async fn send_once_until<S>(
    client: &Client,
    shaping: &Option<PrivacySettings>,
    carrier: S,
    profile: ControlProfile,
    input: ControlInput,
    deadline: Instant,
) -> Result<ControlReceipt, ControlFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    preflight_until(&profile, shaping, deadline)?;
    input.validate(&profile)?;
    let schedule_mode = profile.possible_schedule_releases().is_some();
    timeout_at(deadline, async move {
        let admission = profile.admission();
        require_before(deadline)?;
        let mut stream = client.connect(carrier).await?;
        require_before(deadline)?;
        if stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(invalid().into());
        }
        stream.write_all(&admission).await?;
        stream.flush().await?;
        if stream.read_u8().await? != ACCEPT {
            return Err(invalid().into());
        }
        require_before(deadline)?;
        let ctx = context(&admission);
        let codec = codec(profile, |label, len| {
            stream
                .get_ref()
                .1
                .export_keying_material(Zeroizing::new(vec![0; len]), label, Some(&ctx))
                .map_err(|_| invalid())
        })?;
        require_before(deadline)?;
        let schedule = match codec {
            Codec::Cover(record) => {
                if input.0.len() != 1 {
                    return Err(invalid().into());
                }
                record.send(&input.0[0], &mut OsRng, &mut stream).await?;
                None
            }
            Codec::Schedule(batch) => Some(
                batch
                    .send(input.0, &mut OsRng, &mut stream)
                    .await
                    .map_err(|failure| ControlFailure {
                        kind: failure.kind,
                        schedule_accounting_unknown: false,
                        schedule: Some(failure),
                        completed_schedule: None,
                    })?,
            ),
        };
        let completion = async {
            require_before(deadline)?;
            stream.flush().await?;
            require_before(deadline)?;
            if stream.read_u8().await? != DECODED {
                return Err(invalid());
            }
            require_before(deadline)?;
            Ok::<_, io::Error>(())
        }
        .await;
        if let Err(error) = completion {
            return Err(ControlFailure {
                kind: error.kind(),
                schedule_accounting_unknown: false,
                schedule: None,
                completed_schedule: schedule,
            });
        }
        Ok(ControlReceipt {
            peer_decoded: true,
            schedule,
        })
    })
    .await
    .map_err(|_| timed_out(schedule_mode))?
}

pub async fn receive_once<S>(
    server: &Server,
    shaping: &Option<PrivacySettings>,
    carrier: S,
    profile: ControlProfile,
    deadline: Duration,
) -> Result<ReceivedControl, ControlFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    preflight(&profile, shaping, deadline)?;
    let end = start + deadline;
    receive_once_until(server, shaping, carrier, profile, end).await
}
/// Same absolute endpoint cutoff through accept, admission, decode and ACK.
pub async fn receive_once_until<S>(
    server: &Server,
    shaping: &Option<PrivacySettings>,
    carrier: S,
    profile: ControlProfile,
    deadline: Instant,
) -> Result<ReceivedControl, ControlFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    preflight_until(&profile, shaping, deadline)?;
    let schedule_mode = profile.possible_schedule_releases().is_some();
    let _permit = server.try_acquire()?;
    timeout_at(deadline, async move {
        require_before(deadline)?;
        let (mut stream, lease) = server.accept_with_lease(carrier).await?;
        require_before(deadline)?;
        if stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(invalid().into());
        }
        let exchange = async {
            let mut admission = [0; ADMISSION_BYTES];
            stream.read_exact(&mut admission).await?;
            if admission != profile.admission() {
                return Err(invalid().into());
            }
            require_before(deadline)?;
            stream.write_u8(ACCEPT).await?;
            stream.flush().await?;
            require_before(deadline)?;
            let ctx = context(&admission);
            let codec = codec(profile, |label, len| {
                stream
                    .get_ref()
                    .1
                    .export_keying_material(Zeroizing::new(vec![0; len]), label, Some(&ctx))
                    .map_err(|_| invalid())
            })?;
            require_before(deadline)?;
            let (payloads, schedule) = match codec {
                Codec::Cover(record) => (vec![record.receive(&mut stream).await?], false),
                Codec::Schedule(batch) => (batch.receive(&mut stream).await?.payloads, true),
            };
            require_before(deadline)?;
            stream.write_u8(DECODED).await?;
            stream.flush().await?;
            require_before(deadline)?;
            Ok(ReceivedControl { payloads, schedule })
        };
        tokio::select! { biased;
            error = lease.revoked() => Err(error.into()),
            result = exchange => result,
        }
    })
    .await
    .map_err(|_| timed_out(schedule_mode))?
}

#[cfg(test)]
#[path = "private_control_tests.rs"]
mod tests;
