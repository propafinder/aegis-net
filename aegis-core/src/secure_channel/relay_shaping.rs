//! Explicit paired shaping agreement inside an authenticated relay channel.
//! Absent at both peers means the existing wire is unchanged. Agreement is
//! completed before target/open traffic; no fallback is allowed on rejection.
#[cfg(test)]
use crate::carrier_runtime::shape_authenticated;
use crate::carrier_runtime::{
    shape_authenticated_owned, ByteCarrier, OwnedCarrier, PrivacySettings, ShapingCleanupOwner,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout_at, Instant};
use zeroize::Zeroizing;

#[path = "relay_shaping_liu.rs"]
mod liu;
pub use liu::{
    client_admitted, prepare_liu_admission, server_bound, server_bound_with_training,
    server_bound_with_training_owned, LiuAdmission,
};

#[path = "relay_shaping_training.rs"]
mod training;
pub use training::ServerTraining;

const MAX_CONTROL_BYTES: usize = crate::carrier_runtime::MAX_RELAY_SHAPING_CONTROL_BYTES;

async fn within_establishment<T>(
    deadline: Instant,
    work: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let timeout = || io::Error::new(io::ErrorKind::TimedOut, "relay shaping agreement timed out");
    if Instant::now() >= deadline {
        return Err(timeout());
    }
    let value = timeout_at(deadline, work).await.map_err(|_| timeout())??;
    // A future's final poll can finish synchronous work after the timer. Never
    // promote that late carrier; dropping it cancels its newly owned worker.
    if Instant::now() >= deadline {
        return Err(timeout());
    }
    Ok(value)
}

// Capture the lifetime before validation/preparation/agreement. A nested owner
// may admit a shorter lifetime than the enclosing profile; installing it later
// must not restart that shorter clock.
fn original_owner_deadline(settings: &PrivacySettings, origin: Instant) -> io::Result<Instant> {
    let mut lifetime_ms = settings.session_timeout_ms;
    if let Some(profile) = &settings.adaptive_channel {
        lifetime_ms = lifetime_ms.min(u64::from(profile.session_timeout_ms));
    }
    if let Some(profile) = &settings.cover_stream {
        lifetime_ms = lifetime_ms.min(u64::from(profile.session_timeout_ms));
    }
    origin
        .checked_add(std::time::Duration::from_millis(lifetime_ms))
        .ok_or_else(rejected)
}

/// Fresh contributions travel only inside the already authenticated device TLS.
/// Both parties contribute entropy; profile and direction are bound by HKDF.
/// This is computational session custody, not an ideal OTP or a DP proof.
async fn attach_agreed<S: ByteCarrier + 'static>(
    mut stream: S,
    settings: &PrivacySettings,
    is_client: bool,
    original_session_deadline: Instant,
    prepared: Option<crate::traffic_privacy::adaptive_channel::PreparedChannel>,
    owner: Option<&ShapingCleanupOwner>,
) -> io::Result<OwnedCarrier> {
    if let Some(prepared) = prepared {
        if Some(prepared.settings()) != settings.adaptive_channel.as_ref() {
            return Err(rejected());
        }
        return Ok(Box::new(
            crate::traffic_privacy::adaptive_channel::attach_authenticated_owned(
                stream,
                prepared,
                original_session_deadline,
                owner,
            )?,
        ));
    }
    let net = settings
        .net_shaper
        .as_ref()
        .map(|n| crate::traffic_privacy::netshaper::NetShaperProfile::try_from(n.clone()))
        .transpose()?;
    let bit = settings
        .bit_traps
        .as_ref()
        .map(|b| crate::traffic_privacy::bittraps::BitTrapsConfig::try_from(b.clone()))
        .transpose()?;
    let descriptor = if let Some(profile) = &net {
        profile.descriptor_sha256()
    } else if let Some(profile) = &bit {
        profile.descriptor_sha256()
    } else if let Some(profile) = &settings.cover_stream {
        profile.descriptor()?
    } else {
        let config = settings.validate_opaque()?;
        let shaped = match &settings.poisson_pacing {
            Some(pacing) => crate::traffic_privacy::shaper::attach_poisson_until_owned(
                stream,
                config,
                pacing.clone(),
                original_session_deadline,
                owner,
            )?,
            None => crate::traffic_privacy::shaper::attach_regulated_until_owned(
                stream,
                config,
                settings.arrival_envelope.clone(),
                original_session_deadline,
                owner,
            )?,
        };
        return Ok(Box::new(shaped));
    };
    let mut contributions = Zeroizing::new([0u8; 64]);
    let own = if is_client { 0..32 } else { 32..64 };
    rand::rngs::OsRng
        .try_fill_bytes(&mut contributions[own.clone()])
        .map_err(|_| io::Error::other("relay shaping entropy unavailable"))?;
    if is_client {
        stream.write_all(&contributions[..32]).await?;
        stream.flush().await?;
        stream.read_exact(&mut contributions[32..]).await?;
    } else {
        stream.read_exact(&mut contributions[..32]).await?;
        stream.write_all(&contributions[32..]).await?;
        stream.flush().await?;
    }
    let derive = |direction: &[u8]| -> io::Result<Zeroizing<[u8; 40]>> {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&descriptor), &*contributions);
        let mut material = Zeroizing::new([0u8; 40]);
        let mut info = b"aegis.authenticated.keyed-carrier.epoch.v1/".to_vec();
        info.extend_from_slice(direction);
        hk.expand(&info, &mut *material).map_err(|_| rejected())?;
        Ok(material)
    };
    let c2s = derive(b"client-to-server")?;
    let s2c = derive(b"server-to-client")?;
    let (send, receive) = if is_client { (c2s, s2c) } else { (s2c, c2s) };
    let seed = |material: &Zeroizing<[u8; 40]>| {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&material[..32]);
        key
    };
    if let Some(profile) = net {
        let material = |bytes: &Zeroizing<[u8; 40]>| {
            let mut prefix = [0u8; 8];
            prefix.copy_from_slice(&bytes[32..]);
            crate::traffic_privacy::netshaper::NetShaperMaterial::from_preprovisioned(
                seed(bytes),
                prefix,
            )
        };
        return Ok(Box::new(
            crate::traffic_privacy::netshaper::attach_authenticated_owned(
                stream,
                profile,
                material(&send),
                material(&receive),
                original_session_deadline,
                owner,
            )?,
        ));
    }
    if let Some(profile) = bit {
        return Ok(Box::new(
            crate::traffic_privacy::bittraps::attach_authenticated_owned(
                stream,
                profile,
                crate::traffic_privacy::bittraps::BitTrapsMaterial::from_preprovisioned(seed(
                    &send,
                )),
                crate::traffic_privacy::bittraps::BitTrapsMaterial::from_preprovisioned(seed(
                    &receive,
                )),
                original_session_deadline,
                owner,
            )?,
        ));
    }
    let profile = settings.cover_stream.as_ref().ok_or_else(rejected)?;
    Ok(Box::new(
        crate::traffic_privacy::cover_stream::attach_authenticated_owned(
            stream,
            profile.clone(),
            crate::traffic_privacy::cover_stream::CoverStreamMaterial::new(
                seed(&send),
                u8::from(!is_client),
            )?,
            crate::traffic_privacy::cover_stream::CoverStreamMaterial::new(
                seed(&receive),
                u8::from(is_client),
            )?,
            original_session_deadline,
            owner,
        )?,
    ))
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    RelayShaping,
    RelayShapingAck,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Agreement {
    version: u8,
    operation: Operation,
    profile: PrivacySettings,
}

fn rejected() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "relay shaping agreement rejected",
    )
}

async fn write<S: ByteCarrier>(
    stream: &mut S,
    operation: Operation,
    settings: &PrivacySettings,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(&Agreement {
        version: 1,
        operation,
        profile: settings.clone(),
    })
    .map_err(|_| rejected())?;
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_BYTES {
        return Err(rejected());
    }
    stream.write_u16(bytes.len() as u16).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

async fn read<S: ByteCarrier>(
    stream: &mut S,
    operation: Operation,
    expected: &PrivacySettings,
) -> io::Result<()> {
    let length = usize::from(stream.read_u16().await?);
    if length == 0 || length > MAX_CONTROL_BYTES {
        return Err(rejected());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    let agreement: Agreement = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
    if agreement.version != 1 || agreement.operation != operation || agreement.profile != *expected
    {
        return Err(rejected());
    }
    Ok(())
}

/// Call only after device TLS succeeds. The original total establishment
/// deadline and the original owner lifetime both cover the agreement;
/// cancellation drops the owned stream. All
/// errors remain post-auth terminal failures, never retryable carrier outages.
pub async fn client<S>(
    stream: S,
    privacy: Option<&PrivacySettings>,
    deadline: Instant,
) -> io::Result<OwnedCarrier>
where
    S: ByteCarrier + 'static,
{
    client_owned(stream, privacy, deadline, None).await
}

/// Explicit attachment custody; production client callers retain the original
/// client entry point. The caller must drop forwarding before cancelling/joining.
pub async fn client_owned<S>(
    mut stream: S,
    privacy: Option<&PrivacySettings>,
    deadline: Instant,
    owner: Option<&ShapingCleanupOwner>,
) -> io::Result<OwnedCarrier>
where
    S: ByteCarrier + 'static,
{
    let Some(settings) = privacy else {
        return shape_authenticated_owned(stream, None, owner);
    };
    let origin = Instant::now();
    settings.validate()?;
    if settings.liu_channel.is_some() {
        return Err(rejected());
    }
    let original_session_deadline = original_owner_deadline(settings, origin)?;
    let agreement_deadline = deadline.min(original_session_deadline);
    within_establishment(agreement_deadline, async {
        let prepared = match &settings.adaptive_channel {
            Some(profile) => Some(
                crate::traffic_privacy::adaptive_channel::prepare(
                    profile.clone(),
                    agreement_deadline,
                )
                .await?,
            ),
            None => None,
        };
        write(&mut stream, Operation::RelayShaping, settings).await?;
        read(&mut stream, Operation::RelayShapingAck, settings).await?;
        attach_agreed(
            stream,
            settings,
            true,
            original_session_deadline,
            prepared,
            owner,
        )
        .await
    })
    .await
}

/// The caller must also race this work against the live authorization lease.
/// An unshaped Open/PolicyAck is rejected under an opt-in server policy before
/// a target can be selected. A default/old server rejects our typed hello by
/// its existing strict Open/PolicyAck schema, without any protocol downgrade.
pub async fn server<S>(
    stream: S,
    privacy: Option<&PrivacySettings>,
    deadline: Instant,
) -> io::Result<OwnedCarrier>
where
    S: ByteCarrier + 'static,
{
    server_with_training(stream, privacy, deadline, None).await
}

/// A completed operator-owned profile may be reused only after device TLS.
/// This does not move HELLO or restart any connection/session clock.
pub async fn server_with_training<S>(
    stream: S,
    privacy: Option<&PrivacySettings>,
    deadline: Instant,
    training: Option<&ServerTraining>,
) -> io::Result<OwnedCarrier>
where
    S: ByteCarrier + 'static,
{
    server_with_training_owned(stream, privacy, deadline, training, None).await
}

/// Same agreement with explicit custody of its one spawned framing worker.
pub async fn server_with_training_owned<S>(
    mut stream: S,
    privacy: Option<&PrivacySettings>,
    deadline: Instant,
    training: Option<&ServerTraining>,
    owner: Option<&ShapingCleanupOwner>,
) -> io::Result<OwnedCarrier>
where
    S: ByteCarrier + 'static,
{
    let Some(settings) = privacy else {
        if training.is_some() {
            return Err(rejected());
        }
        return shape_authenticated_owned(stream, None, owner);
    };
    let origin = Instant::now();
    settings.validate()?;
    if let Some(training) = training {
        training.check_profile(settings)?;
    }
    if settings.liu_channel.is_some() {
        return Err(rejected());
    }
    let original_session_deadline = original_owner_deadline(settings, origin)?;
    let agreement_deadline = deadline.min(original_session_deadline);
    within_establishment(agreement_deadline, async {
        let prepared = match &settings.adaptive_channel {
            Some(profile) => Some(match training {
                Some(training) => training.adaptive(settings)?,
                None => {
                    crate::traffic_privacy::adaptive_channel::prepare(
                        profile.clone(),
                        agreement_deadline,
                    )
                    .await?
                }
            }),
            None => None,
        };
        read(&mut stream, Operation::RelayShaping, settings).await?;
        write(&mut stream, Operation::RelayShapingAck, settings).await?;
        attach_agreed(
            stream,
            settings,
            false,
            original_session_deadline,
            prepared,
            owner,
        )
        .await
    })
    .await
}

#[cfg(test)]
#[path = "relay_shaping_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "relay_shaping_training_tests.rs"]
mod training_tests;
