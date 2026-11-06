//! Separate explicit target/purpose-bound Liu admission inside authorized TLS.
use super::*;
use crate::traffic_privacy::liu_channel::{self, BoundContext, PreparedChannel};
use std::time::Duration;

/// Owns the prepared exact kernel and original session cutoff. Never Clone.
pub struct LiuAdmission {
    profile: PrivacySettings,
    context: BoundContext,
    prepared: PreparedChannel,
    original_session_deadline: Instant,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiuAgreement {
    version: u8,
    operation: LiuOperation,
    profile: PrivacySettings,
    context: BoundContext,
    kernels: [u8; 32],
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LiuOperation {
    LiuTrafficOrPolicy,
    LiuTrafficOrPolicyAck,
}

/// Call BEFORE loading private identity or opening sockets. All work, including
/// training, consumes the caller's original establishment/session clocks.
pub async fn prepare_liu_admission(
    profile: &PrivacySettings,
    context: BoundContext,
    origin: Instant,
    deadline: Instant,
) -> io::Result<LiuAdmission> {
    prepare_liu_admission_with_training(profile, context, origin, deadline, None).await
}

async fn prepare_liu_admission_with_training(
    profile: &PrivacySettings,
    context: BoundContext,
    origin: Instant,
    deadline: Instant,
    training: Option<&ServerTraining>,
) -> io::Result<LiuAdmission> {
    profile.validate()?;
    let settings = profile.liu_channel.as_ref().ok_or_else(rejected)?;
    settings.validate_context(&context)?;
    let original_session_deadline = origin
        .checked_add(Duration::from_millis(u64::from(
            settings.session_timeout_ms,
        )))
        .ok_or_else(rejected)?;
    if Instant::now() >= deadline || Instant::now() >= original_session_deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Liu admission original deadline exhausted",
        ));
    }
    let admission = LiuAgreement {
        version: 2,
        operation: LiuOperation::LiuTrafficOrPolicy,
        profile: profile.clone(),
        context: context.clone(),
        kernels: [0; 32],
    };
    if serde_json::to_vec(&admission)
        .map_err(|_| rejected())?
        .len()
        > MAX_CONTROL_BYTES
    {
        return Err(rejected());
    }
    let prepared = match training {
        Some(training) => training.liu(profile)?,
        None => {
            liu_channel::prepare(settings.clone(), deadline.min(original_session_deadline)).await?
        }
    };
    Ok(LiuAdmission {
        profile: profile.clone(),
        context,
        prepared,
        original_session_deadline,
    })
}
async fn write_liu<S: ByteCarrier>(
    stream: &mut S,
    profile: &PrivacySettings,
    context: &BoundContext,
    operation: LiuOperation,
    kernels: [u8; 32],
) -> io::Result<()> {
    let bytes = serde_json::to_vec(&LiuAgreement {
        version: 2,
        operation,
        profile: profile.clone(),
        context: context.clone(),
        kernels,
    })
    .map_err(|_| rejected())?;
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_BYTES {
        return Err(rejected());
    }
    stream.write_u16(bytes.len() as u16).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}
async fn read_liu<S: ByteCarrier>(
    stream: &mut S,
    profile: &PrivacySettings,
    operation: LiuOperation,
) -> io::Result<(BoundContext, [u8; 32])> {
    let len = usize::from(stream.read_u16().await?);
    if len == 0 || len > MAX_CONTROL_BYTES {
        return Err(rejected());
    }
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    let agreement: LiuAgreement = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
    if agreement.version != 2 || agreement.operation != operation || agreement.profile != *profile {
        return Err(rejected());
    }
    profile
        .liu_channel
        .as_ref()
        .ok_or_else(rejected)?
        .validate_context(&agreement.context)?;
    Ok((agreement.context, agreement.kernels))
}
async fn attach_liu<S: ByteCarrier + 'static>(
    mut stream: S,
    admission: LiuAdmission,
    is_client: bool,
    owner: Option<&ShapingCleanupOwner>,
) -> io::Result<OwnedCarrier> {
    let mut contributions = Zeroizing::new([0u8; 64]);
    let own = if is_client { 0..32 } else { 32..64 };
    rand::rngs::OsRng
        .try_fill_bytes(&mut contributions[own])
        .map_err(|_| io::Error::other("Liu session entropy unavailable"))?;
    if is_client {
        stream.write_all(&contributions[..32]).await?;
        stream.flush().await?;
        stream.read_exact(&mut contributions[32..]).await?;
    } else {
        stream.read_exact(&mut contributions[..32]).await?;
        stream.write_all(&contributions[32..]).await?;
        stream.flush().await?;
    }
    let descriptor = admission.prepared.settings().descriptor()?;
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&descriptor), &*contributions);
    let mut seed = Zeroizing::new([0u8; 32]);
    hk.expand(b"AEGIS-Liu-TLS-session-seed-v1", &mut *seed)
        .map_err(|_| rejected())?;
    Ok(Box::new(liu_channel::attach_authenticated_owned(
        stream,
        admission.prepared,
        admission.context,
        seed,
        is_client,
        admission.original_session_deadline,
        owner,
    )?))
}
/// None retains the original agreement. A Liu profile without prepared purpose
/// refuses rather than silently choosing an unknown traffic/control class.
pub fn client_admitted<'a, S: ByteCarrier + 'static>(
    mut stream: S,
    profile: Option<&'a PrivacySettings>,
    deadline: Instant,
    admission: Option<LiuAdmission>,
) -> std::pin::Pin<Box<impl std::future::Future<Output = io::Result<OwnedCarrier>> + Send + 'a>> {
    // This new dispatcher owns its complete handshake state on the heap.
    // Constructing it is lazy; its original deadline and stream Drop stay owned.
    Box::pin(async move {
        let Some(admission) = admission else {
            return client(stream, profile, deadline).await;
        };
        if profile != Some(&admission.profile) {
            return Err(rejected());
        }
        within_establishment(deadline.min(admission.original_session_deadline), async {
            write_liu(
                &mut stream,
                &admission.profile,
                &admission.context,
                LiuOperation::LiuTrafficOrPolicy,
                admission.prepared.kernel_descriptor(),
            )
            .await?;
            let peer = read_liu(
                &mut stream,
                &admission.profile,
                LiuOperation::LiuTrafficOrPolicyAck,
            )
            .await?;
            if peer.0 != admission.context || peer.1 != admission.prepared.kernel_descriptor() {
                return Err(rejected());
            }
            attach_liu(stream, admission, true, None).await
        })
        .await
    })
}
/// Caller must keep the device authorization lease live for negotiation AND
/// forwarding and check the returned purpose against the subsequent request.
pub async fn server_bound<S: ByteCarrier + 'static>(
    stream: S,
    profile: Option<&PrivacySettings>,
    origin: Instant,
    deadline: Instant,
) -> io::Result<(OwnedCarrier, Option<BoundContext>)> {
    server_bound_with_training(stream, profile, origin, deadline, None).await
}

/// Reuses numerical training only; context, lease, entropy and original clocks
/// remain properties of this newly authorized session.
pub async fn server_bound_with_training<S: ByteCarrier + 'static>(
    stream: S,
    profile: Option<&PrivacySettings>,
    origin: Instant,
    deadline: Instant,
    training: Option<&ServerTraining>,
) -> io::Result<(OwnedCarrier, Option<BoundContext>)> {
    server_bound_with_training_owned(stream, profile, origin, deadline, training, None).await
}

/// Retains the exact numerical/context agreement and caller's worker owner.
pub async fn server_bound_with_training_owned<S: ByteCarrier + 'static>(
    mut stream: S,
    profile: Option<&PrivacySettings>,
    origin: Instant,
    deadline: Instant,
    training: Option<&ServerTraining>,
    owner: Option<&ShapingCleanupOwner>,
) -> io::Result<(OwnedCarrier, Option<BoundContext>)> {
    let Some(settings) = profile.filter(|p| p.liu_channel.is_some()) else {
        return Ok((
            server_with_training_owned(stream, profile, deadline, training, owner).await?,
            None,
        ));
    };
    settings.validate()?;
    within_establishment(deadline, async {
        let (context, kernels) =
            read_liu(&mut stream, settings, LiuOperation::LiuTrafficOrPolicy).await?;
        let admission = prepare_liu_admission_with_training(
            settings,
            context.clone(),
            origin,
            deadline,
            training,
        )
        .await?;
        if kernels != admission.prepared.kernel_descriptor() {
            return Err(rejected());
        }
        write_liu(
            &mut stream,
            settings,
            &context,
            LiuOperation::LiuTrafficOrPolicyAck,
            admission.prepared.kernel_descriptor(),
        )
        .await?;
        let carrier = attach_liu(stream, admission, false, owner).await?;
        Ok((carrier, Some(context)))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn profile() -> PrivacySettings {
        serde_json::from_value(serde_json::json!({"payload_bytes":2,"cadence_ms":1,"buffer_bytes":1024,"max_wire_bytes":100000,"io_timeout_ms":300,"session_timeout_ms":3000,"max_queue_delay_ms":400000,"liu_channel":{"class_weights":[1,3],"client_to_server_counts":[[3,1],[1,3]],"server_to_client_counts":[[3,1],[1,3]],"target_classes":[],"unmatched_traffic_class":0,"policy_ack_class":1,"distortion_microunits":125000,"optimizer_iterations":2000,"optimizer_gap_millibits":1,"optimizer_timeout_ms":3000,"buffer_bytes":1024,"wire_batch_bytes":1024,"max_wire_bytes":100000,"io_timeout_ms":300,"session_timeout_ms":3000,"max_queue_delay_ms":400000}})).unwrap()
    }
    #[tokio::test]
    async fn actual_mismatched_prepared_numerical_kernel_refuses_before_contributions() {
        let p = profile();
        let c = p.liu_channel.as_ref().unwrap().policy_context().unwrap();
        let (a, mut b) = tokio::io::duplex(8192);
        let origin = Instant::now();
        let deadline = origin + Duration::from_secs(3);
        let (server, ()) = tokio::join!(server_bound(a, Some(&p), origin, deadline), async {
            write_liu(&mut b, &p, &c, LiuOperation::LiuTrafficOrPolicy, [99; 32])
                .await
                .unwrap();
            assert!(b.read_u8().await.is_err());
        });
        assert!(matches!(server,Err(e)if e.kind()==io::ErrorKind::InvalidData));
    }

    #[tokio::test]
    async fn liu_relay_consumer_delivers_reply_while_request_source_stays_open() {
        let p = profile();
        let context = p.liu_channel.as_ref().unwrap().policy_context().unwrap();
        let origin = Instant::now();
        let deadline = origin + Duration::from_secs(3);
        let admission = prepare_liu_admission(&p, context.clone(), origin, deadline)
            .await
            .unwrap();
        let (client_wire, server_wire) = tokio::io::duplex(16_384);
        let (client, server) = tokio::join!(
            client_admitted(client_wire, Some(&p), deadline, Some(admission)),
            server_bound(server_wire, Some(&p), origin, deadline)
        );
        let mut client = client.unwrap();
        let (mut server, agreed_context) = server.unwrap();
        assert_eq!(agreed_context, Some(context));
        let (mut client_app, mut client_bridge) = tokio::io::duplex(1024);
        let (mut target_app, mut target_bridge) = tokio::io::duplex(1024);
        tokio::time::timeout(Duration::from_millis(1800), async {
            let client_copy = crate::secure_channel::copy_with_idle_timeout(
                &mut client_bridge,
                &mut client,
                Duration::from_millis(1500),
            );
            let server_copy = crate::secure_channel::copy_with_idle_timeout(
                &mut server,
                &mut target_bridge,
                Duration::from_millis(1500),
            );
            let exchange = async {
                client_app.write_all(b"ping").await?;
                let mut request = [0; 4];
                target_app.read_exact(&mut request).await?;
                assert_eq!(&request, b"ping");
                target_app.write_all(b"pong").await?;
                let mut response = [0; 4];
                client_app.read_exact(&mut response).await?;
                assert_eq!(&response, b"pong");
                client_app.shutdown().await?;
                target_app.shutdown().await?;
                io::Result::Ok(())
            };
            tokio::try_join!(client_copy, server_copy, exchange)
        })
        .await
        .expect("Liu request/reply must complete before session cutoff")
        .unwrap();
    }
}

#[cfg(test)]
mod lifetime_tests {
    use super::*;
    #[tokio::test]
    async fn endpoint_preparation_elapsed_time_cannot_reset_original_liu_session() {
        let mut profile = super::tests::profile();
        profile.session_timeout_ms = 500;
        profile.liu_channel.as_mut().unwrap().session_timeout_ms = 500;
        let context = profile
            .liu_channel
            .as_ref()
            .unwrap()
            .policy_context()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let origin = deadline.checked_sub(Duration::from_secs(3)).unwrap();
        let result = prepare_liu_admission(&profile, context, origin, deadline).await;
        assert!(matches!(result,Err(e)if e.kind()==io::ErrorKind::TimedOut));
    }
}

#[cfg(test)]
#[path = "relay_shaping_liu_heap_tests.rs"]
mod heap_tests;
