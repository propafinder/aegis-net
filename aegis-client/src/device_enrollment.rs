//! Pinned, enrollment-only network operations over the private relay carrier.
//! The identity store owns all keys, invitations, request bindings and recovery.
use crate::device_bundle::online::{OnlineMigration, OnlineProfile};
use crate::device_identity::store::{self, LocalCompletion, RequestMaterial};
use aegis_core::secure_channel::{
    enrollment::protocol::{Operation, ProofPurpose},
    enrollment_wire::{self as wire, ExchangeResponse, FailureCode},
    registry,
};
#[cfg(unix)]
use anyhow::Context;
use anyhow::{bail, ensure, Result};
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Debug, clap::Args)]
pub struct RedeemArgs {
    #[arg(long)]
    pub identity_dir: PathBuf,
    #[arg(long)]
    pub bundle_dir: PathBuf,
    /// Protected invitation file; omit only to resume the same saved request.
    #[arg(long)]
    pub invitation_file: Option<PathBuf>,
}

/// Explicit same-binding recovery after an ambiguous Redeem and operator
/// issuance of a new one-use invitation. No new key or CSR is generated.
#[cfg(unix)]
#[derive(Clone, Debug, clap::Args)]
pub struct RefreshRedeemInvitationArgs {
    #[arg(long)]
    pub identity_dir: PathBuf,
    #[arg(long)]
    pub bundle_dir: PathBuf,
    #[arg(long)]
    pub new_invitation_file: PathBuf,
    /// Exclusive private journal outside the identity and public bundle.
    #[arg(long)]
    pub recovery_out: PathBuf,
}

#[derive(Clone, Debug, clap::Args)]
pub struct RenewArgs {
    #[arg(long)]
    pub identity_dir: PathBuf,
    #[arg(long)]
    pub bundle_dir: PathBuf,
    /// Return the current valid status when renewal is not yet due.
    #[arg(long)]
    pub if_due: bool,
}

#[derive(Clone, Debug, clap::Args)]
pub struct EnableOnlineArgs {
    #[arg(long)]
    pub identity_dir: PathBuf,
    #[arg(long)]
    pub old_bundle_dir: PathBuf,
    #[arg(long)]
    pub bundle_dir: PathBuf,
}

#[derive(Clone, Debug, clap::Args)]
pub struct OnlineStatusArgs {
    #[arg(long)]
    pub identity_dir: PathBuf,
}

#[derive(Clone, Debug, clap::Args)]
pub struct RecoverLocalArgs {
    #[arg(long)]
    pub device_id: String,
    #[arg(long)]
    pub identity_dir: PathBuf,
    #[arg(long)]
    pub bundle_dir: PathBuf,
    #[arg(long)]
    pub json: bool,
}

pub fn recover_local(args: &RecoverLocalArgs) -> Result<()> {
    let recovery: store::LocalRecovery = store::recover_local(
        &args.identity_dir,
        &args.bundle_dir,
        &args.device_id,
        registry::unix_now()?,
    )?;
    if args.json {
        println!("{}", serde_json::to_string(&recovery)?);
    } else {
        println!("device local recovery: {}", recovery.phase);
    }
    Ok(())
}

fn print_completion(completion: &LocalCompletion) -> Result<()> {
    println!("{}", serde_json::to_string(completion)?);
    ensure!(
        completion.certificate_valid_now,
        "saved enrollment was recovered, but its certificate is no longer valid"
    );
    Ok(())
}

pub async fn redeem(args: &RedeemArgs) -> Result<()> {
    let profile = OnlineProfile::load(&args.bundle_dir, &args.identity_dir)?;
    if let Some(completion) =
        store::resume_online_response(&args.identity_dir, registry::unix_now()?)?
    {
        return print_completion(&completion);
    }
    let material = store::begin_online_request(
        &args.identity_dir,
        Operation::Redeem,
        profile.digest(),
        args.invitation_file.as_deref(),
        registry::unix_now()?,
    )?;
    let completion = perform(&args.identity_dir, &profile, &material).await?;
    print_completion(&completion)
}

#[cfg(unix)]
pub async fn refresh_redeem_invitation(args: &RefreshRedeemInvitationArgs) -> Result<()> {
    ensure!(
        args.bundle_dir.is_absolute()
            && args.bundle_dir.canonicalize()? == args.bundle_dir
            && !args.recovery_out.starts_with(&args.bundle_dir)
            && !args.new_invitation_file.starts_with(&args.bundle_dir),
        "refresh recovery and invitation must stay outside the public bundle"
    );
    let profile = OnlineProfile::load(&args.bundle_dir, &args.identity_dir)?;
    if let Some(completion) =
        store::resume_online_response(&args.identity_dir, registry::unix_now()?)
            .context("refresh saved-response preflight")?
    {
        return print_completion(&completion);
    }
    let snapshot = store::prepare_refresh(&args.identity_dir, profile.digest())
        .context("refresh pending snapshot")?;
    // Query the original binding under fresh pinned TLS and PoP before any
    // local token read or mutation. An ambiguous exchange is terminal here.
    let receipt = exchange(
        &args.identity_dir,
        &profile,
        &snapshot.material,
        ProofPurpose::Receipt,
    )
    .await
    .context("refresh original receipt exchange");
    refresh_after_receipt(args, &profile, &snapshot, receipt).await
}

#[cfg(unix)]
async fn refresh_after_receipt(
    args: &RefreshRedeemInvitationArgs,
    profile: &OnlineProfile,
    snapshot: &store::RefreshSnapshot,
    receipt: Result<ExchangeResponse>,
) -> Result<()> {
    match receipt? {
        ExchangeResponse::Issued { receipt } => {
            let completion =
                store::accept_online_response(&args.identity_dir, &receipt, registry::unix_now()?)
                    .context("refresh original issuance persistence")?;
            print_completion(&completion)
        }
        ExchangeResponse::Failed {
            code: FailureCode::Rejected,
        } => {
            let replacement = store::replace_refresh_invitation(
                &args.identity_dir,
                profile.digest(),
                snapshot,
                &args.new_invitation_file,
                &args.recovery_out,
            )
            .context("refresh pending invitation replacement")?;
            let completion = perform(&args.identity_dir, profile, &replacement)
                .await
                .context("refresh new authorization")?;
            print_completion(&completion)
        }
        ExchangeResponse::Failed { .. } => {
            bail!("authority did not conclusively reject the original receipt; request retained")
        }
    }
}

pub async fn renew(args: &RenewArgs) -> Result<()> {
    let profile = OnlineProfile::load(&args.bundle_dir, &args.identity_dir)?;
    if let Some(completion) =
        store::resume_online_response(&args.identity_dir, registry::unix_now()?)?
    {
        return print_completion(&completion);
    }
    let status: store::OnlineStatus =
        store::online_status(&args.identity_dir, registry::unix_now()?)?;
    if args.if_due && !status.pending && !status.renewal_due {
        ensure!(
            status.state == "ready",
            "renewal requires a currently valid identity"
        );
        println!("{}", serde_json::to_string(&status)?);
        return Ok(());
    }
    let material = store::begin_online_request(
        &args.identity_dir,
        Operation::Renew,
        profile.digest(),
        None,
        registry::unix_now()?,
    )?;
    let completion = perform(&args.identity_dir, &profile, &material).await?;
    print_completion(&completion)
}

pub fn enable_online(args: &EnableOnlineArgs) -> Result<()> {
    let intent = OnlineMigration::validate(&args.old_bundle_dir, &args.bundle_dir)?;
    store::enable_online(&args.identity_dir, &intent)?;
    println!("{{\"state\":\"online_profile_enabled\"}}");
    Ok(())
}

pub fn online_status(args: &OnlineStatusArgs) -> Result<()> {
    store::resume_online_response(&args.identity_dir, registry::unix_now()?)?;
    let status: store::OnlineStatus =
        store::online_status(&args.identity_dir, registry::unix_now()?)?;
    println!("{}", serde_json::to_string(&status)?);
    Ok(())
}

async fn exchange(
    identity: &std::path::Path,
    profile: &OnlineProfile,
    material: &RequestMaterial,
    purpose: ProofPurpose,
) -> Result<ExchangeResponse> {
    // The connector returns only after both explicit TLS trust checks. Neither
    // the invitation nor the device CSR is available to the outer carrier.
    let mut connection = crate::relay::open_enrollment(profile).await?;
    let deadline = connection.deadline();
    tokio::time::timeout_at(deadline, async {
        let challenge = wire::read_challenge(connection.stream_mut()).await?;
        let signature = store::sign_online_request(
            identity,
            &material.binding,
            &challenge,
            purpose,
            registry::unix_now()?,
        )?;
        let authorize = purpose == ProofPurpose::Authorize;
        let request = wire::ExchangeRequest {
            binding: material.binding.clone(),
            purpose,
            csr_pem: material.csr_pem.clone(),
            predecessor_certificate_pem: if authorize {
                material.predecessor_certificate_pem.clone()
            } else {
                None
            },
            invitation: if authorize {
                material.invitation.as_ref().map(|v| v.to_string())
            } else {
                None
            },
            signature: hex::encode(signature),
        };
        wire::write_request(connection.stream_mut(), &request).await?;
        Ok::<_, anyhow::Error>(wire::read_response(connection.stream_mut()).await?)
    })
    .await?
}

pub(crate) async fn perform(
    identity: &std::path::Path,
    profile: &OnlineProfile,
    material: &RequestMaterial,
) -> Result<LocalCompletion> {
    let mut purpose = if material.resume {
        ProofPurpose::Receipt
    } else {
        ProofPurpose::Authorize
    };
    // Each attempt has a fresh connection challenge and a bounded TLS session.
    // Lost delivery never creates another request or another private key.
    for attempt in 0..3 {
        match exchange(identity, profile, material, purpose).await {
            Ok(ExchangeResponse::Issued { receipt }) => {
                return store::accept_online_response(identity, &receipt, registry::unix_now()?);
            }
            Ok(ExchangeResponse::Failed {
                code: FailureCode::Rejected,
            }) if purpose == ProofPurpose::Receipt => {
                purpose = ProofPurpose::Authorize;
            }
            Ok(ExchangeResponse::Failed {
                code: FailureCode::Rejected,
            }) => {
                bail!("enrollment authorization was rejected; the local request is retained");
            }
            Ok(ExchangeResponse::Failed {
                code: FailureCode::RecoveryRequired,
            }) => {
                bail!("enrollment requires authority recovery; the local request is retained");
            }
            Ok(ExchangeResponse::Failed {
                code: FailureCode::Busy | FailureCode::Unavailable,
            })
            | Err(_) => {
                purpose = ProofPurpose::Receipt;
            }
        }
        if attempt < 2 {
            tokio::time::sleep(Duration::from_millis(100 * (attempt + 1))).await;
        }
    }
    bail!("enrollment is temporarily unavailable; rerun to resume the same local request")
}

#[cfg(all(test, unix))]
#[path = "device_enrollment_tests.rs"]
mod tests;
