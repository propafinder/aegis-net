//! Device enrollment commands; offline operations never load relay runtime state.
use std::path::PathBuf;

#[path = "device_identity_store.rs"]
pub(crate) mod store;

#[derive(Clone, Debug, clap::Args)]
pub struct DeviceArgs {
    #[command(subcommand)]
    pub action: DeviceAction,
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum DeviceAction {
    /// Create an allowlisted public enrollment profile without device secrets.
    BundleCreate(crate::device_bundle::BundleCreateArgs),
    /// Generate the key in its final location, or resume the same request.
    Prepare(PrepareArgs),
    /// Prepare a machine-owned Windows identity for LocalSystem; requires elevation.
    #[cfg(windows)]
    PrepareSystem(PrepareArgs),
    /// Validate and import a public certificate for the existing local key.
    Complete(CompleteArgs),
    /// Inspect enrollment without displaying secret material.
    Status(StatusArgs),
    /// Validate a public enrollment profile and its explicit trust roots.
    BundleInspect(crate::device_bundle::BundleInspectArgs),
    /// Check a completed local identity against the bundle without recovery or network access.
    BundleReady(crate::device_bundle::BundleReadyArgs),
    /// Render an enrolled device configuration from the public profile.
    BundleRender(crate::device_bundle::BundleRenderArgs),
    /// Redeem a protected invitation using the explicitly pinned online profile.
    Redeem(crate::device_enrollment::RedeemArgs),
    /// Recover the same pending request after a pinned receipt query.
    #[cfg(unix)]
    RefreshRedeemInvitation(crate::device_enrollment::RefreshRedeemInvitationArgs),
    /// Renew the same device key using the explicitly pinned online profile.
    Renew(crate::device_enrollment::RenewArgs),
    /// Enable declared online additions while preserving identity and trust roots.
    EnableOnline(crate::device_enrollment::EnableOnlineArgs),
    /// Inspect certificate lifetime and pending online recovery as JSON.
    OnlineStatus(crate::device_enrollment::OnlineStatusArgs),
    /// Recover a retained local response after verifying the expected identity and v3 profile.
    RecoverLocal(crate::device_enrollment::RecoverLocalArgs),
    /// Extract a public ECHConfigList from one DNS HTTPS record for profile pinning.
    /// Performs no DNS or network access; verify with a live handshake before pinning.
    EchFromHttpsRecord(EchFromHttpsRecordArgs),
}

#[derive(Clone, Debug, clap::Args)]
pub struct EchFromHttpsRecordArgs {
    /// File holding one HTTPS record (`dig +short HTTPS name` or `\# LEN HEX`).
    #[arg(long)]
    pub record_file: PathBuf,
}

fn ech_from_https_record(args: &EchFromHttpsRecordArgs) -> anyhow::Result<()> {
    use base64::Engine;
    let text = aegis_core::secret_file::read_config(&args.record_file, 64 * 1024)?;
    let text = std::str::from_utf8(&text)
        .map_err(|_| anyhow::anyhow!("HTTPS record file is not UTF-8"))?;
    let list = aegis_client::ech_policy::ech_config_from_https_record(text)?;
    // Same validation as a pinned profile, including a usable HPKE suite.
    let encoded = base64::engine::general_purpose::STANDARD.encode(&list);
    aegis_client::ech_policy::inline_ech_config(&encoded)?;
    println!(
        "{}",
        serde_json::json!({
            "ech_config_list": encoded,
            "configs": aegis_client::ech_policy::ech_config_summaries(&list)?,
        })
    );
    Ok(())
}

#[derive(Clone, Debug, clap::Args)]
pub struct PrepareArgs {
    #[arg(long)]
    pub device_id: String,
    #[arg(long)]
    pub identity_dir: PathBuf,
    /// Device issuer CA received through an independently trusted channel.
    #[arg(long)]
    pub device_ca: PathBuf,
}

#[derive(Clone, Debug, clap::Args)]
pub struct CompleteArgs {
    #[arg(long)]
    pub identity_dir: PathBuf,
    #[arg(long)]
    pub certificate: PathBuf,
    /// Must match the CA pinned during prepare.
    #[arg(long)]
    pub device_ca: PathBuf,
}

#[derive(Clone, Debug, clap::Args)]
pub struct StatusArgs {
    #[arg(long)]
    pub identity_dir: PathBuf,
    #[arg(long)]
    pub json: bool,
}

pub async fn run_device(args: &DeviceArgs) -> anyhow::Result<()> {
    match &args.action {
        DeviceAction::BundleCreate(args) => return crate::device_bundle::create(args),
        DeviceAction::Prepare(args) => {
            let status = store::prepare(args)?;
            println!("{}", serde_json::to_string(&status)?);
        }
        #[cfg(windows)]
        DeviceAction::PrepareSystem(args) => {
            let status = store::prepare_system(args)?;
            println!("{}", serde_json::to_string(&status)?);
        }
        DeviceAction::Complete(args) => {
            let status = store::complete(args)?;
            println!("{}", serde_json::to_string(&status)?);
        }
        DeviceAction::Status(args) => {
            let status = store::status(&args.identity_dir)?;
            if args.json {
                println!("{}", serde_json::to_string(&status)?);
            } else {
                println!("device enrollment: {}", status.phase);
            }
        }
        DeviceAction::BundleInspect(args) => return crate::device_bundle::inspect(args),
        DeviceAction::BundleReady(args) => return crate::device_bundle::ready(args),
        DeviceAction::BundleRender(args) => return crate::device_bundle::render(args),
        DeviceAction::Redeem(args) => return crate::device_enrollment::redeem(args).await,
        #[cfg(unix)]
        DeviceAction::RefreshRedeemInvitation(args) => {
            return crate::device_enrollment::refresh_redeem_invitation(args).await;
        }
        DeviceAction::Renew(args) => return crate::device_enrollment::renew(args).await,
        DeviceAction::EnableOnline(args) => return crate::device_enrollment::enable_online(args),
        DeviceAction::OnlineStatus(args) => return crate::device_enrollment::online_status(args),
        DeviceAction::RecoverLocal(args) => return crate::device_enrollment::recover_local(args),
        DeviceAction::EchFromHttpsRecord(args) => return ech_from_https_record(args),
    }
    Ok(())
}

#[derive(Clone, Debug, clap::Args)]
pub struct DeviceCsrArgs {
    #[arg(long)]
    pub device_id: String,
    #[arg(long)]
    pub key_out: PathBuf,
    #[arg(long)]
    pub csr_out: PathBuf,
}

pub fn run(args: &DeviceCsrArgs) -> anyhow::Result<()> {
    use aegis_core::secure_channel::enrollment::{generate_csr, write_private_new};
    anyhow::ensure!(
        args.key_out != args.csr_out,
        "device key and CSR require different output files"
    );
    let material = generate_csr(&args.device_id)?;
    write_private_new(&args.key_out, material.private_key_pem.as_bytes())?;
    write_private_new(&args.csr_out, material.csr_pem.as_bytes())?;
    println!("device key and CSR generated; transfer only the CSR to the operator");
    Ok(())
}
