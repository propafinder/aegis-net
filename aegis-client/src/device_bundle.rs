//! Public-only device enrollment profiles. Private identity material never
//! enters a bundle; rendering references its final managed location.
use aegis_client::credential_path_policy::clean_absolute_directory;
#[cfg(any(target_os = "linux", test))]
use aegis_client::public_profile_file::MAX_PUBLIC_BYTES;
use aegis_client::public_profile_file::{read_public, MEMBERS};
use aegis_core::secure_channel::enrollment;
#[cfg(any(target_os = "linux", test))]
use aegis_core::wide_product::{validate_inner_tls_device_settings, WideProductMode};
use anyhow::{ensure, Context, Result};
use clap::Args;
#[cfg(target_os = "linux")]
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::{fs::OpenOptions, io::Read};

pub(crate) use aegis_client::device_bundle_profile::online;
#[cfg(test)]
use aegis_client::device_bundle_profile::policy_settings;
use aegis_client::device_bundle_profile::{
    directories_overlap, inspection, load, load_snapshot, policy_settings_with_overlay,
    profile_digest, settings, validate_ca, validate_profile, PublicProfile,
};

#[cfg(test)]
#[path = "device_bundle_relay_geneva_tests.rs"]
mod relay_geneva_render_tests;

#[cfg(test)]
#[path = "device_bundle_privacy_tests.rs"]
mod privacy_render_tests;

#[derive(Clone, Debug, Args)]
pub struct BundleCreateArgs {
    #[arg(long)]
    pub bundle_dir: PathBuf,
    #[arg(long)]
    pub profile: PathBuf,
    #[arg(long)]
    pub outer_ca: PathBuf,
    #[arg(long)]
    pub inner_ca: PathBuf,
    #[arg(long)]
    pub device_ca: PathBuf,
}

#[derive(Clone, Debug, Args)]
pub struct BundleInspectArgs {
    #[arg(long)]
    pub bundle_dir: PathBuf,
    #[arg(long)]
    pub json: bool,
    /// Pin the public profile after device preparation, before CSR handoff.
    #[arg(long)]
    pub identity_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Args)]
pub struct BundleReadyArgs {
    #[arg(long)]
    pub bundle_dir: PathBuf,
    #[arg(long)]
    pub identity_dir: PathBuf,
    /// Expected enrolled device; a different ready identity is refused.
    #[arg(long)]
    pub device_id: String,
}

#[derive(Clone, Debug, Args)]
pub struct BundleRenderArgs {
    #[arg(long)]
    pub bundle_dir: PathBuf,
    #[arg(long)]
    pub identity_dir: PathBuf,
    /// Final protected configuration directory, not bundle staging.
    #[arg(long)]
    pub config_dir: PathBuf,
    /// New private staging file; existing output is never overwritten.
    #[arg(long)]
    pub output: PathBuf,
    /// Private host-local request; never a member of the public bundle.
    #[arg(long, requires = "relay_geneva_request_sha256")]
    pub relay_geneva_request: Option<PathBuf>,
    /// Exact lowercase SHA256 of the same private request bytes that are parsed.
    #[arg(long, requires = "relay_geneva_request")]
    pub relay_geneva_request_sha256: Option<String>,
    /// Public installed-role proposal; independently pinned before enrollment.
    #[arg(long, requires_all = ["relay_geneva_profile_sha256", "relay_geneva_request"])]
    pub relay_geneva_profile_manifest: Option<PathBuf>,
    #[arg(long, requires = "relay_geneva_profile_manifest")]
    pub relay_geneva_profile_sha256: Option<String>,
    /// Validate planned configuration before enrollment, without pin/output writes.
    #[arg(long)]
    pub validate_only: bool,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedRelayGenevaRequest {
    schema: String,
    profile_sha256: String,
    request: aegis_core::relay_geneva::RelayOuterGenevaSettings,
}

pub fn create(args: &BundleCreateArgs) -> Result<()> {
    let payload = [
        read_public(&args.profile)?,
        read_public(&args.outer_ca)?,
        read_public(&args.inner_ca)?,
        read_public(&args.device_ca)?,
    ];
    validate_profile(&payload[0])?;
    for bytes in &payload[1..] {
        validate_ca(bytes)?;
    }
    enrollment::validate_device_ca(&payload[3])?;
    // Validate every input before creating even a private output directory.
    // This producer never copies a caller's whole folder or a private key.
    enrollment::trusted_parent(&args.bundle_dir)?;
    #[allow(unused_mut)] // Unix sets the creation mode below.
    #[cfg(not(windows))]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    #[cfg(not(windows))]
    let created = builder.create(&args.bundle_dir);
    #[cfg(windows)]
    let created =
        aegis_core::windows_file::create_private_directory(&args.bundle_dir, false, false);
    created.context("public bundle output must be a new directory")?;
    for (name, bytes) in MEMBERS.iter().zip(&payload).skip(1) {
        enrollment::write_private_new(&args.bundle_dir.join(name), bytes)?;
    }
    enrollment::write_private_new(&args.bundle_dir.join(MEMBERS[0]), &payload[0])?;
    aegis_core::secret_file::sync_directory(&args.bundle_dir)?;
    println!("public device enrollment bundle created");
    Ok(())
}

pub fn inspect(args: &BundleInspectArgs) -> Result<()> {
    let output = inspect_metadata(args)?;
    if args.json {
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("public device enrollment bundle validated");
    }
    Ok(())
}

/// Read-only local admission for an already enrolled device. Inspection and
/// planned rendering remain available before enrollment; this command neither
/// creates a trust pin nor recovers a pending response or contacts the relay.
pub fn ready(args: &BundleReadyArgs) -> Result<()> {
    let status = ready_metadata(args, aegis_core::secure_channel::registry::unix_now()?)?;
    println!("{}", serde_json::to_string(&status)?);
    Ok(())
}

pub(crate) fn ready_metadata(
    args: &BundleReadyArgs,
    now: u64,
) -> Result<crate::device_identity::store::BundleReadyStatus> {
    ensure!(
        clean_absolute_directory(&args.bundle_dir)
            && clean_absolute_directory(&args.identity_dir)
            && !directories_overlap(&args.identity_dir, &args.bundle_dir)?,
        "bundle readiness requires separate clean absolute bundle and identity directories"
    );
    let (_, digest, members) = load_snapshot(&args.bundle_dir)?;
    let status = crate::device_identity::store::bundle_ready(
        &args.identity_dir,
        &args.device_id,
        &digest,
        &members["device-ca.pem"],
        now,
    )?;
    let (_, closed_digest, closed_members) = load_snapshot(&args.bundle_dir)?;
    ensure!(
        digest == closed_digest && members == closed_members,
        "public bundle changed during readiness check"
    );
    Ok(status)
}

fn inspect_metadata(args: &BundleInspectArgs) -> Result<serde_json::Value> {
    let profile = load(&args.bundle_dir)?;
    if let Some(identity) = &args.identity_dir {
        pin_profile(&args.bundle_dir, identity)?;
    }
    let mut output = inspection(&profile)?;
    if matches!(
        profile.schema.as_str(),
        "aegis_device_bundle_v3" | "aegis_device_bundle_v4"
    ) {
        // This is the same exact four-file public binding used by preparation
        // and online enrollment. Inspection itself creates no device identity.
        output["profile_sha256"] = profile_digest(&args.bundle_dir)?.into();
    }
    Ok(output)
}

fn pin_profile(bundle: &Path, identity: &Path) -> Result<()> {
    pin_profile_digest(&profile_digest(bundle)?, identity)
}

fn pin_profile_digest(expected: &str, identity: &Path) -> Result<()> {
    #[cfg(not(windows))]
    use std::io::Write;
    let path = identity.join("bundle-profile.sha256");
    let directory = enrollment::trusted_parent(&path)?;
    #[cfg(windows)]
    {
        let machine = aegis_core::windows_file::trusted_system_directory(&directory).is_ok();
        let saved = if machine {
            aegis_core::windows_file::atomic_write_machine_private(
                &path,
                expected.as_bytes(),
                false,
            )
        } else {
            aegis_core::windows_file::atomic_write_private(&path, expected.as_bytes(), false, false)
        };
        match saved {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    #[cfg(not(windows))]
    {
        let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
        temporary.write_all(expected.as_bytes())?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => fs::File::open(directory)?.sync_all()?,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.error.into()),
        }
    }
    #[cfg(windows)]
    if aegis_core::windows_file::trusted_system_directory(&directory).is_ok() {
        aegis_core::windows_file::validate_machine_private(&fs::File::open(&path)?)?;
    }
    let actual = read_public(&path)?;
    ensure!(
        actual.as_slice() == expected.as_bytes(),
        "public enrollment profile changed since device preparation"
    );
    Ok(())
}

fn validate_relay_geneva_arguments(args: &BundleRenderArgs) -> Result<()> {
    ensure!(
        args.relay_geneva_request.is_some() == args.relay_geneva_request_sha256.is_some(),
        "relay Geneva request path and SHA256 must be supplied together"
    );
    ensure!(
        args.relay_geneva_profile_manifest.is_some() == args.relay_geneva_profile_sha256.is_some(),
        "relay Geneva profile manifest and SHA256 must be supplied together"
    );
    ensure!(
        args.relay_geneva_profile_manifest.is_none() || args.relay_geneva_request.is_some(),
        "relay Geneva profile manifest requires the private request pair"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_relay_geneva_request(path: &Path, bundle: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    ensure!(
        clean_absolute_directory(path),
        "relay Geneva request requires a clean absolute path"
    );
    let parent = enrollment::trusted_parent(path)?;
    let path = parent.join(
        path.file_name()
            .context("relay Geneva request file name missing")?,
    );
    ensure!(
        !path.starts_with(bundle.canonicalize()?),
        "relay Geneva request must remain outside the public bundle"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let before = file.metadata()?;
    // Descriptor and named generations agree without following a final link.
    let generation = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.uid(),
            m.gid(),
            m.mode(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    // SAFETY: geteuid only reads the effective process identity.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        before.is_file()
            && before.len() <= MAX_PUBLIC_BYTES
            && before.nlink() == 1
            && (before.uid() == 0 || before.uid() == uid)
            && before.mode() & 0o077 == 0
            && generation(&before) == generation(&fs::symlink_metadata(&path)?),
        "relay Geneva request must be a bounded protected private ordinary file"
    );
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    (&mut file)
        .take(MAX_PUBLIC_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_PUBLIC_BYTES
            && generation(&file.metadata()?) == generation(&before)
            && generation(&fs::symlink_metadata(&path)?) == generation(&before)
            && enrollment::trusted_parent(&path)? == parent,
        "relay Geneva request changed during its bounded read"
    );
    Ok(bytes)
}

fn relay_geneva_planned_parent(path: &Path) -> Result<PathBuf> {
    ensure!(
        clean_absolute_directory(path),
        "selected configuration requires a clean absolute path"
    );
    let mut ancestor = path
        .parent()
        .context("selected configuration parent missing")?;
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(
                    ancestor
                        .file_name()
                        .context("selected configuration ancestor missing")?,
                );
                ancestor = ancestor
                    .parent()
                    .context("selected configuration root missing")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    // Validate existing ancestry without creating the intended directories or
    // reading keys. The real writer independently validates its actual parent.
    let mut resolved = enrollment::trusted_parent(&ancestor.join(".aegis-planned-config"))?;
    for name in missing.into_iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

fn select_relay_geneva_request(
    args: &BundleRenderArgs,
    profile: &PublicProfile,
    profile_sha256: &str,
    settings: &mut aegis_core::Settings,
) -> Result<()> {
    validate_relay_geneva_arguments(args)?;
    let (Some(path), Some(expected)) = (
        &args.relay_geneva_request,
        &args.relay_geneva_request_sha256,
    ) else {
        return Ok(());
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, expected, profile, profile_sha256, settings);
        anyhow::bail!("managed relay Geneva rendering requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        use sha2::{Digest, Sha256};

        ensure!(
            profile.mode()? == WideProductMode::FullWideTun,
            "managed relay Geneva rendering requires the full-wide inner TLS profile"
        );
        ensure!(
            expected.len() == 64
                && expected
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "relay Geneva request SHA256 must be lowercase hexadecimal"
        );
        let bytes = read_relay_geneva_request(path, &args.bundle_dir)?;
        ensure!(
            hex::encode(Sha256::digest(&*bytes)) == *expected,
            "relay Geneva request SHA256 differs"
        );
        // Hash verification and typed parsing use this exact descriptor-read buffer.
        // Parser details may contain private strategy/unknown field text.
        let selected: ManagedRelayGenevaRequest = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid private relay Geneva request"))?;
        ensure!(
            selected.schema == "aegis_relay_geneva_managed_request_v1"
                && selected.profile_sha256 == profile_sha256,
            "relay Geneva request differs from the exact public profile"
        );
        let output_parent = relay_geneva_planned_parent(&args.output)?;
        let config = relay_geneva_planned_parent(&args.config_dir.join(".aegis-planned-config"))?;
        let identity =
            relay_geneva_planned_parent(&args.identity_dir.join(".aegis-planned-identity"))?;
        let bundle = args.bundle_dir.canonicalize()?;
        ensure!(
            !output_parent.starts_with(&bundle)
                && !directories_overlap(&config, &bundle)?
                && !directories_overlap(&identity, &bundle)?
                && !directories_overlap(&identity, &config)?,
            "selected private configuration and identity must remain separate from the public bundle"
        );
        settings.relay.outer_geneva = Some(selected.request);
        settings
            .validate_relay_outer_geneva()
            .map_err(|_| anyhow::anyhow!("private relay Geneva policy refused"))?;
        validate_inner_tls_device_settings(WideProductMode::FullWideTun, profile.udp, settings)
            .map_err(|_| anyhow::anyhow!("private relay Geneva policy refused"))?;
        Ok(())
    }
}

fn validate_relay_geneva_manifest(
    args: &BundleRenderArgs,
    profile: &PublicProfile,
    settings: &aegis_core::Settings,
    member_pins: &BTreeMap<String, String>,
) -> Result<()> {
    let (Some(path), Some(expected)) = (
        &args.relay_geneva_profile_manifest,
        &args.relay_geneva_profile_sha256,
    ) else {
        return Ok(());
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, expected, profile, settings, member_pins);
        anyhow::bail!("managed relay Geneva rendering requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        use sha2::{Digest, Sha256};

        ensure!(
            clean_absolute_directory(path)
                && expected.len() == 64
                && expected
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "relay Geneva profile requires a clean absolute path and lowercase SHA256"
        );
        // This existing bounded metadata reader rejects links, writable ancestry
        // and nonordinary files. Hash and parser receive its SAME raw UTF-8 bytes.
        let raw = crate::profile::read_install_metadata(path)
            .map_err(|_| anyhow::anyhow!("relay Geneva profile metadata refused"))?;
        ensure!(
            hex::encode(Sha256::digest(raw.as_bytes())) == *expected,
            "relay Geneva profile SHA256 differs"
        );
        crate::profile_relay_geneva::validate_managed_proposal(
            raw.as_bytes(),
            settings,
            member_pins,
            matches!(
                profile.schema.as_str(),
                "aegis_device_bundle_v3" | "aegis_device_bundle_v4"
            ),
        )
        .map_err(|_| anyhow::anyhow!("private relay Geneva policy refused"))?;
        Ok(())
    }
}

pub fn render(args: &BundleRenderArgs) -> Result<()> {
    validate_relay_geneva_arguments(args)?;
    let (profile, profile_sha256, member_pins) = load_snapshot(&args.bundle_dir)?;
    let mut settings = match fs::symlink_metadata(&args.identity_dir) {
        Err(error) if args.validate_only && error.kind() == std::io::ErrorKind::NotFound => {
            // Pre-enrollment planning has no final identity or private sidecar.
            // Resolve and validate its existing ancestry without creating it.
            let identity =
                relay_geneva_planned_parent(&args.identity_dir.join(".aegis-planned-identity"))?;
            let config =
                relay_geneva_planned_parent(&args.config_dir.join(".aegis-planned-config"))?;
            ensure!(
                !directories_overlap(&identity, &config)?
                    && !directories_overlap(&identity, &args.bundle_dir.canonicalize()?)?,
                "private device identity must be outside configuration and public bundle"
            );
            policy_settings_with_overlay(&profile, &args.identity_dir, &args.config_dir, false)?
        }
        Err(_) => {
            return Err(anyhow::anyhow!(
                "private device identity directory rejected"
            ))
        }
        Ok(_) => settings(&profile, &args.identity_dir, &args.config_dir)?,
    };
    select_relay_geneva_request(args, &profile, &profile_sha256, &mut settings)?;
    validate_relay_geneva_manifest(args, &profile, &settings, &member_pins)?;
    ensure!(
        !directories_overlap(&args.identity_dir, &args.bundle_dir)?,
        "private device identity must be outside the public bundle"
    );
    let rendered = toml::to_string_pretty(&settings)?;
    ensure!(
        profile_digest(&args.bundle_dir)? == profile_sha256,
        "public enrollment profile changed during rendering"
    );
    if args.validate_only {
        println!("managed device configuration validated; no profile pin or output written");
        return Ok(());
    }
    pin_profile_digest(&profile_sha256, &args.identity_dir)?;
    enrollment::write_private_new(&args.output, rendered.as_bytes())?;
    println!("managed inner TLS configuration rendered");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn public_ech_renders_inline_without_new_members_or_files_and_pins_exact_bytes() {
        let bundle = fixture();
        let config = tempfile::tempdir().unwrap();
        let identity = tempfile::tempdir().unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(bundle.path().join("bundle.json")).unwrap()).unwrap();
        let encoded = crate::relay::inline_ech_fixture();
        value["ech_config_list"] = encoded.clone().into();
        fs::write(
            bundle.path().join("bundle.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        let profile = load(bundle.path()).unwrap();
        let managed = settings(&profile, identity.path(), config.path()).unwrap();
        assert!(managed.relay.ech_config_list.is_none());
        assert_eq!(
            managed.relay.ech_config_list_base64.as_deref(),
            Some(encoded.as_str())
        );
        managed.validate_ech().unwrap();
        let rendered = toml::to_string(&managed).unwrap();
        let reloaded: aegis_core::Settings = toml::from_str(&rendered).unwrap();
        assert_eq!(reloaded.relay.ech_config_list_base64, Some(encoded.clone()));
        assert!(!rendered.contains(bundle.path().to_str().unwrap()));
        assert_eq!(fs::read_dir(bundle.path()).unwrap().count(), MEMBERS.len());
        assert_eq!(fs::read_dir(config.path()).unwrap().count(), 0);
        pin_profile(bundle.path(), identity.path()).unwrap();
        let first = profile_digest(bundle.path()).unwrap();
        let mut alternate = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        alternate[6] = 2; // Another valid config_id changes the bound public policy.
        value["ech_config_list"] = base64::engine::general_purpose::STANDARD
            .encode(alternate)
            .into();
        fs::write(
            bundle.path().join("bundle.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(load(bundle.path()).is_ok());
        assert_ne!(profile_digest(bundle.path()).unwrap(), first);
        assert!(pin_profile(bundle.path(), identity.path()).is_err());
    }

    #[test]
    fn public_ech_invalid_null_paths_encoding_and_size_refuse_before_output_or_pin() {
        let bundle = fixture();
        let initial: serde_json::Value =
            serde_json::from_slice(&fs::read(bundle.path().join("bundle.json")).unwrap()).unwrap();
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!(""),
            serde_json::json!("/private/credential.key"),
            serde_json::json!("private-sentinel!"),
            serde_json::json!("A".repeat(21849)),
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(b"PRIVATE KEY")),
        ] {
            let mut value = initial.clone();
            value["ech_config_list"] = invalid;
            fs::write(
                bundle.path().join("bundle.json"),
                serde_json::to_vec(&value).unwrap(),
            )
            .unwrap();
            let identity = tempfile::tempdir().unwrap();
            let config = tempfile::tempdir().unwrap();
            let output = config.path().join("new.toml");
            let result = render(&BundleRenderArgs {
                bundle_dir: bundle.path().into(),
                identity_dir: identity.path().into(),
                config_dir: config.path().into(),
                output: output.clone(),
                relay_geneva_request: None,
                relay_geneva_request_sha256: None,
                relay_geneva_profile_manifest: None,
                relay_geneva_profile_sha256: None,
                validate_only: false,
            });
            assert!(result.is_err());
            assert!(!output.exists());
            assert!(!identity.path().join("bundle-profile.sha256").exists());
            assert!(!format!("{:#}", result.unwrap_err()).contains("private-sentinel"));
        }
    }

    #[test]
    fn public_profile_without_ech_preserves_legacy_config_and_four_member_contract() {
        let bundle = fixture();
        let profile = load(bundle.path()).unwrap();
        assert!(profile.ech_config_list.is_none());
        assert!(inspection(&profile)
            .unwrap()
            .get("ech_config_list")
            .is_none());
        let identity = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let managed = settings(&profile, identity.path(), config.path()).unwrap();
        assert!(managed.relay.ech_config_list.is_none());
        assert!(managed.relay.ech_config_list_base64.is_none());
        assert!(managed.relay.outer_geneva.is_none());
        assert!(!toml::to_string(&managed)
            .unwrap()
            .contains("ech_config_list_base64"));
    }
    #[test]
    fn absolute_directory_validation_retains_native_root_and_rejects_dot_segments() {
        let root = tempfile::tempdir().unwrap();
        assert!(clean_absolute_directory(&root.path().join("identity")));
        assert!(!clean_absolute_directory(&root.path().join("identity/..")));
        assert!(!clean_absolute_directory(&root.path().join("identity/.")));
        assert!(!clean_absolute_directory(Path::new("relative/identity")));
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_paths_require_local_drive_without_alias_components() {
        for path in [
            r"C:\AEGIS\identity",
            r"\\?\C:\AEGIS\identity",
            r"C:\Пользователь\AEGIS",
        ] {
            assert!(clean_absolute_directory(Path::new(path)), "{path}");
        }
        for path in [
            r"C:identity",
            r"C:\",
            r"\\server\share\identity",
            r"\\.\C:\identity",
            r"C:\AEGIS\..\identity",
            r"C:\AEGIS\.\identity",
            r"C:\AEGIS\identity:stream",
            r"C:\AEGIS\identity.",
            r"C:\AEGIS\identity ",
        ] {
            assert!(!clean_absolute_directory(Path::new(path)), "{path}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_identity_separation_rejects_case_and_prefix_aliases() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("Config");
        for identity in [
            root.path().join("config"),
            root.path().join("CONFIG/identity"),
            root.path().canonicalize().unwrap().join("config/identity"),
        ] {
            assert!(directories_overlap(&identity, &config).unwrap());
            assert!(directories_overlap(&config, &identity).unwrap());
        }
        assert!(directories_overlap(
            &root.path().join("ПРОФИЛЬ/identity"),
            &root.path().join("профиль")
        )
        .unwrap());
        assert!(!directories_overlap(&root.path().join("config-other"), &config).unwrap());
        assert!(!directories_overlap(&root.path().join("identity"), &config).unwrap());
    }

    pub(super) fn fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let mut parameters = rcgen::CertificateParams::new(vec!["fixture.test".into()]).unwrap();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let certificate = parameters
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        for member in &MEMBERS[1..] {
            fs::write(directory.path().join(member), certificate.pem()).unwrap();
        }
        fs::write(directory.path().join("bundle.json"), br#"{"schema":"aegis_device_bundle_v1","relay_server":"relay.test:443","outer_server_name":"relay.test","inner_server_name":"origin.test","udp":false}"#).unwrap();
        directory
    }

    #[test]
    fn typed_public_profile_renders_only_managed_paths_and_authenticated_transport() {
        let directory = fixture();
        let profile =
            validate_profile(&fs::read(directory.path().join("bundle.json")).unwrap()).unwrap();
        let independent = tempfile::tempdir().unwrap();
        let identity_path = independent.path().join("identity");
        let config_path = independent.path().join("config");
        fs::create_dir(&identity_path).unwrap();
        let config = settings(&profile, &identity_path, &config_path).unwrap();
        assert!(config.relay.auth_token.is_empty());
        assert_eq!(config.relay.udp_transport_priority, Some(vec![]));
        assert_eq!(
            config.relay.inner_tls.as_ref().unwrap().key,
            identity_path.join("device.key")
        );
        assert_eq!(
            config.relay.inner_tls.as_ref().unwrap().server_ca,
            config_path.join("inner-ca.pem")
        );
        let rendered = toml::to_string(&config).unwrap();
        let parsed: aegis_core::Settings = toml::from_str(&rendered).unwrap();
        parsed.validate_inner_tls().unwrap();
        assert!(!rendered.contains(directory.path().to_str().unwrap()));
    }

    fn write_profile(directory: &Path, schema: &str, mode: Option<&str>, udp: bool, server: &str) {
        let mut value = serde_json::json!({
            "schema":schema,"relay_server":server,"outer_server_name":"relay.test",
            "inner_server_name":"origin.test","udp":udp,
        });
        if let Some(mode) = mode {
            value["product_mode"] = mode.into();
        }
        fs::write(
            directory.join("bundle.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn normalized_inspection_is_exact_about_scope_and_inner_udp_transport() {
        let directory = fixture();
        let old = inspection(&load(directory.path()).unwrap()).unwrap();
        assert_eq!(old["product_mode"], "socks-only");
        assert_eq!(old["resolved"]["capture_scope"], "per_app");
        assert_eq!(old["resolved"]["udp_transport"], "disabled");
        write_profile(
            directory.path(),
            "aegis_device_bundle_v2",
            Some("full-wide-tun"),
            true,
            "127.0.0.1:443",
        );
        let full = inspection(&load(directory.path()).unwrap()).unwrap();
        assert_eq!(full["resolved"]["capture_scope"], "local_host");
        assert_eq!(full["resolved"]["tcp_transport"], "grpc_stream");
        assert_eq!(full["resolved"]["udp_transport"], "grpc_datagram");
        assert_eq!(full["resolved"]["udp_policy"], "masque_direct"); // Stable capture policy ID, not wire transport.
        assert_eq!(full["resolved"]["ipv6_policy"], "tun_carried");
        assert_eq!(full["resolved"]["inner_tls"], true);
        assert_eq!(full["resolved"]["native_fallback"], false);
        assert_eq!(full["resolved"]["requires_privileged_capture"], true);
    }

    #[test]
    fn legacy_inspector_metadata_has_no_online_digest_or_identity_side_effects() {
        let directory = fixture();
        for (schema, mode) in [
            ("aegis_device_bundle_v1", None),
            ("aegis_device_bundle_v2", Some("socks-only")),
        ] {
            write_profile(directory.path(), schema, mode, false, "relay.test:443");
            let old_output = inspection(&load(directory.path()).unwrap()).unwrap();
            let actual = inspect_metadata(&BundleInspectArgs {
                bundle_dir: directory.path().to_owned(),
                json: true,
                identity_dir: None,
            })
            .unwrap();
            assert_eq!(actual, old_output);
            assert!(actual.get("profile_sha256").is_none());
            assert_eq!(
                fs::read_dir(directory.path()).unwrap().count(),
                MEMBERS.len()
            );
        }
    }

    #[tokio::test]
    async fn public_v3_digest_matches_real_preparation_pin_and_detects_each_public_change() {
        use crate::device_identity::{run_device, DeviceAction, DeviceArgs, PrepareArgs};
        let directory = fixture();
        let mut profile: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.path().join("bundle.json")).unwrap())
                .unwrap();
        profile["schema"] = "aegis_device_bundle_v3".into();
        profile["product_mode"] = "socks-only".into();
        profile["enrollment"] = serde_json::json!({
            "protocol":"aegis-enrollment-v1",
            "authority_server":"authority.test:8443",
            "outer_server_name":"authority.test",
            "inner_server_name":"issuer.test",
            "automatic_renewal":true,
            "renewal_policy":"same-key-v1"
        });
        fs::write(
            directory.path().join("bundle.json"),
            serde_json::to_vec(&profile).unwrap(),
        )
        .unwrap();
        let bytes: Vec<_> = MEMBERS
            .iter()
            .map(|name| fs::read(directory.path().join(name)).unwrap())
            .collect();
        let parent = tempfile::tempdir().unwrap();
        let identity = parent.path().canonicalize().unwrap().join("identity");
        let mut args = BundleInspectArgs {
            bundle_dir: directory.path().to_owned(),
            json: true,
            identity_dir: None,
        };
        let public = inspect_metadata(&args).unwrap();
        let digest = public["profile_sha256"].as_str().unwrap().to_owned();
        assert_eq!(digest.len(), 64);
        assert!(!identity.exists());
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            MEMBERS.len()
        );
        for (name, before) in MEMBERS.iter().zip(&bytes) {
            assert_eq!(fs::read(directory.path().join(name)).unwrap(), *before);
        }
        run_device(&DeviceArgs {
            action: DeviceAction::Prepare(PrepareArgs {
                device_id: "inspection-device".into(),
                identity_dir: identity.clone(),
                device_ca: directory.path().join("device-ca.pem"),
            }),
        })
        .await
        .unwrap();
        args.identity_dir = Some(identity.clone());
        assert_eq!(inspect_metadata(&args).unwrap(), public);
        let pin = identity.join("bundle-profile.sha256");
        assert_eq!(fs::read(&pin).unwrap(), digest.as_bytes());
        assert_eq!(
            online::OnlineProfile::load(directory.path(), &identity)
                .unwrap()
                .digest(),
            digest
        );
        let key_before = fs::read(identity.join("device.key")).unwrap();
        for (name, before) in MEMBERS.iter().zip(&bytes) {
            // Whitespace preserves the public JSON/PEM semantics but changes
            // the exact public bundle bytes bound by the issuer and device.
            let mut changed = before.clone();
            changed.push(b'\n');
            fs::write(directory.path().join(name), changed).unwrap();
            args.identity_dir = None;
            assert_ne!(inspect_metadata(&args).unwrap()["profile_sha256"], digest);
            args.identity_dir = Some(identity.clone());
            assert!(inspect_metadata(&args).is_err());
            assert!(online::OnlineProfile::load(directory.path(), &identity).is_err());
            assert_eq!(fs::read(&pin).unwrap(), digest.as_bytes());
            assert_eq!(fs::read(identity.join("device.key")).unwrap(), key_before);
            fs::write(directory.path().join(name), before).unwrap();
        }
    }

    #[test]
    fn invalid_device_profiles_refuse_before_output_or_profile_pin() {
        let directory = fixture();
        let destination = tempfile::tempdir().unwrap();
        for (schema, mode, udp, server) in [
            (
                "aegis_device_bundle_v1",
                Some("full-wide-tun"),
                true,
                "127.0.0.1:443",
            ),
            (
                "aegis_device_bundle_v1",
                Some("socks-only"),
                false,
                "relay.test:443",
            ),
            ("aegis_device_bundle_v2", None, true, "127.0.0.1:443"),
            (
                "aegis_device_bundle_v2",
                Some("wide-compat"),
                true,
                "127.0.0.1:443",
            ),
            (
                "aegis_device_bundle_v2",
                Some("full-wide-hybrid-geneva"),
                true,
                "127.0.0.1:443",
            ),
            (
                "aegis_device_bundle_v2",
                Some("full-wide-tun"),
                false,
                "127.0.0.1:443",
            ),
            (
                "aegis_device_bundle_v2",
                Some("full-wide-tun"),
                true,
                "relay.test:443",
            ),
            (
                "aegis_device_bundle_v2",
                Some("full-wide-tun"),
                true,
                "[::1]:443",
            ),
            (
                "aegis_device_bundle_v2",
                Some("full-wide-tun"),
                true,
                "198.19.0.2:443",
            ),
            (
                "aegis_device_bundle_v2",
                Some("full-wide-tun"),
                true,
                "0.0.0.0:443",
            ),
        ] {
            write_profile(directory.path(), schema, mode, udp, server);
            let output = destination.path().join("rendered.toml");
            assert!(
                render(&BundleRenderArgs {
                    bundle_dir: directory.path().to_path_buf(),
                    identity_dir: destination.path().join("identity"),
                    config_dir: destination.path().join("config"),
                    output: output.clone(),
                    relay_geneva_request: None,
                    relay_geneva_request_sha256: None,
                    relay_geneva_profile_manifest: None,
                    relay_geneva_profile_sha256: None,
                    validate_only: false,
                })
                .is_err(),
                "{schema} {mode:?} {udp} {server}"
            );
            assert!(!output.exists());
            assert!(!destination.path().join("identity").exists());
        }
        for schema in ["aegis_device_bundle_v1", "aegis_device_bundle_v2"] {
            for field in [
                "direct",
                "masque_server",
                "key",
                "transport_priority",
                "resolved",
            ] {
                write_profile(
                    directory.path(),
                    schema,
                    (schema.ends_with("v2")).then_some("socks-only"),
                    false,
                    "relay.test:443",
                );
                let path = directory.path().join("bundle.json");
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value[field] = "forbidden".into();
                fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
                assert!(load(directory.path()).is_err(), "{schema} {field}");
                let output = destination.path().join("public-output");
                assert!(create(&BundleCreateArgs {
                    bundle_dir: output.clone(),
                    profile: path,
                    outer_ca: directory.path().join("outer-ca.pem"),
                    inner_ca: directory.path().join("inner-ca.pem"),
                    device_ca: directory.path().join("device-ca.pem"),
                })
                .is_err());
                assert!(!output.exists());
            }
        }
    }

    #[test]
    fn rendered_profiles_load_through_real_identity_and_configuration_validation() {
        for (schema, mode, udp) in [
            ("aegis_device_bundle_v1", None, false),
            ("aegis_device_bundle_v2", Some("socks-only"), true),
            ("aegis_device_bundle_v2", Some("full-wide-tun"), true),
        ] {
            let bundle = fixture();
            write_profile(bundle.path(), schema, mode, udp, "127.0.0.1:443");
            let identity = tempfile::tempdir().unwrap();
            let config = tempfile::tempdir().unwrap();
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let mut parameters = rcgen::CertificateParams::new(vec![]).unwrap();
            parameters.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            let certificate = parameters.self_signed(&key).unwrap();
            enrollment::write_private_new(
                &identity.path().join("device.key"),
                key.serialize_pem().as_bytes(),
            )
            .unwrap();
            enrollment::write_private_new(
                &identity.path().join("device.pem"),
                certificate.pem().as_bytes(),
            )
            .unwrap();
            for (source, final_name) in
                [("outer-ca.pem", "ca.pem"), ("inner-ca.pem", "inner-ca.pem")]
            {
                enrollment::write_private_new(
                    &config.path().join(final_name),
                    &fs::read(bundle.path().join(source)).unwrap(),
                )
                .unwrap();
            }
            let output = config.path().join("aegis.toml");
            render(&BundleRenderArgs {
                bundle_dir: bundle.path().to_path_buf(),
                identity_dir: identity.path().to_path_buf(),
                config_dir: config.path().to_path_buf(),
                output: output.clone(),
                relay_geneva_request: None,
                relay_geneva_request_sha256: None,
                relay_geneva_profile_manifest: None,
                relay_geneva_profile_sha256: None,
                validate_only: false,
            })
            .unwrap();
            let loaded = crate::config::load_config(&output).unwrap();
            let resolved_mode = load(bundle.path()).unwrap().mode().unwrap();
            validate_inner_tls_device_settings(resolved_mode, udp, &loaded).unwrap();
            assert_eq!(
                loaded.windows_tunnel.is_some(),
                cfg!(windows) && resolved_mode == WideProductMode::FullWideTun
            );
            assert_eq!(
                loaded.relay.inner_tls.unwrap().key,
                identity.path().join("device.key")
            );
            assert!(!fs::read_to_string(&output).unwrap().contains("PRIVATE KEY"));
            assert!(!config.path().join("device.key").exists());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn capture_and_transport_downgrades_and_identity_config_overlap_are_refused() {
        let directory = fixture();
        write_profile(
            directory.path(),
            "aegis_device_bundle_v2",
            Some("full-wide-tun"),
            true,
            "127.0.0.1:443",
        );
        let profile = load(directory.path()).unwrap();
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config");
        let identity = root.path().join("identity");
        fs::create_dir(&identity).unwrap();
        assert!(settings(&profile, &config.join("identity"), &config).is_err());
        assert!(settings(&profile, &root.path().join("state/../identity"), &config).is_err());
        let baseline = settings(&profile, &identity, &config).unwrap();
        let changes: Vec<fn(&mut aegis_core::Settings)> = vec![
            |c| c.mode = aegis_core::Mode::Direct,
            |c| c.relay.inner_tls = None,
            |c| {
                c.relay.udp_transport_priority =
                    Some(vec![aegis_core::TunnelTransportFamily::MasqueDerived])
            },
            |c| c.relay.masque_server = Some("127.0.0.1:443".into()),
            |c| c.ingress.allow_fallback = true,
            |c| match &mut c.windows_tunnel {
                Some(tunnel) => tunnel.kill_switch = false,
                None => c.ingress.wide.ipv6_tun_carried = false,
            },
            |c| match &mut c.windows_tunnel {
                Some(tunnel) => tunnel.configure_dns = false,
                None => c.ingress.wide.capture_dns = false,
            },
            |c| match &mut c.windows_tunnel {
                Some(tunnel) => tunnel.include_routes = vec!["203.0.113.0/24".into()],
                None => {
                    c.ingress.wide.platform_backend = aegis_core::WidePlatformBackend::LinuxTproxy
                }
            },
        ];
        for change in changes {
            let mut changed = baseline.clone();
            change(&mut changed);
            assert_ne!(
                serde_json::to_value(&changed).unwrap(),
                serde_json::to_value(&baseline).unwrap(),
                "each negative case must change the native capture policy"
            );
            assert!(validate_inner_tls_device_settings(
                WideProductMode::FullWideTun,
                true,
                &changed
            )
            .is_err());
        }
    }

    #[test]
    fn public_profile_refuses_additional_members_and_embedded_private_keys() {
        let directory = fixture();
        fs::write(directory.path().join("device.key"), "not exported").unwrap();
        assert!(load(directory.path()).is_err());
        fs::remove_file(directory.path().join("device.key")).unwrap();
        let path = directory.path().join("inner-ca.pem");
        let content = fs::read_to_string(&path).unwrap() + "\n-----BEGIN PRIVATE KEY-----\n";
        fs::write(path, content).unwrap();
        assert!(load(directory.path()).is_err());
    }

    #[test]
    fn public_ca_rejects_binary_secret_suffix_and_arbitrary_prefix_or_trailer() {
        let directory = fixture();
        let path = directory.path().join("outer-ca.pem");
        let certificate = fs::read(&path).unwrap();
        validate_ca(&certificate).unwrap();
        let key_der = rcgen::KeyPair::generate().unwrap().serialize_der();
        for invalid in [
            [certificate.as_slice(), key_der.as_slice()].concat(),
            [b"untrusted prefix\n", certificate.as_slice()].concat(),
            [certificate.as_slice(), b"\nuntrusted trailer"].concat(),
        ] {
            fs::write(&path, &invalid).unwrap();
            assert!(load(directory.path()).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn public_profile_pin_is_idempotent_and_rejects_changes() {
        let directory = fixture();
        let identity = tempfile::tempdir().unwrap();
        pin_profile(directory.path(), identity.path()).unwrap();
        pin_profile(directory.path(), identity.path()).unwrap();
        let path = directory.path().join("bundle.json");
        let changed = fs::read_to_string(&path)
            .unwrap()
            .replace("origin.test", "changed.test");
        fs::write(path, changed).unwrap();
        assert!(pin_profile(directory.path(), identity.path()).is_err());
        assert_eq!(fs::read_dir(identity.path()).unwrap().count(), 1);
    }

    #[test]
    fn public_producer_rejects_private_input_before_creating_output() {
        let directory = fixture();
        let destination = tempfile::tempdir().unwrap();
        let output = destination.path().join("bundle");
        let private = directory.path().join("private.pem");
        fs::write(
            &private,
            "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----",
        )
        .unwrap();
        let args = BundleCreateArgs {
            bundle_dir: output.clone(),
            profile: directory.path().join("bundle.json"),
            outer_ca: directory.path().join("outer-ca.pem"),
            inner_ca: private,
            device_ca: directory.path().join("device-ca.pem"),
        };
        assert!(create(&args).is_err());
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn public_profile_refuses_links_and_unknown_authority_fields() {
        let directory = fixture();
        let path = directory.path().join("bundle.json");
        let original = fs::read_to_string(&path).unwrap();
        fs::write(
            &path,
            original.replace("\"udp\":false", "\"udp\":false,\"key\":\"/arbitrary\""),
        )
        .unwrap();
        assert!(load(directory.path()).is_err());
        fs::write(&path, original).unwrap();
        fs::remove_file(directory.path().join("outer-ca.pem")).unwrap();
        std::os::unix::fs::symlink("inner-ca.pem", directory.path().join("outer-ca.pem")).unwrap();
        assert!(load(directory.path()).is_err());
    }
}

#[cfg(test)]
#[path = "device_bundle_online_tests.rs"]
mod online_tests;

#[cfg(test)]
#[path = "device_bundle_https_bridge_tests.rs"]
mod https_bridge_tests;
