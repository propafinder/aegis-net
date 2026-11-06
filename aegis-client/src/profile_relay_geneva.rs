#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]
//! Explicit installed relay-Geneva administrative commands. No default profile
//! switches here; the ordinary persistent guard invokes these only with its
//! fixed selected-profile sidecar present. Never print private config contents.
use crate::profile_relay_geneva_role::{attest_current_client, ExpectedRole, RoleMode};
use aegis_core::{
    relay_geneva::{
        installed_guard::{verify_observation, CurrentClientBinding, PublicGuardPolicy},
        installed_profile::{self, GuardTransitionIntent, OwnedGuardState},
        recovery::parse_unique_public_metadata,
    },
    Settings,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io,
    net::{SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
};

const DIR: &str = "/var/lib/aegis-install/client";
const PROFILE: &str = "relay-geneva-profile.json";
const STATE: &str = "relay-geneva-guard-state.json";
const INTENT: &str = "relay-geneva-guard-intent.json";
const INSTALL_INTENT: &str = "relay-geneva-install-intent.json";
const RECOVERY_HELPER: &str = "/usr/local/lib/aegis/aegis-relay-geneva-profile.sh";
const DROP_IN: &str = "/etc/systemd/system/aegis-client.service.d/25-relay-geneva-profile.conf";
const DEVICE_STATE: &str = "/var/lib/aegis-install/client/device-guard.conf";
const TEARDOWN: &str = "relay-geneva-teardown.json";
#[cfg(any(target_os = "linux", test))]
#[path = "profile_relay_geneva_recover_stopped.rs"]
mod stopped_recovery;
#[cfg(target_os = "linux")]
#[path = "profile_relay_geneva_teardown.rs"]
mod teardown;
#[cfg(any(target_os = "linux", test))]
#[path = "profile_relay_geneva_verify_teardown.rs"]
mod verify_teardown;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstalledProfile {
    pub schema: String,
    pub policy: PublicGuardPolicy,
    pub role: ExpectedRole,
    pub recovery_helper_sha256: String,
}
#[derive(clap::Args, Clone, Debug)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub action: Action,
}
#[derive(clap::Subcommand, Clone, Debug)]
pub(crate) enum Action {
    /// Record exact prospective file ownership before the explicit installer
    /// writes either new file. It verifies the old stopped unit independently.
    PrepareInstall {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        recovery_helper: PathBuf,
        #[arg(long)]
        drop_in: PathBuf,
    },
    /// Stage a new explicit root-owned public manifest for a stopped service.
    Stage {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Inspect only the trusted public selected profile; no kernel query.
    Inspect,
    /// Verify retained selected ownership, current role, and the complete kernel
    /// table twice without preparing a transition or changing any state.
    VerifyCurrent {
        /// Require a loaded stopped client and the exact retained blocked table.
        #[arg(long)]
        require_blocked: bool,
    },
    /// Fresh read-only verification of one exact completed selected archive.
    /// The original INET guard remains blocked; no transition or grant is created.
    VerifyTeardown {
        #[arg(long)]
        archive_token: String,
    },
    /// Save owned transition intent and print text for the existing atomic batch.
    GuardPrepare {
        #[arg(long)]
        grant_current: bool,
        #[arg(long)]
        control_parent: bool,
    },
    /// Verify the complete table and commit authority after the existing batch.
    GuardFinish {
        #[arg(long)]
        control_parent: bool,
    },
    /// Before the new client starts, recover only exact dead native journal owners.
    Recover,
    /// Recover exact dead owners from an independently stopped administrative role.
    /// Both original INET and selected NETDEV guards must already be blocked.
    RecoverStopped,
    /// After the kernel block is verified, signal the exact pinned main PID and
    /// wait for its terminal pidfd. This does not claim physical capture proof.
    StopAfterBlock,
    /// Remove only exact stopped selected ownership after durable public archive.
    /// The original INET guard remains armed/blocked for later generic recovery.
    Teardown {
        /// Resume only the explicitly named immutable completed archive if the
        /// operational marker was already removed; no fresh acceptance claim.
        #[arg(long)]
        resume_token: Option<String>,
    },
}
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "installed selected relay profile refused",
    )
}
fn need(v: bool) -> io::Result<()> {
    if v {
        Ok(())
    } else {
        Err(refused())
    }
}
fn source() -> io::Result<&'static str> {
    let s = option_env!("AEGIS_BUILD_SOURCE_COMMIT")
        .or(option_env!("AEGIS_BUILD_GIT_SHA"))
        .ok_or_else(refused)?;
    need(
        s.len() == 40
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
    )?;
    Ok(s)
}

/// Read-only proposed managed handoff. Current installed config/guard/unit and
/// stopped-role attestation remain mandatory later in prepare-install/stage.
pub(crate) fn validate_managed_proposal(
    raw: &[u8],
    settings: &Settings,
    member_pins: &std::collections::BTreeMap<String, String>,
    is_online: bool,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        validate_managed_proposal_source(raw, settings, member_pins, is_online, source()?)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (raw, settings, member_pins, is_online);
        Err(anyhow::anyhow!(
            "managed relay Geneva proposal requires Linux"
        ))
    }
}

#[cfg(any(target_os = "linux", test))]
fn validate_managed_proposal_source(
    raw: &[u8],
    settings: &Settings,
    member_pins: &std::collections::BTreeMap<String, String>,
    is_online: bool,
    compiled_source: &str,
) -> io::Result<()> {
    need(raw.len() <= 65536)?;
    let proposed: InstalledProfile =
        serde_json::from_value(parse_unique_public_metadata(raw)?).map_err(|_| refused())?;
    need(proposed.schema == "aegis_relay_geneva_installed_profile_v1")?;
    let request = settings.relay.outer_geneva.as_ref().ok_or_else(refused)?;
    let mut endpoints = std::iter::once(settings.relay.server.as_str())
        .chain(
            settings
                .relay
                .endpoints
                .iter()
                .map(|endpoint| endpoint.server.as_str()),
        )
        .map(|text| match text.parse::<SocketAddr>() {
            Ok(SocketAddr::V4(address)) => Ok(address),
            _ => Err(refused()),
        })
        .collect::<io::Result<Vec<_>>>()?;
    endpoints.sort_unstable();
    endpoints.dedup();
    proposed
        .policy
        .validate(compiled_source, request, &endpoints)?;
    crate::profile_relay_geneva_role::validate_expected_schema(&proposed.role)?;
    let role = &proposed.role;
    need(
        role.executable_path == Path::new("/usr/local/bin/aegis-client")
            && role.executable_argument_path == role.executable_path
            && role.config_file_path == Path::new("/etc/aegis/client/aegis.toml")
            && role.config_argument_path == role.config_file_path
            && role.fragment_path == Path::new("/etc/systemd/system/aegis-client.service")
            && [
                Path::new("/var/log/aegis-client/runtime-events.jsonl"),
                Path::new("/dev/null"),
            ]
            .contains(&role.runtime_events_argument_path.as_path())
            && role.control_helper_path
                == Path::new("/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh"),
    )?;
    need(
        proposed.recovery_helper_sha256
            == hex::encode(Sha256::digest(include_bytes!(
                "../../scripts/aegis-relay-geneva-profile.sh"
            )))
            && role.control_helper_sha256
                == hex::encode(Sha256::digest(include_bytes!(
                    "../../scripts/aegis-device-egress-guard.sh"
                )))
            && role.drop_in_paths_to_sha256.get(Path::new(DROP_IN))
                == Some(&hex::encode(Sha256::digest(include_bytes!(
                    "../../packaging/systemd/25-relay-geneva-profile.conf"
                )))),
    )?;
    need(member_pins.len() == 4)?;
    match (&role.online_bundle, is_online) {
        (None, false) => {}
        (Some(bundle), true) => need(
            bundle.argument_path == Path::new("/etc/aegis/client/device-bundle")
                && &bundle.members_sha256 == member_pins,
        )?,
        _ => return Err(refused()),
    }
    Ok(())
}
fn read<T: for<'de> Deserialize<'de>>(name: &str) -> io::Result<T> {
    need([PROFILE, STATE, INTENT, INSTALL_INTENT].contains(&name))?;
    let bytes = crate::profile::read_install_metadata(&Path::new(DIR).join(name))?;
    serde_json::from_value(parse_unique_public_metadata(bytes.as_bytes())?).map_err(|_| refused())
}
fn optional<T: for<'de> Deserialize<'de>>(name: &str) -> io::Result<Option<T>> {
    match read(name) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
fn write<T: Serialize>(name: &str, row: &T) -> io::Result<()> {
    let text = serde_json::to_string(row).map_err(|_| refused())?;
    need(text.len() <= 65536)?;
    if name == INTENT || name == STATE {
        match crate::profile::read_install_metadata(&Path::new(DIR).join(name)) {
            Ok(old) => crate::profile::archive_relay_geneva_record(&old)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        crate::profile::archive_relay_geneva_record(&text)?;
    }
    crate::profile::write_relay_geneva_record(name, &text)
}
struct Input {
    profile: InstalledProfile,
    config: Settings,
    endpoints: Vec<SocketAddrV4>,
    profile_bytes_sha256: [u8; 32],
}
fn input_profile(raw_profile: String, require_installed_helper: bool) -> io::Result<Input> {
    let profile: InstalledProfile =
        serde_json::from_value(parse_unique_public_metadata(raw_profile.as_bytes())?)
            .map_err(|_| refused())?;
    need(profile.schema == "aegis_relay_geneva_installed_profile_v1")?;
    if require_installed_helper {
        let helper = crate::profile::read_install_metadata(Path::new(RECOVERY_HELPER))?;
        need(hex::encode(Sha256::digest(helper.as_bytes())) == profile.recovery_helper_sha256)?;
    }
    // Read the private configuration as trusted administrative data, without
    // resolving or copying identity private keys during guard operations.
    let raw_config = crate::profile::read_install_metadata(&profile.role.config_file_path)?;
    need(hex::encode(Sha256::digest(raw_config.as_bytes())) == profile.role.config_sha256)?;
    let config: Settings = toml::from_str(&raw_config).map_err(|_| refused())?;
    config
        .validate_relay_outer_geneva()
        .map_err(|_| refused())?;
    let request = config.relay.outer_geneva.as_ref().ok_or_else(refused)?;
    let mut endpoints = std::iter::once(config.relay.server.as_str())
        .chain(config.relay.endpoints.iter().map(|e| e.server.as_str()))
        .map(|s| match s.parse::<SocketAddr>() {
            Ok(SocketAddr::V4(a)) => Ok(a),
            _ => Err(refused()),
        })
        .collect::<io::Result<Vec<_>>>()?;
    endpoints.sort_unstable();
    endpoints.dedup();
    profile.policy.validate(source()?, request, &endpoints)?;
    let guard = crate::profile::read_install_metadata(Path::new(DEVICE_STATE))?;
    need(
        hex::encode(Sha256::digest(guard.as_bytes())) == profile.policy.device_guard_state_sha256,
    )?;
    need(
        guard.lines().any(|s| s == "schema=aegis_device_guard_v2")
            && guard.lines().any(|s| s == "armed=1")
            && guard.lines().any(|s| s == "service=aegis-client.service"),
    )?;
    Ok(Input {
        profile,
        config,
        endpoints,
        profile_bytes_sha256: Sha256::digest(raw_profile.as_bytes()).into(),
    })
}
fn input() -> io::Result<Input> {
    absent(&Path::new(DIR).join(TEARDOWN))?;
    input_profile(
        crate::profile::read_install_metadata(&Path::new(DIR).join(PROFILE))?,
        true,
    )
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallIntent {
    schema: String,
    source: String,
    manifest_sha256: String,
    recovery_helper_sha256: String,
    drop_in_sha256: String,
    helper_path: String,
    drop_in_path: String,
    initial_service_stopped: bool,
    initial_files_absent: bool,
}
fn absent(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(_) => Err(refused()),
    }
}
fn stable(i: &Input) -> io::Result<()> {
    let current = input()?;
    need(
        current.profile_bytes_sha256 == i.profile_bytes_sha256
            && current.profile.role.config_sha256 == i.profile.role.config_sha256
            && current.endpoints == i.endpoints,
    )
}
fn grant(i: &Input, control: bool) -> io::Result<CurrentClientBinding> {
    attest_current_client(
        &i.profile.role,
        if control {
            RoleMode::CurrentControlParent
        } else {
            RoleMode::RunningMain
        },
    )
}
pub(crate) fn run(args: &Args) -> Result<(), String> {
    run_io(args).map_err(|_|"Installed selected relay profile operation refused; owned evidence and restrictive rules are retained".into())
}
fn run_io(args: &Args) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    need(unsafe { libc::geteuid() } == 0)?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "installed relay profile requires Linux",
        ))
    }
    #[cfg(target_os = "linux")]
    {
        use aegis_core::relay_geneva::linux::recovery as native;
        if matches!(args.action, Action::RecoverStopped) {
            use aegis_core::relay_geneva::operation_deadline;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(80);
            return operation_deadline::with_deadline(deadline, || {
                let output = stopped_recovery::run()?;
                operation_deadline::check()?;
                println!("{output}");
                Ok(())
            });
        }
        if let Action::VerifyTeardown { archive_token } = &args.action {
            use aegis_core::relay_geneva::operation_deadline;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(80);
            return operation_deadline::with_deadline(deadline, || {
                let output = verify_teardown::run(archive_token)?;
                operation_deadline::check()?;
                println!("{output}");
                Ok(())
            });
        }
        if let Action::Teardown { resume_token } = &args.action {
            return teardown::run(resume_token.as_deref());
        }
        if let Action::PrepareInstall {
            manifest,
            recovery_helper,
            drop_in,
        } = &args.action
        {
            absent(&Path::new(DIR).join(TEARDOWN))?;
            for name in [PROFILE, STATE, INTENT, INSTALL_INTENT] {
                need(optional::<Value>(name)?.is_none())?;
            }
            for path in [RECOVERY_HELPER, DROP_IN] {
                absent(Path::new(path))?;
            }
            let raw = crate::profile::read_install_metadata(manifest)?;
            let proposed = input_profile(raw.clone(), false)?;
            let helper = crate::profile::read_install_metadata(recovery_helper)?;
            let dropin = crate::profile::read_install_metadata(drop_in)?;
            let helper_sha = hex::encode(Sha256::digest(helper.as_bytes()));
            let dropin_sha = hex::encode(Sha256::digest(dropin.as_bytes()));
            need(
                helper_sha == proposed.profile.recovery_helper_sha256
                    && proposed
                        .profile
                        .role
                        .drop_in_paths_to_sha256
                        .get(Path::new(DROP_IN))
                        == Some(&dropin_sha),
            )?;
            let mut prior = proposed.profile.role.clone();
            need(
                prior
                    .drop_in_paths_to_sha256
                    .remove(Path::new(DROP_IN))
                    .is_some(),
            )?;
            crate::profile_relay_geneva_role::verify_installable(&prior)?;
            need(
                crate::profile::read_install_metadata(manifest)? == raw
                    && crate::profile::read_install_metadata(recovery_helper)? == helper
                    && crate::profile::read_install_metadata(drop_in)? == dropin,
            )?;
            crate::profile_relay_geneva_role::verify_installable(&prior)?;
            let intent = InstallIntent {
                schema: "aegis_relay_geneva_install_intent_v1".into(),
                source: source()?.into(),
                manifest_sha256: hex::encode(proposed.profile_bytes_sha256),
                recovery_helper_sha256: helper_sha,
                drop_in_sha256: dropin_sha,
                helper_path: RECOVERY_HELPER.into(),
                drop_in_path: DROP_IN.into(),
                initial_service_stopped: true,
                initial_files_absent: true,
            };
            crate::profile::archive_relay_geneva_record(
                &serde_json::to_string(&intent).map_err(|_| refused())?,
            )?;
            write(INSTALL_INTENT, &intent)?;
            return Ok(());
        }
        if let Action::Stage { manifest } = &args.action {
            absent(&Path::new(DIR).join(TEARDOWN))?;
            for name in [PROFILE, STATE, INTENT] {
                need(optional::<Value>(name)?.is_none())?;
            }
            let raw = crate::profile::read_install_metadata(manifest)?;
            let proposed = input_profile(raw.clone(), true)?;
            let intent: InstallIntent = read(INSTALL_INTENT)?;
            need(
                intent.schema == "aegis_relay_geneva_install_intent_v1"
                    && intent.source == source()?
                    && intent.manifest_sha256 == hex::encode(proposed.profile_bytes_sha256)
                    && intent.recovery_helper_sha256 == proposed.profile.recovery_helper_sha256
                    && intent.helper_path == RECOVERY_HELPER
                    && intent.drop_in_path == DROP_IN
                    && intent.initial_service_stopped
                    && intent.initial_files_absent
                    && proposed
                        .profile
                        .role
                        .drop_in_paths_to_sha256
                        .get(Path::new(DROP_IN))
                        == Some(&intent.drop_in_sha256),
            )?;
            crate::profile_relay_geneva_role::verify_installable(&proposed.profile.role)?;
            let final_proposed =
                input_profile(crate::profile::read_install_metadata(manifest)?, true)?;
            need(proposed.profile_bytes_sha256 == final_proposed.profile_bytes_sha256)?;
            crate::profile_relay_geneva_role::verify_installable(&proposed.profile.role)?;
            crate::profile::archive_relay_geneva_record(&raw)?;
            crate::profile::write_relay_geneva_record(PROFILE, &raw)?;
            stable(&proposed)?;
            println!(
                "{}",
                json!({"schema":"aegis_relay_geneva_staged_profile_v1","source":source()?,"profile_sha256":hex::encode(proposed.profile_bytes_sha256),"installed_kernel_acceptance":false})
            );
            return Ok(());
        }
        let i = input()?;
        let request = i.config.relay.outer_geneva.as_ref().ok_or_else(refused)?;
        match args.action {
            Action::Teardown { .. } | Action::RecoverStopped | Action::VerifyTeardown { .. } => {
                return Err(refused());
            }
            Action::PrepareInstall { .. } => return Err(refused()),
            Action::Stage { .. } => return Err(refused()),
            Action::Inspect => println!(
                "{}",
                json!({"schema":i.profile.schema,"policy":i.profile.policy,"source":source()?,"installed_kernel_acceptance":false})
            ),
            Action::VerifyCurrent { require_blocked } => {
                let confirmed = verify_current(&i, require_blocked)?;
                println!(
                    "{}",
                    json!({
                        "schema":"aegis_relay_geneva_current_verification_v1",
                        "source":source()?,"profile_sha256":hex::encode(i.profile_bytes_sha256),
                        "policy_sha256":hex::encode(confirmed.proof.policy_sha256()),
                        "table_sha256":hex::encode(confirmed.proof.table_sha256()),
                        "blocked":require_blocked,"current_binding":confirmed.binding,
                        "complete_selected_kernel_readback_verified":true,
                        "physical_capture_verified":false,"installed_lifecycle_acceptance":false
                    })
                );
            }
            Action::GuardPrepare {
                grant_current,
                control_parent,
            } => {
                need(!control_parent || grant_current)?;
                let proposed = if grant_current {
                    Some(grant(&i, control_parent)?)
                } else {
                    None
                };
                let state: Option<OwnedGuardState> = optional(STATE)?;
                let pending: Option<GuardTransitionIntent> = optional(INTENT)?;
                let observed = native::observe_installed_guard()?;
                let prepared = installed_profile::prepare(
                    &i.profile.policy,
                    state.as_ref(),
                    pending.as_ref(),
                    observed.as_ref(),
                    proposed.as_ref(),
                    source()?,
                    request,
                    &i.endpoints,
                )?;
                stable(&i)?;
                if let Some(ref binding) = proposed {
                    need(grant(&i, control_parent)? == *binding)?;
                }
                // Intent must be durably written before the shell receives even
                // one byte of the batch. Pending state never grants authority.
                write(INTENT, &prepared.intent)?;
                println!("{}", prepared.nft_script);
            }
            Action::GuardFinish { control_parent } => {
                let intent: GuardTransitionIntent = read(INTENT)?;
                let observed = native::observe_installed_guard()?.ok_or_else(refused)?;
                if let Some(ref binding) = intent.proposed_binding {
                    need(grant(&i, control_parent)? == *binding)?;
                }
                let state = installed_profile::finish(
                    &i.profile.policy,
                    &intent,
                    &observed,
                    source()?,
                    request,
                    &i.endpoints,
                )?;
                stable(&i)?;
                write(STATE, &state)?;
                crate::profile::remove_relay_geneva_intent()?;
            }
            Action::Recover => {
                let state: OwnedGuardState = read(STATE)?;
                need(state.table_present && state.active_binding.is_none())?;
                let actual = native::observe_installed_guard()?.ok_or_else(refused)?;
                verify_observation(
                    &actual,
                    &i.profile.policy,
                    None,
                    source()?,
                    request,
                    &i.endpoints,
                )?;
                stable(&i)?;
                let rows = native::recover(request, &i.endpoints, &i.profile.policy)?;
                stable(&i)?;
                println!(
                    "{}",
                    json!({"schema":"aegis_relay_geneva_recovery_command_v1","owned_receipts":rows,"installed_kernel_acceptance":false})
                );
            }
            Action::StopAfterBlock => {
                need(optional::<GuardTransitionIntent>(INTENT)?.is_none())?;
                let state: OwnedGuardState = read(STATE)?;
                need(state.table_present && state.active_binding.is_none())?;
                let actual = native::observe_installed_guard()?.ok_or_else(refused)?;
                verify_observation(
                    &actual,
                    &i.profile.policy,
                    None,
                    source()?,
                    request,
                    &i.endpoints,
                )?;
                stop_bound_main(&i)?;
                stable(&i)?;
                println!(
                    "{}",
                    json!({"schema":"aegis_relay_geneva_block_barrier_v1","owned_main_pid_terminal":true,"physical_capture_verified":false,"pre_hook_frames_cancelled":false})
                );
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct CurrentVerification {
    binding: Option<CurrentClientBinding>,
    proof: aegis_core::relay_geneva::installed_guard::InstalledGuardProof,
}
#[cfg(target_os = "linux")]
fn verify_current(i: &Input, require_blocked: bool) -> io::Result<CurrentVerification> {
    use aegis_core::relay_geneva::linux::recovery as native;
    let request = i.config.relay.outer_geneva.as_ref().ok_or_else(refused)?;
    absent(&Path::new(DIR).join(INTENT))?;
    let state: OwnedGuardState = read(STATE)?;
    need(state.active_binding.is_none() == require_blocked)?;
    let state_bytes = serde_json::to_vec(&state).map_err(|_| refused())?;
    let binding = if require_blocked {
        crate::profile_relay_geneva_role::verify_installable(&i.profile.role)?;
        None
    } else {
        Some(grant(i, false)?)
    };
    let actual = native::observe_installed_guard()?.ok_or_else(refused)?;
    let proof = installed_profile::verify_current(
        &i.profile.policy,
        &state,
        &actual,
        binding.as_ref(),
        source()?,
        request,
        &i.endpoints,
    )?;
    stable(i)?;
    absent(&Path::new(DIR).join(INTENT))?;
    let again: OwnedGuardState = read(STATE)?;
    need(serde_json::to_vec(&again).map_err(|_| refused())? == state_bytes)?;
    let current = if require_blocked {
        crate::profile_relay_geneva_role::verify_installable(&i.profile.role)?;
        None
    } else {
        Some(grant(i, false)?)
    };
    need(current == binding)?;
    let observed = native::observe_installed_guard()?.ok_or_else(refused)?;
    let confirmed = installed_profile::verify_current(
        &i.profile.policy,
        &again,
        &observed,
        current.as_ref(),
        source()?,
        request,
        &i.endpoints,
    )?;
    need(proof.table_sha256() == confirmed.table_sha256())?;
    stable(i)?;
    absent(&Path::new(DIR).join(INTENT))?;
    let final_state: OwnedGuardState = read(STATE)?;
    need(serde_json::to_vec(&final_state).map_err(|_| refused())? == state_bytes)?;
    // Recheck the role after the final kernel observation. A stale
    // process or a restarted unit never inherits this proof.
    if require_blocked {
        crate::profile_relay_geneva_role::verify_installable(&i.profile.role)?;
    } else {
        need(Some(grant(i, false)?) == binding)?;
    }
    aegis_core::relay_geneva::operation_deadline::check()?;
    Ok(CurrentVerification {
        binding,
        proof: confirmed,
    })
}

#[cfg(target_os = "linux")]
fn stop_bound_main(i: &Input) -> io::Result<()> {
    use std::{
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        time::{Duration, Instant},
    };
    let identity = crate::profile_relay_geneva_role::attest_running_identity(&i.profile.role)?;
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, identity.pid, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    need(crate::profile_relay_geneva_role::attest_running_identity(&i.profile.role)? == identity)?;
    let actual = aegis_core::relay_geneva::linux::recovery::observe_installed_guard()?
        .ok_or_else(refused)?;
    let request = i.config.relay.outer_geneva.as_ref().ok_or_else(refused)?;
    verify_observation(
        &actual,
        &i.profile.policy,
        None,
        source()?,
        request,
        &i.endpoints,
    )?;
    stable(i)?;
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGTERM,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        need(Instant::now() < deadline)?;
        let mut event = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut event, 1, 50) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        need(event.revents & (libc::POLLERR | libc::POLLNVAL) == 0)?;
        if event.revents & libc::POLLIN != 0 {
            return Ok(());
        }
    }
}

#[cfg(target_os = "linux")]
struct RunningAuthorization {
    profile_sha256: [u8; 32],
    request_sha256: [u8; 32],
    endpoints: Vec<SocketAddrV4>,
}
#[cfg(target_os = "linux")]
impl aegis_core::relay_geneva::installed_profile::InstalledGuardAuthorization
    for RunningAuthorization
{
    fn verify(
        &self,
        request: &aegis_core::relay_geneva::RelayOuterGenevaSettings,
        endpoints: &[SocketAddrV4],
        actual: &Value,
    ) -> io::Result<aegis_core::relay_geneva::installed_guard::InstalledGuardProof> {
        let i = input()?;
        let configured = i.config.relay.outer_geneva.as_ref().ok_or_else(refused)?;
        let digest =
            |v: &aegis_core::relay_geneva::RelayOuterGenevaSettings| -> io::Result<[u8; 32]> {
                Ok(Sha256::digest(serde_json::to_vec(v).map_err(|_| refused())?).into())
            };
        need(
            i.profile_bytes_sha256 == self.profile_sha256
                && digest(request)? == self.request_sha256
                && digest(configured)? == self.request_sha256
                && endpoints == self.endpoints
                && i.endpoints == self.endpoints,
        )?;
        need(optional::<GuardTransitionIntent>(INTENT)?.is_none())?;
        let binding = attest_current_client(&i.profile.role, RoleMode::StartingOrRunningMain)?;
        let state: OwnedGuardState = read(STATE)?;
        need(
            state.table_present
                && state.active_binding.as_ref() == Some(&binding)
                && state.policy_sha256 == hex::encode(i.profile.policy.digest()?),
        )?;
        let proof = verify_observation(
            actual,
            &i.profile.policy,
            Some(&binding),
            source()?,
            request,
            endpoints,
        )?;
        stable(&i)?;
        Ok(proof)
    }
}

// The inventory is administrative data from input(), never the projected
// per-dial RelaySettings. Keep this validation pure for source regressions.
#[cfg(any(target_os = "linux", test))]
fn runtime_selection_digest(
    request: &aegis_core::relay_geneva::RelayOuterGenevaSettings,
    configured: &aegis_core::relay_geneva::RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
    policy_endpoints: &[SocketAddrV4],
    selected: SocketAddrV4,
) -> io::Result<[u8; 32]> {
    need(
        !endpoints.is_empty()
            && endpoints == policy_endpoints
            && endpoints.windows(2).all(|pair| pair[0] < pair[1])
            && endpoints.contains(&selected),
    )?;
    let digest = |value: &aegis_core::relay_geneva::RelayOuterGenevaSettings| {
        serde_json::to_vec(value)
            .map(|bytes| <[u8; 32]>::from(Sha256::digest(bytes)))
            .map_err(|_| refused())
    };
    let request_sha256 = digest(request)?;
    need(request_sha256 == digest(configured)?)?;
    Ok(request_sha256)
}

#[cfg(target_os = "linux")]
pub(crate) fn runtime_authorization(
    request: &aegis_core::relay_geneva::RelayOuterGenevaSettings,
    selected: SocketAddrV4,
) -> io::Result<(
    Vec<SocketAddrV4>,
    std::sync::Arc<dyn aegis_core::relay_geneva::installed_profile::InstalledGuardAuthorization>,
)> {
    // Every selected product-client dial requires its exact installed profile.
    // The standalone controlled native example uses the core API independently.
    let i = input()?;
    let configured = i.config.relay.outer_geneva.as_ref().ok_or_else(refused)?;
    let request_sha256 = runtime_selection_digest(
        request,
        configured,
        &i.endpoints,
        &i.profile.policy.relay_endpoints,
        selected,
    )?;
    let authorization = std::sync::Arc::new(RunningAuthorization {
        profile_sha256: i.profile_bytes_sha256,
        request_sha256,
        endpoints: i.endpoints.clone(),
    });
    Ok((i.endpoints, authorization))
}

#[cfg(test)]
mod managed_proposal_tests {
    use super::*;

    fn fixture(
        online: bool,
    ) -> (
        InstalledProfile,
        Settings,
        std::collections::BTreeMap<String, String>,
    ) {
        let pins = [
            "bundle.json",
            "outer-ca.pem",
            "inner-ca.pem",
            "device-ca.pem",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), "4".repeat(64)))
        .collect::<std::collections::BTreeMap<_, _>>();
        let mut settings = Settings::default();
        settings.relay.server = "192.0.2.10:8443".into();
        settings.relay.outer_geneva = Some(aegis_core::relay_geneva::RelayOuterGenevaSettings {
            strategy: "[TCP:flags:S]-duplicate-|".into(),
            interface: "eth0".into(),
            local_address: "192.0.2.20".parse().unwrap(),
            local_mac: [2, 0, 0, 0, 0, 1],
            next_hop_mac: [2, 0, 0, 0, 0, 2],
            outbound_queue: 40,
            inbound_queue: 41,
            socket_mark: 161,
            max_duration_secs: 60,
        });
        let profile = InstalledProfile {
            schema: "aegis_relay_geneva_installed_profile_v1".into(),
            policy: PublicGuardPolicy {
                schema: "aegis_relay_geneva_installed_guard_v1".into(),
                source_commit: "1".repeat(40),
                interface: "eth0".into(),
                local_address: "192.0.2.20".parse().unwrap(),
                socket_mark: 161,
                relay_endpoints: vec!["192.0.2.10:8443".parse().unwrap()],
                device_guard_state_sha256: "2".repeat(64),
            },
            role: ExpectedRole {
                executable_path: "/usr/local/bin/aegis-client".into(),
                executable_argument_path: "/usr/local/bin/aegis-client".into(),
                executable_sha256: "3".repeat(64),
                config_file_path: "/etc/aegis/client/aegis.toml".into(),
                config_argument_path: "/etc/aegis/client/aegis.toml".into(),
                config_sha256: "3".repeat(64),
                runtime_events_argument_path: "/var/log/aegis-client/runtime-events.jsonl".into(),
                online_bundle: online.then(|| {
                    crate::profile_relay_geneva_role::OnlineBundleExpectation {
                        argument_path: "/etc/aegis/client/device-bundle".into(),
                        members_sha256: pins.clone(),
                    }
                }),
                fragment_path: "/etc/systemd/system/aegis-client.service".into(),
                fragment_sha256: "3".repeat(64),
                drop_in_paths_to_sha256: [(
                    PathBuf::from(DROP_IN),
                    hex::encode(Sha256::digest(include_bytes!(
                        "../../packaging/systemd/25-relay-geneva-profile.conf"
                    ))),
                )]
                .into(),
                control_helper_path: "/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh"
                    .into(),
                control_helper_sha256: hex::encode(Sha256::digest(include_bytes!(
                    "../../scripts/aegis-device-egress-guard.sh"
                ))),
            },
            recovery_helper_sha256: hex::encode(Sha256::digest(include_bytes!(
                "../../scripts/aegis-relay-geneva-profile.sh"
            ))),
        };
        (profile, settings, pins)
    }

    #[test]
    fn managed_proposal_accepts_only_exact_offline_or_online_public_tuple() {
        for online in [false, true] {
            let (profile, settings, pins) = fixture(online);
            let raw = serde_json::to_vec(&profile).unwrap();
            assert!(validate_managed_proposal_source(
                &raw,
                &settings,
                &pins,
                online,
                &"1".repeat(40)
            )
            .is_ok());
            assert!(validate_managed_proposal_source(
                &raw,
                &settings,
                &pins,
                !online,
                &"1".repeat(40)
            )
            .is_err());
            assert!(validate_managed_proposal_source(
                &raw,
                &settings,
                &pins,
                online,
                &"9".repeat(40)
            )
            .is_err());
        }
    }

    #[test]
    fn managed_proposal_refuses_local_incompatibility_before_any_native_handoff() {
        let (profile, settings, pins) = fixture(true);
        for case in 0..12 {
            let mut bad = profile.clone();
            match case {
                0 => bad.schema = "wrong".into(),
                1 => bad.policy.socket_mark += 1,
                2 => bad.policy.local_address = "192.0.2.21".parse().unwrap(),
                3 => bad
                    .policy
                    .relay_endpoints
                    .push("192.0.2.11:8443".parse().unwrap()),
                4 => bad.role.executable_argument_path = "/opt/alias-client".into(),
                5 => bad.role.config_sha256 = "not-a-pin".into(),
                6 => bad.role.fragment_path = "/etc/systemd/system/other.service".into(),
                7 => bad.recovery_helper_sha256 = "0".repeat(64),
                8 => {
                    bad.role.drop_in_paths_to_sha256.remove(Path::new(DROP_IN));
                }
                9 => bad.role.control_helper_sha256 = "0".repeat(64),
                10 => {
                    bad.role
                        .online_bundle
                        .as_mut()
                        .unwrap()
                        .members_sha256
                        .insert("bundle.json".into(), "0".repeat(64));
                }
                _ => {
                    bad.role.online_bundle.as_mut().unwrap().argument_path =
                        "/etc/foreign-bundle".into()
                }
            }
            assert!(
                validate_managed_proposal_source(
                    &serde_json::to_vec(&bad).unwrap(),
                    &settings,
                    &pins,
                    true,
                    &"1".repeat(40)
                )
                .is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn managed_proposal_refuses_duplicate_or_unknown_public_metadata() {
        let (profile, settings, pins) = fixture(false);
        let mut value = serde_json::to_value(&profile).unwrap();
        value["unknown"] = true.into();
        assert!(validate_managed_proposal_source(
            &serde_json::to_vec(&value).unwrap(),
            &settings,
            &pins,
            false,
            &"1".repeat(40)
        )
        .is_err());
        let raw = serde_json::to_string(&profile).unwrap();
        let duplicate = raw.replacen(
            "{",
            "{\"schema\":\"aegis_relay_geneva_installed_profile_v1\",",
            1,
        );
        assert!(validate_managed_proposal_source(
            duplicate.as_bytes(),
            &settings,
            &pins,
            false,
            &"1".repeat(40)
        )
        .is_err());
    }
}

#[cfg(test)]
mod readonly_command_tests {
    #[test]
    fn completed_teardown_readonly_oracle_cli_is_exposed() {
        use clap::Subcommand;
        let command = super::Action::augment_subcommands(clap::Command::new("relay-geneva"));
        assert!(command
            .try_get_matches_from([
                "relay-geneva",
                "verify-teardown",
                "--archive-token",
                "0123456789abcdef0123456789abcdef"
            ])
            .is_ok());
    }
    #[test]
    fn stopped_administrative_recovery_cli_is_exposed() {
        use clap::Subcommand;
        let command = super::Action::augment_subcommands(clap::Command::new("relay-geneva"));
        assert!(command
            .clone()
            .try_get_matches_from(["relay-geneva", "recover-stopped"])
            .is_ok());
        for option in [
            "--grant-current",
            "--control-parent",
            "--force",
            "--resume-token",
        ] {
            assert!(command
                .clone()
                .try_get_matches_from(["relay-geneva", "recover-stopped", option])
                .is_err());
        }
    }
    #[test]
    fn teardown_oracle_requires_named_archive_and_rejects_mutation_options() {
        use clap::Subcommand;
        let command = super::Action::augment_subcommands(clap::Command::new("relay-geneva"));
        assert!(command
            .clone()
            .try_get_matches_from(["relay-geneva", "verify-teardown"])
            .is_err());
        for option in [
            "--resume-token",
            "--grant-current",
            "--control-parent",
            "--force",
            "--manifest",
        ] {
            assert!(command
                .clone()
                .try_get_matches_from([
                    "relay-geneva",
                    "verify-teardown",
                    "--archive-token",
                    "0123456789abcdef0123456789abcdef",
                    option
                ])
                .is_err());
        }
    }
    use super::{Action, Args};
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn readonly_command_requires_explicit_blocked_mode_and_rejects_write_options() {
        assert!(matches!(
            Command::try_parse_from(["client", "verify-current"])
                .unwrap()
                .args
                .action,
            Action::VerifyCurrent {
                require_blocked: false
            }
        ));
        assert!(matches!(
            Command::try_parse_from(["client", "verify-current", "--require-blocked"])
                .unwrap()
                .args
                .action,
            Action::VerifyCurrent {
                require_blocked: true
            }
        ));
        for option in [
            "--grant-current",
            "--control-parent",
            "--resume-token",
            "--force",
        ] {
            assert!(Command::try_parse_from(["client", "verify-current", option]).is_err());
        }
    }
}

#[cfg(test)]
mod runtime_selection_tests {
    use super::runtime_selection_digest;
    use aegis_core::relay_geneva::RelayOuterGenevaSettings;
    use std::net::SocketAddrV4;

    fn request() -> RelayOuterGenevaSettings {
        RelayOuterGenevaSettings {
            strategy: "[TCP:flags:SA]-duplicate-|".into(),
            interface: "fixture0".into(),
            local_address: "192.0.2.2".parse().unwrap(),
            local_mac: [2, 0, 0, 0, 0, 2],
            next_hop_mac: [2, 0, 0, 0, 0, 3],
            outbound_queue: 101,
            inbound_queue: 102,
            socket_mark: 0x400,
            max_duration_secs: 30,
        }
    }
    fn inventory() -> Vec<SocketAddrV4> {
        ["192.0.2.3:24443", "192.0.2.4:24443", "192.0.2.5:24443"]
            .iter()
            .map(|endpoint| endpoint.parse().unwrap())
            .collect()
    }
    #[test]
    fn every_choice_keeps_the_full_authoritative_inventory() {
        let endpoints = inventory();
        let configured = request();
        for selected in &endpoints {
            assert!(runtime_selection_digest(
                &configured,
                &configured,
                &endpoints,
                &endpoints,
                *selected
            )
            .is_ok());
        }
    }
    #[test]
    fn single_endpoint_is_supported() {
        let endpoints = inventory();
        let configured = request();
        assert!(runtime_selection_digest(
            &configured,
            &configured,
            &endpoints[..1],
            &endpoints[..1],
            endpoints[0]
        )
        .is_ok());
    }
    #[test]
    fn duplicate_or_unsorted_administrative_inventory_is_refused() {
        let endpoints = inventory();
        let configured = request();
        for invalid in [
            vec![endpoints[0], endpoints[0]],
            vec![endpoints[1], endpoints[0]],
        ] {
            assert!(runtime_selection_digest(
                &configured,
                &configured,
                &invalid,
                &invalid,
                endpoints[0]
            )
            .is_err());
        }
    }
    #[test]
    fn subset_or_foreign_inventory_is_refused_even_with_member_selection() {
        let endpoints = inventory();
        let configured = request();
        assert!(runtime_selection_digest(
            &configured,
            &configured,
            &endpoints[..1],
            &endpoints,
            endpoints[0]
        )
        .is_err());
        let mut foreign = endpoints.clone();
        foreign.push("192.0.2.6:24443".parse().unwrap());
        assert!(runtime_selection_digest(
            &configured,
            &configured,
            &foreign,
            &endpoints,
            endpoints[0]
        )
        .is_err());
    }
    #[test]
    fn foreign_selected_endpoint_is_refused() {
        let endpoints = inventory();
        let configured = request();
        assert!(runtime_selection_digest(
            &configured,
            &configured,
            &endpoints,
            &endpoints,
            "192.0.2.6:24443".parse().unwrap()
        )
        .is_err());
    }
    #[test]
    fn empty_inventory_is_refused() {
        let configured = request();
        assert!(runtime_selection_digest(
            &configured,
            &configured,
            &[],
            &[],
            "192.0.2.3:24443".parse().unwrap()
        )
        .is_err());
    }
    #[test]
    fn changed_request_fields_are_refused_before_authorization() {
        let endpoints = inventory();
        let configured = request();
        for field in 0..10 {
            let mut changed = configured.clone();
            match field {
                0 => changed.strategy.push(' '),
                1 => changed.interface.push('x'),
                2 => changed.local_address = "192.0.2.7".parse().unwrap(),
                3 => changed.local_mac[5] ^= 1,
                4 => changed.next_hop_mac[5] ^= 1,
                5 => changed.outbound_queue += 1,
                6 => changed.inbound_queue += 1,
                7 => changed.socket_mark ^= 1,
                8 => changed.max_duration_secs += 1,
                9 => changed.strategy = String::new(),
                _ => unreachable!(),
            }
            assert!(runtime_selection_digest(
                &changed,
                &configured,
                &endpoints,
                &endpoints,
                endpoints[0]
            )
            .is_err());
        }
    }
}
