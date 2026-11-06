//! Protected fixed-unit policy inputs and typed journal for administrative AUTO.
//! Private integration candidate. Preparation never writes unit target paths.
use super::{authority::StageGuard, digest, refuse, AutoMode, Phase, Result};
use crate::profile_auto_capture::{
    self as capture, CaptureLimits, CapturedInput, CapturedTree, GenerationRecord, InputRole,
};
use crate::profile_auto_publication::linux as fs;
use crate::profile_auto_runtime_identity::{RuntimeBinding, RuntimePolicy, ServiceUser};
use crate::profile_auto_stopped_service::InstallLock;
use crate::profile_auto_unit_namespace::{
    self as namespace, ManagedRole, OwnedRestoration, OwnedTransition, UnitNamespaceSnapshot,
};
use crate::profile_auto_unit_policy::linux as policy;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    io::{Read, Seek, SeekFrom},
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const RECIPE: &str = "accepted/unit-target/policy.json";
const LIMIT: usize = 16 * 1024 * 1024;
fn fail<E>(_: E) -> String {
    refuse()
}
fn check(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(refuse())
    }
}
fn key(role: ManagedRole) -> &'static str {
    match role {
        ManagedRole::BaseUnit => "base-unit",
        ManagedRole::Environment => "environment",
        ManagedRole::Dropins => "dropins",
    }
}
fn singleton(role: policy::LeafRole) -> ManagedRole {
    match role {
        policy::LeafRole::BaseUnit => ManagedRole::BaseUnit,
        policy::LeafRole::Environment => ManagedRole::Environment,
    }
}

/// Stable policy epoch is separate from the phase-specific stopped-service epoch.
pub(super) fn transaction_epoch(stage: &StageGuard) -> Result<[u8; 32]> {
    current(stage)?;
    let mut hash = Sha256::new();
    hash.update(b"aegis-auto-unit-policy-v2\0");
    for value in [
        &stage.header.transaction_nonce,
        &stage.header.input_generation,
        &stage.header.planned_generation,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    Ok(hash.finalize().into())
}
fn current(stage: &StageGuard) -> Result<()> {
    stage.store.revalidate()?;
    // The fresh, validated disk header serializes to the held header's bytes.
    stage.store.require_header_equals(&stage.header)
}
fn bound(stage: &StageGuard, path: &Path) -> Result<Vec<u8>> {
    current(stage)?;
    let bytes = stage.store.read(path)?;
    check(
        bytes.len() <= LIMIT
            && stage
                .header
                .leaves
                .get(path)
                .or_else(|| stage.header.unit_records.get(path))
                == Some(&digest(&bytes)),
    )?;
    Ok(bytes.to_vec())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed<T> {
    schema: u32,
    nonce: String,
    input_generation: String,
    planned_generation: String,
    role: ManagedRole,
    epoch: [u8; 32],
    body: T,
}
fn read<T: DeserializeOwned>(stage: &StageGuard, path: &Path, role: ManagedRole) -> Result<T> {
    let value: Sealed<T> = serde_json::from_slice(&bound(stage, path)?).map_err(fail)?;
    check(
        value.schema == 1
            && value.nonce == stage.header.transaction_nonce
            && value.input_generation == stage.header.input_generation
            && value.planned_generation == stage.header.planned_generation
            && value.role == role
            && value.epoch == transaction_epoch(stage)?,
    )?;
    Ok(value.body)
}
fn finalized_restoration_record(path: &Path) -> bool {
    matches!(
        path.to_str(),
        Some(
            "receipts/unit-target/base-unit/rollback-intent.json"
                | "receipts/unit-target/base-unit/restored.json"
                | "receipts/unit-target/base-unit/restoration-transition.json"
                | "receipts/unit-target/environment/rollback-intent.json"
                | "receipts/unit-target/environment/restored.json"
                | "receipts/unit-target/environment/restoration-transition.json"
                | "receipts/unit-target/dropins/restored/stage.json"
                | "receipts/unit-target/dropins/restoration-link.json"
                | "receipts/unit-target/dropins/restoration-transition.json"
                | "receipts/unit-target/restore-manager-intent.json"
                | "receipts/unit-target/restored-manager.json"
        )
    )
}
fn write<T: Serialize>(
    stage: &mut StageGuard,
    path: &Path,
    role: ManagedRole,
    body: &T,
) -> Result<()> {
    current(stage)?;
    check(
        !stage.header.capture_started
            && !matches!(
                stage.header.phase,
                Phase::RolledBack | Phase::NativeRecoveryRequired
            )
            && (stage.header.phase != Phase::Finalized
                || (stage.header.new_unit_namespace.is_some()
                    && stage.header.unit_restored_manager.is_none()
                    && finalized_restoration_record(path)))
            && path.starts_with("receipts/unit-target")
            && super::relative(path)
            && stage.header.unit_records.len() < 128,
    )?;
    let value = Sealed {
        schema: 1,
        nonce: stage.header.transaction_nonce.clone(),
        input_generation: stage.header.input_generation.clone(),
        planned_generation: stage.header.planned_generation.clone(),
        role,
        epoch: transaction_epoch(stage)?,
        body,
    };
    let bytes = serde_json::to_vec(&value).map_err(fail)?;
    check(bytes.len() <= LIMIT)?;
    if stage.header.unit_records.contains_key(path) {
        return check(bound(stage, path)? == bytes);
    }
    stage.store.write_new(path, &bytes)?;
    stage
        .header
        .unit_records
        .insert(path.into(), digest(&bytes));
    stage.persist_header()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyRecipe {
    schema: u32,
    nonce: String,
    input_generation: String,
    planned_generation: String,
    epoch: [u8; 32],
    runtime_identity: Vec<u8>,
    pub unit: Vec<u8>,
    pub environment: Vec<u8>,
    pub dropins: BTreeMap<PathBuf, Vec<u8>>,
    transient: policy::TransientPolicy,
    pub directories: BTreeSet<PathBuf>,
    pub original_files: BTreeMap<PathBuf, Vec<u8>>,
    pub original_unit: policy::Original,
    pub original_environment: policy::Original,
    pub dropin_generation: GenerationRecord,
    pub original_dropin_witness: Option<Vec<u8>>,
    template_generations: Vec<GenerationRecord>,
    parents: BTreeMap<String, Parent>,
}
impl PolicyRecipe {
    pub(super) fn compiled(&self) -> policy::CompiledPolicy {
        policy::CompiledPolicy {
            unit: self.unit.clone(),
            environment: self.environment.clone(),
            dropins: self.dropins.clone(),
            transient: self.transient.clone(),
        }
    }
}
pub(super) fn recipe(stage: &StageGuard) -> Result<PolicyRecipe> {
    check(stage.header.unit_policy_recipe.as_deref() == Some(Path::new(RECIPE)))?;
    let value: PolicyRecipe =
        serde_json::from_slice(&bound(stage, Path::new(RECIPE))?).map_err(fail)?;
    check(
        value.schema == 2
            && value.nonce == stage.header.transaction_nonce
            && value.input_generation == stage.header.input_generation
            && value.planned_generation == stage.header.planned_generation
            && value.epoch == transaction_epoch(stage)?
            && value.runtime_identity
                == serde_json::to_vec(stage.header.runtime_binding.as_ref().ok_or_else(refuse)?)
                    .map_err(fail)?
            && value.unit.len() <= 65536
            && value.environment.len() <= 65536
            && value.dropins.len() <= 128
            && value.template_generations.len() == 2,
    )?;
    Ok(value)
}
pub(super) fn policy_identity(stage: &StageGuard) -> Result<String> {
    let _ = recipe(stage)?;
    Ok(digest(&bound(stage, Path::new(RECIPE))?))
}

// Exact existing receipt input layout, not a second authority supplied by CLI.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptInputs {
    schema: u32,
    nonce: String,
    input_generation: String,
    planned_generation: String,
    public_payload_root: PathBuf,
    candidate_binary: PathBuf,
    installed_binary: PathBuf,
    operator_uid: u32,
    provenance: crate::profile_auto_install_receipt::Provenance,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirstArmReceipt {
    schema: String,
    boot_id: String,
    candidate_sha256: String,
    source_config_sha256: String,
    relay_servers: Vec<String>,
    assessment_sha256: String,
    guard_unit_sha256: String,
    manager: String,
    manager_dropin_sha256: String,
    guardian_install_sha256: String,
    policy_sha256: String,
    installer_source_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GuardPolicyReadback {
    pub(super) state_sha256: String,
    pub(super) policy_sha256: String,
    pub(super) manager_binding_sha256: Option<String>,
}
/// Constructed only after the captured first-arm generation and current
/// installed deny policy both pass the unit-store admission below.
pub(crate) struct VerifiedFirstArm {
    _private: (),
}
#[cfg(test)]
impl VerifiedFirstArm {
    pub(crate) fn test_only() -> Self {
        Self { _private: () }
    }
}
fn hex_sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
/// Reopen each fixed component without following links and hold the final
/// inode while hashing. Root ownership and exact leaf mode are part of the
/// first-arm permission; a digest alone cannot authorize a replacement.
fn fixed_root_read<T>(
    path: &Path,
    mode: u32,
    maximum: u64,
    read: impl FnOnce(&mut File, u64) -> Result<(T, u64)>,
) -> Result<T> {
    check(path.is_absolute())?;
    let root = unsafe {
        libc::open(
            CString::new("/").map_err(fail)?.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    check(root >= 0)?;
    let mut parent = unsafe { OwnedFd::from_raw_fd(root) };
    let parts: Vec<_> = path.components().collect();
    check(parts.len() >= 2)?;
    for component in &parts[1..parts.len() - 1] {
        let Component::Normal(name) = component else {
            return Err(refuse());
        };
        let name = CString::new(name.as_encoded_bytes()).map_err(fail)?;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        check(raw >= 0)?;
        parent = unsafe { OwnedFd::from_raw_fd(raw) };
        let info = File::from(parent.try_clone().map_err(fail)?)
            .metadata()
            .map_err(fail)?;
        use std::os::unix::fs::MetadataExt;
        check(info.is_dir() && info.uid() == 0 && info.gid() == 0 && info.mode() & 0o022 == 0)?;
    }
    let Component::Normal(name) = parts[parts.len() - 1] else {
        return Err(refuse());
    };
    let name = CString::new(name.as_encoded_bytes()).map_err(fail)?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    check(raw >= 0)?;
    let mut file = unsafe { File::from_raw_fd(raw) };
    let before = file.metadata().map_err(fail)?;
    use std::os::unix::fs::MetadataExt;
    check(
        before.is_file()
            && before.uid() == 0
            && before.gid() == 0
            && before.nlink() == 1
            && before.mode() & 0o7777 == mode
            && before.len() <= maximum,
    )?;
    let (value, read_len) = read(&mut file, maximum)?;
    let after = file.metadata().map_err(fail)?;
    let reopened = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    check(reopened >= 0)?;
    let current = unsafe { File::from_raw_fd(reopened) }
        .metadata()
        .map_err(fail)?;
    let same = |other: &std::fs::Metadata| {
        other.dev() == before.dev()
            && other.ino() == before.ino()
            && other.uid() == before.uid()
            && other.gid() == before.gid()
            && other.mode() == before.mode()
            && other.nlink() == before.nlink()
            && other.len() == before.len()
            && other.mtime() == before.mtime()
            && other.mtime_nsec() == before.mtime_nsec()
            && other.ctime() == before.ctime()
            && other.ctime_nsec() == before.ctime_nsec()
    };
    check(read_len == before.len() && same(&after) && same(&current))?;
    Ok(value)
}
fn fixed_root_file(path: &Path, mode: u32, maximum: usize) -> Result<Vec<u8>> {
    fixed_root_read(path, mode, maximum as u64, |file, cap| {
        let mut bytes = Vec::new();
        Read::by_ref(file)
            .take(cap + 1)
            .read_to_end(&mut bytes)
            .map_err(fail)?;
        let count = bytes.len() as u64;
        check(count <= cap)?;
        Ok((bytes, count))
    })
}
fn fixed_root_digest(path: &Path, mode: u32, maximum: u64) -> Result<String> {
    fixed_root_read(path, mode, maximum, |file, cap| {
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let mut chunk = [0u8; 65536];
        loop {
            let size = file.read(&mut chunk).map_err(fail)?;
            if size == 0 {
                break;
            }
            count = count.checked_add(size as u64).ok_or_else(refuse)?;
            check(count <= cap)?;
            hash.update(&chunk[..size]);
        }
        Ok((format!("{:x}", hash.finalize()), count))
    })
}
pub(super) fn guard_policy_readback() -> Result<GuardPolicyReadback> {
    let output = unsafe {
        libc::memfd_create(
            CString::new("aegis-guard-readback").map_err(fail)?.as_ptr(),
            libc::MFD_CLOEXEC,
        )
    };
    check(output >= 0)?;
    let mut output = unsafe { File::from_raw_fd(output) };
    let mut child = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-B",
            "/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py",
            "read-guard-policy",
        ])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(fail)?))
        .stderr(Stdio::null())
        .spawn()
        .map_err(fail)?;
    // S9: wake on the child's exit through its pidfd under the same bound.
    let exit =
        crate::profile_auto_stopped_service::ChildExitWait::open(&child, Duration::from_millis(20));
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(status) = child.try_wait().map_err(fail)? {
            check(status.success())?;
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        exit.wait(&[], deadline);
    }
    check(output.metadata().map_err(fail)?.len() <= 4096)?;
    output.seek(SeekFrom::Start(0)).map_err(fail)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut output)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(fail)?;
    check(bytes.len() <= 4096)?;
    serde_json::from_slice(&bytes).map_err(fail)
}
fn first_arm_relays(settings: &aegis_core::Settings) -> Result<Vec<String>> {
    let mut servers = Vec::new();
    let endpoints = std::iter::once(settings.relay.server.as_str()).chain(
        settings
            .relay
            .endpoints
            .iter()
            .map(|item| item.server.as_str()),
    );
    for endpoint in endpoints {
        let addr: SocketAddrV4 = endpoint.parse().map_err(fail)?;
        let ip: Ipv4Addr = *addr.ip();
        check(
            addr.port() != 0
                && !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_link_local(),
        )?;
        let value = addr.to_string();
        if !servers.contains(&value) {
            servers.push(value);
        }
    }
    check(!servers.is_empty() && servers.len() <= 17)?;
    Ok(servers)
}
fn verify_first_arm(
    stage: &StageGuard,
    input: &ReceiptInputs,
    settings: &aegis_core::Settings,
) -> Result<VerifiedFirstArm> {
    check(stage.header.mode == AutoMode::FullWideTun)?;
    check(
        fixed_root_file(
            Path::new("/var/lib/aegis-auto/control/v2-enabled"),
            0o600,
            128,
        )? == b"{\"schema\":\"aegis_installer_auto_v2_enabled_v1\"}\n",
    )?;
    check(
        fixed_root_file(
            Path::new("/etc/systemd/system/aegis-client.service.d/00-v2-boot-gate.conf"),
            0o644,
            256,
        )? == b"[Unit]\nConditionPathExists=!/\n",
    )?;
    let captured = bound(
        stage,
        Path::new("input/payload/metadata/auto-guard-first-arm.json"),
    )?;
    let receipt: FirstArmReceipt = serde_json::from_slice(&captured).map_err(fail)?;
    check(receipt.schema == "aegis_auto_guard_first_arm_v1")?;
    let hashes = [
        &receipt.candidate_sha256,
        &receipt.source_config_sha256,
        &receipt.assessment_sha256,
        &receipt.guard_unit_sha256,
        &receipt.manager_dropin_sha256,
        &receipt.guardian_install_sha256,
        &receipt.policy_sha256,
        &receipt.installer_source_sha256,
    ];
    check(hashes.iter().all(|value| hex64(value)))?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(fail)?;
    check(receipt.boot_id == boot.trim_end_matches('\n'))?;
    check(matches!(
        receipt.manager.as_str(),
        "NetworkManager.service" | "systemd-networkd.service"
    ))?;
    let source = if stage
        .header
        .leaves
        .contains_key(Path::new("input/payload/bundle-main/aegis-client.toml"))
    {
        Path::new("input/payload/bundle-main/aegis-client.toml")
    } else {
        Path::new("input/payload/config/aegis.toml")
    };
    check(
        hex_sha(&bound(stage, source)?) == receipt.source_config_sha256
            && first_arm_relays(settings)? == receipt.relay_servers,
    )?;
    check(
        fixed_root_digest(&input.candidate_binary, 0o555, 256 * 1024 * 1024)?
            == receipt.candidate_sha256,
    )?;
    let installer = input.public_payload_root.join("install.sh");
    let installer_bytes = fixed_root_file(&installer, 0o555, 1 << 20)
        .or_else(|_| fixed_root_file(&installer, 0o755, 1 << 20))?;
    check(
        hex_sha(include_bytes!("../../install.sh")) == receipt.installer_source_sha256
            && hex_sha(&installer_bytes) == receipt.installer_source_sha256
            && hex_sha(include_bytes!("../../scripts/lib/aegis_auto_guardian.py"))
                == hex_sha(&fixed_root_file(
                    Path::new("/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py"),
                    0o500,
                    1 << 20,
                )?),
    )?;
    check(
        fixed_root_file(
            Path::new("/var/lib/aegis-install/client/auto-guard-first-arm.json"),
            0o600,
            4096,
        )? == captured,
    )?;
    let state = fixed_root_file(
        Path::new("/var/lib/aegis-install/client/device-guard.conf"),
        0o600,
        1 << 15,
    )?;
    check(
        hex_sha(&state) == receipt.assessment_sha256
            && state
                .split(|byte| *byte == b'\n')
                .filter(|line| line.starts_with(b"manager="))
                .count()
                == 1
            && state
                .split(|byte| *byte == b'\n')
                .any(|line| line == format!("manager={}", receipt.manager).as_bytes()),
    )?;
    let unit = fixed_root_file(
        Path::new("/etc/systemd/system/aegis-device-egress-guard.service"),
        0o644,
        1 << 16,
    )?;
    check(hex_sha(&unit) == receipt.guard_unit_sha256)?;
    let dropin_path = Path::new("/etc/systemd/system")
        .join(format!("{}.d", receipt.manager))
        .join("30-aegis-device-guard.conf");
    check(
        hex_sha(&fixed_root_file(&dropin_path, 0o644, 1 << 16)?) == receipt.manager_dropin_sha256,
    )?;
    let install = fixed_root_file(
        Path::new("/var/lib/aegis-install/client/auto-guardian-install.json"),
        0o600,
        4096,
    )?;
    check(hex_sha(&install) == receipt.guardian_install_sha256)?;
    let installed: serde_json::Value = serde_json::from_slice(&install).map_err(fail)?;
    check(
        installed["schema"] == "aegis_auto_guardian_install_v1"
            && installed["guard_unit_sha256"] == receipt.guard_unit_sha256
            && installed["worker_sha256"] == receipt.candidate_sha256,
    )?;
    let policy = fixed_root_file(
        Path::new("/var/lib/aegis-install/client/auto-guardian-policy.json"),
        0o600,
        4096,
    )?;
    let sealed: serde_json::Value = serde_json::from_slice(&policy).map_err(fail)?;
    check(
        sealed["schema"] == "aegis_auto_guardian_policy_v1"
            && sealed["boot_id"] == receipt.boot_id
            && sealed["state_sha256"] == receipt.assessment_sha256
            && sealed["policy_sha256"] == receipt.policy_sha256,
    )?;
    let fresh = guard_policy_readback()?;
    check(
        fresh.state_sha256 == receipt.assessment_sha256
            && fresh.policy_sha256 == receipt.policy_sha256
            && fresh.manager_binding_sha256.as_deref().is_some_and(|hash| {
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            }),
    )?;
    Ok(VerifiedFirstArm { _private: () })
}
/// `step` names the closed BindRuntimeService coordinate of the check that
/// is about to run; the worker reports it only for a generic refusal.
pub(super) fn prepare_policy(
    stage: &mut StageGuard,
    lock: &InstallLock,
    binding: &RuntimeBinding,
    step: &mut &'static str,
) -> Result<()> {
    *step = "policy_stage_current";
    current(stage)?;
    lock.revalidate().map_err(fail)?;
    *step = "policy_stage_state";
    check(
        stage.header.phase == Phase::Prepared
            && !stage.header.capture_started
            && stage.header.service_uid.is_none()
            && stage.header.unit_policy_recipe.is_none()
            && stage.header.runtime_binding.as_ref().is_some(),
    )?;
    *step = "policy_binding";
    binding.revalidate_local_generation().map_err(fail)?;
    check(
        serde_json::to_vec(binding).map_err(fail)?
            == serde_json::to_vec(stage.header.runtime_binding.as_ref().ok_or_else(refuse)?)
                .map_err(fail)?,
    )?;
    *step = "policy_inputs";
    super::receipt_store::revalidate_inputs(stage)?;
    *step = "policy_inputs_record";
    let input: ReceiptInputs = serde_json::from_slice(&bound(
        stage,
        Path::new("input/install-receipt/inputs.json"),
    )?)
    .map_err(fail)?;
    check(
        input.schema == 1
            && input.nonce == stage.header.transaction_nonce
            && input.input_generation == stage.header.input_generation
            && input.planned_generation == stage.header.planned_generation
            && input.operator_uid == stage.manifest.operator_uid
            && input.candidate_binary != input.installed_binary
            && input
                .provenance
                .binds_manifest(&input.public_payload_root.join("bundle.manifest.json")),
    )?;
    input.provenance.validate().map_err(fail)?;
    *step = "policy_templates";
    let limits = CaptureLimits {
        files: 128,
        file_bytes: 65536,
        tree_bytes: 8 * 1024 * 1024,
        ..Default::default()
    };
    let templates = [
        "packaging/systemd/aegis-client.service",
        "packaging/env/aegis-client.env.example",
    ];
    let mut held = Vec::new();
    for leaf in templates {
        held.push(
            CapturedTree::capture_file(
                &input.public_payload_root.join(leaf),
                input.public_payload_root.clone(),
                InputRole::ExplicitBundleData {
                    operator_uid: input.operator_uid,
                    administrator_uid: 0,
                },
                limits,
            )
            .map_err(fail)?,
        );
    }
    let unit_template = held[0].entries().next().ok_or_else(refuse)?.1;
    let environment_template = held[1].entries().next().ok_or_else(refuse)?.1;
    *step = "policy_namespace";
    let namespace_record = super::unit_binding::read(stage, false)?;
    let namespace = UnitNamespaceSnapshot::reopen(&namespace_record, lock).map_err(fail)?;
    let parent_unit = namespace
        .open_original_role_parent(ManagedRole::BaseUnit, lock)
        .map_err(fail)?;
    let parent_environment = namespace
        .open_original_role_parent(ManagedRole::Environment, lock)
        .map_err(fail)?;
    *step = "policy_original_leaves";
    let original_unit =
        policy::capture_original_leaf(&parent_unit, policy::LeafRole::BaseUnit).map_err(fail)?;
    let original_environment =
        policy::capture_original_leaf(&parent_environment, policy::LeafRole::Environment)
            .map_err(fail)?;
    check(
        namespace_record
            .verify_original_singleton(&original_unit.namespace_witness(policy::LeafRole::BaseUnit))
            .map_err(fail)?
            == ManagedRole::BaseUnit
            && namespace_record
                .verify_original_singleton(
                    &original_environment.namespace_witness(policy::LeafRole::Environment),
                )
                .map_err(fail)?
                == ManagedRole::Environment,
    )?;
    *step = "policy_dropins_capture";
    let dropins = CapturedTree::capture_optional(
        ManagedRole::Dropins.fixed_path(),
        ManagedRole::Dropins.fixed_path().into(),
        InputRole::AdministratorMetadata {
            administrator_uid: 0,
        },
        limits,
        true,
    )
    .map_err(fail)?;
    let (original_files, directories) = match &dropins {
        CapturedInput::Present(tree) => (
            tree.entries()
                .map(|(p, b)| (p.into(), b.to_vec()))
                .collect(),
            tree.directories()
                .into_iter()
                .filter(|p| !p.as_os_str().is_empty())
                .map(PathBuf::from)
                .collect(),
        ),
        CapturedInput::Absent(_) => (BTreeMap::new(), BTreeSet::new()),
    };
    *step = "policy_render";
    let rendered =
        crate::profile_auto_render::PreparedRender::restore_private_recipe(stage).map_err(fail)?;
    let settings: aegis_core::Settings = toml::from_str(&rendered.config.bytes).map_err(fail)?;
    *step = "policy_runtime_mode";
    check(
        crate::profile_auto_runtime_identity::runtime_policy(stage.header.mode, &settings)
            .map_err(fail)?
            == binding.policy(),
    )?;
    *step = "policy_first_arm";
    let boot_gate_only = original_files.len() == 1
        && original_files
            .get(Path::new("00-v2-boot-gate.conf"))
            .is_some_and(|bytes| bytes == b"[Unit]\nConditionPathExists=!/\n");
    let fresh_first_arm = if stage.header.mode == AutoMode::FullWideTun
        && (original_files.is_empty() || boot_gate_only)
    {
        check(directories.is_empty())?;
        let admission = verify_first_arm(stage, &input, &settings)?;
        lock.revalidate().map_err(fail)?;
        Some(admission)
    } else {
        None
    };
    let compiler = policy::CompilerInputs {
        mode: match stage.header.mode {
            AutoMode::SocksOnly => policy::Mode::Socks,
            AutoMode::WideRedirectSafe => policy::Mode::Redirect,
            AutoMode::FullWideTun => policy::Mode::FullTun,
        },
        policy: match binding.policy() {
            RuntimePolicy::Root => policy::Policy::Root,
            RuntimePolicy::DedicatedNone => policy::Policy::DedicatedNone,
            RuntimePolicy::DedicatedBind => policy::Policy::DedicatedBind,
        },
        user: match binding.identity().user() {
            ServiceUser::Root => policy::RuntimeUser::Root,
            ServiceUser::Aegis => policy::RuntimeUser::Aegis,
            ServiceUser::AegisSvc => policy::RuntimeUser::AegisSvc,
        },
        binary: input.installed_binary,
        config: stage.header.config_root.join("aegis.toml"),
        state: stage.header.state_dir.clone(),
        events: stage.header.runtime_events.clone(),
    };
    let compiled = if let Some(admission) = &fresh_first_arm {
        policy::compile_first_arm(
            &compiler,
            unit_template,
            environment_template,
            &original_files,
            admission,
        )
    } else {
        policy::compile(
            &compiler,
            unit_template,
            environment_template,
            &original_files,
        )
    }
    .map_err(|error| {
        *step = policy::refusal_code(error);
        refuse()
    })?;
    *step = "policy_recipe_build";
    let value = PolicyRecipe {
        schema: 2,
        nonce: stage.header.transaction_nonce.clone(),
        input_generation: stage.header.input_generation.clone(),
        planned_generation: stage.header.planned_generation.clone(),
        epoch: transaction_epoch(stage)?,
        runtime_identity: serde_json::to_vec(binding).map_err(fail)?,
        transient: compiled.transient_policy(),
        unit: compiled.unit,
        environment: compiled.environment,
        dropins: compiled.dropins,
        directories,
        original_files,
        original_unit,
        original_environment,
        dropin_generation: dropins.export_private_generation().map_err(fail)?,
        original_dropin_witness: {
            dropins.revalidate_original_generation().map_err(fail)?;
            let witness = fs::Target::open(ManagedRole::Dropins.fixed_path())
                .map_err(fail)?
                .inspect()
                .map_err(fail)?
                .map(|g| g.witness().map_err(fail))
                .transpose()?;
            dropins.revalidate_original_generation().map_err(fail)?;
            witness
        },
        template_generations: held
            .iter()
            .map(|h| h.export_private_generation().map_err(fail))
            .collect::<Result<_>>()?,
        parents: [
            (
                "base-unit".into(),
                parent_metadata(&parent_unit).map_err(fail)?,
            ),
            (
                "environment".into(),
                parent_metadata(&parent_environment).map_err(fail)?,
            ),
        ]
        .into_iter()
        .collect(),
    };
    *step = "policy_postflight";
    namespace.revalidate(lock).map_err(fail)?;
    binding.revalidate_local_generation().map_err(fail)?;
    super::receipt_store::revalidate_inputs(stage)?;
    let bytes = serde_json::to_vec(&value).map_err(fail)?;
    check(bytes.len() <= LIMIT)?;
    *step = "policy_recipe_write";
    stage.store.write_new(Path::new(RECIPE), &bytes)?;
    stage.header.leaves.insert(RECIPE.into(), digest(&bytes));
    stage.header.unit_policy_recipe = Some(RECIPE.into());
    stage.persist_header()?;
    namespace.revalidate(lock).map_err(fail)
}

pub(super) fn singleton_receipt(
    stage: &StageGuard,
    role: policy::LeafRole,
) -> Result<policy::Receipt> {
    let role = singleton(role);
    read(
        stage,
        &PathBuf::from(format!("receipts/unit-target/{}/forward.json", key(role))),
        role,
    )
}
pub(super) fn persist_singleton_intent(
    stage: &mut StageGuard,
    intent: &policy::Intent,
    prepared: bool,
) -> Result<()> {
    let role = singleton(intent.role);
    check(intent.epoch == transaction_epoch(stage)?)?;
    let path = PathBuf::from(format!(
        "receipts/unit-target/{}/{}.json",
        key(role),
        if prepared { "prepared" } else { "intent" }
    ));
    write(stage, &path, role, intent)?;
    if !prepared {
        check(
            stage
                .header
                .unit_pending
                .as_ref()
                .is_none_or(|p| p == &path),
        )?;
        stage.header.unit_pending = Some(path);
        stage.persist_header()?;
    }
    Ok(())
}
pub(super) fn admit_singleton_intent(stage: &StageGuard, intent: &policy::Intent) -> Result<()> {
    let role = singleton(intent.role);
    let path = PathBuf::from(format!("receipts/unit-target/{}/intent.json", key(role)));
    check(stage.header.unit_pending.as_ref() == Some(&path))?;
    let actual: policy::Intent = read(stage, &path, role)?;
    check(serde_json::to_vec(&actual).map_err(fail)? == serde_json::to_vec(intent).map_err(fail)?)
}
pub(super) fn persist_singleton_receipt(
    stage: &mut StageGuard,
    receipt: &policy::Receipt,
) -> Result<()> {
    let role = singleton(receipt.role());
    check(receipt.publication_epoch() == transaction_epoch(stage)?)?;
    let _ = recipe(stage)?;
    check(
        super::unit_binding::read(stage, false)?
            .verify_original_singleton(&receipt.original_namespace_witness())
            .map_err(fail)?
            == role,
    )?;
    admit_singleton_intent(stage, receipt.intent())?;
    let path = PathBuf::from(format!("receipts/unit-target/{}/forward.json", key(role)));
    write(stage, &path, role, receipt)?;
    check(
        stage
            .header
            .unit_role_records
            .insert(key(role).into(), path.clone())
            .is_none_or(|old| old == path),
    )?;
    stage.persist_header()
}
pub(super) fn forward_history(stage: &StageGuard) -> Result<Vec<OwnedTransition>> {
    stage
        .header
        .unit_forward_transitions
        .iter()
        .map(|(name, path)| {
            let role = match name.as_str() {
                "base-unit" => ManagedRole::BaseUnit,
                "environment" => ManagedRole::Environment,
                "dropins" => ManagedRole::Dropins,
                _ => return Err(refuse()),
            };
            check(
                path == &PathBuf::from(format!(
                    "receipts/unit-target/{}/transition.json",
                    key(role)
                )),
            )?;
            let value = read(stage, path, role)?;
            authenticate_forward(stage, &value)?;
            Ok(value)
        })
        .collect()
}
pub(super) fn persist_forward(stage: &mut StageGuard, transition: &OwnedTransition) -> Result<()> {
    authenticate_forward(stage, transition)?;
    let role = transition.role();
    let path = PathBuf::from(format!(
        "receipts/unit-target/{}/transition.json",
        key(role)
    ));
    write(stage, &path, role, transition)?;
    check(
        stage
            .header
            .unit_forward_transitions
            .insert(key(role).into(), path.clone())
            .is_none_or(|old| old == path),
    )?;
    stage.header.unit_pending = None;
    stage.persist_header()
}
pub(super) fn authenticate_forward(stage: &StageGuard, transition: &OwnedTransition) -> Result<()> {
    check(transition.epoch() == &transaction_epoch(stage)?)?;
    let role = match transition.role() {
        ManagedRole::BaseUnit => policy::LeafRole::BaseUnit,
        ManagedRole::Environment => policy::LeafRole::Environment,
        // Needs positively authenticated historical fs-record semantic accessor;
        // never derive authority by hashing an unvalidated JSON value.
        ManagedRole::Dropins => {
            return check(
                authenticated_dropin_record(stage, false)?
                    .publication_semantics_sha256()
                    .map_err(fail)?
                    == transition.receipt_semantics_sha256(),
            );
        }
    };
    let actual = singleton_receipt(stage, role)?;
    check(
        namespace::singleton_receipt_digest(&actual).map_err(fail)?
            == transition.receipt_semantics_sha256(),
    )
}
pub(super) fn restoration_history(stage: &StageGuard) -> Result<Vec<OwnedRestoration>> {
    stage
        .header
        .unit_restorations
        .iter()
        .map(|(name, path)| {
            let role = match name.as_str() {
                "base-unit" => ManagedRole::BaseUnit,
                "environment" => ManagedRole::Environment,
                "dropins" => ManagedRole::Dropins,
                _ => return Err(refuse()),
            };
            check(
                path == &PathBuf::from(format!(
                    "receipts/unit-target/{}/restoration-transition.json",
                    key(role)
                )),
            )?;
            let actual = read(stage, path, role)?;
            authenticate_restoration(stage, &actual)?;
            Ok(actual)
        })
        .collect()
}
pub(super) fn persist_singleton_restoration(
    stage: &mut StageGuard,
    receipt: &policy::RestorationReceipt,
) -> Result<()> {
    let role = singleton(receipt.role());
    check(receipt.rollback_epoch() == transaction_epoch(stage)?)?;
    let forward = singleton_receipt(stage, receipt.role())?;
    check(
        serde_json::to_vec(&forward).map_err(fail)?
            == serde_json::to_vec(receipt.forward_receipt()).map_err(fail)?,
    )?;
    write(
        stage,
        &PathBuf::from(format!("receipts/unit-target/{}/restored.json", key(role))),
        role,
        receipt,
    )
}
pub(super) fn authenticate_restoration(
    stage: &StageGuard,
    restoration: &OwnedRestoration,
) -> Result<()> {
    check(restoration.epoch() == &transaction_epoch(stage)?)?;
    let predecessor = forward_history(stage)?
        .into_iter()
        .find(|r| r.role() == restoration.role())
        .ok_or_else(refuse)?;
    check(predecessor.generation() == restoration.forward_generation())?;
    match restoration.role() {
        ManagedRole::BaseUnit => policy::LeafRole::BaseUnit,
        ManagedRole::Environment => policy::LeafRole::Environment,
        ManagedRole::Dropins => {
            let forward = authenticated_dropin_record(stage, false)?;
            let link: DropinRestorationLink = read(
                stage,
                Path::new("receipts/unit-target/dropins/restoration-link.json"),
                ManagedRole::Dropins,
            )?;
            check(
                link.forward_record_sha256 == forward.record_hash()
                    && link.forward_semantics
                        == forward.publication_semantics_sha256().map_err(fail)?,
            )?;
            if stage.header.unit_records.contains_key(&fs_leaf(true)) {
                let restored = authenticated_dropin_record(stage, true)?;
                let actual = fs::authenticated_unit_retained_restoration_semantics_sha256(
                    &forward, &restored,
                )
                .map_err(fail)?;
                return check(
                    matches!(link.kind, RestorationKind::RetainedOriginal)
                        && link.restored_record_sha256 == restored.record_hash()
                        && actual == link.restored_semantics
                        && actual == restoration.restoration_receipt_sha256(),
                );
            }
            check(
                matches!(link.kind, RestorationKind::OriginalAbsence)
                    && forward.original_generation().map_err(fail)?.is_none(),
            )?;
            let record = authenticated_withdrawal_record(stage)?;
            fs::validate_authenticated_withdrawal_predecessor(
                &forward,
                &record,
                &HistoricalAbsentDropin { stage },
            )
            .map_err(fail)?;
            let receipt = fs::reopen_withdrawal_receipt(
                &fs::Target::open(ManagedRole::Dropins.fixed_path()).map_err(fail)?,
                &record,
            )
            .map_err(fail)?;
            let mut hash = Sha256::new();
            hash.update(b"aegis-owned-unit-dropin-restoration-v1\0");
            hash.update(link.forward_semantics.as_bytes());
            hash.update([2]);
            hash.update(serde_json::to_vec(receipt.intent()).map_err(fail)?);
            let actual = format!("{:x}", hash.finalize());
            return check(
                link.restored_record_sha256 == record.record_hash()
                    && actual == link.restored_semantics
                    && actual == restoration.restoration_receipt_sha256(),
            );
        }
    };
    let receipt: policy::RestorationReceipt = read(
        stage,
        &PathBuf::from(format!(
            "receipts/unit-target/{}/restored.json",
            key(restoration.role())
        )),
        restoration.role(),
    )?;
    check(
        receipt.rollback_epoch() == transaction_epoch(stage)?
            && singleton(receipt.role()) == restoration.role()
            && namespace::singleton_receipt_digest(receipt.forward_receipt()).map_err(fail)?
                == predecessor.receipt_semantics_sha256()
            && namespace::singleton_restoration_receipt_digest(&receipt).map_err(fail)?
                == restoration.restoration_receipt_sha256(),
    )
}
pub(super) fn persist_restoration(
    stage: &mut StageGuard,
    restoration: &OwnedRestoration,
) -> Result<()> {
    authenticate_restoration(stage, restoration)?;
    let role = restoration.role();
    let path = PathBuf::from(format!(
        "receipts/unit-target/{}/restoration-transition.json",
        key(role)
    ));
    write(stage, &path, role, restoration)?;
    check(
        stage
            .header
            .unit_restorations
            .insert(key(role).into(), path.clone())
            .is_none_or(|old| old == path),
    )?;
    stage.header.unit_pending = None;
    stage.persist_header()
}

type PResult<T> = std::result::Result<T, &'static str>;
const POLICY_REFUSED: &str = "Administrative owned unit Store refused";
fn p_fail<E>(_: E) -> &'static str {
    POLICY_REFUSED
}
fn p_check(value: bool) -> PResult<()> {
    if value {
        Ok(())
    } else {
        Err(POLICY_REFUSED)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parent {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}
fn parent_metadata(fd: &OwnedFd) -> PResult<Parent> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(POLICY_REFUSED);
    }
    let stat = unsafe { stat.assume_init() };
    p_check(
        stat.st_mode & libc::S_IFMT == libc::S_IFDIR
            && stat.st_uid == 0
            && stat.st_mode & 0o022 == 0,
    )?;
    Ok(Parent {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        uid: stat.st_uid,
        gid: stat.st_gid,
    })
}
fn owned(fd: i32) -> PResult<OwnedFd> {
    if fd < 0 {
        Err(POLICY_REFUSED)
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
fn c(value: &str) -> PResult<CString> {
    CString::new(value).map_err(p_fail)
}
fn fixed_parent(role: policy::LeafRole, expected: &Parent) -> PResult<OwnedFd> {
    let mut directory = owned(unsafe {
        libc::open(
            c("/")?.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    parent_metadata(&directory)?;
    for part in role.parent().components() {
        let Component::Normal(name) = part else {
            continue;
        };
        directory = owned(unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c(name.to_str().ok_or(POLICY_REFUSED)?)?.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        parent_metadata(&directory)?;
    }
    p_check(parent_metadata(&directory)? == *expected)?;
    Ok(directory)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalStage {
    parent: Parent,
    stage: Parent,
}
/// Scoped adapter borrows the one real worker lock indirectly through RootContext.
/// No caller-selected filesystem target or constructed stop-proof is accepted.
#[derive(Clone, Copy)]
enum Purpose {
    Publish,
    Restore,
}
struct UnitContext<'a, 'b> {
    root: &'a super::store_context::RootContext<'b>,
    purpose: Purpose,
}
impl UnitContext<'_, '_> {
    fn singleton_targets(&self, role: policy::LeafRole) -> PResult<policy::Targets> {
        let role_key = key(singleton(role));
        let stage = self.root.stage_cell().borrow();
        let recipe = recipe(&stage).map_err(p_fail)?;
        let parent = fixed_parent(role, recipe.parents.get(role_key).ok_or(POLICY_REFUSED)?)?;
        let nonce = stage.header.transaction_nonce.clone();
        let leaf = PathBuf::from(format!("receipts/unit-target/{role_key}/local-stage.json"));
        let prior = if stage.header.unit_records.contains_key(&leaf) {
            Some(read::<LocalStage>(&stage, &leaf, singleton(role)).map_err(p_fail)?)
        } else {
            None
        };
        drop(stage);
        let name = c(&format!(".aegis-auto-unit-{nonce}-{role_key}"))?;
        let stage = match prior {
            Some(record) => {
                p_check(record.parent == parent_metadata(&parent)?)?;
                let fd = owned(unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                })?;
                p_check(
                    parent_metadata(&fd)? == record.stage
                        && record.stage.mode & 0o777 == 0o700
                        && record.stage.device == record.parent.device,
                )?;
                fd
            }
            None => self.root.stopped_phase(|| {
                if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                    return Err(POLICY_REFUSED);
                }
                let fd = owned(unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                })?;
                let record = LocalStage {
                    parent: parent_metadata(&parent)?,
                    stage: parent_metadata(&fd)?,
                };
                p_check(
                    record.stage.device == record.parent.device
                        && record.stage.mode & 0o777 == 0o700
                        && record.stage.gid == 0,
                )?;
                if unsafe { libc::fsync(parent.as_raw_fd()) } != 0 {
                    return Err(POLICY_REFUSED);
                }
                write(
                    &mut self.root.stage_cell().borrow_mut(),
                    &leaf,
                    singleton(role),
                    &record,
                )
                .map_err(p_fail)?;
                Ok(fd)
            })?,
        };
        Ok(policy::Targets { parent, stage })
    }
    fn lock(&self) -> PResult<&InstallLock> {
        crate::profile_auto_stopped_service::StopAuthority::install_lock(self.root)
    }
}
impl namespace::TransitionAuthority for UnitContext<'_, '_> {
    fn transaction_epoch(&self) -> PResult<[u8; 32]> {
        transaction_epoch(&self.root.stage_cell().borrow()).map_err(p_fail)
    }
    fn authenticate_owned_transition(&self, value: &OwnedTransition) -> PResult<()> {
        authenticate_forward(&self.root.stage_cell().borrow(), value).map_err(p_fail)
    }
    fn sealed_daemon_reload_receipt(
        &self,
    ) -> PResult<Option<crate::profile_auto_stopped_service::DaemonReloadReceipt>> {
        sealed_reload_receipt(&self.root.stage_cell().borrow()).map_err(p_fail)
    }
    fn authenticate_daemon_reload_receipt(
        &self,
        receipt: &crate::profile_auto_stopped_service::DaemonReloadReceipt,
    ) -> PResult<()> {
        authenticate_reload_receipt(&self.root.stage_cell().borrow(), receipt).map_err(p_fail)
    }
}
impl namespace::RestorationAuthority for UnitContext<'_, '_> {
    fn authenticate_owned_restoration(&self, value: &OwnedRestoration) -> PResult<()> {
        authenticate_restoration(&self.root.stage_cell().borrow(), value).map_err(p_fail)
    }
}
impl crate::profile_auto_stopped_service::StopAuthority for UnitContext<'_, '_> {
    fn revalidate(&self) -> PResult<()> {
        crate::profile_auto_stopped_service::StopAuthority::revalidate(self.root)
    }
    fn epoch(&self) -> PResult<crate::profile_auto_stopped_service::Epoch> {
        crate::profile_auto_stopped_service::StopAuthority::epoch(self.root)
    }
    fn sealed_unit_namespace_record(&self) -> PResult<namespace::NamespaceRecord> {
        crate::profile_auto_stopped_service::StopAuthority::sealed_unit_namespace_record(self.root)
    }
    fn sealed_owned_unit_transitions(&self) -> PResult<Vec<OwnedTransition>> {
        forward_history(&self.root.stage_cell().borrow()).map_err(p_fail)
    }
    fn sealed_owned_unit_restorations(&self) -> PResult<Vec<OwnedRestoration>> {
        restoration_history(&self.root.stage_cell().borrow()).map_err(p_fail)
    }
    fn install_lock(&self) -> PResult<&InstallLock> {
        self.lock()
    }
}
impl crate::profile_auto_stopped_service::RuntimeAuthority for UnitContext<'_, '_> {
    fn admit_prepared_operation(
        &self,
        operation: crate::profile_auto_stopped_service::PreparedOperation,
    ) -> PResult<()> {
        crate::profile_auto_stopped_service::RuntimeAuthority::admit_prepared_operation(
            self.root, operation,
        )
    }
    fn prepared_runtime_identity(&self) -> PResult<(u32, u32)> {
        crate::profile_auto_stopped_service::RuntimeAuthority::prepared_runtime_identity(self.root)
    }
    fn sealed_prepared_unit_namespace_record(&self) -> PResult<namespace::NamespaceRecord> {
        crate::profile_auto_stopped_service::RuntimeAuthority::sealed_prepared_unit_namespace_record(
            self.root,
        )
    }
}
impl crate::profile_auto_stopped_service::CompletePolicyAuthority for UnitContext<'_, '_> {
    fn authenticate_complete_published_policy(
        &self,
        transitions: &[OwnedTransition],
    ) -> PResult<()> {
        authenticate_complete_published_policy(self.root, transitions).map_err(p_fail)
    }
    fn expected_dropin_paths(&self) -> PResult<BTreeSet<PathBuf>> {
        expected_dropin_paths(&self.root.stage_cell().borrow()).map_err(p_fail)
    }
    fn policy_identity(&self) -> PResult<String> {
        policy_identity(&self.root.stage_cell().borrow()).map_err(p_fail)
    }
    fn admit_reload_operation(&self) -> PResult<()> {
        self.root.admit_reload_operation()
    }
    fn admit_final_base_publication(&self, transition: &OwnedTransition) -> PResult<()> {
        self.root.admit_final_base_publication(transition)
    }
}
impl policy::Context for UnitContext<'_, '_> {
    fn epoch(&self) -> PResult<[u8; 32]> {
        namespace::TransitionAuthority::transaction_epoch(self)
    }
    fn held_targets(&self, role: policy::LeafRole) -> PResult<policy::Targets> {
        self.singleton_targets(role)
    }
    fn original(&self, role: policy::LeafRole) -> PResult<policy::Original> {
        let recipe = recipe(&self.root.stage_cell().borrow()).map_err(p_fail)?;
        Ok(match role {
            policy::LeafRole::BaseUnit => recipe.original_unit,
            policy::LeafRole::Environment => recipe.original_environment,
        })
    }
    fn accepted_bytes(&self, role: policy::LeafRole) -> PResult<Vec<u8>> {
        let recipe = recipe(&self.root.stage_cell().borrow()).map_err(p_fail)?;
        Ok(match role {
            policy::LeafRole::BaseUnit => recipe.unit,
            policy::LeafRole::Environment => recipe.environment,
        })
    }
    fn original_guard(&self, role: policy::LeafRole, original: &policy::Original) -> PResult<()> {
        p_check(
            serde_json::to_vec(&self.original(role)?).map_err(p_fail)?
                == serde_json::to_vec(original).map_err(p_fail)?,
        )
    }
    fn stopped_mutation(
        &self,
        _role: policy::LeafRole,
        epoch: &[u8; 32],
        operation: policy::Mutation,
        actual: &mut dyn FnMut() -> PResult<()>,
    ) -> PResult<()> {
        p_check(*epoch == policy::Context::epoch(self)?)?;
        let result = if matches!(operation, policy::Mutation::RecoverReadback) {
            self.root.unit_pending_recovery(|| {
                p_check(*epoch == policy::Context::epoch(self)?)?;
                actual()
            })
        } else if matches!(self.purpose, Purpose::Restore)
            && self
                .root
                .stage_cell()
                .borrow()
                .header
                .new_unit_namespace
                .is_some()
            && self
                .root
                .stage_cell()
                .borrow()
                .header
                .unit_restored_manager
                .is_none()
        {
            self.root.unitrestoration_phase(|| {
                p_check(*epoch == policy::Context::epoch(self)?)?;
                actual()
            })
        } else {
            self.root.stopped_phase(|| {
                p_check(*epoch == policy::Context::epoch(self)?)?;
                actual()
            })
        };
        result
    }
    fn stage_prepared(&self, intent: &policy::Intent) -> PResult<()> {
        let result =
            persist_singleton_intent(&mut self.root.stage_cell().borrow_mut(), intent, true)
                .map_err(p_fail);
        result
    }
    fn persist_intent(&self, intent: &policy::Intent) -> PResult<()> {
        let result =
            persist_singleton_intent(&mut self.root.stage_cell().borrow_mut(), intent, false)
                .map_err(p_fail);
        result
    }
    fn admit_durable_publication_intent(&self, intent: &policy::Intent) -> PResult<()> {
        p_check(
            matches!(self.purpose, Purpose::Publish)
                && self.root.recovering_publication_role()? == intent.role,
        )?;
        let stage = self.root.stage_cell().borrow();
        current(&stage).map_err(p_fail)?;
        let path = PathBuf::from(format!(
            "receipts/unit-target/{}/intent.json",
            key(singleton(intent.role))
        ));
        let actual: policy::Intent = read(&stage, &path, singleton(intent.role)).map_err(p_fail)?;
        p_check(
            intent.epoch == transaction_epoch(&stage).map_err(p_fail)?
                && serde_json::to_vec(&actual).map_err(p_fail)?
                    == serde_json::to_vec(intent).map_err(p_fail)?,
        )
    }
    fn admit_intent(&self, intent: &policy::Intent) -> PResult<()> {
        admit_singleton_intent(&self.root.stage_cell().borrow(), intent).map_err(p_fail)
    }
    fn commit_receipt(&self, receipt: &policy::Receipt) -> PResult<()> {
        persist_singleton_receipt(&mut self.root.stage_cell().borrow_mut(), receipt)
            .map_err(p_fail)?;
        let (original, previous) = {
            let stage = self.root.stage_cell().borrow();
            (
                super::unit_binding::read(&stage, false).map_err(p_fail)?,
                forward_history(&stage).map_err(p_fail)?,
            )
        };
        let transition = if receipt.role() == policy::LeafRole::BaseUnit {
            namespace::mint_final_base_policy_transition(
                self,
                self,
                &original,
                &previous,
                receipt,
                self.lock()?,
            )?
        } else {
            namespace::mint_singleton(self, self, &original, &previous, receipt, self.lock()?)?
        };
        let result =
            persist_forward(&mut self.root.stage_cell().borrow_mut(), &transition).map_err(p_fail);
        result
    }
    fn admit_receipt(&self, receipt: &policy::Receipt) -> PResult<()> {
        p_check(
            serde_json::to_vec(
                &singleton_receipt(&self.root.stage_cell().borrow(), receipt.role())
                    .map_err(p_fail)?,
            )
            .map_err(p_fail)?
                == serde_json::to_vec(receipt).map_err(p_fail)?,
        )
    }
    fn persist_rollback_intent(&self, receipt: &policy::Receipt, epoch: &[u8; 32]) -> PResult<()> {
        policy::Context::admit_receipt(self, receipt)?;
        p_check(*epoch == policy::Context::epoch(self)?)?;
        let role = singleton(receipt.role());
        let path = PathBuf::from(format!(
            "receipts/unit-target/{}/rollback-intent.json",
            key(role)
        ));
        let mut stage = self.root.stage_cell().borrow_mut();
        write(&mut stage, &path, role, &(receipt, epoch)).map_err(p_fail)?;
        p_check(
            stage
                .header
                .unit_pending
                .as_ref()
                .is_none_or(|p| p == &path),
        )?;
        stage.header.unit_pending = Some(path);
        stage.persist_header().map_err(p_fail)
    }
    fn admit_rollback_intent(&self, receipt: &policy::Receipt, epoch: &[u8; 32]) -> PResult<()> {
        let role = singleton(receipt.role());
        let path = PathBuf::from(format!(
            "receipts/unit-target/{}/rollback-intent.json",
            key(role)
        ));
        let stage = self.root.stage_cell().borrow();
        p_check(stage.header.unit_pending.as_ref() == Some(&path))?;
        let actual: (policy::Receipt, [u8; 32]) = read(&stage, &path, role).map_err(p_fail)?;
        p_check(
            actual.1 == *epoch
                && serde_json::to_vec(&actual.0).map_err(p_fail)?
                    == serde_json::to_vec(receipt).map_err(p_fail)?,
        )
    }
    fn commit_rollback(&self, receipt: &policy::RestorationReceipt) -> PResult<()> {
        policy::Context::admit_rollback_intent(
            self,
            receipt.forward_receipt(),
            &receipt.rollback_epoch(),
        )?;
        persist_singleton_restoration(&mut self.root.stage_cell().borrow_mut(), receipt)
            .map_err(p_fail)?;
        let (original, previous, restored) = {
            let stage = self.root.stage_cell().borrow();
            (
                super::unit_binding::read(&stage, false).map_err(p_fail)?,
                forward_history(&stage).map_err(p_fail)?,
                restoration_history(&stage).map_err(p_fail)?,
            )
        };
        let transition = namespace::mint_singleton_restoration(
            self,
            self,
            &original,
            (&previous, &restored),
            receipt,
            self.lock()?,
        )?;
        persist_restoration(&mut self.root.stage_cell().borrow_mut(), &transition).map_err(p_fail)
    }
    fn admit_restoration_source(&self, receipt: &policy::RestorationReceipt) -> PResult<()> {
        p_check(matches!(self.purpose, Purpose::Restore))?;
        let role = singleton(receipt.role());
        let intent = PathBuf::from(format!(
            "receipts/unit-target/{}/rollback-intent.json",
            key(role)
        ));
        let stage = self.root.stage_cell().borrow();
        current(&stage).map_err(p_fail)?;
        p_check(
            !stage.header.capture_started
                && matches!(
                    stage.header.phase,
                    Phase::Config | Phase::Metadata | Phase::Finalized
                ),
        )?;
        // Preserve the exact durable source tuple after its pending selector has
        // been retired; this never substitutes a current-path/hash assertion.
        let source: (policy::Receipt, [u8; 32]) = read(&stage, &intent, role).map_err(p_fail)?;
        p_check(
            source.1 == receipt.rollback_epoch()
                && source.1 == transaction_epoch(&stage).map_err(p_fail)?
                && serde_json::to_vec(&source.0).map_err(p_fail)?
                    == serde_json::to_vec(receipt.forward_receipt()).map_err(p_fail)?,
        )?;
        if stage.header.unit_pending.as_ref() == Some(&intent) {
            drop(stage);
            return policy::Context::admit_rollback_intent(
                self,
                receipt.forward_receipt(),
                &receipt.rollback_epoch(),
            );
        }
        p_check(stage.header.unit_pending.is_none())?;
        let transition = stage
            .header
            .unit_restorations
            .get(key(role))
            .ok_or(POLICY_REFUSED)?;
        let completed: OwnedRestoration = read(&stage, transition, role).map_err(p_fail)?;
        authenticate_restoration(&stage, &completed).map_err(p_fail)?;
        p_check(
            completed.role() == role
                && completed.epoch() == &receipt.rollback_epoch()
                && completed.restoration_receipt_sha256()
                    == namespace::singleton_restoration_receipt_digest(receipt).map_err(p_fail)?,
        )
    }
    fn admit_restoration(&self, receipt: &policy::RestorationReceipt) -> PResult<()> {
        let role = singleton(receipt.role());
        let actual: policy::RestorationReceipt = read(
            &self.root.stage_cell().borrow(),
            &PathBuf::from(format!("receipts/unit-target/{}/restored.json", key(role))),
            role,
        )
        .map_err(p_fail)?;
        p_check(
            serde_json::to_vec(&actual).map_err(p_fail)?
                == serde_json::to_vec(receipt).map_err(p_fail)?,
        )
    }
}

fn fs_leaf(restored: bool) -> PathBuf {
    PathBuf::from(if restored {
        "receipts/unit-target/dropins/restored/publication-receipt.json"
    } else {
        "receipts/unit-target/dropins/forward/publication-receipt.json"
    })
}
fn fs_binding(
    stage: &StageGuard,
    sub: &super::durable::Store,
    restored: bool,
) -> Result<fs::RecordBinding> {
    let (dev, ino) = sub.identity()?;
    let phase = if restored { "rollback" } else { "unit_forward" };
    let mut hash = Sha256::new();
    hash.update(b"aegis-auto-unit-fs-record-v2\0");
    hash.update(transaction_epoch(stage)?);
    hash.update(phase.as_bytes());
    hash.update(dev.to_be_bytes());
    hash.update(ino.to_be_bytes());
    Ok(fs::RecordBinding {
        transaction_stage: fs::Identity { dev, ino },
        transaction_nonce: stage.header.transaction_nonce.clone(),
        phase: phase.into(),
        chain_sha256: format!("{:x}", hash.finalize()),
    })
}
struct FsAuthority<'a> {
    stage: &'a StageGuard,
    leaf: PathBuf,
    binding: fs::RecordBinding,
}
impl fs::PhaseAuthority for FsAuthority<'_> {
    fn validate_record_claim(&self, claim: &fs::RecordClaim) -> PResult<()> {
        current(self.stage).map_err(p_fail)?;
        p_check(
            claim.administrator_uid == 0
                && claim.actual_stage == self.binding.transaction_stage
                && claim.binding == self.binding
                && self.leaf.file_name().and_then(|v| v.to_str())
                    == Some(claim.record_leaf.as_str())
                && self.stage.header.unit_records.get(&self.leaf) == Some(&claim.record_sha256),
        )
    }
}
pub(super) fn authenticated_dropin_record(
    stage: &StageGuard,
    restored: bool,
) -> Result<fs::AuthenticatedRecord> {
    let leaf = fs_leaf(restored);
    current(stage)?;
    check(stage.header.unit_records.contains_key(&leaf))?;
    let sub = stage
        .store
        .sub_store(leaf.parent().ok_or_else(refuse)?, false)?;
    let authority = FsAuthority {
        stage,
        leaf,
        binding: fs_binding(stage, &sub, restored)?,
    };
    fs::authenticate_record(
        sub.duplicate_root()?,
        "publication-receipt.json",
        &authority,
    )
    .map_err(fail)
}
fn persist_dropin_publication(
    root: &super::store_context::RootContext<'_>,
    receipt: &fs::PublicationReceipt,
    restored: bool,
) -> Result<()> {
    // Actual coordinator purpose and exact pending namespace select the phase;
    // a restored bool alone never admits Metadata/Finalized publication.
    root.admit_dropin_publication_record(restored)
        .map_err(fail)?;
    let mut stage = root.stage_cell().borrow_mut();
    current(&stage)?;
    let leaf = fs_leaf(restored);
    let sub = stage
        .store
        .sub_store(leaf.parent().ok_or_else(refuse)?, true)?;
    let bytes = receipt
        .durable_bytes(fs_binding(&stage, &sub, restored)?)
        .map_err(fail)?;
    check(bytes.len() <= 4 * 1024 * 1024)?;
    if stage.header.unit_records.contains_key(&leaf) {
        return check(stage.store.read(&leaf)?.as_slice() == bytes.as_slice());
    }
    sub.write_new(Path::new("publication-receipt.json"), &bytes)?;
    stage
        .header
        .unit_records
        .insert(leaf.clone(), digest(&bytes));
    if !restored {
        check(
            stage
                .header
                .unit_role_records
                .insert("dropins".into(), leaf.clone())
                .is_none_or(|old| old == leaf),
        )?;
    }
    stage.persist_header()
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RestorationKind {
    RetainedOriginal,
    OriginalAbsence,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DropinRestorationLink {
    kind: RestorationKind,
    forward_record_sha256: String,
    restored_record_sha256: String,
    forward_semantics: String,
    restored_semantics: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardDropinEpoch {
    record_sha256: String,
    semantics: String,
    epoch: String,
}
fn persist_forward_dropin_epoch(
    stage: &mut StageGuard,
    receipt: &fs::PublicationReceipt,
) -> Result<()> {
    let record = authenticated_dropin_record(stage, false)?;
    check(
        record.publication_semantics_sha256().map_err(fail)?
            == namespace::dropin_receipt_digest(receipt).map_err(fail)?,
    )?;
    // The source is the descriptor-minted actual receipt, not an external JSON
    // or epoch flag. This read-only projection supplies the historical chain
    // capsule; the shared authenticated pair check is still mandatory.
    let projection = serde_json::to_value(receipt.intent()).map_err(fail)?;
    check(
        projection.get("target").and_then(|v| v.as_str())
            == ManagedRole::Dropins.fixed_path().to_str(),
    )?;
    let epoch = projection
        .get("epoch")
        .and_then(|v| v.as_str())
        .ok_or_else(refuse)?
        .to_owned();
    check(
        epoch.starts_with(".auto-config-")
            && epoch.len() == 45
            && epoch[13..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )?;
    let capsule = ForwardDropinEpoch {
        record_sha256: record.record_hash().into(),
        semantics: record.publication_semantics_sha256().map_err(fail)?,
        epoch,
    };
    write(
        stage,
        Path::new("receipts/unit-target/dropins/forward-epoch.json"),
        ManagedRole::Dropins,
        &capsule,
    )
}
struct HistoricalAbsentDropin<'a> {
    stage: &'a StageGuard,
}
impl fs::OwnAbsenceChainAuthority for HistoricalAbsentDropin<'_> {
    fn validate_original_absence_and_chain(
        &self,
        target: &Path,
        current_epoch: &str,
    ) -> PResult<()> {
        let original = recipe(self.stage).map_err(p_fail)?;
        p_check(
            target == ManagedRole::Dropins.fixed_path()
                && original.dropin_generation.kind() == 2
                && original.dropin_generation.original_source() == target
                && original.original_dropin_witness.is_none()
                && self.stage.header.unit_role_records.get("dropins") == Some(&fs_leaf(false)),
        )?;
        let record = authenticated_dropin_record(self.stage, false).map_err(p_fail)?;
        p_check(record.original_generation()?.is_none())?;
        let capsule: ForwardDropinEpoch = read(
            self.stage,
            Path::new("receipts/unit-target/dropins/forward-epoch.json"),
            ManagedRole::Dropins,
        )
        .map_err(p_fail)?;
        p_check(
            capsule.epoch == current_epoch
                && capsule.record_sha256 == record.record_hash()
                && capsule.semantics == record.publication_semantics_sha256()?,
        )?;
        let chain = forward_history(self.stage).map_err(p_fail)?;
        let transition = chain
            .iter()
            .find(|r| r.role() == ManagedRole::Dropins)
            .ok_or(POLICY_REFUSED)?;
        p_check(
            transition.receipt_semantics_sha256() == capsule.semantics
                && transition.epoch() == &transaction_epoch(self.stage).map_err(p_fail)?,
        )
    }
}
fn authenticated_withdrawal_record(stage: &StageGuard) -> Result<fs::AuthenticatedRecord> {
    let leaf = PathBuf::from("receipts/unit-target/dropins/restored/withdrawal-receipt.json");
    current(stage)?;
    check(
        stage.header.unit_records.contains_key(&leaf)
            && !stage.header.unit_records.contains_key(&fs_leaf(true)),
    )?;
    let sub = stage
        .store
        .sub_store(leaf.parent().ok_or_else(refuse)?, false)?;
    let authority = FsAuthority {
        stage,
        leaf,
        binding: fs_binding(stage, &sub, true)?,
    };
    fs::authenticate_record(sub.duplicate_root()?, "withdrawal-receipt.json", &authority)
        .map_err(fail)
}
fn persist_restoration_link(
    stage: &mut StageGuard,
    forward: &fs::PublicationReceipt,
    restored: &policy::DropinRollback,
) -> Result<()> {
    let forward_record = authenticated_dropin_record(stage, false)?;
    check(
        forward_record
            .publication_semantics_sha256()
            .map_err(fail)?
            == namespace::dropin_receipt_digest(forward).map_err(fail)?,
    )?;
    let (kind, restored_hash) = match restored {
        policy::DropinRollback::RetainedOriginal(receipt) => {
            fs::validate_retained_restore_predecessor(forward, receipt).map_err(fail)?;
            let actual = authenticated_dropin_record(stage, true)?;
            fs::validate_authenticated_retained_restore_predecessor(&forward_record, &actual)
                .map_err(fail)?;
            (
                RestorationKind::RetainedOriginal,
                actual.record_hash().to_owned(),
            )
        }
        policy::DropinRollback::OriginalAbsence(receipt) => {
            fs::validate_withdrawal_predecessor(forward, receipt).map_err(fail)?;
            check(
                forward_record
                    .original_generation()
                    .map_err(fail)?
                    .is_none(),
            )?;
            let withdrawn = authenticated_withdrawal_record(stage)?;
            fs::validate_authenticated_withdrawal_predecessor(
                &forward_record,
                &withdrawn,
                &HistoricalAbsentDropin { stage },
            )
            .map_err(fail)?;
            (
                RestorationKind::OriginalAbsence,
                withdrawn.record_hash().to_owned(),
            )
        }
    };
    let link = DropinRestorationLink {
        kind,
        forward_record_sha256: forward_record.record_hash().to_owned(),
        restored_record_sha256: restored_hash,
        forward_semantics: namespace::dropin_receipt_digest(forward).map_err(fail)?,
        restored_semantics: namespace::dropin_restoration_receipt_digest(forward, restored)
            .map_err(fail)?,
    };
    write(
        stage,
        Path::new("receipts/unit-target/dropins/restoration-link.json"),
        ManagedRole::Dropins,
        &link,
    )
}

struct OriginalDropinGuard<'a, 'b> {
    root: &'a super::store_context::RootContext<'b>,
}
impl fs::CaptureGuard for OriginalDropinGuard<'_, '_> {
    fn validate_captured_generation(
        &self,
        target: &Path,
        expected: Option<&fs::Generation>,
    ) -> PResult<()> {
        p_check(target == ManagedRole::Dropins.fixed_path())?;
        let stage = self.root.stage_cell().borrow();
        let captured = recipe(&stage).map_err(p_fail)?;
        p_check(captured.dropin_generation.original_source() == target)?;
        let held = capture::reopen_generation(&captured.dropin_generation).map_err(p_fail)?;
        held.revalidate().map_err(p_fail)?;
        let wanted = expected.map(|g| g.witness()).transpose()?;
        p_check(
            wanted == captured.original_dropin_witness
                && fs::Target::open(target)?.inspect()?.as_ref() == expected,
        )?;
        held.revalidate().map_err(p_fail)
    }
}
struct CurrentDropinGuard {
    receipt: fs::PublicationReceipt,
}
impl fs::CaptureGuard for CurrentDropinGuard {
    fn validate_captured_generation(
        &self,
        target: &Path,
        expected: Option<&fs::Generation>,
    ) -> PResult<()> {
        p_check(
            target == ManagedRole::Dropins.fixed_path()
                && expected == Some(self.receipt.generation()),
        )?;
        fs::revalidate_current_receipt(&fs::Target::open(target)?, &self.receipt)
    }
}
struct OriginalAbsentDropin<'a, 'b> {
    root: &'a super::store_context::RootContext<'b>,
}
impl fs::OwnAbsenceChainAuthority for OriginalAbsentDropin<'_, '_> {
    fn validate_original_absence_and_chain(
        &self,
        target: &Path,
        current_epoch: &str,
    ) -> PResult<()> {
        let stage = self.root.stage_cell().borrow();
        fs::OwnAbsenceChainAuthority::validate_original_absence_and_chain(
            &HistoricalAbsentDropin { stage: &stage },
            target,
            current_epoch,
        )
    }
}
fn persist_fs_bytes(stage: &mut StageGuard, path: &Path, bytes: &[u8]) -> Result<()> {
    current(stage)?;
    check(
        !stage.header.capture_started
            && path.starts_with("receipts/unit-target/dropins")
            && super::relative(path)
            && bytes.len() <= 4 * 1024 * 1024,
    )?;
    if stage.header.unit_records.contains_key(path) {
        return check(stage.store.read(path)?.as_slice() == bytes);
    }
    check(stage.header.unit_records.len() < 128)?;
    stage.store.write_new(path, bytes)?;
    stage.header.unit_records.insert(path.into(), digest(bytes));
    stage.persist_header()
}
fn publication_intent_path(restored: bool) -> PathBuf {
    PathBuf::from(if restored {
        "receipts/unit-target/dropins/restored/publication-intent.json"
    } else {
        "receipts/unit-target/dropins/forward/publication-intent.json"
    })
}
impl policy::DropinContext for UnitContext<'_, '_> {
    fn epoch(&self) -> PResult<[u8; 32]> {
        namespace::TransitionAuthority::transaction_epoch(self)
    }
    fn original_generation(&self) -> PResult<Option<fs::Generation>> {
        let stage = self.root.stage_cell().borrow();
        if stage.header.unit_records.contains_key(&fs_leaf(false)) {
            return authenticated_dropin_record(&stage, false)
                .map_err(p_fail)?
                .original_generation();
        }
        let original = recipe(&stage).map_err(p_fail)?;
        let guard = OriginalDropinGuard { root: self.root };
        original
            .original_dropin_witness
            .as_deref()
            .map(|w| {
                fs::Generation::from_guarded_witness(ManagedRole::Dropins.fixed_path(), w, &guard)
            })
            .transpose()
    }
    fn capture_guard(&self) -> PResult<Box<dyn fs::CaptureGuard + '_>> {
        Ok(Box::new(OriginalDropinGuard { root: self.root }))
    }
    fn stopped_mutation(
        &self,
        epoch: &[u8; 32],
        actual: &mut dyn FnMut() -> PResult<()>,
    ) -> PResult<()> {
        p_check(*epoch == policy::DropinContext::epoch(self)?)?;
        let result = if matches!(self.purpose, Purpose::Restore)
            && self
                .root
                .stage_cell()
                .borrow()
                .header
                .new_unit_namespace
                .is_some()
            && self
                .root
                .stage_cell()
                .borrow()
                .header
                .unit_restored_manager
                .is_none()
        {
            self.root.unitrestoration_phase(|| {
                p_check(*epoch == policy::DropinContext::epoch(self)?)?;
                actual()
            })
        } else {
            self.root.stopped_phase(|| {
                p_check(*epoch == policy::DropinContext::epoch(self)?)?;
                actual()
            })
        };
        result
    }
    fn persist_stage(&self, receipt: &fs::StageReceipt) -> PResult<()> {
        let path = PathBuf::from(format!(
            "receipts/unit-target/dropins/{}/stage.json",
            if matches!(self.purpose, Purpose::Restore) {
                "restored"
            } else {
                "forward"
            }
        ));
        let result = write(
            &mut self.root.stage_cell().borrow_mut(),
            &path,
            ManagedRole::Dropins,
            receipt,
        )
        .map_err(p_fail);
        result
    }
    fn persist_intent(&self, intent: &fs::PublicationIntent) -> PResult<()> {
        let restored = matches!(self.purpose, Purpose::Restore);
        let path = publication_intent_path(restored);
        let mut stage = self.root.stage_cell().borrow_mut();
        let sub = stage
            .store
            .sub_store(path.parent().ok_or(POLICY_REFUSED)?, true)
            .map_err(p_fail)?;
        let bytes = intent.durable_bytes(fs_binding(&stage, &sub, restored).map_err(p_fail)?)?;
        persist_fs_bytes(&mut stage, &path, &bytes).map_err(p_fail)?;
        p_check(
            stage
                .header
                .unit_pending
                .as_ref()
                .is_none_or(|p| p == &path),
        )?;
        stage.header.unit_pending = Some(path);
        stage.persist_header().map_err(p_fail)
    }
    fn commit_receipt(&self, receipt: &fs::PublicationReceipt) -> PResult<()> {
        let stage = self.root.stage_cell().borrow();
        p_check(
            matches!(self.purpose, Purpose::Publish)
                && stage.header.unit_pending.as_ref() == Some(&publication_intent_path(false)),
        )?;
        drop(stage);
        persist_dropin_publication(self.root, receipt, false).map_err(p_fail)?;
        persist_forward_dropin_epoch(&mut self.root.stage_cell().borrow_mut(), receipt)
            .map_err(p_fail)?;
        let (original, previous, compiled, directories, files) = {
            let stage = self.root.stage_cell().borrow();
            let policy = recipe(&stage).map_err(p_fail)?;
            let original = super::unit_binding::read(&stage, false).map_err(p_fail)?;
            let previous = forward_history(&stage).map_err(p_fail)?;
            (
                original,
                previous,
                policy.compiled(),
                policy.directories,
                policy.original_files,
            )
        };
        let lock = self.lock()?;
        let transition = namespace::mint_dropins(
            self,
            self,
            namespace::DropinTransitionInputs {
                original: &original,
                previous: &previous,
                compiled: &compiled,
                directories: &directories,
                original_files: &files,
                receipt,
            },
            lock,
        )?;
        let result =
            persist_forward(&mut self.root.stage_cell().borrow_mut(), &transition).map_err(p_fail);
        result
    }
    fn admit_receipt(&self, receipt: &fs::PublicationReceipt) -> PResult<()> {
        let stage = self.root.stage_cell().borrow();
        let sub = stage
            .store
            .sub_store(fs_leaf(false).parent().ok_or(POLICY_REFUSED)?, false)
            .map_err(p_fail)?;
        let bytes = receipt.durable_bytes(fs_binding(&stage, &sub, false).map_err(p_fail)?)?;
        let _ = authenticated_dropin_record(&stage, false).map_err(p_fail)?;
        p_check(
            stage
                .store
                .read(&fs_leaf(false))
                .map_err(p_fail)?
                .as_slice()
                == bytes.as_slice(),
        )
    }
    fn current_receipt_guard(
        &self,
        receipt: &fs::PublicationReceipt,
    ) -> PResult<Box<dyn fs::CaptureGuard + '_>> {
        policy::DropinContext::admit_receipt(self, receipt)?;
        let stage = self.root.stage_cell().borrow();
        let record = authenticated_dropin_record(&stage, false).map_err(p_fail)?;
        Ok(Box::new(CurrentDropinGuard {
            receipt: fs::reopen_own_receipt(
                &fs::Target::open(ManagedRole::Dropins.fixed_path())?,
                &record,
            )?,
        }))
    }
    fn original_absence_authority(&self) -> PResult<Box<dyn fs::OwnAbsenceChainAuthority + '_>> {
        Ok(Box::new(OriginalAbsentDropin { root: self.root }))
    }
    fn persist_withdrawal(&self, intent: &fs::WithdrawalIntent) -> PResult<()> {
        p_check(
            matches!(self.purpose, Purpose::Restore)
                && intent.target() == ManagedRole::Dropins.fixed_path(),
        )?;
        let path = PathBuf::from("receipts/unit-target/dropins/restored/withdrawal-intent.json");
        let mut stage = self.root.stage_cell().borrow_mut();
        let sub = stage
            .store
            .sub_store(path.parent().ok_or(POLICY_REFUSED)?, true)
            .map_err(p_fail)?;
        let bytes = intent.durable_bytes(fs_binding(&stage, &sub, true).map_err(p_fail)?)?;
        persist_fs_bytes(&mut stage, &path, &bytes).map_err(p_fail)?;
        p_check(
            stage
                .header
                .unit_pending
                .as_ref()
                .is_none_or(|p| p == &path),
        )?;
        stage.header.unit_pending = Some(path);
        stage.persist_header().map_err(p_fail)
    }
    fn commit_rollback(
        &self,
        forward: &fs::PublicationReceipt,
        restored: &policy::DropinRollback,
    ) -> PResult<()> {
        policy::DropinContext::admit_receipt(self, forward)?;
        p_check(matches!(self.purpose, Purpose::Restore))?;
        match restored {
            policy::DropinRollback::RetainedOriginal(receipt) => {
                persist_dropin_publication(self.root, receipt, true).map_err(p_fail)?
            }
            policy::DropinRollback::OriginalAbsence(receipt) => {
                let path =
                    PathBuf::from("receipts/unit-target/dropins/restored/withdrawal-receipt.json");
                let mut stage = self.root.stage_cell().borrow_mut();
                let sub = stage
                    .store
                    .sub_store(path.parent().ok_or(POLICY_REFUSED)?, false)
                    .map_err(p_fail)?;
                let bytes =
                    receipt.durable_bytes(fs_binding(&stage, &sub, true).map_err(p_fail)?)?;
                persist_fs_bytes(&mut stage, &path, &bytes).map_err(p_fail)?;
            }
        }
        persist_restoration_link(&mut self.root.stage_cell().borrow_mut(), forward, restored)
            .map_err(p_fail)?;
        let (original, previous, restorations) = {
            let stage = self.root.stage_cell().borrow();
            (
                super::unit_binding::read(&stage, false).map_err(p_fail)?,
                forward_history(&stage).map_err(p_fail)?,
                restoration_history(&stage).map_err(p_fail)?,
            )
        };
        let transition = namespace::mint_dropin_restoration(
            self,
            self,
            &original,
            (&previous, &restorations),
            (forward, restored),
            self.lock()?,
        )?;
        persist_restoration(&mut self.root.stage_cell().borrow_mut(), &transition).map_err(p_fail)
    }
    fn admit_rollback(
        &self,
        forward: &fs::PublicationReceipt,
        restored: &policy::DropinRollback,
    ) -> PResult<()> {
        policy::DropinContext::admit_receipt(self, forward)?;
        let stage = self.root.stage_cell().borrow();
        let path = match restored {
            policy::DropinRollback::RetainedOriginal(_) => fs_leaf(true),
            policy::DropinRollback::OriginalAbsence(_) => {
                PathBuf::from("receipts/unit-target/dropins/restored/withdrawal-receipt.json")
            }
        };
        let sub = stage
            .store
            .sub_store(path.parent().ok_or(POLICY_REFUSED)?, false)
            .map_err(p_fail)?;
        let binding = fs_binding(&stage, &sub, true).map_err(p_fail)?;
        let bytes = match restored {
            policy::DropinRollback::RetainedOriginal(receipt) => receipt.durable_bytes(binding)?,
            policy::DropinRollback::OriginalAbsence(receipt) => receipt.durable_bytes(binding)?,
        };
        p_check(
            stage.header.unit_records.get(&path) == Some(&digest(&bytes))
                && stage.store.read(&path).map_err(p_fail)?.as_slice() == bytes.as_slice(),
        )
    }
}

fn verify_policy_bodies(root: &super::store_context::RootContext<'_>) -> Result<()> {
    let context = UnitContext {
        root,
        purpose: Purpose::Publish,
    };
    let stage = root.stage_cell().borrow();
    let accepted = recipe(&stage)?;
    stage
        .header
        .runtime_binding
        .as_ref()
        .ok_or_else(refuse)?
        .revalidate_local_generation()
        .map_err(fail)?;
    check(stage.header.unit_role_records.len() == 3 && stage.header.unit_restorations.is_empty())?;
    let unit = singleton_receipt(&stage, policy::LeafRole::BaseUnit)?;
    let env = singleton_receipt(&stage, policy::LeafRole::Environment)?;
    let record = authenticated_dropin_record(&stage, false)?;
    let dropins = fs::reopen_own_receipt(
        &fs::Target::open(ManagedRole::Dropins.fixed_path()).map_err(fail)?,
        &record,
    )
    .map_err(fail)?;
    super::receipt_store::verify_installed(&stage)?;
    drop(stage);
    policy::verify(&context, &unit).map_err(fail)?;
    policy::verify(&context, &env).map_err(fail)?;
    policy::verify_dropins(
        &context,
        &accepted.compiled(),
        &accepted.directories,
        &dropins,
    )
    .map_err(fail)?;
    root.stage_cell()
        .borrow()
        .header
        .runtime_binding
        .as_ref()
        .ok_or_else(refuse)?
        .revalidate_local_generation()
        .map_err(fail)
}
/// Exact LIVE bodies; final-base admission separately binds prior2+candidate.
pub(super) fn verify_published_policy(root: &super::store_context::RootContext<'_>) -> Result<()> {
    verify_policy_bodies(root)
}
fn verify_committed_policy(root: &super::store_context::RootContext<'_>) -> Result<()> {
    {
        let stage = root.stage_cell().borrow();
        check(forward_history(&stage)?.len() == 3)?;
        if stage.header.unit_pending.as_deref() == Some(Path::new(RELOAD_INTENT)) {
            admit_reload_intent(&stage)?;
        } else {
            check(stage.header.unit_pending.is_none())?;
        }
    }
    verify_policy_bodies(root)
}
/// Backend purpose selector is derived from the protected admitted pending
/// record and closed role, never a caller flag. It does not claim rename success.
pub(super) fn admitted_pending_publication(stage: &StageGuard) -> Result<Option<policy::LeafRole>> {
    current(stage)?;
    let Some(path) = stage.header.unit_pending.as_ref() else {
        return Ok(None);
    };
    check(
        stage.header.phase == Phase::Config
            && !stage.header.capture_started
            && stage.header.new_unit_namespace.is_none(),
    )?;
    for role in [policy::LeafRole::BaseUnit, policy::LeafRole::Environment] {
        let fixed = PathBuf::from(format!(
            "receipts/unit-target/{}/intent.json",
            key(singleton(role))
        ));
        if path == &fixed {
            let intent: policy::Intent = read(stage, path, singleton(role))?;
            check(intent.role == role && intent.epoch == transaction_epoch(stage)?)?;
            admit_singleton_intent(stage, &intent)?;
            return Ok(Some(role));
        }
    }
    Ok(None) // caller preserves other typed rollback/dropin/reload refusals
}
/// Recovery purpose closes only the exact completed BaseUnit publication. The
/// protected intent, actual held targets, prior role records and compiled bytes
/// must all agree before ordinary final-base namespace admission can continue.
pub(super) fn validate_recovered_final_base_publication(
    root: &super::store_context::RootContext<'_>,
    transition: &OwnedTransition,
) -> Result<()> {
    {
        let stage = root.stage_cell().borrow();
        check(admitted_pending_publication(&stage)? == Some(policy::LeafRole::BaseUnit))?;
    }
    let context = UnitContext {
        root,
        purpose: Purpose::Publish,
    };
    let intent = {
        let stage = root.stage_cell().borrow();
        let path = stage.header.unit_pending.as_ref().ok_or_else(refuse)?;
        read::<policy::Intent>(&stage, path, ManagedRole::BaseUnit)?
    };
    let proof = policy::pending_publish_readback(&context, &intent).map_err(fail)?;
    proof.require_completed_base(&context).map_err(fail)?;
    validate_final_base_publication(root, transition)?;
    proof.require_completed_base(&context).map_err(fail)
}
pub(super) fn validate_final_base_publication(
    root: &super::store_context::RootContext<'_>,
    transition: &OwnedTransition,
) -> Result<()> {
    let stage = root.stage_cell().borrow();
    check(
        stage.header.phase == Phase::Config
            && !stage.header.capture_started
            && stage.header.new_unit_namespace.is_none(),
    )?;
    check(
        transition.role() == ManagedRole::BaseUnit
            && transition.epoch() == &transaction_epoch(&stage)?,
    )?;
    let previous = forward_history(&stage)?;
    check(
        previous.len() == 2
            && previous.iter().all(|r| r.role() != ManagedRole::BaseUnit)
            && previous
                .iter()
                .any(|r| r.role() == ManagedRole::Environment)
            && previous.iter().any(|r| r.role() == ManagedRole::Dropins)
            && stage.header.unit_pending.as_deref()
                == Some(Path::new("receipts/unit-target/base-unit/intent.json")),
    )?;
    authenticate_forward(&stage, transition)?;
    drop(stage);
    verify_policy_bodies(root)
}
pub(super) fn authenticate_complete_published_policy(
    root: &super::store_context::RootContext<'_>,
    transitions: &[OwnedTransition],
) -> Result<()> {
    let mut supplied = BTreeMap::new();
    for transition in transitions {
        check(supplied.insert(transition.role(), transition).is_none())?;
    }
    check(supplied.len() == 3)?;
    let stage = root.stage_cell().borrow();
    let actual = forward_history(&stage)?;
    if actual.len() == 2 {
        for transition in &actual {
            check(
                supplied
                    .get(&transition.role())
                    .is_some_and(|t| *t == transition),
            )?;
        }
        let candidate = *supplied.get(&ManagedRole::BaseUnit).ok_or_else(refuse)?;
        drop(stage);
        root.admit_final_base_publication(candidate).map_err(fail)?;
        validate_final_base_publication(root, candidate)
    } else {
        check(actual.len() == 3)?;
        if stage.header.unit_pending.as_deref() == Some(Path::new(RELOAD_INTENT)) {
            admit_reload_intent(&stage)?;
        } else {
            check(stage.header.unit_pending.is_none())?;
        }
        for transition in &actual {
            check(
                supplied
                    .get(&transition.role())
                    .is_some_and(|t| *t == transition),
            )?;
        }
        drop(stage);
        verify_committed_policy(root)
    }
}
pub(super) fn expected_dropin_paths(stage: &StageGuard) -> Result<BTreeSet<PathBuf>> {
    Ok(recipe(stage)?
        .dropins
        .keys()
        .filter(|p| p.extension().is_some_and(|e| e == "conf"))
        .map(|p| ManagedRole::Dropins.fixed_path().join(p))
        .collect())
}
/// Forward publication includes two fixed singleton leaves and exactly one
/// Aegis-owned dropin tree. No daemon reload or native service activation occurs.
const RESTORED_MANAGER: &str = "receipts/unit-target/restored-manager.json";
const RESTORE_MANAGER_INTENT: &str = "receipts/unit-target/restore-manager-intent.json";
pub(super) fn admit_accepted_manager_restoration_entry(stage: &StageGuard) -> Result<()> {
    current(stage)?;
    check(
        matches!(
            stage.header.phase,
            Phase::Config | Phase::Metadata | Phase::Finalized
        ) && !stage.header.capture_started
            && stage.header.pending.is_none()
            && stage.header.new_unit_namespace.is_some(),
    )?;
    let accepted = sealed_reload_receipt(stage)?.ok_or_else(refuse)?;
    let namespace = super::unit_binding::read(stage, true)?;
    check(namespace.generation() == accepted.accepted_namespace().generation())?;
    stage
        .header
        .runtime_binding
        .as_ref()
        .ok_or_else(refuse)?
        .revalidate_local_generation()
        .map_err(fail)
}
pub(super) fn admit_accepted_manager_restoration(stage: &StageGuard) -> Result<()> {
    admit_accepted_manager_restoration_entry(stage)?;
    check(stage.header.unit_restored_manager.is_none())?;
    if let Some(path) = &stage.header.unit_pending {
        check(matches!(
            path.to_str(),
            Some(
                "receipts/unit-target/restore-manager-intent.json"
                    | "receipts/unit-target/base-unit/rollback-intent.json"
                    | "receipts/unit-target/environment/rollback-intent.json"
                    | "receipts/unit-target/dropins/restored/publication-intent.json"
                    | "receipts/unit-target/dropins/restored/withdrawal-intent.json"
            )
        ))?;
        let _ = bound(stage, path)?;
    }
    Ok(())
}
pub(super) fn authenticate_restoration_manager_epoch(
    root: &super::store_context::RootContext<'_>,
) -> Result<namespace::RestorationManagerEpoch> {
    root.admit_accepted_manager_restoration().map_err(fail)?;
    let context = UnitContext {
        root,
        purpose: Purpose::Restore,
    };
    let stage = root.stage_cell().borrow();
    let original = super::unit_binding::read(&stage, false)?;
    let forward = forward_history(&stage)?;
    let restored = restoration_history(&stage)?;
    drop(stage);
    namespace::RestorationManagerEpoch::reopen(
        &original,
        &forward,
        &restored,
        &context,
        context.lock().map_err(fail)?,
    )
    .map_err(fail)
}
pub(super) fn revalidate_restoration_manager_epoch(
    root: &super::store_context::RootContext<'_>,
    epoch: &namespace::RestorationManagerEpoch,
) -> Result<()> {
    root.admit_accepted_manager_restoration().map_err(fail)?;
    let context = UnitContext {
        root,
        purpose: Purpose::Restore,
    };
    epoch
        .revalidate(&context, context.lock().map_err(fail)?)
        .map_err(fail)
}
pub(super) fn authenticate_complete_restored_policy(
    root: &super::store_context::RootContext<'_>,
) -> Result<()> {
    let context = UnitContext {
        root,
        purpose: Purpose::Restore,
    };
    let stage = root.stage_cell().borrow();
    current(&stage)?;
    let original = super::unit_binding::read(&stage, false)?;
    let forward = forward_history(&stage)?;
    let restored = restoration_history(&stage)?;
    check(forward.len() == 3 && restored.len() == 3)?;
    drop(stage);
    // Every restoration authentication reopens its protected actual receipt and
    // validates original/retired inode correspondence, not historical digest alone.
    for record in &restored {
        namespace::RestorationAuthority::authenticate_owned_restoration(&context, record)
            .map_err(fail)?;
    }
    let accepted = sealed_reload_receipt(&root.stage_cell().borrow())?.ok_or_else(refuse)?;
    accepted
        .validate_namespace_binding(
            &original,
            &forward,
            transaction_epoch(&root.stage_cell().borrow())?,
        )
        .map_err(fail)
}
pub(super) fn admit_manager_restore_reload(
    root: &super::store_context::RootContext<'_>,
) -> Result<()> {
    root.admit_accepted_manager_restoration().map_err(fail)?;
    let stage = root.stage_cell().borrow();
    current(&stage)?;
    check(
        stage.header.unit_pending.as_deref() == Some(Path::new(RESTORE_MANAGER_INTENT))
            && stage.header.unit_restored_manager.is_none(),
    )?;
    let actual: (String, [u8; 32], String) = read(
        &stage,
        Path::new(RESTORE_MANAGER_INTENT),
        ManagedRole::BaseUnit,
    )?;
    let accepted = sealed_reload_receipt(&stage)?.ok_or_else(refuse)?;
    check(
        actual.0 == "aegis-manager-restoration-attempt-v1"
            && actual.1 == transaction_epoch(&stage)?
            && actual.2 == accepted.generation(),
    )
}
fn validate_restored_manager_candidate(
    root: &super::store_context::RootContext<'_>,
    receipt: &crate::profile_auto_stopped_service::RestoredManagerReceipt,
) -> Result<()> {
    let stage = root.stage_cell().borrow();
    current(&stage)?;
    let accepted = sealed_reload_receipt(&stage)?.ok_or_else(refuse)?;
    let original = super::unit_binding::read(&stage, false)?;
    let forward = forward_history(&stage)?;
    let restored = restoration_history(&stage)?;
    receipt
        .validate_source_binding(
            &original,
            &accepted,
            &forward,
            &restored,
            transaction_epoch(&stage)?,
        )
        .map_err(fail)?;
    receipt
        .validate_current_source(
            &crate::profile_auto_stopped_service::StopAuthority::epoch(root).map_err(fail)?,
        )
        .map_err(fail)?;
    drop(stage);
    let context = UnitContext {
        root,
        purpose: Purpose::Restore,
    };
    namespace::validate_restored_manager_namespace(
        receipt.restored_namespace(),
        &original,
        &forward,
        &restored,
        &context,
    )
    .map_err(fail)?;
    crate::profile_auto_stopped_service::admit_restored_manager_readback(root, receipt)
        .map_err(fail)
}
fn converge_restored_manager_receipt(root: &super::store_context::RootContext<'_>) -> Result<()> {
    admit_manager_restore_reload(root)?;
    let stage = root.stage_cell().borrow();
    // Durable receipt-before-Header may leave the exact protected envelope
    // outside unit_records. Only this fixed pending native operation admits it,
    // and all actual namespace/old actor checks run before pointer publication.
    let bytes = stage.store.read(Path::new(RESTORED_MANAGER))?;
    check(bytes.len() <= LIMIT)?;
    if let Some(hash) = stage.header.unit_records.get(Path::new(RESTORED_MANAGER)) {
        check(hash == &digest(&bytes))?;
    }
    let value: Sealed<crate::profile_auto_stopped_service::RestoredManagerReceipt> =
        serde_json::from_slice(&bytes).map_err(fail)?;
    check(
        value.schema == 1
            && value.nonce == stage.header.transaction_nonce
            && value.input_generation == stage.header.input_generation
            && value.planned_generation == stage.header.planned_generation
            && value.role == ManagedRole::BaseUnit
            && value.epoch == transaction_epoch(&stage)?,
    )?;
    drop(stage);
    validate_restored_manager_candidate(root, &value.body)?;
    let mut stage = root.stage_cell().borrow_mut();
    current(&stage)?;
    check(stage.store.read(Path::new(RESTORED_MANAGER))?.as_slice() == bytes.as_slice())?;
    stage
        .header
        .unit_records
        .insert(RESTORED_MANAGER.into(), digest(&bytes));
    stage.header.unit_restored_manager = Some(RESTORED_MANAGER.into());
    stage.header.unit_pending = None;
    stage.persist_header()
}
pub(super) fn sealed_restored_manager_receipt(
    root: &super::store_context::RootContext<'_>,
) -> Result<crate::profile_auto_stopped_service::RestoredManagerReceipt> {
    let stage = root.stage_cell().borrow();
    current(&stage)?;
    check(stage.header.unit_restored_manager.as_deref() == Some(Path::new(RESTORED_MANAGER)))?;
    let receipt: crate::profile_auto_stopped_service::RestoredManagerReceipt =
        read(&stage, Path::new(RESTORED_MANAGER), ManagedRole::BaseUnit)?;
    let accepted = sealed_reload_receipt(&stage)?.ok_or_else(refuse)?;
    let original = super::unit_binding::read(&stage, false)?;
    let forward = forward_history(&stage)?;
    let restored = restoration_history(&stage)?;
    receipt
        .validate_source_binding(
            &original,
            &accepted,
            &forward,
            &restored,
            transaction_epoch(&stage)?,
        )
        .map_err(fail)?;
    receipt
        .validate_current_source(
            &crate::profile_auto_stopped_service::StopAuthority::epoch(root).map_err(fail)?,
        )
        .map_err(fail)?;
    drop(stage);
    let context = UnitContext {
        root,
        purpose: Purpose::Restore,
    };
    namespace::validate_restored_manager_namespace(
        receipt.restored_namespace(),
        &original,
        &forward,
        &restored,
        &context,
    )
    .map_err(fail)?;
    Ok(receipt)
}
pub(super) fn authenticate_restored_manager_receipt(
    root: &super::store_context::RootContext<'_>,
    receipt: &crate::profile_auto_stopped_service::RestoredManagerReceipt,
) -> Result<()> {
    let actual = sealed_restored_manager_receipt(root)?;
    check(serde_json::to_vec(&actual).map_err(fail)? == serde_json::to_vec(receipt).map_err(fail)?)
}
/// Exact absence of the completion leaf, checked through the retained protected
/// Store descriptor. Any leaf (including a symlink or directory) refuses. Missing
/// parent directories are not evidence of a prepared manager restoration.
fn manager_completion_absent(store: &super::durable::Store) -> Result<()> {
    store.revalidate()?;
    let journal = store.sub_store(Path::new("receipts/unit-target"), false)?;
    let held = journal.duplicate_root()?;
    let leaf = CString::new("restored-manager.json").map_err(fail)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            held.as_raw_fd(),
            leaf.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    let absent =
        result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT);
    journal.revalidate()?;
    store.revalidate()?;
    check(absent)
}
fn persist_manager_restore_attempt(root: &super::store_context::RootContext<'_>) -> Result<()> {
    root.admit_accepted_manager_restoration().map_err(fail)?;
    authenticate_complete_restored_policy(root)?;
    let mut stage = root.stage_cell().borrow_mut();
    current(&stage)?;
    check(
        stage.header.unit_pending.is_none()
            && stage.header.unit_restored_manager.is_none()
            && !stage
                .header
                .unit_records
                .contains_key(Path::new(RESTORED_MANAGER)),
    )?;
    manager_completion_absent(&stage.store)?;
    let accepted = sealed_reload_receipt(&stage)?.ok_or_else(refuse)?;
    let value = (
        "aegis-manager-restoration-attempt-v1".to_owned(),
        transaction_epoch(&stage)?,
        accepted.generation().to_owned(),
    );
    // write() accepts an existing record only when its protected hash and
    // entire sealed envelope equal this actual accepted generation. A crash
    // after write() committed that hash but before the selector committed
    // cannot have reached the native command: its admission requires the
    // durable selector. Unbound files and foreign envelopes still refuse.
    write(
        &mut stage,
        Path::new(RESTORE_MANAGER_INTENT),
        ManagedRole::BaseUnit,
        &value,
    )?;
    stage.header.unit_pending = Some(RESTORE_MANAGER_INTENT.into());
    stage.persist_header()
}
pub(super) fn restore_manager_and_accept(
    root: &super::store_context::RootContext<'_>,
) -> Result<()> {
    {
        let stage = root.stage_cell().borrow();
        current(&stage)?;
        if stage.header.unit_restored_manager.is_some() {
            drop(stage);
            let receipt = sealed_restored_manager_receipt(root)?;
            let lock = crate::profile_auto_stopped_service::StopAuthority::install_lock(root)
                .map_err(fail)?;
            namespace::UnitNamespaceSnapshot::reopen(receipt.restored_namespace(), lock)
                .and_then(|s| s.revalidate(lock))
                .map_err(fail)?;
            return Ok(());
        }
        if stage.header.unit_pending.as_deref() == Some(Path::new(RESTORE_MANAGER_INTENT)) {
            drop(stage);
            // A missing receipt preserves the ambiguous attempt and refuses;
            // convergence never executes the native command a second time.
            return converge_restored_manager_receipt(root);
        }
        check(
            stage.header.unit_pending.is_none()
                && !stage
                    .header
                    .unit_records
                    .contains_key(Path::new(RESTORED_MANAGER)),
        )?;
    }
    authenticate_complete_restored_policy(root)?;
    crate::profile_auto_stopped_service::execute_accepted_manager_stopped(root, || {
        persist_manager_restore_attempt(root)
            .map_err(|_| "protected manager intent preparation refused")
    })
    .map_err(fail)?;
    let receipt =
        crate::profile_auto_stopped_service::restore_service_manager(root).map_err(fail)?;
    write(
        &mut root.stage_cell().borrow_mut(),
        Path::new(RESTORED_MANAGER),
        ManagedRole::BaseUnit,
        &receipt,
    )?;
    converge_restored_manager_receipt(root)
}
fn pending_singleton(
    root: &super::store_context::RootContext<'_>,
) -> Result<(policy::LeafRole, bool)> {
    let stage = root.stage_cell().borrow();
    current(&stage)?;
    check(
        stage.header.phase == Phase::Config
            && !stage.header.capture_started
            && stage.header.new_unit_namespace.is_none(),
    )?;
    let path = stage.header.unit_pending.as_ref().ok_or_else(refuse)?;
    for role in [policy::LeafRole::BaseUnit, policy::LeafRole::Environment] {
        let prefix = format!("receipts/unit-target/{}/", key(singleton(role)));
        if path == &PathBuf::from(format!("{prefix}intent.json")) {
            return Ok((role, false));
        }
        if path == &PathBuf::from(format!("{prefix}rollback-intent.json")) {
            return Ok((role, true));
        }
    }
    Err(refuse()) // dropin and reload require their separate actual capabilities
}
pub(super) fn authenticate_pending_namespace(
    root: &super::store_context::RootContext<'_>,
) -> Result<namespace::PendingSingletonNamespaceView> {
    let (role, restore) = pending_singleton(root)?;
    let context = UnitContext {
        root,
        purpose: if restore {
            Purpose::Restore
        } else {
            Purpose::Publish
        },
    };
    let proof = if restore {
        let stage = root.stage_cell().borrow();
        let path = stage.header.unit_pending.as_ref().ok_or_else(refuse)?;
        let (r, e): (policy::Receipt, [u8; 32]) = read(&stage, path, singleton(role))?;
        drop(stage);
        policy::pending_restore_readback(&context, &r, &e).map_err(fail)?
    } else {
        let stage = root.stage_cell().borrow();
        let path = stage.header.unit_pending.as_ref().ok_or_else(refuse)?;
        let i: policy::Intent = read(&stage, path, singleton(role))?;
        drop(stage);
        policy::pending_publish_readback(&context, &i).map_err(fail)?
    };
    let stage = root.stage_cell().borrow();
    let original = super::unit_binding::read(&stage, false)?;
    let forward = forward_history(&stage)?;
    let restored = restoration_history(&stage)?;
    drop(stage);
    namespace::PendingSingletonNamespaceView::reopen(
        &original,
        &forward,
        &restored,
        &context,
        proof,
        &context,
        context.lock().map_err(fail)?,
    )
    .map_err(fail)
}
pub(super) fn revalidate_pending_namespace(
    root: &super::store_context::RootContext<'_>,
    view: &namespace::PendingSingletonNamespaceView,
) -> Result<()> {
    let (_, restore) = pending_singleton(root)?;
    let context = UnitContext {
        root,
        purpose: if restore {
            Purpose::Restore
        } else {
            Purpose::Publish
        },
    };
    view.revalidate(&context, &context, context.lock().map_err(fail)?)
        .map_err(fail)
}
/// Actual singleton pending dispatch; caller invokes before deciding whether
/// any unit forward records exist. Unhandled dropin/reload refuses explicitly.
/// Ephemeral completion retains actual held target/stage descriptors from the
/// admitted pending source. No JSON/caller enum constructs this capability.
pub(super) struct PublicationRecoveryCompletion {
    proof: policy::PendingSingletonReadback,
    nonce: String,
    input_generation: String,
    planned_generation: String,
}
pub(super) fn validate_publication_recovery_completion(
    root: &super::store_context::RootContext<'_>,
    completion: &PublicationRecoveryCompletion,
    role: policy::LeafRole,
) -> Result<()> {
    let context = UnitContext {
        root,
        purpose: Purpose::Publish,
    };
    completion
        .proof
        .revalidate_recovered_publication(&context)
        .map_err(fail)?;
    let stage = root.stage_cell().borrow();
    current(&stage)?;
    check(
        completion.proof.role() == role
            && completion.nonce == stage.header.transaction_nonce
            && completion.input_generation == stage.header.input_generation
            && completion.planned_generation == stage.header.planned_generation,
    )?;
    match completion.proof.outcome() {
        policy::PendingSingletonOutcome::Completed => {
            let receipt = singleton_receipt(&stage, role)?;
            let leaf = stage
                .header
                .unit_forward_transitions
                .get(key(singleton(role)))
                .ok_or_else(refuse)?;
            let transition: OwnedTransition = read(&stage, leaf, singleton(role))?;
            authenticate_forward(&stage, &transition)?;
            check(
                transition.role() == singleton(role)
                    && transition.epoch() == &transaction_epoch(&stage)?
                    && receipt.publication_epoch() == transaction_epoch(&stage)?,
            )?;
            drop(stage);
            policy::verify(&context, &receipt).map_err(fail)?;
        }
        policy::PendingSingletonOutcome::NotApplied => {
            check(
                !stage
                    .header
                    .unit_role_records
                    .contains_key(key(singleton(role)))
                    && !stage
                        .header
                        .unit_forward_transitions
                        .contains_key(key(singleton(role))),
            )?;
            drop(stage);
        }
    }
    completion
        .proof
        .revalidate_recovered_publication(&context)
        .map_err(fail)
}
pub(super) fn recover_pending_policy(
    root: &super::store_context::RootContext<'_>,
) -> Result<Option<PublicationRecoveryCompletion>> {
    let (role, restore) = pending_singleton(root)?;
    let context = UnitContext {
        root,
        purpose: if restore {
            Purpose::Restore
        } else {
            Purpose::Publish
        },
    };
    if restore {
        let stage = root.stage_cell().borrow();
        let path = stage.header.unit_pending.as_ref().ok_or_else(refuse)?;
        let (r, e): (policy::Receipt, [u8; 32]) = read(&stage, path, singleton(role))?;
        drop(stage);
        let proof = policy::pending_restore_readback(&context, &r, &e).map_err(fail)?;
        let expected = proof.outcome();
        proof.revalidate(&context).map_err(fail)?;
        match (
            expected,
            policy::recover_pending_rollback(&context, &r, &e).map_err(fail)?,
        ) {
            (
                policy::PendingSingletonOutcome::Completed,
                policy::RollbackRecovery::Completed(restoration),
            ) => policy::verify_restoration(&context, &restoration).map_err(fail),
            (policy::PendingSingletonOutcome::NotApplied, policy::RollbackRecovery::NotApplied) => {
                policy::rollback(&context, &r).map_err(fail)?;
                Ok(())
            }
            _ => Err(refuse()),
        }
        .map(|()| None)
    } else {
        let stage = root.stage_cell().borrow();
        let path = stage.header.unit_pending.as_ref().ok_or_else(refuse)?;
        let i: policy::Intent = read(&stage, path, singleton(role))?;
        drop(stage);
        let proof = policy::pending_publish_readback(&context, &i).map_err(fail)?;
        let expected = proof.outcome();
        proof.revalidate(&context).map_err(fail)?;
        match (
            expected,
            policy::recover_pending_publish(&context, &i).map_err(fail)?,
        ) {
            (policy::PendingSingletonOutcome::Completed, policy::Recovery::Completed) => Ok(()),
            (policy::PendingSingletonOutcome::NotApplied, policy::Recovery::NotApplied) => root
                .unit_pending_recovery(|| {
                    let mut stage = root.stage_cell().borrow_mut();
                    admit_singleton_intent(&stage, &i).map_err(p_fail)?;
                    stage.header.unit_pending = None;
                    stage.persist_header().map_err(p_fail)
                })
                .map_err(fail),
            _ => Err(refuse()),
        }?;
        let stage = root.stage_cell().borrow();
        let completion = PublicationRecoveryCompletion {
            proof,
            nonce: stage.header.transaction_nonce.clone(),
            input_generation: stage.header.input_generation.clone(),
            planned_generation: stage.header.planned_generation.clone(),
        };
        drop(stage);
        validate_publication_recovery_completion(root, &completion, role)?;
        Ok(Some(completion))
    }
}
pub(super) fn publish_policy(root: &super::store_context::RootContext<'_>) -> Result<()> {
    {
        let stage = root.stage_cell().borrow();
        current(&stage)?;
        check(
            stage.header.phase == Phase::Config
                && !stage.header.capture_started
                && stage.header.unit_pending.is_none()
                && stage.header.unit_restorations.is_empty(),
        )?;
        let _ = recipe(&stage)?;
        super::receipt_store::verify_installed(&stage)?;
    }
    let context = UnitContext {
        root,
        purpose: Purpose::Publish,
    };
    {
        let role = policy::LeafRole::Environment;
        let stage = root.stage_cell().borrow();
        let complete = stage
            .header
            .unit_forward_transitions
            .contains_key(key(singleton(role)));
        drop(stage);
        if complete {
            let receipt = singleton_receipt(&root.stage_cell().borrow(), role)?;
            policy::verify(&context, &receipt).map_err(fail)?;
        } else {
            policy::publish(&context, role).map_err(fail)?;
        }
    }
    let stage = root.stage_cell().borrow();
    let complete = stage
        .header
        .unit_forward_transitions
        .contains_key("dropins");
    let accepted = recipe(&stage)?;
    drop(stage);
    if complete {
        let record = authenticated_dropin_record(&root.stage_cell().borrow(), false)?;
        let receipt = fs::reopen_own_receipt(
            &fs::Target::open(ManagedRole::Dropins.fixed_path()).map_err(fail)?,
            &record,
        )
        .map_err(fail)?;
        policy::verify_dropins(
            &context,
            &accepted.compiled(),
            &accepted.directories,
            &receipt,
        )
        .map_err(fail)?;
    } else {
        policy::publish_dropins(&context, &accepted.compiled(), &accepted.directories)
            .map_err(fail)?;
    }
    let stage = root.stage_cell().borrow();
    let complete = stage
        .header
        .unit_forward_transitions
        .contains_key("base-unit");
    drop(stage);
    if complete {
        let receipt = singleton_receipt(&root.stage_cell().borrow(), policy::LeafRole::BaseUnit)?;
        policy::verify(&context, &receipt).map_err(fail)?;
    } else {
        policy::publish(&context, policy::LeafRole::BaseUnit).map_err(fail)?;
    }
    verify_committed_policy(root)
}
pub(super) fn rollback_policy(root: &super::store_context::RootContext<'_>) -> Result<()> {
    {
        let stage = root.stage_cell().borrow();
        current(&stage)?;
        // Accepted manager restoration requires provider's separate authenticated
        // epoch. Until supplied, never retry old custody after a new-UID refusal.
        check(!stage.header.capture_started && stage.header.unit_pending.is_none())?;
        if stage.header.new_unit_namespace.is_some() {
            drop(stage);
            root.admit_accepted_manager_restoration().map_err(fail)?;
        } else {
            check(stage.header.phase == Phase::Config)?;
        }
    }
    let context = UnitContext {
        root,
        purpose: Purpose::Restore,
    };
    let stage = root.stage_cell().borrow();
    let dropins = stage
        .header
        .unit_forward_transitions
        .contains_key("dropins");
    let already = stage.header.unit_restorations.contains_key("dropins");
    drop(stage);
    if dropins && !already {
        let record = authenticated_dropin_record(&root.stage_cell().borrow(), false)?;
        let forward = fs::reopen_own_receipt(
            &fs::Target::open(ManagedRole::Dropins.fixed_path()).map_err(fail)?,
            &record,
        )
        .map_err(fail)?;
        policy::rollback_dropins(&context, &forward).map_err(fail)?;
    }
    for role in [policy::LeafRole::BaseUnit, policy::LeafRole::Environment] {
        let stage = root.stage_cell().borrow();
        let has_forward = stage
            .header
            .unit_forward_transitions
            .contains_key(key(singleton(role)));
        let already = stage
            .header
            .unit_restorations
            .contains_key(key(singleton(role)));
        drop(stage);
        if has_forward && !already {
            let forward = singleton_receipt(&root.stage_cell().borrow(), role)?;
            policy::rollback(&context, &forward).map_err(fail)?;
        }
    }
    let stage = root.stage_cell().borrow();
    check(restoration_history(&stage)?.len() == forward_history(&stage)?.len())
}

const RELOAD: &str = "receipts/unit-target/daemon-reload.json";
const RELOAD_INTENT: &str = "receipts/unit-target/reload-intent.json";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReloadIntent {
    policy_identity: String,
    forward_generations: BTreeMap<ManagedRole, String>,
}
fn admit_reload_intent(stage: &StageGuard) -> Result<()> {
    check(
        stage.header.phase == Phase::Config
            && !stage.header.capture_started
            && stage.header.unit_pending.as_deref() == Some(Path::new(RELOAD_INTENT)),
    )?;
    let intent: ReloadIntent = read(stage, Path::new(RELOAD_INTENT), ManagedRole::BaseUnit)?;
    let actual: BTreeMap<_, _> = forward_history(stage)?
        .iter()
        .map(|r| (r.role(), r.generation().to_owned()))
        .collect();
    check(
        actual.len() == 3
            && intent.forward_generations == actual
            && intent.policy_identity == policy_identity(stage)?,
    )
}
fn seal_reload_intent(stage: &mut StageGuard) -> Result<()> {
    check(
        stage.header.phase == Phase::Config
            && !stage.header.capture_started
            && stage.header.unit_pending.is_none()
            && !stage
                .header
                .unit_records
                .contains_key(Path::new(RELOAD_INTENT)),
    )?;
    let intent = ReloadIntent {
        policy_identity: policy_identity(stage)?,
        forward_generations: forward_history(stage)?
            .iter()
            .map(|r| (r.role(), r.generation().to_owned()))
            .collect(),
    };
    check(intent.forward_generations.len() == 3)?;
    write(
        stage,
        Path::new(RELOAD_INTENT),
        ManagedRole::BaseUnit,
        &intent,
    )?;
    stage.header.unit_pending = Some(RELOAD_INTENT.into());
    stage.persist_header()
}
pub(super) fn sealed_reload_receipt(
    stage: &StageGuard,
) -> Result<Option<crate::profile_auto_stopped_service::DaemonReloadReceipt>> {
    current(stage)?;
    if !stage.header.unit_records.contains_key(Path::new(RELOAD)) {
        return Ok(None);
    }
    let actual: crate::profile_auto_stopped_service::DaemonReloadReceipt =
        read(stage, Path::new(RELOAD), ManagedRole::BaseUnit)?;
    let original = super::unit_binding::read(stage, false)?;
    let records = forward_history(stage)?;
    actual
        .validate_namespace_binding(&original, &records, transaction_epoch(stage)?)
        .map_err(fail)?;
    let binding = stage.header.runtime_binding.as_ref().ok_or_else(refuse)?;
    binding.revalidate_local_generation().map_err(fail)?;
    check(
        actual.policy_identity() == policy_identity(stage)?
            && actual.runtime_identity() == (binding.identity().uid(), binding.identity().gid()),
    )?;
    Ok(Some(actual))
}
pub(super) fn authenticate_reload_receipt(
    stage: &StageGuard,
    actual: &crate::profile_auto_stopped_service::DaemonReloadReceipt,
) -> Result<()> {
    let recorded = sealed_reload_receipt(stage)?.ok_or_else(refuse)?;
    check(serde_json::to_vec(&recorded).map_err(fail)? == serde_json::to_vec(actual).map_err(fail)?)
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AcceptedNamespace {
    schema: u32,
    nonce: String,
    input_generation: String,
    planned_generation: String,
    namespace_generation: String,
    record: namespace::NamespaceRecord,
}
/// The only producer of prepared-new namespace here is the provider's actual
/// descriptor-pinned owned daemon-reload receipt. No capture/current fallback.
pub(super) fn reload_and_accept_policy(root: &super::store_context::RootContext<'_>) -> Result<()> {
    let recorded = (|| -> Result<_> {
        let stage = root.stage_cell().borrow();
        current(&stage)?;
        check(
            stage.header.phase == Phase::Config
                && !stage.header.capture_started
                && stage.header.unit_restorations.is_empty(),
        )?;
        let intent = stage
            .header
            .unit_records
            .contains_key(Path::new(RELOAD_INTENT));
        let receipt = stage.header.unit_records.contains_key(Path::new(RELOAD));
        Ok(if receipt {
            check(intent)?;
            if stage.header.new_unit_namespace.is_none() {
                admit_reload_intent(&stage)?;
            } else {
                check(stage.header.unit_pending.is_none())?;
            }
            sealed_reload_receipt(&stage)?
        } else {
            // An intent without an actual checked receipt is an ambiguous failed
            // attempt. Never replay the native command or infer it from manager.
            check(
                !intent
                    && stage.header.unit_pending.is_none()
                    && stage.header.new_unit_namespace.is_none(),
            )?;
            None
        })
    })()
    .map_err(|_| "reload_stage".to_owned())?;
    verify_committed_policy(root).map_err(|_| "reload_committed_policy".to_owned())?;
    let context = UnitContext {
        root,
        purpose: Purpose::Publish,
    };
    let receipt = match recorded {
        Some(actual) => {
            namespace::UnitNamespaceSnapshot::reopen(
                actual.accepted_namespace(),
                context
                    .lock()
                    .map_err(|_| "reload_recorded_namespace".to_owned())?,
            )
            .and_then(|s| s.revalidate(context.lock()?))
            .map_err(|_| "reload_recorded_namespace".to_owned())?;
            actual
        }
        None => {
            seal_reload_intent(&mut root.stage_cell().borrow_mut())
                .map_err(|_| "reload_intent".to_owned())?;
            crate::profile_auto_stopped_service::reload_service_policy(&context).map_err(
                |error| {
                    if crate::profile_auto_stopped_service::reload_failure_label(error) {
                        error.to_owned()
                    } else {
                        "reload_native_unknown".to_owned()
                    }
                },
            )?
        }
    };
    (|| -> Result<()> {
        let stage = root.stage_cell().borrow();
        receipt
            .validate_namespace_binding(
                &super::unit_binding::read(&stage, false)?,
                &forward_history(&stage)?,
                transaction_epoch(&stage)?,
            )
            .map_err(fail)?;
        check(receipt.policy_identity() == policy_identity(&stage)?)?;
        Ok(())
    })()
    .map_err(|_| "reload_receipt_validation".to_owned())?;
    // Seal the actual receipt before publishing its accepted namespace pointer.
    write(
        &mut root.stage_cell().borrow_mut(),
        Path::new(RELOAD),
        ManagedRole::BaseUnit,
        &receipt,
    )
    .map_err(|_| "reload_receipt_write".to_owned())?;
    (|| -> Result<()> {
        let mut stage = root.stage_cell().borrow_mut();
        authenticate_reload_receipt(&stage, &receipt)?;
        let record = AcceptedNamespace {
            schema: 1,
            nonce: stage.header.transaction_nonce.clone(),
            input_generation: stage.header.input_generation.clone(),
            planned_generation: stage.header.planned_generation.clone(),
            namespace_generation: receipt.accepted_namespace().generation().into(),
            record: receipt.accepted_namespace().clone(),
        };
        let bytes = serde_json::to_vec(&record).map_err(fail)?;
        check(bytes.len() <= 2 * 1024 * 1024)?;
        let leaf = Path::new("accepted/unit-target/namespace.json");
        if stage.header.new_unit_namespace.is_some() {
            check(
                stage.header.leaves.get(leaf) == Some(&digest(&bytes))
                    && stage.store.read(leaf)?.as_slice() == bytes.as_slice(),
            )?;
        } else {
            stage.store.write_new(leaf, &bytes)?;
            stage.header.leaves.insert(leaf.into(), digest(&bytes));
            stage.header.new_unit_namespace = Some(leaf.into());
        }
        stage.header.unit_pending = None;
        stage.persist_header()?;
        let admitted = super::unit_binding::read(&stage, true)?;
        check(admitted.generation() == receipt.accepted_namespace().generation())
    })()
    .map_err(|_| "reload_namespace_commit".to_owned())
}
/// Post-start admission authenticates the exact accepted policy, without
/// pretending a running actor is the stopped-service publication provider.
pub(super) fn verify_active_policy(
    root: &super::store_context::RootContext<'_>,
) -> Result<crate::profile_auto_stopped_service::DaemonReloadReceipt> {
    let context = UnitContext {
        root,
        purpose: Purpose::Publish,
    };
    context.lock()?.revalidate().map_err(fail)?;
    let receipt = {
        let stage = root.stage_cell().borrow();
        current(&stage)?;
        check(
            matches!(stage.header.phase, Phase::Metadata | Phase::Finalized)
                && stage.header.pending.is_none()
                && stage.header.unit_pending.is_none()
                && stage.header.new_unit_namespace.is_some(),
        )?;
        let receipt = sealed_reload_receipt(&stage)?.ok_or_else(refuse)?;
        let accepted = super::unit_binding::read(&stage, true)?;
        check(accepted.generation() == receipt.accepted_namespace().generation())?;
        namespace::UnitNamespaceSnapshot::reopen(&accepted, context.lock()?)
            .and_then(|snapshot| snapshot.revalidate(context.lock()?))
            .map_err(fail)?;
        super::receipt_store::verify_activation(&stage)?;
        receipt
    };
    verify_committed_policy(root)?;
    context.lock()?.revalidate().map_err(fail)?;
    Ok(receipt)
}

/// Mint the exact source-derived one-shot PID 1 property set only while the
/// original owner still holds the stopped-service and installation custody.
/// The protected recipe is bound to the accepted published unit generation;
/// callers cannot supply argv, paths, account, or lifecycle hooks here.
pub(super) fn transient_policy(
    root: &super::store_context::RootContext<'_>,
    lock: &InstallLock,
) -> Result<policy::TransientPolicy> {
    lock.revalidate().map_err(fail)?;
    let _ = verify_active_policy(root)?;
    let minted = {
        let stage = root.stage_cell().borrow();
        recipe(&stage)?.transient
    };
    lock.revalidate().map_err(fail)?;
    Ok(minted)
}

/// Reopen the accepted unit policy for an exact owned StopUnit after a runtime
/// projection fault. A config projection may have left its own pending intent;
/// that intent must never authorize another forward effect, but it must not
/// strand the already started private unit. Unit publication pending remains
/// refused because it would make the accepted PID1 policy ambiguous.
pub(super) fn verify_inverse_policy(
    root: &super::store_context::RootContext<'_>,
) -> Result<crate::profile_auto_stopped_service::DaemonReloadReceipt> {
    let context = UnitContext {
        root,
        purpose: Purpose::Publish,
    };
    context.lock()?.revalidate().map_err(fail)?;
    let receipt = {
        let stage = root.stage_cell().borrow();
        current(&stage)?;
        check(
            matches!(stage.header.phase, Phase::Metadata | Phase::Finalized)
                && stage.header.unit_pending.is_none()
                && stage.header.new_unit_namespace.is_some(),
        )?;
        let receipt = sealed_reload_receipt(&stage)?.ok_or_else(refuse)?;
        let accepted = super::unit_binding::read(&stage, true)?;
        check(accepted.generation() == receipt.accepted_namespace().generation())?;
        namespace::UnitNamespaceSnapshot::reopen(&accepted, context.lock()?)
            .and_then(|snapshot| snapshot.revalidate(context.lock()?))
            .map_err(fail)?;
        // Activation admission rejects a pending runtime projection. The
        // inverse still needs the protected installed source while that exact
        // projection intent remains on disk.
        super::receipt_store::verify_installed(&stage)?;
        receipt
    };
    verify_committed_policy(root)?;
    context.lock()?.revalidate().map_err(fail)?;
    Ok(receipt)
}

pub(super) fn validate_accepted_policy_epoch(
    root: &super::store_context::RootContext<'_>,
    operation: crate::profile_auto_stopped_service::PreparedOperation,
) -> Result<()> {
    use crate::profile_auto_stopped_service::PreparedOperation;
    // One read-only PID1 query burst for this whole epoch validation (S7).
    let _burst = crate::profile_auto_stopped_service::pid1::QueryBurst::begin();
    let context = UnitContext {
        root,
        purpose: Purpose::Publish,
    };
    context.lock()?.revalidate().map_err(fail)?;
    {
        let stage = root.stage_cell().borrow();
        current(&stage)?;
        check(!stage.header.capture_started && stage.header.unit_pending.is_none())?;
        match operation {
            PreparedOperation::PublishMetadata => check(matches!(
                stage.header.phase,
                Phase::Config | Phase::Metadata
            ))?,
            PreparedOperation::BeforeActivation => check(stage.header.phase == Phase::Metadata)?,
            // Restoration after accepted manager needs a separate restored
            // manager epoch; never treat the forward receipt as that proof.
            PreparedOperation::StaticRollback => return Err(refuse()),
        }
        let receipt = sealed_reload_receipt(&stage)?.ok_or_else(refuse)?;
        let accepted = super::unit_binding::read(&stage, true)?;
        check(accepted.generation() == receipt.accepted_namespace().generation())?;
        namespace::UnitNamespaceSnapshot::reopen(&accepted, context.lock()?)
            .and_then(|s| s.revalidate(context.lock()?))
            .map_err(fail)?;
        if operation == PreparedOperation::BeforeActivation {
            super::receipt_store::verify_activation(&stage)?;
        } else {
            super::receipt_store::verify_installed(&stage)?;
        }
    }
    verify_committed_policy(root)?;
    context.lock()?.revalidate().map_err(fail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn first_arm_relay_binding_requires_exact_numeric_ipv4_set() {
        let mut settings = aegis_core::Settings::default();
        settings.relay.server = "192.0.2.11:443".into();
        settings.relay.endpoints = vec![
            aegis_core::RelayEndpointSettings {
                server: "192.0.2.11:443".into(),
                server_name: "relay.example".into(),
                masque_server: None,
                masque_server_name: None,
            },
            aegis_core::RelayEndpointSettings {
                server: "198.51.100.17:8443".into(),
                server_name: "relay.example".into(),
                masque_server: None,
                masque_server_name: None,
            },
        ];
        assert_eq!(
            first_arm_relays(&settings).unwrap(),
            vec!["192.0.2.11:443", "198.51.100.17:8443"]
        );
        settings.relay.endpoints[1].server = "relay.example:8443".into();
        assert!(first_arm_relays(&settings).is_err());
        settings.relay.endpoints[1].server = "127.0.0.1:8443".into();
        assert!(first_arm_relays(&settings).is_err());
    }
    fn temporary() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "aegis-unit-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    fn directory(path: &Path) -> OwnedFd {
        owned(unsafe {
            libc::open(
                CString::new(path.as_os_str().as_encoded_bytes())
                    .unwrap()
                    .as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })
        .unwrap()
    }
    #[test]
    #[ignore = "Requires disposable root Linux; only private fixture directories"]
    fn actual_same_mode_replacement_cannot_reuse_held_parent_identity() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = temporary();
        let target = root.join("parent");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let held = directory(&target);
        let before = parent_metadata(&held).unwrap();
        fs::rename(&target, root.join("retained")).unwrap();
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement = directory(&target);
        assert!(parent_metadata(&replacement).unwrap() != before);
        assert!(parent_metadata(&held).unwrap() == before);
        drop(replacement);
        drop(held);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    #[ignore = "Requires disposable root Linux; only private fixture directory"]
    fn actual_group_writable_stage_cannot_retain_parent_admission() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = temporary();
        let held = directory(&root);
        assert!(parent_metadata(&held).is_ok());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(parent_metadata(&held).is_err());
        drop(held);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn actual_manager_preparation_completion_fence_requires_absent_fixed_leaf() {
        let root = temporary();
        let uid = unsafe { libc::geteuid() };
        let store = super::super::durable::Store::create(&root, uid).unwrap();
        // Parent absence is not a completed, protected prepared journal.
        assert!(manager_completion_absent(&store).is_err());
        store
            .write_new(
                Path::new(RESTORE_MANAGER_INTENT),
                b"protected preparation; no native operation performed",
            )
            .unwrap();
        assert!(manager_completion_absent(&store).is_ok());
        let completed = store.path().join(RESTORED_MANAGER);
        store
            .write_new(Path::new(RESTORED_MANAGER), b"durable completion leaf")
            .unwrap();
        assert!(manager_completion_absent(&store).is_err());
        std::fs::remove_file(&completed).unwrap();
        assert!(manager_completion_absent(&store).is_ok());
        std::os::unix::fs::symlink("absent-victim", &completed).unwrap();
        assert!(manager_completion_absent(&store).is_err());
        std::fs::remove_file(&completed).unwrap();
        std::fs::create_dir(&completed).unwrap();
        assert!(manager_completion_absent(&store).is_err());
        std::fs::remove_dir(&completed).unwrap();
        assert!(manager_completion_absent(&store).is_ok());
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
        // Genuine Store/retained-FD syscall fence only. The byte fixture grants
        // no typed intent, Header, actor, systemd, or installed-lifecycle proof.
    }
}
