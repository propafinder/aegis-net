//! Durable history for a successfully finalized V2 generation.
//!
//! The sealed report is evidence of the old boot only. Reopening this file
//! never grants an owner lease, StartUnit, or permission to reuse a /run stage.
#![cfg(target_os = "linux")]

use super::{
    digest, recovery_absent, recovery_chain, recovery_directory, recovery_file_hash,
    recovery_open_at, recovery_stat, refuse, Result,
};
use crate::profile_auto_stopped_service::InstallLock;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::fd::AsRawFd,
    path::Path,
};

pub(super) struct SuccessorHistory {
    pub(super) active: serde_json::Value,
    pub(super) stopped: serde_json::Value,
    pub(super) stage_path: String,
    active_bytes: Vec<u8>,
    stopped_bytes: Vec<u8>,
    pointer_receipt_bytes: Vec<u8>,
    pointer_receipt_sha256: String,
    intent_bytes: Option<Vec<u8>>,
    prior_successor_intent_sha256: Option<String>,
}

/// Exact predecessor artifacts. A3's observed digest still requires an
/// independent artifact receipt before a B build may be admitted.
const COLD_A2_CANDIDATE_SHA256: &str =
    "f3fc01961b8cdca54553c0027cc3828a77b3043ee9f84308b89ed58b88bbc674";
const COLD_A3_CANDIDATE_SHA256: &str =
    "9d65862e9bcc96e0127e349cc54e2e2822425744ee0a6118b22284a2e9161f96";

pub(super) struct AuthenticatedColdArchiveTarget {
    pub(super) public_root: String,
    pub(super) candidate_sha256: String,
}

fn cold_archive_target_from_intent(raw: &[u8]) -> Result<AuthenticatedColdArchiveTarget> {
    let intent: SuccessorIntent = serde_json::from_slice(raw).map_err(|_| refuse())?;
    successor_shape(&intent)?;
    // Both branches are exact artifacts; caller must independently admit
    // this observed A3 build receipt before enabling a B release.
    if intent.next_candidate_sha256 != COLD_A2_CANDIDATE_SHA256
        && intent.next_candidate_sha256 != COLD_A3_CANDIDATE_SHA256
    {
        return Err(refuse());
    }
    Ok(AuthenticatedColdArchiveTarget {
        public_root: intent.next_public_payload_root,
        candidate_sha256: intent.next_candidate_sha256,
    })
}

/// This consumes only intent bytes already authenticated by successor_history.
pub(super) fn admit_cold_archive_target(
    history: &SuccessorHistory,
) -> Result<AuthenticatedColdArchiveTarget> {
    cold_archive_target_from_intent(history.intent_bytes.as_ref().ok_or_else(refuse)?)
}

/// A completed archive can be inspected after A2 has replaced installed B.
/// Rebind old B to its retained release and this executing B ELF without
/// requiring the now-obsolete installed B pathname.
pub(super) fn verify_old_retained_source(history: &SuccessorHistory) -> Result<()> {
    let report = &history.stopped;
    let root = Path::new(
        report["input"]["public_payload_root"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let candidate = Path::new(
        report["input"]["candidate_binary"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let (candidate_sha, installer_sha) = verified_retained_source(root, candidate)?;
    if report["input"]["candidate_sha256"] != candidate_sha
        || installer_sha != digest(include_bytes!("../../../install.sh"))
    {
        return Err(refuse());
    }
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if recovery_file_hash(running.as_raw_fd(), 256 * 1024 * 1024)?.1 != candidate_sha {
        return Err(refuse());
    }
    Ok(())
}

pub(super) fn cold_archive_old_b_coordinator_sha(history: &SuccessorHistory) -> Result<String> {
    let prior_sha = history
        .prior_successor_intent_sha256
        .as_deref()
        .ok_or_else(refuse)?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let archived = history_dir(control.as_raw_fd(), false)?;
    let raw = read_archived(archived.as_raw_fd(), "intent", prior_sha)?;
    let prior: SuccessorIntent = serde_json::from_slice(&raw).map_err(|_| refuse())?;
    successor_shape(&prior)?;
    let old_root = history.stopped["input"]["public_payload_root"]
        .as_str()
        .ok_or_else(refuse)?;
    let old_candidate = history.stopped["input"]["candidate_sha256"]
        .as_str()
        .ok_or_else(refuse)?;
    if prior.next_public_payload_root != old_root
        || prior.next_candidate_sha256 != old_candidate
        || prior.next_sums_sha256.as_deref().is_none()
    {
        return Err(refuse());
    }
    let sums = cold_sums_map(
        Path::new(old_root),
        old_candidate,
        prior.next_sums_sha256.as_deref(),
    )?;
    sums.get("scripts/lib/aegis_installer_auto_v2.py")
        .filter(|sha| exact_hex(sha))
        .cloned()
        .ok_or_else(refuse)
}

pub(super) fn cold_archive_package_sources(
    history: &SuccessorHistory,
    pending: &serde_json::Value,
    context: &serde_json::Value,
    package: &serde_json::Value,
) -> Result<()> {
    let old_root = history.stopped["input"]["public_payload_root"]
        .as_str()
        .ok_or_else(refuse)?;
    let old_candidate = history.stopped["input"]["candidate_sha256"]
        .as_str()
        .ok_or_else(refuse)?;
    let target = admit_cold_archive_target(history)?;
    let old_install = context["old_install_sha256"].as_str().ok_or_else(refuse)?;
    let new_package = pending["package_sha256"].as_str().ok_or_else(refuse)?;
    let sums = pending["next_sums_sha256"].as_str().ok_or_else(refuse)?;
    cold_package_sources_bound(
        package,
        (old_root, &target.public_root),
        (old_candidate, &target.candidate_sha256),
        old_install,
        new_package,
        sums,
    )
}

pub(super) struct ColdRetiredHistory {
    pub(super) old_boot_id: String,
    pub(super) current_boot_id: String,
    pub(super) old_active_sha256: String,
    pub(super) old_stopped_sha256: String,
    pub(super) successor_intent_sha256: String,
    pub(super) old_install_sha256: String,
    pub(super) old_source_sha256: String,
    pub(super) old_context_sha256: Option<String>,
    pub(super) cold_old_context_sha256: Option<String>,
    pub(super) cold_context_state: &'static str,
    pub(super) old_observer_archive_sha256: Option<String>,
    pub(super) migration_state: &'static str,
    pub(super) context_state: &'static str,
    pub(super) new_candidate_sha256: String,
    pub(super) new_package_sha256: String,
    pub(super) bundle_manifest_sha256: String,
    pub(super) sums_sha256: String,
    pub(super) retained_root: String,
    pub(super) migration_record_sha256: Option<String>,
    pub(super) guardian_source_sha256: String,
    pub(super) observer_source_sha256: String,
    pub(super) package_helper_sha256: String,
    pub(super) site_helper_sha256: String,
    pub(super) old_root: String,
    pub(super) old_candidate_sha256: String,
    pub(super) guardian_rotation_intent_sha256: String,
    pub(super) guardian_rotation_denied_sha256: String,
    pub(super) guardian_rotation_retired_sha256: String,
}

pub(super) struct ColdBootstrapSource {
    pub(super) candidate_sha256: String,
    pub(super) coordinator_sha256: String,
    pub(super) successor_intent_sha256: String,
    pub(super) bundle_manifest_sha256: String,
    pub(super) sums_sha256: String,
}

pub(super) struct ColdStaleSource {
    pub(super) bootstrap: ColdBootstrapSource,
    pub(super) retained_root: String,
    pub(super) original_intent_sha256: String,
    pub(super) original_state: &'static str,
    pub(super) prior_intent_sha256: String,
    pub(super) prior_boot_id: String,
    pub(super) old_root: String,
    pub(super) old_candidate_sha256: String,
    pub(super) old_install_sha256: String,
    pub(super) new_package_sha256: String,
    pub(super) old_context_sha256: Option<String>,
    pub(super) selected_manager: String,
    pub(super) guard_shell_sha256: String,
    pub(super) current_head_sha256: Option<String>,
    pub(super) current_intent_sha256: Option<String>,
    pub(super) barrier_sha256: Option<String>,
    pub(super) guardian_rotation_intent_sha256: String,
    pub(super) guardian_source_sha256: String,
    pub(super) package_helper_sha256: String,
    pub(super) site_helper_sha256: String,
    pub(super) prior_pointer_state: &'static str,
}

const LEAF: &str = "generation.json";
const STOPPED_LEAF: &str = "generation-stopped.json";
const RECOVERY_LEAF: &str = "generation-recovery-stopped.json";
const SUCCESSOR_LEAF: &str = "generation-successor-current.json";
const BOOT_SUCCESSOR_LEAF: &str = "generation-boot-successor-current.json";
const COLD_FIRST_ARM_LEAF: &str = "generation-cold-first-arm-current.json";
const PASSIVE_RETIRE_INTENT_LEAF: &str = "passive-successor-retirement-intent.json";
const PASSIVE_RETIRED_LEAF: &str = "passive-successor-retired.json";
const PASSIVE_OLD_STOPPED_LEAF: &str = "generation-passive-old-stopped.json";
const PASSIVE_PREINST_LEAF: &str = "passive-package-preinst.json";
const PASSIVE_ADVANCE_LEAF: &str = "generation-passive-advance.json";
const HISTORY_DIR: &str = "generation-history";
const MAX_REPORT: usize = 128 * 1024;
const MAX_SEAL: usize = MAX_REPORT + 8192;
const MAX_SNAPSHOT_ARCHIVE: usize = 1024 * 1024;

pub(super) struct PassiveTransitionEvidence {
    intent_bytes: Vec<u8>,
    intent: SuccessorIntent,
    old_active: GenerationSeal,
    retire_intent_bytes: Vec<u8>,
    retired_bytes: Vec<u8>,
    stopped_record_bytes: Vec<u8>,
    preinst_bytes: Vec<u8>,
    old_install_sha256: String,
    current_active: Option<GenerationSeal>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GenerationSeal {
    schema: String,
    report_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot_snapshot_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor_intent_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor_boot_intent_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor_cold_intent_sha256: Option<String>,
    report: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoppedGenerationSeal {
    schema: String,
    active_seal_sha256: String,
    stopped_report_sha256: String,
    report: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UnsealedStoppedRecoverySeal {
    schema: String,
    active_seal_present: bool,
    report_sha256: String,
    report: serde_json::Value,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SuccessorIntent {
    schema: String,
    kind: String,
    old_active_sha256: String,
    old_stopped_sha256: String,
    old_pointer_receipt_sha256: String,
    old_stage_path: String,
    old_boot_id: String,
    next_public_payload_root: String,
    next_candidate_binary: String,
    next_candidate_sha256: String,
    next_installer_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_bundle_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_sums_sha256: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootSuccessorIntent {
    schema: String,
    old_active_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    old_stopped_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    old_pointer_receipt_sha256: Option<String>,
    old_snapshot_sha256: String,
    old_pointer_sha256: String,
    verified_boot_sha256: String,
    old_boot_id: String,
    new_boot_id: String,
    public_payload_root: String,
    candidate_binary: String,
    candidate_sha256: String,
    installer_sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdFirstArmIntent {
    schema: String,
    old_active_sha256: String,
    old_stopped_sha256: String,
    successor_intent_sha256: String,
    cold_prebind_sha256: String,
    transition_ready_sha256: String,
    old_boot_id: String,
    current_boot_id: String,
    public_payload_root: String,
    candidate_binary: String,
    candidate_sha256: String,
    installer_sha256: String,
}

fn boot_successor_shape(intent: &BootSuccessorIntent) -> Result<()> {
    let root = Path::new(&intent.public_payload_root);
    let candidate = Path::new(&intent.candidate_binary);
    let root_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(refuse)?;
    if intent.schema != "aegis_auto_v2_boot_successor_v1"
        || intent
            .old_stopped_sha256
            .as_deref()
            .is_some_and(|sha| !exact_hex(sha))
        || intent
            .old_pointer_receipt_sha256
            .as_deref()
            .is_some_and(|sha| !exact_hex(sha))
        || intent.old_stopped_sha256.is_some() != intent.old_pointer_receipt_sha256.is_some()
        || [
            &intent.old_active_sha256,
            &intent.old_snapshot_sha256,
            &intent.old_pointer_sha256,
            &intent.verified_boot_sha256,
            &intent.candidate_sha256,
            &intent.installer_sha256,
        ]
        .iter()
        .any(|hash| !exact_hex(hash))
        || root.parent() != Some(Path::new("/var/lib/aegis-auto/releases"))
        || root_name.is_empty()
        || !root_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || candidate != root.join("bin/aegis-client")
        || intent.old_boot_id.len() != 36
        || intent.new_boot_id.len() != 36
        || intent.old_boot_id == intent.new_boot_id
        || ![&intent.old_boot_id, &intent.new_boot_id]
            .iter()
            .all(|boot| {
                boot.bytes().enumerate().all(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                    }
                })
            })
    {
        return Err(refuse());
    }
    Ok(())
}

fn successor_shape(intent: &SuccessorIntent) -> Result<()> {
    let root = Path::new(&intent.next_public_payload_root);
    let candidate = Path::new(&intent.next_candidate_binary);
    let stage = Path::new(&intent.old_stage_path);
    let root_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(refuse)?;
    if intent.schema != "aegis_auto_v2_stopped_successor_v1"
        || !matches!(intent.kind.as_str(), "restart" | "upgrade")
        || ![
            &intent.old_active_sha256,
            &intent.old_stopped_sha256,
            &intent.old_pointer_receipt_sha256,
            &intent.next_candidate_sha256,
            &intent.next_installer_sha256,
        ]
        .iter()
        .all(|hash| exact_hex(hash))
        || intent.next_bundle_manifest_sha256.is_some() != intent.next_sums_sha256.is_some()
        || intent
            .next_bundle_manifest_sha256
            .as_deref()
            .is_some_and(|v| !exact_hex(v))
        || intent
            .next_sums_sha256
            .as_deref()
            .is_some_and(|v| !exact_hex(v))
        || root.parent() != Some(Path::new("/var/lib/aegis-auto/releases"))
        || root_name.is_empty()
        || root_name == "."
        || root_name == ".."
        || !root_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || candidate != root.join("bin/aegis-client")
        || stage.parent() != Some(Path::new("/run/aegis-installer-config-snapshots"))
        || intent.old_boot_id.len() != 36
        || !intent
            .old_boot_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err(refuse());
    }
    Ok(())
}

fn successor_kind(intent: &SuccessorIntent, old_active: &serde_json::Value) -> Result<()> {
    let old_root = old_active["input"]["public_payload_root"]
        .as_str()
        .ok_or_else(refuse)?;
    let expected = if old_root == intent.next_public_payload_root {
        "restart"
    } else {
        "upgrade"
    };
    if intent.kind != expected {
        return Err(refuse());
    }
    Ok(())
}

fn most_recent_successor_sha(
    active: &GenerationSeal,
    history: i32,
    remaining: usize,
) -> Result<Option<String>> {
    if remaining == 0
        || [
            active.predecessor_intent_sha256.is_some(),
            active.predecessor_boot_intent_sha256.is_some(),
            active.predecessor_cold_intent_sha256.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
            > 1
    {
        return Err(refuse());
    }
    if let Some(sha) = active.predecessor_intent_sha256.as_deref() {
        let raw = read_archived(history, "intent", sha)?;
        let intent: SuccessorIntent = serde_json::from_slice(&raw).map_err(|_| refuse())?;
        successor_shape(&intent)?;
        return Ok(Some(sha.to_owned()));
    }
    if let Some(sha) = active.predecessor_cold_intent_sha256.as_deref() {
        let raw = read_archived(history, "cold-intent", sha)?;
        let value: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| refuse())?;
        if value["schema"] != "aegis_auto_v2_cold_first_arm_intent_v1"
            || value["current_boot_id"] != active.report["terminal"]["boot_id"]
            || value["public_payload_root"] != active.report["input"]["public_payload_root"]
            || value["candidate_sha256"] != active.report["input"]["candidate_sha256"]
            || value["candidate_binary"] != active.report["input"]["candidate_binary"]
        {
            return Err(refuse());
        }
        let old_active_sha = value["old_active_sha256"]
            .as_str()
            .filter(|v| exact_hex(v))
            .ok_or_else(refuse)?;
        let old_stopped_sha = value["old_stopped_sha256"]
            .as_str()
            .filter(|v| exact_hex(v))
            .ok_or_else(refuse)?;
        let successor_sha = value["successor_intent_sha256"]
            .as_str()
            .filter(|v| exact_hex(v))
            .ok_or_else(refuse)?;
        let old_raw = read_archived(history, "active", old_active_sha)?;
        let old = parse_active(&old_raw)?;
        let stopped_raw = read_archived(history, "stopped", old_stopped_sha)?;
        parse_stopped(&stopped_raw, &old_raw, &old)?;
        let predecessor_raw = read_archived(history, "intent", successor_sha)?;
        let predecessor: SuccessorIntent =
            serde_json::from_slice(&predecessor_raw).map_err(|_| refuse())?;
        successor_shape(&predecessor)?;
        if predecessor.old_boot_id != value["old_boot_id"]
            || predecessor.old_active_sha256 != old_active_sha
            || predecessor.old_stopped_sha256 != old_stopped_sha
            || predecessor.next_candidate_sha256 != active.report["input"]["candidate_sha256"]
        {
            return Err(refuse());
        }
        return Ok(Some(successor_sha.to_owned()));
    }
    if let Some(sha) = active.predecessor_boot_intent_sha256.as_deref() {
        let raw = read_archived(history, "boot-intent", sha)?;
        let intent: BootSuccessorIntent = serde_json::from_slice(&raw).map_err(|_| refuse())?;
        boot_successor_shape(&intent)?;
        let old = parse_active(&read_archived(
            history,
            "active",
            &intent.old_active_sha256,
        )?)?;
        if old.boot_snapshot_sha256.as_deref() != Some(intent.old_snapshot_sha256.as_str())
            || old.report["terminal"]["boot_id"].as_str() != Some(intent.old_boot_id.as_str())
            || active.report["terminal"]["boot_id"].as_str() != Some(intent.new_boot_id.as_str())
        {
            return Err(refuse());
        }
        return most_recent_successor_sha(&old, history, remaining - 1);
    }
    Ok(None)
}

/// Resolve the first B active seal reached from an authenticated chain of
/// boot successors. The journal always binds this original seal even if the
/// current B seal has changed on a later boot.
fn passive_first_active_sha(
    active: &GenerationSeal,
    active_sha: &str,
    history: i32,
    intent_sha: &str,
    old_boot: &str,
    remaining: usize,
) -> Result<String> {
    if remaining == 0 {
        return Err(refuse());
    }
    if active.predecessor_intent_sha256.as_deref() == Some(intent_sha)
        && active.predecessor_boot_intent_sha256.is_none()
        && active.report["terminal"]["boot_id"] == old_boot
    {
        return Ok(active_sha.to_owned());
    }
    let boot_sha = active
        .predecessor_boot_intent_sha256
        .as_deref()
        .ok_or_else(refuse)?;
    if active.predecessor_intent_sha256.is_some() {
        return Err(refuse());
    }
    let boot_raw = read_archived(history, "boot-intent", boot_sha)?;
    let boot: BootSuccessorIntent = serde_json::from_slice(&boot_raw).map_err(|_| refuse())?;
    boot_successor_shape(&boot)?;
    let old_raw = read_archived(history, "active", &boot.old_active_sha256)?;
    let old = parse_active(&old_raw)?;
    if old.boot_snapshot_sha256.as_deref() != Some(boot.old_snapshot_sha256.as_str())
        || old.report["terminal"]["boot_id"] != boot.old_boot_id
        || active.report["terminal"]["boot_id"] != boot.new_boot_id
        || old.report["input"]["candidate_sha256"] != active.report["input"]["candidate_sha256"]
    {
        return Err(refuse());
    }
    passive_first_active_sha(
        &old,
        &digest(&old_raw),
        history,
        intent_sha,
        old_boot,
        remaining - 1,
    )
}

fn read_sealed_leaf(parent: i32, name: &str) -> Result<Vec<u8>> {
    read_sealed_leaf_bounded(parent, name, MAX_SEAL)
}

fn read_sealed_leaf_bounded(parent: i32, name: &str, maximum: usize) -> Result<Vec<u8>> {
    let raw = recovery_open_at(parent, name, libc::O_RDONLY, 0)?;
    let before = recovery_stat(raw.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o600
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as usize > maximum
    {
        return Err(refuse());
    }
    let mut file = std::fs::File::from(raw);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    let after = recovery_stat(file.as_raw_fd())?;
    let named = recovery_open_at(parent, name, libc::O_RDONLY, 0)?;
    let current = recovery_stat(named.as_raw_fd())?;
    let identity = |s: &libc::stat| {
        (
            s.st_dev,
            s.st_ino,
            s.st_mode,
            s.st_uid,
            s.st_gid,
            s.st_nlink,
            s.st_size,
            s.st_mtime,
            s.st_mtime_nsec,
            s.st_ctime,
            s.st_ctime_nsec,
        )
    };
    if bytes.len() != before.st_size as usize
        || identity(&before) != identity(&after)
        || identity(&before) != identity(&current)
    {
        return Err(refuse());
    }
    Ok(bytes)
}

fn write_sealed_leaf(parent: i32, name: &str, bytes: &[u8]) -> Result<()> {
    write_sealed_leaf_bounded(parent, name, bytes, MAX_SEAL)
}

fn write_sealed_leaf_bounded(parent: i32, name: &str, bytes: &[u8], maximum: usize) -> Result<()> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(refuse());
    }
    let raw = recovery_open_at(
        parent,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let mut file = std::fs::File::from(raw);
    file.write_all(bytes).map_err(|_| refuse())?;
    file.sync_all().map_err(|_| refuse())?;
    if unsafe { libc::fsync(parent) } != 0 {
        return Err(refuse());
    }
    if read_sealed_leaf_bounded(parent, name, maximum)? != bytes {
        return Err(refuse());
    }
    Ok(())
}

/// New passive continuation records need atomic publication. An interrupted
/// temporary file is inert; only the no-replace final name has authority.
pub(super) fn write_passive_atomic(
    parent: i32,
    name: &str,
    bytes: &[u8],
    maximum: usize,
) -> Result<()> {
    if bytes.is_empty()
        || bytes.len() > maximum
        || name.is_empty()
        || name.len() > 200
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || name.starts_with('.')
    {
        return Err(refuse());
    }
    if recovery_absent(parent, name).is_err() {
        return if read_sealed_leaf_bounded(parent, name, maximum)? == bytes {
            Ok(())
        } else {
            Err(refuse())
        };
    }
    let mut nonce = [0u8; 16];
    if unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) } != nonce.len() as isize
    {
        return Err(refuse());
    }
    let temporary = format!(".aegis-passive-{}.tmp", hex::encode(nonce));
    let fd = recovery_open_at(
        parent,
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes).map_err(|_| refuse())?;
    file.sync_all().map_err(|_| refuse())?;
    let old = std::ffi::CString::new(temporary).map_err(|_| refuse())?;
    let new = std::ffi::CString::new(name).map_err(|_| refuse())?;
    if unsafe {
        libc::renameat2(
            parent,
            old.as_ptr(),
            parent,
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(refuse());
    }
    if unsafe { libc::fsync(parent) } != 0
        || read_sealed_leaf_bounded(parent, name, maximum)? != bytes
    {
        return Err(refuse());
    }
    Ok(())
}

fn history_dir(control: i32, create: bool) -> Result<std::os::fd::OwnedFd> {
    if create {
        let result = unsafe { libc::mkdirat(control, c"generation-history".as_ptr(), 0o700) };
        if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(refuse());
        }
        if result == 0 && unsafe { libc::fsync(control) } != 0 {
            return Err(refuse());
        }
    }
    recovery_directory(control, HISTORY_DIR, Some(0o700))
}

fn archived_name(prefix: &str, hash: &str) -> Result<String> {
    if !matches!(
        prefix,
        "active"
            | "stopped"
            | "intent"
            | "snapshot"
            | "boot-intent"
            | "cold-intent"
            | "boot-proof"
            | "boot-pointer"
            | "stopped-pointer"
            | "passive-retirement-intent"
            | "passive-retired"
            | "passive-old-stopped"
            | "passive-preinst"
            | "passive-advance"
            | "passive-unsealed-recovery"
            | "passive-cold-prior-pointer"
            | "passive-cold-prior-active"
            | "passive-cold-prior-unsealed"
    ) || !exact_hex(hash)
    {
        return Err(refuse());
    }
    Ok(format!("{prefix}-{hash}.json"))
}

fn canonical_object(
    bytes: &[u8],
    schema: &str,
    keys: &[&str],
    newline: bool,
) -> Result<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| refuse())?;
    let object = value.as_object().ok_or_else(refuse)?;
    if object.len() != keys.len()
        || keys.iter().any(|key| !object.contains_key(*key))
        || value["schema"] != schema
    {
        return Err(refuse());
    }
    let mut canonical = serde_json::to_vec(&value).map_err(|_| refuse())?;
    if newline {
        canonical.push(b'\n');
    }
    if canonical != bytes {
        return Err(refuse());
    }
    Ok(value)
}

fn passive_advance_journal(control: i32) -> Result<Option<serde_json::Value>> {
    if recovery_absent(control, PASSIVE_ADVANCE_LEAF).is_ok() {
        return Ok(None);
    }
    let raw = read_sealed_leaf(control, PASSIVE_ADVANCE_LEAF)?;
    let value = canonical_object(
        &raw,
        "aegis_auto_v2_passive_advance_v1",
        &[
            "schema",
            "boot_id",
            "successor_intent_sha256",
            "new_active_sha256",
            "retirement_intent_sha256",
            "retired_sha256",
            "old_stopped_record_sha256",
            "preinst_sha256",
        ],
        false,
    )?;
    for key in [
        "successor_intent_sha256",
        "new_active_sha256",
        "retirement_intent_sha256",
        "retired_sha256",
        "old_stopped_record_sha256",
        "preinst_sha256",
    ] {
        if !value[key].as_str().is_some_and(exact_hex) {
            return Err(refuse());
        }
    }
    // This is the predecessor's write-ahead boot. A completed B may be
    // re-observed after reboot; the caller ties it to the successor intent
    // and current sealed boot lineage before using any archive fallback.
    Ok(Some(value))
}

fn passive_leaf(
    control: i32,
    history: i32,
    name: &str,
    prefix: &str,
    journal: Option<&serde_json::Value>,
    key: &str,
) -> Result<Vec<u8>> {
    let expected = journal.and_then(|value| value[key].as_str());
    if recovery_absent(control, name).is_ok() {
        return read_archived(history, prefix, expected.ok_or_else(refuse)?);
    }
    let bytes = read_sealed_leaf(control, name)?;
    match expected {
        Some(hash) => {
            if digest(&bytes) != hash {
                return Err(refuse());
            }
            // Once the journal exists the archive must either contain the
            // same bytes or not yet exist at this exact write-ahead cut.
            let archive_name = archived_name(prefix, hash)?;
            if recovery_absent(history, &archive_name).is_err() {
                let archived = read_archived(history, prefix, hash)?;
                if archived != bytes {
                    return Err(refuse());
                }
            }
            Ok(bytes)
        }
        None => Ok(bytes),
    }
}

fn archive_exact(history: i32, prefix: &str, hash: &str, bytes: &[u8]) -> Result<()> {
    if digest(bytes) != hash {
        return Err(refuse());
    }
    let name = archived_name(prefix, hash)?;
    let maximum = if prefix == "snapshot" {
        MAX_SNAPSHOT_ARCHIVE
    } else {
        MAX_SEAL
    };
    if recovery_absent(history, &name).is_ok() {
        if prefix.starts_with("passive-") {
            write_passive_atomic(history, &name, bytes, maximum)?;
        } else {
            write_sealed_leaf_bounded(history, &name, bytes, maximum)?;
        }
    } else if read_sealed_leaf_bounded(history, &name, maximum)? != bytes {
        return Err(refuse());
    }
    Ok(())
}

fn retire_exact(parent: i32, name: &str, expected: &[u8]) -> Result<()> {
    if read_sealed_leaf(parent, name)? != expected {
        return Err(refuse());
    }
    let name = std::ffi::CString::new(name).map_err(|_| refuse())?;
    if unsafe { libc::unlinkat(parent, name.as_ptr(), 0) } != 0
        || unsafe { libc::fsync(parent) } != 0
    {
        return Err(refuse());
    }
    Ok(())
}

fn complete_archive_transition(
    control: i32,
    intent_bytes: &[u8],
    intent: &SuccessorIntent,
    active_bytes: &[u8],
    stopped_bytes: &[u8],
    pointer_receipt: &[u8],
) -> Result<()> {
    if read_intent(control)?.0 != intent_bytes
        || digest(active_bytes) != intent.old_active_sha256
        || digest(stopped_bytes) != intent.old_stopped_sha256
        || digest(pointer_receipt) != intent.old_pointer_receipt_sha256
    {
        return Err(refuse());
    }
    let history = history_dir(control, true)?;
    archive_exact(
        history.as_raw_fd(),
        "active",
        &intent.old_active_sha256,
        active_bytes,
    )?;
    archive_exact(
        history.as_raw_fd(),
        "stopped",
        &intent.old_stopped_sha256,
        stopped_bytes,
    )?;
    if recovery_absent(control, "generation-pointer-stopped.json").is_err()
        && read_sealed_leaf(control, "generation-pointer-stopped.json")? != pointer_receipt
    {
        return Err(refuse());
    }
    archive_exact(
        history.as_raw_fd(),
        "stopped-pointer",
        &intent.old_pointer_receipt_sha256,
        pointer_receipt,
    )?;
    if recovery_absent(control, "generation-pointer-stopped.json").is_err() {
        retire_exact(control, "generation-pointer-stopped.json", pointer_receipt)?;
    }
    if recovery_absent(control, STOPPED_LEAF).is_err() {
        retire_exact(control, STOPPED_LEAF, stopped_bytes)?;
    }
    if recovery_absent(control, LEAF).is_err() {
        retire_exact(control, LEAF, active_bytes)?;
    }
    recovery_absent(control, LEAF)?;
    recovery_absent(control, STOPPED_LEAF)?;
    recovery_absent(control, "generation-pointer-stopped.json")?;
    if read_intent(control)?.0 != intent_bytes
        || read_archived(history.as_raw_fd(), "active", &intent.old_active_sha256)? != active_bytes
        || read_archived(history.as_raw_fd(), "stopped", &intent.old_stopped_sha256)?
            != stopped_bytes
        || read_archived(
            history.as_raw_fd(),
            "stopped-pointer",
            &intent.old_pointer_receipt_sha256,
        )? != pointer_receipt
    {
        return Err(refuse());
    }
    Ok(())
}

fn read_intent(control: i32) -> Result<(Vec<u8>, SuccessorIntent)> {
    let bytes = read_sealed_leaf(control, SUCCESSOR_LEAF)?;
    let intent: SuccessorIntent = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    successor_shape(&intent)?;
    if serde_json::to_vec(&intent).map_err(|_| refuse())? != bytes {
        return Err(refuse());
    }
    Ok((bytes, intent))
}

fn read_boot_intent(control: i32) -> Result<(Vec<u8>, BootSuccessorIntent)> {
    let bytes = read_sealed_leaf(control, BOOT_SUCCESSOR_LEAF)?;
    let intent: BootSuccessorIntent = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    boot_successor_shape(&intent)?;
    if serde_json::to_vec(&intent).map_err(|_| refuse())? != bytes {
        return Err(refuse());
    }
    Ok((bytes, intent))
}

fn boot_pointer_legacy(schema: &str, has_backup: bool) -> Result<bool> {
    match schema {
        "aegis_installer_auto_v2_stage_v1" if !has_backup => Ok(true),
        "aegis_installer_auto_v2_stage_v2" | "aegis_installer_auto_v2_boot_stage_v3" => Ok(false),
        _ => Err(refuse()),
    }
}

fn pointer_prepare_evidence(
    control: i32,
    name: &str,
    sha: &str,
    authorized_new_fixed: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if !exact_hex(sha) {
        return Err(refuse());
    }
    let fixed = read_sealed_leaf(control, name);
    let archive_name = format!("prepare-archive-{sha}.json");
    let archived = read_sealed_leaf(control, &archive_name);
    if fixed.is_err() && recovery_absent(control, name).is_err()
        || archived.is_err() && recovery_absent(control, &archive_name).is_err()
    {
        return Err(refuse());
    }
    let bytes = match (fixed, archived) {
        (Ok(a), Ok(b)) if a == b => a,
        (Ok(a), Ok(b)) if authorized_new_fixed.is_some_and(|current| current == a.as_slice()) => b,
        (Ok(a), Err(_)) => a,
        (Err(_), Ok(b)) => b,
        _ => return Err(refuse()),
    };
    if digest(&bytes) != sha {
        return Err(refuse());
    }
    Ok(bytes)
}

fn current_boot_prepare_for_historical_pointer(
    control: i32,
    current: &BootSuccessorIntent,
    current_intent_sha: &str,
) -> Result<[Option<Vec<u8>>; 3]> {
    fn optional(control: i32, name: &str) -> Result<Option<Vec<u8>>> {
        match read_sealed_leaf(control, name) {
            Ok(raw) => Ok(Some(raw)),
            Err(_) => {
                recovery_absent(control, name)?;
                Ok(None)
            }
        }
    }
    let prepared = optional(control, "prepare-current.json")?;
    let created = optional(control, "prepare-stage-created.json")?;
    let completed = optional(control, "prepare-completed.json")?;
    if prepared.is_none() {
        if created.is_some() || completed.is_some() {
            return Err(refuse());
        }
        return Ok([None, None, None]);
    }
    let raw = prepared.as_deref().ok_or_else(refuse)?;
    let p: serde_json::Value = serde_json::from_slice(raw).map_err(|_| refuse())?;
    let stage = p["stage"].as_str().ok_or_else(refuse)?;
    if p.as_object().is_none_or(|row| row.len() != 8)
        || p["schema"] != "aegis_auto_v2_boot_prepare_handoff_v2"
        || p["phase"] != "intent"
        || p["boot_intent_sha256"] != current_intent_sha
        || p["boot_id"] != current.new_boot_id
        || p["candidate_binary"] != current.candidate_binary
        || p["public_payload_root"] != current.public_payload_root
        || !stage.starts_with("/run/aegis-installer-config-snapshots/.auto-")
        || stage.len() != "/run/aegis-installer-config-snapshots/.auto-".len() + 32
        || !stage["/run/aegis-installer-config-snapshots/.auto-".len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || !p["nonce"].as_str().is_some_and(|nonce| {
            nonce.len() == 32
                && nonce
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    {
        return Err(refuse());
    }
    if let Some(bytes) = created.as_deref() {
        let c: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| refuse())?;
        if c.as_object().is_none_or(|row| row.len() != 9)
            || c["schema"] != "aegis_auto_v2_boot_stage_created_v1"
            || c["prepare_intent_sha256"] != digest(raw)
            || c["boot_intent_sha256"] != current_intent_sha
            || c["boot_id"] != current.new_boot_id
            || c["stage"] != stage
            || c["candidate_binary"] != current.candidate_binary
            || c["public_payload_root"] != current.public_payload_root
            || ["stage_device", "stage_inode"]
                .iter()
                .any(|key| c[*key].as_u64().is_none_or(|n| n == 0))
        {
            return Err(refuse());
        }
    }
    if let Some(bytes) = completed.as_deref() {
        let c: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| refuse())?;
        let created_value: serde_json::Value =
            serde_json::from_slice(created.as_deref().ok_or_else(refuse)?).map_err(|_| refuse())?;
        if created.is_none()
            || c.as_object().is_none_or(|row| row.len() != 12)
            || c["schema"] != "aegis_auto_v2_boot_prepare_handoff_v2"
            || c["phase"] != "completed"
            || c["intent_sha256"] != digest(raw)
            || c["boot_intent_sha256"] != current_intent_sha
            || c["stage"] != stage
            || c["candidate_sha256"] != current.candidate_sha256
            || c["stage_created_sha256"] != digest(created.as_deref().ok_or_else(refuse)?)
            || ["header_sha256", "input_generation", "provenance_sha256"]
                .iter()
                .any(|key| !c[*key].as_str().is_some_and(exact_hex))
            || ["stage_device", "stage_inode"]
                .iter()
                .any(|key| c[*key].as_u64().is_none_or(|n| n == 0))
            || c["stage_device"] != created_value["stage_device"]
            || c["stage_inode"] != created_value["stage_inode"]
        {
            return Err(refuse());
        }
    }
    Ok([prepared, created, completed])
}

fn boot_pointer_v3(
    control: i32,
    value: &serde_json::Value,
    report: &serde_json::Value,
) -> Result<()> {
    let boot_sha = value["boot_intent_sha256"].as_str().ok_or_else(refuse)?;
    let prepared_sha = value["prepare_intent_sha256"].as_str().ok_or_else(refuse)?;
    let completed_sha = value["prepare_completed_sha256"]
        .as_str()
        .ok_or_else(refuse)?;
    if ![boot_sha, prepared_sha, completed_sha]
        .iter()
        .all(|sha| exact_hex(sha))
    {
        return Err(refuse());
    }
    let mut later_fixed: [Option<Vec<u8>>; 3] = std::array::from_fn(|_| None);
    let live = read_sealed_leaf(control, BOOT_SUCCESSOR_LEAF);
    let boot_raw = match live {
        Ok(raw) if digest(&raw) == boot_sha => raw,
        Ok(_) => {
            // A later boot may have its own live intent while this pointer
            // is historical. Authenticate that exact successor relationship;
            // malformed or unrelated live bytes never select old archives.
            let (current_raw, current_intent) = read_boot_intent(control)?;
            if value["boot_id"].as_str() == Some(current_boot_id()?.as_str())
                || current_intent.new_boot_id != current_boot_id()?
                || value["boot_id"] != current_intent.old_boot_id
            {
                return Err(refuse());
            }
            later_fixed = current_boot_prepare_for_historical_pointer(
                control,
                &current_intent,
                &digest(&current_raw),
            )?;
            let history = history_dir(control, false)?;
            read_archived(history.as_raw_fd(), "boot-intent", boot_sha)?
        }
        Err(_) if recovery_absent(control, BOOT_SUCCESSOR_LEAF).is_ok() => {
            // A historical v3 pointer can outlive its live intent, but a
            // current-boot archive is admissible only after the exact new
            // generation seal commits this intent and report.
            if value["boot_id"].as_str() == Some(current_boot_id()?.as_str()) {
                let sealed = parse_active(&read_sealed_leaf(control, LEAF)?)?;
                if sealed.predecessor_boot_intent_sha256.as_deref() != Some(boot_sha)
                    || sealed.report != *report
                {
                    return Err(refuse());
                }
            }
            let history = history_dir(control, false)?;
            read_archived(history.as_raw_fd(), "boot-intent", boot_sha)?
        }
        Err(_) => return Err(refuse()),
    };
    if digest(&boot_raw) != boot_sha {
        return Err(refuse());
    }
    let intent: BootSuccessorIntent = serde_json::from_slice(&boot_raw).map_err(|_| refuse())?;
    boot_successor_shape(&intent)?;
    if serde_json::to_vec(&intent).map_err(|_| refuse())? != boot_raw
        || value["boot_id"] != intent.new_boot_id
        || value["candidate_sha256"] != intent.candidate_sha256
        || report["input"]["public_payload_root"] != intent.public_payload_root
        || report["input"]["candidate_binary"] != intent.candidate_binary
    {
        return Err(refuse());
    }
    let prepared = pointer_prepare_evidence(
        control,
        "prepare-current.json",
        prepared_sha,
        later_fixed[0].as_deref(),
    )?;
    let completed = pointer_prepare_evidence(
        control,
        "prepare-completed.json",
        completed_sha,
        later_fixed[2].as_deref(),
    )?;
    let prepare: serde_json::Value = serde_json::from_slice(&prepared).map_err(|_| refuse())?;
    let complete: serde_json::Value = serde_json::from_slice(&completed).map_err(|_| refuse())?;
    if prepare.as_object().is_none_or(|row| row.len() != 8)
        || complete.as_object().is_none_or(|row| row.len() != 12)
        || prepare["schema"] != "aegis_auto_v2_boot_prepare_handoff_v2"
        || prepare["phase"] != "intent"
        || prepare["boot_intent_sha256"] != boot_sha
        || prepare["stage"] != value["stage"]
        || prepare["boot_id"] != value["boot_id"]
        || prepare["public_payload_root"] != intent.public_payload_root
        || prepare["candidate_binary"] != intent.candidate_binary
        || !prepare["nonce"].as_str().is_some_and(|nonce| {
            nonce.len() == 32
                && nonce
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        || complete["schema"] != prepare["schema"]
        || complete["phase"] != "completed"
        || complete["boot_intent_sha256"] != boot_sha
        || !complete["stage_created_sha256"]
            .as_str()
            .is_some_and(exact_hex)
        || complete["intent_sha256"] != prepared_sha
        || complete["stage"] != value["stage"]
        || complete["candidate_sha256"] != value["candidate_sha256"]
        || ["stage_device", "stage_inode"]
            .iter()
            .any(|key| complete[*key].as_u64().is_none_or(|n| n == 0))
        || ["header_sha256", "input_generation", "provenance_sha256"]
            .iter()
            .any(|key| !complete[*key].as_str().is_some_and(exact_hex))
    {
        return Err(refuse());
    }
    let created_sha = complete["stage_created_sha256"]
        .as_str()
        .ok_or_else(refuse)?;
    let created_raw = pointer_prepare_evidence(
        control,
        "prepare-stage-created.json",
        created_sha,
        later_fixed[1].as_deref(),
    )?;
    let created: serde_json::Value = serde_json::from_slice(&created_raw).map_err(|_| refuse())?;
    if created.as_object().is_none_or(|row| row.len() != 9)
        || created["schema"] != "aegis_auto_v2_boot_stage_created_v1"
        || created["prepare_intent_sha256"] != prepared_sha
        || created["boot_intent_sha256"] != boot_sha
        || created["boot_id"] != value["boot_id"]
        || created["stage"] != value["stage"]
        || created["stage_device"] != complete["stage_device"]
        || created["stage_inode"] != complete["stage_inode"]
        || created["candidate_binary"] != intent.candidate_binary
        || created["public_payload_root"] != intent.public_payload_root
    {
        return Err(refuse());
    }
    Ok(())
}

#[cfg(test)]
mod boot_pointer_version_tests {
    use super::{
        archived_name, boot_pointer, boot_pointer_legacy, boot_pointer_with_authorized_current,
        current_boot_id, digest, validated_successor_current_pointer, write_passive_atomic,
        MAX_SEAL,
    };

    #[test]
    fn copied_v1_refuses_including_archives_but_null_v1_and_new_v2_are_typed() {
        assert!(boot_pointer_legacy("aegis_installer_auto_v2_stage_v1", true).is_err());
        assert!(boot_pointer_legacy("aegis_installer_auto_v2_stage_v1", false).unwrap());
        assert!(!boot_pointer_legacy("aegis_installer_auto_v2_stage_v2", true).unwrap());
        assert!(boot_pointer_legacy("unknown", false).is_err());

        // This selected native method also exercises the production pointer
        // reader with a real protected directory. The old archived pointer
        // and the new live pending pointer must be separately authenticated.
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let dir = std::env::temp_dir().join(format!(
            "aegis-successor-pointer-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let history = dir.join("generation-history");
        std::fs::create_dir(&history).unwrap();
        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o700)).unwrap();
        let control = std::fs::File::open(&dir).unwrap();
        let archive = std::fs::File::open(&history).unwrap();
        let fd = control.as_raw_fd();
        let live_boot = current_boot_id().unwrap();
        let old_boot = "00000000-0000-0000-0000-000000000001";
        assert_ne!(live_boot, old_boot);
        let candidate = "a".repeat(64);
        let pointer = |stage: &str, boot: &str, candidate_sha: &str| {
            serde_json::json!({
                "schema":"aegis_installer_auto_v2_stage_v2",
                "stage":stage,"status":"pending","boot_id":boot,
                "installed_binary":"/usr/local/bin/aegis-client",
                "candidate_sha256":candidate_sha,"previous_binary":null
            })
        };
        let old_stage = "/run/aegis-installer-config-snapshots/old";
        let new_stage = "/run/aegis-installer-config-snapshots/new";
        let old_report = serde_json::json!({
            "stage":{"path":old_stage},"terminal":{"boot_id":old_boot},
            "input":{"candidate_sha256":candidate}
        });
        let new_report = serde_json::json!({
            "stage":{"path":new_stage},"terminal":{"boot_id":live_boot},
            "input":{"candidate_sha256":candidate}
        });
        let old_bytes = serde_json::to_vec(&pointer(old_stage, old_boot, &candidate)).unwrap();
        let new_bytes = serde_json::to_vec(&pointer(new_stage, &live_boot, &candidate)).unwrap();
        let old_sha = digest(&old_bytes);
        let archived_leaf = archived_name("boot-pointer", &old_sha).unwrap();
        write_passive_atomic(archive.as_raw_fd(), &archived_leaf, &old_bytes, MAX_SEAL).unwrap();
        write_passive_atomic(fd, "current.json", &new_bytes, MAX_SEAL).unwrap();

        let authorized = validated_successor_current_pointer(fd, &new_report, &live_boot)
            .unwrap()
            .unwrap();
        assert_eq!(authorized, new_bytes);
        assert!(boot_pointer(fd, &old_report, Some(&old_sha)).is_err());
        assert_eq!(
            boot_pointer_with_authorized_current(
                fd,
                &old_report,
                Some(&old_sha),
                Some(&authorized)
            )
            .unwrap(),
            old_bytes
        );
        std::fs::remove_file(history.join(&archived_leaf)).unwrap();
        write_passive_atomic(
            archive.as_raw_fd(),
            &archived_leaf,
            b"bad archive",
            MAX_SEAL,
        )
        .unwrap();
        assert!(boot_pointer_with_authorized_current(
            fd,
            &old_report,
            Some(&old_sha),
            Some(&authorized)
        )
        .is_err());
        std::fs::remove_file(history.join(&archived_leaf)).unwrap();
        write_passive_atomic(archive.as_raw_fd(), &archived_leaf, &old_bytes, MAX_SEAL).unwrap();
        assert!(boot_pointer_with_authorized_current(
            fd,
            &old_report,
            Some(&old_sha),
            Some(b"unvalidated")
        )
        .is_err());
        for key in ["path", "boot_id", "candidate_sha256"] {
            let mut wrong_old = old_report.clone();
            match key {
                "path" => wrong_old["stage"]["path"] = serde_json::json!(new_stage),
                "boot_id" => wrong_old["terminal"]["boot_id"] = serde_json::json!(live_boot),
                _ => wrong_old["input"]["candidate_sha256"] = serde_json::json!("b".repeat(64)),
            }
            assert!(boot_pointer_with_authorized_current(
                fd,
                &wrong_old,
                Some(&old_sha),
                Some(&authorized)
            )
            .is_err());
        }
        std::fs::remove_file(dir.join("current.json")).unwrap();
        let changed_current =
            serde_json::to_vec(&pointer(new_stage, &live_boot, &"b".repeat(64))).unwrap();
        write_passive_atomic(fd, "current.json", &changed_current, MAX_SEAL).unwrap();
        assert!(boot_pointer_with_authorized_current(
            fd,
            &old_report,
            Some(&old_sha),
            Some(&authorized)
        )
        .is_err());
        std::fs::remove_file(dir.join("current.json")).unwrap();
        write_passive_atomic(fd, "current.json", &new_bytes, MAX_SEAL).unwrap();
        let mut wrong_report = new_report.clone();
        wrong_report["terminal"]["boot_id"] = serde_json::json!(old_boot);
        assert!(validated_successor_current_pointer(fd, &wrong_report, &live_boot).is_err());
        for key in ["stage", "boot_id", "candidate_sha256"] {
            std::fs::remove_file(dir.join("current.json")).unwrap();
            let mut changed = pointer(new_stage, &live_boot, &candidate);
            changed[key] = serde_json::json!("wrong");
            let changed = serde_json::to_vec(&changed).unwrap();
            write_passive_atomic(fd, "current.json", &changed, MAX_SEAL).unwrap();
            assert!(validated_successor_current_pointer(fd, &new_report, &live_boot).is_err());
        }
        std::fs::remove_file(dir.join("current.json")).unwrap();
        std::os::unix::fs::symlink(history.join(&archived_leaf), dir.join("current.json")).unwrap();
        assert!(validated_successor_current_pointer(fd, &new_report, &live_boot).is_err());
        std::fs::remove_file(dir.join("current.json")).unwrap();
        assert!(
            validated_successor_current_pointer(fd, &new_report, &live_boot)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            boot_pointer(fd, &old_report, Some(&old_sha)).unwrap(),
            old_bytes
        );
        std::fs::remove_file(history.join(&archived_leaf)).unwrap();
        write_passive_atomic(
            archive.as_raw_fd(),
            &archived_leaf,
            b"bad archive",
            MAX_SEAL,
        )
        .unwrap();
        assert!(boot_pointer(fd, &old_report, Some(&old_sha)).is_err());
        std::fs::remove_file(history.join(&archived_leaf)).unwrap();
        let mut bad_backup = pointer(old_stage, old_boot, &candidate);
        bad_backup["previous_binary"] = serde_json::json!({"name":"backup-invalid.bin"});
        let bad_backup = serde_json::to_vec(&bad_backup).unwrap();
        let bad_sha = digest(&bad_backup);
        let bad_leaf = archived_name("boot-pointer", &bad_sha).unwrap();
        write_passive_atomic(archive.as_raw_fd(), &bad_leaf, &bad_backup, MAX_SEAL).unwrap();
        assert!(boot_pointer(fd, &old_report, Some(&bad_sha)).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

fn boot_pointer(
    control: i32,
    report: &serde_json::Value,
    archived_sha: Option<&str>,
) -> Result<Vec<u8>> {
    boot_pointer_with_authorized_current(control, report, archived_sha, None)
}

fn boot_pointer_with_authorized_current(
    control: i32,
    report: &serde_json::Value,
    archived_sha: Option<&str>,
    authorized_current: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if let Some(expected) = authorized_current {
        // The caller validated this live successor pointer under the held
        // install/guard OFDs. A changed or unreadable current leaf cannot be
        // converted into an archived-predecessor fallback.
        if read_sealed_leaf(control, "current.json")? != expected {
            return Err(refuse());
        }
    }
    let bytes = if let Some(sha) = archived_sha {
        let fixed = read_sealed_leaf(control, "current.json");
        let history = history_dir(control, false).ok();
        let archived = history
            .as_ref()
            .ok_or_else(refuse)
            .and_then(|dir| read_archived(dir.as_raw_fd(), "boot-pointer", sha));
        let stopped_archive = read_sealed_leaf(control, &format!("archived-stopped-{sha}.json"))
            .and_then(|bytes| {
                if digest(&bytes) == sha {
                    Ok(bytes)
                } else {
                    Err(refuse())
                }
            });
        let archived = match (archived, stopped_archive) {
            (Ok(a), Ok(b)) if a == b => Ok(a),
            (Ok(a), Err(_)) => Ok(a),
            (Err(_), Ok(b)) => Ok(b),
            _ => Err(refuse()),
        };
        let cold_archive = history
            .as_ref()
            .ok_or_else(refuse)
            .and_then(|dir| read_archived(dir.as_raw_fd(), "passive-cold-prior-pointer", sha));
        let archived = match (archived, cold_archive) {
            (Ok(a), Ok(b)) if a == b => Ok(a),
            (Ok(a), Err(_)) => Ok(a),
            (Err(_), Ok(b)) => Ok(b),
            _ => Err(refuse()),
        };
        match (fixed, archived) {
            (Ok(a), Ok(b)) if a == b && digest(&a) == sha => a,
            // During a boot successor the newly published current pointer is
            // different from the SHA-pinned predecessor. Its bytes may differ
            // only after the caller has fully validated those same bytes as
            // the new report's live pending pointer. This branch still returns
            // only the authenticated predecessor archive.
            (Ok(a), Ok(b))
                if authorized_current.is_some_and(|current| current == a.as_slice())
                    && digest(&b) == sha =>
            {
                b
            }
            (Ok(a), Err(_)) if digest(&a) == sha => a,
            (Err(_), Ok(b)) if digest(&b) == sha => b,
            _ => return Err(refuse()),
        }
    } else {
        read_sealed_leaf(control, "current.json")?
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    let object = value.as_object().ok_or_else(refuse)?;
    let boot_owned = value["schema"] == "aegis_installer_auto_v2_boot_stage_v3";
    if object.len() != if boot_owned { 10 } else { 7 }
        || [
            "schema",
            "stage",
            "status",
            "boot_id",
            "installed_binary",
            "candidate_sha256",
            "previous_binary",
        ]
        .iter()
        .any(|key| !object.contains_key(*key))
        || (boot_owned
            && [
                "boot_intent_sha256",
                "prepare_intent_sha256",
                "prepare_completed_sha256",
            ]
            .iter()
            .any(|key| !value[*key].as_str().is_some_and(exact_hex)))
        || value["status"] != "pending"
        || value["stage"] != report["stage"]["path"]
        || value["boot_id"] != report["terminal"]["boot_id"]
        || value["installed_binary"] != "/usr/local/bin/aegis-client"
        || value["candidate_sha256"] != report["input"]["candidate_sha256"]
    {
        return Err(refuse());
    }
    let legacy = boot_pointer_legacy(
        value["schema"].as_str().ok_or_else(refuse)?,
        !value["previous_binary"].is_null(),
    )?;
    if boot_owned {
        boot_pointer_v3(control, &value, report)?;
    }
    if !value["previous_binary"].is_null() {
        let previous = value["previous_binary"].as_object().ok_or_else(refuse)?;
        // A copied backup must carry its own identity before this lineage
        // reader may admit it. The old v1 pointer is still refused.
        if previous.len() != if legacy { 6 } else { 8 }
            || ["name", "sha256", "device", "inode", "size", "mode"]
                .iter()
                .any(|key| !previous.contains_key(*key))
            || (!legacy
                && ["backup_device", "backup_inode"]
                    .iter()
                    .any(|key| !previous.contains_key(*key)))
        {
            return Err(refuse());
        }
        let name = value["previous_binary"]["name"]
            .as_str()
            .ok_or_else(refuse)?;
        if !name.starts_with("backup-")
            || !name.ends_with(".bin")
            || name.len() != 43
            || !name[7..39]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !value["previous_binary"]["sha256"]
                .as_str()
                .is_some_and(exact_hex)
            || !matches!(
                value["previous_binary"]["mode"].as_u64(),
                Some(0o555 | 0o755)
            )
            || value["previous_binary"]["device"]
                .as_u64()
                .is_none_or(|n| n == 0)
            || value["previous_binary"]["inode"]
                .as_u64()
                .is_none_or(|n| n == 0)
        {
            return Err(refuse());
        }
        let backup_identity = if legacy {
            true
        } else {
            let device = previous["backup_device"].as_u64().ok_or_else(refuse)?;
            let inode = previous["backup_inode"].as_u64().ok_or_else(refuse)?;
            device != 0
                && inode != 0
                && (device, inode)
                    != (
                        previous["device"].as_u64().ok_or_else(refuse)?,
                        previous["inode"].as_u64().ok_or_else(refuse)?,
                    )
        };
        let backup = recovery_open_at(control, name, libc::O_RDONLY, 0)?;
        let stat = recovery_stat(backup.as_raw_fd())?;
        if stat.st_mode != libc::S_IFREG | 0o600
            || stat.st_uid != 0
            || stat.st_gid != 0
            || stat.st_nlink != 1
            || !backup_identity
            || (!legacy
                && (stat.st_dev != previous["backup_device"].as_u64().ok_or_else(refuse)?
                    || stat.st_ino != previous["backup_inode"].as_u64().ok_or_else(refuse)?))
            || stat.st_size
                != value["previous_binary"]["size"]
                    .as_i64()
                    .ok_or_else(refuse)?
            || recovery_file_hash(backup.as_raw_fd(), 256 * 1024 * 1024)?.1
                != value["previous_binary"]["sha256"]
                    .as_str()
                    .ok_or_else(refuse)?
        {
            return Err(refuse());
        }
    }
    if let Some(expected) = authorized_current {
        if read_sealed_leaf(control, "current.json")? != expected {
            return Err(refuse());
        }
    }
    Ok(bytes)
}

fn validated_successor_current_pointer(
    control: i32,
    new_report: &serde_json::Value,
    intent_new_boot_id: &str,
) -> Result<Option<Vec<u8>>> {
    validated_current_pointer_for_report(control, new_report, intent_new_boot_id, true)
}

fn validated_current_pointer_for_report(
    control: i32,
    new_report: &serde_json::Value,
    intent_new_boot_id: &str,
    require_live_boot: bool,
) -> Result<Option<Vec<u8>>> {
    if lineage_bad(
        new_report["terminal"]["boot_id"].as_str() != Some(intent_new_boot_id),
        LineageGate::BootNewIdentity,
    ) || (require_live_boot
        && lineage_bad(
            lineage_tag(current_boot_id(), LineageGate::BootNewIdentity)? != intent_new_boot_id,
            LineageGate::BootNewIdentity,
        ))
    {
        return Err(refuse());
    }
    if recovery_absent(control, "current.json").is_ok() {
        Ok(None)
    } else {
        // An error from recovery_absent is never treated as permission to
        // ignore the leaf: a present or malformed leaf must pass this complete
        // typed pointer and backup-identity verifier for the new report.
        lineage_tag(
            boot_pointer(control, new_report, None),
            LineageGate::BootNewCurrentPointer,
        )
        .map(Some)
    }
}

fn boot_stopped(
    control: i32,
    active_bytes: &[u8],
    active: &GenerationSeal,
    expected_sha: Option<&str>,
    expected_pointer_receipt_sha: Option<&str>,
) -> Result<Option<(Vec<u8>, String)>> {
    boot_stopped_with_authorized_current(
        control,
        active_bytes,
        active,
        expected_sha,
        expected_pointer_receipt_sha,
        None,
    )
}

fn boot_stopped_with_authorized_current(
    control: i32,
    active_bytes: &[u8],
    active: &GenerationSeal,
    expected_sha: Option<&str>,
    expected_pointer_receipt_sha: Option<&str>,
    authorized_current: Option<&[u8]>,
) -> Result<Option<(Vec<u8>, String)>> {
    let fixed = read_sealed_leaf(control, STOPPED_LEAF);
    let bytes = if let Some(sha) = expected_sha {
        if !exact_hex(sha) {
            return Err(refuse());
        }
        let history = history_dir(control, false).ok();
        let archived = history
            .as_ref()
            .ok_or_else(refuse)
            .and_then(|dir| read_archived(dir.as_raw_fd(), "stopped", sha));
        match (fixed, archived) {
            (Ok(a), Ok(b)) if a == b && digest(&a) == sha => a,
            (Ok(a), Err(_)) if digest(&a) == sha => a,
            (Err(_), Ok(b)) if digest(&b) == sha => b,
            _ => return Err(refuse()),
        }
    } else {
        match fixed {
            Ok(bytes) => bytes,
            Err(_) if recovery_absent(control, STOPPED_LEAF).is_ok() => return Ok(None),
            Err(_) => return Err(refuse()),
        }
    };
    let stopped = parse_stopped(&bytes, active_bytes, active)?;
    let receipt = stopped_pointer_receipt(control, &stopped.report, expected_pointer_receipt_sha)?;
    let value: serde_json::Value = serde_json::from_slice(&receipt).map_err(|_| refuse())?;
    let pointer_sha = value["pointer_sha256"].as_str().ok_or_else(refuse)?;
    if !exact_hex(pointer_sha) {
        return Err(refuse());
    }
    boot_pointer_with_authorized_current(
        control,
        &active.report,
        Some(pointer_sha),
        authorized_current,
    )?;
    Ok(Some((bytes, pointer_sha.to_owned())))
}

fn boot_proof_shape(old: &serde_json::Value, proof: &serde_json::Value) -> Result<()> {
    let deny = &proof["deny"];
    if old["stage"]["mode"] == "socks-only" {
        if deny["schema"] != "aegis_auto_guard_boot_passive_readback_v1"
            || deny["passive"] != true
            || deny["no_private_owner"] != true
            || deny["fixed_client_stopped"] != true
            || !proof["host_assessment"].is_null()
        {
            return Err(refuse());
        }
    } else if deny["schema"] != "aegis_auto_guard_boot_denied_readback_v1"
        || deny["no_client_grant"] != true
        || deny["no_private_owner"] != true
        || deny["fixed_client_stopped"] != true
        || proof["host_assessment"]["schema"] != "aegis_auto_v2_boot_host_assessment_v1"
        || proof["host_assessment"]["assessment_sha256"] != deny["state_sha256"]
    {
        return Err(refuse());
    }
    if deny["candidate_sha256"] != old["input"]["candidate_sha256"]
        || deny["boot_id"] != proof["new_boot_id"]
    {
        return Err(refuse());
    }
    Ok(())
}

fn read_archived(history: i32, prefix: &str, sha: &str) -> Result<Vec<u8>> {
    let maximum = if prefix == "snapshot" {
        MAX_SNAPSHOT_ARCHIVE
    } else {
        MAX_SEAL
    };
    let bytes = read_sealed_leaf_bounded(history, &archived_name(prefix, sha)?, maximum)?;
    if digest(&bytes) != sha {
        return Err(refuse());
    }
    Ok(bytes)
}

fn read_archived_optional(history: i32, prefix: &str, sha: &str) -> Result<Option<Vec<u8>>> {
    let name = archived_name(prefix, sha)?;
    if recovery_absent(history, &name).is_ok() {
        Ok(None)
    } else {
        read_archived(history, prefix, sha).map(Some)
    }
}

fn parse_active(bytes: &[u8]) -> Result<GenerationSeal> {
    let seal: GenerationSeal = serde_json::from_slice(bytes).map_err(|_| refuse())?;
    if seal.schema != "aegis_auto_v2_generation_v1"
        || !exact_hex(&seal.report_sha256)
        || seal
            .boot_snapshot_sha256
            .as_deref()
            .is_some_and(|v| !exact_hex(v))
        || seal
            .predecessor_intent_sha256
            .as_deref()
            .is_some_and(|v| !exact_hex(v))
        || seal
            .predecessor_cold_intent_sha256
            .as_deref()
            .is_some_and(|v| !exact_hex(v))
        || [
            seal.predecessor_intent_sha256.is_some(),
            seal.predecessor_boot_intent_sha256.is_some(),
            seal.predecessor_cold_intent_sha256.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
            > 1
    {
        return Err(refuse());
    }
    report_shape(&seal.report)?;
    let canonical = serde_json::to_vec(&seal.report).map_err(|_| refuse())?;
    if digest(&canonical) != seal.report_sha256 {
        return Err(refuse());
    }
    Ok(seal)
}

fn parse_stopped(
    bytes: &[u8],
    active_bytes: &[u8],
    active: &GenerationSeal,
) -> Result<StoppedGenerationSeal> {
    let stopped: StoppedGenerationSeal = serde_json::from_slice(bytes).map_err(|_| refuse())?;
    if stopped.schema != "aegis_auto_v2_stopped_generation_v1"
        || !exact_hex(&stopped.active_seal_sha256)
        || !exact_hex(&stopped.stopped_report_sha256)
        || stopped.active_seal_sha256 != digest(active_bytes)
    {
        return Err(refuse());
    }
    let canonical = serde_json::to_vec(&stopped.report).map_err(|_| refuse())?;
    if stopped.stopped_report_sha256 != digest(&canonical)
        || stopped.report["schema"] != "aegis_auto_v2_stopped_stage_inspection_v1"
        || stopped.report["terminal"]["outcome"] != "finalized-stopped"
        || stopped.report["stage"]["path"] != active.report["stage"]["path"]
        || stopped.report["stage"]["device"] != active.report["stage"]["device"]
        || stopped.report["stage"]["inode"] != active.report["stage"]["inode"]
        || stopped.report["terminal"]["start_terminal_sha256"]
            != active.report["terminal"]["start_terminal_sha256"]
        || stopped.report["terminal"]["boot_id"] != active.report["terminal"]["boot_id"]
        || stopped.report["input"] != active.report["input"]
        || stopped.report["current_fixed"] != active.report["current_fixed"]
        || stopped.report["published_paths"]["current_publications"]
            != active.report["published_paths"]["current_publications"]
        || stopped.report["guardian"]["prior_manager_binding_sha256"]
            != active.report["guardian"]["manager_binding_sha256"]
        || stopped.report["published_paths"]["current_verified"] != true
        || stopped.report["main"]["stopped_verified"] != true
        || stopped.report["main"]["no_live_lease_verified"] != true
        || stopped.report["main"]["fdstore_empty_verified"] != true
        || stopped.report["guardian"]["deny_verified"] != true
        || stopped.report["guardian"]["fdstore_empty_verified"] != true
    {
        return Err(refuse());
    }
    Ok(stopped)
}

fn verified_retained_source(root: &Path, candidate: &Path) -> Result<(String, String)> {
    if root.parent() != Some(Path::new("/var/lib/aegis-auto/releases"))
        || candidate != root.join("bin/aegis-client")
    {
        return Err(refuse());
    }
    let name = root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(refuse());
    }
    let release = recovery_chain(&["var", "lib", "aegis-auto", "releases", name], Some(0o700))?;
    let bin = recovery_directory(release.as_raw_fd(), "bin", None)?;
    let candidate_fd = recovery_open_at(bin.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    let candidate_stat = recovery_stat(candidate_fd.as_raw_fd())?;
    if candidate_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || candidate_stat.st_uid != 0
        || candidate_stat.st_gid != 0
        || candidate_stat.st_nlink != 1
        || !matches!(candidate_stat.st_mode & 0o7777, 0o555 | 0o755)
    {
        return Err(refuse());
    }
    let candidate_sha = recovery_file_hash(candidate_fd.as_raw_fd(), 256 * 1024 * 1024)?.1;
    let installer_fd = recovery_open_at(release.as_raw_fd(), "install.sh", libc::O_RDONLY, 0)?;
    let installer_stat = recovery_stat(installer_fd.as_raw_fd())?;
    if installer_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || installer_stat.st_uid != 0
        || installer_stat.st_gid != 0
        || installer_stat.st_nlink != 1
        || !matches!(installer_stat.st_mode & 0o7777, 0o555 | 0o755)
    {
        return Err(refuse());
    }
    let installer_sha = recovery_file_hash(installer_fd.as_raw_fd(), 8 * 1024 * 1024)?.1;
    Ok((candidate_sha, installer_sha))
}

/// Bind an explicit recovery actor to the newly retained product source. The
/// old pending pointer still names the old candidate and is never rewritten
/// to make this binary appear to be that candidate.
pub(super) fn verify_fresh_prebind_recovery_actor(root: &Path) -> Result<String> {
    let candidate = root.join("bin/aegis-client");
    let (candidate_sha, _) = verified_retained_source(root, &candidate)?;
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if recovery_file_hash(running.as_raw_fd(), 256 * 1024 * 1024)?.1 != candidate_sha {
        return Err(refuse());
    }
    Ok(candidate_sha)
}

pub(super) fn verify_fresh_prebind_old_source(root: &Path) -> Result<String> {
    verified_retained_source(root, &root.join("bin/aegis-client")).map(|(candidate, _)| candidate)
}

fn verify_old_source(report: &serde_json::Value) -> Result<()> {
    let root = Path::new(
        report["input"]["public_payload_root"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let candidate = Path::new(
        report["input"]["candidate_binary"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let (candidate_sha, installer_sha) = verified_retained_source(root, candidate)?;
    if candidate_sha
        != report["input"]["candidate_sha256"]
            .as_str()
            .ok_or_else(refuse)?
        || installer_sha != digest(include_bytes!("../../../install.sh"))
    {
        return Err(refuse());
    }
    let installed_dir = recovery_chain(&["usr", "local", "bin"], None)?;
    let installed = recovery_open_at(installed_dir.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    let stat = recovery_stat(installed.as_raw_fd())?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || !matches!(stat.st_mode & 0o7777, 0o555 | 0o755)
        || recovery_file_hash(installed.as_raw_fd(), 256 * 1024 * 1024)?.1 != candidate_sha
    {
        return Err(refuse());
    }
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if recovery_file_hash(running.as_raw_fd(), 256 * 1024 * 1024)?.1 != candidate_sha {
        return Err(refuse());
    }
    Ok(())
}

/// Reopen the retained and currently installed source for a boot observer.
/// Historical report bytes alone cannot authorize a successor.
pub(super) fn verify_boot_source(report: &serde_json::Value) -> Result<()> {
    report_shape(report)?;
    verify_old_source(report)
}

/// Production Prepare must match the source already authorized by a stopped
/// or fresh-boot transition. Native fixture Prepare passes no InstallLock and
/// does not enter this production admission path.
pub(super) fn verify_prepare_source(
    root: &Path,
    candidate: &Path,
    lock: &InstallLock,
) -> Result<()> {
    lock.revalidate().map_err(|_| refuse())?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    if read_sealed_leaf(control.as_raw_fd(), "v2-enabled")?
        != b"{\"schema\":\"aegis_installer_auto_v2_enabled_v1\"}\n"
    {
        return Err(refuse());
    }
    recovery_absent(control.as_raw_fd(), RECOVERY_LEAF)?;
    let (candidate_sha, installer_sha) = verified_retained_source(root, candidate)?;
    if installer_sha != digest(include_bytes!("../../../install.sh")) {
        return Err(refuse());
    }
    let successor = recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF).is_err();
    let boot_successor = recovery_absent(control.as_raw_fd(), BOOT_SUCCESSOR_LEAF).is_err();
    let cold_successor = recovery_absent(control.as_raw_fd(), COLD_FIRST_ARM_LEAF).is_err();
    if (successor as u8 + boot_successor as u8 + cold_successor as u8) > 1 {
        return Err(refuse());
    }
    if successor {
        recovery_absent(control.as_raw_fd(), LEAF)?;
        recovery_absent(control.as_raw_fd(), STOPPED_LEAF)?;
        recovery_absent(control.as_raw_fd(), "generation-pointer-stopped.json")?;
        recovery_absent(control.as_raw_fd(), "current.json")?;
        let (_, intent) = read_intent(control.as_raw_fd())?;
        let history = history_dir(control.as_raw_fd(), false)?;
        let old_active = read_archived(history.as_raw_fd(), "active", &intent.old_active_sha256)?;
        let old = parse_active(&old_active)?;
        let old_stopped =
            read_archived(history.as_raw_fd(), "stopped", &intent.old_stopped_sha256)?;
        let stopped = parse_stopped(&old_stopped, &old_active, &old)?;
        stopped_pointer_receipt(
            control.as_raw_fd(),
            &stopped.report,
            Some(&intent.old_pointer_receipt_sha256),
        )?;
        successor_kind(&intent, &old.report)?;
        if intent.old_stage_path != stopped.report["stage"]["path"]
            || intent.old_boot_id != stopped.report["terminal"]["boot_id"]
            || intent.old_boot_id != current_boot_id()?
            || intent.next_public_payload_root != root.to_str().ok_or_else(refuse)?
            || intent.next_candidate_binary != candidate.to_str().ok_or_else(refuse)?
            || intent.next_candidate_sha256 != candidate_sha
            || intent.next_installer_sha256 != installer_sha
        {
            return Err(refuse());
        }
    } else if boot_successor {
        recovery_absent(control.as_raw_fd(), LEAF)?;
        recovery_absent(control.as_raw_fd(), STOPPED_LEAF)?;
        recovery_absent(control.as_raw_fd(), "generation-pointer-stopped.json")?;
        recovery_absent(control.as_raw_fd(), "current.json")?;
        let (_, intent) = read_boot_intent(control.as_raw_fd())?;
        let (old_report, snapshot_sha) = boot_history()?;
        if intent.old_snapshot_sha256 != snapshot_sha
            || intent.old_boot_id != old_report["terminal"]["boot_id"]
            || intent.new_boot_id != current_boot_id()?
            || intent.public_payload_root != root.to_str().ok_or_else(refuse)?
            || intent.candidate_binary != candidate.to_str().ok_or_else(refuse)?
            || intent.candidate_sha256 != candidate_sha
            || intent.installer_sha256 != installer_sha
        {
            return Err(refuse());
        }
    } else if cold_successor {
        for leaf in [
            LEAF,
            STOPPED_LEAF,
            SUCCESSOR_LEAF,
            BOOT_SUCCESSOR_LEAF,
            "generation-pointer-stopped.json",
            "current.json",
        ] {
            recovery_absent(control.as_raw_fd(), leaf)?;
        }
        let (_, intent) = cold_first_arm_intent(control.as_raw_fd())?;
        if intent.public_payload_root != root.to_str().ok_or_else(refuse)?
            || intent.candidate_binary != candidate.to_str().ok_or_else(refuse)?
            || intent.candidate_sha256 != candidate_sha
            || intent.installer_sha256 != installer_sha
        {
            return Err(refuse());
        }
        let history = history_dir(control.as_raw_fd(), false)?;
        read_archived(history.as_raw_fd(), "active", &intent.old_active_sha256)?;
        read_archived(history.as_raw_fd(), "stopped", &intent.old_stopped_sha256)?;
        read_archived(
            history.as_raw_fd(),
            "intent",
            &intent.successor_intent_sha256,
        )?;
        let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
        let migration =
            recovery_directory(guardian.as_raw_fd(), "terminal-migrations", Some(0o700))?;
        let cold = recovery_directory(migration.as_raw_fd(), "cold-recovery", Some(0o700))?;
        let prebind = read_sealed_leaf_bounded(cold.as_raw_fd(), "cold-denied-prebind.json", 8192)?;
        let ready = read_sealed_leaf_bounded(cold.as_raw_fd(), "transition-ready.json", 4096)?;
        if digest(&prebind) != intent.cold_prebind_sha256
            || digest(&ready) != intent.transition_ready_sha256
        {
            return Err(refuse());
        }
    } else {
        // An interrupted or previously active installation cannot mint a new
        // first generation merely because its fixed active leaf is missing.
        for leaf in [
            LEAF,
            STOPPED_LEAF,
            "generation-pointer-stopped.json",
            "current.json",
            "prepare-current.json",
            "prepare-completed.json",
            "prepare-stage-created.json",
        ] {
            recovery_absent(control.as_raw_fd(), leaf)?;
        }
        recovery_absent(control.as_raw_fd(), HISTORY_DIR)?;
    }
    lock.revalidate().map_err(|_| refuse())?;
    Ok(())
}

/// The closed boot Prepare verb carries this exact protected intent into its
/// durable handoff. Ordinary Prepare never receives or serializes this value.
pub(super) fn verified_boot_prepare_intent(
    root: &Path,
    candidate: &Path,
    lock: &InstallLock,
) -> Result<String> {
    verify_prepare_source(root, candidate, lock)?;
    reopened_boot_prepare_intent(root, candidate, lock)
}

/// Completion runs after the new fixed Prepare leaf exists, so replaying
/// boot_history would compare that leaf with the older v3 pointer's archive.
/// The full old-history check preceded creation under this same Install OFD;
/// completion reopens only its exact live boot/source identity.
pub(super) fn reopened_boot_prepare_intent(
    root: &Path,
    candidate: &Path,
    lock: &InstallLock,
) -> Result<String> {
    lock.revalidate().map_err(|_| refuse())?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF)?;
    recovery_absent(control.as_raw_fd(), COLD_FIRST_ARM_LEAF)?;
    recovery_absent(control.as_raw_fd(), "current.json")?;
    let (raw, intent) = read_boot_intent(control.as_raw_fd())?;
    let (candidate_sha, installer_sha) = verified_retained_source(root, candidate)?;
    if intent.new_boot_id != current_boot_id()?
        || intent.public_payload_root != root.to_str().ok_or_else(refuse)?
        || intent.candidate_binary != candidate.to_str().ok_or_else(refuse)?
        || intent.candidate_sha256 != candidate_sha
        || intent.installer_sha256 != installer_sha
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    Ok(digest(&raw))
}

fn current_boot_id() -> Result<String> {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| refuse())?;
    let boot = boot.strip_suffix('\n').ok_or_else(refuse)?;
    if boot.len() != 36
        || !boot.bytes().enumerate().all(|(i, byte)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
    {
        return Err(refuse());
    }
    Ok(boot.to_owned())
}

fn stopped_pointer_receipt(
    control: i32,
    stopped: &serde_json::Value,
    expected_sha: Option<&str>,
) -> Result<Vec<u8>> {
    if expected_sha.is_none() {
        recovery_absent(control, "current.json")?;
    }
    let fixed = read_sealed_leaf(control, "generation-pointer-stopped.json");
    let bytes = if let Some(sha) = expected_sha {
        // An intent is durable before the history directory is created. On
        // that exact crash cut the still-fixed receipt is the only candidate;
        // after retirement the content-addressed archive is mandatory.
        let archived = history_dir(control, false)
            .and_then(|history| read_archived(history.as_raw_fd(), "stopped-pointer", sha));
        match (fixed, archived) {
            (Ok(a), Ok(b)) if digest(&a) == sha && a == b => a,
            (Ok(a), Ok(b)) if digest(&a) != sha => b,
            (Err(_), Ok(b)) => b,
            (Ok(a), Err(_)) if digest(&a) == sha => a,
            _ => return Err(refuse()),
        }
    } else {
        fixed?
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    let object = value.as_object().ok_or_else(refuse)?;
    if object.len() != 7
        || [
            "schema",
            "stage",
            "boot_id",
            "candidate_sha256",
            "pointer_sha256",
            "archive_leaf",
            "stopped_report_sha256",
        ]
        .iter()
        .any(|key| !object.contains_key(*key))
        || value["schema"] != "aegis_auto_v2_stopped_pointer_archive_v1"
        || value["stage"] != stopped["stage"]["path"]
        || value["boot_id"] != stopped["terminal"]["boot_id"]
        || value["candidate_sha256"] != stopped["input"]["candidate_sha256"]
        || value["stopped_report_sha256"].as_str()
            != Some(digest(&serde_json::to_vec(stopped).map_err(|_| refuse())?).as_str())
    {
        return Err(refuse());
    }
    let sha = value["pointer_sha256"].as_str().ok_or_else(refuse)?;
    if !exact_hex(sha) {
        return Err(refuse());
    }
    let leaf = format!("archived-stopped-{sha}.json");
    if value["archive_leaf"].as_str() != Some(leaf.as_str())
        || digest(&read_sealed_leaf(control, &leaf)?) != sha
        || serde_json::to_vec(&value).map_err(|_| refuse())? != bytes
    {
        return Err(refuse());
    }
    if expected_sha.is_some_and(|sha| digest(&bytes) != sha) {
        return Err(refuse());
    }
    Ok(bytes)
}

/// Reads the predecessor records before any mutation. A partially archived
/// retry may use an archived leaf only when its fixed counterpart is absent;
/// if both exist their exact bytes must agree.
pub(super) fn successor_history() -> Result<SuccessorHistory> {
    let history = successor_history_sealed()?;
    verify_old_source(&history.stopped)?;
    Ok(history)
}

/// Parse the already sealed predecessor chain without claiming that its old
/// executable still owns this boot.  The cold caller separately binds both
/// retained releases, the archived old INSTALL receipt, and current deny.
pub(super) fn successor_history_sealed() -> Result<SuccessorHistory> {
    successor_history_with_intent(None)
}

fn successor_history_with_intent(
    cold_archive: Option<(Vec<u8>, SuccessorIntent)>,
) -> Result<SuccessorHistory> {
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    if read_sealed_leaf(control.as_raw_fd(), "v2-enabled")?
        != b"{\"schema\":\"aegis_installer_auto_v2_enabled_v1\"}\n"
    {
        return Err(refuse());
    }
    recovery_absent(control.as_raw_fd(), RECOVERY_LEAF)?;
    let pending = if let Some(archived) = cold_archive {
        recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF)?;
        Some(archived)
    } else if recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF).is_ok() {
        None
    } else {
        Some(read_intent(control.as_raw_fd())?)
    };
    let fixed_active = read_sealed_leaf(control.as_raw_fd(), LEAF);
    let fixed_stopped = read_sealed_leaf(control.as_raw_fd(), STOPPED_LEAF);
    let (active_bytes, stopped_bytes) = if let Some((_, intent)) = &pending {
        let history = history_dir(control.as_raw_fd(), false).ok();
        let archived_active = history
            .as_ref()
            .ok_or_else(refuse)
            .and_then(|fd| read_archived(fd.as_raw_fd(), "active", &intent.old_active_sha256));
        let archived_stopped = history
            .as_ref()
            .ok_or_else(refuse)
            .and_then(|fd| read_archived(fd.as_raw_fd(), "stopped", &intent.old_stopped_sha256));
        let choose =
            |fixed: Result<Vec<u8>>, archived: Result<Vec<u8>>, hash: &str| match (fixed, archived)
            {
                (Ok(a), Ok(b)) if a == b && digest(&a) == hash => Ok(a),
                (Ok(a), Err(_)) if digest(&a) == hash => Ok(a),
                (Err(_), Ok(b)) if digest(&b) == hash => Ok(b),
                _ => Err(refuse()),
            };
        (
            choose(fixed_active, archived_active, &intent.old_active_sha256)?,
            choose(fixed_stopped, archived_stopped, &intent.old_stopped_sha256)?,
        )
    } else {
        (fixed_active?, fixed_stopped?)
    };
    let active = parse_active(&active_bytes)?;
    let stopped = parse_stopped(&stopped_bytes, &active_bytes, &active)?;
    if let Some(prior_sha) = active.predecessor_intent_sha256.as_deref() {
        let archived = history_dir(control.as_raw_fd(), false)?;
        let prior_raw = read_archived(archived.as_raw_fd(), "intent", prior_sha)?;
        let prior: SuccessorIntent = serde_json::from_slice(&prior_raw).map_err(|_| refuse())?;
        successor_shape(&prior)?;
        let old_prior = read_archived(archived.as_raw_fd(), "active", &prior.old_active_sha256)?;
        successor_kind(&prior, &parse_active(&old_prior)?.report)?;
        if active.report["input"]["public_payload_root"].as_str()
            != Some(prior.next_public_payload_root.as_str())
            || active.report["input"]["candidate_binary"].as_str()
                != Some(prior.next_candidate_binary.as_str())
            || active.report["input"]["candidate_sha256"].as_str()
                != Some(prior.next_candidate_sha256.as_str())
            || read_archived(archived.as_raw_fd(), "active", &prior.old_active_sha256).is_err()
            || read_archived(archived.as_raw_fd(), "stopped", &prior.old_stopped_sha256).is_err()
        {
            return Err(refuse());
        }
    }
    let prior_successor_intent_sha256 = if active.predecessor_intent_sha256.is_some()
        || active.predecessor_boot_intent_sha256.is_some()
        || active.predecessor_cold_intent_sha256.is_some()
    {
        let archived = history_dir(control.as_raw_fd(), false)?;
        most_recent_successor_sha(&active, archived.as_raw_fd(), 32)?
    } else {
        None
    };
    let stage_path = stopped.report["stage"]["path"]
        .as_str()
        .ok_or_else(refuse)?
        .to_owned();
    if let Some((_, intent)) = &pending {
        successor_kind(intent, &active.report)?;
        if intent.old_stage_path != stage_path
            || Some(intent.old_boot_id.as_str()) != stopped.report["terminal"]["boot_id"].as_str()
        {
            return Err(refuse());
        }
    }
    let pointer_receipt_bytes = stopped_pointer_receipt(
        control.as_raw_fd(),
        &stopped.report,
        pending
            .as_ref()
            .map(|(_, intent)| intent.old_pointer_receipt_sha256.as_str()),
    )?;
    let pointer_receipt_sha256 = digest(&pointer_receipt_bytes);
    Ok(SuccessorHistory {
        active: active.report,
        stopped: stopped.report,
        stage_path,
        active_bytes,
        stopped_bytes,
        pointer_receipt_bytes,
        pointer_receipt_sha256,
        intent_bytes: pending.map(|(bytes, _)| bytes),
        prior_successor_intent_sha256,
    })
}

fn cold_json(bytes: &[u8]) -> Result<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| refuse())?;
    let mut canonical = serde_json::to_vec(&value).map_err(|_| refuse())?;
    canonical.push(b'\n');
    if !value.is_object() || canonical != bytes {
        return Err(refuse());
    }
    Ok(value)
}

fn cold_exact_keys(value: &serde_json::Value, keys: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or_else(refuse)?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(refuse());
    }
    Ok(())
}

fn cold_recovery_dir() -> Result<std::os::fd::OwnedFd> {
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let migrations = recovery_directory(guardian.as_raw_fd(), "terminal-migrations", Some(0o700))?;
    recovery_directory(migrations.as_raw_fd(), "cold-recovery", Some(0o700))
}

fn cold_dir_entries(dir: i32, maximum: usize) -> Result<Vec<String>> {
    use std::os::fd::AsRawFd;
    if maximum == 0 || maximum > 512 {
        return Err(refuse());
    }
    let held = recovery_stat(dir)?;
    if held.st_mode != libc::S_IFDIR | 0o700 || held.st_uid != 0 || held.st_gid != 0 {
        return Err(refuse());
    }
    let path = format!("/proc/self/fd/{dir}");
    let opened = std::fs::File::open(&path).map_err(|_| refuse())?;
    let named = recovery_stat(opened.as_raw_fd())?;
    if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) {
        return Err(refuse());
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(path).map_err(|_| refuse())? {
        let entry = entry.map_err(|_| refuse())?;
        let name = entry.file_name().into_string().map_err(|_| refuse())?;
        if name.len() > 200
            || name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(refuse());
        }
        names.push(name);
        if names.len() > maximum {
            return Err(refuse());
        }
    }
    names.sort();
    if recovery_stat(dir)?.st_dev != held.st_dev || recovery_stat(dir)?.st_ino != held.st_ino {
        return Err(refuse());
    }
    Ok(names)
}

fn cold_rollover_barrier(
    cold: i32,
    expected_sha: &str,
    original_sha: &str,
    original: &serde_json::Value,
) -> Result<Vec<u8>> {
    if !exact_hex(expected_sha) {
        return Err(refuse());
    }
    let consumed = format!("rollover-barrier-consumed-{expected_sha}.json");
    let active_raw = if recovery_absent(cold, "rollover-barrier.json").is_err() {
        Some(read_sealed_leaf_bounded(
            cold,
            "rollover-barrier.json",
            4096,
        )?)
    } else {
        None
    };
    let consumed_raw = if recovery_absent(cold, &consumed).is_err() {
        Some(read_sealed_leaf_bounded(cold, &consumed, 4096)?)
    } else {
        None
    };
    let raw = active_raw
        .as_ref()
        .or(consumed_raw.as_ref())
        .ok_or_else(refuse)?;
    if digest(raw) != expected_sha
        || active_raw.as_ref().is_some_and(|value| value != raw)
        || consumed_raw.as_ref().is_some_and(|value| value != raw)
    {
        return Err(refuse());
    }
    let value = cold_json(raw)?;
    cold_exact_keys(
        &value,
        &[
            "schema",
            "original_intent_sha256",
            "original_boot_id",
            "retained_root",
            "new_candidate_sha256",
            "next_bundle_manifest_sha256",
            "next_sums_sha256",
        ],
    )?;
    if value["schema"] != "aegis_auto_terminal_cold_rollover_barrier_v1"
        || value["original_intent_sha256"] != original_sha
        || value["original_boot_id"] != original["current_boot_id"]
        || value["retained_root"] != original["retained_root"]
        || value["new_candidate_sha256"] != original["new_candidate_sha256"]
        || value["next_bundle_manifest_sha256"] != original["next_bundle_manifest_sha256"]
        || value["next_sums_sha256"] != original["next_sums_sha256"]
    {
        return Err(refuse());
    }
    Ok(raw.clone())
}

fn cold_selected_barrier_sha(
    cold: i32,
    original_sha: &str,
    original: &serde_json::Value,
) -> Result<Option<String>> {
    let active = if recovery_absent(cold, "rollover-barrier.json").is_err() {
        Some(read_sealed_leaf_bounded(
            cold,
            "rollover-barrier.json",
            4096,
        )?)
    } else {
        None
    };
    let consumed: Vec<_> = cold_dir_entries(cold, 512)?
        .into_iter()
        .filter(|name| name.starts_with("rollover-barrier-consumed-"))
        .collect();
    if consumed.len() > 1 {
        return Err(refuse());
    }
    let selected = if let Some(raw) = active {
        raw
    } else if let Some(name) = consumed.first() {
        read_sealed_leaf_bounded(cold, name, 4096)?
    } else {
        return Ok(None);
    };
    let sha = digest(&selected);
    if consumed
        .first()
        .is_some_and(|name| name != &format!("rollover-barrier-consumed-{sha}.json"))
    {
        return Err(refuse());
    }
    cold_rollover_barrier(cold, &sha, original_sha, original)?;
    Ok(Some(sha))
}

fn cold_rotation_leaf(
    guardian: i32,
    active: &str,
    archive_prefix: &str,
    expected_sha: &str,
) -> Result<Vec<u8>> {
    if !exact_hex(expected_sha) {
        return Err(refuse());
    }
    let raw = if recovery_absent(guardian, active).is_err() {
        read_sealed_leaf_bounded(guardian, active, 1 << 20)?
    } else {
        let name = format!("{archive_prefix}-{expected_sha}.json");
        read_sealed_leaf_bounded(guardian, &name, 1 << 20)?
    };
    if digest(&raw) != expected_sha {
        return Err(refuse());
    }
    Ok(raw)
}

struct ColdPriorAttempt {
    original_raw: Vec<u8>,
    original_sha: String,
    original_state: &'static str,
    prior_raw: Vec<u8>,
    prior_sha: String,
    prior_boot: String,
    ancestor_boot_ids: Vec<String>,
    orphan_parent_sha: Option<String>,
    orphan_parent_boot: Option<String>,
    current_head_sha: Option<String>,
    current_intent_sha: Option<String>,
}

/// Resolve immutable prior attempts from the held cold directory. This only
/// selects historical bytes; a caller must separately prove the fresh boot's
/// kernel deny, actor absence and retained B source before any mutation.
fn cold_prior_attempt(
    cold: i32,
    current_boot: &str,
    allow_unpublished_stage: bool,
) -> Result<ColdPriorAttempt> {
    let entries = cold_dir_entries(cold, 512)?;
    let head_names: Vec<_> = entries
        .iter()
        .filter(|name| name.starts_with("attempt-head-"))
        .collect();
    if head_names.len() > 32 {
        return Err(refuse());
    }
    let active_original = recovery_absent(cold, "intent.json").is_err();
    let original_raw = if active_original {
        read_sealed_leaf_bounded(cold, "intent.json", 8192)?
    } else if recovery_absent(cold, "transition-ready.json").is_err() {
        let ready_raw = read_sealed_leaf_bounded(cold, "transition-ready.json", 4096)?;
        let ready = cold_json(&ready_raw)?;
        cold_exact_keys(
            &ready,
            &[
                "schema",
                "current_boot_id",
                "intent_sha256",
                "cold_prebind_sha256",
                "source_config_sha256",
                "observer_ready_sha256",
                "site_readback_sha256",
                "deny_policy_sha256",
                "consumed_intent_leaf",
                "consumed_pending_leaf",
            ],
        )?;
        if ready["schema"] != "aegis_auto_terminal_cold_transition_ready_v1" {
            return Err(refuse());
        }
        let sha = cold_hex(&ready["intent_sha256"])?;
        let name = format!("intent-consumed-{sha}.json");
        if ready["consumed_intent_leaf"] != name {
            return Err(refuse());
        }
        let raw = read_sealed_leaf_bounded(cold, &name, 8192)?;
        if digest(&raw) != sha {
            return Err(refuse());
        }
        raw
    } else {
        // The first rollover may have consumed the original intent using a
        // per-attempt ready. Every head must then agree on its original SHA.
        let first = head_names.first().ok_or_else(refuse)?;
        let raw = read_sealed_leaf_bounded(cold, first, 4096)?;
        let value = cold_json(&raw)?;
        let sha = cold_hex(&value["original_intent_sha256"])?;
        let raw = read_sealed_leaf_bounded(cold, &format!("intent-consumed-{sha}.json"), 8192)?;
        if digest(&raw) != sha {
            return Err(refuse());
        }
        raw
    };
    let original = cold_json(&original_raw)?;
    cold_exact_keys(
        &original,
        &[
            "schema",
            "old_boot_id",
            "current_boot_id",
            "old_active_sha256",
            "old_stopped_sha256",
            "successor_intent_sha256",
            "old_install_sha256",
            "old_source_sha256",
            "guardian_rotation_intent_sha256",
            "guardian_rotation_denied_sha256",
            "guardian_rotation_retired_sha256",
            "retained_root",
            "new_candidate_sha256",
            "new_package_sha256",
            "selected_manager",
            "manager31_sha256",
            "guard30_sha256",
            "old_context_sha256",
            "deny_policy_sha256",
            "initial_denied_proof_sha256",
            "initial_infrastructure_rows_sha256",
            "next_bundle_manifest_sha256",
            "next_sums_sha256",
        ],
    )?;
    if original["schema"] != "aegis_auto_terminal_cold_intent_v1"
        || original["current_boot_id"] == current_boot
    {
        return Err(refuse());
    }
    let original_sha = digest(&original_raw);
    if active_original {
        recovery_absent(cold, &format!("intent-consumed-{original_sha}.json"))?;
    }
    let original_boot = original["current_boot_id"]
        .as_str()
        .ok_or_else(refuse)?
        .to_owned();
    let attempts = if recovery_absent(cold, "attempts").is_ok() {
        None
    } else {
        Some(recovery_directory(cold, "attempts", Some(0o700))?)
    };
    let mut next_by_parent =
        std::collections::BTreeMap::<String, (String, String, String, String, String)>::new();
    let mut expected_directories = std::collections::BTreeSet::<String>::new();
    for name in head_names {
        let raw = read_sealed_leaf_bounded(cold, name, 4096)?;
        let head = cold_json(&raw)?;
        cold_exact_keys(
            &head,
            &[
                "schema",
                "current_boot_id",
                "prior_boot_id",
                "prior_intent_sha256",
                "original_intent_sha256",
                "barrier_sha256",
                "attempt_intent_sha256",
                "attempt_dir",
            ],
        )?;
        let boot = head["current_boot_id"].as_str().ok_or_else(refuse)?;
        let prior_boot = head["prior_boot_id"].as_str().ok_or_else(refuse)?;
        let parent_sha = cold_hex(&head["prior_intent_sha256"])?;
        let attempt_sha = cold_hex(&head["attempt_intent_sha256"])?;
        let dirname = format!("{boot}-{parent_sha}");
        if head["schema"] != "aegis_auto_terminal_cold_attempt_head_v1"
            || head["original_intent_sha256"] != original_sha
            || head["attempt_dir"]
                != format!(
                    "/var/lib/aegis-install/client/terminal-migrations/cold-recovery/attempts/{dirname}"
                )
            || *name != format!("attempt-head-{boot}-{attempt_sha}.json")
            || next_by_parent.contains_key(parent_sha)
            || !expected_directories.insert(dirname.clone())
        {
            return Err(refuse());
        }
        if head["barrier_sha256"].is_null() {
            let bound_name = format!("barrier-bound-{attempt_sha}.json");
            if recovery_absent(cold, &bound_name).is_err() {
                let bound_raw = read_sealed_leaf_bounded(cold, &bound_name, 4096)?;
                let bound = cold_json(&bound_raw)?;
                cold_exact_keys(
                    &bound,
                    &[
                        "schema",
                        "current_boot_id",
                        "attempt_head_sha256",
                        "attempt_intent_sha256",
                        "barrier_sha256",
                        "original_intent_sha256",
                    ],
                )?;
                let barrier_sha = cold_hex(&bound["barrier_sha256"])?;
                let barrier_raw =
                    cold_rollover_barrier(cold, barrier_sha, &original_sha, &original)?;
                if bound["schema"] != "aegis_auto_terminal_cold_barrier_bound_v1"
                    || bound["current_boot_id"] != boot
                    || bound["attempt_head_sha256"] != digest(&raw)
                    || bound["attempt_intent_sha256"] != attempt_sha
                    || bound["barrier_sha256"] != digest(&barrier_raw)
                    || bound["original_intent_sha256"] != original_sha
                {
                    return Err(refuse());
                }
            } else if !active_original {
                // A null immutable head is only an intermediate pre-B cut
                // while the original sticky intent is still active.
                return Err(refuse());
            }
        } else {
            let barrier_sha = cold_hex(&head["barrier_sha256"])?;
            let barrier_raw = cold_rollover_barrier(cold, barrier_sha, &original_sha, &original)?;
            if digest(&barrier_raw) != barrier_sha {
                return Err(refuse());
            }
        }
        let dir = attempts.as_ref().ok_or_else(refuse)?;
        let attempt = recovery_directory(dir.as_raw_fd(), &dirname, Some(0o700))?;
        let attempt_raw = if recovery_absent(attempt.as_raw_fd(), "intent.json").is_err() {
            read_sealed_leaf_bounded(attempt.as_raw_fd(), "intent.json", 8192)?
        } else {
            read_sealed_leaf_bounded(
                attempt.as_raw_fd(),
                &format!("intent-consumed-{attempt_sha}.json"),
                8192,
            )?
        };
        let intent = cold_json(&attempt_raw)?;
        cold_exact_keys(
            &intent,
            &[
                "schema",
                "old_boot_id",
                "current_boot_id",
                "old_active_sha256",
                "old_stopped_sha256",
                "successor_intent_sha256",
                "old_install_sha256",
                "old_source_sha256",
                "guardian_rotation_intent_sha256",
                "guardian_rotation_denied_sha256",
                "guardian_rotation_retired_sha256",
                "retained_root",
                "new_candidate_sha256",
                "new_package_sha256",
                "selected_manager",
                "manager31_sha256",
                "guard30_sha256",
                "old_context_sha256",
                "deny_policy_sha256",
                "initial_denied_proof_sha256",
                "initial_infrastructure_rows_sha256",
                "next_bundle_manifest_sha256",
                "next_sums_sha256",
            ],
        )?;
        if digest(&attempt_raw) != attempt_sha
            || intent["schema"] != "aegis_auto_terminal_cold_intent_v1"
            || intent["current_boot_id"] != boot
        {
            return Err(refuse());
        }
        next_by_parent.insert(
            parent_sha.to_owned(),
            (
                attempt_sha.to_owned(),
                boot.to_owned(),
                prior_boot.to_owned(),
                digest(&raw),
                dirname,
            ),
        );
    }
    let mut prior_sha = original_sha.clone();
    let mut prior_boot = original_boot;
    let mut ancestor_boot_ids = vec![prior_boot.clone()];
    let mut seen = 0;
    let mut current_head_sha = None;
    let mut current_intent_sha = None;
    let mut prior_dirname = None;
    while let Some((next_sha, next_boot, expected_prior_boot, head_sha, dirname)) =
        next_by_parent.get(&prior_sha)
    {
        if seen >= 32 || next_boot == &prior_boot || expected_prior_boot != &prior_boot {
            return Err(refuse());
        }
        seen += 1;
        if next_boot == current_boot {
            current_head_sha = Some(head_sha.clone());
            current_intent_sha = Some(next_sha.clone());
            break;
        }
        prior_sha = next_sha.clone();
        prior_boot = next_boot.clone();
        ancestor_boot_ids.push(prior_boot.clone());
        prior_dirname = Some(dirname.clone());
    }
    if seen != next_by_parent.len() {
        return Err(refuse());
    }
    let mut orphan_raw = None;
    let mut orphan_parent_sha = None;
    let mut orphan_parent_boot = None;
    if let Some(dir) = attempts.as_ref() {
        let found: std::collections::BTreeSet<_> =
            cold_dir_entries(dir.as_raw_fd(), 64)?.into_iter().collect();
        let extras: Vec<_> = found.difference(&expected_directories).collect();
        if extras.len() > 2
            || expected_directories.difference(&found).next().is_some()
            || extras.len() == 2
                && !(allow_unpublished_stage
                    && extras
                        .iter()
                        .filter(|name| name.starts_with("stage-"))
                        .count()
                        == 1)
        {
            return Err(refuse());
        }
        // A crash may leave one unpublished stage and one prior-boot
        // intent-only final directory. Authenticate the stage against the
        // predecessor before advancing the predecessor through the orphan.
        for name in extras
            .iter()
            .filter(|name| name.starts_with("stage-"))
            .chain(extras.iter().filter(|name| !name.starts_with("stage-")))
        {
            if name.starts_with("stage-") {
                if !allow_unpublished_stage || current_head_sha.is_some() {
                    return Err(refuse());
                }
                let suffix = format!("-{prior_sha}");
                let stage_boot = name
                    .strip_prefix("stage-")
                    .and_then(|value| value.strip_suffix(&suffix))
                    .ok_or_else(refuse)?;
                if stage_boot == prior_boot
                    || stage_boot.len() != 36
                    || !stage_boot.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                        }
                    })
                {
                    return Err(refuse());
                }
                let stage = recovery_directory(dir.as_raw_fd(), name, Some(0o700))?;
                let stage_names = cold_dir_entries(stage.as_raw_fd(), 2)?;
                if !(stage_names.is_empty()
                    || stage_names.len() == 1 && stage_names[0] == "intent.json")
                {
                    return Err(refuse());
                }
                if stage_names.len() == 1 {
                    let raw = read_sealed_leaf_bounded(stage.as_raw_fd(), "intent.json", 8192)?;
                    let value = cold_json(&raw)?;
                    if value["schema"] != "aegis_auto_terminal_cold_intent_v1"
                        || value["current_boot_id"] != stage_boot
                        || value["successor_intent_sha256"] != original["successor_intent_sha256"]
                        || value["next_bundle_manifest_sha256"]
                            != original["next_bundle_manifest_sha256"]
                        || value["next_sums_sha256"] != original["next_sums_sha256"]
                    {
                        return Err(refuse());
                    }
                }
            } else {
                // A prior boot may have durably published its intent before its
                // head. No phase or ready byte can be carried across that cut.
                let suffix = format!("-{prior_sha}");
                let orphan_boot = name.strip_suffix(&suffix).ok_or_else(refuse)?;
                if orphan_boot == prior_boot
                    || orphan_boot.len() != 36
                    || !orphan_boot.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                        }
                    })
                    || current_head_sha.is_some()
                {
                    return Err(refuse());
                }
                let orphan = recovery_directory(dir.as_raw_fd(), name, Some(0o700))?;
                let orphan_names = cold_dir_entries(orphan.as_raw_fd(), 4)?;
                if orphan_names.len() != 1 || orphan_names[0] != "intent.json" {
                    return Err(refuse());
                }
                let raw = read_sealed_leaf_bounded(orphan.as_raw_fd(), "intent.json", 8192)?;
                let value = cold_json(&raw)?;
                cold_exact_keys(
                    &value,
                    &[
                        "schema",
                        "old_boot_id",
                        "current_boot_id",
                        "old_active_sha256",
                        "old_stopped_sha256",
                        "successor_intent_sha256",
                        "old_install_sha256",
                        "old_source_sha256",
                        "guardian_rotation_intent_sha256",
                        "guardian_rotation_denied_sha256",
                        "guardian_rotation_retired_sha256",
                        "retained_root",
                        "new_candidate_sha256",
                        "new_package_sha256",
                        "selected_manager",
                        "manager31_sha256",
                        "guard30_sha256",
                        "old_context_sha256",
                        "deny_policy_sha256",
                        "initial_denied_proof_sha256",
                        "initial_infrastructure_rows_sha256",
                        "next_bundle_manifest_sha256",
                        "next_sums_sha256",
                    ],
                )?;
                if value["schema"] != "aegis_auto_terminal_cold_intent_v1"
                    || value["current_boot_id"] != orphan_boot
                    || value["successor_intent_sha256"] != original["successor_intent_sha256"]
                    || value["next_bundle_manifest_sha256"]
                        != original["next_bundle_manifest_sha256"]
                    || value["next_sums_sha256"] != original["next_sums_sha256"]
                {
                    return Err(refuse());
                }
                if orphan_boot == current_boot {
                    current_intent_sha = Some(digest(&raw));
                } else {
                    orphan_parent_sha = Some(prior_sha.clone());
                    orphan_parent_boot = Some(prior_boot.clone());
                    prior_sha = digest(&raw);
                    prior_boot = orphan_boot.to_owned();
                    ancestor_boot_ids.push(prior_boot.clone());
                    orphan_raw = Some(raw);
                }
            }
        }
    }
    let prior_raw = if prior_sha == original_sha {
        original_raw.clone()
    } else if let Some(raw) = orphan_raw {
        raw
    } else {
        let dir = attempts.as_ref().ok_or_else(refuse)?;
        let name = prior_dirname.as_deref().ok_or_else(refuse)?;
        let attempt = recovery_directory(dir.as_raw_fd(), name, Some(0o700))?;
        let active = recovery_absent(attempt.as_raw_fd(), "intent.json").is_err();
        let leaf = if active {
            "intent.json".to_owned()
        } else {
            format!("intent-consumed-{prior_sha}.json")
        };
        let raw = read_sealed_leaf_bounded(attempt.as_raw_fd(), &leaf, 8192)?;
        if digest(&raw) != prior_sha {
            return Err(refuse());
        }
        raw
    };
    Ok(ColdPriorAttempt {
        original_raw,
        original_sha,
        original_state: if active_original {
            "active"
        } else {
            "consumed"
        },
        prior_raw,
        prior_sha,
        prior_boot,
        ancestor_boot_ids,
        orphan_parent_sha,
        orphan_parent_boot,
        current_head_sha,
        current_intent_sha,
    })
}

/// Compute only the immutable bytes for a unique, intent-only historical
/// orphan. Publication requires a separate fresh-lock denial proof and is not
/// performed by this read-only source parser.
fn cold_orphan_head_candidate(cold: i32, current_boot: &str) -> Result<Option<(String, Vec<u8>)>> {
    let prior = cold_prior_attempt(cold, current_boot, false)?;
    let Some(parent_sha) = prior.orphan_parent_sha.as_deref() else {
        return Ok(None);
    };
    let parent_boot = prior.orphan_parent_boot.as_deref().ok_or_else(refuse)?;
    let barrier_sha = if prior.original_state == "active" {
        recovery_absent(cold, "rollover-barrier.json")?;
        serde_json::Value::Null
    } else {
        let raw = read_sealed_leaf_bounded(cold, "rollover-barrier.json", 4096)?;
        let sha = digest(&raw);
        cold_rollover_barrier(
            cold,
            &sha,
            &prior.original_sha,
            &cold_json(&prior.original_raw)?,
        )?;
        serde_json::json!(sha)
    };
    let name = format!("attempt-head-{}-{}.json", prior.prior_boot, prior.prior_sha);
    let head = serde_json::json!({
        "schema": "aegis_auto_terminal_cold_attempt_head_v1",
        "current_boot_id": &prior.prior_boot,
        "prior_boot_id": parent_boot,
        "prior_intent_sha256": parent_sha,
        "original_intent_sha256": &prior.original_sha,
        "barrier_sha256": barrier_sha,
        "attempt_intent_sha256": &prior.prior_sha,
        "attempt_dir": format!("/var/lib/aegis-install/client/terminal-migrations/cold-recovery/attempts/{}-{}",
            prior.prior_boot, parent_sha),
    });
    let mut raw = serde_json::to_vec(&head).map_err(|_| refuse())?;
    raw.push(b'\n');
    if raw.len() > 4096 {
        return Err(refuse());
    }
    Ok(Some((name, raw)))
}

pub(super) fn complete_cold_orphan_head(
    root: &Path,
    expected_prior_sha: &str,
    proof: &serde_json::Value,
    lock: &InstallLock,
) -> Result<Vec<u8>> {
    lock.revalidate().map_err(|_| refuse())?;
    let source = cold_stale_source(root)?;
    let current_boot = current_boot_id()?;
    if !exact_hex(expected_prior_sha)
        || source.prior_intent_sha256 != expected_prior_sha
        || proof["schema"] != "aegis_auto_v2_cold_stale_verification_v1"
        || proof["current_boot_id"] != current_boot
        || proof["prior_boot_id"] != source.prior_boot_id
        || proof["prior_intent_sha256"] != expected_prior_sha
        || proof["original_intent_sha256"] != source.original_intent_sha256
        || proof["new_candidate_sha256"] != source.bootstrap.candidate_sha256
        || proof["retained_root"].as_str() != root.to_str()
        || cold_hex(&proof["prior_pointer_retirement_sha256"]).is_err()
        || cold_hex(&proof["deny_policy_sha256"]).is_err()
        || cold_hex(&proof["guard30_sha256"]).is_err()
        || proof["client_actors_absent"] != true
        || proof["jobs_absent"] != true
        || proof["cgroups_empty"] != true
        || proof["stop_intent_absent"] != true
        || proof["no_client_grant"] != true
    {
        return Err(refuse());
    }
    let cold = cold_recovery_dir()?;
    let candidate = cold_orphan_head_candidate(cold.as_raw_fd(), &current_boot)?;
    let (orphan_sha, head_sha) = if let Some((name, raw)) = candidate {
        let orphan_sha = source.prior_intent_sha256.clone();
        write_passive_atomic(cold.as_raw_fd(), &name, &raw, 4096)?;
        if read_sealed_leaf_bounded(cold.as_raw_fd(), &name, 4096)? != raw {
            return Err(refuse());
        }
        (Some(orphan_sha), Some(digest(&raw)))
    } else {
        (None, None)
    };
    let after = cold_stale_source(root)?;
    if after.prior_intent_sha256 != source.prior_intent_sha256
        || after.original_intent_sha256 != source.original_intent_sha256
        || after.bootstrap.candidate_sha256 != source.bootstrap.candidate_sha256
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_cold_orphan_head_completion_v1",
        "current_boot_id": current_boot,
        "prior_intent_sha256": expected_prior_sha,
        "old_orphan_intent_sha256": orphan_sha,
        "old_head_sha256": head_sha,
        "no_client_grant": true,
    }))
    .map_err(|_| refuse())
}

/// Source-qualified unpublished attempt debris. A final attempt directory is
/// never retired here; only its exact `stage-*` predecessor may move to an
/// immutable no-replace archive. A crash after rename completes the receipt.
pub(super) fn retire_cold_unpublished_stage(
    root: &Path,
    expected_prior_sha: &str,
    proof: &serde_json::Value,
    lock: &InstallLock,
) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    lock.revalidate().map_err(|_| refuse())?;
    let source = cold_stale_source_for_stage(root)?;
    let boot = current_boot_id()?;
    if !exact_hex(expected_prior_sha)
        || source.prior_intent_sha256 != expected_prior_sha
        || proof["schema"] != "aegis_auto_v2_cold_stale_preretire_v1"
        || proof["current_boot_id"] != boot
        || proof["prior_intent_sha256"] != expected_prior_sha
        || proof["original_intent_sha256"] != source.original_intent_sha256
        || proof["new_candidate_sha256"] != source.bootstrap.candidate_sha256
        || proof["retained_root"].as_str() != root.to_str()
        || proof["client_actors_absent"] != true
        || proof["jobs_absent"] != true
        || proof["cgroups_empty"] != true
        || proof["stop_intent_absent"] != true
        || proof["no_client_grant"] != true
        || cold_hex(&proof["deny_policy_sha256"]).is_err()
        || cold_hex(&proof["guard30_sha256"]).is_err()
    {
        return Err(refuse());
    }
    let cold = cold_recovery_dir()?;
    if recovery_absent(cold.as_raw_fd(), "attempts").is_ok() {
        return serde_json::to_vec(&serde_json::json!({
            "schema":"aegis_auto_v2_cold_unpublished_stage_retirement_v1",
            "current_boot_id":boot,"prior_intent_sha256":expected_prior_sha,
            "stage_name":null,"stage_archive_sha256":null,"no_client_grant":true,
        }))
        .map_err(|_| refuse());
    }
    let attempts = recovery_directory(cold.as_raw_fd(), "attempts", Some(0o700))?;
    let names = cold_dir_entries(attempts.as_raw_fd(), 64)?;
    let stages: Vec<_> = names
        .iter()
        .filter(|name| name.starts_with("stage-"))
        .collect();
    if stages.len() > 1 {
        return Err(refuse());
    }
    let mut incomplete = Vec::new();
    for name in cold_dir_entries(cold.as_raw_fd(), 512)? {
        if let Some(suffix) = name.strip_prefix("stage-retired-") {
            if suffix.len() != 36 + 1 + 64 || !suffix.ends_with(&format!("-{expected_prior_sha}")) {
                continue;
            }
            let receipt_name = format!("stage-retirement-{suffix}.json");
            if recovery_absent(cold.as_raw_fd(), &receipt_name).is_ok() {
                incomplete.push(suffix.to_owned());
            }
        }
    }
    if incomplete.len() > 1 || !stages.is_empty() && !incomplete.is_empty() {
        return Err(refuse());
    }
    let chosen = if let Some(name) = stages.first() {
        let suffix = name.strip_prefix("stage-").ok_or_else(refuse)?;
        if suffix.len() != 36 + 1 + 64 || !suffix.ends_with(&format!("-{expected_prior_sha}")) {
            return Err(refuse());
        }
        Some(((*name).clone(), suffix.to_owned(), true))
    } else {
        incomplete
            .first()
            .map(|suffix| (format!("stage-{suffix}"), suffix.clone(), false))
    };
    let Some((stage_name, suffix, active)) = chosen else {
        return serde_json::to_vec(&serde_json::json!({
            "schema":"aegis_auto_v2_cold_unpublished_stage_retirement_v1",
            "current_boot_id":boot,"prior_intent_sha256":expected_prior_sha,
            "stage_name":null,"stage_archive_sha256":null,"no_client_grant":true,
        }))
        .map_err(|_| refuse());
    };
    let archive_name = format!("stage-retired-{suffix}");
    let stage_parent = if active {
        attempts.as_raw_fd()
    } else {
        cold.as_raw_fd()
    };
    let stage_leaf = if active {
        stage_name.as_str()
    } else {
        archive_name.as_str()
    };
    let stage = recovery_directory(stage_parent, stage_leaf, Some(0o700))?;
    let entries = cold_dir_entries(stage.as_raw_fd(), 2)?;
    if !(entries.is_empty() || entries.len() == 1 && entries[0] == "intent.json") {
        return Err(refuse());
    }
    let intent_sha = if entries.is_empty() {
        None
    } else {
        let raw = read_sealed_leaf_bounded(stage.as_raw_fd(), "intent.json", 8192)?;
        let value = cold_json(&raw)?;
        cold_exact_keys(
            &value,
            &[
                "schema",
                "old_boot_id",
                "current_boot_id",
                "old_active_sha256",
                "old_stopped_sha256",
                "successor_intent_sha256",
                "old_install_sha256",
                "old_source_sha256",
                "guardian_rotation_intent_sha256",
                "guardian_rotation_denied_sha256",
                "guardian_rotation_retired_sha256",
                "retained_root",
                "new_candidate_sha256",
                "new_package_sha256",
                "selected_manager",
                "manager31_sha256",
                "guard30_sha256",
                "old_context_sha256",
                "deny_policy_sha256",
                "initial_denied_proof_sha256",
                "initial_infrastructure_rows_sha256",
                "next_bundle_manifest_sha256",
                "next_sums_sha256",
            ],
        )?;
        if value["schema"] != "aegis_auto_terminal_cold_intent_v1"
            || value["successor_intent_sha256"] != source.bootstrap.successor_intent_sha256
            || value["new_candidate_sha256"] != source.bootstrap.candidate_sha256
            || value["next_bundle_manifest_sha256"] != source.bootstrap.bundle_manifest_sha256
            || value["next_sums_sha256"] != source.bootstrap.sums_sha256
            || value["retained_root"].as_str() != root.to_str()
        {
            return Err(refuse());
        }
        Some(digest(&raw))
    };
    if active {
        recovery_absent(cold.as_raw_fd(), &archive_name)?;
        let old = std::ffi::CString::new(stage_name.as_str()).map_err(|_| refuse())?;
        let new = std::ffi::CString::new(archive_name.as_str()).map_err(|_| refuse())?;
        if unsafe {
            libc::renameat2(
                attempts.as_raw_fd(),
                old.as_ptr(),
                cold.as_raw_fd(),
                new.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
            || unsafe { libc::fsync(attempts.as_raw_fd()) } != 0
            || unsafe { libc::fsync(cold.as_raw_fd()) } != 0
        {
            return Err(refuse());
        }
    }
    let archived = recovery_directory(cold.as_raw_fd(), &archive_name, Some(0o700))?;
    if cold_dir_entries(archived.as_raw_fd(), 2)? != entries {
        return Err(refuse());
    }
    let receipt = serde_json::json!({
        "schema":"aegis_auto_v2_cold_unpublished_stage_retirement_v1",
        "current_boot_id":boot,"prior_intent_sha256":expected_prior_sha,
        "stage_name":stage_name,"archive_name":archive_name,
        "stage_intent_sha256":intent_sha,
        "deny_policy_sha256":proof["deny_policy_sha256"],
        "guard30_sha256":proof["guard30_sha256"],"no_client_grant":true,
    });
    let mut raw = serde_json::to_vec(&receipt).map_err(|_| refuse())?;
    raw.push(b'\n');
    let receipt_name = format!("stage-retirement-{suffix}.json");
    write_passive_atomic(cold.as_raw_fd(), &receipt_name, &raw, 4096)?;
    if read_sealed_leaf_bounded(cold.as_raw_fd(), &receipt_name, 4096)? != raw
        || recovery_absent(attempts.as_raw_fd(), &stage_name).is_err()
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema":"aegis_auto_v2_cold_unpublished_stage_retirement_v1",
        "current_boot_id":boot,"prior_intent_sha256":expected_prior_sha,
        "stage_name":stage_name,"stage_archive_sha256":digest(&raw),
        "no_client_grant":true,
    }))
    .map_err(|_| refuse())
}

/// Archive and retire the prior B pointer under a fresh denied-boot proof.
/// An immutable intent precedes all unlinks; every leaf has a source-bound
/// archived twin, so a crash after any unlink can finish under fresh proof.
pub(super) fn retire_cold_prior_pointer(
    root: &Path,
    expected_prior_sha: &str,
    proof: &serde_json::Value,
    lock: &InstallLock,
) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    lock.revalidate().map_err(|_| refuse())?;
    let source = cold_stale_source_for_stage(root)?;
    let boot = current_boot_id()?;
    if source.prior_intent_sha256 != expected_prior_sha
        || proof["schema"] != "aegis_auto_v2_cold_stale_preretire_v1"
        || proof["current_boot_id"] != boot
        || proof["prior_intent_sha256"] != expected_prior_sha
        || proof["original_intent_sha256"] != source.original_intent_sha256
        || proof["old_pointer_state"] != source.prior_pointer_state
        || proof["retained_root"].as_str() != root.to_str()
        || proof["client_actors_absent"] != true
        || proof["jobs_absent"] != true
        || proof["cgroups_empty"] != true
        || proof["stop_intent_absent"] != true
        || proof["no_client_grant"] != true
        || cold_hex(&proof["deny_policy_sha256"]).is_err()
        || cold_hex(&proof["guard30_sha256"]).is_err()
    {
        return Err(refuse());
    }
    let cold = cold_recovery_dir()?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let history = history_dir(control.as_raw_fd(), true)?;
    let existing =
        cold_pointer_retire_intent(expected_prior_sha, &source.original_intent_sha256, root)?;
    let state = source.prior_pointer_state;
    if !["absent", "unsealed", "sealed", "sealed_incomplete"].contains(&state) {
        return Err(refuse());
    }
    let expected = existing.as_ref();
    let active_raw = if matches!(state, "sealed" | "sealed_incomplete") {
        let live = read_sealed_leaf(control.as_raw_fd(), LEAF);
        let archived = expected
            .and_then(|row| row["active_generation_sha256"].as_str())
            .and_then(|sha| {
                read_archived(history.as_raw_fd(), "passive-cold-prior-active", sha).ok()
            });
        Some(match (live, archived) {
            (Ok(a), Some(b)) if a == b => a,
            (Ok(a), None) => a,
            (Err(_), Some(b)) => b,
            _ => return Err(refuse()),
        })
    } else {
        None
    };
    let unsealed_raw = if state == "unsealed" {
        let live = read_sealed_leaf(control.as_raw_fd(), RECOVERY_LEAF);
        let archived = expected
            .and_then(|row| row["unsealed_recovery_sha256"].as_str())
            .and_then(|sha| {
                read_archived(history.as_raw_fd(), "passive-cold-prior-unsealed", sha).ok()
            });
        Some(match (live, archived) {
            (Ok(a), Some(b)) if a == b => a,
            (Ok(a), None) => a,
            (Err(_), Some(b)) => b,
            _ => return Err(refuse()),
        })
    } else {
        None
    };
    let report = if let Some(raw) = &active_raw {
        parse_active(raw)?.report
    } else if let Some(raw) = &unsealed_raw {
        validate_unsealed_stopped_recovery_bytes(raw)?
    } else {
        serde_json::Value::Null
    };
    let pointer_raw = if state == "absent" {
        None
    } else {
        let sha = expected.and_then(|row| row["old_pointer_sha256"].as_str());
        Some(boot_pointer(control.as_raw_fd(), &report, sha)?)
    };
    let activation_sha = if matches!(state, "sealed" | "sealed_incomplete") {
        let unit = report["terminal"]["private_unit"]
            .as_str()
            .ok_or_else(refuse)?;
        let token = unit
            .strip_prefix("aegis-auto@")
            .and_then(|v| v.strip_suffix(".service"))
            .filter(|v| exact_hex(v))
            .ok_or_else(refuse)?;
        let leaf = if state == "sealed" {
            format!("auto-terminal-activation-{token}.json")
        } else {
            format!("auto-terminal-activation-preseal-{token}.json")
        };
        Some(digest(&read_sealed_leaf_bounded(
            guardian.as_raw_fd(),
            &leaf,
            4096,
        )?))
    } else {
        None
    };
    let pointer_sha = pointer_raw.as_ref().map(|raw| digest(raw));
    let active_sha = active_raw.as_ref().map(|raw| digest(raw));
    let unsealed_sha = unsealed_raw.as_ref().map(|raw| digest(raw));
    let intent = serde_json::json!({
        "schema":"aegis_auto_v2_cold_prior_pointer_retire_intent_v1",
        "current_boot_id":boot,"prior_intent_sha256":expected_prior_sha,
        "original_intent_sha256":source.original_intent_sha256,
        "retained_root":root.to_str().ok_or_else(refuse)?,
        "old_pointer_state":state,"old_pointer_sha256":pointer_sha,
        "active_generation_sha256":active_sha,"old_activation_sha256":activation_sha,
        "unsealed_recovery_sha256":unsealed_sha,
        "deny_policy_sha256":proof["deny_policy_sha256"],
        "guard30_sha256":proof["guard30_sha256"],"no_client_grant":true,
    });
    let mut intent_raw = serde_json::to_vec(&intent).map_err(|_| refuse())?;
    intent_raw.push(b'\n');
    let intent_name = format!("prior-pointer-retire-intent-{expected_prior_sha}.json");
    if let Some(old) = &existing {
        for key in [
            "prior_intent_sha256",
            "original_intent_sha256",
            "retained_root",
            "old_pointer_state",
            "old_pointer_sha256",
            "active_generation_sha256",
            "old_activation_sha256",
            "unsealed_recovery_sha256",
            "no_client_grant",
        ] {
            if old[key] != intent[key] {
                return Err(refuse());
            }
        }
    } else {
        write_passive_atomic(cold.as_raw_fd(), &intent_name, &intent_raw, 4096)?;
    }
    if cold_pointer_retire_intent(expected_prior_sha, &source.original_intent_sha256, root)?
        .is_none()
    {
        return Err(refuse());
    }
    if let (Some(raw), Some(sha)) = (&pointer_raw, &pointer_sha) {
        archive_exact(history.as_raw_fd(), "passive-cold-prior-pointer", sha, raw)?;
    }
    if let (Some(raw), Some(sha)) = (&active_raw, &active_sha) {
        archive_exact(history.as_raw_fd(), "passive-cold-prior-active", sha, raw)?;
    }
    if let (Some(raw), Some(sha)) = (&unsealed_raw, &unsealed_sha) {
        archive_exact(history.as_raw_fd(), "passive-cold-prior-unsealed", sha, raw)?;
    }
    lock.revalidate().map_err(|_| refuse())?;
    if let Some(raw) = &pointer_raw {
        if recovery_absent(control.as_raw_fd(), "current.json").is_err() {
            retire_exact(control.as_raw_fd(), "current.json", raw)?;
        }
    }
    if let Some(raw) = &active_raw {
        if recovery_absent(control.as_raw_fd(), LEAF).is_err() {
            retire_exact(control.as_raw_fd(), LEAF, raw)?;
        }
    }
    if let Some(raw) = &unsealed_raw {
        if recovery_absent(control.as_raw_fd(), RECOVERY_LEAF).is_err() {
            retire_exact(control.as_raw_fd(), RECOVERY_LEAF, raw)?;
        }
    }
    recovery_absent(control.as_raw_fd(), "current.json")?;
    recovery_absent(control.as_raw_fd(), LEAF)?;
    recovery_absent(control.as_raw_fd(), RECOVERY_LEAF)?;
    let after = cold_stale_source_for_stage(root)?;
    if after.prior_intent_sha256 != source.prior_intent_sha256
        || after.prior_pointer_state != source.prior_pointer_state
    {
        return Err(refuse());
    }
    let receipt = serde_json::json!({
        "schema":"aegis_auto_v2_cold_prior_pointer_retired_v1",
        "current_boot_id":boot,"prior_intent_sha256":expected_prior_sha,
        "original_intent_sha256":source.original_intent_sha256,
        "old_pointer_state":state,"old_pointer_sha256":pointer_sha,
        "active_generation_sha256":active_sha,"old_activation_sha256":activation_sha,
        "deny_policy_sha256":proof["deny_policy_sha256"],
        "guard30_sha256":proof["guard30_sha256"],"no_client_grant":true,
    });
    let mut raw = serde_json::to_vec(&receipt).map_err(|_| refuse())?;
    raw.push(b'\n');
    let receipt_name = format!("prior-pointer-retired-{boot}-{expected_prior_sha}.json");
    write_passive_atomic(cold.as_raw_fd(), &receipt_name, &raw, 4096)?;
    let historical_name = format!("prior-pointer-retired-{expected_prior_sha}.json");
    if recovery_absent(cold.as_raw_fd(), &historical_name).is_ok() {
        write_passive_atomic(cold.as_raw_fd(), &historical_name, &raw, 4096)?;
    }
    if read_sealed_leaf_bounded(cold.as_raw_fd(), &receipt_name, 4096)? != raw {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema":"aegis_auto_v2_cold_prior_pointer_retirement_v1",
        "current_boot_id":boot,"prior_intent_sha256":expected_prior_sha,
        "old_pointer_sha256":pointer_sha,"retirement_sha256":digest(&raw),
        "no_client_grant":true,
    }))
    .map_err(|_| refuse())
}

pub(super) fn cold_prior_retirement_receipt(
    source: &ColdStaleSource,
    guardian_proof: &serde_json::Value,
) -> Result<String> {
    let cold = cold_recovery_dir()?;
    let name = format!(
        "prior-pointer-retired-{}-{}.json",
        current_boot_id()?,
        source.prior_intent_sha256
    );
    let raw = read_sealed_leaf_bounded(cold.as_raw_fd(), &name, 4096)?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), "current.json")?;
    recovery_absent(control.as_raw_fd(), LEAF)?;
    recovery_absent(control.as_raw_fd(), RECOVERY_LEAF)?;
    let receipt = cold_json(&raw)?;
    cold_exact_keys(
        &receipt,
        &[
            "schema",
            "current_boot_id",
            "prior_intent_sha256",
            "original_intent_sha256",
            "old_pointer_state",
            "old_pointer_sha256",
            "active_generation_sha256",
            "old_activation_sha256",
            "deny_policy_sha256",
            "guard30_sha256",
            "no_client_grant",
        ],
    )?;
    let intent = cold_pointer_retire_intent(
        &source.prior_intent_sha256,
        &source.original_intent_sha256,
        Path::new(&source.retained_root),
    )?
    .ok_or_else(refuse)?;
    for key in [
        "prior_intent_sha256",
        "original_intent_sha256",
        "old_pointer_state",
        "old_pointer_sha256",
        "active_generation_sha256",
        "old_activation_sha256",
        "no_client_grant",
    ] {
        if receipt[key] != intent[key] {
            return Err(refuse());
        }
    }
    let old_state = receipt["old_pointer_state"].as_str().ok_or_else(refuse)?;
    let pointer_sha = receipt["old_pointer_sha256"].as_str();
    let active_sha = receipt["active_generation_sha256"].as_str();
    let activation_sha = receipt["old_activation_sha256"].as_str();
    if receipt["schema"] != "aegis_auto_v2_cold_prior_pointer_retired_v1"
        || receipt["current_boot_id"] != current_boot_id()?
        || receipt["prior_intent_sha256"] != source.prior_intent_sha256
        || receipt["original_intent_sha256"] != source.original_intent_sha256
        || receipt["deny_policy_sha256"] != guardian_proof["policy_sha256"]
        || receipt["guard30_sha256"] != guardian_proof["guard30_sha256"]
        || receipt["no_client_grant"] != true
        || old_state != source.prior_pointer_state
        || !["absent", "unsealed", "sealed", "sealed_incomplete"].contains(&old_state)
        || match old_state {
            "absent" => pointer_sha.is_some() || active_sha.is_some() || activation_sha.is_some(),
            "unsealed" => {
                pointer_sha.is_none_or(|value| !exact_hex(value))
                    || active_sha.is_some()
                    || activation_sha.is_some()
            }
            "sealed" | "sealed_incomplete" => [pointer_sha, active_sha, activation_sha]
                .iter()
                .any(|value| value.is_none_or(|sha| !exact_hex(sha))),
            _ => true,
        }
    {
        return Err(refuse());
    }
    Ok(digest(&raw))
}

fn cold_resolve_intent(cold: i32) -> Result<Option<Vec<u8>>> {
    let active = recovery_absent(cold, "intent.json").is_err();
    let ready = if recovery_absent(cold, "transition-ready.json").is_ok() {
        None
    } else {
        let raw = read_sealed_leaf_bounded(cold, "transition-ready.json", 4096)?;
        let value = cold_json(&raw)?;
        let object = value.as_object().ok_or_else(refuse)?;
        let keys = [
            "schema",
            "current_boot_id",
            "intent_sha256",
            "cold_prebind_sha256",
            "source_config_sha256",
            "observer_ready_sha256",
            "site_readback_sha256",
            "deny_policy_sha256",
            "consumed_intent_leaf",
            "consumed_pending_leaf",
        ];
        if object.len() != keys.len()
            || keys.iter().any(|key| !object.contains_key(*key))
            || value["schema"] != "aegis_auto_terminal_cold_transition_ready_v1"
            || value["current_boot_id"] != current_boot_id()?
            || [
                "source_config_sha256",
                "observer_ready_sha256",
                "site_readback_sha256",
                "deny_policy_sha256",
            ]
            .iter()
            .any(|key| cold_hex(&value[*key]).is_err())
        {
            return Err(refuse());
        }
        let intent_sha = cold_hex(&value["intent_sha256"])?;
        let prebind_sha = cold_hex(&value["cold_prebind_sha256"])?;
        let prebind = read_sealed_leaf_bounded(cold, "cold-denied-prebind.json", 8192)?;
        if digest(&prebind) != prebind_sha {
            return Err(refuse());
        }
        let consumed_leaf = value["consumed_intent_leaf"].as_str().ok_or_else(refuse)?;
        if consumed_leaf != format!("intent-consumed-{intent_sha}.json") {
            return Err(refuse());
        }
        if !value["consumed_pending_leaf"].is_null() {
            let pending_leaf = value["consumed_pending_leaf"].as_str().ok_or_else(refuse)?;
            let pending_sha = pending_leaf
                .strip_prefix("pending-consumed-")
                .and_then(|text| text.strip_suffix(".json"))
                .ok_or_else(refuse)?;
            if !exact_hex(pending_sha) {
                return Err(refuse());
            }
        }
        Some((intent_sha.to_owned(), consumed_leaf.to_owned()))
    };
    if !active && ready.is_none() {
        return Ok(None);
    }
    let name = if active {
        "intent.json".to_owned()
    } else {
        ready.as_ref().ok_or_else(refuse)?.1.clone()
    };
    let raw = read_sealed_leaf_bounded(cold, &name, 4096)?;
    let value = cold_json(&raw)?;
    if value["schema"] != "aegis_auto_terminal_cold_intent_v1"
        || value["current_boot_id"] != current_boot_id()?
    {
        return Err(refuse());
    }
    if let Some((expected, consumed)) = &ready {
        if digest(&raw) != *expected || (active && recovery_absent(cold, consumed).is_err()) {
            return Err(refuse());
        }
    }
    Ok(Some(raw))
}

/// Select the current boot's cold phase. The original fixed R9 directory is
/// selected only for its own boot. Rollover uses an authenticated current head
/// and a complete attempt directory; no caller-supplied path is accepted.
pub(super) fn cold_current_phase() -> Result<(std::os::fd::OwnedFd, Vec<u8>, bool, Option<String>)>
{
    use std::os::fd::{AsRawFd, FromRawFd};
    let cold = cold_recovery_dir()?;
    let boot = current_boot_id()?;
    let fixed_current = if recovery_absent(cold.as_raw_fd(), "intent.json").is_err() {
        let raw = read_sealed_leaf_bounded(cold.as_raw_fd(), "intent.json", 8192)?;
        cold_json(&raw)?["current_boot_id"] == boot
    } else if recovery_absent(cold.as_raw_fd(), "transition-ready.json").is_err() {
        let raw = read_sealed_leaf_bounded(cold.as_raw_fd(), "transition-ready.json", 4096)?;
        cold_json(&raw)?["current_boot_id"] == boot
    } else {
        false
    };
    if fixed_current {
        let raw = cold_resolve_intent(cold.as_raw_fd())?.ok_or_else(refuse)?;
        let value = cold_json(&raw)?;
        if value["current_boot_id"] != boot {
            return Err(refuse());
        }
        return Ok((cold, raw, false, None));
    }
    let prior = cold_prior_attempt(cold.as_raw_fd(), &boot, false)?;
    let head_sha = prior.current_head_sha.ok_or_else(refuse)?;
    let intent_sha = prior.current_intent_sha.ok_or_else(refuse)?;
    let attempts = recovery_directory(cold.as_raw_fd(), "attempts", Some(0o700))?;
    let name = format!("{boot}-{}", prior.prior_sha);
    let attempt = recovery_directory(attempts.as_raw_fd(), &name, Some(0o700))?;
    let active = recovery_absent(attempt.as_raw_fd(), "intent.json").is_err();
    let leaf = if active {
        "intent.json".to_owned()
    } else {
        format!("intent-consumed-{intent_sha}.json")
    };
    let raw = read_sealed_leaf_bounded(attempt.as_raw_fd(), &leaf, 8192)?;
    let intent = cold_json(&raw)?;
    if digest(&raw) != intent_sha
        || intent["schema"] != "aegis_auto_terminal_cold_intent_v1"
        || intent["current_boot_id"] != boot
        || read_sealed_leaf_bounded(attempt.as_raw_fd(), "phase-00.json", 8192)? != raw
    {
        return Err(refuse());
    }
    if recovery_absent(attempt.as_raw_fd(), "transition-ready.json").is_err() {
        let ready_raw =
            read_sealed_leaf_bounded(attempt.as_raw_fd(), "transition-ready.json", 4096)?;
        let ready = cold_json(&ready_raw)?;
        cold_exact_keys(
            &ready,
            &[
                "schema",
                "current_boot_id",
                "original_intent_sha256",
                "prior_intent_sha256",
                "attempt_head_sha256",
                "attempt_intent_sha256",
                "barrier_sha256",
                "cold_prebind_sha256",
                "source_config_sha256",
                "observer_ready_sha256",
                "site_readback_sha256",
                "deny_policy_sha256",
                "phase02_sha256",
                "phase03_sha256",
                "phase04_sha256",
                "native_transition_sha256",
                "consumed_original_intent_leaf",
                "consumed_attempt_intent_leaf",
                "consumed_pending_leaf",
                "consumed_rollover_barrier_leaf",
            ],
        )?;
        let barrier_sha = cold_hex(&ready["barrier_sha256"])?;
        let original_sha = prior.original_sha;
        if ready["schema"] != "aegis_auto_terminal_cold_rollover_transition_ready_v1"
            || ready["current_boot_id"] != boot
            || ready["original_intent_sha256"] != original_sha
            || ready["prior_intent_sha256"] != prior.prior_sha
            || ready["attempt_head_sha256"] != head_sha
            || ready["attempt_intent_sha256"] != intent_sha
            || ready["consumed_original_intent_leaf"]
                != format!("intent-consumed-{original_sha}.json")
            || ready["consumed_attempt_intent_leaf"] != format!("intent-consumed-{intent_sha}.json")
            || ready["consumed_rollover_barrier_leaf"]
                != format!("rollover-barrier-consumed-{barrier_sha}.json")
            || [
                "cold_prebind_sha256",
                "source_config_sha256",
                "observer_ready_sha256",
                "site_readback_sha256",
                "deny_policy_sha256",
                "phase02_sha256",
                "phase03_sha256",
                "phase04_sha256",
                "native_transition_sha256",
            ]
            .iter()
            .any(|key| cold_hex(&ready[*key]).is_err())
        {
            return Err(refuse());
        }
        for (leaf, key, max) in [
            ("cold-denied-prebind.json", "cold_prebind_sha256", 8192),
            ("phase-02.json", "phase02_sha256", 4096),
            ("phase-03.json", "phase03_sha256", 8192),
            ("phase-04.json", "phase04_sha256", 8192),
        ] {
            if digest(&read_sealed_leaf_bounded(attempt.as_raw_fd(), leaf, max)?)
                != cold_hex(&ready[key])?
            {
                return Err(refuse());
            }
        }
        if !ready["consumed_pending_leaf"].is_null() {
            let leaf = ready["consumed_pending_leaf"].as_str().ok_or_else(refuse)?;
            let sha = leaf
                .strip_prefix("pending-consumed-")
                .and_then(|v| v.strip_suffix(".json"))
                .ok_or_else(refuse)?;
            if !exact_hex(sha) {
                return Err(refuse());
            }
            if !active && digest(&read_sealed_leaf_bounded(attempt.as_raw_fd(), leaf, 8192)?) != sha
            {
                return Err(refuse());
            }
        }
        if !active {
            let original_name = format!("intent-consumed-{original_sha}.json");
            if recovery_absent(cold.as_raw_fd(), "intent.json").is_err()
                || read_sealed_leaf_bounded(cold.as_raw_fd(), &original_name, 8192)?
                    != prior.original_raw
                || recovery_absent(cold.as_raw_fd(), "rollover-barrier.json").is_err()
                || digest(&read_sealed_leaf_bounded(
                    cold.as_raw_fd(),
                    &format!("rollover-barrier-consumed-{barrier_sha}.json"),
                    4096,
                )?) != barrier_sha
            {
                return Err(refuse());
            }
            let migrations = recovery_chain(
                &[
                    "var",
                    "lib",
                    "aegis-install",
                    "client",
                    "terminal-migrations",
                ],
                Some(0o700),
            )?;
            recovery_absent(migrations.as_raw_fd(), "pending.json")?;
        }
    } else if !active {
        return Err(refuse());
    }
    let duplicate = unsafe { libc::fcntl(attempt.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 3 {
        return Err(refuse());
    }
    let phase = unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicate) };
    Ok((phase, raw, true, Some(head_sha)))
}

fn cold_current_pending(migration: i32) -> Result<Option<Vec<u8>>> {
    let active = recovery_absent(migration, "pending.json").is_err();
    let consumed = if recovery_absent(migration, "cold-recovery").is_ok() {
        None
    } else {
        let cold = recovery_directory(migration, "cold-recovery", Some(0o700))?;
        if recovery_absent(cold.as_raw_fd(), "transition-ready.json").is_ok() {
            None
        } else {
            cold_resolve_intent(cold.as_raw_fd())?.ok_or_else(refuse)?;
            let ready_raw =
                read_sealed_leaf_bounded(cold.as_raw_fd(), "transition-ready.json", 4096)?;
            let ready = cold_json(&ready_raw)?;
            if ready["schema"] != "aegis_auto_terminal_cold_transition_ready_v1"
                || ready["current_boot_id"] != current_boot_id()?
            {
                return Err(refuse());
            }
            let leaf = if ready["consumed_pending_leaf"].is_null() {
                None
            } else {
                let leaf = ready["consumed_pending_leaf"].as_str().ok_or_else(refuse)?;
                let sha = leaf
                    .strip_prefix("pending-consumed-")
                    .and_then(|value| value.strip_suffix(".json"))
                    .ok_or_else(refuse)?;
                if !exact_hex(sha) {
                    return Err(refuse());
                }
                Some((leaf.to_owned(), sha.to_owned()))
            };
            Some(leaf)
        }
    };
    if active {
        if consumed == Some(None) {
            return Err(refuse());
        }
        let raw = read_sealed_leaf_bounded(migration, "pending.json", 4096)?;
        if let Some(Some((leaf, sha))) = consumed {
            let cold = recovery_directory(migration, "cold-recovery", Some(0o700))?;
            if digest(&raw) != sha || recovery_absent(cold.as_raw_fd(), &leaf).is_err() {
                return Err(refuse());
            }
        }
        return Ok(Some(raw));
    }
    if let Some(Some((leaf, sha))) = consumed {
        let cold = recovery_directory(migration, "cold-recovery", Some(0o700))?;
        let raw = read_sealed_leaf_bounded(cold.as_raw_fd(), &leaf, 4096)?;
        if digest(&raw) != sha {
            return Err(refuse());
        }
        return Ok(Some(raw));
    }
    Ok(None)
}

pub(super) fn cold_current_intent_sha(expected_successor_sha: &str) -> Result<Option<String>> {
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    if recovery_absent(guardian.as_raw_fd(), "terminal-migrations").is_ok() {
        return Ok(None);
    }
    let migrations = recovery_directory(guardian.as_raw_fd(), "terminal-migrations", Some(0o700))?;
    if recovery_absent(migrations.as_raw_fd(), "cold-recovery").is_ok() {
        return Ok(None);
    }
    // A fresh rollover can be inspected before its current head is
    // published. The old intent remains the sticky deny in that prefix.
    let cold = recovery_directory(migrations.as_raw_fd(), "cold-recovery", Some(0o700))?;
    let boot = current_boot_id()?;
    let fixed_is_current = if recovery_absent(cold.as_raw_fd(), "intent.json").is_err() {
        cold_json(&read_sealed_leaf_bounded(
            cold.as_raw_fd(),
            "intent.json",
            8192,
        )?)?["current_boot_id"]
            == boot
    } else if recovery_absent(cold.as_raw_fd(), "transition-ready.json").is_err() {
        cold_json(&read_sealed_leaf_bounded(
            cold.as_raw_fd(),
            "transition-ready.json",
            4096,
        )?)?["current_boot_id"]
            == boot
    } else {
        false
    };
    if !fixed_is_current {
        let prior = cold_prior_attempt(cold.as_raw_fd(), &boot, false)?;
        if prior.current_head_sha.is_none() {
            if prior.current_intent_sha.is_some() {
                return Err(refuse());
            }
            return Ok(None);
        }
    }
    let (_phase, raw, _rollover, _head) = cold_current_phase()?;
    let value = cold_json(&raw)?;
    if value["schema"] != "aegis_auto_terminal_cold_intent_v1"
        || value["current_boot_id"] != current_boot_id()?
        || value["successor_intent_sha256"] != expected_successor_sha
    {
        return Err(refuse());
    }
    Ok(Some(digest(&raw)))
}

pub(super) fn cold_quiesce_receipt(
    expected_intent_sha: &str,
) -> Result<Option<(serde_json::Value, String)>> {
    if !exact_hex(expected_intent_sha) {
        return Err(refuse());
    }
    let (phase_dir, intent_raw, _rollover, _head) = cold_current_phase()?;
    let phase00 = read_sealed_leaf_bounded(phase_dir.as_raw_fd(), "phase-00.json", 8192)?;
    if intent_raw != phase00 || digest(&intent_raw) != expected_intent_sha {
        return Err(refuse());
    }
    let intent = cold_json(&intent_raw)?;
    let initial = cold_hex(&intent["initial_infrastructure_rows_sha256"])?;
    if recovery_absent(phase_dir.as_raw_fd(), "phase-01.json").is_ok() {
        return Ok(None);
    }
    let raw = read_sealed_leaf_bounded(phase_dir.as_raw_fd(), "phase-01.json", 4096)?;
    let phase = cold_json(&raw)?;
    let object = phase.as_object().ok_or_else(refuse)?;
    let keys = [
        "schema",
        "intent_sha256",
        "deny_policy_sha256",
        "pre_quiesce_infrastructure_sha256",
        "post_quiesce_infrastructure_sha256",
        "quiesce_monotonic_tick",
    ];
    if object.len() != keys.len()
        || keys.iter().any(|key| !object.contains_key(*key))
        || phase["schema"] != "aegis_auto_terminal_cold_deny_v2"
        || phase["intent_sha256"] != expected_intent_sha
        || phase["deny_policy_sha256"] != intent["deny_policy_sha256"]
        || phase["pre_quiesce_infrastructure_sha256"] != initial
        || cold_hex(&phase["post_quiesce_infrastructure_sha256"]).is_err()
        || phase["quiesce_monotonic_tick"]
            .as_u64()
            .is_none_or(|tick| tick == 0)
    {
        return Err(refuse());
    }
    Ok(Some((phase, digest(&raw))))
}

pub(super) fn cold_package_repair_receipt(
    expected_intent_sha: &str,
    quiesce_tick: u64,
) -> Result<Option<(serde_json::Value, String)>> {
    if !exact_hex(expected_intent_sha) || quiesce_tick == 0 {
        return Err(refuse());
    }
    let (phase_dir, intent_raw, _rollover, _head) = cold_current_phase()?;
    if digest(&intent_raw) != expected_intent_sha {
        return Err(refuse());
    }
    if recovery_absent(phase_dir.as_raw_fd(), "phase-02.json").is_ok() {
        return Ok(None);
    }
    let raw = read_sealed_leaf_bounded(phase_dir.as_raw_fd(), "phase-02.json", 4096)?;
    let phase = cold_json(&raw)?;
    let object = phase.as_object().ok_or_else(refuse)?;
    let keys = [
        "schema",
        "intent_sha256",
        "proof_sha256",
        "package_repaired_tick",
    ];
    if object.len() != keys.len()
        || keys.iter().any(|key| !object.contains_key(*key))
        || phase["schema"] != "aegis_auto_terminal_cold_package_repaired_v2"
        || phase["intent_sha256"] != expected_intent_sha
        || cold_hex(&phase["proof_sha256"]).is_err()
        || phase["package_repaired_tick"]
            .as_u64()
            .is_none_or(|tick| tick <= quiesce_tick)
    {
        return Err(refuse());
    }
    Ok(Some((phase, digest(&raw))))
}

fn cold_hex(value: &serde_json::Value) -> Result<&str> {
    let value = value.as_str().ok_or_else(refuse)?;
    if !exact_hex(value) {
        return Err(refuse());
    }
    Ok(value)
}

fn cold_retained_package(release: i32, expected_sha: &str) -> Result<()> {
    let packages = recovery_directory(release, "packages", None)?;
    let split = recovery_open_at(
        packages.as_raw_fd(),
        "split-deb-packages.manifest.json",
        libc::O_RDONLY,
        0,
    )?;
    let stat = recovery_stat(split.as_raw_fd())?;
    if stat.st_mode != libc::S_IFREG | 0o444
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size > 1 << 20
    {
        return Err(refuse());
    }
    let mut bytes = Vec::new();
    std::fs::File::from(split)
        .take((1 << 20) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    if bytes.len() > 1 << 20 {
        return Err(refuse());
    }
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    if manifest["packages"].as_object().is_none() {
        return Err(refuse());
    }
    let name = manifest["packages"]["aegis-client"]["deb_file"]
        .as_str()
        .ok_or_else(refuse)?;
    if !name.starts_with("aegis-client_")
        || !name.ends_with(".deb")
        || name.len() > 160
        || !name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'+' | b'-' | b':' | b'~')
        })
    {
        return Err(refuse());
    }
    let package = recovery_open_at(packages.as_raw_fd(), name, libc::O_RDONLY, 0)?;
    let stat = recovery_stat(package.as_raw_fd())?;
    if stat.st_mode != libc::S_IFREG | 0o444
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size > 512 << 20
        || recovery_file_hash(package.as_raw_fd(), 512 << 20)?.1 != expected_sha
    {
        return Err(refuse());
    }
    let named = recovery_open_at(packages.as_raw_fd(), name, libc::O_RDONLY, 0)?;
    let now = recovery_stat(named.as_raw_fd())?;
    if (
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime,
        stat.st_ctime,
    ) != (
        now.st_dev,
        now.st_ino,
        now.st_size,
        now.st_mtime,
        now.st_ctime,
    ) {
        return Err(refuse());
    }
    let sidecar = recovery_open_at(
        packages.as_raw_fd(),
        &format!("{name}.sha256"),
        libc::O_RDONLY,
        0,
    )?;
    let sidecar_stat = recovery_stat(sidecar.as_raw_fd())?;
    if sidecar_stat.st_mode != libc::S_IFREG | 0o444
        || sidecar_stat.st_uid != 0
        || sidecar_stat.st_gid != 0
        || sidecar_stat.st_nlink != 1
        || sidecar_stat.st_size <= 0
        || sidecar_stat.st_size > 128
    {
        return Err(refuse());
    }
    let mut sidecar_raw = Vec::new();
    std::fs::File::from(sidecar)
        .take(129)
        .read_to_end(&mut sidecar_raw)
        .map_err(|_| refuse())?;
    if sidecar_raw != format!("{expected_sha}  {name}\n").as_bytes() {
        return Err(refuse());
    }
    Ok(())
}

/// Recover the B client DEB hash from the SuccessorIntent-anchored SUMS file.
/// A pre-migration_prepare boot has no terminal context carrying package_sha.
fn cold_anchored_client_package_sha(release: i32, expected_sums_sha: &str) -> Result<String> {
    if !exact_hex(expected_sums_sha) {
        return Err(refuse());
    }
    let fd = recovery_open_at(release, "SHA256SUMS", libc::O_RDONLY, 0)?;
    let before = recovery_stat(fd.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o444
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size > 4 << 20
    {
        return Err(refuse());
    }
    let mut raw = Vec::new();
    std::fs::File::from(fd)
        .take((4 << 20) + 1)
        .read_to_end(&mut raw)
        .map_err(|_| refuse())?;
    let named = recovery_open_at(release, "SHA256SUMS", libc::O_RDONLY, 0)?;
    let after = recovery_stat(named.as_raw_fd())?;
    if raw.len() as i64 != before.st_size
        || digest(&raw) != expected_sums_sha
        || (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime,
            before.st_ctime,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime,
            after.st_ctime,
        )
    {
        return Err(refuse());
    }
    let text = std::str::from_utf8(&raw).map_err(|_| refuse())?;
    let mut client = None;
    for line in text.lines() {
        let (sha, path) = line.split_once("  ").ok_or_else(refuse)?;
        if !exact_hex(sha) {
            return Err(refuse());
        }
        if path.starts_with("packages/aegis-client_")
            && path.ends_with(".deb")
            && client.replace((sha.to_owned(), path.to_owned())).is_some()
        {
            return Err(refuse());
        }
    }
    let (sha, sums_path) = client.ok_or_else(refuse)?;
    let packages = recovery_directory(release, "packages", None)?;
    let split = recovery_open_at(
        packages.as_raw_fd(),
        "split-deb-packages.manifest.json",
        libc::O_RDONLY,
        0,
    )?;
    let split_stat = recovery_stat(split.as_raw_fd())?;
    if split_stat.st_mode != libc::S_IFREG | 0o444
        || split_stat.st_uid != 0
        || split_stat.st_gid != 0
        || split_stat.st_nlink != 1
        || split_stat.st_size <= 0
        || split_stat.st_size > 1 << 20
    {
        return Err(refuse());
    }
    let mut split_raw = Vec::new();
    std::fs::File::from(split)
        .take((1 << 20) + 1)
        .read_to_end(&mut split_raw)
        .map_err(|_| refuse())?;
    let split_named = recovery_open_at(
        packages.as_raw_fd(),
        "split-deb-packages.manifest.json",
        libc::O_RDONLY,
        0,
    )?;
    let split_now = recovery_stat(split_named.as_raw_fd())?;
    if split_raw.len() as i64 != split_stat.st_size
        || (
            split_stat.st_dev,
            split_stat.st_ino,
            split_stat.st_mode,
            split_stat.st_uid,
            split_stat.st_gid,
            split_stat.st_nlink,
            split_stat.st_size,
            split_stat.st_mtime,
            split_stat.st_ctime,
        ) != (
            split_now.st_dev,
            split_now.st_ino,
            split_now.st_mode,
            split_now.st_uid,
            split_now.st_gid,
            split_now.st_nlink,
            split_now.st_size,
            split_now.st_mtime,
            split_now.st_ctime,
        )
    {
        return Err(refuse());
    }
    let split_value: serde_json::Value =
        serde_json::from_slice(&split_raw).map_err(|_| refuse())?;
    let split_name = split_value["packages"]["aegis-client"]["deb_file"]
        .as_str()
        .ok_or_else(refuse)?;
    if sums_path != format!("packages/{split_name}") {
        return Err(refuse());
    }
    cold_retained_package(release, &sha)?;
    Ok(sha)
}

const COLD_HELPERS: &[&str] = &[
    "lib/root-state.sh",
    "lib/aegis_installer_auto_v2.py",
    "lib/aegis_auto_uninstall_journal.py",
    "lib/aegis_auto_capture.py",
    "lib/aegis_auto_capture_topology.py",
    "lib/aegis_auto_endpoint.py",
    "lib/aegis_auto_guard_policy.py",
    "lib/aegis_auto_foreign_policy.py",
    "lib/aegis_auto_foreign_monitor.py",
    "lib/aegis_auto_ufw_pins.json",
    "lib/aegis_initrd_policy.py",
    "lib/aegis_initrd_classic.py",
    "lib/aegis_auto_guardian.py",
    "lib/aegis_auto_guardian_watchdog.py",
    "lib/aegis_auto_terminal_witness.py",
    "lib/aegis_auto_terminal_boot_store.py",
    "lib/aegis_auto_terminal_register.py",
    "lib/aegis_auto_boot_transition.py",
    "lib/aegis-auto-terminal-hook",
    "lib/aegis_auto_launch.py",
    "lib/aegis_auto_native_witness.py",
    "lib/aegis_auto_sink.py",
    "lib/aegis_auto_trace_rollback.py",
    "lib/aegis_auto_witness_topology.py",
    "aegis-device-egress-guard.sh",
    "purge-installed-aegis.sh",
    "aegis-ubuntu-uninstall.sh",
    "aegis-wide-enable.sh",
    "aegis-wide-disable.sh",
    "aegis-wide-persist-install.sh",
    "janitor-wide-linux-tproxy.sh",
    "setup-wide-linux-redirect.sh",
    "setup-wide-linux-tproxy.sh",
    "setup-wide-linux-nfqueue.sh",
];
const COLD_UNITS: &[&str] = &[
    "aegis-auto-config.service",
    "aegis-auto-capture-topology.service",
    "aegis-auto-guardian-watchdog.service",
    "aegis-auto-guardian.service",
    "aegis-auto-terminal-a@.service",
    "aegis-auto-terminal-b@.service",
    "aegis-auto-terminal-observer.service",
    "aegis-auto-terminal-transition.service",
    "aegis-auto-trace-rollback-actor.service",
    "aegis-auto-trace-rollback.service",
    "aegis-auto-trace-rollback.timer",
    "aegis-auto-witness-topology.service",
    "aegis-foreign-policy-monitor.service",
    "aegis-auto-clean-shutdown.service",
    "aegis-device-dhcp-refresh.service",
    "aegis-device-dhcp-refresh.timer",
];

fn cold_sums_map(
    root: &Path,
    candidate_sha: &str,
    expected_sums_sha: Option<&str>,
) -> Result<std::collections::BTreeMap<String, String>> {
    let (_, installer_sha) = verified_retained_source(root, &root.join("bin/aegis-client"))?;
    let (_, sums_sha) = retained_bundle_anchor(root, candidate_sha, &installer_sha)?;
    if expected_sums_sha.is_some_and(|expected| expected != sums_sha.as_str()) {
        return Err(refuse());
    }
    let name = root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    let release = recovery_chain(&["var", "lib", "aegis-auto", "releases", name], Some(0o700))?;
    let sums = recovery_open_at(release.as_raw_fd(), "SHA256SUMS", libc::O_RDONLY, 0)?;
    let before = recovery_stat(sums.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o444
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size > 4 << 20
    {
        return Err(refuse());
    }
    let mut raw = Vec::new();
    std::fs::File::from(sums)
        .take((4 << 20) + 1)
        .read_to_end(&mut raw)
        .map_err(|_| refuse())?;
    let named = recovery_open_at(release.as_raw_fd(), "SHA256SUMS", libc::O_RDONLY, 0)?;
    let after = recovery_stat(named.as_raw_fd())?;
    if digest(&raw) != sums_sha
        || raw.len() as i64 != before.st_size
        || (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime,
            before.st_ctime,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime,
            after.st_ctime,
        )
    {
        return Err(refuse());
    }
    let mut result = std::collections::BTreeMap::new();
    for line in std::str::from_utf8(&raw).map_err(|_| refuse())?.lines() {
        let (sha, path) = line.split_once("  ").ok_or_else(refuse)?;
        if !exact_hex(sha)
            || path.is_empty()
            || path.starts_with('/')
            || path.contains("..")
            || result.insert(path.to_owned(), sha.to_owned()).is_some()
        {
            return Err(refuse());
        }
    }
    Ok(result)
}

pub(super) fn cold_package_sources(
    history: &ColdRetiredHistory,
    package: &serde_json::Value,
) -> Result<()> {
    cold_package_sources_bound(
        package,
        (&history.old_root, &history.retained_root),
        (&history.old_candidate_sha256, &history.new_candidate_sha256),
        &history.old_install_sha256,
        &history.new_package_sha256,
        &history.sums_sha256,
    )
}

pub(super) fn cold_stale_package_sources(
    source: &ColdStaleSource,
    package: &serde_json::Value,
) -> Result<()> {
    cold_package_sources_bound(
        package,
        (&source.old_root, &source.retained_root),
        (
            &source.old_candidate_sha256,
            &source.bootstrap.candidate_sha256,
        ),
        &source.old_install_sha256,
        &source.new_package_sha256,
        &source.bootstrap.sums_sha256,
    )
}

fn cold_package_sources_bound(
    package: &serde_json::Value,
    roots: (&str, &str),
    candidates: (&str, &str),
    old_install_sha: &str,
    new_package_sha: &str,
    sums_sha: &str,
) -> Result<()> {
    let (old_root, retained_root) = roots;
    let (old_candidate_sha, new_candidate_sha) = candidates;
    if package["schema"] != "aegis_auto_v2_cold_package_readback_v1"
        || package["old_root"] != old_root
        || package["new_root"] != retained_root
        || package["old_package_sha256"]
            .as_str()
            .is_none_or(|v| !exact_hex(v))
        || package["new_package_sha256"] != new_package_sha
    {
        return Err(refuse());
    }
    let old = Path::new(old_root);
    let name = old
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    let release = recovery_chain(&["var", "lib", "aegis-auto", "releases", name], Some(0o700))?;
    cold_retained_package(
        release.as_raw_fd(),
        package["old_package_sha256"].as_str().ok_or_else(refuse)?,
    )?;
    let new = Path::new(retained_root);
    let name = new
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    let release = recovery_chain(&["var", "lib", "aegis-auto", "releases", name], Some(0o700))?;
    cold_retained_package(release.as_raw_fd(), new_package_sha)?;
    let old_sums = cold_sums_map(old, old_candidate_sha, None)?;
    let new_sums = cold_sums_map(new, new_candidate_sha, Some(sums_sha))?;
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let old_install_raw = read_sealed_leaf_bounded(
        guardian.as_raw_fd(),
        &format!("auto-guardian-install-guarded-{old_install_sha}.json"),
        1 << 20,
    )?;
    if digest(&old_install_raw) != old_install_sha {
        return Err(refuse());
    }
    let old_install = cold_json(&old_install_raw)?;
    for (path, field) in [
        (
            "scripts/lib/aegis_auto_terminal_register.py",
            "terminal_register_sha256",
        ),
        (
            "scripts/lib/aegis_auto_terminal_witness.py",
            "terminal_witness_sha256",
        ),
        (
            "scripts/lib/aegis_auto_terminal_boot_store.py",
            "terminal_boot_store_sha256",
        ),
        (
            "scripts/lib/aegis_auto_boot_transition.py",
            "terminal_transition_sha256",
        ),
        (
            "packaging/systemd/aegis-auto-terminal-a@.service",
            "terminal_a_unit_sha256",
        ),
        (
            "packaging/systemd/aegis-auto-terminal-b@.service",
            "terminal_b_unit_sha256",
        ),
        (
            "packaging/systemd/aegis-auto-terminal-observer.service",
            "terminal_observer_unit_sha256",
        ),
        (
            "packaging/systemd/aegis-auto-terminal-transition.service",
            "terminal_transition_unit_sha256",
        ),
        (
            "packaging/systemd/system-shutdown/aegis-auto-terminal-hook",
            "terminal_hook_staged_sha256",
        ),
    ] {
        if old_install[field].as_str() != old_sums.get(path).map(String::as_str) {
            return Err(refuse());
        }
    }
    let mut old_client_packages = old_sums
        .iter()
        .filter(|(path, _)| path.starts_with("packages/aegis-client_") && path.ends_with(".deb"));
    let (_, old_client_sha) = old_client_packages.next().ok_or_else(refuse)?;
    if old_client_packages.next().is_some()
        || package["old_package_sha256"] != old_client_sha.as_str()
    {
        return Err(refuse());
    }
    let roster = package["roster"].as_array().ok_or_else(refuse)?;
    if roster.len() != COLD_HELPERS.len() + COLD_UNITS.len() {
        return Err(refuse());
    }
    for (index, leaf) in COLD_HELPERS.iter().chain(COLD_UNITS.iter()).enumerate() {
        let helper = index < COLD_HELPERS.len();
        let path = if helper {
            format!("helper/{leaf}")
        } else {
            format!("unit/{leaf}")
        };
        if roster[index]["path"].as_str() != Some(path.as_str()) {
            return Err(refuse());
        }
        let source = if helper && *leaf == "lib/aegis-auto-terminal-hook" {
            "packaging/systemd/system-shutdown/aegis-auto-terminal-hook".to_owned()
        } else if helper {
            format!("scripts/{leaf}")
        } else {
            format!("packaging/systemd/{leaf}")
        };
        let old_sha = old_sums.get(&source).ok_or_else(refuse)?;
        let new_sha = new_sums.get(&source).ok_or_else(refuse)?;
        let mode = if !helper {
            0o644
        } else if leaf.starts_with("lib/aegis_auto_")
            || [
                "lib/aegis_installer_auto_v2.py",
                "lib/aegis_initrd_policy.py",
                "lib/aegis_initrd_classic.py",
                "lib/aegis-auto-terminal-hook",
            ]
            .contains(leaf)
        {
            0o500
        } else {
            0o755
        };
        let row = &roster[index];
        if row["relation"] == "absent" {
            if package["package_state"] != "known_interrupted"
                || !row["sha256"].is_null()
                || !row["mode"].is_null()
            {
                return Err(refuse());
            }
            continue;
        }
        if row["mode"].as_u64() != Some(mode as u64) {
            return Err(refuse());
        }
        let actual = row["sha256"].as_str().ok_or_else(refuse)?;
        let relation = if actual == old_sha && actual == new_sha {
            "both"
        } else if actual == old_sha {
            "old"
        } else if actual == new_sha {
            "new"
        } else {
            return Err(refuse());
        };
        if row["relation"] != relation
            || (package["package_state"] == "old_exact" && !["old", "both"].contains(&relation))
            || (package["package_state"] == "new_exact" && !["new", "both"].contains(&relation))
        {
            return Err(refuse());
        }
    }
    Ok(())
}

fn cold_script_source(release: i32, script: &str) -> Result<String> {
    if !matches!(
        script,
        "aegis_auto_guardian.py"
            | "aegis_installer_auto_v2.py"
            | "aegis_auto_terminal_witness.py"
            | "aegis_auto_terminal_register.py"
    ) {
        return Err(refuse());
    }
    let sums = recovery_open_at(release, "SHA256SUMS", libc::O_RDONLY, 0)?;
    let stat = recovery_stat(sums.as_raw_fd())?;
    if stat.st_mode != libc::S_IFREG | 0o444
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size > 4 << 20
    {
        return Err(refuse());
    }
    let mut raw = Vec::new();
    std::fs::File::from(sums)
        .take((4 << 20) + 1)
        .read_to_end(&mut raw)
        .map_err(|_| refuse())?;
    if raw.len() > 4 << 20 {
        return Err(refuse());
    }
    let value = std::str::from_utf8(&raw).map_err(|_| refuse())?;
    let mut expected = None;
    for line in value.lines() {
        let (hash, path) = line.split_once("  ").ok_or_else(refuse)?;
        if !exact_hex(hash) || path.is_empty() || path.starts_with('/') || path.contains("..") {
            return Err(refuse());
        }
        if path == format!("scripts/lib/{script}") && expected.replace(hash.to_owned()).is_some() {
            return Err(refuse());
        }
    }
    let expected = expected.ok_or_else(refuse)?;
    let scripts = recovery_directory(release, "scripts", None)?;
    let lib = recovery_directory(scripts.as_raw_fd(), "lib", None)?;
    let file = recovery_open_at(lib.as_raw_fd(), script, libc::O_RDONLY, 0)?;
    let stat = recovery_stat(file.as_raw_fd())?;
    if stat.st_mode != libc::S_IFREG | 0o444
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || recovery_file_hash(file.as_raw_fd(), 4 << 20)?.1 != expected
    {
        return Err(refuse());
    }
    let named = recovery_open_at(lib.as_raw_fd(), script, libc::O_RDONLY, 0)?;
    let now = recovery_stat(named.as_raw_fd())?;
    if (
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime,
        stat.st_ctime,
    ) != (
        now.st_dev,
        now.st_ino,
        now.st_size,
        now.st_mtime,
        now.st_ctime,
    ) {
        return Err(refuse());
    }
    Ok(expected)
}

/// Historical source and package proof for an interrupted guarded upgrade.
/// This never observes a live old stage and never treats a missing BOOT marker
/// as a clean shutdown. The caller must separately prove current deny twice.
fn cold_before_migration_prepare(
    root: &Path,
    history: &SuccessorHistory,
    successor_raw: &[u8],
    successor: &SuccessorIntent,
    current_boot_id: String,
    new_candidate_sha256: String,
    sums_sha: &str,
) -> Result<ColdRetiredHistory> {
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let rotation_intent = read_sealed_leaf_bounded(
        guardian.as_raw_fd(),
        "auto-guard-rotation-intent.json",
        1 << 20,
    )?;
    let rotation_denied = read_sealed_leaf_bounded(
        guardian.as_raw_fd(),
        "auto-guard-rotation-denied.json",
        1 << 20,
    )?;
    let rotation_retired = read_sealed_leaf_bounded(
        guardian.as_raw_fd(),
        "auto-guard-rotation-retired.json",
        1 << 20,
    )?;
    let rotation = cold_json(&rotation_intent)?;
    let denied = cold_json(&rotation_denied)?;
    let retired = cold_json(&rotation_retired)?;
    let old_install_sha = cold_hex(&rotation["old_install_sha256"])?;
    if rotation["schema"] != "aegis_auto_guard_rotation_intent_v1"
        || rotation["boot_id"] != successor.old_boot_id
        || rotation["successor"]["intent_sha256"] != digest(successor_raw)
        || denied["schema"] != "aegis_auto_guard_rotation_denied_v1"
        || denied["intent_sha256"] != digest(&rotation_intent)
        || retired["schema"] != "aegis_auto_guard_rotation_retired_v1"
        || retired["intent_sha256"] != digest(&rotation_intent)
        || retired["no_live_actors"] != true
    {
        return Err(refuse());
    }
    let old_install = read_sealed_leaf_bounded(
        guardian.as_raw_fd(),
        &format!("auto-guardian-install-guarded-{old_install_sha}.json"),
        1 << 20,
    )?;
    if digest(&old_install) != old_install_sha {
        return Err(refuse());
    }
    let old_install_value = cold_json(&old_install)?;
    let old_root = Path::new(
        history.stopped["input"]["public_payload_root"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let old_candidate = old_root.join("bin/aegis-client");
    let (old_candidate_sha, _) = verified_retained_source(old_root, &old_candidate)?;
    if old_install_value["worker_sha256"] != old_candidate_sha
        || history.stopped["input"]["candidate_sha256"] != old_candidate_sha
    {
        return Err(refuse());
    }
    let cold_state = if recovery_absent(guardian.as_raw_fd(), "terminal-migrations").is_ok() {
        None
    } else {
        let migrations =
            recovery_directory(guardian.as_raw_fd(), "terminal-migrations", Some(0o700))?;
        if recovery_absent(migrations.as_raw_fd(), "cold-recovery").is_ok() {
            None
        } else {
            let cold = recovery_directory(migrations.as_raw_fd(), "cold-recovery", Some(0o700))?;
            cold_resolve_intent(cold.as_raw_fd())?.map(|raw| (cold, raw))
        }
    };
    let (old_source, cold_context_sha, cold_context_state) = if let Some((cold, intent_raw)) =
        &cold_state
    {
        let intent = cold_json(intent_raw)?;
        let context_sha = cold_hex(&intent["old_context_sha256"])?;
        if intent["old_boot_id"] != successor.old_boot_id
            || intent["current_boot_id"] != current_boot_id
            || intent["successor_intent_sha256"] != digest(successor_raw)
            || intent["old_active_sha256"] != digest(&history.active_bytes)
            || intent["old_stopped_sha256"] != digest(&history.stopped_bytes)
            || intent["old_install_sha256"] != old_install_sha
            || intent["guardian_rotation_intent_sha256"] != digest(&rotation_intent)
            || intent["guardian_rotation_denied_sha256"] != digest(&rotation_denied)
            || intent["guardian_rotation_retired_sha256"] != digest(&rotation_retired)
        {
            return Err(refuse());
        }
        let context_name = format!("cold-old-context-{context_sha}.json");
        if recovery_absent(cold.as_raw_fd(), &context_name).is_ok() {
            let etc = recovery_chain(&["etc"], None)?;
            let live =
                read_sealed_leaf_bounded(etc.as_raw_fd(), "aegis-auto-terminal-source.json", 4096)?;
            if intent["old_source_sha256"] != digest(&live) {
                return Err(refuse());
            }
            (
                live,
                Some(context_sha.to_owned()),
                "missing_reconstructible",
            )
        } else {
            let raw = read_sealed_leaf_bounded(cold.as_raw_fd(), &context_name, 256 << 10)?;
            if digest(&raw) != context_sha {
                return Err(refuse());
            }
            let context = cold_json(&raw)?;
            if context["schema"] != "aegis_auto_terminal_cold_old_context_v1"
                || context["old_boot_id"] != successor.old_boot_id
                || context["current_boot_id"] != current_boot_id
                || context["old_active_sha256"] != digest(&history.active_bytes)
                || context["old_stopped_sha256"] != digest(&history.stopped_bytes)
                || context["successor_intent_sha256"] != digest(successor_raw)
                || context["old_install_sha256"] != old_install_sha
                || context["old_source_sha256"] != intent["old_source_sha256"]
                || context["guardian_rotation_intent_sha256"] != digest(&rotation_intent)
                || context["guardian_rotation_denied_sha256"] != digest(&rotation_denied)
                || context["guardian_rotation_retired_sha256"] != digest(&rotation_retired)
                || context["next_bundle_manifest_sha256"]
                    != successor
                        .next_bundle_manifest_sha256
                        .as_deref()
                        .ok_or_else(refuse)?
                || context["next_sums_sha256"] != sums_sha
            {
                return Err(refuse());
            }
            let source_hex = context["leaves"]["/etc/aegis-auto-terminal-source.json"]["hex"]
                .as_str()
                .ok_or_else(refuse)?;
            let old = hex::decode(source_hex).map_err(|_| refuse())?;
            if intent["old_source_sha256"] != digest(&old) {
                return Err(refuse());
            }
            let source_value = cold_json(&old)?;
            if context["selected_manager"] != source_value["selected_manager"]
                || intent["selected_manager"] != source_value["selected_manager"]
            {
                return Err(refuse());
            }
            (old, Some(context_sha.to_owned()), "present_exact")
        }
    } else {
        let etc = recovery_chain(&["etc"], None)?;
        (
            read_sealed_leaf_bounded(etc.as_raw_fd(), "aegis-auto-terminal-source.json", 4096)?,
            None,
            "absent_not_prepared",
        )
    };
    let old_source_value = cold_json(&old_source)?;
    if old_source_value["schema"] != "aegis_auto_terminal_source_v1"
        || old_source_value["selected_manager"].as_str().is_none()
    {
        return Err(refuse());
    }
    if let Some((_, intent_raw)) = &cold_state {
        let intent = cold_json(intent_raw)?;
        if intent["old_source_sha256"] != digest(&old_source)
            || intent["selected_manager"] != old_source_value["selected_manager"]
        {
            return Err(refuse());
        }
    }
    let release_name = root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    let release = recovery_chain(
        &["var", "lib", "aegis-auto", "releases", release_name],
        Some(0o700),
    )?;
    let new_package_sha = cold_anchored_client_package_sha(release.as_raw_fd(), sums_sha)?;
    let guardian_source_sha = cold_script_source(release.as_raw_fd(), "aegis_auto_guardian.py")?;
    let observer_source_sha =
        cold_script_source(release.as_raw_fd(), "aegis_auto_terminal_witness.py")?;
    let package_helper_sha = cold_script_source(release.as_raw_fd(), "aegis_installer_auto_v2.py")?;
    let site_helper_sha =
        cold_script_source(release.as_raw_fd(), "aegis_auto_terminal_register.py")?;
    Ok(ColdRetiredHistory {
        old_boot_id: successor.old_boot_id.clone(),
        current_boot_id,
        old_active_sha256: digest(&history.active_bytes),
        old_stopped_sha256: digest(&history.stopped_bytes),
        successor_intent_sha256: digest(successor_raw),
        old_install_sha256: old_install_sha.to_owned(),
        old_source_sha256: digest(&old_source),
        old_context_sha256: None,
        cold_old_context_sha256: cold_context_sha,
        cold_context_state,
        old_observer_archive_sha256: None,
        migration_state: "preparation_absent",
        context_state: "absent_not_prepared",
        new_candidate_sha256,
        new_package_sha256: new_package_sha,
        bundle_manifest_sha256: successor
            .next_bundle_manifest_sha256
            .as_deref()
            .ok_or_else(refuse)?
            .to_owned(),
        sums_sha256: sums_sha.to_owned(),
        retained_root: root.to_str().ok_or_else(refuse)?.to_owned(),
        migration_record_sha256: None,
        guardian_source_sha256: guardian_source_sha,
        observer_source_sha256: observer_source_sha,
        package_helper_sha256: package_helper_sha,
        site_helper_sha256: site_helper_sha,
        old_root: old_root.to_str().ok_or_else(refuse)?.to_owned(),
        old_candidate_sha256: old_candidate_sha,
        guardian_rotation_intent_sha256: digest(&rotation_intent),
        guardian_rotation_denied_sha256: digest(&rotation_denied),
        guardian_rotation_retired_sha256: digest(&rotation_retired),
    })
}

pub(super) fn cold_retired_history(root: &Path) -> Result<ColdRetiredHistory> {
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let archived_successor = if recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF).is_ok() {
        let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
        let migrations =
            recovery_directory(guardian.as_raw_fd(), "terminal-migrations", Some(0o700))?;
        let cold = recovery_directory(migrations.as_raw_fd(), "cold-recovery", Some(0o700))?;
        let raw = cold_resolve_intent(cold.as_raw_fd())?.ok_or_else(refuse)?;
        let value = cold_json(&raw)?;
        if value["schema"] != "aegis_auto_terminal_cold_intent_v1"
            || value["current_boot_id"] != current_boot_id()?
        {
            return Err(refuse());
        }
        let sha = cold_hex(&value["successor_intent_sha256"])?;
        let history = history_dir(control.as_raw_fd(), false)?;
        let bytes = read_archived(history.as_raw_fd(), "intent", sha)?;
        let intent: SuccessorIntent = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
        successor_shape(&intent)?;
        if digest(&bytes) != sha || serde_json::to_vec(&intent).map_err(|_| refuse())? != bytes {
            return Err(refuse());
        }
        Some((bytes, intent))
    } else {
        None
    };
    let history = successor_history_with_intent(archived_successor.clone())?;
    if history.stopped["stage"]["mode"] == "socks-only" {
        return Err(refuse());
    }
    let (successor_raw, successor) = if let Some(value) = archived_successor {
        value
    } else {
        read_intent(control.as_raw_fd())?
    };
    if successor.old_boot_id != history.stopped["terminal"]["boot_id"]
        || successor.next_public_payload_root != root.to_str().ok_or_else(refuse)?
    {
        return Err(refuse());
    }
    let current_boot_id = current_boot_id()?;
    if current_boot_id == successor.old_boot_id {
        return Err(refuse());
    }
    let (new_candidate_sha256, new_installer_sha256) =
        verified_retained_source(root, &root.join("bin/aegis-client"))?;
    if new_candidate_sha256 != successor.next_candidate_sha256
        || new_installer_sha256 != successor.next_installer_sha256
    {
        return Err(refuse());
    }
    let expected_bundle = successor
        .next_bundle_manifest_sha256
        .as_deref()
        .ok_or_else(refuse)?;
    let expected_sums = successor.next_sums_sha256.as_deref().ok_or_else(refuse)?;
    let (bundle_sha, sums_sha) =
        retained_bundle_anchor(root, &new_candidate_sha256, &new_installer_sha256)?;
    if bundle_sha != expected_bundle || sums_sha != expected_sums {
        return Err(refuse());
    }
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if recovery_file_hash(running.as_raw_fd(), 256 << 20)?.1 != new_candidate_sha256 {
        return Err(refuse());
    }
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    if recovery_absent(guardian.as_raw_fd(), "terminal-migrations").is_ok() {
        return cold_before_migration_prepare(
            root,
            &history,
            &successor_raw,
            &successor,
            current_boot_id,
            new_candidate_sha256,
            &sums_sha,
        );
    }
    let migration = recovery_directory(guardian.as_raw_fd(), "terminal-migrations", Some(0o700))?;
    let current_pending = cold_current_pending(migration.as_raw_fd())?;
    let pending_present = current_pending.is_some();
    if !pending_present {
        if recovery_absent(migration.as_raw_fd(), "head.json").is_ok() {
            return cold_before_migration_prepare(
                root,
                &history,
                &successor_raw,
                &successor,
                current_boot_id,
                new_candidate_sha256,
                &sums_sha,
            );
        }
        let head_raw = read_sealed_leaf_bounded(migration.as_raw_fd(), "head.json", 4096)?;
        let head = cold_json(&head_raw)?;
        if head["schema"] != "aegis_auto_terminal_migration_head_v1" {
            return Err(refuse());
        }
        let prior_edge_sha = cold_hex(&head["edge_sha256"])?;
        let prior_edge_raw = read_sealed_leaf_bounded(
            migration.as_raw_fd(),
            &format!("edge-{prior_edge_sha}.json"),
            4096,
        )?;
        if digest(&prior_edge_raw) != prior_edge_sha {
            return Err(refuse());
        }
        let prior_edge = cold_json(&prior_edge_raw)?;
        if prior_edge["schema"] != "aegis_auto_terminal_migration_edge_v1" {
            return Err(refuse());
        }
        if prior_edge["candidate_sha256"] == history.stopped["input"]["candidate_sha256"] {
            let complete = read_sealed_leaf_bounded(
                migration.as_raw_fd(),
                &format!("complete-{prior_edge_sha}.json"),
                4096,
            )?;
            let completed = cold_json(&complete)?;
            if completed["schema"] != "aegis_auto_terminal_migration_complete_v1"
                || completed["edge_sha256"] != prior_edge_sha
                || completed["candidate_sha256"] != prior_edge["candidate_sha256"]
            {
                return Err(refuse());
            }
            let preparation = cold_before_migration_prepare(
                root,
                &history,
                &successor_raw,
                &successor,
                current_boot_id,
                new_candidate_sha256,
                &sums_sha,
            )?;
            if prior_edge["new_install_sha256"] != preparation.old_install_sha256
                || prior_edge["new_source_sha256"] != preparation.old_source_sha256
            {
                return Err(refuse());
            }
            return Ok(preparation);
        }
        if prior_edge["candidate_sha256"] != new_candidate_sha256 {
            return Err(refuse());
        }
    }
    let (context_sha, old_source_sha, new_package_sha, migration_raw_sha, observer_archive_sha) =
        if pending_present {
            let raw = current_pending.as_ref().ok_or_else(refuse)?.clone();
            let pending = cold_json(&raw)?;
            if pending["schema"] != "aegis_auto_terminal_migration_pending_v1"
                || pending["boot_id"] != successor.old_boot_id
                || pending["release_root"] != root.to_str().ok_or_else(refuse)?
                || pending["candidate_sha256"] != new_candidate_sha256
                || pending["next_bundle_manifest_sha256"] != bundle_sha
                || pending["next_sums_sha256"] != sums_sha
            {
                return Err(refuse());
            }
            let archive_name = format!("observer-runtime-{}.json", digest(&raw));
            let observer_archive_sha =
                if recovery_absent(migration.as_raw_fd(), &archive_name).is_ok() {
                    None
                } else {
                    let archive =
                        read_sealed_leaf_bounded(migration.as_raw_fd(), &archive_name, 16384)?;
                    let record = cold_json(&archive)?;
                    if record["schema"] != "aegis_auto_terminal_observer_runtime_v1"
                        || record["pending_sha256"] != digest(&raw)
                        || record["old_source_sha256"] != pending["old_source_sha256"]
                    {
                        return Err(refuse());
                    }
                    Some(digest(&archive))
                };
            (
                cold_hex(&pending["context_sha256"])?.to_owned(),
                cold_hex(&pending["old_source_sha256"])?.to_owned(),
                cold_hex(&pending["package_sha256"])?.to_owned(),
                digest(&raw),
                observer_archive_sha,
            )
        } else {
            let head_raw = read_sealed_leaf_bounded(migration.as_raw_fd(), "head.json", 4096)?;
            let head = cold_json(&head_raw)?;
            if head["schema"] != "aegis_auto_terminal_migration_head_v1" {
                return Err(refuse());
            }
            let edge_sha = cold_hex(&head["edge_sha256"])?;
            let edge_raw = read_sealed_leaf_bounded(
                migration.as_raw_fd(),
                &format!("edge-{edge_sha}.json"),
                4096,
            )?;
            if digest(&edge_raw) != edge_sha {
                return Err(refuse());
            }
            let edge = cold_json(&edge_raw)?;
            let complete_raw = read_sealed_leaf_bounded(
                migration.as_raw_fd(),
                &format!("complete-{edge_sha}.json"),
                4096,
            )?;
            let complete = cold_json(&complete_raw)?;
            if edge["schema"] != "aegis_auto_terminal_migration_edge_v1"
                || complete["schema"] != "aegis_auto_terminal_migration_complete_v1"
                || complete["edge_sha256"] != edge_sha
                || edge["candidate_sha256"] != new_candidate_sha256
                || edge["next_bundle_manifest_sha256"] != bundle_sha
                || edge["next_sums_sha256"] != sums_sha
                || complete["candidate_sha256"] != new_candidate_sha256
                || complete["intent_sha256"] != edge["intent_sha256"]
            {
                return Err(refuse());
            }
            let observer_archive_sha = cold_hex(&edge["observer_runtime_sha256"])?.to_owned();
            let pending_sha = cold_hex(&edge["intent_sha256"])?;
            let observer_archive = read_sealed_leaf_bounded(
                migration.as_raw_fd(),
                &format!("observer-runtime-{pending_sha}.json"),
                16384,
            )?;
            let observer_record = cold_json(&observer_archive)?;
            if digest(&observer_archive) != observer_archive_sha
                || observer_record["schema"] != "aegis_auto_terminal_observer_runtime_v1"
                || observer_record["pending_sha256"] != pending_sha
                || observer_record["old_source_sha256"] != edge["old_source_sha256"]
            {
                return Err(refuse());
            }
            (
                cold_hex(&edge["old_context_sha256"])?.to_owned(),
                cold_hex(&edge["old_source_sha256"])?.to_owned(),
                cold_hex(&edge["package_sha256"])?.to_owned(),
                digest(&edge_raw),
                Some(observer_archive_sha),
            )
        };
    let context_name = format!("context-{context_sha}.json");
    let context_present = recovery_absent(migration.as_raw_fd(), &context_name).is_err();
    if !context_present && !pending_present {
        return Err(refuse());
    }
    let context = if context_present {
        let context_raw =
            read_sealed_leaf_bounded(migration.as_raw_fd(), &context_name, 256 << 10)?;
        if digest(&context_raw) != context_sha {
            return Err(refuse());
        }
        let value = cold_json(&context_raw)?;
        if value["schema"] != "aegis_auto_terminal_migration_context_v1"
            || value["old_source_sha256"] != old_source_sha
            || value["next_bundle_manifest_sha256"] != bundle_sha
            || value["next_sums_sha256"] != sums_sha
        {
            return Err(refuse());
        }
        Some(value)
    } else {
        None
    };
    if !context_present && observer_archive_sha.is_some() {
        return Err(refuse());
    }
    let rotation_intent = read_sealed_leaf_bounded(
        guardian.as_raw_fd(),
        "auto-guard-rotation-intent.json",
        1 << 20,
    )?;
    let rotation = cold_json(&rotation_intent)?;
    let rotation_old_install_sha = cold_hex(&rotation["old_install_sha256"])?;
    let old_install_sha = if let Some(value) = &context {
        let sha = cold_hex(&value["old_install_sha256"])?;
        if sha != rotation_old_install_sha {
            return Err(refuse());
        }
        sha
    } else {
        rotation_old_install_sha
    };
    let old_install_name = if context.is_some() {
        format!("auto-guardian-install-guarded-{old_install_sha}.json")
    } else {
        "auto-guardian-install.json".to_owned()
    };
    let old_install_raw =
        read_sealed_leaf_bounded(guardian.as_raw_fd(), &old_install_name, 1 << 20)?;
    if digest(&old_install_raw) != old_install_sha {
        return Err(refuse());
    }
    let old_install = cold_json(&old_install_raw)?;
    if old_install["worker_sha256"] != history.stopped["input"]["candidate_sha256"] {
        return Err(refuse());
    }
    let old_root = Path::new(
        history.stopped["input"]["public_payload_root"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let old_candidate = old_root.join("bin/aegis-client");
    let (old_candidate_sha, _) = verified_retained_source(old_root, &old_candidate)?;
    if old_candidate_sha != old_install["worker_sha256"] {
        return Err(refuse());
    }
    let source_raw = if let Some(value) = &context {
        let leaves = value["leaves"].as_object().ok_or_else(refuse)?;
        let source_hex = leaves
            .get("/etc/aegis-auto-terminal-source.json")
            .and_then(|v| v["hex"].as_str())
            .ok_or_else(refuse)?;
        hex::decode(source_hex).map_err(|_| refuse())?
    } else {
        let etc = recovery_chain(&["etc"], None)?;
        read_sealed_leaf_bounded(etc.as_raw_fd(), "aegis-auto-terminal-source.json", 4096)?
    };
    if digest(&source_raw) != old_source_sha {
        return Err(refuse());
    }
    let release_name = root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    let release = recovery_chain(
        &["var", "lib", "aegis-auto", "releases", release_name],
        Some(0o700),
    )?;
    if cold_anchored_client_package_sha(release.as_raw_fd(), &sums_sha)? != new_package_sha {
        return Err(refuse());
    }
    let guardian_source_sha256 = cold_script_source(release.as_raw_fd(), "aegis_auto_guardian.py")?;
    let observer_source_sha256 =
        cold_script_source(release.as_raw_fd(), "aegis_auto_terminal_witness.py")?;
    let package_helper_sha256 =
        cold_script_source(release.as_raw_fd(), "aegis_installer_auto_v2.py")?;
    let site_helper_sha256 =
        cold_script_source(release.as_raw_fd(), "aegis_auto_terminal_register.py")?;
    let rotation_intent = read_sealed_leaf_bounded(
        guardian.as_raw_fd(),
        "auto-guard-rotation-intent.json",
        1 << 20,
    )?;
    let rotation_denied = read_sealed_leaf_bounded(
        guardian.as_raw_fd(),
        "auto-guard-rotation-denied.json",
        1 << 20,
    )?;
    let rotation_retired = read_sealed_leaf_bounded(
        guardian.as_raw_fd(),
        "auto-guard-rotation-retired.json",
        1 << 20,
    )?;
    let rotation = cold_json(&rotation_intent)?;
    let denied = cold_json(&rotation_denied)?;
    let retired = cold_json(&rotation_retired)?;
    if rotation["schema"] != "aegis_auto_guard_rotation_intent_v1"
        || rotation["boot_id"] != successor.old_boot_id
        || rotation["old_install_sha256"] != old_install_sha
        || rotation["successor"]["intent_sha256"] != digest(&successor_raw)
        || denied["schema"] != "aegis_auto_guard_rotation_denied_v1"
        || denied["intent_sha256"] != digest(&rotation_intent)
        || retired["schema"] != "aegis_auto_guard_rotation_retired_v1"
        || retired["intent_sha256"] != digest(&rotation_intent)
        || retired["no_live_actors"] != true
    {
        return Err(refuse());
    }
    Ok(ColdRetiredHistory {
        old_boot_id: successor.old_boot_id,
        current_boot_id,
        old_active_sha256: digest(&history.active_bytes),
        old_stopped_sha256: digest(&history.stopped_bytes),
        successor_intent_sha256: digest(&successor_raw),
        old_install_sha256: old_install_sha.to_owned(),
        old_source_sha256: old_source_sha,
        old_context_sha256: Some(context_sha),
        cold_old_context_sha256: None,
        cold_context_state: "absent_not_prepared",
        old_observer_archive_sha256: observer_archive_sha,
        migration_state: if pending_present {
            "pending_prefix"
        } else {
            "completed_edge"
        },
        context_state: if context_present {
            "present_exact"
        } else {
            "missing_reconstructible"
        },
        new_candidate_sha256,
        new_package_sha256: new_package_sha,
        bundle_manifest_sha256: bundle_sha,
        sums_sha256: sums_sha,
        retained_root: root.to_str().ok_or_else(refuse)?.to_owned(),
        migration_record_sha256: Some(migration_raw_sha),
        guardian_source_sha256,
        observer_source_sha256,
        package_helper_sha256,
        site_helper_sha256,
        old_root: old_root.to_str().ok_or_else(refuse)?.to_owned(),
        old_candidate_sha256: old_candidate_sha,
        guardian_rotation_intent_sha256: digest(&rotation_intent),
        guardian_rotation_denied_sha256: digest(&rotation_denied),
        guardian_rotation_retired_sha256: digest(&rotation_retired),
    })
}

/// B-native source gate for the externally authenticated cold launcher.  The
/// launcher has already checked this ELF against its independent host pin;
/// this gate binds its coordinator to A's immutable stopped-successor intent
/// before any B Python byte is executed. It claims no current-boot recovery.
pub(super) fn cold_bootstrap_source(root: &Path) -> Result<ColdBootstrapSource> {
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let archived = if recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF).is_ok() {
        let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
        let migrations =
            recovery_directory(guardian.as_raw_fd(), "terminal-migrations", Some(0o700))?;
        let cold = recovery_directory(migrations.as_raw_fd(), "cold-recovery", Some(0o700))?;
        let raw = cold_resolve_intent(cold.as_raw_fd())?.ok_or_else(refuse)?;
        let value = cold_json(&raw)?;
        if value["schema"] != "aegis_auto_terminal_cold_intent_v1"
            || value["current_boot_id"] != current_boot_id()?
        {
            return Err(refuse());
        }
        let sha = cold_hex(&value["successor_intent_sha256"])?;
        let history = history_dir(control.as_raw_fd(), false)?;
        let bytes = read_archived(history.as_raw_fd(), "intent", sha)?;
        let intent: SuccessorIntent = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
        successor_shape(&intent)?;
        if digest(&bytes) != sha || serde_json::to_vec(&intent).map_err(|_| refuse())? != bytes {
            return Err(refuse());
        }
        Some((bytes, intent))
    } else {
        None
    };
    let history = successor_history_with_intent(archived.clone())?;
    if history.stopped["stage"]["mode"] == "socks-only" {
        return Err(refuse());
    }
    let (raw, intent) = if let Some(value) = archived {
        value
    } else {
        read_intent(control.as_raw_fd())?
    };
    if intent.old_boot_id != history.stopped["terminal"]["boot_id"]
        || intent.next_public_payload_root != root.to_str().ok_or_else(refuse)?
        || intent.old_boot_id == current_boot_id()?
    {
        return Err(refuse());
    }
    let candidate = root.join("bin/aegis-client");
    let (candidate_sha, installer_sha) = verified_retained_source(root, &candidate)?;
    if candidate_sha != intent.next_candidate_sha256
        || installer_sha != intent.next_installer_sha256
    {
        return Err(refuse());
    }
    let (bundle_sha, sums_sha) = retained_bundle_anchor(root, &candidate_sha, &installer_sha)?;
    if intent.next_bundle_manifest_sha256.as_deref() != Some(bundle_sha.as_str())
        || intent.next_sums_sha256.as_deref() != Some(sums_sha.as_str())
    {
        return Err(refuse());
    }
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if recovery_file_hash(running.as_raw_fd(), 256 << 20)?.1 != candidate_sha {
        return Err(refuse());
    }
    let name = root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    let release = recovery_chain(&["var", "lib", "aegis-auto", "releases", name], Some(0o700))?;
    let _ = cold_anchored_client_package_sha(release.as_raw_fd(), &sums_sha)?;
    let coordinator_sha = cold_script_source(release.as_raw_fd(), "aegis_installer_auto_v2.py")?;
    Ok(ColdBootstrapSource {
        candidate_sha256: candidate_sha,
        coordinator_sha256: coordinator_sha,
        successor_intent_sha256: digest(&raw),
        bundle_manifest_sha256: bundle_sha,
        sums_sha256: sums_sha,
    })
}

/// Classify the prior B pointer from durable native and terminal lineage.
/// A reported sealed owner must have its full activation body after /run is
/// gone; process absence or a bare generation leaf never proves retirement.
fn cold_pointer_retire_intent(
    prior_sha: &str,
    original_sha: &str,
    root: &Path,
) -> Result<Option<serde_json::Value>> {
    let cold = cold_recovery_dir()?;
    let name = format!("prior-pointer-retire-intent-{prior_sha}.json");
    if recovery_absent(cold.as_raw_fd(), &name).is_ok() {
        return Ok(None);
    }
    let raw = read_sealed_leaf_bounded(cold.as_raw_fd(), &name, 4096)?;
    let value = cold_json(&raw)?;
    cold_exact_keys(
        &value,
        &[
            "schema",
            "current_boot_id",
            "prior_intent_sha256",
            "original_intent_sha256",
            "retained_root",
            "old_pointer_state",
            "old_pointer_sha256",
            "active_generation_sha256",
            "old_activation_sha256",
            "unsealed_recovery_sha256",
            "deny_policy_sha256",
            "guard30_sha256",
            "no_client_grant",
        ],
    )?;
    let state = value["old_pointer_state"].as_str().ok_or_else(refuse)?;
    if value["schema"] != "aegis_auto_v2_cold_prior_pointer_retire_intent_v1"
        || value["prior_intent_sha256"] != prior_sha
        || value["original_intent_sha256"] != original_sha
        || value["retained_root"].as_str() != root.to_str()
        || value["current_boot_id"].as_str().is_none_or(|boot| {
            boot.len() != 36
                || !boot.bytes().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                    }
                })
        })
        || value["no_client_grant"] != true
        || cold_hex(&value["deny_policy_sha256"]).is_err()
        || cold_hex(&value["guard30_sha256"]).is_err()
        || !["absent", "unsealed", "sealed", "sealed_incomplete"].contains(&state)
        || match state {
            "absent" => [
                "old_pointer_sha256",
                "active_generation_sha256",
                "old_activation_sha256",
                "unsealed_recovery_sha256",
            ]
            .iter()
            .any(|key| !value[*key].is_null()),
            "unsealed" => {
                cold_hex(&value["old_pointer_sha256"]).is_err()
                    || cold_hex(&value["unsealed_recovery_sha256"]).is_err()
                    || !value["active_generation_sha256"].is_null()
                    || !value["old_activation_sha256"].is_null()
            }
            "sealed" | "sealed_incomplete" => {
                [
                    "old_pointer_sha256",
                    "active_generation_sha256",
                    "old_activation_sha256",
                ]
                .iter()
                .any(|key| cold_hex(&value[*key]).is_err())
                    || !value["unsealed_recovery_sha256"].is_null()
            }
            _ => true,
        }
    {
        return Err(refuse());
    }
    Ok(Some(value))
}

fn cold_prior_b_pointer(
    control: i32,
    guardian: i32,
    root: &Path,
    ancestor_boots: &[String],
    original: (&str, &str),
    successor: &SuccessorIntent,
    candidate_and_prior: (&str, &str),
) -> Result<&'static str> {
    let (original_intent_sha, original_successor_sha) = original;
    let (candidate_sha, prior_sha) = candidate_and_prior;
    let retirement = cold_pointer_retire_intent(prior_sha, original_intent_sha, root)?;
    let retired_state = retirement
        .as_ref()
        .and_then(|row| row["old_pointer_state"].as_str());
    let sealed = recovery_absent(control, LEAF).is_err()
        || matches!(retired_state, Some("sealed" | "sealed_incomplete"));
    let pointer = recovery_absent(control, "current.json").is_err();
    let unsealed =
        recovery_absent(control, RECOVERY_LEAF).is_err() || retired_state == Some("unsealed");
    if sealed && unsealed {
        return Err(refuse());
    }
    if !sealed {
        if pointer != unsealed && retirement.is_none() {
            return Err(refuse());
        }
        if unsealed {
            let seal_sha = retirement
                .as_ref()
                .and_then(|row| row["unsealed_recovery_sha256"].as_str());
            let history = if recovery_absent(control, HISTORY_DIR).is_ok() {
                None
            } else {
                Some(history_dir(control, false)?)
            };
            let live = if recovery_absent(control, RECOVERY_LEAF).is_ok() {
                None
            } else {
                Some(read_sealed_leaf(control, RECOVERY_LEAF)?)
            };
            let archived = if let (Some(sha), Some(dir)) = (seal_sha, history.as_ref()) {
                read_archived_optional(dir.as_raw_fd(), "passive-cold-prior-unsealed", sha)?
            } else {
                None
            };
            let raw = match (live, archived) {
                (Some(a), Some(b)) if a == b => a,
                (Some(a), None) => a,
                (None, Some(b)) => b,
                _ => return Err(refuse()),
            };
            if seal_sha.is_some_and(|sha| digest(&raw) != sha) {
                return Err(refuse());
            }
            let report = validate_unsealed_stopped_recovery_bytes(&raw)?;
            if !ancestor_boots
                .iter()
                .any(|boot| report["terminal"]["boot_id"] == *boot)
                || report["input"]["candidate_sha256"] != candidate_sha
                || report["stage"]["phase"] != "finalized"
            {
                return Err(refuse());
            }
            let pointer_sha = retirement
                .as_ref()
                .and_then(|row| row["old_pointer_sha256"].as_str());
            let pointer_raw = boot_pointer(control, &report, pointer_sha)?;
            if pointer_sha.is_some_and(|sha| digest(&pointer_raw) != sha) {
                return Err(refuse());
            }
            return Ok("unsealed");
        }
        if retirement.is_some() && retired_state != Some("absent") {
            return Err(refuse());
        }
        if pointer {
            return Err(refuse());
        }
        return Ok("absent");
    }
    if !pointer && retirement.is_none() {
        return Err(refuse());
    }
    let history = history_dir(control, false)?;
    let live_active = if recovery_absent(control, LEAF).is_ok() {
        None
    } else {
        Some(read_sealed_leaf(control, LEAF)?)
    };
    let archived_active = if let Some(sha) = retirement
        .as_ref()
        .and_then(|row| row["active_generation_sha256"].as_str())
    {
        read_archived_optional(history.as_raw_fd(), "passive-cold-prior-active", sha)?
    } else {
        None
    };
    let active_raw = match (live_active, archived_active) {
        (Some(a), Some(b)) if a == b => a,
        (Some(a), None) => a,
        (None, Some(b)) => b,
        _ => return Err(refuse()),
    };
    if retirement.as_ref().is_some_and(|row| {
        row["active_generation_sha256"].as_str() != Some(digest(&active_raw).as_str())
    }) {
        return Err(refuse());
    }
    let active = parse_active(&active_raw)?;
    let cold_sha = active
        .predecessor_cold_intent_sha256
        .as_deref()
        .ok_or_else(refuse)?;
    let cold_raw = read_archived(history.as_raw_fd(), "cold-intent", cold_sha)?;
    let cold: ColdFirstArmIntent = serde_json::from_slice(&cold_raw).map_err(|_| refuse())?;
    if cold.schema != "aegis_auto_v2_cold_first_arm_intent_v1"
        || serde_json::to_vec(&cold).map_err(|_| refuse())? != cold_raw
        || !ancestor_boots.contains(&cold.current_boot_id)
        || cold.successor_intent_sha256 != original_successor_sha
        || cold.old_boot_id != successor.old_boot_id
        || cold.old_active_sha256 != successor.old_active_sha256
        || cold.old_stopped_sha256 != successor.old_stopped_sha256
        || cold.public_payload_root != root.to_str().ok_or_else(refuse)?
        || cold.candidate_binary != successor.next_candidate_binary
        || cold.candidate_sha256 != candidate_sha
        || cold.installer_sha256 != successor.next_installer_sha256
        || active.report["terminal"]["boot_id"] != cold.current_boot_id
        || active.report["input"]["candidate_sha256"] != candidate_sha
        || active.report["stage"]["phase"] != "finalized"
        || !exact_hex(original_intent_sha)
    {
        return Err(refuse());
    }
    let pointer_sha = retirement
        .as_ref()
        .and_then(|row| row["old_pointer_sha256"].as_str());
    let pointer_raw = boot_pointer(control, &active.report, pointer_sha)?;
    if pointer_sha.is_some_and(|sha| digest(&pointer_raw) != sha) {
        return Err(refuse());
    }
    let unit = active.report["terminal"]["private_unit"]
        .as_str()
        .ok_or_else(refuse)?;
    let token = unit
        .strip_prefix("aegis-auto@")
        .and_then(|value| value.strip_suffix(".service"))
        .filter(|value| exact_hex(value))
        .ok_or_else(refuse)?;
    let pending_raw = read_sealed_leaf_bounded(
        guardian,
        &format!("auto-terminal-registration-pending-{token}.json"),
        4096,
    )?;
    let complete_name = format!("auto-terminal-registration-complete-{token}.json");
    let complete_raw = if recovery_absent(guardian, &complete_name).is_ok() {
        None
    } else {
        Some(read_sealed_leaf_bounded(guardian, &complete_name, 4096)?)
    };
    let activation_name = format!("auto-terminal-activation-{token}.json");
    let activation_raw = if recovery_absent(guardian, &activation_name).is_ok() {
        None
    } else {
        Some(read_sealed_leaf_bounded(guardian, &activation_name, 4096)?)
    };
    let preseal_raw = read_sealed_leaf_bounded(
        guardian,
        &format!("auto-terminal-activation-preseal-{token}.json"),
        4096,
    )?;
    let pending = cold_json(&pending_raw)?;
    let complete = complete_raw
        .as_ref()
        .map(|raw| cold_json(raw))
        .transpose()?;
    let activation = activation_raw
        .as_ref()
        .map(|raw| cold_json(raw))
        .transpose()?;
    let preseal = cold_json(&preseal_raw)?;
    cold_exact_keys(&pending, &["schema", "boot_id", "unit", "source_sha256"])?;
    if let Some(complete) = &complete {
        cold_exact_keys(
            complete,
            &[
                "schema",
                "pending_sha256",
                "activation_sha256",
                "active_generation_sha256",
            ],
        )?;
    }
    cold_exact_keys(
        &preseal,
        &[
            "schema",
            "boot_id",
            "unit",
            "nonce",
            "stage_path",
            "stage_dev",
            "stage_ino",
            "terminal_sha256",
            "installed_generation_sha256",
            "installed_manifest_sha256",
            "source_sha256",
        ],
    )?;
    if let Some(activation) = &activation {
        cold_exact_keys(
            activation,
            &[
                "schema",
                "boot_id",
                "unit",
                "nonce",
                "stage_path",
                "stage_dev",
                "stage_ino",
                "terminal_sha256",
                "installed_generation_sha256",
                "installed_manifest_sha256",
                "active_generation_sha256",
                "active_report_sha256",
                "boot_snapshot_sha256",
                "source_sha256",
            ],
        )?;
    }
    if pending["schema"] != "aegis_auto_terminal_registration_pending_v1"
        || pending["unit"] != unit
        || pending["boot_id"] != cold.current_boot_id
        || complete.is_some() && activation.is_none()
        || complete.as_ref().is_some_and(|row| {
            row["schema"] != "aegis_auto_terminal_registration_complete_v1"
                || row["pending_sha256"] != digest(&pending_raw)
                || row["activation_sha256"]
                    != activation_raw
                        .as_ref()
                        .map(|raw| digest(raw))
                        .unwrap_or_default()
                || row["active_generation_sha256"] != digest(&active_raw)
        })
        || preseal["schema"] != "aegis_auto_terminal_activation_preseal_v1"
        || preseal["unit"] != unit
        || preseal["boot_id"] != cold.current_boot_id
        || preseal["nonce"].as_str().is_none_or(|value| {
            value.len() != 32
                || value
                    .bytes()
                    .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
        })
        || preseal["source_sha256"] != pending["source_sha256"]
        || preseal["installed_manifest_sha256"]
            != active.report["input"]["installed_manifest_sha256"]
        || preseal["installed_generation_sha256"]
            .as_str()
            .is_none_or(|value| !exact_hex(value))
        || preseal["terminal_sha256"] != active.report["terminal"]["start_terminal_sha256"]
        || preseal["stage_path"] != active.report["stage"]["path"]
        || preseal["stage_dev"] != active.report["stage"]["device"]
        || preseal["stage_ino"] != active.report["stage"]["inode"]
        || activation.as_ref().is_some_and(|row| {
            row["schema"] != "aegis_auto_terminal_activation_v1"
                || row["unit"] != preseal["unit"]
                || row["boot_id"] != preseal["boot_id"]
                || row["nonce"] != preseal["nonce"]
                || row["source_sha256"] != preseal["source_sha256"]
                || row["installed_manifest_sha256"] != preseal["installed_manifest_sha256"]
                || row["installed_generation_sha256"] != preseal["installed_generation_sha256"]
                || row["terminal_sha256"] != preseal["terminal_sha256"]
                || row["stage_path"] != preseal["stage_path"]
                || row["stage_dev"] != preseal["stage_dev"]
                || row["stage_ino"] != preseal["stage_ino"]
                || row["active_generation_sha256"] != digest(&active_raw)
                || row["active_report_sha256"] != active.report_sha256
                || row["boot_snapshot_sha256"].as_str() != active.boot_snapshot_sha256.as_deref()
        })
    {
        return Err(refuse());
    }
    let state = if complete.is_some() {
        "sealed"
    } else {
        "sealed_incomplete"
    };
    if retired_state.is_some_and(|expected| expected != state) {
        return Err(refuse());
    }
    Ok(state)
}

/// Source identity for a fresh-boot rollover. It deliberately reads the old
/// immutable A successor and prior cold attempt rather than treating their
/// boot IDs or phase receipts as authority in the new boot.
pub(super) fn cold_original_intent(source: &ColdStaleSource) -> Result<serde_json::Value> {
    let cold = cold_recovery_dir()?;
    let name = if source.original_state == "active" {
        "intent.json".to_owned()
    } else {
        format!("intent-consumed-{}.json", source.original_intent_sha256)
    };
    let raw = read_sealed_leaf_bounded(cold.as_raw_fd(), &name, 8192)?;
    if digest(&raw) != source.original_intent_sha256 {
        return Err(refuse());
    }
    let value = cold_json(&raw)?;
    if value["schema"] != "aegis_auto_terminal_cold_intent_v1"
        || value["retained_root"] != source.retained_root
        || value["new_candidate_sha256"] != source.bootstrap.candidate_sha256
        || value["next_bundle_manifest_sha256"] != source.bootstrap.bundle_manifest_sha256
        || value["next_sums_sha256"] != source.bootstrap.sums_sha256
    {
        return Err(refuse());
    }
    Ok(value)
}

pub(super) fn cold_stale_source(root: &Path) -> Result<ColdStaleSource> {
    cold_stale_source_mode(root, false)
}

pub(super) fn cold_stale_source_for_stage(root: &Path) -> Result<ColdStaleSource> {
    cold_stale_source_mode(root, true)
}

fn cold_stale_source_mode(root: &Path, allow_unpublished_stage: bool) -> Result<ColdStaleSource> {
    let cold = cold_recovery_dir()?;
    let current_boot = current_boot_id()?;
    let prior = cold_prior_attempt(cold.as_raw_fd(), &current_boot, allow_unpublished_stage)?;
    let original = cold_json(&prior.original_raw)?;
    let previous = cold_json(&prior.prior_raw)?;
    let successor_sha = cold_hex(&original["successor_intent_sha256"])?;
    let rotation_sha = cold_hex(&original["guardian_rotation_intent_sha256"])?;
    let barrier_sha = cold_selected_barrier_sha(cold.as_raw_fd(), &prior.original_sha, &original)?;
    for field in [
        "old_boot_id",
        "old_active_sha256",
        "old_stopped_sha256",
        "successor_intent_sha256",
        "old_install_sha256",
        "old_source_sha256",
        "guardian_rotation_intent_sha256",
        "guardian_rotation_denied_sha256",
        "guardian_rotation_retired_sha256",
        "retained_root",
        "new_candidate_sha256",
        "new_package_sha256",
        "next_bundle_manifest_sha256",
        "next_sums_sha256",
    ] {
        if previous[field] != original[field] {
            return Err(refuse());
        }
    }
    if original["schema"] != "aegis_auto_terminal_cold_intent_v1"
        || previous["schema"] != "aegis_auto_terminal_cold_intent_v1"
        || previous["current_boot_id"] != prior.prior_boot
        || prior.prior_boot == current_boot
        || previous["successor_intent_sha256"] != successor_sha
        || previous["retained_root"] != root.to_str().ok_or_else(refuse)?
        || previous["next_bundle_manifest_sha256"] != original["next_bundle_manifest_sha256"]
        || previous["next_sums_sha256"] != original["next_sums_sha256"]
    {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let history = history_dir(control.as_raw_fd(), false)?;
    let successor_raw = read_archived(history.as_raw_fd(), "intent", successor_sha)?;
    let successor: SuccessorIntent =
        serde_json::from_slice(&successor_raw).map_err(|_| refuse())?;
    successor_shape(&successor)?;
    if digest(&successor_raw) != successor_sha
        || serde_json::to_vec(&successor).map_err(|_| refuse())? != successor_raw
        || successor.next_public_payload_root != root.to_str().ok_or_else(refuse)?
        || successor.old_boot_id != original["old_boot_id"]
    {
        return Err(refuse());
    }
    let old_active_raw =
        read_archived(history.as_raw_fd(), "active", &successor.old_active_sha256)?;
    let old_stopped_raw = read_archived(
        history.as_raw_fd(),
        "stopped",
        &successor.old_stopped_sha256,
    )?;
    let old_active = parse_active(&old_active_raw)?;
    parse_stopped(&old_stopped_raw, &old_active_raw, &old_active)?;
    successor_kind(&successor, &old_active.report)?;
    let old_root = old_active.report["input"]["public_payload_root"]
        .as_str()
        .ok_or_else(refuse)?
        .to_owned();
    if original["old_active_sha256"] != successor.old_active_sha256
        || original["old_stopped_sha256"] != successor.old_stopped_sha256
        || original["old_boot_id"] != successor.old_boot_id
        || original["new_candidate_sha256"] != successor.next_candidate_sha256
        || original["old_install_sha256"]
            .as_str()
            .is_none_or(|v| !exact_hex(v))
        || original["old_source_sha256"]
            .as_str()
            .is_none_or(|v| !exact_hex(v))
        || original["guardian_rotation_denied_sha256"]
            .as_str()
            .is_none_or(|v| !exact_hex(v))
        || original["guardian_rotation_retired_sha256"]
            .as_str()
            .is_none_or(|v| !exact_hex(v))
    {
        return Err(refuse());
    }
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let old_install_sha = cold_hex(&original["old_install_sha256"])?;
    let old_context_sha = if original["old_context_sha256"].is_null() {
        None
    } else {
        Some(cold_hex(&original["old_context_sha256"])?.to_owned())
    };
    let selected_manager = original["selected_manager"].as_str().ok_or_else(refuse)?;
    if !["NetworkManager.service", "systemd-networkd.service"].contains(&selected_manager) {
        return Err(refuse());
    }
    let old_install_raw = read_sealed_leaf_bounded(
        guardian.as_raw_fd(),
        &format!("auto-guardian-install-guarded-{old_install_sha}.json"),
        1 << 20,
    )?;
    if digest(&old_install_raw) != old_install_sha {
        return Err(refuse());
    }
    let rotation_intent = cold_rotation_leaf(
        guardian.as_raw_fd(),
        "auto-guard-rotation-intent.json",
        "auto-guard-prior-intent",
        rotation_sha,
    )?;
    let rotation_denied = cold_rotation_leaf(
        guardian.as_raw_fd(),
        "auto-guard-rotation-denied.json",
        "auto-guard-prior-denied",
        cold_hex(&original["guardian_rotation_denied_sha256"])?,
    )?;
    let rotation_retired = cold_rotation_leaf(
        guardian.as_raw_fd(),
        "auto-guard-rotation-retired.json",
        "auto-guard-prior-retired",
        cold_hex(&original["guardian_rotation_retired_sha256"])?,
    )?;
    let rotation = cold_json(&rotation_intent)?;
    let denied = cold_json(&rotation_denied)?;
    let retired = cold_json(&rotation_retired)?;
    if rotation["schema"] != "aegis_auto_guard_rotation_intent_v1"
        || rotation["boot_id"] != successor.old_boot_id
        || rotation["successor"]["intent_sha256"] != successor_sha
        || rotation["old_install_sha256"] != old_install_sha
        || denied["schema"] != "aegis_auto_guard_rotation_denied_v1"
        || denied["intent_sha256"] != rotation_sha
        || retired["schema"] != "aegis_auto_guard_rotation_retired_v1"
        || retired["intent_sha256"] != rotation_sha
        || retired["no_live_actors"] != true
    {
        return Err(refuse());
    }
    let old_install = cold_json(&old_install_raw)?;
    let old_candidate_sha = old_active.report["input"]["candidate_sha256"]
        .as_str()
        .ok_or_else(refuse)?
        .to_owned();
    let old_sums = cold_sums_map(Path::new(&old_root), &old_candidate_sha, None)?;
    for (path, field) in [
        (
            "scripts/lib/aegis_auto_terminal_register.py",
            "terminal_register_sha256",
        ),
        (
            "scripts/lib/aegis_auto_terminal_witness.py",
            "terminal_witness_sha256",
        ),
        (
            "scripts/lib/aegis_auto_terminal_boot_store.py",
            "terminal_boot_store_sha256",
        ),
        (
            "scripts/lib/aegis_auto_boot_transition.py",
            "terminal_transition_sha256",
        ),
        (
            "packaging/systemd/aegis-auto-terminal-a@.service",
            "terminal_a_unit_sha256",
        ),
        (
            "packaging/systemd/aegis-auto-terminal-b@.service",
            "terminal_b_unit_sha256",
        ),
        (
            "packaging/systemd/aegis-auto-terminal-observer.service",
            "terminal_observer_unit_sha256",
        ),
        (
            "packaging/systemd/aegis-auto-terminal-transition.service",
            "terminal_transition_unit_sha256",
        ),
        (
            "packaging/systemd/system-shutdown/aegis-auto-terminal-hook",
            "terminal_hook_staged_sha256",
        ),
    ] {
        if old_install[field].as_str() != old_sums.get(path).map(String::as_str) {
            return Err(refuse());
        }
    }
    let candidate = root.join("bin/aegis-client");
    let (candidate_sha, installer_sha) = verified_retained_source(root, &candidate)?;
    let (bundle_sha, sums_sha) = retained_bundle_anchor(root, &candidate_sha, &installer_sha)?;
    if candidate_sha != successor.next_candidate_sha256
        || installer_sha != successor.next_installer_sha256
        || successor.next_bundle_manifest_sha256.as_deref() != Some(bundle_sha.as_str())
        || successor.next_sums_sha256.as_deref() != Some(sums_sha.as_str())
        || original["next_bundle_manifest_sha256"] != bundle_sha
        || original["next_sums_sha256"] != sums_sha
    {
        return Err(refuse());
    }
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if recovery_file_hash(running.as_raw_fd(), 256 << 20)?.1 != candidate_sha {
        return Err(refuse());
    }
    let name = root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    let release = recovery_chain(&["var", "lib", "aegis-auto", "releases", name], Some(0o700))?;
    let new_package_sha = cold_anchored_client_package_sha(release.as_raw_fd(), &sums_sha)?;
    let coordinator_sha = cold_script_source(release.as_raw_fd(), "aegis_installer_auto_v2.py")?;
    let guardian_sha = cold_script_source(release.as_raw_fd(), "aegis_auto_guardian.py")?;
    let site_sha = cold_script_source(release.as_raw_fd(), "aegis_auto_terminal_register.py")?;
    let b_sums = cold_sums_map(root, &candidate_sha, Some(&sums_sha))?;
    let guard_shell_sha = b_sums
        .get("scripts/aegis-device-egress-guard.sh")
        .ok_or_else(refuse)?
        .to_owned();
    let pointer_state = cold_prior_b_pointer(
        control.as_raw_fd(),
        guardian.as_raw_fd(),
        root,
        &prior.ancestor_boot_ids,
        (&prior.original_sha, successor_sha),
        &successor,
        (&candidate_sha, &prior.prior_sha),
    )?;
    Ok(ColdStaleSource {
        bootstrap: ColdBootstrapSource {
            candidate_sha256: candidate_sha,
            coordinator_sha256: coordinator_sha.clone(),
            successor_intent_sha256: digest(&successor_raw),
            bundle_manifest_sha256: bundle_sha,
            sums_sha256: sums_sha,
        },
        retained_root: root.to_str().ok_or_else(refuse)?.to_owned(),
        original_intent_sha256: prior.original_sha,
        original_state: prior.original_state,
        prior_intent_sha256: prior.prior_sha,
        prior_boot_id: prior.prior_boot,
        old_root,
        old_candidate_sha256: old_candidate_sha,
        old_install_sha256: old_install_sha.to_owned(),
        new_package_sha256: new_package_sha,
        old_context_sha256: old_context_sha,
        selected_manager: selected_manager.to_owned(),
        guard_shell_sha256: guard_shell_sha,
        current_head_sha256: prior.current_head_sha,
        current_intent_sha256: prior.current_intent_sha,
        barrier_sha256: barrier_sha,
        guardian_rotation_intent_sha256: rotation_sha.to_owned(),
        guardian_source_sha256: guardian_sha,
        package_helper_sha256: coordinator_sha,
        site_helper_sha256: site_sha,
        prior_pointer_state: pointer_state,
    })
}

pub(super) fn retire_cold_successor(
    root: &Path,
    expected_intent_sha: &str,
    proof: &serde_json::Value,
    lock: &InstallLock,
) -> Result<Vec<u8>> {
    if cold_stale_source(root).is_ok() {
        return retire_cold_rollover_successor(root, expected_intent_sha, proof, lock);
    }
    lock.revalidate().map_err(|_| refuse())?;
    if !exact_hex(expected_intent_sha)
        || proof["schema"] != "aegis_auto_v2_cold_retired_successor_v2"
        || proof["retained_root"].as_str() != root.to_str()
        || proof["current_boot_id"] != current_boot_id()?
        || proof["package_state"] != "new_exact"
        || proof["quiesce_state"] != "post"
        || cold_hex(&proof["package_repair_receipt_sha256"]).is_err()
        || proof["client_actors_absent"] != true
        || proof["jobs_absent"] != true
        || proof["cgroups_empty"] != true
        || proof["stop_intent_absent"] != true
        || proof["infrastructure_qualified"] != true
        || proof["infrastructure_quiescent"] != true
        || proof["observer_state"] != "absent"
        || proof["cold_intent_sha256"] != expected_intent_sha
        || proof["context_state"] == "missing_reconstructible"
        || proof["cold_context_state"] == "missing_reconstructible"
        || proof["site_state"] == "b_prefix"
    {
        return Err(refuse());
    }
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let migration = recovery_directory(guardian.as_raw_fd(), "terminal-migrations", Some(0o700))?;
    let cold = recovery_directory(migration.as_raw_fd(), "cold-recovery", Some(0o700))?;
    let intent_raw = read_sealed_leaf_bounded(cold.as_raw_fd(), "intent.json", 4096)?;
    let intent = cold_json(&intent_raw)?;
    let history = cold_retired_history(root)?;
    if digest(&intent_raw) != expected_intent_sha
        || intent["schema"] != "aegis_auto_terminal_cold_intent_v1"
        || intent["current_boot_id"] != proof["current_boot_id"]
        || intent["old_boot_id"] != proof["old_boot_id"]
        || intent["retained_root"] != proof["retained_root"]
        || intent["old_active_sha256"] != proof["old_active_sha256"]
        || intent["old_stopped_sha256"] != proof["old_stopped_sha256"]
        || intent["old_install_sha256"] != proof["old_install_sha256"]
        || intent["old_source_sha256"] != proof["old_source_sha256"]
        || intent["old_context_sha256"].as_str() != history.cold_old_context_sha256.as_deref()
        || intent["guardian_rotation_intent_sha256"] != proof["guardian_rotation_intent_sha256"]
        || intent["guardian_rotation_denied_sha256"] != proof["guardian_rotation_denied_sha256"]
        || intent["guardian_rotation_retired_sha256"] != proof["guardian_rotation_retired_sha256"]
        || intent["successor_intent_sha256"] != proof["successor_intent_sha256"]
        || intent["new_candidate_sha256"] != proof["new_candidate_sha256"]
        || intent["new_package_sha256"] != proof["new_package_sha256"]
        || intent["selected_manager"] != proof["selected_manager"]
        || intent["manager31_sha256"] != proof["manager31_sha256"]
        || intent["guard30_sha256"] != proof["guard30_sha256"]
        || intent["deny_policy_sha256"] != proof["deny_policy_sha256"]
    {
        return Err(refuse());
    }
    if history.successor_intent_sha256 != proof["successor_intent_sha256"]
        || history.old_active_sha256 != proof["old_active_sha256"]
        || history.old_stopped_sha256 != proof["old_stopped_sha256"]
        || (history.migration_state == "preparation_absent" && proof["site_state"] != "a_exact")
    {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), LEAF)?;
    recovery_absent(control.as_raw_fd(), STOPPED_LEAF)?;
    recovery_absent(control.as_raw_fd(), RECOVERY_LEAF)?;
    let archived = history_dir(control.as_raw_fd(), true)?;
    let successor_bytes = if recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF).is_err() {
        read_sealed_leaf(control.as_raw_fd(), SUCCESSOR_LEAF)?
    } else {
        read_archived(
            archived.as_raw_fd(),
            "intent",
            &history.successor_intent_sha256,
        )?
    };
    if digest(&successor_bytes) != history.successor_intent_sha256 {
        return Err(refuse());
    }
    let sealed = successor_history_with_intent(Some((
        successor_bytes.clone(),
        serde_json::from_slice(&successor_bytes).map_err(|_| refuse())?,
    )))?;
    let pointer: serde_json::Value =
        serde_json::from_slice(&sealed.pointer_receipt_bytes).map_err(|_| refuse())?;
    let pointer_sha = cold_hex(&pointer["pointer_sha256"])?;
    let pointer_bytes = boot_pointer(control.as_raw_fd(), &sealed.active, Some(pointer_sha))?;
    archive_exact(
        archived.as_raw_fd(),
        "intent",
        &history.successor_intent_sha256,
        &successor_bytes,
    )?;
    archive_exact(
        archived.as_raw_fd(),
        "boot-pointer",
        pointer_sha,
        &pointer_bytes,
    )?;
    let proof_raw = serde_json::to_vec(proof).map_err(|_| refuse())?;
    if proof_raw.len() > 8192 {
        return Err(refuse());
    }
    let prebind = serde_json::json!({
        "schema": "aegis_auto_v2_cold_denied_prebind_v1",
        "boot_id": history.current_boot_id,
        "old_boot_id": history.old_boot_id,
        "intent_sha256": expected_intent_sha,
        "native_proof_sha256": digest(&proof_raw),
        "old_active_sha256": history.old_active_sha256,
        "old_stopped_sha256": history.old_stopped_sha256,
        "successor_intent_sha256": history.successor_intent_sha256,
        "old_pointer_sha256": pointer_sha,
        "new_candidate_sha256": history.new_candidate_sha256,
        "new_package_sha256": history.new_package_sha256,
        "retained_root": history.retained_root,
        "guard30_sha256": proof["guard30_sha256"],
        "manager31_sha256": proof["manager31_sha256"],
        "guardian31_sha256": proof["guardian31_sha256"],
        "site_state": proof["site_state"],
        "site_readback_sha256": proof["site_readback_sha256"],
        "old_context_sha256": proof["old_context_sha256"],
        "old_observer_archive_sha256": proof["old_observer_archive_sha256"],
        "deny_policy_sha256": proof["deny_policy_sha256"],
        "no_client_grant": true,
    });
    let mut prebind_raw = serde_json::to_vec(&prebind).map_err(|_| refuse())?;
    prebind_raw.push(b'\n');
    write_passive_atomic(
        cold.as_raw_fd(),
        "cold-denied-prebind.json",
        &prebind_raw,
        8192,
    )?;
    lock.revalidate().map_err(|_| refuse())?;
    if recovery_absent(control.as_raw_fd(), "current.json").is_err() {
        retire_exact(control.as_raw_fd(), "current.json", &pointer_bytes)?;
    }
    if recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF).is_err() {
        retire_exact(control.as_raw_fd(), SUCCESSOR_LEAF, &successor_bytes)?;
    }
    recovery_absent(control.as_raw_fd(), "current.json")?;
    recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF)?;
    if read_sealed_leaf_bounded(cold.as_raw_fd(), "cold-denied-prebind.json", 8192)? != prebind_raw
        || read_archived(
            archived.as_raw_fd(),
            "intent",
            &history.successor_intent_sha256,
        )? != successor_bytes
        || read_archived(archived.as_raw_fd(), "boot-pointer", pointer_sha)? != pointer_bytes
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_cold_retired_successor_retirement_v1",
        "boot_id": history.current_boot_id,
        "intent_sha256": expected_intent_sha,
        "deny_policy_sha256": proof["deny_policy_sha256"],
        "cold_prebind_sha256": digest(&prebind_raw),
        "no_client_grant": true,
    }))
    .map_err(|_| refuse())
}

fn retire_cold_rollover_successor(
    root: &Path,
    expected_intent_sha: &str,
    proof: &serde_json::Value,
    lock: &InstallLock,
) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    lock.revalidate().map_err(|_| refuse())?;
    let source = cold_stale_source(root)?;
    let (phase, intent_raw, rollover, head_sha) = cold_current_phase()?;
    let intent = cold_json(&intent_raw)?;
    let head_sha = head_sha.ok_or_else(refuse)?;
    if !rollover
        || !exact_hex(expected_intent_sha)
        || digest(&intent_raw) != expected_intent_sha
        || source.current_intent_sha256.as_deref() != Some(expected_intent_sha)
        || source.current_head_sha256.as_deref() != Some(head_sha.as_str())
        || proof["schema"] != "aegis_auto_v2_cold_retired_successor_v2"
        || proof["cold_intent_sha256"] != expected_intent_sha
        || proof["current_boot_id"] != current_boot_id()?
        || proof["package_state"] != "new_exact"
        || proof["quiesce_state"] != "post"
        || cold_hex(&proof["package_repair_receipt_sha256"]).is_err()
        || proof["infrastructure_quiescent"] != true
        || proof["observer_state"] != "absent"
        || proof["client_actors_absent"] != true
        || proof["jobs_absent"] != true
        || proof["cgroups_empty"] != true
        || proof["stop_intent_absent"] != true
        || proof["infrastructure_qualified"] != true
        || proof["retained_root"].as_str() != root.to_str()
        || intent["successor_intent_sha256"] != source.bootstrap.successor_intent_sha256
        || intent["new_candidate_sha256"] != source.bootstrap.candidate_sha256
        || intent["new_package_sha256"] != source.new_package_sha256
        || intent["deny_policy_sha256"] != proof["deny_policy_sha256"]
        || intent["guard30_sha256"] != proof["guard30_sha256"]
        || intent["selected_manager"] != proof["selected_manager"]
    {
        return Err(refuse());
    }
    let guardian = serde_json::json!({
        "policy_sha256":proof["deny_policy_sha256"],
        "guard30_sha256":proof["guard30_sha256"],
    });
    let retirement_sha = cold_prior_retirement_receipt(&source, &guardian)?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    for leaf in [
        "current.json",
        LEAF,
        RECOVERY_LEAF,
        SUCCESSOR_LEAF,
        BOOT_SUCCESSOR_LEAF,
    ] {
        recovery_absent(control.as_raw_fd(), leaf)?;
    }
    let proof_raw = serde_json::to_vec(proof).map_err(|_| refuse())?;
    if proof_raw.len() > 8192 {
        return Err(refuse());
    }
    let prebind = serde_json::json!({
        "schema":"aegis_auto_v2_cold_rollover_denied_prebind_v1",
        "boot_id":proof["current_boot_id"],
        "intent_sha256":expected_intent_sha,
        "attempt_head_sha256":head_sha,
        "original_intent_sha256":source.original_intent_sha256,
        "prior_intent_sha256":source.prior_intent_sha256,
        "prior_pointer_retirement_sha256":retirement_sha,
        "native_proof_sha256":digest(&proof_raw),
        "old_active_sha256":proof["old_active_sha256"],
        "old_stopped_sha256":proof["old_stopped_sha256"],
        "successor_intent_sha256":proof["successor_intent_sha256"],
        "new_candidate_sha256":proof["new_candidate_sha256"],
        "new_package_sha256":proof["new_package_sha256"],
        "retained_root":proof["retained_root"],
        "guard30_sha256":proof["guard30_sha256"],
        "manager31_sha256":proof["manager31_sha256"],
        "guardian31_sha256":proof["guardian31_sha256"],
        "site_state":proof["site_state"],
        "site_readback_sha256":proof["site_readback_sha256"],
        "old_context_sha256":proof["old_context_sha256"],
        "old_observer_archive_sha256":proof["old_observer_archive_sha256"],
        "deny_policy_sha256":proof["deny_policy_sha256"],
        "no_client_grant":true,
    });
    let mut raw = serde_json::to_vec(&prebind).map_err(|_| refuse())?;
    raw.push(b'\n');
    write_passive_atomic(phase.as_raw_fd(), "cold-denied-prebind.json", &raw, 8192)?;
    if read_sealed_leaf_bounded(phase.as_raw_fd(), "cold-denied-prebind.json", 8192)? != raw
        || cold_stale_source(root)?.current_head_sha256.as_deref() != Some(head_sha.as_str())
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema":"aegis_auto_v2_cold_retired_successor_retirement_v1",
        "boot_id":proof["current_boot_id"],
        "intent_sha256":expected_intent_sha,
        "deny_policy_sha256":proof["deny_policy_sha256"],
        "cold_prebind_sha256":digest(&raw),
        "no_client_grant":true,
    }))
    .map_err(|_| refuse())
}

/// Read-only S3 seal: a source-bound native retirement plus a fresh denied
/// current-boot proof. The B registrar calls this before publishing site bytes.
fn verify_cold_rollover_prebind(
    root: &Path,
    expected_intent_sha: &str,
    proof: &serde_json::Value,
) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let source = cold_stale_source(root)?;
    let (phase, intent_raw, rollover, head_sha) = cold_current_phase()?;
    let head_sha = head_sha.ok_or_else(refuse)?;
    let prebind_raw =
        read_sealed_leaf_bounded(phase.as_raw_fd(), "cold-denied-prebind.json", 8192)?;
    let prebind = cold_json(&prebind_raw)?;
    if !rollover
        || digest(&intent_raw) != expected_intent_sha
        || source.current_intent_sha256.as_deref() != Some(expected_intent_sha)
        || source.current_head_sha256.as_deref() != Some(head_sha.as_str())
        || proof["schema"] != "aegis_auto_v2_cold_retired_successor_v2"
        || proof["cold_intent_sha256"] != expected_intent_sha
        || proof["current_boot_id"] != current_boot_id()?
        || proof["package_state"] != "new_exact"
        || proof["quiesce_state"] != "post"
        || cold_hex(&proof["package_repair_receipt_sha256"]).is_err()
        || proof["client_actors_absent"] != true
        || proof["jobs_absent"] != true
        || proof["cgroups_empty"] != true
        || proof["stop_intent_absent"] != true
        || proof["infrastructure_qualified"] != true
        || !["absent", "b_ready"].contains(&proof["observer_state"].as_str().ok_or_else(refuse)?)
        || (proof["site_state"] != "b_complete" && proof["infrastructure_quiescent"] != true)
        || prebind["schema"] != "aegis_auto_v2_cold_rollover_denied_prebind_v1"
        || prebind["boot_id"] != proof["current_boot_id"]
        || prebind["intent_sha256"] != expected_intent_sha
        || prebind["attempt_head_sha256"] != head_sha
        || prebind["original_intent_sha256"] != source.original_intent_sha256
        || prebind["prior_intent_sha256"] != source.prior_intent_sha256
        || prebind["old_active_sha256"] != proof["old_active_sha256"]
        || prebind["old_stopped_sha256"] != proof["old_stopped_sha256"]
        || prebind["successor_intent_sha256"] != proof["successor_intent_sha256"]
        || prebind["new_candidate_sha256"] != proof["new_candidate_sha256"]
        || prebind["new_package_sha256"] != proof["new_package_sha256"]
        || prebind["guard30_sha256"] != proof["guard30_sha256"]
        || prebind["old_context_sha256"] != proof["old_context_sha256"]
        || prebind["old_observer_archive_sha256"] != proof["old_observer_archive_sha256"]
        || prebind["deny_policy_sha256"] != proof["deny_policy_sha256"]
        || prebind["no_client_grant"] != true
    {
        return Err(refuse());
    }
    let guardian = serde_json::json!({
        "policy_sha256":proof["deny_policy_sha256"],
        "guard30_sha256":proof["guard30_sha256"],
    });
    if prebind["prior_pointer_retirement_sha256"]
        != cold_prior_retirement_receipt(&source, &guardian)?
    {
        return Err(refuse());
    }
    let config_intent = if recovery_absent(phase.as_raw_fd(), "cold-config-intent.json").is_ok() {
        None
    } else {
        let raw = read_sealed_leaf_bounded(phase.as_raw_fd(), "cold-config-intent.json", 8192)?;
        let value = cold_json(&raw)?;
        cold_exact_keys(
            &value,
            &[
                "schema",
                "current_boot_id",
                "intent_sha256",
                "cold_prebind_sha256",
                "old_context_sha256",
                "new_install_sha256",
                "source_config_sha256",
                "store_config_sha256",
                "active_hook_sha256",
                "manager31_sha256",
                "guardian31_sha256",
                "selected_manager",
            ],
        )?;
        if value["schema"] != "aegis_auto_terminal_cold_config_intent_v1"
            || value["current_boot_id"] != proof["current_boot_id"]
            || value["intent_sha256"] != expected_intent_sha
            || value["cold_prebind_sha256"] != digest(&prebind_raw)
            || value["new_install_sha256"] != proof["installed_source_sha256"]
            || value["selected_manager"] != proof["selected_manager"]
            || value["old_context_sha256"] != proof["old_context_sha256"]
                && value["old_context_sha256"] != proof["cold_old_context_sha256"]
        {
            return Err(refuse());
        }
        Some(value)
    };
    if config_intent.is_none() {
        let proof_raw = serde_json::to_vec(proof).map_err(|_| refuse())?;
        if prebind["native_proof_sha256"] != digest(&proof_raw)
            || prebind["site_state"] != proof["site_state"]
            || prebind["site_readback_sha256"] != proof["site_readback_sha256"]
            || prebind["manager31_sha256"] != proof["manager31_sha256"]
            || prebind["guardian31_sha256"] != proof["guardian31_sha256"]
            || proof["observer_state"] != "absent"
        {
            return Err(refuse());
        }
    } else if let Some(value) = &config_intent {
        for key in ["manager31_sha256", "guardian31_sha256"] {
            if !proof[key].is_null() && proof[key] != value[key] {
                return Err(refuse());
            }
        }
        if proof["site_state"] == "b_complete"
            && (proof["source_config_sha256"] != value["source_config_sha256"]
                || proof["observer_state"] != "b_ready")
        {
            return Err(refuse());
        }
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    for leaf in [
        "current.json",
        LEAF,
        RECOVERY_LEAF,
        SUCCESSOR_LEAF,
        BOOT_SUCCESSOR_LEAF,
    ] {
        recovery_absent(control.as_raw_fd(), leaf)?;
    }
    let mut result = serde_json::to_vec(&serde_json::json!({
        "schema":"aegis_auto_v2_cold_prebind_verification_v1",
        "boot_id":proof["current_boot_id"],
        "intent_sha256":expected_intent_sha,
        "cold_prebind_sha256":digest(&prebind_raw),
        "deny_policy_sha256":proof["deny_policy_sha256"],
        "site_state":proof["site_state"],
        "site_readback_sha256":proof["site_readback_sha256"],
        "observer_state":proof["observer_state"],
        "observer_ready_sha256":proof["observer_ready_sha256"],
        "source_config_sha256":proof["source_config_sha256"],
        "package_repair_receipt_sha256":proof["package_repair_receipt_sha256"],
        "no_client_grant":true,
    }))
    .map_err(|_| refuse())?;
    result.push(b'\n');
    Ok(result)
}

/// Before the transition unit can publish its current-boot ready receipt,
/// independently bind the complete B site phase and the active sticky
/// rollover barrier under the caller's inherited Install→Guard OFDs.
pub(super) fn verify_cold_rollover_transition_phase(
    root: &Path,
    expected_intent_sha: &str,
    proof: &serde_json::Value,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    let source = cold_stale_source(root)?;
    let (phase, intent_raw, rollover, head_sha) = cold_current_phase()?;
    if !rollover
        || digest(&intent_raw) != expected_intent_sha
        || source.current_intent_sha256.as_deref() != Some(expected_intent_sha)
        || head_sha != source.current_head_sha256
        || source.barrier_sha256.is_none()
        || proof["site_state"] != "b_complete"
        || proof["observer_state"] != "b_ready"
        || proof["package_state"] != "new_exact"
    {
        return Err(refuse());
    }
    let cold = cold_recovery_dir()?;
    let barrier = read_sealed_leaf_bounded(cold.as_raw_fd(), "rollover-barrier.json", 4096)?;
    if Some(digest(&barrier)) != source.barrier_sha256 {
        return Err(refuse());
    }
    let phase02 = read_sealed_leaf_bounded(phase.as_raw_fd(), "phase-02.json", 4096)?;
    let phase03 = read_sealed_leaf_bounded(phase.as_raw_fd(), "phase-03.json", 8192)?;
    let phase04 = read_sealed_leaf_bounded(phase.as_raw_fd(), "phase-04.json", 8192)?;
    let p3 = cold_json(&phase03)?;
    let p4 = cold_json(&phase04)?;
    cold_exact_keys(
        &p4,
        &[
            "schema",
            "intent_sha256",
            "cold_prebind_sha256",
            "source_config_sha256",
            "observer_ready_sha256",
        ],
    )?;
    let prebind = read_sealed_leaf_bounded(phase.as_raw_fd(), "cold-denied-prebind.json", 8192)?;
    let etc = recovery_chain(&["etc"], None)?;
    let source_raw =
        read_sealed_leaf_bounded(etc.as_raw_fd(), "aegis-auto-terminal-source.json", 4096)?;
    if p3["schema"] != "aegis_auto_terminal_cold_denied_prebind_v2"
        || p3["intent_sha256"] != expected_intent_sha
        || p3["package_repaired_sha256"] != digest(&phase02)
        || p3["cold_prebind_sha256"] != digest(&prebind)
        || p4["schema"] != "aegis_auto_terminal_cold_site_ready_v1"
        || p4["intent_sha256"] != expected_intent_sha
        || p4["cold_prebind_sha256"] != digest(&prebind)
        || p4["source_config_sha256"] != digest(&source_raw)
        || p4["source_config_sha256"] != proof["source_config_sha256"]
        || p4["observer_ready_sha256"] != proof["observer_ready_sha256"]
        || proof["package_repair_receipt_sha256"] != digest(&phase02)
    {
        return Err(refuse());
    }
    Ok(())
}

pub(super) fn verify_cold_prebind(
    root: &Path,
    expected_intent_sha: &str,
    proof: &serde_json::Value,
) -> Result<Vec<u8>> {
    if cold_stale_source(root).is_ok() {
        return verify_cold_rollover_prebind(root, expected_intent_sha, proof);
    }
    if !exact_hex(expected_intent_sha)
        || proof["schema"] != "aegis_auto_v2_cold_retired_successor_v2"
        || proof["retained_root"].as_str() != root.to_str()
        || proof["current_boot_id"] != current_boot_id()?
        || proof["cold_intent_sha256"] != expected_intent_sha
        || proof["package_state"] != "new_exact"
        || proof["quiesce_state"] != "post"
        || cold_hex(&proof["package_repair_receipt_sha256"]).is_err()
        || proof["client_actors_absent"] != true
        || proof["jobs_absent"] != true
        || proof["cgroups_empty"] != true
        || proof["stop_intent_absent"] != true
        || proof["infrastructure_qualified"] != true
        || !["absent", "b_ready"].contains(&proof["observer_state"].as_str().ok_or_else(refuse)?)
        || (proof["site_state"] != "b_complete" && proof["infrastructure_quiescent"] != true)
    {
        return Err(refuse());
    }
    let history = cold_retired_history(root)?;
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let migration = recovery_directory(guardian.as_raw_fd(), "terminal-migrations", Some(0o700))?;
    let cold = recovery_directory(migration.as_raw_fd(), "cold-recovery", Some(0o700))?;
    let intent_raw = read_sealed_leaf_bounded(cold.as_raw_fd(), "intent.json", 4096)?;
    let prebind_raw = read_sealed_leaf_bounded(cold.as_raw_fd(), "cold-denied-prebind.json", 8192)?;
    let prebind = cold_json(&prebind_raw)?;
    let proof_raw = serde_json::to_vec(proof).map_err(|_| refuse())?;
    if history.old_context_sha256.is_some() == history.cold_old_context_sha256.is_some() {
        return Err(refuse());
    }
    let config_intent = if recovery_absent(cold.as_raw_fd(), "cold-config-intent.json").is_ok() {
        None
    } else {
        let raw = read_sealed_leaf_bounded(cold.as_raw_fd(), "cold-config-intent.json", 8192)?;
        let value = cold_json(&raw)?;
        let object = value.as_object().ok_or_else(refuse)?;
        let keys = [
            "schema",
            "current_boot_id",
            "intent_sha256",
            "cold_prebind_sha256",
            "old_context_sha256",
            "new_install_sha256",
            "source_config_sha256",
            "store_config_sha256",
            "active_hook_sha256",
            "manager31_sha256",
            "guardian31_sha256",
            "selected_manager",
        ];
        if object.len() != keys.len()
            || keys.iter().any(|key| !object.contains_key(*key))
            || value["schema"] != "aegis_auto_terminal_cold_config_intent_v1"
            || value["current_boot_id"] != history.current_boot_id
            || value["intent_sha256"] != expected_intent_sha
            || value["cold_prebind_sha256"] != digest(&prebind_raw)
            || value["old_context_sha256"].as_str()
                != history
                    .old_context_sha256
                    .as_deref()
                    .or(history.cold_old_context_sha256.as_deref())
            || value["new_install_sha256"] != proof["installed_source_sha256"]
            || value["selected_manager"] != proof["selected_manager"]
            || [
                "source_config_sha256",
                "store_config_sha256",
                "active_hook_sha256",
                "manager31_sha256",
                "guardian31_sha256",
            ]
            .iter()
            .any(|key| cold_hex(&value[*key]).is_err())
        {
            return Err(refuse());
        }
        Some(value)
    };
    if config_intent.is_none()
        && (proof["observer_state"] != "absent"
            || (history.migration_state == "preparation_absent"
                && proof["site_state"] != "a_exact"))
    {
        return Err(refuse());
    }
    if proof["observer_state"] == "b_ready" && proof["site_state"] != "b_complete" {
        return Err(refuse());
    }
    if digest(&intent_raw) != expected_intent_sha
        || prebind["schema"] != "aegis_auto_v2_cold_denied_prebind_v1"
        || prebind["boot_id"] != history.current_boot_id
        || prebind["intent_sha256"] != expected_intent_sha
        || prebind["old_active_sha256"] != history.old_active_sha256
        || prebind["old_stopped_sha256"] != history.old_stopped_sha256
        || prebind["successor_intent_sha256"] != history.successor_intent_sha256
        || prebind["new_candidate_sha256"] != history.new_candidate_sha256
        || prebind["new_package_sha256"] != history.new_package_sha256
        || prebind["guard30_sha256"] != proof["guard30_sha256"]
        || prebind["old_context_sha256"] != proof["old_context_sha256"]
        || prebind["old_observer_archive_sha256"] != proof["old_observer_archive_sha256"]
        || prebind["deny_policy_sha256"] != proof["deny_policy_sha256"]
        || prebind["no_client_grant"] != true
    {
        return Err(refuse());
    }
    if config_intent.is_none()
        && (prebind["native_proof_sha256"] != digest(&proof_raw)
            || prebind["manager31_sha256"] != proof["manager31_sha256"]
            || prebind["guardian31_sha256"] != proof["guardian31_sha256"]
            || prebind["site_state"] != proof["site_state"]
            || prebind["site_readback_sha256"] != proof["site_readback_sha256"])
    {
        return Err(refuse());
    }
    if let Some(value) = &config_intent {
        for key in ["manager31_sha256", "guardian31_sha256"] {
            if !proof[key].is_null() && proof[key] != value[key] {
                return Err(refuse());
            }
        }
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), "current.json")?;
    recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF)?;
    let archived = history_dir(control.as_raw_fd(), false)?;
    let pointer_sha = cold_hex(&prebind["old_pointer_sha256"])?;
    let pointer = read_archived(archived.as_raw_fd(), "boot-pointer", pointer_sha)?;
    let successor = read_archived(
        archived.as_raw_fd(),
        "intent",
        &history.successor_intent_sha256,
    )?;
    if digest(&pointer) != pointer_sha || digest(&successor) != history.successor_intent_sha256 {
        return Err(refuse());
    }
    let mut result = serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_cold_prebind_verification_v1",
        "boot_id": history.current_boot_id,
        "intent_sha256": expected_intent_sha,
        "cold_prebind_sha256": digest(&prebind_raw),
        "deny_policy_sha256": proof["deny_policy_sha256"],
        "site_state": proof["site_state"],
        "site_readback_sha256": proof["site_readback_sha256"],
        "observer_state": proof["observer_state"],
        "observer_ready_sha256": proof["observer_ready_sha256"],
        "source_config_sha256": proof["source_config_sha256"],
        "package_repair_receipt_sha256": proof["package_repair_receipt_sha256"],
        "no_client_grant": true,
    }))
    .map_err(|_| refuse())?;
    result.push(b'\n');
    Ok(result)
}

fn cold_first_arm_intent(control: i32) -> Result<(Vec<u8>, ColdFirstArmIntent)> {
    let bytes = read_sealed_leaf(control, COLD_FIRST_ARM_LEAF)?;
    let intent: ColdFirstArmIntent = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    if intent.schema != "aegis_auto_v2_cold_first_arm_intent_v1"
        || ![
            &intent.old_active_sha256,
            &intent.old_stopped_sha256,
            &intent.successor_intent_sha256,
            &intent.cold_prebind_sha256,
            &intent.transition_ready_sha256,
            &intent.candidate_sha256,
            &intent.installer_sha256,
        ]
        .iter()
        .all(|v| exact_hex(v))
        || intent.current_boot_id != current_boot_id()?
        || intent.old_boot_id == intent.current_boot_id
        || serde_json::to_vec(&intent).map_err(|_| refuse())? != bytes
    {
        return Err(refuse());
    }
    Ok((bytes, intent))
}

pub(super) fn begin_cold_first_arm(
    root: &Path,
    proof: &serde_json::Value,
    lock: &InstallLock,
) -> Result<Vec<u8>> {
    if cold_stale_source(root).is_ok() {
        return begin_cold_rollover_first_arm(root, proof, lock);
    }
    lock.revalidate().map_err(|_| refuse())?;
    let history = cold_retired_history(root)?;
    if proof["schema"] != "aegis_auto_v2_cold_retired_successor_v2"
        || proof["current_boot_id"] != history.current_boot_id
        || proof["package_state"] != "new_exact"
        || proof["quiesce_state"] != "post"
        || cold_hex(&proof["package_repair_receipt_sha256"]).is_err()
        || proof["successor_intent_sha256"] != history.successor_intent_sha256
        || proof["new_candidate_sha256"] != history.new_candidate_sha256
        || proof["new_package_sha256"] != history.new_package_sha256
        || proof["client_actors_absent"] != true
        || proof["jobs_absent"] != true
        || proof["cgroups_empty"] != true
        || proof["site_state"] != "b_complete"
        || proof["observer_state"] != "b_ready"
        || proof["infrastructure_qualified"] != true
    {
        return Err(refuse());
    }
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let migration = recovery_directory(guardian.as_raw_fd(), "terminal-migrations", Some(0o700))?;
    let cold = recovery_directory(migration.as_raw_fd(), "cold-recovery", Some(0o700))?;
    recovery_absent(cold.as_raw_fd(), "intent.json")?;
    let intent_raw = cold_resolve_intent(cold.as_raw_fd())?.ok_or_else(refuse)?;
    let prebind_raw = read_sealed_leaf_bounded(cold.as_raw_fd(), "cold-denied-prebind.json", 8192)?;
    let prebind = cold_json(&prebind_raw)?;
    let ready_raw = read_sealed_leaf_bounded(cold.as_raw_fd(), "transition-ready.json", 4096)?;
    let ready = cold_json(&ready_raw)?;
    if ready["consumed_pending_leaf"].is_null() {
        recovery_absent(migration.as_raw_fd(), "pending.json")?;
    } else {
        recovery_absent(migration.as_raw_fd(), "pending.json")?;
        let pending = cold_current_pending(migration.as_raw_fd())?.ok_or_else(refuse)?;
        let expected = ready["consumed_pending_leaf"].as_str().ok_or_else(refuse)?;
        if expected != format!("pending-consumed-{}.json", digest(&pending)) {
            return Err(refuse());
        }
    }
    let phase = read_sealed_leaf_bounded(cold.as_raw_fd(), "phase-03.json", 4096)?;
    let phase_value = cold_json(&phase)?;
    let phase_object = phase_value.as_object().ok_or_else(refuse)?;
    let phase02 = read_sealed_leaf_bounded(cold.as_raw_fd(), "phase-02.json", 4096)?;
    if prebind["schema"] != "aegis_auto_v2_cold_denied_prebind_v1"
        || prebind["boot_id"] != history.current_boot_id
        || prebind["intent_sha256"] != digest(&intent_raw)
        || prebind["successor_intent_sha256"] != history.successor_intent_sha256
        || prebind["new_candidate_sha256"] != history.new_candidate_sha256
        || prebind["new_package_sha256"] != history.new_package_sha256
        || prebind["deny_policy_sha256"] != proof["deny_policy_sha256"]
        || prebind["guard30_sha256"] != proof["guard30_sha256"]
        || ready["schema"] != "aegis_auto_terminal_cold_transition_ready_v1"
        || ready["current_boot_id"] != history.current_boot_id
        || ready["intent_sha256"] != digest(&intent_raw)
        || ready["cold_prebind_sha256"] != digest(&prebind_raw)
        || ready["observer_ready_sha256"] != proof["observer_ready_sha256"]
        || ready["site_readback_sha256"] != proof["site_readback_sha256"]
        || ready["deny_policy_sha256"] != proof["deny_policy_sha256"]
        || phase_object.len() != 4
        || [
            "schema",
            "intent_sha256",
            "package_repaired_sha256",
            "cold_prebind_sha256",
        ]
        .iter()
        .any(|key| !phase_object.contains_key(*key))
        || phase_value["schema"] != "aegis_auto_terminal_cold_denied_prebind_v2"
        || phase_value["intent_sha256"] != digest(&intent_raw)
        || phase_value["package_repaired_sha256"] != digest(&phase02)
        || proof["package_repair_receipt_sha256"] != digest(&phase02)
        || phase_value["cold_prebind_sha256"] != digest(&prebind_raw)
    {
        return Err(refuse());
    }
    let etc = recovery_chain(&["etc"], None)?;
    let source_raw =
        read_sealed_leaf_bounded(etc.as_raw_fd(), "aegis-auto-terminal-source.json", 4096)?;
    if ready["source_config_sha256"] != digest(&source_raw) {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    for leaf in [
        LEAF,
        STOPPED_LEAF,
        RECOVERY_LEAF,
        SUCCESSOR_LEAF,
        BOOT_SUCCESSOR_LEAF,
        "current.json",
        "generation-pointer-stopped.json",
    ] {
        recovery_absent(control.as_raw_fd(), leaf)?;
    }
    let (_, installer_sha) = verified_retained_source(root, &root.join("bin/aegis-client"))?;
    if installer_sha != digest(include_bytes!("../../../install.sh")) {
        return Err(refuse());
    }
    let intent = ColdFirstArmIntent {
        schema: "aegis_auto_v2_cold_first_arm_intent_v1".into(),
        old_active_sha256: history.old_active_sha256,
        old_stopped_sha256: history.old_stopped_sha256,
        successor_intent_sha256: history.successor_intent_sha256,
        cold_prebind_sha256: digest(&prebind_raw),
        transition_ready_sha256: digest(&ready_raw),
        old_boot_id: history.old_boot_id,
        current_boot_id: history.current_boot_id,
        public_payload_root: history.retained_root,
        candidate_binary: root
            .join("bin/aegis-client")
            .to_str()
            .ok_or_else(refuse)?
            .into(),
        candidate_sha256: history.new_candidate_sha256,
        installer_sha256: installer_sha,
    };
    let bytes = serde_json::to_vec(&intent).map_err(|_| refuse())?;
    write_passive_atomic(control.as_raw_fd(), COLD_FIRST_ARM_LEAF, &bytes, MAX_SEAL)?;
    let (again, parsed) = cold_first_arm_intent(control.as_raw_fd())?;
    if again != bytes || parsed.cold_prebind_sha256 != digest(&prebind_raw) {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_cold_first_arm_verification_v1",
        "old_boot_id": intent.old_boot_id,
        "new_boot_id": intent.current_boot_id,
        "current_boot_id": intent.current_boot_id,
        "public_payload_root": intent.public_payload_root,
        "candidate_binary": intent.candidate_binary,
        "candidate_sha256": intent.candidate_sha256,
        "installer_sha256": intent.installer_sha256,
        "cold_prebind_sha256": intent.cold_prebind_sha256,
    }))
    .map_err(|_| refuse())
}

fn begin_cold_rollover_first_arm(
    root: &Path,
    proof: &serde_json::Value,
    lock: &InstallLock,
) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    lock.revalidate().map_err(|_| refuse())?;
    let source = cold_stale_source(root)?;
    let (phase, intent_raw, rollover, head_sha) = cold_current_phase()?;
    if !rollover
        || head_sha.as_deref() != source.current_head_sha256.as_deref()
        || Some(digest(&intent_raw)) != source.current_intent_sha256
        || proof["schema"] != "aegis_auto_v2_cold_retired_successor_v2"
        || proof["current_boot_id"] != current_boot_id()?
        || proof["package_state"] != "new_exact"
        || proof["quiesce_state"] != "post"
        || cold_hex(&proof["package_repair_receipt_sha256"]).is_err()
        || proof["site_state"] != "b_complete"
        || proof["observer_state"] != "b_ready"
        || proof["infrastructure_qualified"] != true
        || proof["client_actors_absent"] != true
        || proof["jobs_absent"] != true
        || proof["cgroups_empty"] != true
    {
        return Err(refuse());
    }
    recovery_absent(phase.as_raw_fd(), "intent.json")?;
    let prebind_raw =
        read_sealed_leaf_bounded(phase.as_raw_fd(), "cold-denied-prebind.json", 8192)?;
    let prebind = cold_json(&prebind_raw)?;
    let ready_raw = read_sealed_leaf_bounded(phase.as_raw_fd(), "transition-ready.json", 4096)?;
    let ready = cold_json(&ready_raw)?;
    let phase02 = read_sealed_leaf_bounded(phase.as_raw_fd(), "phase-02.json", 4096)?;
    let phase03 = read_sealed_leaf_bounded(phase.as_raw_fd(), "phase-03.json", 8192)?;
    let phase03_value = cold_json(&phase03)?;
    if prebind["schema"] != "aegis_auto_v2_cold_rollover_denied_prebind_v1"
        || prebind["intent_sha256"] != digest(&intent_raw)
        || prebind["attempt_head_sha256"] != head_sha.as_deref().ok_or_else(refuse)?
        || prebind["prior_intent_sha256"] != source.prior_intent_sha256
        || prebind["original_intent_sha256"] != source.original_intent_sha256
        || prebind["successor_intent_sha256"] != source.bootstrap.successor_intent_sha256
        || prebind["new_candidate_sha256"] != source.bootstrap.candidate_sha256
        || prebind["new_package_sha256"] != source.new_package_sha256
        || prebind["deny_policy_sha256"] != proof["deny_policy_sha256"]
        || prebind["guard30_sha256"] != proof["guard30_sha256"]
        || ready["schema"] != "aegis_auto_terminal_cold_rollover_transition_ready_v1"
        || ready["current_boot_id"] != proof["current_boot_id"]
        || ready["attempt_intent_sha256"] != digest(&intent_raw)
        || ready["attempt_head_sha256"] != head_sha.as_deref().ok_or_else(refuse)?
        || ready["cold_prebind_sha256"] != digest(&prebind_raw)
        || ready["observer_ready_sha256"] != proof["observer_ready_sha256"]
        || ready["site_readback_sha256"] != proof["site_readback_sha256"]
        || ready["deny_policy_sha256"] != proof["deny_policy_sha256"]
        || ready["phase02_sha256"] != digest(&phase02)
        || ready["phase03_sha256"] != digest(&phase03)
        || phase03_value["schema"] != "aegis_auto_terminal_cold_denied_prebind_v2"
        || phase03_value["cold_prebind_sha256"] != digest(&prebind_raw)
        || phase03_value["package_repaired_sha256"] != digest(&phase02)
        || proof["package_repair_receipt_sha256"] != digest(&phase02)
    {
        return Err(refuse());
    }
    let etc = recovery_chain(&["etc"], None)?;
    let source_raw =
        read_sealed_leaf_bounded(etc.as_raw_fd(), "aegis-auto-terminal-source.json", 4096)?;
    if ready["source_config_sha256"] != digest(&source_raw) {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    for leaf in [
        LEAF,
        STOPPED_LEAF,
        RECOVERY_LEAF,
        SUCCESSOR_LEAF,
        BOOT_SUCCESSOR_LEAF,
        "current.json",
        "generation-pointer-stopped.json",
    ] {
        recovery_absent(control.as_raw_fd(), leaf)?;
    }
    let (_, installer_sha) = verified_retained_source(root, &root.join("bin/aegis-client"))?;
    if installer_sha != digest(include_bytes!("../../../install.sh")) {
        return Err(refuse());
    }
    let original = cold_original_intent(&source)?;
    let intent = ColdFirstArmIntent {
        schema: "aegis_auto_v2_cold_first_arm_intent_v1".into(),
        old_active_sha256: cold_hex(&original["old_active_sha256"])?.to_owned(),
        old_stopped_sha256: cold_hex(&original["old_stopped_sha256"])?.to_owned(),
        successor_intent_sha256: source.bootstrap.successor_intent_sha256,
        cold_prebind_sha256: digest(&prebind_raw),
        transition_ready_sha256: digest(&ready_raw),
        old_boot_id: original["old_boot_id"]
            .as_str()
            .ok_or_else(refuse)?
            .to_owned(),
        current_boot_id: current_boot_id()?,
        public_payload_root: source.retained_root,
        candidate_binary: root
            .join("bin/aegis-client")
            .to_str()
            .ok_or_else(refuse)?
            .into(),
        candidate_sha256: source.bootstrap.candidate_sha256,
        installer_sha256: installer_sha,
    };
    let bytes = serde_json::to_vec(&intent).map_err(|_| refuse())?;
    write_passive_atomic(control.as_raw_fd(), COLD_FIRST_ARM_LEAF, &bytes, MAX_SEAL)?;
    let (again, parsed) = cold_first_arm_intent(control.as_raw_fd())?;
    if again != bytes || parsed.cold_prebind_sha256 != digest(&prebind_raw) {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema":"aegis_auto_v2_cold_first_arm_verification_v1",
        "old_boot_id":intent.old_boot_id,
        "new_boot_id":intent.current_boot_id,
        "current_boot_id":intent.current_boot_id,
        "public_payload_root":intent.public_payload_root,
        "candidate_binary":intent.candidate_binary,
        "candidate_sha256":intent.candidate_sha256,
        "installer_sha256":intent.installer_sha256,
        "cold_prebind_sha256":intent.cold_prebind_sha256,
    }))
    .map_err(|_| refuse())
}

pub(super) fn cold_active_lineage(
    root: &Path,
    expected_intent_sha: &str,
) -> Result<(serde_json::Value, String, String, String)> {
    if !exact_hex(expected_intent_sha) {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let active_raw = read_sealed_leaf(control.as_raw_fd(), LEAF)?;
    let active = parse_active(&active_raw)?;
    let cold_sha = active
        .predecessor_cold_intent_sha256
        .as_deref()
        .ok_or_else(refuse)?;
    let history = history_dir(control.as_raw_fd(), false)?;
    let cold_raw = read_archived(history.as_raw_fd(), "cold-intent", cold_sha)?;
    let cold: ColdFirstArmIntent = serde_json::from_slice(&cold_raw).map_err(|_| refuse())?;
    if cold.schema != "aegis_auto_v2_cold_first_arm_intent_v1"
        || cold.current_boot_id != current_boot_id()?
        || cold.public_payload_root != root.to_str().ok_or_else(refuse)?
        || active.report["terminal"]["boot_id"] != cold.current_boot_id
        || active.report["input"]["public_payload_root"] != cold.public_payload_root
        || active.report["input"]["candidate_binary"] != cold.candidate_binary
        || active.report["input"]["candidate_sha256"] != cold.candidate_sha256
    {
        return Err(refuse());
    }
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let (dir, intent_raw, rollover, _) = cold_current_phase()?;
    recovery_absent(dir.as_raw_fd(), "intent.json")?;
    let prebind_raw = read_sealed_leaf_bounded(dir.as_raw_fd(), "cold-denied-prebind.json", 8192)?;
    let ready_raw = read_sealed_leaf_bounded(dir.as_raw_fd(), "transition-ready.json", 4096)?;
    let ready = cold_json(&ready_raw)?;
    if rollover {
        if ready["schema"] != "aegis_auto_terminal_cold_rollover_transition_ready_v1"
            || ready["attempt_intent_sha256"] != digest(&intent_raw)
            || ready["cold_prebind_sha256"] != digest(&prebind_raw)
            || ready["current_boot_id"] != cold.current_boot_id
        {
            return Err(refuse());
        }
    } else if ready["schema"] != "aegis_auto_terminal_cold_transition_ready_v1" {
        return Err(refuse());
    }
    if digest(&intent_raw) != expected_intent_sha
        || digest(&prebind_raw) != cold.cold_prebind_sha256
        || digest(&ready_raw) != cold.transition_ready_sha256
    {
        return Err(refuse());
    }
    let (candidate, installer) = verified_retained_source(root, &root.join("bin/aegis-client"))?;
    if candidate != cold.candidate_sha256
        || installer != cold.installer_sha256
        || installer != digest(include_bytes!("../../../install.sh"))
    {
        return Err(refuse());
    }
    let installed = recovery_chain(&["usr", "local", "bin"], None)?;
    let binary = recovery_open_at(installed.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    if recovery_file_hash(binary.as_raw_fd(), 256 << 20)?.1 != candidate {
        return Err(refuse());
    }
    let unit = active.report["terminal"]["private_unit"]
        .as_str()
        .ok_or_else(refuse)?;
    let token = unit
        .strip_prefix("aegis-auto@")
        .and_then(|v| v.strip_suffix(".service"))
        .filter(|v| exact_hex(v))
        .ok_or_else(refuse)?;
    let pending_raw = read_sealed_leaf_bounded(
        guardian.as_raw_fd(),
        &format!("auto-terminal-registration-pending-{token}.json"),
        4096,
    )?;
    let complete_raw = read_sealed_leaf_bounded(
        guardian.as_raw_fd(),
        &format!("auto-terminal-registration-complete-{token}.json"),
        4096,
    )?;
    let pending = cold_json(&pending_raw)?;
    let complete = cold_json(&complete_raw)?;
    let etc = recovery_chain(&["etc"], None)?;
    let source_raw =
        read_sealed_leaf_bounded(etc.as_raw_fd(), "aegis-auto-terminal-source.json", 4096)?;
    let runtime = recovery_chain(&["run", "aegis-auto-terminal"], Some(0o700))?;
    let activation_raw = read_sealed_leaf_bounded(
        runtime.as_raw_fd(),
        &format!("activation-{token}.json"),
        4096,
    )?;
    let activation = cold_json(&activation_raw)?;
    if pending["schema"] != "aegis_auto_terminal_registration_pending_v1"
        || pending["boot_id"] != cold.current_boot_id
        || pending["unit"] != unit
        || pending["source_sha256"] != digest(&source_raw)
        || complete["schema"] != "aegis_auto_terminal_registration_complete_v1"
        || complete["pending_sha256"] != digest(&pending_raw)
        || complete["activation_sha256"] != digest(&activation_raw)
        || complete["active_generation_sha256"] != digest(&active_raw)
        || activation["unit"] != unit
        || activation["boot_id"] != cold.current_boot_id
        || activation["active_generation_sha256"] != digest(&active_raw)
        || activation["terminal_sha256"] != active.report["terminal"]["start_terminal_sha256"]
    {
        return Err(refuse());
    }
    Ok((
        active.report,
        digest(&active_raw),
        cold.cold_prebind_sha256,
        digest(&complete_raw),
    ))
}

fn retained_bundle_anchor(
    root: &Path,
    candidate_sha: &str,
    installer_sha: &str,
) -> Result<(String, String)> {
    let name = root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    if root.parent() != Some(Path::new("/var/lib/aegis-auto/releases"))
        || name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(refuse());
    }
    let release = recovery_chain(&["var", "lib", "aegis-auto", "releases", name], Some(0o700))?;
    let read = |leaf: &str| -> Result<Vec<u8>> {
        let file = recovery_open_at(release.as_raw_fd(), leaf, libc::O_RDONLY, 0)?;
        let before = recovery_stat(file.as_raw_fd())?;
        if before.st_mode != libc::S_IFREG | 0o444
            || before.st_uid != 0
            || before.st_gid != 0
            || before.st_nlink != 1
            || before.st_size <= 0
            || before.st_size > 4 << 20
        {
            return Err(refuse());
        }
        let mut raw = Vec::new();
        std::fs::File::from(file)
            .take((4 << 20) + 1)
            .read_to_end(&mut raw)
            .map_err(|_| refuse())?;
        let named = recovery_open_at(release.as_raw_fd(), leaf, libc::O_RDONLY, 0)?;
        let after = recovery_stat(named.as_raw_fd())?;
        if raw.len() as i64 != before.st_size
            || (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_gid,
                before.st_nlink,
                before.st_size,
                before.st_mtime,
                before.st_ctime,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_gid,
                after.st_nlink,
                after.st_size,
                after.st_mtime,
                after.st_ctime,
            )
        {
            return Err(refuse());
        }
        Ok(raw)
    };
    let manifest_raw = read("bundle.manifest.json")?;
    let sums_raw = read("SHA256SUMS")?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_raw).map_err(|_| refuse())?;
    if manifest["schema"] != "aegis_release_bundle_manifest_v2"
        || manifest["binaries"]["aegis-client"]["path"] != "bin/aegis-client"
        || manifest["binaries"]["aegis-client"]["sha256"] != candidate_sha
    {
        return Err(refuse());
    }
    let files = manifest["files"].as_array().ok_or_else(refuse)?;
    if files.is_empty() || files.len() > 4096 {
        return Err(refuse());
    }
    let mut listed = std::collections::BTreeSet::new();
    for value in files {
        let name = value.as_str().ok_or_else(refuse)?;
        if name.is_empty() || name.starts_with('/') || name.contains("..") || !listed.insert(name) {
            return Err(refuse());
        }
    }
    let sums = std::str::from_utf8(&sums_raw).map_err(|_| refuse())?;
    let mut rows = std::collections::BTreeMap::new();
    for line in sums.lines() {
        let (hash, path) = line.split_once("  ").ok_or_else(refuse)?;
        if !exact_hex(hash)
            || path.is_empty()
            || path.starts_with('/')
            || path.contains("..")
            || rows.insert(path, hash).is_some()
        {
            return Err(refuse());
        }
    }
    listed.remove("SHA256SUMS");
    if rows
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        != listed
        || rows.get("bin/aegis-client").copied() != Some(candidate_sha)
        || rows.get("install.sh").copied() != Some(installer_sha)
    {
        return Err(refuse());
    }
    Ok((digest(&manifest_raw), digest(&sums_raw)))
}

fn successor_intent(
    history: &SuccessorHistory,
    root: &Path,
    candidate: &Path,
) -> Result<SuccessorIntent> {
    let kind = if history.stopped["input"]["public_payload_root"].as_str() == root.to_str() {
        "restart"
    } else {
        "upgrade"
    };
    let (candidate_sha, installer_sha) = verified_retained_source(root, candidate)?;
    let (bundle_sha, sums_sha) = retained_bundle_anchor(root, &candidate_sha, &installer_sha)?;
    let intent = SuccessorIntent {
        schema: "aegis_auto_v2_stopped_successor_v1".into(),
        kind: kind.into(),
        old_active_sha256: digest(&history.active_bytes),
        old_stopped_sha256: digest(&history.stopped_bytes),
        old_pointer_receipt_sha256: history.pointer_receipt_sha256.clone(),
        old_stage_path: history.stage_path.clone(),
        old_boot_id: history.stopped["terminal"]["boot_id"]
            .as_str()
            .ok_or_else(refuse)?
            .to_owned(),
        next_public_payload_root: root.to_str().ok_or_else(refuse)?.to_owned(),
        next_candidate_binary: candidate.to_str().ok_or_else(refuse)?.to_owned(),
        next_candidate_sha256: candidate_sha,
        next_installer_sha256: installer_sha,
        next_bundle_manifest_sha256: Some(bundle_sha),
        next_sums_sha256: Some(sums_sha),
    };
    successor_shape(&intent)?;
    Ok(intent)
}

fn successor_output(
    stopped: &serde_json::Value,
    intent: &SuccessorIntent,
    intent_sha: &str,
    prior_successor_intent_sha: Option<&str>,
) -> Result<Vec<u8>> {
    if prior_successor_intent_sha.is_some_and(|sha| !exact_hex(sha)) {
        return Err(refuse());
    }
    let value = serde_json::json!({
        "schema": "aegis_auto_v2_stopped_successor_verification_v1",
        "stopped": stopped,
        "successor": {
            "intent_sha256": intent_sha,
            "kind": intent.kind,
            "old_active_sha256": intent.old_active_sha256,
            "old_stopped_sha256": intent.old_stopped_sha256,
            "next_public_payload_root": intent.next_public_payload_root,
            "next_candidate_binary": intent.next_candidate_binary,
            "next_candidate_sha256": intent.next_candidate_sha256,
            "next_installer_sha256": intent.next_installer_sha256,
            "next_bundle_manifest_sha256": intent.next_bundle_manifest_sha256,
            "next_sums_sha256": intent.next_sums_sha256,
            "prior_successor_intent_sha256": prior_successor_intent_sha,
        }
    });
    serde_json::to_vec(&value).map_err(|_| refuse())
}

/// Persist a strict, resumable intent under the original InstallLock. The
/// StageGuard and guard flock in `observed` remain held by the caller.
pub(super) fn begin_stopped_successor(
    history: &SuccessorHistory,
    observed: &[u8],
    root: &Path,
    candidate: &Path,
    lock: &InstallLock,
) -> Result<Vec<u8>> {
    lock.revalidate().map_err(|_| refuse())?;
    if observed != serde_json::to_vec(&history.stopped).map_err(|_| refuse())? {
        return Err(refuse());
    }
    let intent = successor_intent(history, root, candidate)?;
    let bytes = serde_json::to_vec(&intent).map_err(|_| refuse())?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), RECOVERY_LEAF)?;
    if let Some(existing) = &history.intent_bytes {
        if existing != &bytes {
            return Err(refuse());
        }
    } else {
        recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF)?;
        write_sealed_leaf(control.as_raw_fd(), SUCCESSOR_LEAF, &bytes)?;
    }
    let intent_sha = digest(&bytes);
    complete_archive_transition(
        control.as_raw_fd(),
        &bytes,
        &intent,
        &history.active_bytes,
        &history.stopped_bytes,
        &history.pointer_receipt_bytes,
    )?;
    lock.revalidate().map_err(|_| refuse())?;
    successor_output(
        &history.stopped,
        &intent,
        &intent_sha,
        history.prior_successor_intent_sha256.as_deref(),
    )
}

/// Retire an old active generation only after the opaque fresh-boot observer
/// has remeasured its capsule, installed source, fixed namespace and deny.
/// This transition never manufactures a Stop receipt for the old boot.
pub(super) fn begin_boot_successor(
    verified: &super::installer_v2_boot::VerifiedBootObservation,
    lock: &InstallLock,
) -> Result<Vec<u8>> {
    lock.revalidate().map_err(|_| refuse())?;
    verified.revalidate(lock)?;
    let (old_report, snapshot_sha) = boot_history()?;
    if &old_report != verified.report() || snapshot_sha != verified.snapshot_sha256() {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), RECOVERY_LEAF)?;
    recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF)?;
    let old_active_bytes = if recovery_absent(control.as_raw_fd(), LEAF).is_err() {
        read_sealed_leaf(control.as_raw_fd(), LEAF)?
    } else {
        let (_, pending) = read_boot_intent(control.as_raw_fd())?;
        let history = history_dir(control.as_raw_fd(), false)?;
        read_archived(history.as_raw_fd(), "active", &pending.old_active_sha256)?
    };
    let old_active = parse_active(&old_active_bytes)?;
    if old_active.report != old_report
        || old_active.boot_snapshot_sha256.as_deref() != Some(snapshot_sha.as_str())
    {
        return Err(refuse());
    }
    let snapshot_bytes = super::installer_v2_boot::reopen_snapshot_bytes(&snapshot_sha)?;
    let prior_intent = if recovery_absent(control.as_raw_fd(), BOOT_SUCCESSOR_LEAF).is_ok() {
        None
    } else {
        Some(read_boot_intent(control.as_raw_fd())?.1)
    };
    let stopped = boot_stopped(
        control.as_raw_fd(),
        &old_active_bytes,
        &old_active,
        prior_intent
            .as_ref()
            .and_then(|intent| intent.old_stopped_sha256.as_deref()),
        prior_intent
            .as_ref()
            .and_then(|intent| intent.old_pointer_receipt_sha256.as_deref()),
    )?;
    if prior_intent
        .as_ref()
        .is_some_and(|intent| intent.old_stopped_sha256.is_some())
        != stopped.is_some()
    {
        return Err(refuse());
    }
    let prior_pointer_sha = prior_intent
        .as_ref()
        .map(|intent| intent.old_pointer_sha256.as_str());
    let stopped_pointer_sha = stopped.as_ref().map(|(_, sha)| sha.as_str());
    if prior_pointer_sha.is_some()
        && stopped_pointer_sha.is_some()
        && prior_pointer_sha != stopped_pointer_sha
    {
        return Err(refuse());
    }
    let pointer_receipt = if let Some((bytes, _)) = &stopped {
        let parsed = parse_stopped(bytes, &old_active_bytes, &old_active)?;
        Some(stopped_pointer_receipt(
            control.as_raw_fd(),
            &parsed.report,
            prior_intent
                .as_ref()
                .and_then(|intent| intent.old_pointer_receipt_sha256.as_deref()),
        )?)
    } else {
        None
    };
    let pointer_bytes = boot_pointer(
        control.as_raw_fd(),
        &old_report,
        prior_pointer_sha.or(stopped_pointer_sha),
    )?;
    let verified_proof: serde_json::Value =
        serde_json::from_slice(verified.verified_bytes()).map_err(|_| refuse())?;
    boot_proof_shape(&old_report, &verified_proof)?;
    let root = Path::new(
        old_report["input"]["public_payload_root"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let candidate = Path::new(
        old_report["input"]["candidate_binary"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let (candidate_sha, installer_sha) = verified_retained_source(root, candidate)?;
    if old_report["input"]["candidate_sha256"].as_str() != Some(candidate_sha.as_str()) {
        return Err(refuse());
    }
    let intent = BootSuccessorIntent {
        schema: "aegis_auto_v2_boot_successor_v1".into(),
        old_active_sha256: digest(&old_active_bytes),
        old_stopped_sha256: stopped.as_ref().map(|(bytes, _)| digest(bytes)),
        old_pointer_receipt_sha256: pointer_receipt.as_ref().map(|bytes| digest(bytes)),
        old_snapshot_sha256: snapshot_sha,
        old_pointer_sha256: digest(&pointer_bytes),
        verified_boot_sha256: digest(verified.verified_bytes()),
        old_boot_id: old_report["terminal"]["boot_id"]
            .as_str()
            .ok_or_else(refuse)?
            .into(),
        new_boot_id: verified.current_boot_id().into(),
        public_payload_root: root.to_str().ok_or_else(refuse)?.into(),
        candidate_binary: candidate.to_str().ok_or_else(refuse)?.into(),
        candidate_sha256: candidate_sha,
        installer_sha256: installer_sha,
    };
    boot_successor_shape(&intent)?;
    let intent_bytes = serde_json::to_vec(&intent).map_err(|_| refuse())?;
    if recovery_absent(control.as_raw_fd(), BOOT_SUCCESSOR_LEAF).is_ok() {
        verified.revalidate(lock)?;
        write_sealed_leaf(control.as_raw_fd(), BOOT_SUCCESSOR_LEAF, &intent_bytes)?;
    } else if read_boot_intent(control.as_raw_fd())?.0 != intent_bytes {
        return Err(refuse());
    }
    let history = history_dir(control.as_raw_fd(), true)?;
    archive_exact(
        history.as_raw_fd(),
        "active",
        &intent.old_active_sha256,
        &old_active_bytes,
    )?;
    if let (Some(sha), Some((bytes, _))) = (&intent.old_stopped_sha256, &stopped) {
        archive_exact(history.as_raw_fd(), "stopped", sha, bytes)?;
    }
    if let (Some(sha), Some(bytes)) = (&intent.old_pointer_receipt_sha256, &pointer_receipt) {
        archive_exact(history.as_raw_fd(), "stopped-pointer", sha, bytes)?;
    }
    archive_exact(
        history.as_raw_fd(),
        "snapshot",
        &intent.old_snapshot_sha256,
        &snapshot_bytes,
    )?;
    archive_exact(
        history.as_raw_fd(),
        "boot-proof",
        &intent.verified_boot_sha256,
        verified.verified_bytes(),
    )?;
    archive_exact(
        history.as_raw_fd(),
        "boot-pointer",
        &intent.old_pointer_sha256,
        &pointer_bytes,
    )?;
    if recovery_absent(control.as_raw_fd(), "current.json").is_err() {
        retire_exact(control.as_raw_fd(), "current.json", &pointer_bytes)?;
    }
    if recovery_absent(control.as_raw_fd(), LEAF).is_err() {
        retire_exact(control.as_raw_fd(), LEAF, &old_active_bytes)?;
    }
    if let Some((bytes, _)) = &stopped {
        if recovery_absent(control.as_raw_fd(), STOPPED_LEAF).is_err() {
            retire_exact(control.as_raw_fd(), STOPPED_LEAF, bytes)?;
        }
    }
    if let Some(bytes) = &pointer_receipt {
        if recovery_absent(control.as_raw_fd(), "generation-pointer-stopped.json").is_err() {
            retire_exact(
                control.as_raw_fd(),
                "generation-pointer-stopped.json",
                bytes,
            )?;
        }
    }
    recovery_absent(control.as_raw_fd(), LEAF)?;
    recovery_absent(control.as_raw_fd(), STOPPED_LEAF)?;
    recovery_absent(control.as_raw_fd(), "generation-pointer-stopped.json")?;
    recovery_absent(control.as_raw_fd(), "current.json")?;
    if read_boot_intent(control.as_raw_fd())?.0 != intent_bytes
        || read_archived(history.as_raw_fd(), "active", &intent.old_active_sha256)?
            != old_active_bytes
        || intent.old_stopped_sha256.as_ref().is_some_and(|sha| {
            stopped.as_ref().is_none_or(|(bytes, _)| {
                read_archived(history.as_raw_fd(), "stopped", sha)
                    .ok()
                    .as_deref()
                    != Some(bytes.as_slice())
            })
        })
        || read_archived(history.as_raw_fd(), "snapshot", &intent.old_snapshot_sha256)?
            != snapshot_bytes
        || read_archived(
            history.as_raw_fd(),
            "boot-proof",
            &intent.verified_boot_sha256,
        )? != verified.verified_bytes()
        || read_archived(
            history.as_raw_fd(),
            "boot-pointer",
            &intent.old_pointer_sha256,
        )? != pointer_bytes
    {
        return Err(refuse());
    }
    verified.revalidate(lock)?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_boot_successor_verification_v1",
        "intent_sha256": digest(&intent_bytes),
        "old_active_sha256": intent.old_active_sha256,
        "old_stopped_sha256": intent.old_stopped_sha256,
        "old_pointer_receipt_sha256": intent.old_pointer_receipt_sha256,
        "old_snapshot_sha256": intent.old_snapshot_sha256,
        "verified_boot_sha256": intent.verified_boot_sha256,
        "old_boot_id": intent.old_boot_id,
        "new_boot_id": intent.new_boot_id,
        "public_payload_root": intent.public_payload_root,
        "candidate_binary": intent.candidate_binary,
        "candidate_sha256": intent.candidate_sha256,
        "installer_sha256": intent.installer_sha256,
    }))
    .map_err(|_| refuse())
}

pub(super) fn verify_stopped_successor(
    history: &SuccessorHistory,
    observed: &[u8],
) -> Result<Vec<u8>> {
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), LEAF)?;
    recovery_absent(control.as_raw_fd(), STOPPED_LEAF)?;
    recovery_absent(control.as_raw_fd(), RECOVERY_LEAF)?;
    let (bytes, intent) = read_intent(control.as_raw_fd())?;
    let expected = successor_intent(
        history,
        Path::new(&intent.next_public_payload_root),
        Path::new(&intent.next_candidate_binary),
    )?;
    if serde_json::to_vec(&expected).map_err(|_| refuse())? != bytes
        || observed != serde_json::to_vec(&history.stopped).map_err(|_| refuse())?
    {
        return Err(refuse());
    }
    let archived = history_dir(control.as_raw_fd(), false)?;
    if read_archived(archived.as_raw_fd(), "active", &intent.old_active_sha256)?
        != history.active_bytes
        || read_archived(archived.as_raw_fd(), "stopped", &intent.old_stopped_sha256)?
            != history.stopped_bytes
    {
        return Err(refuse());
    }
    successor_output(
        &history.stopped,
        &intent,
        &digest(&bytes),
        history.prior_successor_intent_sha256.as_deref(),
    )
}

/// Post-retirement package boundary. The caller obtains `retired_readback`
/// only from the old installed guardian's bounded source-verified CLI while
/// it holds the inherited guard OFD. This method independently binds its
/// fresh deny/actor result to the archived Rust successor and protected
/// guardian transition receipts; it never grants a new Start or owner lease.
pub(super) fn verify_retired_successor(
    history: &SuccessorHistory,
    retired_readback: &serde_json::Value,
) -> Result<Vec<u8>> {
    if history.stopped["stage"]["mode"] == "socks-only" {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), LEAF)?;
    recovery_absent(control.as_raw_fd(), STOPPED_LEAF)?;
    recovery_absent(control.as_raw_fd(), RECOVERY_LEAF)?;
    let (bytes, intent) = read_intent(control.as_raw_fd())?;
    let expected = successor_intent(
        history,
        Path::new(&intent.next_public_payload_root),
        Path::new(&intent.next_candidate_binary),
    )?;
    if serde_json::to_vec(&expected).map_err(|_| refuse())? != bytes {
        return Err(refuse());
    }
    let archived = history_dir(control.as_raw_fd(), false)?;
    if read_archived(archived.as_raw_fd(), "active", &intent.old_active_sha256)?
        != history.active_bytes
        || read_archived(archived.as_raw_fd(), "stopped", &intent.old_stopped_sha256)?
            != history.stopped_bytes
    {
        return Err(refuse());
    }
    let successor_bytes = successor_output(
        &history.stopped,
        &intent,
        &digest(&bytes),
        history.prior_successor_intent_sha256.as_deref(),
    )?;
    let successor: serde_json::Value =
        serde_json::from_slice(&successor_bytes).map_err(|_| refuse())?;
    let readback = retired_readback.as_object().ok_or_else(refuse)?;
    if readback.len() != 8
        || [
            "schema",
            "boot_id",
            "intent_sha256",
            "denied_sha256",
            "stopped_successor_sha256",
            "retired_sha256",
            "deny_policy_sha256",
            "no_live_actors",
        ]
        .iter()
        .any(|key| !readback.contains_key(*key))
        || retired_readback["schema"] != "aegis_auto_guard_rotation_retired_readback_v1"
        || retired_readback["boot_id"].as_str() != Some(intent.old_boot_id.as_str())
        || retired_readback["no_live_actors"] != true
        || retired_readback["stopped_successor_sha256"].as_str()
            != Some(digest(&successor_bytes).as_str())
        || ![
            "intent_sha256",
            "denied_sha256",
            "retired_sha256",
            "deny_policy_sha256",
        ]
        .iter()
        .all(|key| retired_readback[*key].as_str().is_some_and(exact_hex))
    {
        return Err(refuse());
    }
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let guardian_intent =
        read_sealed_leaf(guardian.as_raw_fd(), "auto-guard-rotation-intent.json")?;
    let denied = read_sealed_leaf(guardian.as_raw_fd(), "auto-guard-rotation-denied.json")?;
    let retired = read_sealed_leaf(guardian.as_raw_fd(), "auto-guard-rotation-retired.json")?;
    let guardian_value: serde_json::Value =
        serde_json::from_slice(&guardian_intent).map_err(|_| refuse())?;
    if retired_readback["intent_sha256"].as_str() != Some(digest(&guardian_intent).as_str())
        || retired_readback["denied_sha256"].as_str() != Some(digest(&denied).as_str())
        || retired_readback["retired_sha256"].as_str() != Some(digest(&retired).as_str())
        || guardian_value["schema"] != "aegis_auto_guard_rotation_intent_v1"
        || guardian_value["stopped_successor_sha256"].as_str()
            != Some(digest(&successor_bytes).as_str())
        || guardian_value["successor"] != successor["successor"]
        || guardian_value["old_public_payload_root"].as_str()
            != history.stopped["input"]["public_payload_root"].as_str()
    {
        return Err(refuse());
    }
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_retired_successor_verification_v1",
        "stopped": history.stopped,
        "successor": successor["successor"],
        "retired": retired_readback,
    }))
    .map_err(|_| refuse())
}

/// SOCKS package transition has no host guard OFD or deny policy. Its own
/// source-checked actor retirement is sealed under the original InstallLock
/// after a stopped successor was proved while the old actors were still live.
pub(super) fn verify_retired_passive_successor(
    history: &SuccessorHistory,
    retired_readback: &serde_json::Value,
) -> Result<Vec<u8>> {
    if history.stopped["stage"]["mode"] != "socks-only" {
        return Err(refuse());
    }
    let stopped = serde_json::to_vec(&history.stopped).map_err(|_| refuse())?;
    let successor_bytes = verify_stopped_successor(history, &stopped)?;
    let successor: serde_json::Value =
        serde_json::from_slice(&successor_bytes).map_err(|_| refuse())?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let intent_raw = read_sealed_leaf(
        control.as_raw_fd(),
        "passive-successor-retirement-intent.json",
    )?;
    let successor_intent_raw = read_sealed_leaf(control.as_raw_fd(), SUCCESSOR_LEAF)?;
    let retired_raw = read_sealed_leaf(control.as_raw_fd(), "passive-successor-retired.json")?;
    let stopped_raw = read_sealed_leaf(control.as_raw_fd(), "generation-passive-old-stopped.json")?;
    let intent: serde_json::Value = serde_json::from_slice(&intent_raw).map_err(|_| refuse())?;
    let retired: serde_json::Value = serde_json::from_slice(&retired_raw).map_err(|_| refuse())?;
    if intent.as_object().is_none_or(|o| o.len() != 8)
        || retired.as_object().is_none_or(|o| o.len() != 7)
        || intent["schema"] != "aegis_auto_v2_passive_successor_retirement_intent_v1"
        || retired["schema"] != "aegis_auto_v2_passive_successor_retired_v1"
        || intent["boot_id"] != history.stopped["terminal"]["boot_id"]
        || retired["boot_id"] != intent["boot_id"]
        || intent["successor_sha256"] != digest(&successor_bytes)
        || intent["successor_intent_sha256"] != digest(&successor_intent_raw)
        || retired["stopped_successor_sha256"] != intent["successor_sha256"]
        || intent["stopped_sha256"] != digest(&stopped)
        || stopped_raw != [stopped.as_slice(), b"\n"].concat()
        || retired["intent_sha256"] != digest(&intent_raw)
        || retired["source_sha256"] != intent["source_sha256"]
        || !retired["source_sha256"].as_str().is_some_and(exact_hex)
        || retired["no_live_actors"] != true
        || retired["non_actor_units_stopped"] != true
        || retired_readback != &retired
        || intent["actors"].as_object().is_none_or(|o| o.len() != 4)
        || intent["actor_start_ticks"]
            .as_object()
            .is_none_or(|o| o.len() != 4)
    {
        return Err(refuse());
    }
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_retired_passive_successor_verification_v1",
        "stopped": history.stopped,
        "successor": successor["successor"],
        "retired": retired,
    }))
    .map_err(|_| refuse())
}

/// Continue an interrupted passive retirement using the archived predecessor
/// chain; the live stopped observer cannot run after its guardian has stopped.
pub(super) fn verify_passive_retirement_intent(history: &SuccessorHistory) -> Result<Vec<u8>> {
    if history.stopped["stage"]["mode"] != "socks-only" {
        return Err(refuse());
    }
    let stopped = serde_json::to_vec(&history.stopped).map_err(|_| refuse())?;
    let successor = verify_stopped_successor(history, &stopped)?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let intent_raw = read_sealed_leaf(
        control.as_raw_fd(),
        "passive-successor-retirement-intent.json",
    )?;
    let intent: serde_json::Value = serde_json::from_slice(&intent_raw).map_err(|_| refuse())?;
    let original = read_sealed_leaf(control.as_raw_fd(), "generation-passive-old-stopped.json")?;
    let successor_intent = read_sealed_leaf(control.as_raw_fd(), SUCCESSOR_LEAF)?;
    if intent.as_object().is_none_or(|object| object.len() != 8)
        || intent["schema"] != "aegis_auto_v2_passive_successor_retirement_intent_v1"
        || intent["boot_id"] != history.stopped["terminal"]["boot_id"]
        || intent["stopped_sha256"] != digest(&stopped)
        || original != [stopped.as_slice(), b"\n"].concat()
        || intent["successor_sha256"] != digest(&successor)
        || intent["successor_intent_sha256"] != digest(&successor_intent)
        || intent["actors"]
            .as_object()
            .is_none_or(|object| object.len() != 4)
        || intent["actor_start_ticks"]
            .as_object()
            .is_none_or(|object| object.len() != 4)
    {
        return Err(refuse());
    }
    Ok(successor)
}

/// Read the source-bound passive package handoff without assuming that the
/// installed executable still belongs to the predecessor. Package unpack may
/// replace that executable before the coordinator is able to resume.
pub(super) fn passive_transition_evidence() -> Result<PassiveTransitionEvidence> {
    passive_transition_evidence_inner(false)
}

pub(super) fn passive_transition_evidence_with_unsealed() -> Result<PassiveTransitionEvidence> {
    passive_transition_evidence_inner(true)
}

fn passive_transition_evidence_inner(allow_unsealed: bool) -> Result<PassiveTransitionEvidence> {
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    if read_sealed_leaf(control.as_raw_fd(), "v2-enabled")?
        != b"{\"schema\":\"aegis_installer_auto_v2_enabled_v1\"}\n"
    {
        return Err(refuse());
    }
    if !allow_unsealed {
        recovery_absent(control.as_raw_fd(), RECOVERY_LEAF)?;
    }
    recovery_absent(control.as_raw_fd(), BOOT_SUCCESSOR_LEAF)?;
    let history = history_dir(control.as_raw_fd(), false)?;
    let journal = passive_advance_journal(control.as_raw_fd())?;
    let preinst_bytes = passive_leaf(
        control.as_raw_fd(),
        history.as_raw_fd(),
        PASSIVE_PREINST_LEAF,
        "passive-preinst",
        journal.as_ref(),
        "preinst_sha256",
    )?;
    let preinst = canonical_object(
        &preinst_bytes,
        "aegis_auto_v2_passive_package_preinst_v1",
        &[
            "schema",
            "successor_intent_sha256",
            "retired_intent_sha256",
            "candidate_sha256",
            "old_install_sha256",
        ],
        true,
    )?;
    let intent_sha = preinst["successor_intent_sha256"]
        .as_str()
        .ok_or_else(refuse)?;
    let retired_intent_sha = preinst["retired_intent_sha256"]
        .as_str()
        .ok_or_else(refuse)?;
    let old_install_sha = preinst["old_install_sha256"].as_str().ok_or_else(refuse)?;
    if ![intent_sha, retired_intent_sha, old_install_sha]
        .iter()
        .all(|sha| exact_hex(sha))
    {
        return Err(refuse());
    }
    let intent_archive = archived_name("intent", intent_sha)?;
    let intent_bytes = if recovery_absent(history.as_raw_fd(), &intent_archive).is_ok() {
        let raw = read_sealed_leaf(control.as_raw_fd(), SUCCESSOR_LEAF)?;
        if digest(&raw) != intent_sha {
            return Err(refuse());
        }
        raw
    } else {
        read_archived(history.as_raw_fd(), "intent", intent_sha)?
    };
    if recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF).is_err()
        && read_sealed_leaf(control.as_raw_fd(), SUCCESSOR_LEAF)? != intent_bytes
    {
        return Err(refuse());
    }
    let intent: SuccessorIntent = serde_json::from_slice(&intent_bytes).map_err(|_| refuse())?;
    successor_shape(&intent)?;
    if serde_json::to_vec(&intent).map_err(|_| refuse())? != intent_bytes
        || intent.kind != "upgrade"
        || preinst["candidate_sha256"].as_str() != Some(intent.next_candidate_sha256.as_str())
        || intent.next_installer_sha256 != digest(include_bytes!("../../../install.sh"))
    {
        return Err(refuse());
    }
    let old_active_bytes = read_archived(history.as_raw_fd(), "active", &intent.old_active_sha256)?;
    let old_stopped_bytes =
        read_archived(history.as_raw_fd(), "stopped", &intent.old_stopped_sha256)?;
    let old_active = parse_active(&old_active_bytes)?;
    let old_stopped = parse_stopped(&old_stopped_bytes, &old_active_bytes, &old_active)?;
    successor_kind(&intent, &old_active.report)?;
    if old_stopped.report["stage"]["mode"] != "socks-only"
        || old_stopped.report["stage"]["path"].as_str() != Some(intent.old_stage_path.as_str())
        || old_stopped.report["terminal"]["boot_id"].as_str() != Some(intent.old_boot_id.as_str())
        || read_archived(
            history.as_raw_fd(),
            "stopped-pointer",
            &intent.old_pointer_receipt_sha256,
        )
        .is_err()
    {
        return Err(refuse());
    }
    let old_root = old_active.report["input"]["public_payload_root"]
        .as_str()
        .ok_or_else(refuse)?;
    let old_candidate = old_active.report["input"]["candidate_binary"]
        .as_str()
        .ok_or_else(refuse)?;
    let (old_candidate_sha, _) =
        verified_retained_source(Path::new(old_root), Path::new(old_candidate))?;
    let (next_candidate_sha, next_installer_sha) = verified_retained_source(
        Path::new(&intent.next_public_payload_root),
        Path::new(&intent.next_candidate_binary),
    )?;
    if old_candidate_sha != old_active.report["input"]["candidate_sha256"]
        || next_candidate_sha != intent.next_candidate_sha256
        || next_installer_sha != intent.next_installer_sha256
    {
        return Err(refuse());
    }
    let stopped_report_bytes = serde_json::to_vec(&old_stopped.report).map_err(|_| refuse())?;
    let mut expected_stopped_record = stopped_report_bytes.clone();
    expected_stopped_record.push(b'\n');
    let stopped_record_bytes = passive_leaf(
        control.as_raw_fd(),
        history.as_raw_fd(),
        PASSIVE_OLD_STOPPED_LEAF,
        "passive-old-stopped",
        journal.as_ref(),
        "old_stopped_record_sha256",
    )?;
    let retire_intent_bytes = passive_leaf(
        control.as_raw_fd(),
        history.as_raw_fd(),
        PASSIVE_RETIRE_INTENT_LEAF,
        "passive-retirement-intent",
        journal.as_ref(),
        "retirement_intent_sha256",
    )?;
    let retired_bytes = passive_leaf(
        control.as_raw_fd(),
        history.as_raw_fd(),
        PASSIVE_RETIRED_LEAF,
        "passive-retired",
        journal.as_ref(),
        "retired_sha256",
    )?;
    let retire_intent = canonical_object(
        &retire_intent_bytes,
        "aegis_auto_v2_passive_successor_retirement_intent_v1",
        &[
            "schema",
            "boot_id",
            "successor_sha256",
            "successor_intent_sha256",
            "stopped_sha256",
            "source_sha256",
            "actors",
            "actor_start_ticks",
        ],
        true,
    )?;
    let retired = canonical_object(
        &retired_bytes,
        "aegis_auto_v2_passive_successor_retired_v1",
        &[
            "schema",
            "boot_id",
            "intent_sha256",
            "stopped_successor_sha256",
            "source_sha256",
            "no_live_actors",
            "non_actor_units_stopped",
        ],
        true,
    )?;
    let prior = most_recent_successor_sha(&old_active, history.as_raw_fd(), 32)?;
    let successor = successor_output(&old_stopped.report, &intent, intent_sha, prior.as_deref())?;
    if stopped_record_bytes != expected_stopped_record
        || retire_intent["boot_id"] != intent.old_boot_id
        || retired["boot_id"] != intent.old_boot_id
        || retire_intent["successor_intent_sha256"] != intent_sha
        || retire_intent["successor_sha256"] != digest(&successor)
        || retire_intent["stopped_sha256"] != digest(&stopped_report_bytes)
        || retire_intent["source_sha256"]
            .as_str()
            .is_none_or(|sha| !exact_hex(sha))
        || retire_intent["actors"]
            .as_object()
            .is_none_or(|actors| actors.len() != 4)
        || retire_intent["actor_start_ticks"]
            .as_object()
            .is_none_or(|ticks| ticks.len() != 4)
        || retired["intent_sha256"] != retired_intent_sha
        || digest(&retire_intent_bytes) != retired_intent_sha
        || retired["stopped_successor_sha256"] != retire_intent["successor_sha256"]
        || retired["source_sha256"] != retire_intent["source_sha256"]
        || retired["no_live_actors"] != true
        || retired["non_actor_units_stopped"] != true
    {
        return Err(refuse());
    }
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let archived_old_install =
        format!("auto-guardian-install-passive-successor-{old_install_sha}.json");
    let old_install = if recovery_absent(guardian.as_raw_fd(), &archived_old_install).is_ok() {
        read_sealed_leaf(guardian.as_raw_fd(), "auto-guardian-install.json")?
    } else {
        read_sealed_leaf(guardian.as_raw_fd(), &archived_old_install)?
    };
    let old_install_value: serde_json::Value =
        serde_json::from_slice(&old_install).map_err(|_| refuse())?;
    if digest(&old_install) != old_install_sha
        || old_install_value["worker_sha256"] != old_candidate_sha
        || !old_install_value["guard_unit_sha256"].is_null()
    {
        return Err(refuse());
    }
    let installed_dir = recovery_chain(&["usr", "local", "bin"], None)?;
    let installed = recovery_open_at(installed_dir.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    let stat = recovery_stat(installed.as_raw_fd())?;
    let installed_sha = recovery_file_hash(installed.as_raw_fd(), 256 * 1024 * 1024)?.1;
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || !matches!(stat.st_mode & 0o7777, 0o555 | 0o755)
        || ![
            old_candidate_sha.as_str(),
            intent.next_candidate_sha256.as_str(),
        ]
        .contains(&installed_sha.as_str())
        || recovery_file_hash(running.as_raw_fd(), 256 * 1024 * 1024)?.1
            != intent.next_candidate_sha256
    {
        return Err(refuse());
    }
    let current_boot = current_boot_id()?;
    let current_active = if recovery_absent(control.as_raw_fd(), LEAF).is_ok() {
        if intent.old_boot_id != current_boot {
            return Err(refuse());
        }
        None
    } else {
        let seal = read_history()?;
        let predecessor = if intent.old_boot_id == current_boot {
            seal.predecessor_intent_sha256.as_deref() == Some(intent_sha)
                && seal.report["terminal"]["boot_id"] == intent.old_boot_id
        } else {
            seal.predecessor_boot_intent_sha256.is_some()
                && seal.report["terminal"]["boot_id"] == current_boot
                && most_recent_successor_sha(&seal, history.as_raw_fd(), 32)?.as_deref()
                    == Some(intent_sha)
        };
        if !predecessor
            || seal.report["stage"]["mode"] != "socks-only"
            || seal.report["input"]["candidate_sha256"] != intent.next_candidate_sha256
        {
            return Err(refuse());
        }
        Some(seal)
    };
    if let Some(journal) = journal {
        let active = read_sealed_leaf(control.as_raw_fd(), LEAF)?;
        let current = current_active.as_ref().ok_or_else(refuse)?;
        let first_sha = passive_first_active_sha(
            current,
            &digest(&active),
            history.as_raw_fd(),
            intent_sha,
            &intent.old_boot_id,
            32,
        )?;
        if journal["successor_intent_sha256"] != intent_sha
            || journal["new_active_sha256"] != first_sha
            || journal["boot_id"] != intent.old_boot_id
        {
            return Err(refuse());
        }
    }
    Ok(PassiveTransitionEvidence {
        intent_bytes,
        intent,
        old_active,
        retire_intent_bytes,
        retired_bytes,
        stopped_record_bytes,
        preinst_bytes,
        old_install_sha256: old_install_sha.to_owned(),
        current_active,
    })
}

pub(super) fn passive_active_stage_path(evidence: &PassiveTransitionEvidence) -> Option<&str> {
    evidence
        .current_active
        .as_ref()
        .and_then(|seal| seal.report["stage"]["path"].as_str())
}

pub(super) fn passive_transition_status(
    evidence: &PassiveTransitionEvidence,
    fresh_active: Option<&serde_json::Value>,
) -> Result<Vec<u8>> {
    let old_sha = evidence.old_active.report["input"]["candidate_sha256"]
        .as_str()
        .ok_or_else(refuse)?;
    let installed_dir = recovery_chain(&["usr", "local", "bin"], None)?;
    let installed = recovery_open_at(installed_dir.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    let installed_sha = recovery_file_hash(installed.as_raw_fd(), 256 * 1024 * 1024)?.1;
    let phase = match (&evidence.current_active, fresh_active) {
        (Some(seal), Some(fresh))
            if installed_sha == evidence.intent.next_candidate_sha256
                && fresh["stage"]["path"] == seal.report["stage"]["path"]
                && fresh["stage"]["device"] == seal.report["stage"]["device"]
                && fresh["stage"]["inode"] == seal.report["stage"]["inode"]
                && fresh["terminal"]["start_terminal_sha256"]
                    == seal.report["terminal"]["start_terminal_sha256"]
                && fresh["terminal"]["invocation_id"]
                    == seal.report["terminal"]["invocation_id"]
                && fresh["input"] == seal.report["input"]
                && fresh["current_fixed"] == seal.report["current_fixed"]
                && fresh["published_paths"]["current_publications"]
                    == seal.report["published_paths"]["current_publications"]
                && fresh["main"]["active_verified"] == true
                && fresh["guardian"]["active_verified"] == true =>
        {
            "new-active"
        }
        (Some(_), _) => return Err(refuse()),
        (None, None)
            if installed_sha == evidence.intent.next_candidate_sha256
                && installed_sha != old_sha =>
        {
            "package-installed"
        }
        (None, None) if installed_sha == old_sha => "pending-old",
        _ => return Err(refuse()),
    };
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_passive_transition_status_v1",
        "phase": phase,
        "successor_intent_sha256": digest(&evidence.intent_bytes),
        "candidate_sha256": evidence.intent.next_candidate_sha256,
        "public_payload_root": evidence.intent.next_public_payload_root,
        "preinst_sha256": digest(&evidence.preinst_bytes),
        "old_install_sha256": evidence.old_install_sha256,
        "old_candidate_sha256": old_sha,
        "old_public_payload_root": evidence.old_active.report["input"]["public_payload_root"],
    }))
    .map_err(|_| refuse())
}

/// Absence is a no-op only when every current transition leaf is absent.
/// A lone partial leaf is never treated as a completed transition.
pub(super) fn passive_transition_present() -> Result<bool> {
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let leaves = [
        PASSIVE_PREINST_LEAF,
        PASSIVE_RETIRE_INTENT_LEAF,
        PASSIVE_RETIRED_LEAF,
        PASSIVE_OLD_STOPPED_LEAF,
        PASSIVE_ADVANCE_LEAF,
    ];
    let present = leaves
        .iter()
        .filter(|leaf| recovery_absent(control.as_raw_fd(), leaf).is_err())
        .count();
    if present == 0 {
        return Ok(false);
    }
    if recovery_absent(control.as_raw_fd(), PASSIVE_PREINST_LEAF).is_ok()
        && recovery_absent(control.as_raw_fd(), PASSIVE_ADVANCE_LEAF).is_ok()
    {
        return Err(refuse());
    }
    Ok(true)
}

/// Only an independently acquired original InstallLock may retire these
/// leaves. The live StageGuard is retained by the caller through this write.
pub(super) fn advance_completed_passive_transition(
    evidence: &PassiveTransitionEvidence,
    fresh_active: &serde_json::Value,
    lock: &InstallLock,
) -> Result<Vec<u8>> {
    lock.revalidate().map_err(|_| refuse())?;
    let status_bytes = passive_transition_status(evidence, Some(fresh_active))?;
    let status: serde_json::Value = serde_json::from_slice(&status_bytes).map_err(|_| refuse())?;
    if status["phase"] != "new-active" {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let active_bytes = read_sealed_leaf(control.as_raw_fd(), LEAF)?;
    let active = parse_active(&active_bytes)?;
    let history = history_dir(control.as_raw_fd(), false)?;
    let current_boot = current_boot_id()?;
    let direct = current_boot == evidence.intent.old_boot_id
        && active.predecessor_intent_sha256.as_deref()
            == Some(digest(&evidence.intent_bytes).as_str());
    let via_boot = current_boot != evidence.intent.old_boot_id
        && active.predecessor_boot_intent_sha256.is_some()
        && most_recent_successor_sha(&active, history.as_raw_fd(), 32)?.as_deref()
            == Some(digest(&evidence.intent_bytes).as_str());
    if !(direct || via_boot)
        || active.report["stage"]["mode"] != "socks-only"
        || active.report["terminal"]["boot_id"] != current_boot
    {
        return Err(refuse());
    }
    let first_active_sha = passive_first_active_sha(
        &active,
        &digest(&active_bytes),
        history.as_raw_fd(),
        &digest(&evidence.intent_bytes),
        &evidence.intent.old_boot_id,
        32,
    )?;
    let journal = serde_json::json!({
        "schema": "aegis_auto_v2_passive_advance_v1",
        "boot_id": evidence.intent.old_boot_id,
        "successor_intent_sha256": digest(&evidence.intent_bytes),
        "new_active_sha256": first_active_sha,
        "retirement_intent_sha256": digest(&evidence.retire_intent_bytes),
        "retired_sha256": digest(&evidence.retired_bytes),
        "old_stopped_record_sha256": digest(&evidence.stopped_record_bytes),
        "preinst_sha256": digest(&evidence.preinst_bytes),
    });
    let journal_bytes = serde_json::to_vec(&journal).map_err(|_| refuse())?;
    if recovery_absent(control.as_raw_fd(), PASSIVE_ADVANCE_LEAF).is_ok() {
        write_passive_atomic(
            control.as_raw_fd(),
            PASSIVE_ADVANCE_LEAF,
            &journal_bytes,
            MAX_SEAL,
        )?;
    } else if read_sealed_leaf(control.as_raw_fd(), PASSIVE_ADVANCE_LEAF)? != journal_bytes {
        return Err(refuse());
    }
    let records = [
        (
            PASSIVE_OLD_STOPPED_LEAF,
            "passive-old-stopped",
            &evidence.stopped_record_bytes,
        ),
        (
            PASSIVE_RETIRE_INTENT_LEAF,
            "passive-retirement-intent",
            &evidence.retire_intent_bytes,
        ),
        (
            PASSIVE_RETIRED_LEAF,
            "passive-retired",
            &evidence.retired_bytes,
        ),
        (
            PASSIVE_PREINST_LEAF,
            "passive-preinst",
            &evidence.preinst_bytes,
        ),
    ];
    // Archive every record before removing the first fixed name. An
    // interrupted retry accepts only the exact hash named by the journal.
    for (_, prefix, bytes) in records {
        archive_exact(history.as_raw_fd(), prefix, &digest(bytes), bytes)?;
    }
    lock.revalidate().map_err(|_| refuse())?;
    for (name, _, bytes) in records {
        if recovery_absent(control.as_raw_fd(), name).is_err() {
            retire_exact(control.as_raw_fd(), name, bytes)?;
        }
    }
    for (name, prefix, bytes) in records {
        if recovery_absent(control.as_raw_fd(), name).is_err()
            || read_archived(history.as_raw_fd(), prefix, &digest(bytes))? != *bytes
        {
            return Err(refuse());
        }
    }
    archive_exact(
        history.as_raw_fd(),
        "passive-advance",
        &digest(&journal_bytes),
        &journal_bytes,
    )?;
    retire_exact(control.as_raw_fd(), PASSIVE_ADVANCE_LEAF, &journal_bytes)?;
    lock.revalidate().map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_passive_transition_advance_v1",
        "outcome": "archived",
        "successor_intent_sha256": digest(&evidence.intent_bytes),
        "new_active_sha256": digest(&active_bytes),
        "journal_sha256": digest(&journal_bytes),
    }))
    .map_err(|_| refuse())
}

fn fixed_roles_shape(value: &serde_json::Value) -> Result<()> {
    let nodes = value.as_array().ok_or_else(refuse)?;
    if !(2..=132).contains(&nodes.len()) {
        return Err(refuse());
    }
    let mut prior: Option<&Path> = None;
    for node in nodes {
        let object = node.as_object().ok_or_else(refuse)?;
        let fields = [
            "role", "path", "kind", "sha256", "uid", "gid", "mode", "size", "device", "inode",
        ];
        if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
            return Err(refuse());
        }
        let path = Path::new(node["path"].as_str().ok_or_else(refuse)?);
        let role = node["role"].as_str().ok_or_else(refuse)?;
        let kind = node["kind"].as_str().ok_or_else(refuse)?;
        let role_path = match role {
            "base-unit" => path == Path::new("/etc/systemd/system/aegis-client.service"),
            "environment" => path == Path::new("/etc/default/aegis-client"),
            "dropins" => {
                path == Path::new("/etc/systemd/system/aegis-client.service.d")
                    || path.parent()
                        == Some(Path::new("/etc/systemd/system/aegis-client.service.d"))
            }
            _ => false,
        };
        if !role_path
            || !super::absolute(path)
            || prior.is_some_and(|old| old >= path)
            || !matches!(
                kind,
                "regular" | "directory" | "missing-file" | "missing-directory"
            )
        {
            return Err(refuse());
        }
        prior = Some(path);
        let numeric = ["uid", "gid", "mode", "size", "device", "inode"];
        if kind.starts_with("missing") {
            if !node["sha256"].is_null() || numeric.iter().any(|key| !node[key].is_null()) {
                return Err(refuse());
            }
        } else if numeric.iter().any(|key| node[key].as_u64().is_none())
            || (kind == "regular" && !node["sha256"].as_str().is_some_and(exact_hex))
            || (kind == "directory" && !node["sha256"].is_null())
        {
            return Err(refuse());
        }
    }
    Ok(())
}

fn unsealed_stopped_shape(report: &serde_json::Value) -> Result<()> {
    let object = report.as_object().ok_or_else(refuse)?;
    if object.len() != 8
        || [
            "schema",
            "stage",
            "terminal",
            "published_paths",
            "current_fixed",
            "input",
            "main",
            "guardian",
        ]
        .iter()
        .any(|key| !object.contains_key(*key))
        || report["schema"] != "aegis_auto_v2_stopped_stage_inspection_v1"
        || report["stage"]["phase"] != "finalized"
        || !matches!(
            report["stage"]["mode"].as_str(),
            Some("socks-only" | "wide-redirect-safe" | "full-wide-tun")
        )
        || report["terminal"]["outcome"] != "finalized-stopped"
        || report["published_paths"]["current_verified"] != true
        || report["main"]["stopped_verified"] != true
        || report["main"]["no_live_lease_verified"] != true
        || report["main"]["fdstore_empty_verified"] != true
        || report["guardian"]["deny_verified"] != true
        || report["guardian"]["fdstore_empty_verified"] != true
        || !report["guardian"]["prior_manager_binding_sha256"].is_null()
        || !report["stage"]["device"].as_u64().is_some_and(|v| v > 0)
        || !report["stage"]["inode"].as_u64().is_some_and(|v| v > 0)
        || [
            "start_terminal_sha256",
            "stop_submitted_sha256",
            "stop_completed_sha256",
            "stop_terminal_sha256",
        ]
        .iter()
        .any(|key| !report["terminal"][key].as_str().is_some_and(exact_hex))
        || !report["terminal"]["boot_id"].is_string()
        || fixed_roles_shape(&report["current_fixed"]).is_err()
    {
        return Err(refuse());
    }
    let passive = report["stage"]["mode"] == "socks-only";
    if !(if passive {
        report["guardian"]["manager_binding_sha256"].is_null()
    } else {
        report["guardian"]["manager_binding_sha256"]
            .as_str()
            .is_some_and(exact_hex)
    }) {
        return Err(refuse());
    }
    let roots = report["published_paths"]["current_publications"]
        .as_object()
        .ok_or_else(refuse)?;
    if roots.len() != 3
        || ["config", "state", "metadata"].iter().any(|key| {
            !roots
                .get(*key)
                .and_then(|v| v.as_str())
                .is_some_and(exact_hex)
        })
    {
        return Err(refuse());
    }
    let input = report["input"].as_object().ok_or_else(refuse)?;
    if input.len() != 5
        || [
            "public_payload_root",
            "candidate_binary",
            "candidate_sha256",
            "provenance_sha256",
            "installed_manifest_sha256",
        ]
        .iter()
        .any(|key| !input.contains_key(*key))
        || [
            "candidate_sha256",
            "provenance_sha256",
            "installed_manifest_sha256",
        ]
        .iter()
        .any(|key| !report["input"][key].as_str().is_some_and(exact_hex))
    {
        return Err(refuse());
    }
    let stage = Path::new(report["stage"]["path"].as_str().ok_or_else(refuse)?);
    let public = Path::new(
        report["input"]["public_payload_root"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let candidate = Path::new(
        report["input"]["candidate_binary"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    if stage.parent() != Some(Path::new("/run/aegis-installer-config-snapshots"))
        || public.parent() != Some(Path::new("/var/lib/aegis-auto/releases"))
        || candidate != public.join("bin/aegis-client")
    {
        return Err(refuse());
    }
    Ok(())
}

fn archived_lineage_is_current(
    active: &serde_json::Value,
    incoming: &serde_json::Value,
    newer_successor_pending: bool,
) -> bool {
    active == incoming && !newer_successor_pending
}

fn boot_successor_for_new_report(
    control: i32,
    report: &serde_json::Value,
) -> Result<Option<(Vec<u8>, BootSuccessorIntent)>> {
    let pending = if recovery_absent(control, BOOT_SUCCESSOR_LEAF).is_err() {
        Some(lineage_tag(
            read_boot_intent(control),
            LineageGate::BootIntentRead,
        )?)
    } else if recovery_absent(control, LEAF).is_err() {
        let active_bytes =
            lineage_tag(read_sealed_leaf(control, LEAF), LineageGate::BootActiveRead)?;
        let existing = lineage_tag(parse_active(&active_bytes), LineageGate::BootActiveShape)?;
        if let Some(sha) = existing.predecessor_boot_intent_sha256 {
            // Archived boot ancestry authorizes only an idempotent seal of
            // this exact generation. A later successor has its own intent.
            if !archived_lineage_is_current(
                &existing.report,
                report,
                recovery_absent(control, SUCCESSOR_LEAF).is_err()
                    || recovery_absent(control, COLD_FIRST_ARM_LEAF).is_err(),
            ) {
                return Ok(None);
            }
            let history = lineage_tag(history_dir(control, false), LineageGate::BootHistory)?;
            let bytes = lineage_tag(
                read_archived(history.as_raw_fd(), "boot-intent", &sha),
                LineageGate::BootArchivedIntent,
            )?;
            let intent: BootSuccessorIntent = lineage_tag(
                serde_json::from_slice(&bytes).map_err(|_| refuse()),
                LineageGate::BootArchivedIntent,
            )?;
            lineage_tag(
                boot_successor_shape(&intent),
                LineageGate::BootArchivedIntent,
            )?;
            Some((bytes, intent))
        } else {
            None
        }
    } else {
        None
    };
    let Some((bytes, intent)) = pending else {
        return Ok(None);
    };
    lineage_tag(
        recovery_absent(control, SUCCESSOR_LEAF),
        LineageGate::BootPendingExclusion,
    )?;
    lineage_tag(
        recovery_absent(control, STOPPED_LEAF),
        LineageGate::BootPendingExclusion,
    )?;
    let history = lineage_tag(history_dir(control, false), LineageGate::BootHistory)?;
    let old_raw = lineage_tag(
        read_archived(history.as_raw_fd(), "active", &intent.old_active_sha256),
        LineageGate::BootOldActive,
    )?;
    let old = lineage_tag(parse_active(&old_raw), LineageGate::BootOldActiveShape)?;
    // The new pending pointer is an independent live authority. An absent
    // pointer keeps the old archived-only path; any present pointer must pass
    // the existing complete typed, backup and source binding against the new
    // finalized report before the old archive can be reopened.
    let authorized_current =
        validated_successor_current_pointer(control, report, &intent.new_boot_id)?;
    let old_stopped = lineage_tag(
        boot_stopped_with_authorized_current(
            control,
            &old_raw,
            &old,
            intent.old_stopped_sha256.as_deref(),
            intent.old_pointer_receipt_sha256.as_deref(),
            authorized_current.as_deref(),
        ),
        LineageGate::BootStoppedShape,
    )?;
    if lineage_bad(
        old_stopped.is_some() != intent.old_stopped_sha256.is_some(),
        LineageGate::BootStoppedIdentity,
    ) || lineage_bad(
        old_stopped
            .as_ref()
            .is_some_and(|(_, sha)| sha != &intent.old_pointer_sha256),
        LineageGate::BootStoppedIdentity,
    ) {
        return Err(refuse());
    }
    let capsule = lineage_tag(
        read_archived(history.as_raw_fd(), "snapshot", &intent.old_snapshot_sha256),
        LineageGate::BootSnapshot,
    )?;
    let boot_proof = lineage_tag(
        read_archived(
            history.as_raw_fd(),
            "boot-proof",
            &intent.verified_boot_sha256,
        ),
        LineageGate::BootProof,
    )?;
    let pointer = lineage_tag(
        read_archived(
            history.as_raw_fd(),
            "boot-pointer",
            &intent.old_pointer_sha256,
        ),
        LineageGate::BootPointer,
    )?;
    let proof: serde_json::Value = lineage_tag(
        serde_json::from_slice(&boot_proof).map_err(|_| refuse()),
        LineageGate::BootProofShape,
    )?;
    lineage_tag(
        boot_proof_shape(&old.report, &proof),
        LineageGate::BootProofShape,
    )?;
    if lineage_bad(
        old.boot_snapshot_sha256.as_deref() != Some(intent.old_snapshot_sha256.as_str()),
        LineageGate::BootOldIdentity,
    ) || lineage_bad(
        old.report["terminal"]["boot_id"].as_str() != Some(intent.old_boot_id.as_str()),
        LineageGate::BootOldIdentity,
    ) || lineage_bad(
        capsule
            != lineage_tag(
                super::installer_v2_boot::reopen_snapshot_bytes(&intent.old_snapshot_sha256),
                LineageGate::BootSnapshotReopen,
            )?,
        LineageGate::BootSnapshotReopen,
    ) || lineage_bad(
        lineage_tag(
            boot_pointer_with_authorized_current(
                control,
                &old.report,
                Some(&intent.old_pointer_sha256),
                authorized_current.as_deref(),
            ),
            LineageGate::BootPointerReopen,
        )? != pointer,
        LineageGate::BootPointerReopen,
    ) || lineage_bad(
        proof["schema"] != "aegis_auto_v2_verified_boot_v1",
        LineageGate::BootProofIdentity,
    ) || lineage_bad(
        proof["old_report_sha256"].as_str()
            != Some(
                digest(&lineage_tag(
                    serde_json::to_vec(&old.report).map_err(|_| refuse()),
                    LineageGate::BootProofIdentity,
                )?)
                .as_str(),
            ),
        LineageGate::BootProofIdentity,
    ) || lineage_bad(
        proof["snapshot_sha256"].as_str() != Some(intent.old_snapshot_sha256.as_str()),
        LineageGate::BootProofIdentity,
    ) || lineage_bad(
        proof["old_boot_id"].as_str() != Some(intent.old_boot_id.as_str()),
        LineageGate::BootProofIdentity,
    ) || lineage_bad(
        proof["new_boot_id"].as_str() != Some(intent.new_boot_id.as_str()),
        LineageGate::BootProofIdentity,
    ) || lineage_bad(
        old.report["input"]["public_payload_root"].as_str()
            != Some(intent.public_payload_root.as_str()),
        LineageGate::BootOldIdentity,
    ) || lineage_bad(
        old.report["input"]["candidate_binary"].as_str() != Some(intent.candidate_binary.as_str()),
        LineageGate::BootOldIdentity,
    ) || lineage_bad(
        old.report["input"]["candidate_sha256"].as_str() != Some(intent.candidate_sha256.as_str()),
        LineageGate::BootOldIdentity,
    ) || lineage_bad(
        report["terminal"]["boot_id"].as_str() != Some(intent.new_boot_id.as_str()),
        LineageGate::BootNewIdentity,
    ) || lineage_bad(
        report["input"]["public_payload_root"].as_str()
            != Some(intent.public_payload_root.as_str()),
        LineageGate::BootNewIdentity,
    ) || lineage_bad(
        report["input"]["candidate_binary"].as_str() != Some(intent.candidate_binary.as_str()),
        LineageGate::BootNewIdentity,
    ) || lineage_bad(
        report["input"]["candidate_sha256"].as_str() != Some(intent.candidate_sha256.as_str()),
        LineageGate::BootNewIdentity,
    ) || lineage_bad(
        intent.installer_sha256 != digest(include_bytes!("../../../install.sh")),
        LineageGate::BootInstallerIdentity,
    ) {
        return Err(refuse());
    }
    let (candidate_sha, installer_sha) = lineage_tag(
        verified_retained_source(
            Path::new(&intent.public_payload_root),
            Path::new(&intent.candidate_binary),
        ),
        LineageGate::BootRetainedSource,
    )?;
    if lineage_bad(
        candidate_sha != intent.candidate_sha256,
        LineageGate::BootRetainedIdentity,
    ) || lineage_bad(
        installer_sha != intent.installer_sha256,
        LineageGate::BootRetainedIdentity,
    ) {
        return Err(refuse());
    }
    Ok(Some((bytes, intent)))
}

fn exact_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn report_shape(report: &serde_json::Value) -> Result<()> {
    let object = report.as_object().ok_or_else(refuse)?;
    let required = [
        "schema",
        "stage",
        "terminal",
        "published_paths",
        "current_fixed",
        "input",
        "main",
        "guardian",
    ];
    if object.len() != required.len()
        || required.iter().any(|key| !object.contains_key(*key))
        || report["schema"] != "aegis_auto_active_stage_inspection_v1"
        || report["stage"]["phase"] != "finalized"
        || !matches!(
            report["stage"]["mode"].as_str(),
            Some("socks-only" | "wide-redirect-safe" | "full-wide-tun")
        )
        || report["terminal"]["outcome"] != "finalized"
        || report["published_paths"]["current_verified"] != true
        || report["main"]["active_verified"] != true
        || report["guardian"]["active_verified"] != true
        || !report["stage"]["device"]
            .as_u64()
            .is_some_and(|value| value > 0)
        || !report["stage"]["inode"]
            .as_u64()
            .is_some_and(|value| value > 0)
    {
        return Err(refuse());
    }
    let passive = report["stage"]["mode"] == "socks-only";
    if !(if passive {
        report["guardian"]["manager_binding_sha256"].is_null()
    } else {
        report["guardian"]["manager_binding_sha256"]
            .as_str()
            .is_some_and(exact_hex)
    }) {
        return Err(refuse());
    }
    let roots = report["published_paths"]["current_publications"]
        .as_object()
        .ok_or_else(refuse)?;
    let input = report["input"].as_object().ok_or_else(refuse)?;
    if input.len() != 5
        || [
            "public_payload_root",
            "candidate_binary",
            "candidate_sha256",
            "provenance_sha256",
            "installed_manifest_sha256",
        ]
        .iter()
        .any(|key| !input.contains_key(*key))
        || roots.len() != 3
        || ["config", "state", "metadata"].iter().any(|key| {
            !roots
                .get(*key)
                .and_then(|v| v.as_str())
                .is_some_and(exact_hex)
        })
        || !report["input"]["candidate_sha256"]
            .as_str()
            .is_some_and(exact_hex)
        || !report["input"]["provenance_sha256"]
            .as_str()
            .is_some_and(exact_hex)
        || !report["input"]["installed_manifest_sha256"]
            .as_str()
            .is_some_and(exact_hex)
        || !report["input"]["public_payload_root"].is_string()
        || !report["input"]["candidate_binary"].is_string()
        || !report["stage"]["path"].is_string()
        || !report["terminal"]["boot_id"].is_string()
        || !report["terminal"]["start_terminal_sha256"]
            .as_str()
            .is_some_and(exact_hex)
    {
        return Err(refuse());
    }
    for key in ["public_payload_root", "candidate_binary"] {
        let path = Path::new(report["input"][key].as_str().ok_or_else(refuse)?);
        if !super::absolute(path) {
            return Err(refuse());
        }
    }
    let stage = Path::new(report["stage"]["path"].as_str().ok_or_else(refuse)?);
    let public = Path::new(
        report["input"]["public_payload_root"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let candidate = Path::new(
        report["input"]["candidate_binary"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    if stage.parent() != Some(Path::new("/run/aegis-installer-config-snapshots"))
        || public.parent() != Some(Path::new("/var/lib/aegis-auto/releases"))
        || candidate != public.join("bin/aegis-client")
        || fixed_roles_shape(&report["current_fixed"]).is_err()
    {
        return Err(refuse());
    }
    Ok(())
}

type BootLineage = Option<(Vec<u8>, BootSuccessorIntent)>;
type StoppedLineage = Option<(Vec<u8>, SuccessorIntent)>;
type ColdLineage = Option<(Vec<u8>, ColdFirstArmIntent)>;

// Only these static coordinates can leave the private installed stderr. They
// annotate propagated refusals; absent, inapplicable lineage is silent.
#[derive(Clone, Copy, Debug)]
enum LineageGate {
    RecoveryAbsent,
    StoppedAbsent,
    BootSelection,
    ColdSelection,
    BootIntentRead,
    BootArchivedIntent,
    BootActiveRead,
    BootActiveShape,
    BootPendingExclusion,
    BootHistory,
    BootOldActive,
    BootOldActiveShape,
    BootStoppedShape,
    BootStoppedIdentity,
    BootSnapshot,
    BootProof,
    BootPointer,
    BootProofShape,
    BootSnapshotReopen,
    BootPointerReopen,
    BootNewCurrentPointer,
    BootOldIdentity,
    BootProofIdentity,
    BootNewIdentity,
    BootInstallerIdentity,
    BootRetainedSource,
    BootRetainedIdentity,
    ColdIntentRead,
    ColdActiveRead,
    ColdActiveShape,
    ColdHistory,
    ColdArchivedIntent,
    ColdIntentShape,
    ColdPendingExclusion,
    ColdCurrentIdentity,
    ColdNewIdentity,
    ColdInstallerIdentity,
    ColdOldActive,
    ColdOldStopped,
    ColdStoppedShape,
    ColdSuccessorIntent,
    ColdPredecessorIdentity,
    GenericIntentRead,
    GenericActiveRead,
    GenericActiveShape,
    GenericHistory,
    GenericArchivedIntent,
    GenericIntentShape,
    GenericOldActive,
    GenericOldStopped,
    GenericStoppedShape,
    GenericSuccessorKind,
    GenericOldIdentity,
    GenericNewIdentity,
    GenericInstallerIdentity,
    GenericRetainedSource,
    GenericRetainedIdentity,
    FreshHistoryAbsent,
    FreshBootIntentAbsent,
}

fn lineage_refusal(gate: LineageGate) {
    // Stderr is private execution evidence. A closed stderr never changes the
    // original error or grants authority.
    let _ = writeln!(
        std::io::stderr().lock(),
        "AUTO_GENERATION_LINEAGE_REFUSED gate={gate:?}"
    );
}

fn lineage_tag<T>(result: Result<T>, gate: LineageGate) -> Result<T> {
    result.inspect_err(|_| lineage_refusal(gate))
}

fn lineage_bad(predicate: bool, gate: LineageGate) -> bool {
    if predicate {
        lineage_refusal(gate);
    }
    predicate
}

fn cold_successor_for_new_report(control: i32, report: &serde_json::Value) -> Result<ColdLineage> {
    let pending = if recovery_absent(control, COLD_FIRST_ARM_LEAF).is_err() {
        Some(lineage_tag(
            cold_first_arm_intent(control),
            LineageGate::ColdIntentRead,
        )?)
    } else if recovery_absent(control, LEAF).is_err() {
        let active_bytes =
            lineage_tag(read_sealed_leaf(control, LEAF), LineageGate::ColdActiveRead)?;
        let active = lineage_tag(parse_active(&active_bytes), LineageGate::ColdActiveShape)?;
        if let Some(sha) = active.predecessor_cold_intent_sha256 {
            // The archived cold intent belongs only to an idempotent seal of
            // this exact active generation. A later ordinary successor or
            // boot successor must select its own lineage, even while the old
            // active generation still carries cold ancestry.
            if !archived_lineage_is_current(
                &active.report,
                report,
                recovery_absent(control, SUCCESSOR_LEAF).is_err()
                    || recovery_absent(control, BOOT_SUCCESSOR_LEAF).is_err(),
            ) {
                return Ok(None);
            }
            let history = lineage_tag(history_dir(control, false), LineageGate::ColdHistory)?;
            let bytes = lineage_tag(
                read_archived(history.as_raw_fd(), "cold-intent", &sha),
                LineageGate::ColdArchivedIntent,
            )?;
            let intent: ColdFirstArmIntent = lineage_tag(
                serde_json::from_slice(&bytes).map_err(|_| refuse()),
                LineageGate::ColdIntentShape,
            )?;
            if lineage_bad(
                intent.schema != "aegis_auto_v2_cold_first_arm_intent_v1",
                LineageGate::ColdIntentShape,
            ) {
                return Err(refuse());
            }
            Some((bytes, intent))
        } else {
            None
        }
    } else {
        None
    };
    let Some((bytes, intent)) = pending else {
        return Ok(None);
    };
    for leaf in [
        SUCCESSOR_LEAF,
        BOOT_SUCCESSOR_LEAF,
        STOPPED_LEAF,
        "current.json",
    ] {
        lineage_tag(
            recovery_absent(control, leaf),
            LineageGate::ColdPendingExclusion,
        )?;
    }
    if lineage_bad(
        intent.current_boot_id != lineage_tag(current_boot_id(), LineageGate::ColdCurrentIdentity)?,
        LineageGate::ColdCurrentIdentity,
    ) || lineage_bad(
        report["terminal"]["boot_id"] != intent.current_boot_id,
        LineageGate::ColdCurrentIdentity,
    ) || lineage_bad(
        report["input"]["public_payload_root"] != intent.public_payload_root,
        LineageGate::ColdNewIdentity,
    ) || lineage_bad(
        report["input"]["candidate_binary"] != intent.candidate_binary,
        LineageGate::ColdNewIdentity,
    ) || lineage_bad(
        report["input"]["candidate_sha256"] != intent.candidate_sha256,
        LineageGate::ColdNewIdentity,
    ) || lineage_bad(
        intent.installer_sha256 != digest(include_bytes!("../../../install.sh")),
        LineageGate::ColdInstallerIdentity,
    ) {
        return Err(refuse());
    }
    let history = lineage_tag(history_dir(control, false), LineageGate::ColdHistory)?;
    let old = lineage_tag(
        read_archived(history.as_raw_fd(), "active", &intent.old_active_sha256),
        LineageGate::ColdOldActive,
    )?;
    let stopped = lineage_tag(
        read_archived(history.as_raw_fd(), "stopped", &intent.old_stopped_sha256),
        LineageGate::ColdOldStopped,
    )?;
    let parsed = lineage_tag(parse_active(&old), LineageGate::ColdOldActive)?;
    lineage_tag(
        parse_stopped(&stopped, &old, &parsed),
        LineageGate::ColdStoppedShape,
    )?;
    let successor = lineage_tag(
        read_archived(
            history.as_raw_fd(),
            "intent",
            &intent.successor_intent_sha256,
        ),
        LineageGate::ColdSuccessorIntent,
    )?;
    let predecessor: SuccessorIntent = lineage_tag(
        serde_json::from_slice(&successor).map_err(|_| refuse()),
        LineageGate::ColdSuccessorIntent,
    )?;
    if lineage_bad(
        predecessor.old_boot_id != intent.old_boot_id,
        LineageGate::ColdPredecessorIdentity,
    ) || lineage_bad(
        predecessor.next_candidate_sha256 != intent.candidate_sha256,
        LineageGate::ColdPredecessorIdentity,
    ) {
        return Err(refuse());
    }
    Ok(Some((bytes, intent)))
}

fn admitted_lineage(
    control: i32,
    report: &serde_json::Value,
) -> Result<(BootLineage, StoppedLineage, ColdLineage)> {
    lineage_tag(
        recovery_absent(control, RECOVERY_LEAF),
        LineageGate::RecoveryAbsent,
    )?;
    lineage_tag(
        recovery_absent(control, STOPPED_LEAF),
        LineageGate::StoppedAbsent,
    )?;
    let boot_successor = lineage_tag(
        boot_successor_for_new_report(control, report),
        LineageGate::BootSelection,
    )?;
    let cold_successor = lineage_tag(
        cold_successor_for_new_report(control, report),
        LineageGate::ColdSelection,
    )?;
    if lineage_bad(
        boot_successor.is_some() && cold_successor.is_some(),
        LineageGate::ColdPendingExclusion,
    ) {
        return Err(refuse());
    }
    let successor = if boot_successor.is_some() || cold_successor.is_some() {
        None
    } else if recovery_absent(control, SUCCESSOR_LEAF).is_err()
        || recovery_absent(control, LEAF).is_err() && history_dir(control, false).is_ok()
    {
        let (intent_bytes, intent) = if recovery_absent(control, SUCCESSOR_LEAF).is_err() {
            lineage_tag(read_intent(control), LineageGate::GenericIntentRead)?
        } else {
            let active_bytes = lineage_tag(
                read_sealed_leaf(control, LEAF),
                LineageGate::GenericActiveRead,
            )?;
            let existing =
                lineage_tag(parse_active(&active_bytes), LineageGate::GenericActiveShape)?;
            let sha = lineage_tag(
                existing.predecessor_intent_sha256.ok_or_else(refuse),
                LineageGate::GenericArchivedIntent,
            )?;
            let history = lineage_tag(history_dir(control, false), LineageGate::GenericHistory)?;
            let bytes = lineage_tag(
                read_archived(history.as_raw_fd(), "intent", &sha),
                LineageGate::GenericArchivedIntent,
            )?;
            let intent: SuccessorIntent = lineage_tag(
                serde_json::from_slice(&bytes).map_err(|_| refuse()),
                LineageGate::GenericIntentShape,
            )?;
            lineage_tag(successor_shape(&intent), LineageGate::GenericIntentShape)?;
            (bytes, intent)
        };
        let history = lineage_tag(history_dir(control, false), LineageGate::GenericHistory)?;
        let old_active = lineage_tag(
            read_archived(history.as_raw_fd(), "active", &intent.old_active_sha256),
            LineageGate::GenericOldActive,
        )?;
        let old_stopped = lineage_tag(
            read_archived(history.as_raw_fd(), "stopped", &intent.old_stopped_sha256),
            LineageGate::GenericOldStopped,
        )?;
        let parsed_active = lineage_tag(parse_active(&old_active), LineageGate::GenericOldActive)?;
        lineage_tag(
            successor_kind(&intent, &parsed_active.report),
            LineageGate::GenericSuccessorKind,
        )?;
        let parsed_stopped = lineage_tag(
            parse_stopped(&old_stopped, &old_active, &parsed_active),
            LineageGate::GenericStoppedShape,
        )?;
        if lineage_bad(
            parsed_stopped.report["stage"]["path"].as_str() != Some(intent.old_stage_path.as_str()),
            LineageGate::GenericOldIdentity,
        ) || lineage_bad(
            parsed_stopped.report["terminal"]["boot_id"].as_str()
                != Some(intent.old_boot_id.as_str()),
            LineageGate::GenericOldIdentity,
        ) || lineage_bad(
            report["terminal"]["boot_id"].as_str() != Some(intent.old_boot_id.as_str()),
            LineageGate::GenericNewIdentity,
        ) || lineage_bad(
            report["input"]["public_payload_root"].as_str()
                != Some(intent.next_public_payload_root.as_str()),
            LineageGate::GenericNewIdentity,
        ) || lineage_bad(
            report["input"]["candidate_binary"].as_str()
                != Some(intent.next_candidate_binary.as_str()),
            LineageGate::GenericNewIdentity,
        ) || lineage_bad(
            report["input"]["candidate_sha256"].as_str()
                != Some(intent.next_candidate_sha256.as_str()),
            LineageGate::GenericNewIdentity,
        ) || lineage_bad(
            intent.next_installer_sha256 != digest(include_bytes!("../../../install.sh")),
            LineageGate::GenericInstallerIdentity,
        ) {
            return Err(refuse());
        }
        let (actual_candidate, actual_installer) = lineage_tag(
            verified_retained_source(
                Path::new(&intent.next_public_payload_root),
                Path::new(&intent.next_candidate_binary),
            ),
            LineageGate::GenericRetainedSource,
        )?;
        if lineage_bad(
            actual_candidate != intent.next_candidate_sha256,
            LineageGate::GenericRetainedIdentity,
        ) || lineage_bad(
            actual_installer != intent.next_installer_sha256,
            LineageGate::GenericRetainedIdentity,
        ) {
            return Err(refuse());
        }
        Some((intent_bytes, intent))
    } else {
        // No caller-controlled flag can mint a fresh generation after any
        // stopped, recovery, successor or archived lineage exists.
        lineage_tag(
            recovery_absent(control, HISTORY_DIR),
            LineageGate::FreshHistoryAbsent,
        )?;
        lineage_tag(
            recovery_absent(control, BOOT_SUCCESSOR_LEAF),
            LineageGate::FreshBootIntentAbsent,
        )?;
        None
    };
    Ok((boot_successor, successor, cold_successor))
}

/// Called only with bytes returned by the active-finalized StageGuard inspector
/// while its original InstallLock remains held. An old seal is sticky: a new
/// generation requires a separate authenticated Stop/archive transition.
pub(super) fn seal_verified_report(
    report_bytes: &[u8],
    lock: &InstallLock,
    stage: &super::authority::StageGuard,
) -> Result<()> {
    let (report, canonical, control) = (|| {
        lock.revalidate().map_err(|_| refuse())?;
        if report_bytes.is_empty() || report_bytes.len() > MAX_REPORT {
            return Err(refuse());
        }
        let report: serde_json::Value =
            serde_json::from_slice(report_bytes).map_err(|_| refuse())?;
        report_shape(&report)
            .inspect_err(|_| eprintln!("AUTO_GENERATION_SEAL_DIAGNOSTIC phase=report_shape"))?;
        let canonical = serde_json::to_vec(&report).map_err(|_| refuse())?;
        let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
        Ok((report, canonical, control))
    })()
    .inspect_err(|_| eprintln!("AUTO_GENERATION_SEAL_DIAGNOSTIC phase=report_admission"))?;
    let (boot_successor, successor, cold_successor) =
        admitted_lineage(control.as_raw_fd(), &report)
            .inspect_err(|_| eprintln!("AUTO_GENERATION_SEAL_DIAGNOSTIC phase=control_lineage"))?;
    #[expect(
        clippy::manual_inspect,
        reason = "Preserve the existing boot_snapshot error mapping in this bounded repair"
    )]
    let boot_snapshot_sha = super::installer_v2_boot::capture_and_seal_current(
        &report, lock, stage,
    )
    .map_err(|error| {
        eprintln!("AUTO_GENERATION_SEAL_DIAGNOSTIC phase=boot_snapshot");
        error
    })?;
    (|| {
        if !exact_hex(&boot_snapshot_sha) {
            return Err(refuse());
        }
        let seal = GenerationSeal {
            schema: "aegis_auto_v2_generation_v1".into(),
            report_sha256: digest(&canonical),
            boot_snapshot_sha256: Some(boot_snapshot_sha),
            predecessor_intent_sha256: successor.as_ref().map(|(bytes, _)| digest(bytes)),
            predecessor_boot_intent_sha256: boot_successor.as_ref().map(|(bytes, _)| digest(bytes)),
            predecessor_cold_intent_sha256: cold_successor.as_ref().map(|(bytes, _)| digest(bytes)),
            report,
        };
        let bytes = serde_json::to_vec(&seal).map_err(|_| refuse())?;
        if bytes.len() > MAX_SEAL {
            return Err(refuse());
        }
        if recovery_absent(control.as_raw_fd(), LEAF).is_err() {
            if read_sealed_leaf(control.as_raw_fd(), LEAF)? != bytes {
                return Err(refuse());
            }
        } else {
            lock.revalidate().map_err(|_| refuse())?;
            let raw = recovery_open_at(
                control.as_raw_fd(),
                LEAF,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            let mut file = std::fs::File::from(raw);
            file.write_all(&bytes).map_err(|_| refuse())?;
            file.sync_all().map_err(|_| refuse())?;
            if unsafe { libc::fsync(control.as_raw_fd()) } != 0 {
                return Err(refuse());
            }
            let actual = recovery_open_at(control.as_raw_fd(), LEAF, libc::O_RDONLY, 0)?;
            let stat = recovery_stat(actual.as_raw_fd())?;
            if stat.st_mode != libc::S_IFREG | 0o600
                || stat.st_uid != 0
                || stat.st_gid != 0
                || stat.st_nlink != 1
                || stat.st_size != bytes.len() as i64
            {
                return Err(refuse());
            }
            let mut reopened = Vec::new();
            std::fs::File::from(actual)
                .take((MAX_SEAL + 1) as u64)
                .read_to_end(&mut reopened)
                .map_err(|_| refuse())?;
            if reopened != bytes {
                return Err(refuse());
            }
        }
        Ok(())
    })()
    .inspect_err(|_| eprintln!("AUTO_GENERATION_SEAL_DIAGNOSTIC phase=seal_leaf"))?;
    (|| {
        if let Some((intent_bytes, _)) = successor {
            let history = history_dir(control.as_raw_fd(), false)?;
            archive_exact(
                history.as_raw_fd(),
                "intent",
                &digest(&intent_bytes),
                &intent_bytes,
            )?;
            if recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF).is_err() {
                retire_exact(control.as_raw_fd(), SUCCESSOR_LEAF, &intent_bytes)?;
            }
        }
        if let Some((intent_bytes, _)) = boot_successor {
            let history = history_dir(control.as_raw_fd(), false)?;
            archive_exact(
                history.as_raw_fd(),
                "boot-intent",
                &digest(&intent_bytes),
                &intent_bytes,
            )?;
            if recovery_absent(control.as_raw_fd(), BOOT_SUCCESSOR_LEAF).is_err() {
                retire_exact(control.as_raw_fd(), BOOT_SUCCESSOR_LEAF, &intent_bytes)?;
            }
        }
        if let Some((intent_bytes, _)) = cold_successor {
            let history = history_dir(control.as_raw_fd(), false)?;
            archive_exact(
                history.as_raw_fd(),
                "cold-intent",
                &digest(&intent_bytes),
                &intent_bytes,
            )?;
            if recovery_absent(control.as_raw_fd(), COLD_FIRST_ARM_LEAF).is_err() {
                retire_exact(control.as_raw_fd(), COLD_FIRST_ARM_LEAF, &intent_bytes)?;
            }
        }
        lock.revalidate().map_err(|_| refuse())?;
        Ok(())
    })()
    .inspect_err(|_| eprintln!("AUTO_GENERATION_SEAL_DIAGNOSTIC phase=lineage_retire"))
}

/// Historical readback only. The caller must establish a fresh boot's guard,
/// host assessment, source, fixed unit and new StageGuard separately.
#[allow(dead_code)] // Reserved for the separately gated fresh-boot coordinator.
pub(super) fn read_history() -> Result<GenerationSeal> {
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    read_history_at(&control)
}

fn read_history_at(control: &impl std::os::fd::AsRawFd) -> Result<GenerationSeal> {
    let raw = recovery_open_at(control.as_raw_fd(), LEAF, libc::O_RDONLY, 0)?;
    let stat = recovery_stat(raw.as_raw_fd())?;
    if stat.st_mode != libc::S_IFREG | 0o600
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size as usize > MAX_SEAL
    {
        return Err(refuse());
    }
    let mut bytes = Vec::new();
    let mut file = std::fs::File::from(raw);
    Read::by_ref(&mut file)
        .take((MAX_SEAL + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    let after = recovery_stat(file.as_raw_fd())?;
    let again = recovery_open_at(control.as_raw_fd(), LEAF, libc::O_RDONLY, 0)?;
    let named = recovery_stat(again.as_raw_fd())?;
    let same = |item: &libc::stat| {
        (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_gid,
            item.st_nlink,
            item.st_size,
            item.st_mtime,
            item.st_mtime_nsec,
            item.st_ctime,
            item.st_ctime_nsec,
        ) == (
            stat.st_dev,
            stat.st_ino,
            stat.st_mode,
            stat.st_uid,
            stat.st_gid,
            stat.st_nlink,
            stat.st_size,
            stat.st_mtime,
            stat.st_mtime_nsec,
            stat.st_ctime,
            stat.st_ctime_nsec,
        )
    };
    if bytes.len() != stat.st_size as usize || !same(&after) || !same(&named) {
        return Err(refuse());
    }
    let seal: GenerationSeal = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    if seal.schema != "aegis_auto_v2_generation_v1" || !exact_hex(&seal.report_sha256) {
        return Err(refuse());
    }
    if seal
        .boot_snapshot_sha256
        .as_deref()
        .is_some_and(|v| !exact_hex(v))
    {
        return Err(refuse());
    }
    report_shape(&seal.report)?;
    let canonical = serde_json::to_vec(&seal.report).map_err(|_| refuse())?;
    if digest(&canonical) != seal.report_sha256 {
        return Err(refuse());
    }
    if let Some(intent_sha) = seal.predecessor_intent_sha256.as_deref() {
        if !exact_hex(intent_sha) {
            return Err(refuse());
        }
        let history = history_dir(control.as_raw_fd(), false)?;
        let intent_bytes = read_archived(history.as_raw_fd(), "intent", intent_sha)?;
        let intent: SuccessorIntent =
            serde_json::from_slice(&intent_bytes).map_err(|_| refuse())?;
        successor_shape(&intent)?;
        let old_prior = read_archived(history.as_raw_fd(), "active", &intent.old_active_sha256)?;
        successor_kind(&intent, &parse_active(&old_prior)?.report)?;
        if seal.report["input"]["public_payload_root"].as_str()
            != Some(intent.next_public_payload_root.as_str())
            || seal.report["input"]["candidate_binary"].as_str()
                != Some(intent.next_candidate_binary.as_str())
            || seal.report["input"]["candidate_sha256"].as_str()
                != Some(intent.next_candidate_sha256.as_str())
            || read_archived(history.as_raw_fd(), "active", &intent.old_active_sha256).is_err()
            || read_archived(history.as_raw_fd(), "stopped", &intent.old_stopped_sha256).is_err()
        {
            return Err(refuse());
        }
    }
    if let Some(intent_sha) = seal.predecessor_boot_intent_sha256.as_deref() {
        if seal.predecessor_intent_sha256.is_some() || !exact_hex(intent_sha) {
            return Err(refuse());
        }
        let history = history_dir(control.as_raw_fd(), false)?;
        let intent_bytes = read_archived(history.as_raw_fd(), "boot-intent", intent_sha)?;
        let intent: BootSuccessorIntent =
            serde_json::from_slice(&intent_bytes).map_err(|_| refuse())?;
        boot_successor_shape(&intent)?;
        let old = parse_active(&read_archived(
            history.as_raw_fd(),
            "active",
            &intent.old_active_sha256,
        )?)?;
        let old_raw = read_archived(history.as_raw_fd(), "active", &intent.old_active_sha256)?;
        let proof_raw = read_archived(
            history.as_raw_fd(),
            "boot-proof",
            &intent.verified_boot_sha256,
        )?;
        let proof: serde_json::Value = serde_json::from_slice(&proof_raw).map_err(|_| refuse())?;
        boot_proof_shape(&old.report, &proof)?;
        if old.boot_snapshot_sha256.as_deref() != Some(intent.old_snapshot_sha256.as_str())
            || seal.report["terminal"]["boot_id"].as_str() != Some(intent.new_boot_id.as_str())
            || seal.report["input"]["public_payload_root"].as_str()
                != Some(intent.public_payload_root.as_str())
            || seal.report["input"]["candidate_binary"].as_str()
                != Some(intent.candidate_binary.as_str())
            || seal.report["input"]["candidate_sha256"].as_str()
                != Some(intent.candidate_sha256.as_str())
            || read_archived(history.as_raw_fd(), "snapshot", &intent.old_snapshot_sha256).is_err()
            || read_archived(
                history.as_raw_fd(),
                "boot-pointer",
                &intent.old_pointer_sha256,
            )
            .is_err()
        {
            return Err(refuse());
        }
        // A sealed historical generation may be inspected on a later boot.
        // The committed new report and archived intent bind this pointer;
        // read_history itself is never a live-boot activation grant.
        let authorized_current = validated_current_pointer_for_report(
            control.as_raw_fd(),
            &seal.report,
            &intent.new_boot_id,
            false,
        )?;
        let stopped = boot_stopped_with_authorized_current(
            control.as_raw_fd(),
            &old_raw,
            &old,
            intent.old_stopped_sha256.as_deref(),
            intent.old_pointer_receipt_sha256.as_deref(),
            authorized_current.as_deref(),
        )?;
        if stopped.is_some() != intent.old_stopped_sha256.is_some()
            || stopped
                .as_ref()
                .is_some_and(|(_, sha)| sha != &intent.old_pointer_sha256)
        {
            return Err(refuse());
        }
    }
    Ok(seal)
}

/// The seal supplies an address only; the caller must inspect the live stage
/// and PID1 under its own InstallLock before accepting this identity.
pub(super) fn current_active_report_address() -> Result<serde_json::Value> {
    Ok(read_history()?.report)
}

/// Strictly reopened historical report for a same-boot stopped inspector.
/// The caller must still prove fresh PID1, deny policy, fixed namespace and
/// current published roots under its separately held InstallLock.
pub(super) fn history_report() -> Result<serde_json::Value> {
    Ok(read_history()?.report)
}

/// A boot coordinator may read the old generation only with a sealed boot
/// capsule. The capsule itself is separately reopened and remeasured under
/// the boot coordinator's held InstallLock; old history grants no lease.
pub(super) fn boot_history() -> Result<(serde_json::Value, String)> {
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), RECOVERY_LEAF)?;
    recovery_absent(control.as_raw_fd(), SUCCESSOR_LEAF)?;
    let seal = if recovery_absent(control.as_raw_fd(), BOOT_SUCCESSOR_LEAF).is_ok() {
        let active = read_history()?;
        let active_bytes = read_sealed_leaf(control.as_raw_fd(), LEAF)?;
        if parse_active(&active_bytes)?.report != active.report {
            return Err(refuse());
        }
        if boot_stopped(control.as_raw_fd(), &active_bytes, &active, None, None)?.is_none() {
            boot_pointer(control.as_raw_fd(), &active.report, None)?;
        }
        active
    } else {
        let (_, intent) = read_boot_intent(control.as_raw_fd())?;
        let history = history_dir(control.as_raw_fd(), false).ok();
        let fixed = read_sealed_leaf(control.as_raw_fd(), LEAF);
        let archived = history
            .as_ref()
            .ok_or_else(refuse)
            .and_then(|dir| read_archived(dir.as_raw_fd(), "active", &intent.old_active_sha256));
        let bytes = match (fixed, archived) {
            (Ok(a), Ok(b)) if a == b && digest(&a) == intent.old_active_sha256 => a,
            (Ok(a), Err(_)) if digest(&a) == intent.old_active_sha256 => a,
            (Err(_), Ok(b)) if digest(&b) == intent.old_active_sha256 => b,
            _ => return Err(refuse()),
        };
        let old = parse_active(&bytes)?;
        if old.boot_snapshot_sha256.as_deref() != Some(intent.old_snapshot_sha256.as_str())
            || old.report["terminal"]["boot_id"].as_str() != Some(intent.old_boot_id.as_str())
            || old.report["input"]["public_payload_root"].as_str()
                != Some(intent.public_payload_root.as_str())
            || old.report["input"]["candidate_binary"].as_str()
                != Some(intent.candidate_binary.as_str())
            || old.report["input"]["candidate_sha256"].as_str()
                != Some(intent.candidate_sha256.as_str())
            || (history.as_ref().is_some_and(|dir| {
                recovery_absent(
                    dir.as_raw_fd(),
                    &archived_name("snapshot", &intent.old_snapshot_sha256).unwrap_or_default(),
                )
                .is_err()
            }) && history.as_ref().ok_or_else(refuse).and_then(|dir| {
                read_archived(dir.as_raw_fd(), "snapshot", &intent.old_snapshot_sha256)
            })? != super::installer_v2_boot::reopen_snapshot_bytes(
                &intent.old_snapshot_sha256,
            )?)
        {
            return Err(refuse());
        }
        let stopped = boot_stopped(
            control.as_raw_fd(),
            &bytes,
            &old,
            intent.old_stopped_sha256.as_deref(),
            intent.old_pointer_receipt_sha256.as_deref(),
        )?;
        if (stopped.is_some()) != (intent.old_stopped_sha256.is_some()) {
            return Err(refuse());
        }
        if let Some((_, pointer_sha)) = stopped {
            if pointer_sha != intent.old_pointer_sha256 {
                return Err(refuse());
            }
        }
        let pointer = boot_pointer(
            control.as_raw_fd(),
            &old.report,
            Some(&intent.old_pointer_sha256),
        )?;
        if digest(&pointer) != intent.old_pointer_sha256 {
            return Err(refuse());
        }
        old
    };
    let sha = seal.boot_snapshot_sha256.ok_or_else(refuse)?;
    if !exact_hex(&sha) {
        return Err(refuse());
    }
    Ok((seal.report, sha))
}

/// Uninstall-only old-boot reader. A crash may leave a stopped seal before
/// the pointer receipt, or a fsynced receipt before pointer unlink. Neither
/// state is activation authority. The caller must still perform the fresh
/// boot snapshot, PID1, fixed namespace and deny observations.
pub(super) fn boot_history_for_uninstall() -> Result<(serde_json::Value, String)> {
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    for leaf in [RECOVERY_LEAF, SUCCESSOR_LEAF, BOOT_SUCCESSOR_LEAF] {
        recovery_absent(control.as_raw_fd(), leaf)?;
    }
    let active = read_history()?;
    let active_bytes = read_sealed_leaf(control.as_raw_fd(), LEAF)?;
    if parse_active(&active_bytes)?.report != active.report {
        return Err(refuse());
    }
    let stopped = match read_sealed_leaf(control.as_raw_fd(), STOPPED_LEAF) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            recovery_absent(control.as_raw_fd(), STOPPED_LEAF)?;
            None
        }
    };
    let receipt = match read_sealed_leaf(control.as_raw_fd(), "generation-pointer-stopped.json") {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            recovery_absent(control.as_raw_fd(), "generation-pointer-stopped.json")?;
            None
        }
    };
    match (stopped, receipt) {
        (None, None) => {
            boot_pointer(control.as_raw_fd(), &active.report, None)?;
        }
        (Some(stopped), None) => {
            parse_stopped(&stopped, &active_bytes, &active)?;
            boot_pointer(control.as_raw_fd(), &active.report, None)?;
        }
        (Some(stopped), Some(receipt)) => {
            let stopped = parse_stopped(&stopped, &active_bytes, &active)?;
            let checked = stopped_pointer_receipt(
                control.as_raw_fd(),
                &stopped.report,
                Some(&digest(&receipt)),
            )?;
            if checked != receipt {
                return Err(refuse());
            }
            let value: serde_json::Value =
                serde_json::from_slice(&receipt).map_err(|_| refuse())?;
            let pointer_sha = value["pointer_sha256"].as_str().ok_or_else(refuse)?;
            boot_pointer(control.as_raw_fd(), &active.report, Some(pointer_sha))?;
        }
        (None, Some(_)) => return Err(refuse()),
    }
    let snapshot_sha = active.boot_snapshot_sha256.ok_or_else(refuse)?;
    if !exact_hex(&snapshot_sha) {
        return Err(refuse());
    }
    Ok((active.report, snapshot_sha))
}

/// Strict historical stopped record. It is only a source-bound old-boot fact;
/// the caller must inspect the current deny, PID1, namespace and publications.
pub(super) fn stopped_history_report() -> Result<serde_json::Value> {
    let active = read_history()?;
    let active_bytes = serde_json::to_vec(&active).map_err(|_| refuse())?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let raw = recovery_open_at(control.as_raw_fd(), STOPPED_LEAF, libc::O_RDONLY, 0)?;
    let stat = recovery_stat(raw.as_raw_fd())?;
    if stat.st_mode != libc::S_IFREG | 0o600
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size as usize > MAX_SEAL
    {
        return Err(refuse());
    }
    let mut bytes = Vec::new();
    let mut file = std::fs::File::from(raw);
    Read::by_ref(&mut file)
        .take((MAX_SEAL + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    let after = recovery_stat(file.as_raw_fd())?;
    let named = recovery_open_at(control.as_raw_fd(), STOPPED_LEAF, libc::O_RDONLY, 0)?;
    let current = recovery_stat(named.as_raw_fd())?;
    let same = |value: &libc::stat| {
        (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_size,
            value.st_mtime,
            value.st_mtime_nsec,
            value.st_ctime,
            value.st_ctime_nsec,
        ) == (
            stat.st_dev,
            stat.st_ino,
            stat.st_mode,
            stat.st_uid,
            stat.st_gid,
            stat.st_nlink,
            stat.st_size,
            stat.st_mtime,
            stat.st_mtime_nsec,
            stat.st_ctime,
            stat.st_ctime_nsec,
        )
    };
    if bytes.len() != stat.st_size as usize || !same(&after) || !same(&current) {
        return Err(refuse());
    }
    let stopped: StoppedGenerationSeal = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    if stopped.schema != "aegis_auto_v2_stopped_generation_v1"
        || !exact_hex(&stopped.active_seal_sha256)
        || !exact_hex(&stopped.stopped_report_sha256)
        || stopped.active_seal_sha256 != digest(&active_bytes)
    {
        return Err(refuse());
    }
    let canonical = serde_json::to_vec(&stopped.report).map_err(|_| refuse())?;
    if stopped.stopped_report_sha256 != digest(&canonical)
        || stopped.report["schema"] != "aegis_auto_v2_stopped_stage_inspection_v1"
        || stopped.report["terminal"]["outcome"] != "finalized-stopped"
        || stopped.report["stage"]["path"] != active.report["stage"]["path"]
        || stopped.report["stage"]["device"] != active.report["stage"]["device"]
        || stopped.report["stage"]["inode"] != active.report["stage"]["inode"]
        || stopped.report["terminal"]["start_terminal_sha256"]
            != active.report["terminal"]["start_terminal_sha256"]
        || stopped.report["terminal"]["boot_id"] != active.report["terminal"]["boot_id"]
        || stopped.report["input"] != active.report["input"]
    {
        return Err(refuse());
    }
    Ok(stopped.report)
}

/// Recovery-only history for a stage that really stopped after Finalize, but
/// whose active-generation seal never completed. It cannot authorize boot or
/// a new active generation. The caller must prove fresh current facts again.
pub(super) fn validate_unsealed_stopped_recovery_bytes(bytes: &[u8]) -> Result<serde_json::Value> {
    let seal: UnsealedStoppedRecoverySeal = serde_json::from_slice(bytes).map_err(|_| refuse())?;
    if seal.schema != "aegis_auto_v2_unsealed_stopped_recovery_v1"
        || seal.active_seal_present
        || !exact_hex(&seal.report_sha256)
    {
        return Err(refuse());
    }
    unsealed_stopped_shape(&seal.report)?;
    let canonical = serde_json::to_vec(&seal.report).map_err(|_| refuse())?;
    if digest(&canonical) != seal.report_sha256
        || serde_json::to_vec(&seal).map_err(|_| refuse())? != bytes
    {
        return Err(refuse());
    }
    Ok(seal.report)
}

pub(super) fn archive_passive_unsealed_recovery(bytes: &[u8]) -> Result<()> {
    validate_unsealed_stopped_recovery_bytes(bytes)?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let history = history_dir(control.as_raw_fd(), true)?;
    archive_exact(
        history.as_raw_fd(),
        "passive-unsealed-recovery",
        &digest(bytes),
        bytes,
    )
}

pub(super) fn read_passive_unsealed_recovery_archive(sha: &str) -> Result<Vec<u8>> {
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let history = history_dir(control.as_raw_fd(), false)?;
    let bytes = read_archived(history.as_raw_fd(), "passive-unsealed-recovery", sha)?;
    validate_unsealed_stopped_recovery_bytes(&bytes)?;
    Ok(bytes)
}

pub(super) fn read_current_unsealed_recovery_bytes() -> Result<Vec<u8>> {
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let bytes = read_sealed_leaf(control.as_raw_fd(), RECOVERY_LEAF)?;
    validate_unsealed_stopped_recovery_bytes(&bytes)?;
    Ok(bytes)
}

pub(super) fn retire_current_unsealed_recovery_bytes(bytes: &[u8]) -> Result<()> {
    validate_unsealed_stopped_recovery_bytes(bytes)?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    retire_exact(control.as_raw_fd(), RECOVERY_LEAF, bytes)
}

pub(super) fn unsealed_stopped_recovery_report() -> Result<serde_json::Value> {
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), LEAF)?;
    recovery_absent(control.as_raw_fd(), STOPPED_LEAF)?;
    let raw = recovery_open_at(control.as_raw_fd(), RECOVERY_LEAF, libc::O_RDONLY, 0)?;
    let before = recovery_stat(raw.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o600
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as usize > MAX_SEAL
    {
        return Err(refuse());
    }
    let mut bytes = Vec::new();
    let mut file = std::fs::File::from(raw);
    Read::by_ref(&mut file)
        .take((MAX_SEAL + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    let after = recovery_stat(file.as_raw_fd())?;
    let named = recovery_open_at(control.as_raw_fd(), RECOVERY_LEAF, libc::O_RDONLY, 0)?;
    let current = recovery_stat(named.as_raw_fd())?;
    let identity = |value: &libc::stat| {
        (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_size,
            value.st_mtime,
            value.st_mtime_nsec,
            value.st_ctime,
            value.st_ctime_nsec,
        )
    };
    if bytes.len() != before.st_size as usize
        || identity(&before) != identity(&after)
        || identity(&before) != identity(&current)
    {
        return Err(refuse());
    }
    let report = validate_unsealed_stopped_recovery_bytes(&bytes)?;
    recovery_absent(control.as_raw_fd(), LEAF)?;
    recovery_absent(control.as_raw_fd(), STOPPED_LEAF)?;
    Ok(report)
}

/// The stopped observer must retain its StageGuard, guard lease and same
/// InstallLock through this call. Mere JSON shape never substitutes for its
/// typed Start/Stop and fresh PID1/deny observations.
pub(super) fn seal_unsealed_stopped_report(report_bytes: &[u8], lock: &InstallLock) -> Result<()> {
    lock.revalidate().map_err(|_| refuse())?;
    if report_bytes.is_empty() || report_bytes.len() > MAX_REPORT {
        return Err(refuse());
    }
    let report: serde_json::Value = serde_json::from_slice(report_bytes).map_err(|_| refuse())?;
    unsealed_stopped_shape(&report)?;
    let canonical = serde_json::to_vec(&report).map_err(|_| refuse())?;
    let seal = UnsealedStoppedRecoverySeal {
        schema: "aegis_auto_v2_unsealed_stopped_recovery_v1".into(),
        active_seal_present: false,
        report_sha256: digest(&canonical),
        report,
    };
    let bytes = serde_json::to_vec(&seal).map_err(|_| refuse())?;
    if bytes.len() > MAX_SEAL {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), LEAF)?;
    recovery_absent(control.as_raw_fd(), STOPPED_LEAF)?;
    if recovery_absent(control.as_raw_fd(), RECOVERY_LEAF).is_err() {
        let existing = unsealed_stopped_recovery_report()?;
        if serde_json::to_vec(&existing).map_err(|_| refuse())? != canonical {
            return Err(refuse());
        }
        lock.revalidate().map_err(|_| refuse())?;
        return Ok(());
    }
    lock.revalidate().map_err(|_| refuse())?;
    let raw = recovery_open_at(
        control.as_raw_fd(),
        RECOVERY_LEAF,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let mut file = std::fs::File::from(raw);
    file.write_all(&bytes).map_err(|_| refuse())?;
    file.sync_all().map_err(|_| refuse())?;
    if unsafe { libc::fsync(control.as_raw_fd()) } != 0 {
        return Err(refuse());
    }
    let checked = unsealed_stopped_recovery_report()?;
    if serde_json::to_vec(&checked).map_err(|_| refuse())? != canonical {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    Ok(())
}

/// A stopped report is produced only from a separate authenticated Stop
/// inspector while it retains the same InstallLock. It records old-boot
/// history; it never grants a new boot a Main lease or guard permission.
#[allow(dead_code)] // Wired by the separate typed stopped-stage inspector.
pub(super) fn archive_verified_stopped_report(
    report_bytes: &[u8],
    lock: &InstallLock,
) -> Result<()> {
    lock.revalidate().map_err(|_| refuse())?;
    if report_bytes.is_empty() || report_bytes.len() > MAX_REPORT {
        return Err(refuse());
    }
    let report: serde_json::Value = serde_json::from_slice(report_bytes).map_err(|_| refuse())?;
    let keys = report.as_object().ok_or_else(refuse)?;
    if keys.len() != 8
        || [
            "schema",
            "stage",
            "terminal",
            "published_paths",
            "current_fixed",
            "input",
            "main",
            "guardian",
        ]
        .iter()
        .any(|key| !keys.contains_key(*key))
        || report["schema"] != "aegis_auto_v2_stopped_stage_inspection_v1"
        || report["stage"]["phase"] != "finalized"
        || report["terminal"]["outcome"] != "finalized-stopped"
        || report["published_paths"]["current_verified"] != true
        || report["main"]["stopped_verified"] != true
        || report["main"]["no_live_lease_verified"] != true
        || report["guardian"]["deny_verified"] != true
        || report["guardian"]["fdstore_empty_verified"] != true
        || [
            "stop_submitted_sha256",
            "stop_completed_sha256",
            "stop_terminal_sha256",
        ]
        .iter()
        .any(|key| !report["terminal"][key].as_str().is_some_and(exact_hex))
    {
        return Err(refuse());
    }
    let active = read_history()?;
    let passive = active.report["stage"]["mode"] == "socks-only";
    if !(if passive {
        report["guardian"]["prior_manager_binding_sha256"].is_null()
            && report["guardian"]["manager_binding_sha256"].is_null()
    } else {
        report["guardian"]["prior_manager_binding_sha256"]
            .as_str()
            .is_some_and(exact_hex)
            && report["guardian"]["manager_binding_sha256"]
                .as_str()
                .is_some_and(exact_hex)
    }) {
        return Err(refuse());
    }
    for key in ["path", "device", "inode"] {
        if report["stage"][key] != active.report["stage"][key] {
            return Err(refuse());
        }
    }
    for key in ["start_terminal_sha256", "boot_id"] {
        if report["terminal"][key] != active.report["terminal"][key] {
            return Err(refuse());
        }
    }
    if report["input"] != active.report["input"]
        || report["current_fixed"] != active.report["current_fixed"]
        || report["published_paths"]["current_publications"]
            != active.report["published_paths"]["current_publications"]
        || report["guardian"]["prior_manager_binding_sha256"]
            != active.report["guardian"]["manager_binding_sha256"]
    {
        return Err(refuse());
    }
    let active_bytes = serde_json::to_vec(&active).map_err(|_| refuse())?;
    let canonical = serde_json::to_vec(&report).map_err(|_| refuse())?;
    let stopped = StoppedGenerationSeal {
        schema: "aegis_auto_v2_stopped_generation_v1".into(),
        active_seal_sha256: digest(&active_bytes),
        stopped_report_sha256: digest(&canonical),
        report,
    };
    let bytes = serde_json::to_vec(&stopped).map_err(|_| refuse())?;
    if bytes.len() > MAX_SEAL {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), RECOVERY_LEAF)?;
    if recovery_absent(control.as_raw_fd(), STOPPED_LEAF).is_err() {
        // A crash after the durable seal but before the Python pointer
        // archival may retry. Reopen the exact previously authenticated
        // record and accept only a byte-identical canonical projection.
        let existing = stopped_history_report()?;
        if serde_json::to_vec(&existing).map_err(|_| refuse())? != canonical {
            return Err(refuse());
        }
        lock.revalidate().map_err(|_| refuse())?;
        return Ok(());
    }
    lock.revalidate().map_err(|_| refuse())?;
    let raw = recovery_open_at(
        control.as_raw_fd(),
        STOPPED_LEAF,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let mut file = std::fs::File::from(raw);
    file.write_all(&bytes).map_err(|_| refuse())?;
    file.sync_all().map_err(|_| refuse())?;
    if unsafe { libc::fsync(control.as_raw_fd()) } != 0 {
        return Err(refuse());
    }
    let reopened = recovery_open_at(control.as_raw_fd(), STOPPED_LEAF, libc::O_RDONLY, 0)?;
    let stat = recovery_stat(reopened.as_raw_fd())?;
    if stat.st_mode != libc::S_IFREG | 0o600
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_size != bytes.len() as i64
    {
        return Err(refuse());
    }
    let mut checked = Vec::new();
    std::fs::File::from(reopened)
        .take((MAX_SEAL + 1) as u64)
        .read_to_end(&mut checked)
        .map_err(|_| refuse())?;
    if checked != bytes {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_archive_target_requires_exact_sealed_successor_candidate() {
        let mut intent = SuccessorIntent {
            schema: "aegis_auto_v2_stopped_successor_v1".into(),
            kind: "upgrade".into(),
            old_active_sha256: "a".repeat(64),
            old_stopped_sha256: "b".repeat(64),
            old_pointer_receipt_sha256: "c".repeat(64),
            old_stage_path: "/run/aegis-installer-config-snapshots/old".into(),
            old_boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            next_public_payload_root: "/var/lib/aegis-auto/releases/next".into(),
            next_candidate_binary: "/var/lib/aegis-auto/releases/next/bin/aegis-client".into(),
            next_candidate_sha256: COLD_A2_CANDIDATE_SHA256.into(),
            next_installer_sha256: "d".repeat(64),
            next_bundle_manifest_sha256: None,
            next_sums_sha256: None,
        };
        for candidate in [COLD_A2_CANDIDATE_SHA256, COLD_A3_CANDIDATE_SHA256] {
            intent.next_candidate_sha256 = candidate.into();
            let wire = serde_json::to_vec(&intent).unwrap();
            let target = cold_archive_target_from_intent(&wire).unwrap();
            assert_eq!(target.public_root, intent.next_public_payload_root);
            assert_eq!(target.candidate_sha256, candidate);
        }
        intent.next_candidate_sha256 = "e".repeat(64);
        assert!(cold_archive_target_from_intent(&serde_json::to_vec(&intent).unwrap()).is_err());
        intent.next_candidate_sha256 = COLD_A3_CANDIDATE_SHA256.into();
        intent.next_candidate_binary =
            "/var/lib/aegis-auto/releases/foreign/bin/aegis-client".into();
        assert!(cold_archive_target_from_intent(&serde_json::to_vec(&intent).unwrap()).is_err());
        assert!(cold_archive_target_from_intent(br#"{"schema":"incomplete"}"#).is_err());
    }

    #[test]
    fn archived_cold_and_boot_lineage_only_reseal_the_same_generation() {
        let active = serde_json::json!({
            "stage": {"path": "/run/aegis-installer-config-snapshots/old"},
            "terminal": {"boot_id": "01234567-89ab-cdef-0123-456789abcdef"},
            "input": {"candidate_sha256": "a".repeat(64)},
        });
        let next_stage = serde_json::json!({
            "stage": {"path": "/run/aegis-installer-config-snapshots/new"},
            "terminal": {"boot_id": "01234567-89ab-cdef-0123-456789abcdef"},
            "input": {"candidate_sha256": "b".repeat(64)},
        });
        let next_boot = serde_json::json!({
            "stage": {"path": "/run/aegis-installer-config-snapshots/new"},
            "terminal": {"boot_id": "11234567-89ab-cdef-0123-456789abcdef"},
            "input": {"candidate_sha256": "a".repeat(64)},
        });
        assert!(archived_lineage_is_current(&active, &active, false));
        assert!(!archived_lineage_is_current(&active, &active, true));
        assert!(!archived_lineage_is_current(&active, &next_stage, false));
        assert!(!archived_lineage_is_current(&active, &next_boot, false));
    }

    #[test]
    #[ignore = "requires disposable Linux root filesystem"]
    fn optional_archive_refuses_present_malformed_evidence() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{symlink, PermissionsExt};
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            std::env::var("AEGIS_SUCCESSOR_ARCHIVE_TEST_DISPOSABLE").as_deref(),
            Ok("1")
        );
        let dir = std::env::temp_dir().join(format!(
            "aegis-optional-archive-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = std::fs::File::open(&dir).unwrap();
        let fd = held.as_raw_fd();
        let archive_bytes = b"sealed optional archive";
        let sha = digest(archive_bytes);
        let archive = archived_name("passive-cold-prior-active", &sha).unwrap();
        let archive_path = dir.join(&archive);
        write_passive_atomic(fd, LEAF, b"valid live fallback", MAX_SEAL).unwrap();

        // Only a named absence may select the live predecessor.
        assert!(
            read_archived_optional(fd, "passive-cold-prior-active", &sha)
                .unwrap()
                .is_none()
        );
        assert_eq!(read_sealed_leaf(fd, LEAF).unwrap(), b"valid live fallback");

        std::fs::write(&archive_path, archive_bytes).unwrap();
        std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_archived_optional(fd, "passive-cold-prior-active", &sha)
                .unwrap()
                .unwrap(),
            archive_bytes
        );
        std::fs::write(&archive_path, b"wrong sealed bytes").unwrap();
        assert!(read_archived_optional(fd, "passive-cold-prior-active", &sha).is_err());
        assert_eq!(read_sealed_leaf(fd, LEAF).unwrap(), b"valid live fallback");

        std::fs::write(&archive_path, archive_bytes).unwrap();
        std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_archived_optional(fd, "passive-cold-prior-active", &sha).is_err());

        std::fs::remove_file(&archive_path).unwrap();
        symlink(dir.join(LEAF), &archive_path).unwrap();
        assert!(read_archived_optional(fd, "passive-cold-prior-active", &sha).is_err());
        assert_eq!(read_sealed_leaf(fd, LEAF).unwrap(), b"valid live fallback");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "requires disposable Linux root filesystem"]
    fn later_successor_does_not_select_archived_boot_ancestry() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            std::env::var("AEGIS_SUCCESSOR_ARCHIVE_TEST_DISPOSABLE").as_deref(),
            Ok("1")
        );
        let dir = std::env::temp_dir().join(format!(
            "aegis-boot-ancestry-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = std::fs::File::open(&dir).unwrap();
        let fd = held.as_raw_fd();
        let report = active_report();
        let active = GenerationSeal {
            schema: "aegis_auto_v2_generation_v1".into(),
            report_sha256: digest(&serde_json::to_vec(&report).unwrap()),
            boot_snapshot_sha256: Some("a".repeat(64)),
            predecessor_intent_sha256: None,
            predecessor_boot_intent_sha256: Some("b".repeat(64)),
            predecessor_cold_intent_sha256: None,
            report: report.clone(),
        };
        write_passive_atomic(fd, LEAF, &serde_json::to_vec(&active).unwrap(), MAX_SEAL).unwrap();
        let mut new_report = report.clone();
        new_report["stage"]["path"] =
            serde_json::json!("/run/aegis-installer-config-snapshots/new");
        assert!(boot_successor_for_new_report(fd, &new_report)
            .unwrap()
            .is_none());
        // A newer ordinary successor must take priority over the ancestry.
        write_passive_atomic(fd, SUCCESSOR_LEAF, b"pending", MAX_SEAL).unwrap();
        assert!(boot_successor_for_new_report(fd, &new_report)
            .unwrap()
            .is_none());
        // Exact same-generation retry still authenticates archived history.
        assert!(boot_successor_for_new_report(fd, &report)
            .unwrap()
            .is_none());
        std::fs::remove_file(dir.join(SUCCESSOR_LEAF)).unwrap();
        assert!(boot_successor_for_new_report(fd, &report).is_err());
        // A distinct pending boot intent remains a strict parse gate.
        write_passive_atomic(fd, BOOT_SUCCESSOR_LEAF, b"invalid", MAX_SEAL).unwrap();
        assert!(boot_successor_for_new_report(fd, &new_report).is_err());
        // Exercise the production seal admission, not just its branch helper:
        // malformed live boot ancestry must propagate a refusal, while an
        // inapplicable archived branch above remains silent.
        assert!(admitted_lineage(fd, &new_report).is_err());
        std::fs::remove_file(dir.join(BOOT_SUCCESSOR_LEAF)).unwrap();
        write_passive_atomic(fd, RECOVERY_LEAF, b"invalid", MAX_SEAL).unwrap();
        assert!(admitted_lineage(fd, &new_report).is_err());
        std::fs::remove_file(dir.join(RECOVERY_LEAF)).unwrap();
        write_passive_atomic(fd, STOPPED_LEAF, b"invalid", MAX_SEAL).unwrap();
        assert!(admitted_lineage(fd, &new_report).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "requires disposable Linux root filesystem"]
    fn passive_atomic_publication_survives_orphan_temp_and_refuses_named_partial() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            std::env::var("AEGIS_SUCCESSOR_ARCHIVE_TEST_DISPOSABLE").as_deref(),
            Ok("1")
        );
        let dir = std::env::temp_dir().join(format!(
            "aegis-passive-atomic-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = std::fs::File::open(&dir).unwrap();
        let fd = held.as_raw_fd();
        // A killed writer leaves only this inert, unpublished temporary name.
        std::fs::write(dir.join(".aegis-passive-dead.tmp"), b"half").unwrap();
        assert!(recovery_absent(fd, PASSIVE_ADVANCE_LEAF).is_ok());
        write_passive_atomic(fd, PASSIVE_ADVANCE_LEAF, b"complete-journal", MAX_SEAL).unwrap();
        assert_eq!(
            read_sealed_leaf(fd, PASSIVE_ADVANCE_LEAF).unwrap(),
            b"complete-journal"
        );
        write_passive_atomic(fd, PASSIVE_ADVANCE_LEAF, b"complete-journal", MAX_SEAL).unwrap();
        assert!(write_passive_atomic(fd, PASSIVE_ADVANCE_LEAF, b"foreign", MAX_SEAL).is_err());
        let archive = archived_name("passive-preinst", &digest(b"complete-archive")).unwrap();
        std::fs::write(dir.join(&archive), b"partial").unwrap();
        assert!(archive_exact(
            fd,
            "passive-preinst",
            &digest(b"complete-archive"),
            b"complete-archive"
        )
        .is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "requires disposable Linux root filesystem"]
    fn passive_journal_exact_archive_survives_each_retirement_cut() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            std::env::var("AEGIS_SUCCESSOR_ARCHIVE_TEST_DISPOSABLE").as_deref(),
            Ok("1")
        );
        let dir = std::env::temp_dir().join(format!(
            "aegis-passive-cut-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = std::fs::File::open(&dir).unwrap();
        let fd = held.as_raw_fd();
        let hist = history_dir(fd, true).unwrap();
        let body = b"{\"schema\":\"exact-preinst\"}\n";
        let hash = digest(body);
        let journal = serde_json::json!({"preinst_sha256": hash});
        write_sealed_leaf(fd, PASSIVE_PREINST_LEAF, body).unwrap();
        assert_eq!(
            passive_leaf(
                fd,
                hist.as_raw_fd(),
                PASSIVE_PREINST_LEAF,
                "passive-preinst",
                Some(&journal),
                "preinst_sha256"
            )
            .unwrap(),
            body
        );
        archive_exact(hist.as_raw_fd(), "passive-preinst", &hash, body).unwrap();
        assert_eq!(
            passive_leaf(
                fd,
                hist.as_raw_fd(),
                PASSIVE_PREINST_LEAF,
                "passive-preinst",
                Some(&journal),
                "preinst_sha256"
            )
            .unwrap(),
            body
        );
        retire_exact(fd, PASSIVE_PREINST_LEAF, body).unwrap();
        assert_eq!(
            passive_leaf(
                fd,
                hist.as_raw_fd(),
                PASSIVE_PREINST_LEAF,
                "passive-preinst",
                Some(&journal),
                "preinst_sha256"
            )
            .unwrap(),
            body
        );
        // A later foreign fixed leaf cannot override the archived authority.
        write_sealed_leaf(fd, PASSIVE_PREINST_LEAF, b"foreign").unwrap();
        assert!(passive_leaf(
            fd,
            hist.as_raw_fd(),
            PASSIVE_PREINST_LEAF,
            "passive-preinst",
            Some(&journal),
            "preinst_sha256"
        )
        .is_err());
        let old_boot = "01234567-89ab-cdef-0123-456789abcdef";
        let advance = serde_json::to_vec(&serde_json::json!({
            "schema": "aegis_auto_v2_passive_advance_v1",
            "boot_id": old_boot,
            "successor_intent_sha256": hash,
            "new_active_sha256": hash,
            "retirement_intent_sha256": hash,
            "retired_sha256": hash,
            "old_stopped_record_sha256": hash,
            "preinst_sha256": hash,
        }))
        .unwrap();
        write_passive_atomic(fd, PASSIVE_ADVANCE_LEAF, &advance, MAX_SEAL).unwrap();
        assert_eq!(
            passive_advance_journal(fd).unwrap().unwrap()["boot_id"],
            old_boot
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "requires disposable Linux root filesystem"]
    fn passive_advance_replays_original_active_sha_after_new_boot_seal() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            std::env::var("AEGIS_SUCCESSOR_ARCHIVE_TEST_DISPOSABLE").as_deref(),
            Ok("1")
        );
        let dir = std::env::temp_dir().join(format!("aegis-passive-boot-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = std::fs::File::open(&dir).unwrap();
        let history = history_dir(held.as_raw_fd(), true).unwrap();
        let old_boot = "01234567-89ab-cdef-0123-456789abcdef";
        let new_boot = "11234567-89ab-cdef-0123-456789abcdef";
        let successor_sha = "a".repeat(64);
        let root = "/var/lib/aegis-auto/releases/source-123";
        let candidate = format!("{root}/bin/aegis-client");
        let report = serde_json::json!({
            "schema": "aegis_auto_active_stage_inspection_v1",
            "stage": {"path": "/run/aegis-installer-config-snapshots/first", "phase": "finalized",
                "mode": "socks-only", "device": 12, "inode": 34},
            "terminal": {"outcome": "finalized", "boot_id": old_boot,
                "start_terminal_sha256": "b".repeat(64)},
            "published_paths": {"current_verified": true, "current_publications": {
                "config": "a".repeat(64), "state": "b".repeat(64), "metadata": "c".repeat(64)}},
            "current_fixed": serde_json::to_value(crate::profile_auto_unit_namespace::test_inspected_role_nodes()).unwrap(),
            "input": {"candidate_sha256": "d".repeat(64), "candidate_binary": candidate,
                "public_payload_root": root, "provenance_sha256": "e".repeat(64),
                "installed_manifest_sha256": "f".repeat(64)},
            "main": {"active_verified": true},
            "guardian": {"active_verified": true, "manager_binding_sha256": null},
        });
        assert!(report_shape(&report).is_ok());
        let old = GenerationSeal {
            schema: "aegis_auto_v2_generation_v1".into(),
            report_sha256: digest(&serde_json::to_vec(&report).unwrap()),
            boot_snapshot_sha256: Some("c".repeat(64)),
            predecessor_intent_sha256: Some(successor_sha.clone()),
            predecessor_boot_intent_sha256: None,
            predecessor_cold_intent_sha256: None,
            report: report.clone(),
        };
        let old_raw = serde_json::to_vec(&old).unwrap();
        let old_sha = digest(&old_raw);
        archive_exact(history.as_raw_fd(), "active", &old_sha, &old_raw).unwrap();
        let boot = BootSuccessorIntent {
            schema: "aegis_auto_v2_boot_successor_v1".into(),
            old_active_sha256: old_sha.clone(),
            old_stopped_sha256: None,
            old_pointer_receipt_sha256: None,
            old_snapshot_sha256: "c".repeat(64),
            old_pointer_sha256: "e".repeat(64),
            verified_boot_sha256: "f".repeat(64),
            old_boot_id: old_boot.into(),
            new_boot_id: new_boot.into(),
            public_payload_root: root.into(),
            candidate_binary: candidate,
            candidate_sha256: "d".repeat(64),
            installer_sha256: "e".repeat(64),
        };
        let boot_raw = serde_json::to_vec(&boot).unwrap();
        let boot_sha = digest(&boot_raw);
        archive_exact(history.as_raw_fd(), "boot-intent", &boot_sha, &boot_raw).unwrap();
        let mut next_report = report;
        next_report["terminal"]["boot_id"] = serde_json::json!(new_boot);
        next_report["stage"]["path"] =
            serde_json::json!("/run/aegis-installer-config-snapshots/next");
        let next = GenerationSeal {
            schema: "aegis_auto_v2_generation_v1".into(),
            report_sha256: digest(&serde_json::to_vec(&next_report).unwrap()),
            boot_snapshot_sha256: Some("d".repeat(64)),
            predecessor_intent_sha256: None,
            predecessor_boot_intent_sha256: Some(boot_sha),
            predecessor_cold_intent_sha256: None,
            report: next_report,
        };
        let next_sha = digest(&serde_json::to_vec(&next).unwrap());
        assert_ne!(next_sha, old_sha);
        assert_eq!(
            passive_first_active_sha(
                &next,
                &next_sha,
                history.as_raw_fd(),
                &successor_sha,
                old_boot,
                32
            )
            .unwrap(),
            old_sha
        );
        let mut foreign = next;
        foreign.report["terminal"]["boot_id"] = serde_json::json!(old_boot);
        assert!(passive_first_active_sha(
            &foreign,
            &next_sha,
            history.as_raw_fd(),
            &successor_sha,
            old_boot,
            32
        )
        .is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "requires disposable Linux root filesystem"]
    fn boot_intent_only_retry_requires_exact_fixed_pointer_receipt() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            std::env::var("AEGIS_SUCCESSOR_ARCHIVE_TEST_DISPOSABLE").as_deref(),
            Ok("1")
        );
        let dir = std::env::temp_dir().join(format!(
            "aegis-boot-intent-pointer-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = std::fs::File::open(&dir).unwrap();
        let fd = held.as_raw_fd();
        let stopped = serde_json::json!({
            "stage": {"path": "/run/aegis-installer-config-snapshots/old"},
            "terminal": {"boot_id": "01234567-89ab-cdef-0123-456789abcdef"},
            "input": {"candidate_sha256": "a".repeat(64)},
        });
        let pointer = b"old-pointer-bytes";
        let pointer_sha = digest(pointer);
        let archive = format!("archived-stopped-{pointer_sha}.json");
        write_sealed_leaf(fd, &archive, pointer).unwrap();
        let receipt = serde_json::to_vec(&serde_json::json!({
            "schema": "aegis_auto_v2_stopped_pointer_archive_v1",
            "stage": stopped["stage"]["path"],
            "boot_id": stopped["terminal"]["boot_id"],
            "candidate_sha256": stopped["input"]["candidate_sha256"],
            "pointer_sha256": pointer_sha,
            "archive_leaf": archive,
            "stopped_report_sha256": digest(&serde_json::to_vec(&stopped).unwrap()),
        }))
        .unwrap();
        let receipt_sha = digest(&receipt);
        write_sealed_leaf(fd, "generation-pointer-stopped.json", &receipt).unwrap();
        assert!(recovery_absent(fd, HISTORY_DIR).is_ok());
        assert_eq!(
            stopped_pointer_receipt(fd, &stopped, Some(&receipt_sha)).unwrap(),
            receipt
        );
        std::fs::write(dir.join("generation-pointer-stopped.json"), b"foreign").unwrap();
        assert!(stopped_pointer_receipt(fd, &stopped, Some(&receipt_sha)).is_err());
        std::fs::write(dir.join("generation-pointer-stopped.json"), &receipt).unwrap();
        let history = history_dir(fd, true).unwrap();
        archive_exact(
            history.as_raw_fd(),
            "stopped-pointer",
            &receipt_sha,
            &receipt,
        )
        .unwrap();
        retire_exact(fd, "generation-pointer-stopped.json", &receipt).unwrap();
        assert_eq!(
            stopped_pointer_receipt(fd, &stopped, Some(&receipt_sha)).unwrap(),
            receipt
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn boot_successor_requires_distinct_boot_and_exact_retained_source_shape() {
        let mut intent = BootSuccessorIntent {
            schema: "aegis_auto_v2_boot_successor_v1".into(),
            old_active_sha256: "a".repeat(64),
            old_stopped_sha256: None,
            old_pointer_receipt_sha256: None,
            old_snapshot_sha256: "b".repeat(64),
            old_pointer_sha256: "c".repeat(64),
            verified_boot_sha256: "d".repeat(64),
            old_boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            new_boot_id: "11234567-89ab-cdef-0123-456789abcdef".into(),
            public_payload_root: "/var/lib/aegis-auto/releases/source-123".into(),
            candidate_binary: "/var/lib/aegis-auto/releases/source-123/bin/aegis-client".into(),
            candidate_sha256: "e".repeat(64),
            installer_sha256: "f".repeat(64),
        };
        assert!(boot_successor_shape(&intent).is_ok());
        intent.new_boot_id = intent.old_boot_id.clone();
        assert!(boot_successor_shape(&intent).is_err());
        intent.new_boot_id = "11234567-89ab-cdef-0123-456789abcdef".into();
        intent.candidate_binary = "/var/lib/aegis-auto/releases/foreign/bin/aegis-client".into();
        assert!(boot_successor_shape(&intent).is_err());
        intent.candidate_binary = "/var/lib/aegis-auto/releases/source-123/bin/aegis-client".into();
        intent.old_pointer_sha256 = "A".repeat(64);
        assert!(boot_successor_shape(&intent).is_err());
    }

    #[test]
    #[ignore = "requires disposable Linux root filesystem"]
    fn boot_snapshot_archive_has_its_own_exact_bound() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            std::env::var("AEGIS_SUCCESSOR_ARCHIVE_TEST_DISPOSABLE").as_deref(),
            Ok("1")
        );
        let dir = std::env::temp_dir().join(format!(
            "aegis-boot-snapshot-bound-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = std::fs::File::open(&dir).unwrap();
        let fd = held.as_raw_fd();
        let permitted = vec![b'a'; MAX_SEAL + 1];
        let sha = digest(&permitted);
        archive_exact(fd, "snapshot", &sha, &permitted).unwrap();
        assert_eq!(read_archived(fd, "snapshot", &sha).unwrap(), permitted);
        let oversized = vec![b'b'; MAX_SNAPSHOT_ARCHIVE + 1];
        let sha = digest(&oversized);
        assert!(archive_exact(fd, "snapshot", &sha, &oversized).is_err());
        assert!(recovery_absent(fd, &archived_name("snapshot", &sha).unwrap()).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Execute only in a disposable Linux root container. Every case uses a
    /// distinct private temporary directory; no fixed product path is touched.
    #[test]
    #[ignore = "requires disposable Linux root filesystem"]
    fn successor_archive_interruption_and_foreign_leaf_control() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            std::env::var("AEGIS_SUCCESSOR_ARCHIVE_TEST_DISPOSABLE").as_deref(),
            Ok("1")
        );
        let base = std::env::temp_dir().join(format!(
            "aegis-successor-archive-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        for cut in 0..10 {
            let dir = base.join(format!("case-{cut}"));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let control = std::fs::File::open(&dir).unwrap();
            let fd = control.as_raw_fd();
            let active = b"active-seal-bytes";
            let stopped = b"stopped-seal-bytes";
            let pointer = b"stopped-pointer-receipt-bytes";
            let intent = SuccessorIntent {
                schema: "aegis_auto_v2_stopped_successor_v1".into(),
                kind: "upgrade".into(),
                old_active_sha256: digest(active),
                old_stopped_sha256: digest(stopped),
                old_pointer_receipt_sha256: digest(pointer),
                old_stage_path: "/run/aegis-installer-config-snapshots/old".into(),
                old_boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
                next_public_payload_root: "/var/lib/aegis-auto/releases/next".into(),
                next_candidate_binary: "/var/lib/aegis-auto/releases/next/bin/aegis-client".into(),
                next_candidate_sha256: "a".repeat(64),
                next_installer_sha256: "b".repeat(64),
                next_bundle_manifest_sha256: None,
                next_sums_sha256: None,
            };
            let wire = serde_json::to_vec(&intent).unwrap();
            write_sealed_leaf(fd, LEAF, active).unwrap();
            write_sealed_leaf(fd, STOPPED_LEAF, stopped).unwrap();
            write_sealed_leaf(fd, "generation-pointer-stopped.json", pointer).unwrap();
            write_sealed_leaf(fd, SUCCESSOR_LEAF, &wire).unwrap();
            let hist = history_dir(fd, true).unwrap();
            if cut >= 1 {
                archive_exact(
                    hist.as_raw_fd(),
                    "active",
                    &intent.old_active_sha256,
                    active,
                )
                .unwrap();
            }
            if cut >= 2 {
                archive_exact(
                    hist.as_raw_fd(),
                    "stopped",
                    &intent.old_stopped_sha256,
                    stopped,
                )
                .unwrap();
            }
            if cut >= 3 {
                archive_exact(
                    hist.as_raw_fd(),
                    "stopped-pointer",
                    &intent.old_pointer_receipt_sha256,
                    pointer,
                )
                .unwrap();
            }
            if cut >= 4 && cut != 9 {
                retire_exact(fd, "generation-pointer-stopped.json", pointer).unwrap();
            }
            if cut >= 5 {
                retire_exact(fd, STOPPED_LEAF, stopped).unwrap();
            }
            if cut >= 6 {
                retire_exact(fd, LEAF, active).unwrap();
            }
            if cut == 7 {
                let name = archived_name("active", &intent.old_active_sha256).unwrap();
                std::fs::write(dir.join(HISTORY_DIR).join(name), b"foreign").unwrap();
                assert!(
                    complete_archive_transition(fd, &wire, &intent, active, stopped, pointer)
                        .is_err()
                );
            } else if cut == 8 {
                let name =
                    archived_name("stopped-pointer", &intent.old_pointer_receipt_sha256).unwrap();
                std::fs::write(dir.join(HISTORY_DIR).join(name), b"foreign").unwrap();
                assert!(
                    complete_archive_transition(fd, &wire, &intent, active, stopped, pointer)
                        .is_err()
                );
            } else if cut == 9 {
                std::fs::write(dir.join("generation-pointer-stopped.json"), b"foreign").unwrap();
                assert!(
                    complete_archive_transition(fd, &wire, &intent, active, stopped, pointer)
                        .is_err()
                );
            } else {
                complete_archive_transition(fd, &wire, &intent, active, stopped, pointer).unwrap();
                complete_archive_transition(fd, &wire, &intent, active, stopped, pointer).unwrap();
                assert!(recovery_absent(fd, LEAF).is_ok());
                assert!(recovery_absent(fd, STOPPED_LEAF).is_ok());
                assert!(recovery_absent(fd, "generation-pointer-stopped.json").is_ok());
            }
        }
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn successor_intent_shape_and_wire_reject_foreign_roots() {
        let mut intent = SuccessorIntent {
            schema: "aegis_auto_v2_stopped_successor_v1".into(),
            kind: "upgrade".into(),
            old_active_sha256: "a".repeat(64),
            old_stopped_sha256: "b".repeat(64),
            old_pointer_receipt_sha256: "f".repeat(64),
            old_stage_path: "/run/aegis-installer-config-snapshots/old".into(),
            old_boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            next_public_payload_root: "/var/lib/aegis-auto/releases/new".into(),
            next_candidate_binary: "/var/lib/aegis-auto/releases/new/bin/aegis-client".into(),
            next_candidate_sha256: "c".repeat(64),
            next_installer_sha256: "d".repeat(64),
            next_bundle_manifest_sha256: None,
            next_sums_sha256: None,
        };
        assert!(successor_shape(&intent).is_ok());
        let wire = successor_output(
            &serde_json::json!({"old": true}),
            &intent,
            &"e".repeat(64),
            None,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        let successor = value["successor"].as_object().unwrap();
        assert_eq!(successor.len(), 11);
        for key in [
            "intent_sha256",
            "kind",
            "old_active_sha256",
            "old_stopped_sha256",
            "next_public_payload_root",
            "next_candidate_binary",
            "next_candidate_sha256",
            "next_installer_sha256",
            "next_bundle_manifest_sha256",
            "next_sums_sha256",
            "prior_successor_intent_sha256",
        ] {
            assert!(
                successor.contains_key(key),
                "missing successor field: {key}"
            );
        }
        assert!(successor
            .get("next_bundle_manifest_sha256")
            .unwrap()
            .is_null());
        assert!(successor.get("next_sums_sha256").unwrap().is_null());
        assert!(value["successor"]["prior_successor_intent_sha256"].is_null());
        assert_eq!(
            value["schema"],
            "aegis_auto_v2_stopped_successor_verification_v1"
        );
        intent.next_candidate_binary =
            "/var/lib/aegis-auto/releases/foreign/bin/aegis-client".into();
        assert!(successor_shape(&intent).is_err());
        intent.next_candidate_binary = "/var/lib/aegis-auto/releases/new/bin/aegis-client".into();
        intent.old_active_sha256 = "A".repeat(64);
        assert!(successor_shape(&intent).is_err());
        intent.old_active_sha256 = "a".repeat(64);
        intent.next_public_payload_root = "/var/lib/aegis-auto/releases/..".into();
        assert!(successor_shape(&intent).is_err());
        intent.next_public_payload_root = "/var/lib/aegis-auto/releases/new".into();
        intent.kind = "unknown".into();
        assert!(successor_shape(&intent).is_err());
        intent.kind = "restart".into();
        let old = serde_json::json!({"input": {"public_payload_root":
            "/var/lib/aegis-auto/releases/new"}});
        assert!(successor_kind(&intent, &old).is_ok());
        intent.kind = "upgrade".into();
        assert!(successor_kind(&intent, &old).is_err());
    }

    fn active_report() -> serde_json::Value {
        serde_json::json!({
            "schema": "aegis_auto_active_stage_inspection_v1",
            "stage": {"path": "/run/aegis-installer-config-snapshots/stage", "phase": "finalized",
                "mode": "wide-redirect-safe",
                "device": 12, "inode": 34},
            "terminal": {"outcome": "finalized", "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
                "start_terminal_sha256": "a".repeat(64)},
            "published_paths": {"current_verified": true, "current_publications": {
                "config": "a".repeat(64), "state": "b".repeat(64), "metadata": "c".repeat(64)}},
            "current_fixed": serde_json::to_value(crate::profile_auto_unit_namespace::test_inspected_role_nodes()).unwrap(),
            "input": {"candidate_sha256": "d".repeat(64), "candidate_binary": "/var/lib/aegis-auto/releases/x/bin/aegis-client",
                "public_payload_root": "/var/lib/aegis-auto/releases/x",
                "provenance_sha256": "e".repeat(64), "installed_manifest_sha256": "f".repeat(64)},
            "main": {"active_verified": true}, "guardian": {"active_verified": true,
                "manager_binding_sha256": "a".repeat(64)}
        })
    }

    #[test]
    fn sealed_boot_successor_reopens_distinct_pointer_with_and_without_stopped_predecessor() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        for stopped_predecessor in [false, true] {
            let dir = std::env::temp_dir().join(format!(
                "aegis-sealed-boot-history-{}-{}-{}",
                std::process::id(),
                stopped_predecessor,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let history_path = dir.join("generation-history");
            std::fs::create_dir(&history_path).unwrap();
            std::fs::set_permissions(&history_path, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let control = std::fs::File::open(&dir).unwrap();
            let history = std::fs::File::open(&history_path).unwrap();
            let old_boot = "01234567-89ab-cdef-0123-456789abcdef";
            let actual_boot = current_boot_id().unwrap();
            let new_boot = if stopped_predecessor {
                "11234567-89ab-cdef-0123-456789abcdef"
            } else {
                actual_boot.as_str()
            };
            let mut old_report = active_report();
            old_report["stage"]["mode"] = serde_json::json!("socks-only");
            old_report["guardian"]["manager_binding_sha256"] = serde_json::Value::Null;
            let mut new_report = old_report.clone();
            new_report["stage"]["path"] =
                serde_json::json!("/run/aegis-installer-config-snapshots/new");
            new_report["terminal"]["boot_id"] = serde_json::json!(new_boot);
            assert!(report_shape(&old_report).is_ok());
            assert!(report_shape(&new_report).is_ok());
            let snapshot = b"sealed historical snapshot";
            let snapshot_sha = digest(snapshot);
            let old_seal = GenerationSeal {
                schema: "aegis_auto_v2_generation_v1".into(),
                report_sha256: digest(&serde_json::to_vec(&old_report).unwrap()),
                boot_snapshot_sha256: Some(snapshot_sha.clone()),
                predecessor_intent_sha256: None,
                predecessor_boot_intent_sha256: None,
                predecessor_cold_intent_sha256: None,
                report: old_report.clone(),
            };
            let old_seal_bytes = serde_json::to_vec(&old_seal).unwrap();
            let pointer = |report: &serde_json::Value| {
                serde_json::json!({
                    "schema":"aegis_installer_auto_v2_stage_v2",
                    "stage":report["stage"]["path"],"status":"pending",
                    "boot_id":report["terminal"]["boot_id"],
                    "installed_binary":"/usr/local/bin/aegis-client",
                    "candidate_sha256":report["input"]["candidate_sha256"],
                    "previous_binary":null
                })
            };
            let old_pointer = serde_json::to_vec(&pointer(&old_report)).unwrap();
            let old_pointer_sha = digest(&old_pointer);
            let proof = serde_json::json!({
                "schema":"aegis_auto_v2_verified_boot_v1",
                "old_report_sha256":digest(&serde_json::to_vec(&old_report).unwrap()),
                "snapshot_sha256":snapshot_sha,
                "old_boot_id":old_boot,"new_boot_id":new_boot,
                "deny":{"schema":"aegis_auto_guard_boot_passive_readback_v1",
                    "passive":true,"no_private_owner":true,"fixed_client_stopped":true,
                    "candidate_sha256":old_report["input"]["candidate_sha256"],
                    "boot_id":new_boot},
                "host_assessment":null
            });
            let proof_bytes = serde_json::to_vec(&proof).unwrap();
            let mut intent = BootSuccessorIntent {
                schema: "aegis_auto_v2_boot_successor_v1".into(),
                old_active_sha256: digest(&old_seal_bytes),
                old_stopped_sha256: None,
                old_pointer_receipt_sha256: None,
                old_snapshot_sha256: snapshot_sha.clone(),
                old_pointer_sha256: old_pointer_sha.clone(),
                verified_boot_sha256: digest(&proof_bytes),
                old_boot_id: old_boot.into(),
                new_boot_id: new_boot.into(),
                public_payload_root: old_report["input"]["public_payload_root"]
                    .as_str()
                    .unwrap()
                    .into(),
                candidate_binary: old_report["input"]["candidate_binary"]
                    .as_str()
                    .unwrap()
                    .into(),
                candidate_sha256: old_report["input"]["candidate_sha256"]
                    .as_str()
                    .unwrap()
                    .into(),
                installer_sha256: "a".repeat(64),
            };
            let archive = |role: &str, bytes: &[u8]| {
                let sha = digest(bytes);
                let leaf = archived_name(role, &sha).unwrap();
                write_passive_atomic(history.as_raw_fd(), &leaf, bytes, MAX_SEAL).unwrap();
                sha
            };
            archive("active", &old_seal_bytes);
            archive("snapshot", snapshot);
            archive("boot-proof", &proof_bytes);
            archive("boot-pointer", &old_pointer);
            if stopped_predecessor {
                let mut stopped_report = old_report.clone();
                stopped_report["schema"] =
                    serde_json::json!("aegis_auto_v2_stopped_stage_inspection_v1");
                stopped_report["terminal"]["outcome"] = serde_json::json!("finalized-stopped");
                for key in [
                    "stop_submitted_sha256",
                    "stop_completed_sha256",
                    "stop_terminal_sha256",
                ] {
                    stopped_report["terminal"][key] = serde_json::json!("b".repeat(64));
                }
                stopped_report["main"] = serde_json::json!({
                    "stopped_verified":true,"no_live_lease_verified":true,
                    "fdstore_empty_verified":true
                });
                stopped_report["guardian"] = serde_json::json!({
                    "deny_verified":true,"fdstore_empty_verified":true,
                    "prior_manager_binding_sha256":null,"manager_binding_sha256":null
                });
                let stopped_seal = StoppedGenerationSeal {
                    schema: "aegis_auto_v2_stopped_generation_v1".into(),
                    active_seal_sha256: digest(&old_seal_bytes),
                    stopped_report_sha256: digest(&serde_json::to_vec(&stopped_report).unwrap()),
                    report: stopped_report.clone(),
                };
                let stopped_bytes = serde_json::to_vec(&stopped_seal).unwrap();
                let receipt = serde_json::json!({
                    "schema":"aegis_auto_v2_stopped_pointer_archive_v1",
                    "stage":stopped_report["stage"]["path"],"boot_id":old_boot,
                    "candidate_sha256":stopped_report["input"]["candidate_sha256"],
                    "pointer_sha256":old_pointer_sha,
                    "archive_leaf":format!("archived-stopped-{old_pointer_sha}.json"),
                    "stopped_report_sha256":digest(&serde_json::to_vec(&stopped_report).unwrap())
                });
                let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
                intent.old_stopped_sha256 = Some(archive("stopped", &stopped_bytes));
                intent.old_pointer_receipt_sha256 =
                    Some(archive("stopped-pointer", &receipt_bytes));
                write_passive_atomic(
                    control.as_raw_fd(),
                    &format!("archived-stopped-{old_pointer_sha}.json"),
                    &old_pointer,
                    MAX_SEAL,
                )
                .unwrap();
            }
            assert!(boot_successor_shape(&intent).is_ok());
            let intent_bytes = serde_json::to_vec(&intent).unwrap();
            let intent_sha = archive("boot-intent", &intent_bytes);
            let prepared = serde_json::json!({
                "schema":"aegis_auto_v2_boot_prepare_handoff_v2","phase":"intent",
                "boot_id":new_boot,"stage":new_report["stage"]["path"],
                "candidate_binary":intent.candidate_binary,
                "public_payload_root":intent.public_payload_root,
                "nonce":"a".repeat(32),"boot_intent_sha256":intent_sha
            });
            let prepared_bytes = serde_json::to_vec(&prepared).unwrap();
            let prepared_sha = digest(&prepared_bytes);
            let created = serde_json::json!({
                "schema":"aegis_auto_v2_boot_stage_created_v1",
                "prepare_intent_sha256":prepared_sha,"boot_intent_sha256":intent_sha,
                "boot_id":new_boot,"stage":new_report["stage"]["path"],
                "stage_device":12,"stage_inode":34,
                "candidate_binary":intent.candidate_binary,
                "public_payload_root":intent.public_payload_root
            });
            let created_bytes = serde_json::to_vec(&created).unwrap();
            let created_sha = digest(&created_bytes);
            let completed = serde_json::json!({
                "schema":"aegis_auto_v2_boot_prepare_handoff_v2","phase":"completed",
                "intent_sha256":prepared_sha,"stage":new_report["stage"]["path"],
                "stage_device":12,"stage_inode":34,
                "header_sha256":"a".repeat(64),"input_generation":"b".repeat(64),
                "candidate_sha256":new_report["input"]["candidate_sha256"],
                "provenance_sha256":"c".repeat(64),"boot_intent_sha256":intent_sha,
                "stage_created_sha256":created_sha
            });
            let completed_bytes = serde_json::to_vec(&completed).unwrap();
            let completed_sha = digest(&completed_bytes);
            for (sha, bytes) in [
                (&prepared_sha, &prepared_bytes),
                (&created_sha, &created_bytes),
                (&completed_sha, &completed_bytes),
            ] {
                write_passive_atomic(
                    control.as_raw_fd(),
                    &format!("prepare-archive-{sha}.json"),
                    bytes,
                    MAX_SEAL,
                )
                .unwrap();
            }
            let mut new_pointer_value = pointer(&new_report);
            new_pointer_value["schema"] =
                serde_json::json!("aegis_installer_auto_v2_boot_stage_v3");
            new_pointer_value["boot_intent_sha256"] = serde_json::json!(intent_sha);
            new_pointer_value["prepare_intent_sha256"] = serde_json::json!(prepared_sha);
            new_pointer_value["prepare_completed_sha256"] = serde_json::json!(completed_sha);
            let new_pointer = serde_json::to_vec(&new_pointer_value).unwrap();
            let new_seal = GenerationSeal {
                schema: "aegis_auto_v2_generation_v1".into(),
                report_sha256: digest(&serde_json::to_vec(&new_report).unwrap()),
                boot_snapshot_sha256: None,
                predecessor_intent_sha256: None,
                predecessor_boot_intent_sha256: Some(intent_sha),
                predecessor_cold_intent_sha256: None,
                report: new_report.clone(),
            };
            write_passive_atomic(
                control.as_raw_fd(),
                LEAF,
                &serde_json::to_vec(&new_seal).unwrap(),
                MAX_SEAL,
            )
            .unwrap();
            write_passive_atomic(control.as_raw_fd(), "current.json", &new_pointer, MAX_SEAL)
                .unwrap();
            assert_eq!(read_history_at(&control).unwrap().report, new_report);
            if stopped_predecessor {
                let mut later = intent.clone();
                later.old_boot_id = new_boot.into();
                later.new_boot_id = actual_boot.clone();
                assert!(boot_successor_shape(&later).is_ok());
                let later_bytes = serde_json::to_vec(&later).unwrap();
                let later_sha = digest(&later_bytes);
                write_passive_atomic(
                    control.as_raw_fd(),
                    BOOT_SUCCESSOR_LEAF,
                    &later_bytes,
                    MAX_SEAL,
                )
                .unwrap();
                assert!(
                    boot_pointer_v3(control.as_raw_fd(), &new_pointer_value, &new_report).is_ok()
                );
                let next_stage = format!(
                    "/run/aegis-installer-config-snapshots/.auto-{}",
                    "b".repeat(32)
                );
                let next_prepare = serde_json::json!({
                    "schema":"aegis_auto_v2_boot_prepare_handoff_v2","phase":"intent",
                    "boot_id":actual_boot,"stage":next_stage,
                    "candidate_binary":later.candidate_binary,
                    "public_payload_root":later.public_payload_root,
                    "nonce":"c".repeat(32),"boot_intent_sha256":later_sha
                });
                let next_prepare_raw = serde_json::to_vec(&next_prepare).unwrap();
                write_passive_atomic(
                    control.as_raw_fd(),
                    "prepare-current.json",
                    &next_prepare_raw,
                    MAX_SEAL,
                )
                .unwrap();
                assert!(
                    boot_pointer_v3(control.as_raw_fd(), &new_pointer_value, &new_report).is_ok()
                );
                let next_created = serde_json::json!({
                    "schema":"aegis_auto_v2_boot_stage_created_v1",
                    "prepare_intent_sha256":digest(&next_prepare_raw),
                    "boot_intent_sha256":later_sha,"boot_id":actual_boot,"stage":next_stage,
                    "stage_device":56,"stage_inode":78,
                    "candidate_binary":later.candidate_binary,
                    "public_payload_root":later.public_payload_root
                });
                let next_created_raw = serde_json::to_vec(&next_created).unwrap();
                write_passive_atomic(
                    control.as_raw_fd(),
                    "prepare-stage-created.json",
                    &next_created_raw,
                    MAX_SEAL,
                )
                .unwrap();
                assert!(
                    boot_pointer_v3(control.as_raw_fd(), &new_pointer_value, &new_report).is_ok()
                );
                let next_complete = serde_json::json!({
                    "schema":"aegis_auto_v2_boot_prepare_handoff_v2","phase":"completed",
                    "intent_sha256":digest(&next_prepare_raw),"stage":next_stage,
                    "stage_device":56,"stage_inode":78,
                    "header_sha256":"a".repeat(64),"input_generation":"b".repeat(64),
                    "candidate_sha256":later.candidate_sha256,
                    "provenance_sha256":"c".repeat(64),"boot_intent_sha256":later_sha,
                    "stage_created_sha256":digest(&next_created_raw)
                });
                let next_complete_raw = serde_json::to_vec(&next_complete).unwrap();
                write_passive_atomic(
                    control.as_raw_fd(),
                    "prepare-completed.json",
                    &next_complete_raw,
                    MAX_SEAL,
                )
                .unwrap();
                assert!(
                    boot_pointer_v3(control.as_raw_fd(), &new_pointer_value, &new_report).is_ok()
                );
                let mut wrong_stage_complete = next_complete.clone();
                wrong_stage_complete["stage_inode"] = serde_json::json!(79);
                std::fs::write(
                    dir.join("prepare-completed.json"),
                    serde_json::to_vec(&wrong_stage_complete).unwrap(),
                )
                .unwrap();
                assert!(
                    boot_pointer_v3(control.as_raw_fd(), &new_pointer_value, &new_report).is_err()
                );
                std::fs::write(dir.join("prepare-completed.json"), &next_complete_raw).unwrap();
                assert!(
                    boot_pointer_v3(control.as_raw_fd(), &new_pointer_value, &new_report).is_ok()
                );
                std::fs::write(dir.join("prepare-current.json"), b"invalid").unwrap();
                assert!(
                    boot_pointer_v3(control.as_raw_fd(), &new_pointer_value, &new_report).is_err()
                );
                std::fs::remove_file(dir.join("prepare-current.json")).unwrap();
                std::fs::remove_file(dir.join("prepare-stage-created.json")).unwrap();
                std::fs::remove_file(dir.join("prepare-completed.json")).unwrap();
                std::fs::remove_file(dir.join(BOOT_SUCCESSOR_LEAF)).unwrap();
            }
            // An archive never excuses a present malformed or swapped live
            // successor intent, even if its archived bytes still match.
            write_passive_atomic(
                control.as_raw_fd(),
                BOOT_SUCCESSOR_LEAF,
                b"invalid",
                MAX_SEAL,
            )
            .unwrap();
            assert!(read_history_at(&control).is_err());
            std::fs::remove_file(dir.join(BOOT_SUCCESSOR_LEAF)).unwrap();
            std::fs::remove_file(dir.join("current.json")).unwrap();
            let mut changed = new_pointer_value;
            changed["candidate_sha256"] = serde_json::json!("c".repeat(64));
            write_passive_atomic(
                control.as_raw_fd(),
                "current.json",
                &serde_json::to_vec(&changed).unwrap(),
                MAX_SEAL,
            )
            .unwrap();
            assert!(read_history_at(&control).is_err());
            std::fs::remove_file(dir.join("current.json")).unwrap();
            assert_eq!(read_history_at(&control).unwrap().report, new_report);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn generation_shape_never_accepts_a_stopped_or_partial_projection() {
        let mut report = active_report();
        assert!(report_shape(&report).is_ok());
        report["stage"]["mode"] = serde_json::json!("socks-only");
        assert!(report_shape(&report).is_err());
        report["guardian"]["manager_binding_sha256"] = serde_json::Value::Null;
        assert!(report_shape(&report).is_ok());
        report["stage"]["mode"] = serde_json::json!("wide-redirect-safe");
        report["guardian"]["manager_binding_sha256"] = serde_json::json!("a".repeat(64));
        report["published_paths"]["current_publications"]
            .as_object_mut()
            .unwrap()
            .remove("metadata");
        assert!(report_shape(&report).is_err());
        report["published_paths"]["current_publications"]["metadata"] =
            serde_json::json!("c".repeat(64));
        report["terminal"]["outcome"] = serde_json::json!("finalized-stopped");
        assert!(report_shape(&report).is_err());
    }

    #[test]
    fn unsealed_recovery_shape_never_implies_active_history() {
        let mut report = serde_json::json!({
            "schema": "aegis_auto_v2_stopped_stage_inspection_v1",
            "stage": {"path": "/run/aegis-installer-config-snapshots/stage", "phase": "finalized",
                "mode": "wide-redirect-safe", "device": 12, "inode": 34},
            "terminal": {"outcome": "finalized-stopped", "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
                "start_terminal_sha256": "a".repeat(64),
                "stop_submitted_sha256": "b".repeat(64),
                "stop_completed_sha256": "c".repeat(64),
                "stop_terminal_sha256": "d".repeat(64)},
            "published_paths": {"current_verified": true, "current_publications": {
                "config": "a".repeat(64), "state": "b".repeat(64), "metadata": "c".repeat(64)}},
            "current_fixed": serde_json::to_value(crate::profile_auto_unit_namespace::test_inspected_role_nodes()).unwrap(),
            "input": {"candidate_sha256": "d".repeat(64),
                "candidate_binary": "/var/lib/aegis-auto/releases/x/bin/aegis-client",
                "public_payload_root": "/var/lib/aegis-auto/releases/x",
                "provenance_sha256": "e".repeat(64), "installed_manifest_sha256": "f".repeat(64)},
            "main": {"stopped_verified": true, "no_live_lease_verified": true,
                "fdstore_empty_verified": true},
            "guardian": {"deny_verified": true, "fdstore_empty_verified": true,
                "prior_manager_binding_sha256": null,
                "manager_binding_sha256": "a".repeat(64)}
        });
        assert!(unsealed_stopped_shape(&report).is_ok());
        report["guardian"]["prior_manager_binding_sha256"] = serde_json::json!("a".repeat(64));
        assert!(unsealed_stopped_shape(&report).is_err());
        report["guardian"]["prior_manager_binding_sha256"] = serde_json::Value::Null;
        report["main"]["no_live_lease_verified"] = serde_json::json!(false);
        assert!(unsealed_stopped_shape(&report).is_err());
        report["main"]["no_live_lease_verified"] = serde_json::json!(true);
        report["stage"]["mode"] = serde_json::json!("socks-only");
        assert!(unsealed_stopped_shape(&report).is_err());
        report["guardian"]["manager_binding_sha256"] = serde_json::Value::Null;
        assert!(unsealed_stopped_shape(&report).is_ok());
    }
    #[test]
    fn actual_fixed_role_producer_arrays_are_bound_by_both_report_builders() {
        let value =
            serde_json::to_value(crate::profile_auto_unit_namespace::test_inspected_role_nodes())
                .unwrap();
        assert!(fixed_roles_shape(&value).is_ok());
        let mut active = active_report();
        active["stage"]["mode"] = serde_json::json!("socks-only");
        active["guardian"]["manager_binding_sha256"] = serde_json::Value::Null;
        let built = super::super::active_generation_report(
            active["stage"].clone(),
            active["terminal"].clone(),
            active["published_paths"].clone(),
            value.clone(),
            active["input"].clone(),
            active["main"].clone(),
            active["guardian"].clone(),
        );
        assert!(report_shape(&built).is_ok());
        let mut stopped = built.clone();
        stopped["terminal"]["outcome"] = serde_json::json!("finalized-stopped");
        for (key, hash) in [
            ("stop_submitted_sha256", "b"),
            ("stop_completed_sha256", "c"),
            ("stop_terminal_sha256", "d"),
        ] {
            stopped["terminal"][key] = serde_json::json!(hash.repeat(64));
        }
        let built_stopped = super::super::stopped_generation_report(
            stopped["stage"].clone(),
            stopped["terminal"].clone(),
            stopped["published_paths"].clone(),
            value.clone(),
            stopped["input"].clone(),
            serde_json::json!({"stopped_verified":true,"no_live_lease_verified":true,"fdstore_empty_verified":true}),
            serde_json::json!({"deny_verified":true,"fdstore_empty_verified":true,"prior_manager_binding_sha256":null,"manager_binding_sha256":null}),
        );
        assert!(unsealed_stopped_shape(&built_stopped).is_ok());
        let mut unsorted = value.clone();
        unsorted.as_array_mut().unwrap().reverse();
        let duplicate = serde_json::json!([value[0], value[0]]);
        let mut unknown = value.clone();
        unknown[0]["role"] = serde_json::json!("unknown");
        for invalid in [
            serde_json::json!({}),
            serde_json::json!([]),
            unsorted,
            duplicate,
            unknown,
        ] {
            let mut a = built.clone();
            a["current_fixed"] = invalid.clone();
            let mut b = built_stopped.clone();
            b["current_fixed"] = invalid;
            assert!(report_shape(&a).is_err());
            assert!(unsealed_stopped_shape(&b).is_err());
        }
    }
}
