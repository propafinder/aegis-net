//! PRIVATE UNAPPLIED: administrative AUTO stage and phase coordinator.
//! Root-owned durable files are admitted again on every CLI invocation; no FD
//! identity is claimed to persist between invocations. No network/service IO.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

const PROTOCOL: &str = "auto-config-snapshot-v2";
const MAX_LEAF: usize = 16 * 1024 * 1024;
const MAX_STAGE: usize = 256 * 1024 * 1024;
const MAX_LEAVES: usize = 4096;
fn leaf_bound(path: &Path) -> usize {
    if matches!(
        path.to_str(),
        Some("accepted/render-recipe.json" | "accepted/final-render-recipe.json")
    ) {
        96 * 1024 * 1024
    } else {
        MAX_LEAF
    }
}
fn refuse() -> String {
    "Administrative AUTO transaction refused".into()
}
type Result<T> = std::result::Result<T, String>;
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path.components().all(|p| matches!(p, Component::Normal(_)))
}
fn absolute(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|p| matches!(p, Component::RootDir | Component::Normal(_)))
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Prepared,
    Custody,
    State,
    Config,
    Metadata,
    Finalized,
    RolledBack,
    NativeRecoveryRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum AutoMode {
    SocksOnly,
    WideRedirectSafe,
    FullWideTun,
}
impl AutoMode {
    fn name(self) -> &'static str {
        match self {
            Self::SocksOnly => "socks-only",
            Self::WideRedirectSafe => "wide-redirect-safe",
            Self::FullWideTun => "full-wide-tun",
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Header {
    protocol: String,
    administrator_uid: u32,
    config_root: PathBuf,
    state_dir: PathBuf,
    metadata_dir: PathBuf,
    phase: Phase,
    transaction_nonce: String,
    current_records: BTreeMap<PathBuf, RecordSeal>,
    active_records: BTreeMap<String, PathBuf>,
    pending: Option<(PathBuf, RecordSeal)>,
    mode: AutoMode,
    plan: serde_json::Value,
    old_unit_namespace: Option<PathBuf>,
    new_unit_namespace: Option<PathBuf>,
    runtime_events: PathBuf,
    unit_policy_recipe: Option<PathBuf>,
    unit_records: BTreeMap<PathBuf, String>,
    unit_role_records: BTreeMap<String, PathBuf>,
    unit_pending: Option<PathBuf>,
    unit_forward_transitions: BTreeMap<String, PathBuf>,
    unit_restorations: BTreeMap<String, PathBuf>,
    unit_restored_manager: Option<PathBuf>,
    runtime_binding: Option<crate::profile_auto_runtime_identity::RuntimeBinding>,
    installed_receipt_recipe: Option<PathBuf>,
    service_uid: Option<u32>,
    service_gid: Option<u32>,
    state_records: BTreeMap<PathBuf, String>,
    namespace_records: BTreeMap<PathBuf, String>,
    service_was_active: Option<bool>,
    capture_started: bool,
    // Hashes and paths stay within this administrator-private stage.
    leaves: BTreeMap<PathBuf, String>,
    input_generation: String,
    accepted_generation: String,
    planned_generation: String,
    render_recipe: PathBuf,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordSeal {
    role: String,
    phase: String,
    predecessor_sha256: Option<String>,
    chain_sha256: String,
    sha256: String,
    stage_dev: u64,
    stage_ino: u64,
}
impl Header {
    fn validate(&self, uid: u32) -> Result<()> {
        if self
            .old_unit_namespace
            .as_ref()
            .is_some_and(|p| p != Path::new("input/unit-target/namespace.json"))
            || self
                .new_unit_namespace
                .as_ref()
                .is_some_and(|p| p != Path::new("accepted/unit-target/namespace.json"))
            || self.unit_restored_manager.as_ref().is_some_and(|p| {
                p != Path::new("receipts/unit-target/restored-manager.json")
                    || !self.unit_records.contains_key(p)
                    || self.new_unit_namespace.is_none()
                    || self.unit_pending.is_some()
            })
            || self
                .installed_receipt_recipe
                .as_ref()
                .is_some_and(|p| p != Path::new("accepted/install-receipt/recipe.json"))
            || self.unit_policy_recipe.as_ref().is_some_and(|p| {
                p != Path::new("accepted/unit-target/policy.json") || !self.leaves.contains_key(p)
            })
            || self.unit_records.len() > 128
            || self.unit_records.iter().any(|(p, h)| {
                !relative(p)
                    || !p.starts_with("receipts/unit-target")
                    || h.len() != 64
                    || !h
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || [
                &self.unit_role_records,
                &self.unit_forward_transitions,
                &self.unit_restorations,
            ]
            .iter()
            .any(|m| {
                m.len() > 3
                    || m.iter().any(|(r, p)| {
                        !matches!(r.as_str(), "base-unit" | "environment" | "dropins")
                            || !self.unit_records.contains_key(p)
                    })
            })
            || self
                .unit_pending
                .as_ref()
                .is_some_and(|p| !self.unit_records.contains_key(p))
            || self.protocol != PROTOCOL
            || self.administrator_uid != uid
            || !matches!(
                self.render_recipe.to_str(),
                Some("accepted/render-recipe.json" | "accepted/final-render-recipe.json")
            )
            || self.plan["schema"] != "aegis_auto_install_plan_v1"
            || self.plan["status"] != "planned"
            || self.plan["product_mode"] != self.mode.name()
            || self.plan["connectivity_verified"] != false
            || !absolute(&self.config_root)
            || !absolute(&self.state_dir)
            || !absolute(&self.metadata_dir)
            || !absolute(&self.runtime_events)
            || [
                (&self.config_root, &self.state_dir),
                (&self.config_root, &self.metadata_dir),
                (&self.state_dir, &self.metadata_dir),
            ]
            .iter()
            .any(|(a, b)| a.starts_with(b) || b.starts_with(a))
            || self.transaction_nonce.len() != 32
            || !self
                .transaction_nonce
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || self.namespace_records.len() > 64
            || self.namespace_records.iter().any(|(p, h)| {
                !relative(p) || !p.starts_with("receipts/namespaces") || h.len() != 64
            })
            || self.state_records.len() > 128
            || self
                .state_records
                .iter()
                .any(|(p, h)| !relative(p) || !p.starts_with("receipts/state") || h.len() != 64)
            || self
                .active_records
                .keys()
                .any(|s| !matches!(s.as_str(), "config" | "state" | "metadata"))
            || self
                .active_records
                .iter()
                .any(|(role, p)| self.current_records.get(p).is_none_or(|r| r.role != *role))
            || self.current_records.len() > 16
            || self.current_records.iter().any(|(p, r)| {
                !relative(p)
                    || !matches!(r.role.as_str(), "config" | "state" | "metadata")
                    || !matches!(
                        r.phase.as_str(),
                        "custody" | "state" | "config" | "metadata" | "rollback" | "projection"
                    )
                    || r.sha256.len() != 64
                    || r.chain_sha256.len() != 64
            })
            || self.leaves.len() > MAX_LEAVES
            || self.leaves.keys().any(|p| !relative(p))
            || self.leaves.values().any(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
        {
            return Err(refuse());
        }
        Ok(())
    }
    #[cfg(test)]
    fn require(&self, phase: Phase) -> Result<()> {
        if self.phase == phase {
            Ok(())
        } else {
            Err(refuse())
        }
    }
}
struct Leaves(BTreeMap<PathBuf, Zeroizing<Vec<u8>>>);
impl Leaves {
    fn new() -> Self {
        Self(BTreeMap::new())
    }
    fn insert(&mut self, path: PathBuf, bytes: Vec<u8>) -> Result<()> {
        if !relative(&path)
            || bytes.len() > MAX_LEAF
            || self.0.len() >= MAX_LEAVES
            || self.0.contains_key(&path)
            || self
                .0
                .values()
                .map(|b| b.len())
                .sum::<usize>()
                .saturating_add(bytes.len())
                > MAX_STAGE
        {
            return Err(refuse());
        }
        self.0.insert(path, Zeroizing::new(bytes));
        Ok(())
    }

    fn generation(&self, domain: &[u8]) -> String {
        let mut hash = Sha256::new();
        hash.update(domain);
        for (path, bytes) in &self.0 {
            let name = path.as_os_str().as_encoded_bytes();
            hash.update((name.len() as u64).to_le_bytes());
            hash.update(name);
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes.as_slice());
        }
        format!("{:x}", hash.finalize())
    }
}

/// Every authority operation is synchronous and keeps its admitted descriptors
/// alive until publication/rollback finishes. Implementations must not re-read
/// original selected bytes; the durable witness contains metadata/namespace only.
#[cfg(test)]
trait Publication {
    fn verify_original_generation(&mut self) -> Result<()>;
    fn publish_old_config(&mut self, old: &Leaves, service_uid: u32) -> Result<()>;
    fn publish_prior_state_if_absent(&mut self, old: &Leaves) -> Result<()>;
    fn publish_final_config(&mut self, accepted: &Leaves) -> Result<()>;
    fn verify_published(
        &mut self,
        accepted: &Leaves,
        allow_redirect_dns_projection: bool,
    ) -> Result<Leaves>;
    fn publish_administrative_metadata(&mut self, accepted: &Leaves) -> Result<()>;
    fn restore_old_generations(&mut self, old: &Leaves) -> Result<()>;
}
/// Complete phase rules independent of command re-entry. The fd-backed store
/// writes the new phase only after this publication succeeds. Failed publishing
/// leaves the prior phase and all old bytes available for explicit rollback.
#[cfg(test)]
struct Transaction {
    header: Header,
    old: Leaves,
    accepted: Leaves,
}
#[cfg(test)]
impl Transaction {
    fn verify_sealed(&self, uid: u32) -> Result<()> {
        self.header.validate(uid)?;
        let plan_bytes = self
            .accepted
            .0
            .get(Path::new("metadata/auto-install-plan.json"))
            .ok_or_else(refuse)?;
        let staged_plan: serde_json::Value =
            serde_json::from_slice(plan_bytes).map_err(|_| refuse())?;
        let profile_bytes = self
            .accepted
            .0
            .get(Path::new("metadata/wide-profile.json"))
            .ok_or_else(refuse)?;
        let staged_profile: serde_json::Value =
            serde_json::from_slice(profile_bytes).map_err(|_| refuse())?;
        if staged_plan != self.header.plan
            || staged_profile["product_mode"] != self.header.mode.name()
        {
            return Err(refuse());
        }
        if self.old.generation(b"aegis-auto-original-v1\0") != self.header.input_generation
            || self.accepted.generation(b"aegis-auto-accepted-v1\0")
                != self.header.accepted_generation
        {
            return Err(refuse());
        }
        Ok(())
    }
    fn verify_before_custody(&self, authority: &mut dyn Publication) -> Result<()> {
        self.verify_sealed(self.header.administrator_uid)?;
        self.header.require(Phase::Prepared)?;
        authority.verify_original_generation()
    }
    fn custody(
        &mut self,
        authority: &mut dyn Publication,
        uid: u32,
        was_active: bool,
    ) -> Result<()> {
        self.verify_before_custody(authority)?;
        authority.publish_old_config(&self.old, uid)?;
        self.header.service_uid = Some(uid);
        self.header.service_was_active = Some(was_active);
        self.header.phase = Phase::Custody;
        Ok(())
    }
    fn state(&mut self, authority: &mut dyn Publication) -> Result<()> {
        self.verify_sealed(self.header.administrator_uid)?;
        self.header.require(Phase::Custody)?;
        authority.publish_prior_state_if_absent(&self.old)?;
        self.header.phase = Phase::State;
        Ok(())
    }
    fn config(&mut self, authority: &mut dyn Publication) -> Result<()> {
        self.verify_sealed(self.header.administrator_uid)?;
        self.header.require(Phase::State)?;
        authority.publish_final_config(&self.accepted)?;
        // No source bytes are read here; acceptance checks the staged generation.
        authority.verify_published(&self.accepted, false)?;
        self.header.phase = Phase::Config;
        Ok(())
    }
    fn metadata(&mut self, authority: &mut dyn Publication) -> Result<()> {
        self.verify_sealed(self.header.administrator_uid)?;
        self.header.require(Phase::Config)?;
        authority.verify_published(&self.accepted, false)?;
        authority.publish_administrative_metadata(&self.accepted)?;
        self.header.phase = Phase::Metadata;
        Ok(())
    }
    fn begin_capture(&mut self) -> Result<()> {
        self.verify_sealed(self.header.administrator_uid)?;
        self.header.require(Phase::Metadata)?;
        if self.header.mode == AutoMode::SocksOnly {
            return Err(refuse());
        }
        self.header.capture_started = true;
        Ok(())
    }
    fn finalize(&mut self, authority: &mut dyn Publication) -> Result<()> {
        self.verify_sealed(self.header.administrator_uid)?;
        self.header.require(Phase::Metadata)?;
        let redirect = self.header.mode == AutoMode::WideRedirectSafe;
        if self.header.mode != AutoMode::SocksOnly && !self.header.capture_started {
            return Err(refuse());
        }
        let observed = authority.verify_published(&self.accepted, redirect)?;
        // Only a typed whole-document comparison may admit the three-key DNS
        // projection. No caller-provided JSON/hash can broaden that acceptance.
        if redirect {
            self.accepted = observed;
            self.header.accepted_generation = self.accepted.generation(b"aegis-auto-accepted-v1\0");
        }
        self.header.phase = Phase::Finalized;
        Ok(())
    }
    fn rollback(&mut self, authority: &mut dyn Publication, capture_started: bool) -> Result<()> {
        self.verify_sealed(self.header.administrator_uid)?;
        if self.header.phase == Phase::Finalized || self.header.phase == Phase::RolledBack {
            return Err(refuse());
        }
        if capture_started || self.header.capture_started {
            self.header.capture_started = true;
            self.header.phase = Phase::NativeRecoveryRequired;
            return Err("AUTO capture requires separately authorized native recovery; private stage retained".into());
        }
        if self.header.phase != Phase::Prepared {
            authority.restore_old_generations(&self.old)?;
        }
        self.header.phase = Phase::RolledBack;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_rollback_leaf_requires_one_stable_private_regular_file() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{symlink, PermissionsExt};

        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let held = std::fs::File::open(dir.path()).unwrap();
        let leaf = dir.path().join("archived-leaf.json");
        std::fs::write(&leaf, b"ok").unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_fresh_rollback_leaf(held.as_raw_fd(), "archived-leaf.json", 2).unwrap(),
            b"ok"
        );

        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_fresh_rollback_leaf(held.as_raw_fd(), "archived-leaf.json", 2).is_err());
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_fresh_rollback_leaf(held.as_raw_fd(), "archived-leaf.json", 1).is_err());

        std::fs::remove_file(&leaf).unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"ok").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &leaf).unwrap();
        assert!(read_fresh_rollback_leaf(held.as_raw_fd(), "archived-leaf.json", 2).is_err());

        std::fs::remove_file(&leaf).unwrap();
        std::fs::hard_link(&target, &leaf).unwrap();
        assert!(read_fresh_rollback_leaf(held.as_raw_fd(), "archived-leaf.json", 2).is_err());
        std::fs::remove_file(&leaf).unwrap();
        assert!(read_fresh_rollback_leaf(held.as_raw_fd(), "archived-leaf.json", 2).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_prebind_pointer_retirement_is_atomic_and_idempotent() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let held = std::fs::File::open(dir.path()).unwrap();
        let pointer = b"protected pending pointer";
        let archive = fresh_prebind_archive_leaf(pointer);
        let current = dir.path().join("current.json");
        std::fs::write(&current, pointer).unwrap();
        std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o600)).unwrap();
        fresh_prebind_retire_pointer(held.as_raw_fd(), pointer, &archive).unwrap();
        assert!(!current.exists());
        assert_eq!(std::fs::read(dir.path().join(&archive)).unwrap(), pointer);
        fresh_prebind_retire_pointer(held.as_raw_fd(), pointer, &archive).unwrap();
        assert_eq!(
            fresh_prebind_archives(held.as_raw_fd()).unwrap(),
            vec![archive]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_prebind_rename_before_directory_sync_converges_on_retry() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let held = std::fs::File::open(dir.path()).unwrap();
        let pointer = b"protected pending pointer";
        let archive = fresh_prebind_archive_leaf(pointer);
        let current = dir.path().join("current.json");
        std::fs::write(&current, pointer).unwrap();
        std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(fresh_prebind_retire_pointer_with_cut(
            held.as_raw_fd(),
            pointer,
            &archive,
            || Err(refuse()),
        )
        .is_err());
        assert!(!current.exists());
        assert_eq!(std::fs::read(dir.path().join(&archive)).unwrap(), pointer);
        fresh_prebind_retire_pointer(held.as_raw_fd(), pointer, &archive).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_prebind_pointer_retirement_refuses_foreign_and_recovers_old_cut() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let held = std::fs::File::open(dir.path()).unwrap();
        let pointer = b"protected pending pointer";
        let current = dir.path().join("current.json");
        let old_archive = "archived-0123456789abcdef0123456789abcdef.json";
        std::fs::write(&current, pointer).unwrap();
        std::fs::write(dir.path().join(old_archive), b"foreign").unwrap();
        std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(
            dir.path().join(old_archive),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(fresh_prebind_retire_pointer(held.as_raw_fd(), pointer, old_archive).is_err());
        assert!(current.exists());
        std::fs::write(dir.path().join(old_archive), pointer).unwrap();
        fresh_prebind_retire_pointer(held.as_raw_fd(), pointer, old_archive).unwrap();
        assert!(!current.exists());
        fresh_prebind_retire_pointer(held.as_raw_fd(), pointer, old_archive).unwrap();
        let second = "archived-fedcba9876543210fedcba9876543210.json";
        std::fs::write(dir.path().join(second), pointer).unwrap();
        std::fs::set_permissions(
            dir.path().join(second),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(fresh_prebind_retire_pointer(held.as_raw_fd(), pointer, old_archive).is_err());
    }

    struct Authority {
        events: Vec<&'static str>,
        changed: bool,
        fail: Option<&'static str>,
    }
    impl Authority {
        fn call(&mut self, name: &'static str) -> Result<()> {
            self.events.push(name);
            if self.fail == Some(name) {
                Err(refuse())
            } else {
                Ok(())
            }
        }
    }
    impl Publication for Authority {
        fn verify_original_generation(&mut self) -> Result<()> {
            self.call("verify")?;
            if self.changed {
                Err(refuse())
            } else {
                Ok(())
            }
        }
        fn publish_old_config(&mut self, _: &Leaves, _: u32) -> Result<()> {
            self.call("custody")
        }
        fn publish_prior_state_if_absent(&mut self, _: &Leaves) -> Result<()> {
            self.call("state")
        }
        fn publish_final_config(&mut self, _: &Leaves) -> Result<()> {
            self.call("config")
        }
        fn verify_published(&mut self, accepted: &Leaves, _: bool) -> Result<Leaves> {
            self.call("verify-published")?;
            let mut copy = Leaves::new();
            for (p, b) in &accepted.0 {
                copy.insert(p.clone(), b.to_vec())?;
            }
            Ok(copy)
        }
        fn publish_administrative_metadata(&mut self, _: &Leaves) -> Result<()> {
            self.call("metadata")
        }
        fn restore_old_generations(&mut self, _: &Leaves) -> Result<()> {
            self.call("restore")
        }
    }
    #[test]
    fn dropin_restored_record_route_requires_typed_purpose_and_exact_pending_intent() {
        use super::store_context::{dropin_record_route, DropinRecordRoute, UnitOperation};
        let mut tx = fixture();
        tx.header.new_unit_namespace = Some("accepted/unit-target/namespace.json".into());
        tx.header.unit_pending =
            Some("receipts/unit-target/dropins/restored/publication-intent.json".into());
        for phase in [Phase::Config, Phase::Metadata, Phase::Finalized] {
            tx.header.phase = phase;
            assert!(matches!(
                dropin_record_route(
                    &tx.header,
                    Some(UnitOperation::RestoreAcceptedManager),
                    true
                ),
                Ok(DropinRecordRoute::AcceptedRestoration)
            ));
            assert!(dropin_record_route(&tx.header, Some(UnitOperation::Publish), true).is_err());
            assert!(dropin_record_route(&tx.header, Some(UnitOperation::Rollback), true).is_err());
            assert!(dropin_record_route(
                &tx.header,
                Some(UnitOperation::RestoreAcceptedManager),
                false
            )
            .is_err());
        }
        tx.header.capture_started = true;
        assert!(dropin_record_route(
            &tx.header,
            Some(UnitOperation::RestoreAcceptedManager),
            true
        )
        .is_err());
        tx.header.capture_started = false;
        tx.header.phase = Phase::Custody;
        assert!(dropin_record_route(
            &tx.header,
            Some(UnitOperation::RestoreAcceptedManager),
            true
        )
        .is_err());
        tx.header.phase = Phase::Metadata;
        tx.header.unit_pending = None;
        assert!(dropin_record_route(
            &tx.header,
            Some(UnitOperation::RestoreAcceptedManager),
            true
        )
        .is_err());
        // Structural routing only: the consumer still checks real Store/manager
        // proof before publishing; this test grants no accepted capability.
    }
    #[test]
    fn restored_manager_pointer_is_fixed_bound_and_cannot_coexist_with_pending() {
        let mut tx = fixture();
        let leaf = PathBuf::from("receipts/unit-target/restored-manager.json");
        tx.header.unit_restored_manager = Some(leaf.clone());
        assert!(tx.header.validate(7).is_err());
        tx.header.new_unit_namespace = Some("accepted/unit-target/namespace.json".into());
        assert!(tx.header.validate(7).is_err());
        tx.header.unit_records.insert(leaf.clone(), "a".repeat(64));
        assert!(tx.header.validate(7).is_ok());
        let intent = PathBuf::from("receipts/unit-target/restore-manager-intent.json");
        tx.header
            .unit_records
            .insert(intent.clone(), "b".repeat(64));
        tx.header.unit_pending = Some(intent);
        assert!(tx.header.validate(7).is_err());
        tx.header.unit_pending = None;
        tx.header.unit_restored_manager = Some("receipts/unit-target/foreign.json".into());
        assert!(tx.header.validate(7).is_err());
        // Header shape alone is not a restored manager receipt or actor proof.
    }
    fn fixture() -> Transaction {
        let mut old = Leaves::new();
        old.insert("config/aegis.toml".into(), b"private original".to_vec())
            .unwrap();
        let mut accepted = Leaves::new();
        accepted
            .insert("config/aegis.toml".into(), b"private rendered".to_vec())
            .unwrap();
        accepted.insert("metadata/auto-install-plan.json".into(),serde_json::to_vec(&serde_json::json!({"schema":"aegis_auto_install_plan_v1","status":"planned","product_mode":"socks-only","connectivity_verified":false})).unwrap()).unwrap();
        accepted
            .insert(
                "metadata/wide-profile.json".into(),
                serde_json::to_vec(&serde_json::json!({"product_mode":"socks-only"})).unwrap(),
            )
            .unwrap();
        let header = Header {
            protocol: PROTOCOL.into(),
            administrator_uid: 7,
            config_root: "/etc/aegis/client".into(),
            state_dir: "/var/lib/aegis".into(),
            metadata_dir: "/var/lib/aegis-install/client".into(),
            phase: Phase::Prepared,
            transaction_nonce: "00112233445566778899aabbccddeeff".into(),
            current_records: BTreeMap::new(),
            active_records: BTreeMap::new(),
            pending: None,
            mode: AutoMode::SocksOnly,
            plan: serde_json::json!({"schema":"aegis_auto_install_plan_v1","status":"planned","product_mode":"socks-only","connectivity_verified":false}),
            old_unit_namespace: None,
            new_unit_namespace: None,
            runtime_events: "/dev/null".into(),
            unit_policy_recipe: None,
            unit_records: BTreeMap::new(),
            unit_role_records: BTreeMap::new(),
            unit_pending: None,
            unit_forward_transitions: BTreeMap::new(),
            unit_restorations: BTreeMap::new(),
            unit_restored_manager: None,
            runtime_binding: None,
            installed_receipt_recipe: None,
            service_uid: None,
            service_gid: None,
            state_records: BTreeMap::new(),
            namespace_records: BTreeMap::new(),
            service_was_active: None,
            capture_started: false,
            leaves: BTreeMap::new(),
            input_generation: old.generation(b"aegis-auto-original-v1\0"),
            accepted_generation: accepted.generation(b"aegis-auto-accepted-v1\0"),
            planned_generation: accepted.generation(b"aegis-auto-accepted-v1\0"),
            render_recipe: "accepted/render-recipe.json".into(),
        };
        Transaction {
            header,
            old,
            accepted,
        }
    }
    fn authority() -> Authority {
        Authority {
            events: vec![],
            changed: false,
            fail: None,
        }
    }
    #[test]
    fn positive_fixture_nonce_matches_producer_and_17_bytes_refuse_before_authority() {
        let mut tx = fixture();
        // Production Header creation hex-encodes exactly sixteen random bytes.
        // This public diagnostic input tests the same shape without randomness.
        let producer_shape = hex::encode([0u8; 16]);
        assert_eq!(tx.header.transaction_nonce.len(), producer_shape.len());
        assert_eq!(producer_shape.len(), 32);
        tx.header.validate(7).unwrap();
        tx.header.transaction_nonce = producer_shape;
        tx.header.validate(7).unwrap();
        tx.header.transaction_nonce = hex::encode([0u8; 17]);
        assert_eq!(tx.header.transaction_nonce.len(), 34);
        let mut a = authority();
        assert!(tx.custody(&mut a, 8, false).is_err());
        assert!(a.events.is_empty());
        assert!(tx.header.service_uid.is_none());
        assert!(tx.header.phase == Phase::Prepared);
    }
    #[test]
    fn typed_phase_order_refuses_without_publication() {
        let mut tx = fixture();
        let mut a = authority();
        assert!(tx.config(&mut a).is_err());
        assert!(tx.metadata(&mut a).is_err());
        assert!(tx.finalize(&mut a).is_err());
        assert!(a.events.is_empty());
    }
    #[test]
    fn original_generation_change_refuses_before_custody() {
        let mut tx = fixture();
        let mut a = authority();
        a.changed = true;
        assert!(tx.custody(&mut a, 8, true).is_err());
        assert_eq!(a.events, vec!["verify"]);
        assert!(tx.header.service_uid.is_none());
        assert!(tx.header.phase == Phase::Prepared);
    }
    #[test]
    fn complete_order_preserves_service_fact_and_finishes() {
        let mut tx = fixture();
        let mut a = authority();
        tx.verify_sealed(7).unwrap();
        tx.custody(&mut a, 8, true).unwrap();
        tx.state(&mut a).unwrap();
        tx.config(&mut a).unwrap();
        tx.metadata(&mut a).unwrap();
        tx.finalize(&mut a).unwrap();
        assert_eq!(
            a.events,
            vec![
                "verify",
                "custody",
                "state",
                "config",
                "verify-published",
                "verify-published",
                "metadata",
                "verify-published"
            ]
        );
        assert_eq!(tx.header.service_was_active, Some(true));
        assert!(tx.header.phase == Phase::Finalized);
    }
    #[test]
    fn failed_publication_keeps_old_stage_for_explicit_restore() {
        let mut tx = fixture();
        let mut a = authority();
        tx.custody(&mut a, 8, false).unwrap();
        tx.state(&mut a).unwrap();
        a.fail = Some("config");
        assert!(tx.config(&mut a).is_err());
        assert!(tx.header.phase == Phase::State);
        a.fail = None;
        tx.rollback(&mut a, false).unwrap();
        assert_eq!(a.events.last(), Some(&"restore"));
        assert!(tx.header.phase == Phase::RolledBack);
    }
    #[test]
    fn prepared_rollback_never_restores_or_publishes_old_generations() {
        let mut tx = fixture();
        let mut a = authority();
        tx.rollback(&mut a, false).unwrap();
        assert!(a.events.is_empty());
        assert!(tx.header.phase == Phase::RolledBack);
        assert!(!tx.header.capture_started);
        assert!(tx.rollback(&mut a, false).is_err());
    }
    #[test]
    fn model_begin_capture_requires_metadata_and_then_blocks_rollback() {
        let mut tx = fixture();
        let mut a = authority();
        tx.header.mode = AutoMode::WideRedirectSafe;
        tx.header.plan["product_mode"] = serde_json::Value::String("wide-redirect-safe".into());
        tx.accepted.0.insert(
            "metadata/auto-install-plan.json".into(),
            Zeroizing::new(serde_json::to_vec(&tx.header.plan).unwrap()),
        );
        tx.accepted.0.insert(
            "metadata/wide-profile.json".into(),
            Zeroizing::new(
                serde_json::to_vec(&serde_json::json!({"product_mode":"wide-redirect-safe"}))
                    .unwrap(),
            ),
        );
        tx.header.accepted_generation = tx.accepted.generation(b"aegis-auto-accepted-v1\0");
        tx.header.planned_generation = tx.header.accepted_generation.clone();
        assert!(tx.begin_capture().is_err());
        tx.custody(&mut a, 8, false).unwrap();
        tx.state(&mut a).unwrap();
        tx.config(&mut a).unwrap();
        tx.metadata(&mut a).unwrap();
        tx.begin_capture().unwrap();
        assert!(tx.header.capture_started);
        assert!(tx.rollback(&mut a, false).is_err());
        assert!(tx.header.phase == Phase::NativeRecoveryRequired);
    }
    #[test]
    fn late_capture_rollback_does_not_release_native_guards() {
        let mut tx = fixture();
        let mut a = authority();
        tx.custody(&mut a, 8, false).unwrap();
        a.events.clear();
        assert!(tx.rollback(&mut a, true).is_err());
        assert!(a.events.is_empty());
        assert!(tx.header.phase == Phase::NativeRecoveryRequired);
    }
    #[test]
    fn input_and_final_domains_and_owned_substitution_are_distinct() {
        let mut tx = fixture();
        assert_ne!(
            tx.old.generation(b"aegis-auto-original-v1\0"),
            tx.old.generation(b"aegis-auto-accepted-v1\0")
        );
        tx.old.0.get_mut(Path::new("config/aegis.toml")).unwrap()[0] = b'X';
        assert!(tx.verify_sealed(7).is_err());
        assert_eq!(
            &tx.accepted.0[Path::new("config/aegis.toml")][..],
            b"private rendered"
        );
    }
    #[test]
    fn path_roles_cannot_escape_or_duplicate_staged_entries() {
        let mut values = Leaves::new();
        for path in ["../config", "/etc/private", "", "one/../../victim"] {
            assert!(values.insert(path.into(), vec![1]).is_err());
        }
        values.insert("config/aegis.toml".into(), vec![1]).unwrap();
        assert!(values.insert("config/aegis.toml".into(), vec![2]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires disposable Linux root filesystem"]
    fn current_socks_pointer_binds_fresh_active_stage_and_refuses_foreign_pending() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            std::env::var("AEGIS_SUCCESSOR_ARCHIVE_TEST_DISPOSABLE").as_deref(),
            Ok("1")
        );
        let dir = std::env::temp_dir().join(format!("aegis-socks-pointer-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = std::fs::File::open(&dir).unwrap();
        let active = serde_json::json!({
            "stage": {"path": "/run/aegis-installer-config-snapshots/stage"},
            "terminal": {"boot_id": "01234567-89ab-cdef-0123-456789abcdef"},
            "input": {"candidate_sha256": "a".repeat(64)},
        });
        let pointer = serde_json::json!({
            "schema": "aegis_installer_auto_v2_stage_v2",
            "stage": active["stage"]["path"], "status": "pending",
            "boot_id": active["terminal"]["boot_id"],
            "installed_binary": "/usr/local/bin/aegis-client",
            "candidate_sha256": active["input"]["candidate_sha256"],
            "previous_binary": null,
        });
        let leaf = dir.join("current.json");
        std::fs::write(&leaf, serde_json::to_vec(&pointer).unwrap()).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o600)).unwrap();
        verify_current_active_pointer(held.as_raw_fd(), &active).unwrap();
        let mut foreign = pointer.clone();
        foreign["candidate_sha256"] = serde_json::json!("b".repeat(64));
        std::fs::write(&leaf, serde_json::to_vec(&foreign).unwrap()).unwrap();
        assert!(verify_current_active_pointer(held.as_raw_fd(), &active).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(target_os = "linux")]
mod durable {
    use super::*;
    use crate::profile_auto_stopped_service::InstallLock;
    use std::{
        cell::RefCell,
        ffi::{CStr, CString},
        fs::File,
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
            unix::ffi::OsStrExt,
        },
        sync::{Mutex, MutexGuard, OnceLock},
    };
    const PREPARE_HANDOFF: &str = "/var/lib/aegis-auto/control/prepare-current.json";
    const PREPARE_COMPLETED: &str = "prepare-completed.json";
    const PREPARE_STAGE_CREATED: &str = "prepare-stage-created.json";
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PrepareIntent {
        schema: String,
        phase: String,
        boot_id: String,
        stage: PathBuf,
        candidate_binary: PathBuf,
        public_payload_root: PathBuf,
        nonce: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        boot_intent_sha256: Option<String>,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PrepareCompletion {
        schema: String,
        phase: String,
        intent_sha256: String,
        stage: PathBuf,
        stage_device: u64,
        stage_inode: u64,
        header_sha256: String,
        input_generation: String,
        candidate_sha256: String,
        provenance_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        boot_intent_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stage_created_sha256: Option<String>,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PrepareStageCreated {
        schema: String,
        prepare_intent_sha256: String,
        boot_intent_sha256: String,
        boot_id: String,
        stage: PathBuf,
        stage_device: u64,
        stage_inode: u64,
        candidate_binary: PathBuf,
        public_payload_root: PathBuf,
    }
    fn prepare_control(path: &Path) -> Result<OwnedFd> {
        if path != Path::new(PREPARE_HANDOFF) {
            return Err(refuse());
        }
        open_absolute(Path::new("/var/lib/aegis-auto/control"), 0, true)
    }
    fn prepare_write(parent: RawFd, name: &str, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(refuse());
        }
        let leaf = c(name)?;
        let raw = fd(unsafe {
            libc::openat(
                parent,
                leaf.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        })?;
        let mut file = File::from(raw);
        // A failed write or sync is sticky. Unlinking could erase the only
        // evidence that creation of a private stage was attempted.
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| refuse())?;
        let identity = stat(file.as_raw_fd())?;
        if identity.st_mode != (libc::S_IFREG | 0o600)
            || identity.st_uid != 0
            || identity.st_gid != 0
            || identity.st_nlink != 1
            || unsafe { libc::fsync(parent) } != 0
        {
            return Err(refuse());
        }
        Ok(())
    }
    fn prepare_read(parent: RawFd, name: &str) -> Result<Vec<u8>> {
        let leaf = c(name)?;
        let held = fd(unsafe {
            libc::openat(
                parent,
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        })?;
        let identity = stat(held.as_raw_fd())?;
        if identity.st_mode != (libc::S_IFREG | 0o600)
            || identity.st_uid != 0
            || identity.st_gid != 0
            || identity.st_nlink != 1
            || identity.st_size <= 0
            || identity.st_size > 4096
        {
            return Err(refuse());
        }
        let mut bytes = Vec::new();
        File::from(held)
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| refuse())?;
        if bytes.len() != identity.st_size as usize {
            return Err(refuse());
        }
        Ok(bytes)
    }
    const ACTIVATION_INTENT: &str = "activation-intent.json";
    const ACTIVATION_CONSUMED: &str = "activation-consumed.json";
    // R8's uncalled supervisor model uses this separate one-shot leaf. Its
    // presence must revoke ordinary stage publication even when malformed or
    // orphaned; it is never positive activation authority by itself.
    const ACTIVATION_SUPERVISOR_ONCE: &str = "activation-intent-once";
    // R15 prerequisite only: presence is an ambiguous manager-call marker,
    // never positive activation authority in this source cohort.
    const ACTIVATION_OWNER_MAY_SEND: &str = "activation-owner-may-send.json";
    // Separate source-only post-marker protocol. These leaves revoke every
    // ordinary Store reentry by presence, including torn or foreign bytes.
    const ACTIVATION_OWNER_MAY_SEND_V2: &str = "activation-owner-may-send-v2.json";
    const ACTIVATION_OWNER_CLAIM_V2: &str = "activation-owner-claim-v2.json";
    const ACTIVATION_OWNER_MAY_SEND_V3: &str = "activation-owner-may-send-v3.json";
    const ACTIVATION_OWNER_CLAIM_V3: &str = "activation-owner-claim-v3.json";
    const ACTIVATION_OWNER_SUBMITTED: &str = "receipts/activation-owner/submitted.json";
    const ACTIVATION_OWNER_COMPLETED: &str = "receipts/activation-owner/completed.json";
    const ACTIVATION_OWNER_LAUNCH_CONSUMED: &str = "receipts/activation-owner/launch-consumed.json";
    const ACTIVATION_OWNER_STOP_SUBMITTED: &str = "receipts/activation-owner/stop-submitted.json";
    const ACTIVATION_OWNER_STOP_COMPLETED: &str = "receipts/activation-owner/stop-completed.json";
    const ACTIVATION_OWNER_TERMINAL: &str = "receipts/activation-owner/terminal.json";
    const ACTIVATION_OWNER_MARKER_ARCHIVE: &str = "receipts/activation-owner/marker-archive.json";
    const ACTIVATION_OWNER_POSTTERMINAL_STOP_INTENT: &str =
        "activation-owner-postterminal-stop.json";
    const ACTIVATION_OWNER_TERMINAL_HANDOFF: &str = "activation-owner-terminal-handoff.json";
    const ACTIVATION_OWNER_NATIVE_RECOVERY: &str = "activation-owner-native-recovery.json";
    const ACTIVATION_OWNER_POSTTERMINAL_COMPENSATED: &str =
        "receipts/activation-owner/postterminal-compensated.json";
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum StickyFault {
        None,
        #[cfg(test)]
        AfterCreate,
        #[cfg(test)]
        BeforeFileSync,
    }
    const MUTATION_LOCK: &str = ".stage-mutation.lock";
    const PUBLICATION_FENCE: &str = ".publication-fence.lock";
    fn reserved_lock_path(path: &Path) -> bool {
        matches!(
            path.components().next(),
            Some(Component::Normal(name))
                if name == std::ffi::OsStr::new(MUTATION_LOCK)
                    || name == std::ffi::OsStr::new(PUBLICATION_FENCE)
                    // Only a future protected supervisor constructor may
                    // create this stage-root name. Store's ordinary writer
                    // must not mint a marker which it treats as revocation.
                    || name == std::ffi::OsStr::new(ACTIVATION_SUPERVISOR_ONCE)
                    || name == std::ffi::OsStr::new(ACTIVATION_OWNER_MAY_SEND)
                    || name == std::ffi::OsStr::new(ACTIVATION_OWNER_MAY_SEND_V2)
                    || name == std::ffi::OsStr::new(ACTIVATION_OWNER_CLAIM_V2)
                    || name == std::ffi::OsStr::new(ACTIVATION_OWNER_MAY_SEND_V3)
                    || name == std::ffi::OsStr::new(ACTIVATION_OWNER_CLAIM_V3)
                    || name == std::ffi::OsStr::new(ACTIVATION_OWNER_POSTTERMINAL_STOP_INTENT)
                    || name == std::ffi::OsStr::new(ACTIVATION_OWNER_TERMINAL_HANDOFF)
                    || name == std::ffi::OsStr::new(ACTIVATION_OWNER_NATIVE_RECOVERY)
                    || name == std::ffi::OsStr::new(finalized_stop::INTENT)
        )
    }
    static MUTATION_THREAD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    struct MutationGuard {
        _process: OwnedFd,
        _thread: Option<MutexGuard<'static, ()>>,
    }
    // Only a synchronous closure borrowing the original owner may install
    // this thread-local scope. It is checked against the held activation root
    // and both exact one-use marker bytes on every Store mutation. A reopened
    // worker cannot construct it, and an unrelated stage cannot use it.
    #[derive(Clone)]
    struct OwnerScope {
        activation_id: (u64, u64),
        stage_id: (u64, u64),
        stage_path: PathBuf,
        marker: Option<OwnerScopeMarker>,
        inverse_after_terminal: bool,
        publication_fd: RawFd,
        mutation_fd: RawFd,
    }
    #[derive(Clone)]
    struct OwnerScopeMarker {
        may_send_sha256: String,
        claim_sha256: String,
        may_send_leaf: &'static str,
        claim_leaf: &'static str,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OwnerMarkerArchive {
        schema: u32,
        may_send_hex: String,
        claim_hex: String,
        may_send_sha256: String,
        claim_sha256: String,
    }
    thread_local! {
        static CURRENT_OWNER: RefCell<Option<OwnerScope>> = const { RefCell::new(None) };
        static FRESH_STOP_READ: RefCell<Option<FreshStopReadScope>> = const { RefCell::new(None) };
    }
    // This borrows the original mutation OFD only for sub_store(false). It
    // never grants writer admission or creates a second thread mutex guard.
    #[derive(Clone)]
    struct FreshStopReadScope {
        stage_id: (u64, u64),
        stage_path: PathBuf,
        header_sha256: String,
        terminal_sha256: String,
        publication_fd: RawFd,
        mutation_fd: RawFd,
    }
    pub(super) struct RestoreFreshStopReadScope;
    impl Drop for RestoreFreshStopReadScope {
        fn drop(&mut self) {
            FRESH_STOP_READ.with(|current| *current.borrow_mut() = None);
        }
    }
    struct RestoreOwnerScope;
    impl Drop for RestoreOwnerScope {
        fn drop(&mut self) {
            CURRENT_OWNER.with(|current| *current.borrow_mut() = None);
        }
    }
    /// Hold this across the complete external check, target effect and durable
    /// receipt interval. The recovery-only seal takes the opposing exclusive
    /// lock; this primitive does not itself authorize any target publication.
    pub(crate) struct PublicationLease {
        _process: OwnedFd,
    }
    /// Locks acquired before StageGuard takes the stage-root flock. The
    /// returned value owns both leases, so a later StageGuard admission cannot
    /// invert publication -> mutation -> stage-root order.
    #[allow(dead_code)]
    pub(super) struct OwnerStageLocks {
        store: Store,
        publication: PublicationLease,
        mutation: MutationGuard,
        stage_id: (u64, u64),
        activation_id: (u64, u64),
        uid: u32,
    }
    /// The same Store that took the prelocks has been moved into StageGuard.
    /// No caller-supplied reopened Store can be substituted at bind time.
    #[allow(dead_code)]
    pub(super) struct OwnerStageSession {
        stage: super::authority::StageGuard,
        publication: Option<PublicationLease>,
        mutation: Option<MutationGuard>,
        stage_id: (u64, u64),
        activation_id: (u64, u64),
        uid: u32,
    }
    /// Same-process continuation derived from the original admitted StageGuard.
    /// The Store is duplicated from held descriptors, never reopened by name;
    /// all three original locks remain owned until terminal handling ends.
    pub(super) struct OwnerContinuation {
        store: Store,
        publication: Option<PublicationLease>,
        mutation: Option<MutationGuard>,
        stage_id: (u64, u64),
        activation_id: (u64, u64),
        uid: u32,
        marker_sha256: Option<String>,
        claim_sha256: Option<String>,
        marker_attempted: bool,
        product_commitments: Option<OwnerProductCommitments>,
        submitted_sha256: Option<String>,
        submitted_job: Option<(u32, String)>,
        completed_sha256: Option<String>,
        launch_consumed_sha256: Option<String>,
        start_invocation: Option<String>,
        stop_submitted_sha256: Option<String>,
        stop_submitted_job: Option<(u32, String)>,
        stop_completed_sha256: Option<String>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum OwnerMarkerState {
        Fresh,
        RecoveryRequired,
    }
    /// Read-only identity for an installed actor handoff. This is not a
    /// may-send grant: a separate protected deny ACK and durable marker are
    /// still required before one PID-1 mutating call.
    #[allow(dead_code)]
    #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
    pub(super) struct OwnerBinding {
        pub(super) transaction_nonce: String,
        pub(super) planned_generation: String,
        pub(super) stage: (u64, u64),
        pub(super) header_sha256: String,
    }
    /// Holds every Store-side fence across inspection and one-use marker write.
    /// It does not own PID1, InstallLock, deny, capture or compensation.
    #[allow(dead_code)]
    pub(super) struct OwnerMarkerFence<'a> {
        store: &'a Store,
        state: OwnerMarkerState,
        _publication: PublicationLease,
        _mutation: MutationGuard,
    }
    #[allow(dead_code)]
    impl OwnerStageLocks {
        /// Move the held Store into the admitted StageGuard while the
        /// publication and mutation locks remain owned by this value.
        pub(super) fn admit(self) -> Result<OwnerStageSession> {
            if unsafe { libc::geteuid() } != 0 || self.uid != 0 {
                return Err(refuse());
            }
            self.admit_with(super::authority::StageGuard::admit)
        }
        #[cfg(test)]
        pub(super) fn admit_fixture(self, uid: u32) -> Result<OwnerStageSession> {
            if unsafe { libc::geteuid() } != uid || self.uid != uid {
                return Err(refuse());
            }
            self.admit_with(|store| super::authority::StageGuard::admit_fixture(store, uid))
        }
        fn admit_with<F>(self, admit: F) -> Result<OwnerStageSession>
        where
            F: FnOnce(Store) -> Result<super::authority::StageGuard>,
        {
            let stage = admit(self.store)?;
            Ok(OwnerStageSession {
                stage,
                publication: Some(self.publication),
                mutation: Some(self.mutation),
                stage_id: self.stage_id,
                activation_id: self.activation_id,
                uid: self.uid,
            })
        }
    }
    #[allow(dead_code)]
    impl OwnerStageSession {
        pub(super) fn split(self) -> Result<(super::authority::StageGuard, OwnerContinuation)> {
            self.stage.revalidate_owner_pre_marker()?;
            let store = self.stage.store.clone_held()?;
            if store.identity()? != self.stage_id || store.uid != self.uid {
                return Err(refuse());
            }
            let activation = stat(store.activation_root.as_raw_fd())?;
            if (activation.st_dev as u64, activation.st_ino as u64) != self.activation_id {
                return Err(refuse());
            }
            Ok((
                self.stage,
                OwnerContinuation {
                    store,
                    publication: self.publication,
                    mutation: self.mutation,
                    stage_id: self.stage_id,
                    activation_id: self.activation_id,
                    uid: self.uid,
                    marker_sha256: None,
                    claim_sha256: None,
                    marker_attempted: false,
                    product_commitments: None,
                    submitted_sha256: None,
                    submitted_job: None,
                    completed_sha256: None,
                    launch_consumed_sha256: None,
                    start_invocation: None,
                    stop_submitted_sha256: None,
                    stop_submitted_job: None,
                    stop_completed_sha256: None,
                },
            ))
        }
        /// Pre-marker only. The returned fence borrows this retained StageGuard;
        /// it cannot outlive the stage or be rebound to a reopened Store.
        pub(super) fn bind(&mut self) -> Result<OwnerMarkerFence<'_>> {
            self.stage.revalidate_owner_pre_marker()?;
            let store = &self.stage.store;
            store.require_activation_root()?;
            let activation = stat(store.activation_root.as_raw_fd())?;
            if store.uid != self.uid
                || store.identity()? != self.stage_id
                || (activation.st_dev as u64, activation.st_ino as u64) != self.activation_id
            {
                return Err(refuse());
            }
            store.exclusive()?;
            if store.activation_leaf_present()? || store.leaf_present(ACTIVATION_OWNER_TERMINAL)? {
                return Err(refuse());
            }
            Ok(OwnerMarkerFence {
                store,
                state: OwnerMarkerState::Fresh,
                _publication: self.publication.take().ok_or_else(refuse)?,
                _mutation: self.mutation.take().ok_or_else(refuse)?,
            })
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OwnerMaySend {
        schema: u32,
        nonce: String,
        stage: (u64, u64),
        header_sha256: String,
    }
    /// The fields have no public constructor: only a future source-owned
    /// StageGuard/PID-1/native-deny adapter may mint authenticated inputs.
    /// This type is not a guard ACK or manager-call capability by itself.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
    pub(super) struct OwnerSendCommitments {
        binding: OwnerBinding,
        boot_id: String,
        pid1_owner: String,
        pid1_connection: u64,
        netns_ino: u64,
        private_unit: String,
        fixed_unit: String,
        launch_ticket_sha256: String,
        deny_ack_sha256: String,
        nft_sha256: String,
        route_rule_sha256: String,
    }
    /// Product marker binds the actual verified PID1 connection and the held
    /// installed guardian response. It has no caller-supplied private unit or
    /// synthetic launch/route digest fields from the older refusal-only model.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
    pub(super) struct OwnerProductCommitments {
        binding: OwnerBinding,
        mode: AutoMode,
        boot_id: String,
        pid1_socket: (u64, u64),
        pid1_netns: (u64, u64),
        installed_generation_sha256: String,
        installed_manifest_sha256: String,
        policy_generation: String,
        native_guard: Option<OwnerNativeGuardCommitment>,
        private_unit: String,
        fixed_unit: String,
        launch_ticket_sha256: String,
    }
    #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
    struct OwnerNativeGuardCommitment {
        guardian_pid: u32,
        guardian_nonce: String,
        guardian_receipt_sha256: String,
        policy_sha256: String,
    }
    #[derive(Serialize)]
    struct OwnerMaySendV3 {
        schema: u32,
        commitments: OwnerProductCommitments,
    }
    #[derive(Serialize)]
    struct OwnerClaimV3 {
        schema: u32,
        may_send_sha256: String,
        nonce: String,
        stage: (u64, u64),
    }
    #[derive(Serialize)]
    struct OwnerMaySendV2 {
        schema: u32,
        commitments: OwnerSendCommitments,
    }
    // The one-use claim remains an ambiguity record, never a PID-1 grant.
    // R26's guarded bridge may create it only while both held locks survive.
    #[derive(Serialize)]
    struct OwnerClaimV2 {
        schema: u32,
        may_send_sha256: String,
        nonce: String,
        stage: (u64, u64),
    }
    /// A retained post-marker lease, never reconstructible after process
    /// loss. It has no PID-1 method, capture grant or replay constructor.
    // These fields deliberately retain Store fences, the worker lock and
    // immutable commitments even though no production PID-1 sender exists.
    // The expectation must disappear when the source-owned actor consumes them.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "B-02 held fence and commitments await installed native actor; no production send authority"
        )
    )]
    pub(super) struct HeldPostMarker<'f, 'a> {
        fence: &'f mut OwnerMarkerFence<'a>,
        install_lock: Option<&'f InstallLock>,
        commitments: OwnerSendCommitments,
        marker_sha256: String,
        claimed: bool,
    }
    fn hex64(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }
    fn hex32(value: &str) -> bool {
        value.len() == 32
            && value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }
    impl OwnerSendCommitments {
        fn shape_valid(&self) -> bool {
            let Some(unit_digest) = self
                .private_unit
                .strip_prefix("aegis-auto@")
                .and_then(|name| name.strip_suffix(".service"))
            else {
                return false;
            };
            self.binding.stage.0 > 0
                && self.binding.stage.1 > 0
                && self.pid1_connection > 0
                && self.netns_ino > 0
                && self.boot_id.len() == 36
                && self.boot_id.is_ascii()
                && !self.pid1_owner.is_empty()
                && self.pid1_owner.is_ascii()
                && hex32(&self.binding.transaction_nonce)
                && hex64(&self.binding.planned_generation)
                && hex64(&self.binding.header_sha256)
                && hex64(unit_digest)
                && self.fixed_unit == "aegis-client.service"
                && self.private_unit != self.fixed_unit
                && hex64(&self.launch_ticket_sha256)
                && hex64(&self.deny_ack_sha256)
                && hex64(&self.nft_sha256)
                && hex64(&self.route_rule_sha256)
        }
    }
    impl OwnerProductCommitments {
        fn from_installed(
            binding: OwnerBinding,
            manager: &crate::profile_auto_stopped_service::pid1::ManagerIdentity,
            unit: &crate::profile_auto_stopped_service::pid1::PrivateUnit,
            installed: &super::owner_installed::ProtectedInstalledFacts<'_, '_>,
            launch: &crate::profile_auto_launch_service::LaunchOwnerLease,
            mode: AutoMode,
            native_guard: Option<OwnerNativeGuardCommitment>,
        ) -> Result<Self> {
            let installed = installed.current()?;
            launch.revalidate().map_err(|_| refuse())?;
            if launch.unit() != unit.name()
                || launch.stage_identity() != binding.stage
                || launch.boot_id() != manager.boot_id()
            {
                return Err(refuse());
            }
            let value = Self {
                binding,
                mode,
                boot_id: manager.boot_id().to_owned(),
                pid1_socket: manager.socket_identity(),
                pid1_netns: manager.netns_identity(),
                installed_generation_sha256: installed.installed_generation_sha256.to_owned(),
                installed_manifest_sha256: installed.installed_manifest_sha256.to_owned(),
                policy_generation: installed.policy_generation.to_owned(),
                native_guard,
                private_unit: unit.name().to_owned(),
                fixed_unit: "aegis-client.service".into(),
                launch_ticket_sha256: launch.ticket_sha256().to_owned(),
            };
            if !value.shape_valid() {
                return Err(refuse());
            }
            Ok(value)
        }
        pub(super) fn from_socks_verified(
            binding: OwnerBinding,
            manager: &crate::profile_auto_stopped_service::pid1::ManagerIdentity,
            unit: &crate::profile_auto_stopped_service::pid1::PrivateUnit,
            installed: &super::owner_installed::ProtectedInstalledFacts<'_, '_>,
            launch: &crate::profile_auto_launch_service::LaunchOwnerLease,
        ) -> Result<Self> {
            Self::from_installed(
                binding,
                manager,
                unit,
                installed,
                launch,
                AutoMode::SocksOnly,
                None,
            )
        }
        pub(super) fn from_wide_verified(
            binding: OwnerBinding,
            manager: &crate::profile_auto_stopped_service::pid1::ManagerIdentity,
            unit: &crate::profile_auto_stopped_service::pid1::PrivateUnit,
            installed: &super::owner_installed::ProtectedInstalledFacts<'_, '_>,
            launch: &crate::profile_auto_launch_service::LaunchOwnerLease,
            guardian: &crate::profile_auto_guardian::GuardDenyLease,
            mode: AutoMode,
        ) -> Result<Self> {
            if !matches!(mode, AutoMode::WideRedirectSafe | AutoMode::FullWideTun) {
                return Err(refuse());
            }
            guardian.revalidate().map_err(|_| refuse())?;
            if guardian.stage_identity() != binding.stage
                || guardian.boot_id() != manager.boot_id()
                || guardian.netns_ino() != manager.netns_identity().1
                || guardian.private_unit() != unit.name()
            {
                return Err(refuse());
            }
            let guard = OwnerNativeGuardCommitment {
                guardian_pid: guardian.guardian_pid(),
                guardian_nonce: guardian.nonce().to_owned(),
                guardian_receipt_sha256: guardian.native_receipt_sha256().to_owned(),
                policy_sha256: guardian.policy_sha256().to_owned(),
            };
            let value =
                Self::from_installed(binding, manager, unit, installed, launch, mode, Some(guard))?;
            guardian.revalidate().map_err(|_| refuse())?;
            Ok(value)
        }
        fn shape_valid(&self) -> bool {
            self.binding.stage.0 > 0
                && self.binding.stage.1 > 0
                && hex32(&self.binding.transaction_nonce)
                && hex64(&self.binding.planned_generation)
                && hex64(&self.binding.header_sha256)
                && self.boot_id.len() == 36
                && self.boot_id.is_ascii()
                && self.pid1_socket.0 > 0
                && self.pid1_socket.1 > 0
                && self.pid1_netns.0 > 0
                && self.pid1_netns.1 > 0
                && self
                    .private_unit
                    .strip_prefix("aegis-auto@")
                    .and_then(|name| name.strip_suffix(".service"))
                    .is_some_and(hex64)
                && hex64(&self.installed_generation_sha256)
                && hex64(&self.installed_manifest_sha256)
                && hex64(&self.policy_generation)
                && hex64(&self.launch_ticket_sha256)
                && match (self.mode, &self.native_guard) {
                    (AutoMode::SocksOnly, None) => true,
                    (AutoMode::WideRedirectSafe | AutoMode::FullWideTun, Some(guard)) => {
                        guard.guardian_pid > 1
                            && hex64(&guard.guardian_nonce)
                            && hex64(&guard.guardian_receipt_sha256)
                            && hex64(&guard.policy_sha256)
                    }
                    _ => false,
                }
                && self.fixed_unit == "aegis-client.service"
        }
    }
    #[allow(dead_code)]
    impl<'a> OwnerMarkerFence<'a> {
        pub(super) fn state(&self) -> OwnerMarkerState {
            self.state
        }
        /// Return only descriptor-derived, revalidated Stage/Header identity
        /// while the publication and mutation fences remain held. The caller
        /// must retain this fence and its worker InstallLock; these bytes do
        /// not authorize a manager call or any capture/finalize phase.
        pub(super) fn read_binding(&self) -> std::result::Result<OwnerBinding, OwnerMarkerState> {
            if self.state != OwnerMarkerState::Fresh {
                return Err(OwnerMarkerState::RecoveryRequired);
            }
            self.read_binding_held()
        }
        /// Source-owned post-marker readback under the same held fences. This
        /// is private to this Store protocol; ordinary worker reentry still
        /// refuses on marker presence and cannot call it.
        fn read_binding_held(&self) -> std::result::Result<OwnerBinding, OwnerMarkerState> {
            let attempt = || -> Result<OwnerBinding> {
                self.store.require_activation_root()?;
                self.store.revalidate()?;
                let header_bytes = self.store.read(Path::new("header.json"))?;
                let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| refuse())?;
                header.validate(self.store.uid)?;
                self.store.verify_payloads(&header)?;
                if header.phase != Phase::Metadata
                    || header.pending.is_some()
                    || header.unit_pending.is_some()
                    || header.capture_started
                {
                    return Err(refuse());
                }
                Ok(OwnerBinding {
                    transaction_nonce: header.transaction_nonce,
                    planned_generation: header.planned_generation,
                    stage: self.store.identity()?,
                    header_sha256: digest(&header_bytes),
                })
            };
            attempt().map_err(|_| OwnerMarkerState::RecoveryRequired)
        }
        /// Persist a full ambiguity marker before any future manager send.
        /// Unknown write/readback permanently revokes this in-memory lease.
        /// No positive caller exists until native ACK/boot/rollback acceptance.
        fn prepare_post_marker<'f>(
            &'f mut self,
            commitments: OwnerSendCommitments,
        ) -> std::result::Result<HeldPostMarker<'f, 'a>, OwnerMarkerState> {
            if self.state != OwnerMarkerState::Fresh {
                return Err(OwnerMarkerState::RecoveryRequired);
            }
            self.state = OwnerMarkerState::RecoveryRequired;
            let attempt = || -> Result<(String, OwnerSendCommitments)> {
                if !commitments.shape_valid() {
                    return Err(refuse());
                }
                let actual = self.read_binding_held().map_err(|_| refuse())?;
                if commitments.binding != actual || self.store.activation_leaf_present()? {
                    return Err(refuse());
                }
                let marker = serde_json::to_vec(&OwnerMaySendV2 {
                    schema: 2,
                    commitments: commitments.clone(),
                })
                .map_err(|_| refuse())?;
                self.store
                    .write_new_sticky_unchecked(Path::new(ACTIVATION_OWNER_MAY_SEND_V2), &marker)?;
                let readback = self.store.read(Path::new(ACTIVATION_OWNER_MAY_SEND_V2))?;
                if readback.as_slice() != marker
                    || self.read_binding_held().map_err(|_| refuse())? != actual
                {
                    return Err(refuse());
                }
                Ok((digest(&marker), commitments))
            };
            let (marker_sha256, commitments) =
                attempt().map_err(|_| OwnerMarkerState::RecoveryRequired)?;
            Ok(HeldPostMarker {
                fence: self,
                install_lock: None,
                commitments,
                marker_sha256,
                claimed: false,
            })
        }
        /// Product entry to the inert post-marker lease. The exact worker
        /// InstallLock must remain borrowed through marker claim and any
        /// future PID-1 transport. There is no production commitment producer
        /// or manager-send method in this cohort.
        pub(super) fn prepare_post_marker_with_install_lock<'f>(
            &'f mut self,
            lock: &'f InstallLock,
            commitments: OwnerSendCommitments,
        ) -> std::result::Result<HeldPostMarker<'f, 'a>, OwnerMarkerState> {
            lock.revalidate()
                .map_err(|_| OwnerMarkerState::RecoveryRequired)?;
            let mut held = self.prepare_post_marker(commitments)?;
            held.install_lock = Some(lock);
            lock.revalidate()
                .map_err(|_| OwnerMarkerState::RecoveryRequired)?;
            Ok(held)
        }
        /// Duplicate the exact held stage directory for a future installed
        /// guard helper's inherited FD. The parent must retain this fence and
        /// its worker InstallLock through the helper response; the duplicate
        /// alone is never a grant or a fresh pathname admission.
        pub(super) fn duplicate_held_stage(
            &self,
        ) -> std::result::Result<OwnedFd, OwnerMarkerState> {
            if self.state != OwnerMarkerState::Fresh {
                return Err(OwnerMarkerState::RecoveryRequired);
            }
            let attempt = || -> Result<OwnedFd> {
                self.store.require_activation_root()?;
                self.store.revalidate()?;
                let held = self.store.root.try_clone().map_err(|_| refuse())?;
                valid_dir(held.as_raw_fd(), self.store.uid, true)?;
                let actual = stat(held.as_raw_fd())?;
                if (actual.st_dev as u64, actual.st_ino as u64) != self.store.identity()? {
                    return Err(refuse());
                }
                Ok(held)
            };
            attempt().map_err(|_| OwnerMarkerState::RecoveryRequired)
        }
        /// Only an inert, transaction-bound ambiguity marker is created.
        /// This does not authorize PID1, release deny, or admit activation.
        pub(super) fn write_once(&mut self) -> std::result::Result<(), OwnerMarkerState> {
            if self.state != OwnerMarkerState::Fresh {
                return Err(OwnerMarkerState::RecoveryRequired);
            }
            // Every failure, including pre-marker source readback, is typed
            // recovery. No caller may infer that a prior invocation never
            // reached PID1 from a pathname or lock error.
            self.state = OwnerMarkerState::RecoveryRequired;
            let attempt = || -> Result<()> {
                self.store.require_activation_root()?;
                self.store.revalidate()?;
                let header_bytes = self.store.read(Path::new("header.json"))?;
                let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| refuse())?;
                header.validate(self.store.uid)?;
                self.store.verify_payloads(&header)?;
                if header.phase != Phase::Metadata
                    || header.pending.is_some()
                    || header.unit_pending.is_some()
                    || header.capture_started
                {
                    return Err(refuse());
                }
                let bytes = serde_json::to_vec(&OwnerMaySend {
                    schema: 1,
                    nonce: header.transaction_nonce,
                    stage: self.store.identity()?,
                    header_sha256: digest(&header_bytes),
                })
                .map_err(|_| refuse())?;
                self.store
                    .write_new_unchecked(Path::new(ACTIVATION_OWNER_MAY_SEND), &bytes)
            };
            attempt().map_err(|_| OwnerMarkerState::RecoveryRequired)
        }
    }
    impl HeldPostMarker<'_, '_> {
        /// Durable one-use claim only. This intentionally returns no token or
        /// PID-1 send method. After ambiguity or process loss, old leaves
        /// remain and every fresh worker/reopen refuses rather than retrying.
        fn claim_inert_once(&mut self) -> std::result::Result<(), OwnerMarkerState> {
            if self.claimed {
                return Err(OwnerMarkerState::RecoveryRequired);
            }
            self.claimed = true;
            let attempt = || -> Result<()> {
                if let Some(lock) = self.install_lock {
                    lock.revalidate().map_err(|_| refuse())?;
                }
                let fence = &self.fence;
                let actual = fence.read_binding_held().map_err(|_| refuse())?;
                if actual != self.commitments.binding {
                    return Err(refuse());
                }
                let marker = fence.store.read(Path::new(ACTIVATION_OWNER_MAY_SEND_V2))?;
                if digest(&marker) != self.marker_sha256
                    || fence.store.leaf_present(ACTIVATION_OWNER_CLAIM_V2)?
                {
                    return Err(refuse());
                }
                let claim = serde_json::to_vec(&OwnerClaimV2 {
                    schema: 2,
                    may_send_sha256: self.marker_sha256.clone(),
                    nonce: self.commitments.binding.transaction_nonce.clone(),
                    stage: self.commitments.binding.stage,
                })
                .map_err(|_| refuse())?;
                fence
                    .store
                    .write_new_sticky_unchecked(Path::new(ACTIVATION_OWNER_CLAIM_V2), &claim)?;
                let readback = fence.store.read(Path::new(ACTIVATION_OWNER_CLAIM_V2))?;
                if readback.as_slice() != claim
                    || digest(&fence.store.read(Path::new(ACTIVATION_OWNER_MAY_SEND_V2))?)
                        != self.marker_sha256
                    || fence.read_binding_held().map_err(|_| refuse())? != actual
                {
                    return Err(refuse());
                }
                if let Some(lock) = self.install_lock {
                    lock.revalidate().map_err(|_| refuse())?;
                }
                Ok(())
            };
            attempt().map_err(|_| OwnerMarkerState::RecoveryRequired)
        }
    }
    impl OwnerContinuation {
        #[cfg(test)]
        pub(super) fn stage_identity(&self) -> (u64, u64) {
            self.stage_id
        }
        fn admit_job(
            &self,
            job: &crate::profile_auto_stopped_service::pid1::SubmittedJob,
        ) -> Result<()> {
            let expected = self.product_commitments.as_ref().ok_or_else(refuse)?;
            let manager = job.manager();
            if job.id() == 0
                || job.unit() != expected.private_unit
                || job.path() != format!("/org/freedesktop/systemd1/job/{}", job.id())
                || manager.boot_id() != expected.boot_id
                || manager.socket_identity() != expected.pid1_socket
                || manager.netns_identity() != expected.pid1_netns
            {
                return Err(refuse());
            }
            Ok(())
        }
        pub(super) fn record_submitted(
            &mut self,
            lock: &InstallLock,
            job: &crate::profile_auto_stopped_service::pid1::SubmittedJob,
        ) -> Result<()> {
            if self.submitted_sha256.is_some() {
                return Err(refuse());
            }
            self.admit_job(job)?;
            let bytes = serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "kind": "owned-start-submitted",
                "may_send_sha256": self.marker_sha256.as_ref().ok_or_else(refuse)?,
                "claim_sha256": self.claim_sha256.as_ref().ok_or_else(refuse)?,
                "job_id": job.id(),
                "job_path": job.path(),
                "unit": job.unit(),
                "boot_id": job.manager().boot_id(),
                "pid1_socket": job.manager().socket_identity(),
                "pid1_netns": job.manager().netns_identity(),
            }))
            .map_err(|_| refuse())?;
            self.with_owned_effect(lock, || {
                self.store
                    .write_new_sticky_unchecked(Path::new(ACTIVATION_OWNER_SUBMITTED), &bytes)
            })?;
            let actual = self.store.read(Path::new(ACTIVATION_OWNER_SUBMITTED))?;
            if actual.as_slice() != bytes {
                return Err(refuse());
            }
            self.submitted_sha256 = Some(digest(&bytes));
            self.submitted_job = Some((job.id(), job.path().to_owned()));
            Ok(())
        }
        pub(super) fn record_completed(
            &mut self,
            lock: &InstallLock,
            completed: &crate::profile_auto_stopped_service::pid1::CompletedStart,
        ) -> Result<()> {
            if self.completed_sha256.is_some() {
                return Err(refuse());
            }
            let (job, invocation) = completed.facts();
            self.admit_job(job)?;
            if self.submitted_job.as_ref() != Some(&(job.id(), job.path().to_owned())) {
                return Err(refuse());
            }
            if !hex32(invocation) {
                return Err(refuse());
            }
            let submitted_sha256 = self.submitted_sha256.as_ref().ok_or_else(refuse)?;
            if digest(&self.store.read(Path::new(ACTIVATION_OWNER_SUBMITTED))?) != *submitted_sha256
            {
                return Err(refuse());
            }
            let bytes = serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "kind": "owned-start-completed",
                "submitted_sha256": submitted_sha256,
                "job_id": job.id(),
                "job_path": job.path(),
                "unit": job.unit(),
                "invocation_id": invocation,
            }))
            .map_err(|_| refuse())?;
            self.with_owned_effect(lock, || {
                self.store
                    .write_new_sticky_unchecked(Path::new(ACTIVATION_OWNER_COMPLETED), &bytes)
            })?;
            let actual = self.store.read(Path::new(ACTIVATION_OWNER_COMPLETED))?;
            if actual.as_slice() != bytes {
                return Err(refuse());
            }
            self.completed_sha256 = Some(digest(&bytes));
            self.start_invocation = Some(invocation.to_owned());
            Ok(())
        }
        pub(super) fn record_launch_consumed(
            &mut self,
            lock: &InstallLock,
            proof: &crate::profile_auto_launch_service::LaunchProof,
        ) -> Result<()> {
            let product = self.product_commitments.as_ref().ok_or_else(refuse)?;
            if self.launch_consumed_sha256.is_some()
                || self.completed_sha256.is_none()
                || self.start_invocation.as_deref() != Some(proof.invocation())
                || proof.unit() != product.private_unit
                || proof.ticket_sha256() != product.launch_ticket_sha256
                || proof.stage_identity() != product.binding.stage
                || proof.boot_id() != product.boot_id
                || proof.pid() <= 1
                || proof.start_tick() == 0
            {
                return Err(refuse());
            }
            proof.revalidate().map_err(|_| refuse())?;
            let completed_sha256 = self.completed_sha256.as_ref().ok_or_else(refuse)?;
            if digest(&self.store.read(Path::new(ACTIVATION_OWNER_COMPLETED))?) != *completed_sha256
            {
                return Err(refuse());
            }
            let bytes = serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "kind": "owned-launch-consumed",
                "completed_sha256": completed_sha256,
                "ticket_sha256": product.launch_ticket_sha256,
                "private_unit": product.private_unit,
                "invocation_id": proof.invocation(),
                "main_pid": proof.pid(),
                "main_start_tick": proof.start_tick(),
                "guardian_pid": proof.guardian_pid(),
                "guardian_invocation_id": proof.guardian_invocation(),
            }))
            .map_err(|_| refuse())?;
            self.with_owned_effect(lock, || {
                self.store
                    .write_new_sticky_unchecked(Path::new(ACTIVATION_OWNER_LAUNCH_CONSUMED), &bytes)
            })?;
            if self
                .store
                .read(Path::new(ACTIVATION_OWNER_LAUNCH_CONSUMED))?
                .as_slice()
                != bytes
            {
                return Err(refuse());
            }
            proof.revalidate().map_err(|_| refuse())?;
            self.launch_consumed_sha256 = Some(digest(&bytes));
            Ok(())
        }
        pub(super) fn record_stop_submitted(
            &mut self,
            lock: &InstallLock,
            job: &crate::profile_auto_stopped_service::pid1::SubmittedJob,
        ) -> Result<()> {
            if self.stop_submitted_sha256.is_some()
                || self.completed_sha256.is_none()
                || self.submitted_job.as_ref() == Some(&(job.id(), job.path().to_owned()))
            {
                return Err(refuse());
            }
            self.admit_job(job)?;
            let bytes = serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "kind": "owned-stop-submitted",
                "completed_start_sha256": self.completed_sha256.as_ref().ok_or_else(refuse)?,
                "job_id": job.id(),
                "job_path": job.path(),
                "unit": job.unit(),
                "boot_id": job.manager().boot_id(),
                "pid1_socket": job.manager().socket_identity(),
                "pid1_netns": job.manager().netns_identity(),
            }))
            .map_err(|_| refuse())?;
            self.with_inverse_effect(lock, || {
                self.store
                    .write_new_sticky_unchecked(Path::new(ACTIVATION_OWNER_STOP_SUBMITTED), &bytes)
            })?;
            if self
                .store
                .read(Path::new(ACTIVATION_OWNER_STOP_SUBMITTED))?
                .as_slice()
                != bytes
            {
                return Err(refuse());
            }
            self.stop_submitted_sha256 = Some(digest(&bytes));
            self.stop_submitted_job = Some((job.id(), job.path().to_owned()));
            Ok(())
        }
        pub(super) fn record_stop_completed(
            &mut self,
            lock: &InstallLock,
            completed: &crate::profile_auto_stopped_service::pid1::CompletedStop,
        ) -> Result<()> {
            if self.stop_completed_sha256.is_some() {
                return Err(refuse());
            }
            let (job, prior_invocation) = completed.facts();
            self.admit_job(job)?;
            if self.stop_submitted_job.as_ref() != Some(&(job.id(), job.path().to_owned()))
                || self.start_invocation.as_deref() != Some(prior_invocation)
            {
                return Err(refuse());
            }
            let submitted_sha256 = self.stop_submitted_sha256.as_ref().ok_or_else(refuse)?;
            if digest(
                &self
                    .store
                    .read(Path::new(ACTIVATION_OWNER_STOP_SUBMITTED))?,
            ) != *submitted_sha256
            {
                return Err(refuse());
            }
            let bytes = serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "kind": "owned-stop-completed",
                "stop_submitted_sha256": submitted_sha256,
                "job_id": job.id(),
                "job_path": job.path(),
                "unit": job.unit(),
                "prior_invocation_id": prior_invocation,
            }))
            .map_err(|_| refuse())?;
            self.with_inverse_effect(lock, || {
                self.store
                    .write_new_sticky_unchecked(Path::new(ACTIVATION_OWNER_STOP_COMPLETED), &bytes)
            })?;
            if self
                .store
                .read(Path::new(ACTIVATION_OWNER_STOP_COMPLETED))?
                .as_slice()
                != bytes
            {
                return Err(refuse());
            }
            self.stop_completed_sha256 = Some(digest(&bytes));
            Ok(())
        }
        pub(super) fn claim_product_once(
            &mut self,
            lock: &InstallLock,
            commitments: OwnerProductCommitments,
            installed: &super::owner_installed::ProtectedInstalledFacts<'_, '_>,
        ) -> std::result::Result<(), OwnerMarkerState> {
            let actual = self
                .binding(lock)
                .map_err(|_| OwnerMarkerState::RecoveryRequired)?;
            let header = self
                .store
                .load_header()
                .map_err(|_| OwnerMarkerState::RecoveryRequired)?;
            let current = self
                .with_pre_marker_effect(lock, || installed.current())
                .map_err(|_| OwnerMarkerState::RecoveryRequired)?;
            if commitments.binding != actual
                || !commitments.shape_valid()
                || header.mode != commitments.mode
                || header.leaves.get(Path::new(
                    "accepted/install-receipt/installed-generation.json",
                )) != Some(&commitments.installed_generation_sha256)
                || header
                    .leaves
                    .get(Path::new("accepted/install-receipt/manifest.json"))
                    != Some(&commitments.installed_manifest_sha256)
                || current.installed_generation_sha256 != commitments.installed_generation_sha256
                || current.installed_manifest_sha256 != commitments.installed_manifest_sha256
                || current.policy_generation != commitments.policy_generation
            {
                return Err(OwnerMarkerState::RecoveryRequired);
            }
            // Burn the in-memory attempt before the first sticky O_EXCL. Any
            // uncertain write leaves a recovery-only marker when created.
            self.marker_attempted = true;
            let attempt = || -> Result<(String, String)> {
                let marker = serde_json::to_vec(&OwnerMaySendV3 {
                    schema: 3,
                    commitments: commitments.clone(),
                })
                .map_err(|_| refuse())?;
                self.store
                    .write_new_sticky_unchecked(Path::new(ACTIVATION_OWNER_MAY_SEND_V3), &marker)?;
                if self
                    .store
                    .read(Path::new(ACTIVATION_OWNER_MAY_SEND_V3))?
                    .as_slice()
                    != marker
                    || digest(&self.store.read(Path::new("header.json"))?) != actual.header_sha256
                {
                    return Err(refuse());
                }
                let marker_sha = digest(&marker);
                let claim = serde_json::to_vec(&OwnerClaimV3 {
                    schema: 3,
                    may_send_sha256: marker_sha.clone(),
                    nonce: actual.transaction_nonce,
                    stage: actual.stage,
                })
                .map_err(|_| refuse())?;
                self.store
                    .write_new_sticky_unchecked(Path::new(ACTIVATION_OWNER_CLAIM_V3), &claim)?;
                if self
                    .store
                    .read(Path::new(ACTIVATION_OWNER_CLAIM_V3))?
                    .as_slice()
                    != claim
                    || digest(&self.store.read(Path::new(ACTIVATION_OWNER_MAY_SEND_V3))?)
                        != marker_sha
                {
                    return Err(refuse());
                }
                lock.revalidate().map_err(|_| refuse())?;
                Ok((marker_sha, digest(&claim)))
            };
            let (marker_sha256, claim_sha256) =
                attempt().map_err(|_| OwnerMarkerState::RecoveryRequired)?;
            self.marker_sha256 = Some(marker_sha256);
            self.claim_sha256 = Some(claim_sha256);
            self.product_commitments = Some(commitments);
            self.with_owned_effect(lock, || {
                let current = installed.current()?;
                let proof = self.product_commitments.as_ref().ok_or_else(refuse)?;
                if current.installed_generation_sha256 != proof.installed_generation_sha256
                    || current.installed_manifest_sha256 != proof.installed_manifest_sha256
                    || current.policy_generation != proof.policy_generation
                {
                    return Err(refuse());
                }
                Ok(())
            })
            .map_err(|_| OwnerMarkerState::RecoveryRequired)
        }
        fn revalidate_held(&self, lock: &InstallLock) -> Result<()> {
            lock.revalidate().map_err(|_| refuse())?;
            self.store.revalidate()?;
            self.store.require_activation_root()?;
            if self.store.uid != self.uid || self.store.identity()? != self.stage_id {
                return Err(refuse());
            }
            let activation = stat(self.store.activation_root.as_raw_fd())?;
            if (activation.st_dev as u64, activation.st_ino as u64) != self.activation_id {
                return Err(refuse());
            }
            let publication = self.publication.as_ref().ok_or_else(refuse)?;
            let mutation = self.mutation.as_ref().ok_or_else(refuse)?;
            if Store::lock_identity(publication._process.as_raw_fd(), self.uid)?
                != self.store.publication_fence_identity.ok_or_else(refuse)?
                || Store::lock_identity(mutation._process.as_raw_fd(), self.uid)?
                    != self.store.mutation_lock_identity.ok_or_else(refuse)?
            {
                return Err(refuse());
            }
            Ok(())
        }
        pub(super) fn binding(&self, lock: &InstallLock) -> Result<OwnerBinding> {
            self.revalidate_held(lock)?;
            if self.marker_attempted
                || self.store.activation_leaf_present()?
                || self.store.leaf_present(ACTIVATION_OWNER_TERMINAL)?
            {
                return Err(refuse());
            }
            let fence = OwnerMarkerFence {
                store: &self.store,
                state: OwnerMarkerState::Fresh,
                _publication: PublicationLease {
                    _process: self
                        .publication
                        .as_ref()
                        .ok_or_else(refuse)?
                        ._process
                        .try_clone()
                        .map_err(|_| refuse())?,
                },
                _mutation: MutationGuard {
                    _process: self
                        .mutation
                        .as_ref()
                        .ok_or_else(refuse)?
                        ._process
                        .try_clone()
                        .map_err(|_| refuse())?,
                    _thread: None,
                },
            };
            fence.read_binding().map_err(|_| refuse())
        }
        pub(super) fn duplicate_stage_fd(&self, lock: &InstallLock) -> Result<OwnedFd> {
            self.revalidate_held(lock)?;
            if self.marker_attempted
                || self.store.activation_leaf_present()?
                || self.store.leaf_present(ACTIVATION_OWNER_TERMINAL)?
            {
                return Err(refuse());
            }
            self.store.duplicate_root()
        }
        /// Existing publication and stage code executes only while this
        /// original worker still owns every lock and both exact markers.
        pub(super) fn with_pre_marker_effect<T>(
            &self,
            lock: &InstallLock,
            effect: impl FnOnce() -> Result<T>,
        ) -> Result<T> {
            self.revalidate_held(lock)?;
            if self.marker_attempted || self.store.activation_leaf_present()? {
                return Err(refuse());
            }
            let scope = OwnerScope {
                activation_id: self.activation_id,
                stage_id: self.stage_id,
                stage_path: self.store.path.clone(),
                marker: None,
                inverse_after_terminal: false,
                publication_fd: self
                    .publication
                    .as_ref()
                    .ok_or_else(refuse)?
                    ._process
                    .as_raw_fd(),
                mutation_fd: self
                    .mutation
                    .as_ref()
                    .ok_or_else(refuse)?
                    ._process
                    .as_raw_fd(),
            };
            self.store.verify_owner_scope(&scope)?;
            CURRENT_OWNER.with(|current| {
                let mut current = current.borrow_mut();
                if current.is_some() {
                    return Err(refuse());
                }
                *current = Some(scope);
                Ok(())
            })?;
            let reset = RestoreOwnerScope;
            let result = effect();
            drop(reset);
            self.revalidate_held(lock)?;
            result
        }
        pub(super) fn with_owned_effect<T>(
            &self,
            lock: &InstallLock,
            effect: impl FnOnce() -> Result<T>,
        ) -> Result<T> {
            self.with_marker_effect(lock, false, effect)
        }
        fn with_inverse_effect<T>(
            &self,
            lock: &InstallLock,
            effect: impl FnOnce() -> Result<T>,
        ) -> Result<T> {
            self.with_marker_effect(lock, true, effect)
        }
        fn with_marker_effect<T>(
            &self,
            lock: &InstallLock,
            inverse_after_terminal: bool,
            effect: impl FnOnce() -> Result<T>,
        ) -> Result<T> {
            self.revalidate_held(lock)?;
            let scope = OwnerScope {
                activation_id: self.activation_id,
                stage_id: self.stage_id,
                stage_path: self.store.path.clone(),
                marker: Some(OwnerScopeMarker {
                    may_send_sha256: self.marker_sha256.clone().ok_or_else(refuse)?,
                    claim_sha256: self.claim_sha256.clone().ok_or_else(refuse)?,
                    may_send_leaf: if self.product_commitments.is_some() {
                        ACTIVATION_OWNER_MAY_SEND_V3
                    } else {
                        ACTIVATION_OWNER_MAY_SEND_V2
                    },
                    claim_leaf: if self.product_commitments.is_some() {
                        ACTIVATION_OWNER_CLAIM_V3
                    } else {
                        ACTIVATION_OWNER_CLAIM_V2
                    },
                }),
                inverse_after_terminal,
                publication_fd: self
                    .publication
                    .as_ref()
                    .ok_or_else(refuse)?
                    ._process
                    .as_raw_fd(),
                mutation_fd: self
                    .mutation
                    .as_ref()
                    .ok_or_else(refuse)?
                    ._process
                    .as_raw_fd(),
            };
            self.store.verify_owner_scope(&scope)?;
            CURRENT_OWNER.with(|current| {
                let mut current = current.borrow_mut();
                if current.is_some() {
                    return Err(refuse());
                }
                *current = Some(scope);
                Ok(())
            })?;
            let reset = RestoreOwnerScope;
            let result = effect();
            drop(reset);
            self.revalidate_held(lock)?;
            result
        }
        /// Re-admit only the exact installed binary and accepted unit policy
        /// captured before the one-use START claim. A projection intent may
        /// be pending, so this never grants a forward operation.
        pub(super) fn verify_inverse_installed(
            &self,
            lock: &InstallLock,
            context: &super::store_context::RootContext<'_>,
        ) -> Result<()> {
            let product = self.product_commitments.as_ref().ok_or_else(refuse)?;
            self.with_inverse_effect(lock, || {
                let installed =
                    super::owner_installed::ProtectedInstalledFacts::capture_for_inverse(
                        context, lock,
                    )?;
                let current = installed.current_for_inverse()?;
                if current.installed_generation_sha256 != product.installed_generation_sha256
                    || current.installed_manifest_sha256 != product.installed_manifest_sha256
                    || current.policy_generation != product.policy_generation
                {
                    return Err(refuse());
                }
                Ok(())
            })
        }
        /// Once a finalized terminal exists, commit/retirement failure must
        /// leave an unambiguous durable stop intent before any StopUnit send.
        /// This root marker blocks ordinary read reentry even if both v3
        /// markers have already been retired. The original owner remains held.
        pub(super) fn begin_postterminal_inverse(&self, lock: &InstallLock) -> Result<bool> {
            if !self.store.leaf_present(ACTIVATION_OWNER_TERMINAL)? {
                return Ok(false);
            }
            self.with_inverse_effect(lock, || {
                let header = self.store.load_header()?;
                let terminal = self.store.read(Path::new(ACTIVATION_OWNER_TERMINAL))?;
                if !header.leaves.contains_key(Path::new(ACTIVATION_OWNER_TERMINAL)) {
                    // Terminal write completed before Header fsync. The two
                    // original markers remain intact, so the original owner
                    // may still StopUnit; the orphan terminal stays sticky
                    // recovery evidence and cannot produce a clean receipt.
                    if !self.store.leaf_present(ACTIVATION_OWNER_MAY_SEND_V3)?
                        || !self.store.leaf_present(ACTIVATION_OWNER_CLAIM_V3)?
                    {
                        return Err(refuse());
                    }
                    return Ok(false);
                }
                let archive = self.store.read(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))?;
                if header.phase != Phase::Finalized
                    || header.leaves.get(Path::new(ACTIVATION_OWNER_TERMINAL))
                        != Some(&digest(&terminal))
                    || header.leaves.get(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))
                        != Some(&digest(&archive))
                {
                    return Err(refuse());
                }
                let bytes = serde_json::to_vec(&serde_json::json!({
                    "schema": 1,
                    "kind": "postterminal-stop-intent",
                    "stage": self.stage_id,
                    "terminal_sha256": digest(&terminal),
                    "marker_archive_sha256": digest(&archive),
                    "may_send_sha256": self.marker_sha256.as_ref().ok_or_else(refuse)?,
                    "claim_sha256": self.claim_sha256.as_ref().ok_or_else(refuse)?,
                    "private_unit": self.product_commitments.as_ref().ok_or_else(refuse)?.private_unit,
                })).map_err(|_| refuse())?;
                self.store.write_new_sticky_unchecked(
                    Path::new(ACTIVATION_OWNER_POSTTERMINAL_STOP_INTENT), &bytes)?;
                if self.store.read(Path::new(ACTIVATION_OWNER_POSTTERMINAL_STOP_INTENT))?.as_slice()
                    != bytes
                {
                    return Err(refuse());
                }
                Ok(true)
            })
        }
        fn persist_terminal(
            &self,
            lock: &InstallLock,
            outcome: &str,
            include_stop: bool,
            launch: Option<&crate::profile_auto_launch_service::LaunchProof>,
            capture: Option<&crate::profile_auto_guardian::CaptureReady>,
            inverse: Option<&crate::profile_auto_guardian::CompletedCaptureInverse>,
        ) -> Result<()> {
            let product = self.product_commitments.as_ref().ok_or_else(refuse)?;
            let submitted = self.submitted_sha256.as_ref().ok_or_else(refuse)?;
            let completed = self.completed_sha256.as_ref().ok_or_else(refuse)?;
            let launch_consumed = if let Some(proof) = launch {
                proof.revalidate().map_err(|_| refuse())?;
                if proof.ticket_sha256() != product.launch_ticket_sha256
                    || proof.unit() != product.private_unit
                    || proof.stage_identity() != product.binding.stage
                    || proof.boot_id() != product.boot_id
                    || self.start_invocation.as_deref() != Some(proof.invocation())
                {
                    return Err(refuse());
                }
                Some(self.launch_consumed_sha256.as_ref().ok_or_else(refuse)?)
            } else {
                self.launch_consumed_sha256.as_ref()
            };
            if (outcome == "finalized" && launch.is_none())
                || (launch_consumed.is_none()
                    && self.store.leaf_present(ACTIVATION_OWNER_LAUNCH_CONSUMED)?)
            {
                return Err(refuse());
            }
            let stop_submitted = if include_stop {
                Some(self.stop_submitted_sha256.as_ref().ok_or_else(refuse)?)
            } else {
                None
            };
            let stop_completed = if include_stop {
                Some(self.stop_completed_sha256.as_ref().ok_or_else(refuse)?)
            } else {
                None
            };
            let tracked = [
                (ACTIVATION_OWNER_SUBMITTED, Some(submitted)),
                (ACTIVATION_OWNER_COMPLETED, Some(completed)),
                (ACTIVATION_OWNER_LAUNCH_CONSUMED, launch_consumed),
                (ACTIVATION_OWNER_STOP_SUBMITTED, stop_submitted),
                (ACTIVATION_OWNER_STOP_COMPLETED, stop_completed),
            ];
            self.with_owned_effect(lock, || {
                let mut header = self.store.load_header()?;
                if header.pending.is_some()
                    || header.unit_pending.is_some()
                    || match outcome {
                        "finalized" => header.phase != Phase::Finalized,
                        "compensated-failure" => {
                            header.phase != Phase::Metadata
                                || header.render_recipe != Path::new("accepted/render-recipe.json")
                                || self
                                    .store
                                    .leaf_present("accepted/final-render-recipe.json")?
                                || self.store.leaf_present(
                                    "receipts/config-projection/projection-receipt.json",
                                )?
                                || header.active_records.get("config").is_some_and(|p| {
                                    header
                                        .current_records
                                        .get(p)
                                        .is_some_and(|s| s.phase == "projection")
                                })
                        }
                        _ => true,
                    }
                {
                    return Err(refuse());
                }
                for (leaf, expected) in tracked {
                    if let Some(expected) = expected {
                        if digest(&self.store.read(Path::new(leaf))?) != *expected {
                            return Err(refuse());
                        }
                    }
                }
                let may = self.store.read(Path::new(ACTIVATION_OWNER_MAY_SEND_V3))?;
                let claim = self.store.read(Path::new(ACTIVATION_OWNER_CLAIM_V3))?;
                let marker_sha = self.marker_sha256.as_ref().ok_or_else(refuse)?;
                let claim_sha = self.claim_sha256.as_ref().ok_or_else(refuse)?;
                if digest(&may) != *marker_sha || digest(&claim) != *claim_sha {
                    return Err(refuse());
                }
                let archive = serde_json::to_vec(&OwnerMarkerArchive {
                    schema: 1,
                    may_send_hex: hex::encode(&may),
                    claim_hex: hex::encode(&claim),
                    may_send_sha256: marker_sha.clone(),
                    claim_sha256: claim_sha.clone(),
                })
                .map_err(|_| refuse())?;
                if self.store.leaf_present(ACTIVATION_OWNER_MARKER_ARCHIVE)? {
                    if self
                        .store
                        .read(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))?
                        .as_slice()
                        != archive.as_slice()
                    {
                        return Err(refuse());
                    }
                } else {
                    self.store.write_new_sticky_unchecked(
                        Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE),
                        &archive,
                    )?;
                    if self
                        .store
                        .read(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))?
                        .as_slice()
                        != archive.as_slice()
                    {
                        return Err(refuse());
                    }
                }
                let archive_sha = digest(&archive);
                let terminal = serde_json::to_vec(&serde_json::json!({
                    "schema": 1,
                    "outcome": outcome,
                    "transaction_nonce": product.binding.transaction_nonce,
                    "stage": product.binding.stage,
                    "private_unit": product.private_unit,
                    "may_send_sha256": self.marker_sha256.as_ref().ok_or_else(refuse)?,
                    "claim_sha256": self.claim_sha256.as_ref().ok_or_else(refuse)?,
                    "marker_archive_sha256": archive_sha,
                    "submitted_sha256": submitted,
                    "completed_sha256": completed,
                    "launch_consumed_sha256": launch_consumed,
                    "launch_ticket_sha256": product.launch_ticket_sha256,
                    "stop_submitted_sha256": stop_submitted,
                    "stop_completed_sha256": stop_completed,
                    "native_guard": product.native_guard,
                    "native_capture_sha256": capture.map(|proof| proof.native_capture_sha256()),
                    "native_inverse_sha256": inverse.map(|proof| proof.native_inverse_sha256()),
                    "post_deny_policy_sha256": inverse.map(|proof| proof.post_deny_policy_sha256()),
                }))
                .map_err(|_| refuse())?;
                self.store
                    .write_new_sticky_unchecked(Path::new(ACTIVATION_OWNER_TERMINAL), &terminal)?;
                if self
                    .store
                    .read(Path::new(ACTIVATION_OWNER_TERMINAL))?
                    .as_slice()
                    != terminal
                {
                    return Err(refuse());
                }
                for (leaf, expected) in tracked {
                    if let Some(expected) = expected {
                        header.leaves.insert(PathBuf::from(leaf), expected.clone());
                    }
                }
                header
                    .leaves
                    .insert(PathBuf::from(ACTIVATION_OWNER_TERMINAL), digest(&terminal));
                header
                    .leaves
                    .insert(PathBuf::from(ACTIVATION_OWNER_MARKER_ARCHIVE), archive_sha);
                self.store.save_header(&header)?;
                self.store.verify_payloads(&self.store.load_header()?)
            })
        }
        fn persist_postterminal_compensated(
            &self,
            lock: &InstallLock,
            inverse: Option<&crate::profile_auto_guardian::CompletedCaptureInverse>,
        ) -> Result<()> {
            let product = self.product_commitments.as_ref().ok_or_else(refuse)?;
            let stop_submitted = self.stop_submitted_sha256.as_ref().ok_or_else(refuse)?;
            let stop_completed = self.stop_completed_sha256.as_ref().ok_or_else(refuse)?;
            self.with_inverse_effect(lock, || {
                let mut header = self.store.load_header()?;
                let terminal = self.store.read(Path::new(ACTIVATION_OWNER_TERMINAL))?;
                let archive = self
                    .store
                    .read(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))?;
                let intent = self
                    .store
                    .read(Path::new(ACTIVATION_OWNER_POSTTERMINAL_STOP_INTENT))?;
                if header.phase != Phase::Finalized
                    || header.leaves.get(Path::new(ACTIVATION_OWNER_TERMINAL))
                        != Some(&digest(&terminal))
                    || header
                        .leaves
                        .get(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))
                        != Some(&digest(&archive))
                    || digest(
                        &self
                            .store
                            .read(Path::new(ACTIVATION_OWNER_STOP_SUBMITTED))?,
                    ) != *stop_submitted
                    || digest(
                        &self
                            .store
                            .read(Path::new(ACTIVATION_OWNER_STOP_COMPLETED))?,
                    ) != *stop_completed
                {
                    return Err(refuse());
                }
                let intent_json: serde_json::Value =
                    serde_json::from_slice(&intent).map_err(|_| refuse())?;
                if intent_json.get("terminal_sha256").and_then(|v| v.as_str())
                    != Some(digest(&terminal).as_str())
                    || intent_json
                        .get("marker_archive_sha256")
                        .and_then(|v| v.as_str())
                        != Some(digest(&archive).as_str())
                    || intent_json.get("private_unit").and_then(|v| v.as_str())
                        != Some(product.private_unit.as_str())
                {
                    return Err(refuse());
                }
                let bytes = serde_json::to_vec(&serde_json::json!({
                    "schema": 1,
                    "outcome": "postterminal-compensated",
                    "transaction_nonce": product.binding.transaction_nonce,
                    "stage": product.binding.stage,
                    "private_unit": product.private_unit,
                    "terminal_sha256": digest(&terminal),
                    "marker_archive_sha256": digest(&archive),
                    "stop_intent_sha256": digest(&intent),
                    "stop_submitted_sha256": stop_submitted,
                    "stop_completed_sha256": stop_completed,
                    "native_inverse_sha256": inverse.map(|proof| proof.native_inverse_sha256()),
                    "post_deny_policy_sha256": inverse.map(|proof| proof.post_deny_policy_sha256()),
                }))
                .map_err(|_| refuse())?;
                self.store.write_new_sticky_unchecked(
                    Path::new(ACTIVATION_OWNER_POSTTERMINAL_COMPENSATED),
                    &bytes,
                )?;
                if self
                    .store
                    .read(Path::new(ACTIVATION_OWNER_POSTTERMINAL_COMPENSATED))?
                    .as_slice()
                    != bytes
                {
                    return Err(refuse());
                }
                header.leaves.insert(
                    PathBuf::from(ACTIVATION_OWNER_STOP_SUBMITTED),
                    stop_submitted.clone(),
                );
                header.leaves.insert(
                    PathBuf::from(ACTIVATION_OWNER_STOP_COMPLETED),
                    stop_completed.clone(),
                );
                header.leaves.insert(
                    PathBuf::from(ACTIVATION_OWNER_POSTTERMINAL_COMPENSATED),
                    digest(&bytes),
                );
                header.phase = Phase::NativeRecoveryRequired;
                self.store.save_header(&header)?;
                self.store.verify_payloads(&self.store.load_header()?)
            })
        }
        fn terminal_handoff_bytes(&self) -> Result<Vec<u8>> {
            let product = self.product_commitments.as_ref().ok_or_else(refuse)?;
            let header = self.store.load_header()?;
            let terminal = self.store.read(Path::new(ACTIVATION_OWNER_TERMINAL))?;
            let archive = self
                .store
                .read(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))?;
            if header.phase != Phase::Finalized
                || header.leaves.get(Path::new(ACTIVATION_OWNER_TERMINAL))
                    != Some(&digest(&terminal))
                || header
                    .leaves
                    .get(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))
                    != Some(&digest(&archive))
            {
                return Err(refuse());
            }
            serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "kind": "terminal-guardian-handoff",
                "stage": product.binding.stage,
                "private_unit": product.private_unit,
                "terminal_sha256": digest(&terminal),
                "marker_archive_sha256": digest(&archive),
                "may_send_sha256": self.marker_sha256.as_ref().ok_or_else(refuse)?,
                "claim_sha256": self.claim_sha256.as_ref().ok_or_else(refuse)?,
            }))
            .map_err(|_| refuse())
        }
        fn write_terminal_handoff(&self, lock: &InstallLock) -> Result<()> {
            self.with_owned_effect(lock, || {
                let bytes = self.terminal_handoff_bytes()?;
                self.store.write_new_sticky_unchecked(
                    Path::new(ACTIVATION_OWNER_TERMINAL_HANDOFF),
                    &bytes,
                )?;
                if self
                    .store
                    .read(Path::new(ACTIVATION_OWNER_TERMINAL_HANDOFF))?
                    .as_slice()
                    != bytes
                {
                    return Err(refuse());
                }
                Ok(())
            })
        }
        fn clear_terminal_handoff(&self, lock: &InstallLock) -> Result<()> {
            self.with_inverse_effect(lock, || {
                let expected = self.terminal_handoff_bytes()?;
                if self
                    .store
                    .read(Path::new(ACTIVATION_OWNER_TERMINAL_HANDOFF))?
                    .as_slice()
                    != expected
                    || self.store.leaf_present(ACTIVATION_OWNER_MAY_SEND_V3)?
                    || self.store.leaf_present(ACTIVATION_OWNER_CLAIM_V3)?
                    || self
                        .store
                        .leaf_present(ACTIVATION_OWNER_POSTTERMINAL_STOP_INTENT)?
                {
                    return Err(refuse());
                }
                let (parent, name) = self
                    .store
                    .parent(Path::new(ACTIVATION_OWNER_TERMINAL_HANDOFF), false)?;
                if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0
                    || unsafe { libc::fsync(parent.as_raw_fd()) } != 0
                {
                    return Err(refuse());
                }
                if self.store.activation_leaf_present()? {
                    return Err(refuse());
                }
                Ok(())
            })
        }
        fn retire_exact_markers(&self, lock: &InstallLock, handoff: bool) -> Result<()> {
            self.revalidate_held(lock)?;
            let scope = OwnerScope {
                activation_id: self.activation_id,
                stage_id: self.stage_id,
                stage_path: self.store.path.clone(),
                marker: Some(OwnerScopeMarker {
                    may_send_sha256: self.marker_sha256.clone().ok_or_else(refuse)?,
                    claim_sha256: self.claim_sha256.clone().ok_or_else(refuse)?,
                    may_send_leaf: ACTIVATION_OWNER_MAY_SEND_V3,
                    claim_leaf: ACTIVATION_OWNER_CLAIM_V3,
                }),
                inverse_after_terminal: false,
                publication_fd: self
                    .publication
                    .as_ref()
                    .ok_or_else(refuse)?
                    ._process
                    .as_raw_fd(),
                mutation_fd: self
                    .mutation
                    .as_ref()
                    .ok_or_else(refuse)?
                    ._process
                    .as_raw_fd(),
            };
            self.store.verify_owner_scope(&scope)?;
            for stale in [
                ACTIVATION_INTENT,
                ACTIVATION_CONSUMED,
                ACTIVATION_SUPERVISOR_ONCE,
                ACTIVATION_OWNER_MAY_SEND,
                ACTIVATION_OWNER_MAY_SEND_V2,
                ACTIVATION_OWNER_CLAIM_V2,
            ] {
                if self.store.leaf_present(stale)? {
                    return Err(refuse());
                }
            }
            let header = self.store.load_header()?;
            if !header
                .leaves
                .contains_key(Path::new(ACTIVATION_OWNER_TERMINAL))
            {
                return Err(refuse());
            }
            self.store.verify_payloads(&header)?;
            if handoff != self.store.leaf_present(ACTIVATION_OWNER_TERMINAL_HANDOFF)? {
                return Err(refuse());
            }
            let marker = scope.marker.as_ref().ok_or_else(refuse)?;
            for (leaf, expected) in [
                (ACTIVATION_OWNER_CLAIM_V3, &marker.claim_sha256),
                (ACTIVATION_OWNER_MAY_SEND_V3, &marker.may_send_sha256),
            ] {
                if digest(&self.store.read(Path::new(leaf))?) != *expected {
                    return Err(refuse());
                }
                let (parent, name) = self.store.parent(Path::new(leaf), false)?;
                if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0
                    || unsafe { libc::fsync(parent.as_raw_fd()) } != 0
                {
                    return Err(refuse());
                }
            }
            if handoff {
                if !self.store.leaf_present(ACTIVATION_OWNER_TERMINAL_HANDOFF)?
                    || self.store.leaf_present(ACTIVATION_OWNER_MAY_SEND_V3)?
                    || self.store.leaf_present(ACTIVATION_OWNER_CLAIM_V3)?
                {
                    return Err(refuse());
                }
            } else if self.store.activation_leaf_present()? {
                return Err(refuse());
            }
            lock.revalidate().map_err(|_| refuse())
        }
        fn handoff_terminal_sha256(&self, lock: &InstallLock) -> Result<String> {
            lock.revalidate().map_err(|_| refuse())?;
            let header = self.store.load_header()?;
            let terminal = self.store.read(Path::new(ACTIVATION_OWNER_TERMINAL))?;
            let archive = self
                .store
                .read(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))?;
            let terminal_sha256 = digest(&terminal);
            if header.phase != Phase::Finalized
                || header.pending.is_some()
                || header.unit_pending.is_some()
                || header.leaves.get(Path::new(ACTIVATION_OWNER_TERMINAL)) != Some(&terminal_sha256)
                || header
                    .leaves
                    .get(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))
                    != Some(&digest(&archive))
                || !self.store.leaf_present(ACTIVATION_OWNER_TERMINAL_HANDOFF)?
                || self
                    .store
                    .read(Path::new(ACTIVATION_OWNER_TERMINAL_HANDOFF))?
                    .as_slice()
                    != self.terminal_handoff_bytes()?.as_slice()
                || self.store.leaf_present(ACTIVATION_OWNER_MAY_SEND_V3)?
                || self.store.leaf_present(ACTIVATION_OWNER_CLAIM_V3)?
                || self
                    .store
                    .leaf_present(ACTIVATION_OWNER_POSTTERMINAL_STOP_INTENT)?
            {
                return Err(refuse());
            }
            self.store.verify_payloads(&header)?;
            lock.revalidate().map_err(|_| refuse())?;
            Ok(terminal_sha256)
        }
        pub(super) fn terminal_success_socks(
            &self,
            lock: &InstallLock,
            launch: &mut crate::profile_auto_launch_service::LaunchProof,
        ) -> Result<()> {
            if self.product_commitments.as_ref().ok_or_else(refuse)?.mode != AutoMode::SocksOnly {
                return Err(refuse());
            }
            self.persist_terminal(lock, "finalized", false, Some(launch), None, None)?;
            self.write_terminal_handoff(lock)?;
            self.retire_exact_markers(lock, true)?;
            let terminal_sha256 = self.handoff_terminal_sha256(lock)?;
            launch
                .finish_terminal(&terminal_sha256)
                .map_err(|_| refuse())?;
            self.clear_terminal_handoff(lock)
        }
        pub(super) fn terminal_success_wide(
            &self,
            lock: &InstallLock,
            guardian: &mut crate::profile_auto_guardian::GuardDenyLease,
            launch: &mut crate::profile_auto_launch_service::LaunchProof,
            capture: &crate::profile_auto_guardian::CaptureReady,
            started: &mut crate::profile_auto_stopped_service::pid1::OwnedStart,
        ) -> Result<()> {
            let product = self.product_commitments.as_ref().ok_or_else(refuse)?;
            if !matches!(
                product.mode,
                AutoMode::WideRedirectSafe | AutoMode::FullWideTun
            ) {
                return Err(refuse());
            }
            let native_guard = product.native_guard.as_ref().ok_or_else(refuse)?;
            guardian.revalidate().map_err(|_| refuse())?;
            if guardian.native_receipt_sha256() != native_guard.guardian_receipt_sha256
                || guardian.policy_sha256() != native_guard.policy_sha256
                || guardian.nonce() != native_guard.guardian_nonce
                || guardian.guardian_pid() != native_guard.guardian_pid
                || guardian.private_unit() != product.private_unit
            {
                return Err(refuse());
            }
            capture
                .revalidate(guardian, started)
                .map_err(|_| refuse())?;
            if !hex64(capture.native_capture_sha256()) {
                return Err(refuse());
            }
            guardian.prepare_complete().map_err(|_| refuse())?;
            self.persist_terminal(lock, "finalized", false, Some(launch), Some(capture), None)?;
            self.write_terminal_handoff(lock)?;
            self.retire_exact_markers(lock, true)?;
            guardian.commit_done().map_err(|_| refuse())?;
            let terminal_sha256 = self.handoff_terminal_sha256(lock)?;
            launch
                .finish_terminal(&terminal_sha256)
                .map_err(|_| refuse())?;
            self.clear_terminal_handoff(lock)?;
            guardian.finish_handoff().map_err(|_| refuse())
        }
        pub(super) fn terminal_compensated_failure_socks(&self, lock: &InstallLock) -> Result<()> {
            let product = self.product_commitments.as_ref().ok_or_else(refuse)?;
            if product.mode != AutoMode::SocksOnly
                || product.native_guard.is_some()
                || self.stop_completed_sha256.is_none()
            {
                return Err(refuse());
            }
            if self
                .store
                .leaf_present(ACTIVATION_OWNER_POSTTERMINAL_STOP_INTENT)?
            {
                return self.persist_postterminal_compensated(lock, None);
            }
            self.persist_terminal(lock, "compensated-failure", true, None, None, None)?;
            self.retire_exact_markers(lock, false)
        }
        /// A known projection failure can become an admitted read-only stage
        /// only after the original manager connection has completed StopUnit
        /// and the held native guardian proved the matching capture inverse.
        /// Every uncertain branch leaves the one-use markers in place.
        pub(super) fn terminal_compensated_failure_wide(
            &self,
            lock: &InstallLock,
            guardian: &crate::profile_auto_guardian::GuardDenyLease,
            inverse: &mut crate::profile_auto_guardian::CompletedCaptureInverse,
        ) -> Result<()> {
            inverse.revalidate().map_err(|_| refuse())?;
            let product = self.product_commitments.as_ref().ok_or_else(refuse)?;
            if !matches!(
                product.mode,
                AutoMode::WideRedirectSafe | AutoMode::FullWideTun
            ) {
                return Err(refuse());
            }
            let native_guard = product.native_guard.as_ref().ok_or_else(refuse)?;
            let (stop_id, stop_path) = self.stop_submitted_job.as_ref().ok_or_else(refuse)?;
            if self.stop_completed_sha256.is_none()
                || inverse.stop_job_id() != *stop_id
                || inverse.stop_job_path() != stop_path.as_str()
                || inverse.stop_unit() != product.private_unit
                || Some(inverse.prior_invocation_id()) != self.start_invocation.as_deref()
                || inverse.boot_id() != product.boot_id
                || inverse.netns_ino() != product.pid1_netns.1
                || inverse.stage_identity() != product.binding.stage
                || inverse.guardian_nonce() != native_guard.guardian_nonce
                || guardian.nonce() != native_guard.guardian_nonce
                || guardian.guardian_pid() != native_guard.guardian_pid
                || !hex64(inverse.native_inverse_sha256())
                || !hex64(inverse.post_deny_policy_sha256())
            {
                return Err(refuse());
            }
            if self
                .store
                .leaf_present(ACTIVATION_OWNER_POSTTERMINAL_STOP_INTENT)?
            {
                self.persist_postterminal_compensated(lock, Some(inverse))?;
                return inverse.complete_effect().map_err(|_| refuse());
            }
            self.persist_terminal(lock, "compensated-failure", true, None, None, Some(inverse))?;
            inverse.complete_effect().map_err(|_| refuse())?;
            self.retire_exact_markers(lock, false)
        }
    }
    /// R26 scratch-only bridge. It is intentionally not called by the worker:
    /// the installed deny ACK, packet witness and PID-1 inverse do not exist.
    /// Keeping it inside `durable` lets it borrow the real post-marker owner
    /// and the worker's original InstallLock without constructing either.
    #[allow(dead_code)]
    mod guardian_bridge {
        use super::*;
        const GUARD_PARENT: &str = "/var/lib/aegis-install/client";
        const GUARD_LOCK: &str = "device-guard.conf.lock";
        const SPLIT: &str = "device-guard.conf.auto-lease-split";

        fn absent(parent: RawFd, name: &str) -> Result<()> {
            let mut m = std::mem::MaybeUninit::<libc::stat>::uninit();
            let rc = unsafe {
                libc::fstatat(
                    parent,
                    c(name)?.as_ptr(),
                    m.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(refuse())
            }
        }

        fn guard_identity(parent: RawFd, name: &str) -> Result<(OwnedFd, (u64, u64))> {
            if name != GUARD_LOCK {
                return Err(refuse());
            }
            let held = fd(unsafe {
                libc::openat(
                    parent,
                    c(name)?.as_ptr(),
                    libc::O_RDWR | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            let m = stat(held.as_raw_fd())?;
            if m.st_uid != 0
                || m.st_gid != 0
                || m.st_nlink != 1
                || m.st_mode != (libc::S_IFREG | 0o600)
            {
                return Err(refuse());
            }
            Ok((held, (m.st_dev as u64, m.st_ino as u64)))
        }

        fn held_guard_flock(held: RawFd, inode: u64) -> Result<()> {
            let flags = unsafe { libc::fcntl(held, libc::F_GETFD) };
            if held < 3
                || flags < 0
                || flags & libc::FD_CLOEXEC == 0
                || unsafe { libc::getpid() } < 2
            {
                return Err(refuse());
            }
            let mut bytes = Vec::new();
            File::open(format!("/proc/self/fdinfo/{held}"))
                .map_err(|_| refuse())?
                .take(16 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| refuse())?;
            if bytes.len() > 16 * 1024 {
                return Err(refuse());
            }
            let raw = std::str::from_utf8(&bytes).map_err(|_| refuse())?;
            let pid = unsafe { libc::getpid() }.to_string();
            let inode = inode.to_string();
            let mut inode_seen = false;
            let mut locks = 0;
            for line in raw.lines() {
                let f: Vec<_> = line.split_ascii_whitespace().collect();
                if f.first().copied() == Some("ino:") {
                    if inode_seen || f.len() != 2 || f[1] != inode {
                        return Err(refuse());
                    }
                    inode_seen = true;
                    continue;
                }
                if f.first().copied() != Some("lock:") {
                    continue;
                }
                if f.len() != 9
                    || f[2..6] != ["FLOCK", "ADVISORY", "WRITE", pid.as_str()]
                    || f[6].rsplit(':').next() != Some(inode.as_str())
                    || f[7..9] != ["0", "EOF"]
                {
                    return Err(refuse());
                }
                locks += 1;
            }
            if inode_seen && locks == 1 {
                Ok(())
            } else {
                Err(refuse())
            }
        }

        pub(super) struct GuardianLease<'owner, 'f, 'a> {
            owner: &'owner mut HeldPostMarker<'f, 'a>,
            parent: OwnedFd,
            parent_id: (u64, u64),
            guard: OwnedFd,
            guard_id: (u64, u64),
            ticket_reserved: bool,
        }
        impl<'owner, 'f, 'a> GuardianLease<'owner, 'f, 'a> {
            pub(super) fn acquire(
                owner: &'owner mut HeldPostMarker<'f, 'a>,
            ) -> std::result::Result<Self, OwnerMarkerState> {
                Self::acquire_inner(owner).map_err(|_| OwnerMarkerState::RecoveryRequired)
            }
            fn acquire_inner(owner: &'owner mut HeldPostMarker<'f, 'a>) -> Result<Self> {
                let lock = owner.install_lock.ok_or_else(refuse)?;
                lock.revalidate().map_err(|_| refuse())?;
                let parent = open_absolute(Path::new(GUARD_PARENT), 0, false)?;
                let p = stat(parent.as_raw_fd())?;
                if p.st_uid != 0 || p.st_gid != 0 || p.st_mode & 0o022 != 0 {
                    return Err(refuse());
                }
                let (guard, guard_id) = guard_identity(parent.as_raw_fd(), GUARD_LOCK)?;
                if unsafe { libc::flock(guard.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                    return Err(refuse());
                }
                let lease = Self {
                    owner,
                    parent,
                    parent_id: (p.st_dev as u64, p.st_ino as u64),
                    guard,
                    guard_id,
                    ticket_reserved: false,
                };
                lease.revalidate_preclaim().map_err(|_| refuse())?;
                Ok(lease)
            }
            fn revalidate_common(&self) -> std::result::Result<(), OwnerMarkerState> {
                let attempt = || -> Result<()> {
                    let lock = self.owner.install_lock.ok_or_else(refuse)?;
                    lock.revalidate().map_err(|_| refuse())?;
                    let actual = self.owner.fence.read_binding_held().map_err(|_| refuse())?;
                    if actual != self.owner.commitments.binding {
                        return Err(refuse());
                    }
                    let marker = self
                        .owner
                        .fence
                        .store
                        .read(Path::new(ACTIVATION_OWNER_MAY_SEND_V2))?;
                    if digest(&marker) != self.owner.marker_sha256 {
                        return Err(refuse());
                    }
                    let p = stat(self.parent.as_raw_fd())?;
                    if (p.st_dev as u64, p.st_ino as u64) != self.parent_id
                        || p.st_uid != 0
                        || p.st_gid != 0
                        || p.st_mode & 0o022 != 0
                    {
                        return Err(refuse());
                    }
                    let fresh = open_absolute(Path::new(GUARD_PARENT), 0, false)?;
                    let n = stat(fresh.as_raw_fd())?;
                    if (n.st_dev as u64, n.st_ino as u64) != self.parent_id {
                        return Err(refuse());
                    }
                    let (named, id) = guard_identity(self.parent.as_raw_fd(), GUARD_LOCK)?;
                    let g = stat(self.guard.as_raw_fd())?;
                    if id != self.guard_id || (g.st_dev as u64, g.st_ino as u64) != id {
                        return Err(refuse());
                    }
                    drop(named);
                    held_guard_flock(self.guard.as_raw_fd(), id.1)?;
                    absent(self.parent.as_raw_fd(), SPLIT)?;
                    lock.revalidate().map_err(|_| refuse())
                };
                attempt().map_err(|_| OwnerMarkerState::RecoveryRequired)
            }
            pub(super) fn revalidate_preclaim(&self) -> std::result::Result<(), OwnerMarkerState> {
                self.revalidate_common()?;
                if self.owner.claimed
                    || self
                        .owner
                        .fence
                        .store
                        .leaf_present(ACTIVATION_OWNER_CLAIM_V2)
                        .map_err(|_| OwnerMarkerState::RecoveryRequired)?
                {
                    return Err(OwnerMarkerState::RecoveryRequired);
                }
                Ok(())
            }
            pub(super) fn reserve_inert_ticket(
                &mut self,
            ) -> std::result::Result<TicketReservation<'_, 'owner, 'f, 'a>, OwnerMarkerState>
            {
                self.revalidate_preclaim()?;
                if self.ticket_reserved {
                    return Err(OwnerMarkerState::RecoveryRequired);
                }
                self.ticket_reserved = true;
                Ok(TicketReservation {
                    lease: self,
                    attempted: false,
                })
            }
        }
        pub(super) struct TicketReservation<'ticket, 'owner, 'f, 'a> {
            lease: &'ticket mut GuardianLease<'owner, 'f, 'a>,
            attempted: bool,
        }
        impl<'ticket, 'owner, 'f, 'a> TicketReservation<'ticket, 'owner, 'f, 'a> {
            pub(super) fn consume_inert_once(
                &mut self,
            ) -> std::result::Result<(), OwnerMarkerState> {
                if self.attempted {
                    return Err(OwnerMarkerState::RecoveryRequired);
                }
                self.attempted = true;
                self.lease.revalidate_preclaim()?;
                Err(OwnerMarkerState::RecoveryRequired)
            }
            /// Burns the ticket before any possible claim write. The result
            /// holds every original lease and Store fence; it cannot send.
            pub(super) fn claim_ambiguity_once(
                mut self,
            ) -> std::result::Result<PostClaim<'ticket, 'owner, 'f, 'a>, OwnerMarkerState>
            {
                if self.attempted {
                    return Err(OwnerMarkerState::RecoveryRequired);
                }
                self.attempted = true;
                self.lease.revalidate_preclaim()?;
                self.lease.owner.claim_inert_once()?;
                let bytes = self
                    .lease
                    .owner
                    .fence
                    .store
                    .read(Path::new(ACTIVATION_OWNER_CLAIM_V2))
                    .map_err(|_| OwnerMarkerState::RecoveryRequired)?;
                let claim_sha256 = digest(&bytes);
                let post = PostClaim {
                    lease: self.lease,
                    claim_sha256,
                    send_attempted: false,
                };
                post.revalidate()?;
                Ok(post)
            }
        }

        pub(super) struct PostClaim<'ticket, 'owner, 'f, 'a> {
            lease: &'ticket mut GuardianLease<'owner, 'f, 'a>,
            claim_sha256: String,
            send_attempted: bool,
        }
        pub(super) fn validate_claim_marker(
            owner: &HeldPostMarker<'_, '_>,
            sealed_digest: &str,
        ) -> Result<()> {
            if !owner.claimed {
                return Err(refuse());
            }
            let expected = serde_json::to_vec(&OwnerClaimV2 {
                schema: 2,
                may_send_sha256: owner.marker_sha256.clone(),
                nonce: owner.commitments.binding.transaction_nonce.clone(),
                stage: owner.commitments.binding.stage,
            })
            .map_err(|_| refuse())?;
            let actual = owner
                .fence
                .store
                .read(Path::new(ACTIVATION_OWNER_CLAIM_V2))?;
            if actual.as_slice() != expected || digest(&actual) != sealed_digest {
                return Err(refuse());
            }
            Ok(())
        }
        impl PostClaim<'_, '_, '_, '_> {
            pub(super) fn revalidate(&self) -> std::result::Result<(), OwnerMarkerState> {
                self.lease.revalidate_common()?;
                validate_claim_marker(self.lease.owner, &self.claim_sha256)
                    .map_err(|_| OwnerMarkerState::RecoveryRequired)?;
                self.lease.revalidate_common()
            }
            /// There is deliberately no native/PID-1 sender in this state.
            pub(super) fn refuse_send_once(&mut self) -> std::result::Result<(), OwnerMarkerState> {
                if self.send_attempted {
                    return Err(OwnerMarkerState::RecoveryRequired);
                }
                self.send_attempted = true;
                self.revalidate()?;
                Err(OwnerMarkerState::RecoveryRequired)
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use std::os::unix::fs::{symlink, PermissionsExt};

            #[test]
            fn split_marker_presence_and_broken_symlink_both_refuse() {
                let tmp = tempfile::tempdir().unwrap();
                let path = CString::new(tmp.path().as_os_str().as_bytes()).unwrap();
                let parent = fd(unsafe {
                    libc::open(
                        path.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                })
                .unwrap();
                assert!(absent(parent.as_raw_fd(), SPLIT).is_ok());
                let marker = tmp.path().join(SPLIT);
                std::fs::write(&marker, b"capture-recovery-in-progress-v1\n").unwrap();
                assert!(absent(parent.as_raw_fd(), SPLIT).is_err());
                std::fs::remove_file(&marker).unwrap();
                symlink("missing-target", &marker).unwrap();
                assert!(absent(parent.as_raw_fd(), SPLIT).is_err());
            }

            #[test]
            fn held_guard_fd_must_retain_its_flock() {
                if unsafe { libc::geteuid() } != 0 {
                    return;
                }
                let tmp = tempfile::tempdir().unwrap();
                let path = CString::new(tmp.path().as_os_str().as_bytes()).unwrap();
                let parent = fd(unsafe {
                    libc::open(
                        path.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                })
                .unwrap();
                let lock = tmp.path().join(GUARD_LOCK);
                std::fs::write(&lock, b"").unwrap();
                std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
                let (held, id) = guard_identity(parent.as_raw_fd(), GUARD_LOCK).unwrap();
                assert!(held_guard_flock(held.as_raw_fd(), id.1).is_err());
                assert_eq!(
                    unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                    0
                );
                assert!(held_guard_flock(held.as_raw_fd(), id.1).is_ok());
                assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_UN) }, 0);
                assert!(held_guard_flock(held.as_raw_fd(), id.1).is_err());
            }
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ActivationIntent {
        schema: u32,
        nonce: String,
        stage: (u64, u64),
        header_sha256: String,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ActivationConsumed {
        schema: u32,
        intent_sha256: String,
        stage: (u64, u64),
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum RecoveryTicket {
        IntentOnly,
        Consumed,
    }
    fn c(s: &str) -> Result<CString> {
        CString::new(s).map_err(|_| refuse())
    }
    fn fd(value: RawFd) -> Result<OwnedFd> {
        if value < 0 {
            Err(refuse())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(value) })
        }
    }
    fn stat(fd: RawFd) -> Result<libc::stat> {
        let mut value = std::mem::MaybeUninit::uninit();
        if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
            return Err(refuse());
        }
        Ok(unsafe { value.assume_init() })
    }
    fn open_dir(parent: RawFd, name: &CStr) -> Result<OwnedFd> {
        fd(unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })
    }
    fn valid_dir(fd: RawFd, uid: u32, terminal: bool) -> Result<()> {
        let m = stat(fd)?;
        let sticky = !terminal && m.st_uid == 0 && m.st_mode & libc::S_ISVTX != 0;
        if m.st_mode & libc::S_IFMT != libc::S_IFDIR
            || !(m.st_uid == 0 || m.st_uid == uid)
            || (m.st_mode & 0o022 != 0 && !sticky)
            || (terminal && (m.st_uid != uid || m.st_mode & 0o7777 != 0o700))
        {
            return Err(refuse());
        }
        Ok(())
    }
    fn open_absolute(path: &Path, uid: u32, terminal: bool) -> Result<OwnedFd> {
        if !absolute(path) {
            return Err(refuse());
        }
        let root = c("/")?;
        let mut held = fd(unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        valid_dir(held.as_raw_fd(), uid, false)?;
        for part in path.components() {
            if let Component::Normal(part) = part {
                let part = CString::new(part.as_bytes()).map_err(|_| refuse())?;
                held = open_dir(held.as_raw_fd(), &part)?;
                valid_dir(held.as_raw_fd(), uid, false)?;
            }
        }
        valid_dir(held.as_raw_fd(), uid, terminal)?;
        Ok(held)
    }
    fn nonce() -> String {
        let bytes: [u8; 16] = rand::random();
        format!(".auto-{}", hex::encode(bytes))
    }
    /// The last header.json bytes this Store parsed into a Header that passed
    /// Header::validate(uid). serde_json::from_slice::<Header> and
    /// Header::validate are deterministic and do no I/O, so their outcome is
    /// a function of (bytes, uid) alone, and a Store's uid never changes.
    /// Only a success is held, never a refusal. The file is still read fresh
    /// on every call; only byte-identical bytes skip the repeated parse and
    /// validate. The held bytes stay Zeroizing and are dropped with the Store.
    #[derive(Default)]
    struct HeaderAdmission(Mutex<Option<Zeroizing<Vec<u8>>>>);
    impl HeaderAdmission {
        fn admitted(&self, bytes: &[u8]) -> bool {
            self.0
                .lock()
                .is_ok_and(|held| held.as_ref().is_some_and(|held| held.as_slice() == bytes))
        }
        fn remember(&self, bytes: &[u8]) {
            if let Ok(mut held) = self.0.lock() {
                *held = Some(Zeroizing::new(bytes.to_vec()));
            }
        }
    }
    pub(super) struct Store {
        root: OwnedFd,
        activation_root: OwnedFd,
        activation_path: PathBuf,
        // None admits a pre-lock stage for inspection only. It must never be
        // upgraded in place while an older writer could still be running.
        mutation_lock_identity: Option<(u64, u64)>,
        publication_fence_identity: Option<(u64, u64)>,
        path: PathBuf,
        uid: u32,
        header_admission: HeaderAdmission,
    }
    impl Store {
        pub(super) fn enter_fresh_stop_read_scope(
            &self,
            stage_id: (u64, u64),
            publication_fd: RawFd,
            mutation_fd: RawFd,
        ) -> Result<RestoreFreshStopReadScope> {
            self.require_activation_root()?;
            if self.identity()? != stage_id
                || Store::lock_identity(publication_fd, self.uid)?
                    != self.publication_fence_identity.ok_or_else(refuse)?
                || Store::lock_identity(mutation_fd, self.uid)?
                    != self.mutation_lock_identity.ok_or_else(refuse)?
            {
                return Err(refuse());
            }
            let header_bytes = self.read(Path::new("header.json"))?;
            let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| refuse())?;
            header.validate(self.uid)?;
            let terminal_bytes = self.read(Path::new(ACTIVATION_OWNER_TERMINAL))?;
            let terminal_sha256 = digest(&terminal_bytes);
            let terminal: serde_json::Value =
                serde_json::from_slice(&terminal_bytes).map_err(|_| refuse())?;
            if header.phase != Phase::Finalized
                || header.pending.is_some()
                || header.unit_pending.is_some()
                || header.leaves.get(Path::new(ACTIVATION_OWNER_TERMINAL)) != Some(&terminal_sha256)
                || terminal.get("outcome").and_then(|v| v.as_str()) != Some("finalized")
                || terminal.get("transaction_nonce").and_then(|v| v.as_str())
                    != Some(header.transaction_nonce.as_str())
                || terminal
                    .get("stage")
                    .and_then(|v| v.as_array())
                    .is_none_or(|v| {
                        v.len() != 2
                            || v[0].as_u64() != Some(stage_id.0)
                            || v[1].as_u64() != Some(stage_id.1)
                    })
            {
                return Err(refuse());
            }
            let scope = FreshStopReadScope {
                stage_id,
                stage_path: self.path.clone(),
                header_sha256: digest(&header_bytes),
                terminal_sha256,
                publication_fd,
                mutation_fd,
            };
            if CURRENT_OWNER.with(|current| current.borrow().is_some()) {
                return Err(refuse());
            }
            FRESH_STOP_READ.with(|current| {
                let mut current = current.borrow_mut();
                if current.is_some() {
                    return Err(refuse());
                }
                *current = Some(scope);
                Ok(RestoreFreshStopReadScope)
            })
        }
        fn verify_fresh_stop_read_scope(&self, scope: &FreshStopReadScope) -> Result<()> {
            self.revalidate_activation_root()?;
            let activation = stat(self.activation_root.as_raw_fd())?;
            if (activation.st_dev as u64, activation.st_ino as u64) != scope.stage_id
                || self.activation_path != scope.stage_path
                || !self.path.starts_with(&scope.stage_path)
                || Store::lock_identity(scope.publication_fd, self.uid)?
                    != self.publication_fence_identity.ok_or_else(refuse)?
                || Store::lock_identity(scope.mutation_fd, self.uid)?
                    != self.mutation_lock_identity.ok_or_else(refuse)?
            {
                return Err(refuse());
            }
            let root = Self {
                root: self.activation_root.try_clone().map_err(|_| refuse())?,
                activation_root: self.activation_root.try_clone().map_err(|_| refuse())?,
                activation_path: self.activation_path.clone(),
                mutation_lock_identity: self.mutation_lock_identity,
                publication_fence_identity: self.publication_fence_identity,
                path: self.activation_path.clone(),
                uid: self.uid,
                header_admission: HeaderAdmission::default(),
            };
            let header_bytes = root.read(Path::new("header.json"))?;
            let terminal_bytes = root.read(Path::new(ACTIVATION_OWNER_TERMINAL))?;
            let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| refuse())?;
            if digest(&header_bytes) != scope.header_sha256
                || digest(&terminal_bytes) != scope.terminal_sha256
                || header.phase != Phase::Finalized
                || header.leaves.get(Path::new(ACTIVATION_OWNER_TERMINAL))
                    != Some(&scope.terminal_sha256)
            {
                return Err(refuse());
            }
            Ok(())
        }
        fn verify_owner_scope(&self, scope: &OwnerScope) -> Result<()> {
            self.revalidate_activation_root()?;
            let actual = stat(self.activation_root.as_raw_fd())?;
            let activation_store = Self {
                root: self.activation_root.try_clone().map_err(|_| refuse())?,
                activation_root: self.activation_root.try_clone().map_err(|_| refuse())?,
                activation_path: self.activation_path.clone(),
                mutation_lock_identity: self.mutation_lock_identity,
                publication_fence_identity: self.publication_fence_identity,
                path: self.activation_path.clone(),
                uid: self.uid,
                header_admission: HeaderAdmission::default(),
            };
            if (actual.st_dev as u64, actual.st_ino as u64) != scope.activation_id
                || (actual.st_dev as u64, actual.st_ino as u64) != scope.stage_id
                || self.activation_path != scope.stage_path
                || !self.path.starts_with(&scope.stage_path)
                || Store::lock_identity(scope.publication_fd, self.uid)?
                    != self.publication_fence_identity.ok_or_else(refuse)?
                || Store::lock_identity(scope.mutation_fd, self.uid)?
                    != self.mutation_lock_identity.ok_or_else(refuse)?
            {
                return Err(refuse());
            }
            match &scope.marker {
                Some(marker) => {
                    let may_present = activation_store.leaf_present(marker.may_send_leaf)?;
                    let claim_present = activation_store.leaf_present(marker.claim_leaf)?;
                    if may_present
                        && digest(&activation_store.read(Path::new(marker.may_send_leaf))?)
                            != marker.may_send_sha256
                    {
                        return Err(refuse());
                    }
                    if claim_present
                        && digest(&activation_store.read(Path::new(marker.claim_leaf))?)
                            != marker.claim_sha256
                    {
                        return Err(refuse());
                    }
                    if !may_present || !claim_present {
                        if !scope.inverse_after_terminal
                            || marker.may_send_leaf != ACTIVATION_OWNER_MAY_SEND_V3
                            || marker.claim_leaf != ACTIVATION_OWNER_CLAIM_V3
                        {
                            return Err(refuse());
                        }
                        let header = activation_store.load_header()?;
                        let archive_bytes =
                            activation_store.read(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))?;
                        let terminal_bytes =
                            activation_store.read(Path::new(ACTIVATION_OWNER_TERMINAL))?;
                        if header
                            .leaves
                            .get(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))
                            != Some(&digest(&archive_bytes))
                            || header.leaves.get(Path::new(ACTIVATION_OWNER_TERMINAL))
                                != Some(&digest(&terminal_bytes))
                        {
                            return Err(refuse());
                        }
                        let archive: OwnerMarkerArchive =
                            serde_json::from_slice(&archive_bytes).map_err(|_| refuse())?;
                        let may = hex::decode(&archive.may_send_hex).map_err(|_| refuse())?;
                        let claim = hex::decode(&archive.claim_hex).map_err(|_| refuse())?;
                        let terminal: serde_json::Value =
                            serde_json::from_slice(&terminal_bytes).map_err(|_| refuse())?;
                        if archive.schema != 1
                            || archive.may_send_sha256 != marker.may_send_sha256
                            || archive.claim_sha256 != marker.claim_sha256
                            || digest(&may) != marker.may_send_sha256
                            || digest(&claim) != marker.claim_sha256
                            || terminal.get("may_send_sha256").and_then(|v| v.as_str())
                                != Some(marker.may_send_sha256.as_str())
                            || terminal.get("claim_sha256").and_then(|v| v.as_str())
                                != Some(marker.claim_sha256.as_str())
                            || terminal
                                .get("stage")
                                .and_then(|v| v.as_array())
                                .is_none_or(|v| {
                                    v.len() != 2
                                        || v[0].as_u64() != Some(scope.stage_id.0)
                                        || v[1].as_u64() != Some(scope.stage_id.1)
                                })
                        {
                            return Err(refuse());
                        }
                    }
                }
                None => {
                    if self.activation_leaf_present()?
                        || activation_store.leaf_present(ACTIVATION_OWNER_TERMINAL)?
                    {
                        return Err(refuse());
                    }
                }
            }
            Ok(())
        }
        fn owner_scope(&self) -> Result<Option<OwnerScope>> {
            let scope = CURRENT_OWNER.with(|current| current.borrow().clone());
            if let Some(scope) = &scope {
                self.verify_owner_scope(scope)?;
            }
            Ok(scope)
        }
        pub(super) fn owner_effect_active(&self) -> Result<bool> {
            Ok(self.owner_scope()?.is_some())
        }
        fn require_writer_admission(&self) -> Result<()> {
            if self.activation_leaf_present()? && self.owner_scope()?.is_none() {
                return Err(refuse());
            }
            Ok(())
        }
        fn clone_held(&self) -> Result<Self> {
            self.revalidate()?;
            self.revalidate_activation_root()?;
            Ok(Self {
                root: self.root.try_clone().map_err(|_| refuse())?,
                activation_root: self.activation_root.try_clone().map_err(|_| refuse())?,
                activation_path: self.activation_path.clone(),
                mutation_lock_identity: self.mutation_lock_identity,
                publication_fence_identity: self.publication_fence_identity,
                path: self.path.clone(),
                uid: self.uid,
                header_admission: HeaderAdmission::default(),
            })
        }
        fn lock_identity(fd: RawFd, uid: u32) -> Result<(u64, u64)> {
            let s = stat(fd)?;
            if s.st_mode != (libc::S_IFREG | 0o600) || s.st_uid != uid || s.st_nlink != 1 {
                return Err(refuse());
            }
            Ok((s.st_dev as u64, s.st_ino as u64))
        }
        fn open_mutation_lock(root: RawFd, uid: u32) -> Result<(OwnedFd, (u64, u64))> {
            let name = c(MUTATION_LOCK)?;
            let held = fd(unsafe {
                libc::openat(
                    root,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            })?;
            let identity = Self::lock_identity(held.as_raw_fd(), uid)?;
            Ok((held, identity))
        }
        fn open_publication_fence(root: RawFd, uid: u32) -> Result<(OwnedFd, (u64, u64))> {
            let name = c(PUBLICATION_FENCE)?;
            let held = fd(unsafe {
                libc::openat(
                    root,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            })?;
            let identity = Self::lock_identity(held.as_raw_fd(), uid)?;
            Ok((held, identity))
        }
        fn publication_fence_held(&self, operation: libc::c_int) -> Result<PublicationLease> {
            let expected = self.publication_fence_identity.ok_or_else(refuse)?;
            let (held, identity) =
                Self::open_publication_fence(self.activation_root.as_raw_fd(), self.uid)?;
            if identity != expected
                || unsafe { libc::flock(held.as_raw_fd(), operation | libc::LOCK_NB) } != 0
            {
                return Err(refuse());
            }
            let (_, named_identity) =
                Self::open_publication_fence(self.activation_root.as_raw_fd(), self.uid)?;
            if named_identity != identity {
                return Err(refuse());
            }
            self.revalidate_activation_root()?;
            self.revalidate()?;
            Ok(PublicationLease { _process: held })
        }
        fn publication_fence(&self, operation: libc::c_int) -> Result<PublicationLease> {
            if let Some(scope) = self.owner_scope()? {
                return Ok(PublicationLease {
                    _process: fd(unsafe {
                        libc::fcntl(scope.publication_fd, libc::F_DUPFD_CLOEXEC, 0)
                    })?,
                });
            }
            if self.activation_leaf_present()? {
                return Err(refuse());
            }
            let held = self.publication_fence_held(operation)?;
            if self.activation_leaf_present()? {
                return Err(refuse());
            }
            Ok(held)
        }
        /// A future publisher must retain this lease through effect and
        /// receipt. Current production publisher call sites do not use it.
        #[allow(dead_code)]
        pub(super) fn publication_lease(&self) -> Result<PublicationLease> {
            self.publication_fence(libc::LOCK_SH)
        }
        /// Prerequisite only. The leases are acquired in publication ->
        /// mutation -> stage-root order and held by the returned value.
        /// Every failure is typed recovery; no PID1 call is reachable here.
        #[allow(dead_code)]
        pub(super) fn begin_owner_marker_fence(
            &self,
        ) -> std::result::Result<OwnerMarkerFence<'_>, OwnerMarkerState> {
            let attempt = || -> Result<OwnerMarkerFence<'_>> {
                // Early classification protects a stale marker even if later
                // path/lock admission fails. Recheck under all held fences.
                if self.activation_leaf_present()?
                    || self.leaf_present(ACTIVATION_OWNER_TERMINAL)?
                {
                    return Err(refuse());
                }
                let publication = self.publication_fence_held(libc::LOCK_EX)?;
                let mutation = self.mutation_guard()?;
                self.require_activation_root()?;
                self.exclusive()?;
                if self.activation_leaf_present()?
                    || self.leaf_present(ACTIVATION_OWNER_TERMINAL)?
                {
                    return Err(refuse());
                }
                Ok(OwnerMarkerFence {
                    store: self,
                    state: OwnerMarkerState::Fresh,
                    _publication: publication,
                    _mutation: mutation,
                })
            };
            attempt().map_err(|_| OwnerMarkerState::RecoveryRequired)
        }
        /// First half of an actor admission. This consumes the Store and keeps
        /// it in the returned value until it is moved into StageGuard. No
        /// marker or effect is emitted.
        #[allow(dead_code)]
        pub(super) fn begin_owner_stage_locks(
            self,
        ) -> std::result::Result<OwnerStageLocks, OwnerMarkerState> {
            let attempt = || -> Result<OwnerStageLocks> {
                if self.activation_leaf_present()?
                    || self.leaf_present(ACTIVATION_OWNER_TERMINAL)?
                {
                    return Err(refuse());
                }
                let publication = self.publication_fence_held(libc::LOCK_EX)?;
                let mutation = self.mutation_guard()?;
                self.require_activation_root()?;
                if self.activation_leaf_present()?
                    || self.leaf_present(ACTIVATION_OWNER_TERMINAL)?
                {
                    return Err(refuse());
                }
                let activation = stat(self.activation_root.as_raw_fd())?;
                let stage_id = self.identity()?;
                let uid = self.uid;
                Ok(OwnerStageLocks {
                    store: self,
                    publication,
                    mutation,
                    stage_id,
                    activation_id: (activation.st_dev as u64, activation.st_ino as u64),
                    uid,
                })
            };
            attempt().map_err(|_| OwnerMarkerState::RecoveryRequired)
        }
        fn mutation_guard(&self) -> Result<MutationGuard> {
            if FRESH_STOP_READ.with(|current| current.borrow().is_some()) {
                return Err(refuse());
            }
            if let Some(scope) = self.owner_scope()? {
                return Ok(MutationGuard {
                    _process: fd(unsafe {
                        libc::fcntl(scope.mutation_fd, libc::F_DUPFD_CLOEXEC, 0)
                    })?,
                    _thread: None,
                });
            }
            let expected = self.mutation_lock_identity.ok_or_else(refuse)?;
            let thread = MUTATION_THREAD_LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .map_err(|_| refuse())?;
            let (held, identity) =
                Self::open_mutation_lock(self.activation_root.as_raw_fd(), self.uid)?;
            if identity != expected
                || unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
            {
                return Err(refuse());
            }
            let (_, named_identity) =
                Self::open_mutation_lock(self.activation_root.as_raw_fd(), self.uid)?;
            if named_identity != identity {
                return Err(refuse());
            }
            self.revalidate_activation_root()?;
            // A Store may hold a receipt descendant rather than the stage
            // root. The stage lock alone does not bind this held descriptor
            // to its original child name after a rename or substitution.
            self.revalidate()?;
            Ok(MutationGuard {
                _process: held,
                _thread: Some(thread),
            })
        }
        fn revalidate_activation_root(&self) -> Result<()> {
            valid_dir(self.activation_root.as_raw_fd(), self.uid, true)?;
            let s = stat(self.activation_root.as_raw_fd())?;
            let named = open_absolute(&self.activation_path, self.uid, true)?;
            let n = stat(named.as_raw_fd())?;
            if s.st_dev != n.st_dev || s.st_ino != n.st_ino {
                return Err(refuse());
            }
            Ok(())
        }
        fn activation_leaf_present_on(root: RawFd) -> Result<bool> {
            for name in [
                ACTIVATION_INTENT,
                ACTIVATION_CONSUMED,
                ACTIVATION_SUPERVISOR_ONCE,
                ACTIVATION_OWNER_MAY_SEND,
                ACTIVATION_OWNER_MAY_SEND_V2,
                ACTIVATION_OWNER_CLAIM_V2,
                ACTIVATION_OWNER_MAY_SEND_V3,
                ACTIVATION_OWNER_CLAIM_V3,
                ACTIVATION_OWNER_POSTTERMINAL_STOP_INTENT,
                ACTIVATION_OWNER_TERMINAL_HANDOFF,
                ACTIVATION_OWNER_NATIVE_RECOVERY,
                finalized_stop::INTENT,
            ] {
                let name = c(name)?;
                let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
                let result = unsafe {
                    libc::fstatat(
                        root,
                        name.as_ptr(),
                        status.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if result == 0 {
                    return Ok(true);
                }
                if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                    return Err(refuse());
                }
            }
            Ok(false)
        }
        /// Presence alone revokes ordinary stage mutation. A torn or orphaned
        /// activation leaf is recovery-only; it never permits another start.
        pub(super) fn activation_leaf_present(&self) -> Result<bool> {
            Self::activation_leaf_present_on(self.activation_root.as_raw_fd())
        }
        /// A read-only worker classification before any command-specific
        /// refusal. It cannot grant a phase or inspect a recovery ticket.
        pub(super) fn marker_preflight_for_worker(
            path: &Path,
            uid: u32,
        ) -> std::result::Result<(), OwnerMarkerState> {
            let root =
                open_absolute(path, uid, true).map_err(|_| OwnerMarkerState::RecoveryRequired)?;
            if Self::activation_leaf_present_on(root.as_raw_fd())
                .map_err(|_| OwnerMarkerState::RecoveryRequired)?
            {
                return Err(OwnerMarkerState::RecoveryRequired);
            }
            Ok(())
        }
        /// Worker admission observes the activation marker before reopening
        /// lock leaves. Any uncertainty is typed recovery, never clean retry.
        /// This does not parse a recovery receipt or grant activation.
        pub(super) fn reopen_for_worker(
            path: &Path,
            uid: u32,
        ) -> std::result::Result<Self, OwnerMarkerState> {
            let map = |_| OwnerMarkerState::RecoveryRequired;
            let before = open_absolute(path, uid, true).map_err(map)?;
            if Self::activation_leaf_present_on(before.as_raw_fd()).map_err(map)? {
                return Err(OwnerMarkerState::RecoveryRequired);
            }
            let store = Self::reopen(path, uid).map_err(map)?;
            let original = stat(before.as_raw_fd()).map_err(map)?;
            let reopened = stat(store.root.as_raw_fd()).map_err(map)?;
            if original.st_dev != reopened.st_dev
                || original.st_ino != reopened.st_ino
                || store.activation_leaf_present().map_err(map)?
            {
                return Err(OwnerMarkerState::RecoveryRequired);
            }
            Ok(store)
        }
        /// Read-only reentry: neither variant permits another manager request.
        #[allow(dead_code)] // consumed activation has no production caller yet
        pub(super) fn recovery_ticket(&self) -> Result<RecoveryTicket> {
            self.require_activation_root()?;
            // The owner marker has no recovery parser in this prerequisite.
            // It must never be interpreted as the older recovery-only ticket.
            if self.leaf_present(ACTIVATION_OWNER_MAY_SEND)?
                || self.leaf_present(ACTIVATION_OWNER_MAY_SEND_V2)?
                || self.leaf_present(ACTIVATION_OWNER_CLAIM_V2)?
                || self.leaf_present(ACTIVATION_OWNER_MAY_SEND_V3)?
                || self.leaf_present(ACTIVATION_OWNER_CLAIM_V3)?
                || self.leaf_present(finalized_stop::INTENT)?
            {
                return Err(refuse());
            }
            // R8's one-shot leaf has no authenticated recovery parser or
            // installed supervisor. Its coexistence with either canonical
            // recovery variant is ambiguous and must never be accepted.
            if self.leaf_present(ACTIVATION_SUPERVISOR_ONCE)? {
                return Err(refuse());
            }
            let header_bytes = self.read(Path::new("header.json"))?;
            let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| refuse())?;
            header.validate(self.uid)?;
            self.verify_payloads(&header)?;
            let intent_bytes = self.read(Path::new(ACTIVATION_INTENT))?;
            let intent: ActivationIntent =
                serde_json::from_slice(&intent_bytes).map_err(|_| refuse())?;
            if intent.schema != 1
                || intent.nonce != header.transaction_nonce
                || intent.stage != self.identity()?
                || intent.header_sha256 != digest(&header_bytes)
            {
                return Err(refuse());
            }
            if !self.leaf_present(ACTIVATION_CONSUMED)? {
                self.revalidate()?;
                if self.leaf_present(ACTIVATION_SUPERVISOR_ONCE)? {
                    return Err(refuse());
                }
                return Ok(RecoveryTicket::IntentOnly);
            }
            let bytes = self.read(Path::new(ACTIVATION_CONSUMED))?;
            let consumed: ActivationConsumed =
                serde_json::from_slice(&bytes).map_err(|_| refuse())?;
            if consumed.schema != 1
                || consumed.intent_sha256 != digest(&intent_bytes)
                || consumed.stage != intent.stage
            {
                return Err(refuse());
            }
            self.revalidate()?;
            if self.leaf_present(ACTIVATION_SUPERVISOR_ONCE)? {
                return Err(refuse());
            }
            Ok(RecoveryTicket::Consumed)
        }
        fn leaf_present(&self, name: &str) -> Result<bool> {
            let name = c(name)?;
            let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
            let result = unsafe {
                libc::fstatat(
                    self.root.as_raw_fd(),
                    name.as_ptr(),
                    status.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result == 0 {
                return Ok(true);
            }
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(false)
            } else {
                Err(refuse())
            }
        }
        fn require_activation_root(&self) -> Result<()> {
            let a = stat(self.root.as_raw_fd())?;
            let b = stat(self.activation_root.as_raw_fd())?;
            if a.st_dev != b.st_dev || a.st_ino != b.st_ino {
                return Err(refuse());
            }
            self.revalidate()
        }
        /// This seal is recovery-only. It deliberately has no StartUnit,
        /// network grant, rollback or replay method.
        #[allow(dead_code)] // no activation consumer until independent watchdog exists
        pub(super) fn arm_recovery_only(&self) -> Result<()> {
            let _publication_fence = self.publication_fence(libc::LOCK_EX)?;
            let _guard = self.mutation_guard()?;
            self.require_activation_root()?;
            self.exclusive()?;
            if self.activation_leaf_present()? {
                return Err(refuse());
            }
            let header_bytes = self.read(Path::new("header.json"))?;
            let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| refuse())?;
            header.validate(self.uid)?;
            self.verify_payloads(&header)?;
            if header.phase != Phase::Metadata
                || header.pending.is_some()
                || header.unit_pending.is_some()
                || header.capture_started
            {
                return Err(refuse());
            }
            let bytes = serde_json::to_vec(&ActivationIntent {
                schema: 1,
                nonce: header.transaction_nonce,
                stage: self.identity()?,
                header_sha256: digest(&header_bytes),
            })
            .map_err(|_| refuse())?;
            self.write_activation_leaf(ACTIVATION_INTENT, &bytes)
        }
        #[allow(dead_code)] // no activation consumer until independent watchdog exists
        pub(super) fn consume_recovery_only(&self) -> Result<()> {
            let _guard = self.mutation_guard()?;
            self.require_activation_root()?;
            self.exclusive()?;
            if self.recovery_ticket()? != RecoveryTicket::IntentOnly {
                return Err(refuse());
            }
            let intent_bytes = self.read(Path::new(ACTIVATION_INTENT))?;
            let bytes = serde_json::to_vec(&ActivationConsumed {
                schema: 1,
                intent_sha256: digest(&intent_bytes),
                stage: self.identity()?,
            })
            .map_err(|_| refuse())?;
            self.write_activation_leaf(ACTIVATION_CONSUMED, &bytes)
        }
        fn write_activation_leaf(&self, name: &str, bytes: &[u8]) -> Result<()> {
            if !matches!(name, ACTIVATION_INTENT | ACTIVATION_CONSUMED) {
                return Err(refuse());
            }
            self.write_new_unchecked(Path::new(name), bytes)
        }
        pub(super) fn create(parent: &Path, uid: u32) -> Result<Self> {
            // Admission of the configured parent happens before mkdir. It must
            // already be administrative0700; the caller cannot select runtime
            // state as fallback or relax ancestry by providing editable JSON.
            let held = open_absolute(parent, uid, true)?;
            let leaf = c(&nonce())?;
            Self::create_on_held(parent, uid, held, &leaf, None)
        }
        pub(super) fn create_with_handoff(
            parent: &Path,
            uid: u32,
            lock: &InstallLock,
            handoff: &Path,
            candidate: &Path,
            public_root: &Path,
            boot_intent_sha256: Option<&str>,
        ) -> Result<Self> {
            lock.revalidate().map_err(|_| refuse())?;
            if uid != 0 || !absolute(candidate) || !absolute(public_root) {
                return Err(refuse());
            }
            // open_absolute only opens existing components. Its terminal
            // flag requires this pre-provisioned parent to be exact 0700;
            // the durable handoff still precedes the first stage mkdir.
            let held = open_absolute(parent, uid, true)?;
            let control = prepare_control(handoff)?;
            let leaf = c(&nonce())?;
            let stage = parent.join(leaf.to_str().map_err(|_| refuse())?);
            let boot_id =
                std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| refuse())?;
            let boot_id = boot_id.trim();
            if boot_id.len() != 36
                || !boot_id.bytes().enumerate().all(|(index, byte)| {
                    if [8, 13, 18, 23].contains(&index) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                    }
                })
            {
                return Err(refuse());
            }
            let intent = PrepareIntent {
                schema: (if boot_intent_sha256.is_some() {
                    "aegis_auto_v2_boot_prepare_handoff_v2"
                } else {
                    "aegis_auto_v2_prepare_handoff_v1"
                })
                .into(),
                phase: "intent".into(),
                boot_id: boot_id.into(),
                stage,
                candidate_binary: candidate.into(),
                public_payload_root: public_root.into(),
                nonce: hex::encode(rand::random::<[u8; 16]>()),
                boot_intent_sha256: boot_intent_sha256.map(str::to_owned),
            };
            let bytes = serde_json::to_vec(&intent).map_err(|_| refuse())?;
            prepare_write(control.as_raw_fd(), "prepare-current.json", &bytes)?;
            lock.revalidate().map_err(|_| refuse())?;
            let boot_created =
                boot_intent_sha256.map(|sha| (control.as_raw_fd(), bytes.as_slice(), &intent, sha));
            Self::create_on_held(parent, uid, held, &leaf, boot_created)
        }
        fn create_on_held(
            parent: &Path,
            uid: u32,
            held: OwnedFd,
            leaf: &CStr,
            boot_created: Option<(RawFd, &[u8], &PrepareIntent, &str)>,
        ) -> Result<Self> {
            if unsafe { libc::mkdirat(held.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
                return Err(refuse());
            }
            let root = match open_dir(held.as_raw_fd(), leaf) {
                Ok(x) => x,
                Err(e) => {
                    unsafe {
                        libc::unlinkat(held.as_raw_fd(), leaf.as_ptr(), libc::AT_REMOVEDIR);
                    }
                    return Err(e);
                }
            };
            valid_dir(root.as_raw_fd(), uid, true)?;
            if let Some((control, intent_raw, intent, boot_sha)) = boot_created {
                // The directory name and inode are durable before any stage
                // lock or content is written. A crash before this receipt
                // leaves only an empty private directory.
                if unsafe { libc::fsync(held.as_raw_fd()) } != 0 {
                    return Err(refuse());
                }
                let identity = stat(root.as_raw_fd())?;
                let created = PrepareStageCreated {
                    schema: "aegis_auto_v2_boot_stage_created_v1".into(),
                    prepare_intent_sha256: digest(intent_raw),
                    boot_intent_sha256: boot_sha.into(),
                    boot_id: intent.boot_id.clone(),
                    stage: intent.stage.clone(),
                    stage_device: identity.st_dev,
                    stage_inode: identity.st_ino,
                    candidate_binary: intent.candidate_binary.clone(),
                    public_payload_root: intent.public_payload_root.clone(),
                };
                prepare_write(
                    control,
                    PREPARE_STAGE_CREATED,
                    &serde_json::to_vec(&created).map_err(|_| refuse())?,
                )?;
            }
            let lock_name = c(MUTATION_LOCK)?;
            let mutation_lock = fd(unsafe {
                libc::openat(
                    root.as_raw_fd(),
                    lock_name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            })?;
            let mutation_lock_identity = Self::lock_identity(mutation_lock.as_raw_fd(), uid)?;
            let fence_name = c(PUBLICATION_FENCE)?;
            let publication_fence = fd(unsafe {
                libc::openat(
                    root.as_raw_fd(),
                    fence_name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            })?;
            let publication_fence_identity =
                Self::lock_identity(publication_fence.as_raw_fd(), uid)?;
            if unsafe { libc::fsync(mutation_lock.as_raw_fd()) } != 0
                || unsafe { libc::fsync(publication_fence.as_raw_fd()) } != 0
                || unsafe { libc::fsync(root.as_raw_fd()) } != 0
            {
                return Err(refuse());
            }
            // The stage name itself must survive a crash before any later
            // consumed activation marker can be treated as durable authority.
            // A failed sync leaves the new private directory for recovery;
            // unlinking it could discard an already visible stage.
            if unsafe { libc::fsync(held.as_raw_fd()) } != 0 {
                return Err(refuse());
            }
            let path = parent.join(leaf.to_str().map_err(|_| refuse())?);
            let activation_path = path.clone();
            let activation_root = root.try_clone().map_err(|_| refuse())?;
            Ok(Self {
                root,
                activation_root,
                activation_path,
                mutation_lock_identity: Some(mutation_lock_identity),
                publication_fence_identity: Some(publication_fence_identity),
                path,
                uid,
                header_admission: HeaderAdmission::default(),
            })
        }
        pub(super) fn complete_handoff(
            stage: &super::authority::StageGuard,
            lock: &InstallLock,
            handoff: &Path,
        ) -> Result<()> {
            lock.revalidate().map_err(|_| refuse())?;
            let control = prepare_control(handoff)?;
            let intent_bytes = prepare_read(control.as_raw_fd(), "prepare-current.json")?;
            let intent: PrepareIntent =
                serde_json::from_slice(&intent_bytes).map_err(|_| refuse())?;
            let (admitted_candidate, admitted_root, candidate_sha, provenance_sha) =
                super::receipt_store::prepare_handoff_facts(stage)?;
            let stage_created = if intent.boot_intent_sha256.is_some() {
                let raw = prepare_read(control.as_raw_fd(), PREPARE_STAGE_CREATED)?;
                let created: PrepareStageCreated =
                    serde_json::from_slice(&raw).map_err(|_| refuse())?;
                let identity = stage.store.identity()?;
                if created.schema != "aegis_auto_v2_boot_stage_created_v1"
                    || created.prepare_intent_sha256 != digest(&intent_bytes)
                    || created.boot_intent_sha256
                        != intent.boot_intent_sha256.as_deref().ok_or_else(refuse)?
                    || created.boot_id != intent.boot_id
                    || created.stage != intent.stage
                    || created.stage_device != identity.0
                    || created.stage_inode != identity.1
                    || created.candidate_binary != intent.candidate_binary
                    || created.public_payload_root != intent.public_payload_root
                {
                    return Err(refuse());
                }
                Some(digest(&raw))
            } else {
                None
            };
            if !matches!(
                intent.schema.as_str(),
                "aegis_auto_v2_prepare_handoff_v1" | "aegis_auto_v2_boot_prepare_handoff_v2"
            ) || (intent.schema == "aegis_auto_v2_boot_prepare_handoff_v2")
                != intent.boot_intent_sha256.is_some()
                || intent.boot_intent_sha256.as_deref().is_some_and(|sha| {
                    sha.len() != 64
                        || !sha
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                })
                || intent.phase != "intent"
                || intent.stage != stage.store.path()
                || intent.candidate_binary != admitted_candidate
                || intent.public_payload_root != admitted_root
                || intent.nonce.len() != 32
                || !intent.nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
                || stage.header.phase != Phase::Prepared
                || stage.header.pending.is_some()
                || stage.header.unit_pending.is_some()
            {
                return Err(refuse());
            }
            if let Some(boot_sha) = intent.boot_intent_sha256.as_deref() {
                if super::installer_v2_generation::verified_boot_prepare_intent(
                    &intent.public_payload_root,
                    &intent.candidate_binary,
                    lock,
                )? != boot_sha
                {
                    return Err(refuse());
                }
            }
            stage.store.revalidate()?;
            stage.revalidate_originals()?;
            super::receipt_store::revalidate_inputs(stage)?;
            let header_bytes = stage.store.read(Path::new("header.json"))?;
            let identity = stage.store.identity()?;
            let complete = PrepareCompletion {
                schema: intent.schema,
                phase: "completed".into(),
                intent_sha256: digest(&intent_bytes),
                stage: intent.stage,
                stage_device: identity.0,
                stage_inode: identity.1,
                header_sha256: digest(&header_bytes),
                input_generation: stage.header.input_generation.clone(),
                candidate_sha256: candidate_sha,
                provenance_sha256: provenance_sha,
                boot_intent_sha256: intent.boot_intent_sha256,
                stage_created_sha256: stage_created,
            };
            let bytes = serde_json::to_vec(&complete).map_err(|_| refuse())?;
            lock.revalidate().map_err(|_| refuse())?;
            prepare_write(control.as_raw_fd(), PREPARE_COMPLETED, &bytes)
        }
        pub(super) fn complete_boot_prepare_after_crash(lock: &InstallLock) -> Result<PathBuf> {
            lock.revalidate().map_err(|_| refuse())?;
            let control = prepare_control(Path::new(PREPARE_HANDOFF))?;
            super::recovery_absent(control.as_raw_fd(), "current.json")?;
            super::recovery_absent(control.as_raw_fd(), PREPARE_COMPLETED)?;
            let raw = prepare_read(control.as_raw_fd(), "prepare-current.json")?;
            let intent: PrepareIntent = serde_json::from_slice(&raw).map_err(|_| refuse())?;
            let boot_sha = intent.boot_intent_sha256.as_deref().ok_or_else(refuse)?;
            if intent.schema != "aegis_auto_v2_boot_prepare_handoff_v2"
                || intent.phase != "intent"
                || intent.stage.parent() != Some(Path::new("/run/aegis-installer-config-snapshots"))
                || super::installer_v2_generation::verified_boot_prepare_intent(
                    &intent.public_payload_root,
                    &intent.candidate_binary,
                    lock,
                )? != boot_sha
            {
                return Err(refuse());
            }
            let stage = super::authority::StageGuard::admit(Store::reopen(&intent.stage, 0)?)?;
            if stage.header.phase != super::Phase::Prepared
                || stage.header.capture_started
                || stage.header.pending.is_some()
                || stage.header.unit_pending.is_some()
            {
                return Err(refuse());
            }
            stage.revalidate_originals()?;
            super::receipt_store::revalidate_inputs(&stage)?;
            Store::complete_handoff(&stage, lock, Path::new(PREPARE_HANDOFF))?;
            lock.revalidate().map_err(|_| refuse())?;
            Ok(intent.stage)
        }
        pub(super) fn reopen(path: &Path, uid: u32) -> Result<Self> {
            let root = open_absolute(path, uid, true)?;
            let mutation_lock_identity = match Self::open_mutation_lock(root.as_raw_fd(), uid) {
                Ok((_, identity)) => Some(identity),
                Err(_) => {
                    // Only an absent leaf is legacy. A malformed, inaccessible,
                    // or substituted leaf is never silently downgraded.
                    let name = c(MUTATION_LOCK)?;
                    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
                    let status = unsafe {
                        libc::fstatat(
                            root.as_raw_fd(),
                            name.as_ptr(),
                            metadata.as_mut_ptr(),
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    };
                    if status == 0
                        || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
                    {
                        return Err(refuse());
                    }
                    None
                }
            };
            let publication_fence_identity =
                match Self::open_publication_fence(root.as_raw_fd(), uid) {
                    Ok((_, identity)) => Some(identity),
                    Err(_) => {
                        // Missing means a prior stage format, never a lease
                        // upgrade. Any present but malformed leaf refuses.
                        let name = c(PUBLICATION_FENCE)?;
                        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
                        let status = unsafe {
                            libc::fstatat(
                                root.as_raw_fd(),
                                name.as_ptr(),
                                metadata.as_mut_ptr(),
                                libc::AT_SYMLINK_NOFOLLOW,
                            )
                        };
                        if status == 0
                            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
                        {
                            return Err(refuse());
                        }
                        None
                    }
                };
            let activation_root = root.try_clone().map_err(|_| refuse())?;
            Ok(Self {
                root,
                activation_root,
                activation_path: path.to_path_buf(),
                mutation_lock_identity,
                publication_fence_identity,
                path: path.to_path_buf(),
                uid,
                header_admission: HeaderAdmission::default(),
            })
        }
        fn parent(&self, path: &Path, create: bool) -> Result<(OwnedFd, CString)> {
            if create && FRESH_STOP_READ.with(|current| current.borrow().is_some()) {
                return Err(refuse());
            }
            if !relative(path) {
                return Err(refuse());
            }
            let mut parts = path.components().peekable();
            let dot = c(".")?;
            let mut held = open_dir(self.root.as_raw_fd(), &dot)?;
            while let Some(part) = parts.next() {
                let Component::Normal(name) = part else {
                    return Err(refuse());
                };
                let name = CString::new(name.as_bytes()).map_err(|_| refuse())?;
                if parts.peek().is_none() {
                    return Ok((held, name));
                }
                if create {
                    let made = unsafe { libc::mkdirat(held.as_raw_fd(), name.as_ptr(), 0o700) };
                    if made == 0 {
                        // Each new ancestor name must survive a crash before a
                        // later leaf or activation marker can claim durability.
                        if unsafe { libc::fsync(held.as_raw_fd()) } != 0 {
                            return Err(refuse());
                        }
                    } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                        return Err(refuse());
                    }
                }
                held = open_dir(held.as_raw_fd(), &name)?;
                valid_dir(held.as_raw_fd(), self.uid, true)?;
            }
            Err(refuse())
        }
        pub(super) fn write_new(&self, path: &Path, bytes: &[u8]) -> Result<()> {
            if reserved_lock_path(path) {
                return Err(refuse());
            }
            let _guard = self.mutation_guard()?;
            self.require_writer_admission()?;
            self.write_new_unchecked(path, bytes)
        }
        #[cfg(test)]
        pub(super) fn write_new_paused_for_race_test(
            &self,
            path: &Path,
            bytes: &[u8],
            entered: std::sync::mpsc::Sender<()>,
            resume: std::sync::mpsc::Receiver<()>,
        ) -> Result<()> {
            let _guard = self.mutation_guard()?;
            if self.activation_leaf_present()? {
                return Err(refuse());
            }
            entered.send(()).map_err(|_| refuse())?;
            resume.recv().map_err(|_| refuse())?;
            self.write_new_unchecked(path, bytes)
        }
        /// Only the typed, one-use recovery-only ledger may call this after
        /// ordinary stage admission has been revoked.
        fn write_new_unchecked(&self, path: &Path, bytes: &[u8]) -> Result<()> {
            if FRESH_STOP_READ.with(|current| current.borrow().is_some()) {
                return Err(refuse());
            }
            if bytes.len() > leaf_bound(path) {
                return Err(refuse());
            }
            let (parent, name) = self.parent(path, true)?;
            let raw = fd(unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            })?;
            let mut file = File::from(raw);
            if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
                unsafe {
                    libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0);
                }
                return Err(refuse());
            }
            let m = stat(file.as_raw_fd())?;
            if m.st_uid != self.uid || m.st_mode & 0o7777 != 0o600 || m.st_nlink != 1 {
                return Err(refuse());
            }
            if unsafe { libc::fsync(parent.as_raw_fd()) } != 0 {
                return Err(refuse());
            }
            Ok(())
        }
        /// Ambiguous actor leaves are sticky after O_EXCL creation. Unlike
        /// ordinary Store records, a write or fsync error must not remove the
        /// leaf and accidentally reopen worker admission after process loss.
        /// The caller already holds publication/mutation/stage fences.
        fn write_new_sticky_unchecked(&self, path: &Path, bytes: &[u8]) -> Result<()> {
            self.write_new_sticky_inner(path, bytes, StickyFault::None)
        }
        fn write_new_sticky_inner(
            &self,
            path: &Path,
            bytes: &[u8],
            fault: StickyFault,
        ) -> Result<()> {
            if FRESH_STOP_READ.with(|current| current.borrow().is_some()) {
                return Err(refuse());
            }
            if bytes.len() > leaf_bound(path) {
                return Err(refuse());
            }
            let (parent, name) = self.parent(path, true)?;
            let raw = fd(unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            })?;
            let mut file = File::from(raw);
            let mut attempt = || -> Result<()> {
                #[cfg(test)]
                if fault == StickyFault::AfterCreate {
                    return Err(refuse());
                }
                let _ = fault;
                file.write_all(bytes).map_err(|_| refuse())?;
                #[cfg(test)]
                if fault == StickyFault::BeforeFileSync {
                    return Err(refuse());
                }
                file.sync_all().map_err(|_| refuse())?;
                let m = stat(file.as_raw_fd())?;
                if m.st_uid != self.uid || m.st_mode & 0o7777 != 0o600 || m.st_nlink != 1 {
                    return Err(refuse());
                }
                if unsafe { libc::fsync(parent.as_raw_fd()) } != 0 {
                    return Err(refuse());
                }
                Ok(())
            };
            let result = attempt();
            if result.is_err() {
                // Best effort only: power-loss persistence after a failed
                // fsync is not established. Never unlink the created leaf.
                let _ = file.sync_all();
                unsafe { libc::fsync(parent.as_raw_fd()) };
            }
            result
        }
        /// Scope restricted to withdrawal receipt acceptance. Caller must
        /// already admit the protected pending envelope and descriptor-minted
        /// live receipt. Existing bytes are never general journal authority.
        pub(super) fn write_or_verify_withdrawal_receipt(&self, bytes: &[u8]) -> Result<()> {
            let _guard = self.mutation_guard()?;
            self.require_writer_admission()?;
            let path = Path::new("withdrawal-receipt.json");
            if bytes.len() > leaf_bound(path) {
                return Err(refuse());
            }
            self.revalidate()?;
            let (parent, name) = self.parent(path, false)?;
            let open = || unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            let mut raw = open();
            if raw < 0 {
                if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                    return Err(refuse());
                }
                self.write_new_unchecked(path, bytes)?;
                raw = open(); // new and existing receipts use the same held-FD admission
            }
            let held = fd(raw)?;
            let before = stat(held.as_raw_fd())?;
            if before.st_uid != self.uid
                || before.st_mode != (libc::S_IFREG | 0o600)
                || before.st_nlink != 1
                || before.st_size < 0
                || before.st_size as usize > leaf_bound(path)
            {
                return Err(refuse());
            }
            // Bytes are read from THIS held descriptor, not a second path open;
            // matching namespace attributes cannot substitute an ABA byte proof.
            let mut file = File::from(held);
            let mut actual = Zeroizing::new(Vec::new());
            (&mut file)
                .take((leaf_bound(path) + 1) as u64)
                .read_to_end(&mut actual)
                .map_err(|_| refuse())?;
            if actual.len() > leaf_bound(path) || actual.as_slice() != bytes {
                return Err(refuse());
            }
            let same = |now: &libc::stat| {
                before.st_dev == now.st_dev
                    && before.st_ino == now.st_ino
                    && before.st_uid == now.st_uid
                    && before.st_gid == now.st_gid
                    && before.st_mode == now.st_mode
                    && before.st_nlink == now.st_nlink
                    && before.st_size == now.st_size
                    && before.st_mtime == now.st_mtime
                    && before.st_mtime_nsec == now.st_mtime_nsec
                    && before.st_ctime == now.st_ctime
                    && before.st_ctime_nsec == now.st_ctime_nsec
            };
            let named_before = fd(open())?;
            if !same(&stat(file.as_raw_fd())?) || !same(&stat(named_before.as_raw_fd())?) {
                return Err(refuse());
            }
            if unsafe { libc::fsync(file.as_raw_fd()) } != 0
                || unsafe { libc::fsync(parent.as_raw_fd()) } != 0
            {
                return Err(refuse());
            }
            let named_after = fd(open())?;
            if !same(&stat(file.as_raw_fd())?)
                || !same(&stat(named_before.as_raw_fd())?)
                || !same(&stat(named_after.as_raw_fd())?)
            {
                return Err(refuse());
            }
            self.revalidate()
        }
        pub(super) fn read(&self, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
            let (parent, name) = self.parent(path, false)?;
            let raw = fd(unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            })?;
            let before = stat(raw.as_raw_fd())?;
            if before.st_uid != self.uid
                || before.st_mode & libc::S_IFMT != libc::S_IFREG
                || before.st_mode & 0o7777 != 0o600
                || before.st_nlink != 1
                || before.st_size < 0
                || before.st_size as usize > leaf_bound(path)
            {
                return Err(refuse());
            }
            let mut file = File::from(raw);
            // Presized from the checked st_size: no reallocation leaves an
            // unzeroized copy behind, and take() still bounds the read.
            let mut bytes = Zeroizing::new(Vec::with_capacity(before.st_size as usize + 1));
            (&mut file)
                .take((leaf_bound(path) + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| refuse())?;
            let after = stat(file.as_raw_fd())?;
            if bytes.len() > leaf_bound(path)
                || before.st_dev != after.st_dev
                || before.st_ino != after.st_ino
                || before.st_size != after.st_size
                || before.st_mtime != after.st_mtime
                || before.st_mtime_nsec != after.st_mtime_nsec
                || before.st_ctime != after.st_ctime
                || before.st_ctime_nsec != after.st_ctime_nsec
            {
                return Err(refuse());
            }
            Ok(bytes)
        }
        fn replace_record(&self, path: &Path, bytes: &[u8]) -> Result<()> {
            if FRESH_STOP_READ.with(|current| current.borrow().is_some()) {
                return Err(refuse());
            }
            let temporary = PathBuf::from(nonce());
            self.write_new_unchecked(&temporary, bytes)?;
            self.require_writer_admission()?;
            let (from, old) = self.parent(&temporary, false)?;
            let (to, new) = self.parent(path, false)?;
            if unsafe {
                libc::renameat(from.as_raw_fd(), old.as_ptr(), to.as_raw_fd(), new.as_ptr())
            } != 0
            {
                unsafe {
                    libc::unlinkat(from.as_raw_fd(), old.as_ptr(), 0);
                }
                return Err(refuse());
            }
            if unsafe { libc::fsync(to.as_raw_fd()) } != 0 {
                return Err(refuse());
            }
            Ok(())
        }
        pub(super) fn save_header(&self, header: &Header) -> Result<()> {
            let _guard = self.mutation_guard()?;
            self.require_writer_admission()?;
            header.validate(self.uid)?;
            let bytes = serde_json::to_vec(header).map_err(|_| refuse())?;
            if bytes.len() > 1024 * 1024 {
                return Err(refuse());
            }
            self.replace_record(Path::new("header.json"), &bytes)
        }
        pub(super) fn load_header(&self) -> Result<Header> {
            Ok(self.load_header_with_bytes()?.0)
        }
        /// The validated header and the exact bytes it was parsed from.
        pub(super) fn load_header_with_bytes(&self) -> Result<(Header, Zeroizing<Vec<u8>>)> {
            let bytes = self.read(Path::new("header.json"))?;
            let header: Header = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
            // The same bytes parse to the same value, which already passed
            // the pure Header::validate for this uid (HeaderAdmission).
            if !self.header_admission.admitted(&bytes) {
                header.validate(self.uid)?;
                self.header_admission.remember(&bytes);
            }
            Ok((header, bytes))
        }
        /// Fresh header.json bytes that parse into a Header passing
        /// Header::validate for this Store's uid. The read (held-root walk,
        /// O_NOFOLLOW open, owner/mode/nlink/size checks and fstat bracket)
        /// runs on every call; only bytes identical to ones this Store has
        /// already admitted skip the repeated pure parse and validate.
        pub(super) fn validated_header_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
            let bytes = self.read(Path::new("header.json"))?;
            if !self.header_admission.admitted(&bytes) {
                let header: Header = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
                header.validate(self.uid)?;
                self.header_admission.remember(&bytes);
            }
            Ok(bytes)
        }
        /// The fresh on-disk header must equal `held`: today's condition is
        /// that serializing the parsed, validated disk header gives the bytes
        /// of serializing `held`, freshly on every call. If the disk bytes
        /// already are those bytes, that condition holds through the lossless
        /// serde round trip (as in fresh_header), so the parse and second
        /// serialization are skipped; any other bytes are compared as before.
        pub(super) fn require_header_equals(&self, held: &Header) -> Result<()> {
            let raw = self.validated_header_bytes()?;
            let expected = serde_json::to_vec(held).map_err(|_| refuse())?;
            if raw.as_slice() == expected.as_slice() {
                return Ok(());
            }
            let disk: Header = serde_json::from_slice(&raw).map_err(|_| refuse())?;
            if serde_json::to_vec(&disk).map_err(|_| refuse())? != expected {
                return Err(refuse());
            }
            Ok(())
        }
        pub(super) fn verify_payloads(&self, header: &Header) -> Result<()> {
            header.validate(self.uid)?;
            self.verify_validated_payloads(header)
        }
        /// verify_payloads for a header this caller has just loaded and
        /// validated itself: Header::validate is pure (no I/O), so repeating
        /// it on the same immutable value adds nothing. Every leaf keeps its
        /// held-root walk, O_NOFOLLOW open, owner/mode/nlink/size checks,
        /// before/after fstat bracket, bound and digest compare; nothing is
        /// cached. Two scoped workers split the leaves; the first failure in
        /// leaf order is reported and the total stage bound is checked after
        /// the join (each half also stops reading once its own total passes
        /// it). If a worker cannot be started, the leaves are read in order.
        pub(super) fn verify_validated_payloads(&self, header: &Header) -> Result<()> {
            let leaves: Vec<(&PathBuf, &String)> = header.leaves.iter().collect();
            let run = |part: &[(&PathBuf, &String)]| -> Vec<Result<usize>> {
                let mut results = Vec::with_capacity(part.len());
                let mut total = 0usize;
                for (path, expected) in part {
                    let result = self.read(path).and_then(|bytes| {
                        if digest(&bytes) == **expected {
                            Ok(bytes.len())
                        } else {
                            Err(refuse())
                        }
                    });
                    let stop = match &result {
                        Ok(length) => {
                            total = total.saturating_add(*length);
                            total > MAX_STAGE
                        }
                        Err(_) => true,
                    };
                    results.push(result);
                    if stop {
                        break;
                    }
                }
                results
            };
            let (first, second) = leaves.split_at(leaves.len().div_ceil(2));
            let (left, right) = std::thread::scope(|scope| {
                match std::thread::Builder::new().spawn_scoped(scope, || run(second)) {
                    Ok(worker) => {
                        let left = run(first);
                        (left, worker.join().map_err(|_| refuse()))
                    }
                    Err(_) => (run(first), Ok(run(second))),
                }
            });
            let mut total = 0usize;
            let complete = left.len() == first.len();
            for result in left {
                total = total.saturating_add(result?);
                if total > MAX_STAGE {
                    return Err(refuse());
                }
            }
            if !complete {
                return Err(refuse());
            }
            for result in right? {
                total = total.saturating_add(result?);
                if total > MAX_STAGE {
                    return Err(refuse());
                }
            }
            Ok(())
        }
        pub(super) fn path(&self) -> &Path {
            &self.path
        }
        pub(super) fn identity(&self) -> Result<(u64, u64)> {
            let s = stat(self.root.as_raw_fd())?;
            Ok((s.st_dev as u64, s.st_ino as u64))
        }
        pub(super) fn revalidate(&self) -> Result<()> {
            valid_dir(self.root.as_raw_fd(), self.uid, true)?;
            let reopened = open_absolute(&self.path, self.uid, true)?;
            let a = stat(self.root.as_raw_fd())?;
            let b = stat(reopened.as_raw_fd())?;
            if a.st_dev != b.st_dev || a.st_ino != b.st_ino {
                return Err(refuse());
            }
            Ok(())
        }
        pub(super) fn duplicate_root(&self) -> Result<OwnedFd> {
            self.revalidate()?;
            fd(unsafe { libc::fcntl(self.root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })
        }
        pub(super) fn exclusive(&self) -> Result<()> {
            if unsafe { libc::flock(self.root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(refuse());
            }
            self.revalidate()
        }
        pub(super) fn sub_store(&self, relative: &Path, create: bool) -> Result<Self> {
            if reserved_lock_path(relative) {
                return Err(refuse());
            }
            let read_scope = FRESH_STOP_READ.with(|current| current.borrow().clone());
            let _guard = if let Some(scope) = &read_scope {
                if create {
                    return Err(refuse());
                }
                self.verify_fresh_stop_read_scope(scope)?;
                None
            } else {
                let guard = self.mutation_guard()?;
                self.require_writer_admission()?;
                Some(guard)
            };
            if !super::relative(relative) {
                return Err(refuse());
            }
            let path = self.path.join(relative);
            let terminal = relative.join(".anchor");
            let (parent, _) = self.parent(&terminal, create)?;
            valid_dir(parent.as_raw_fd(), self.uid, true)?;
            let sub = Self {
                root: parent,
                activation_root: self.activation_root.try_clone().map_err(|_| refuse())?,
                activation_path: self.activation_path.clone(),
                mutation_lock_identity: self.mutation_lock_identity,
                publication_fence_identity: self.publication_fence_identity,
                path,
                uid: self.uid,
                header_admission: HeaderAdmission::default(),
            };
            sub.revalidate()?;
            Ok(sub)
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{symlink, PermissionsExt};
        struct Fixture(PathBuf);
        impl Fixture {
            fn new() -> Self {
                let p = std::env::temp_dir().join(nonce());
                std::fs::create_dir(&p).unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
                Self(p)
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        fn uid() -> u32 {
            unsafe { libc::geteuid() }
        }
        fn metadata_header(uid: u32) -> Header {
            Header {
                protocol: PROTOCOL.into(),
                administrator_uid: uid,
                config_root: "/etc/aegis/client".into(),
                state_dir: "/var/lib/aegis".into(),
                metadata_dir: "/var/lib/aegis-install/client".into(),
                phase: Phase::Metadata,
                transaction_nonce: "00112233445566778899aabbccddeeff".into(),
                current_records: BTreeMap::new(),
                active_records: BTreeMap::new(),
                pending: None,
                mode: AutoMode::SocksOnly,
                plan: serde_json::json!({"schema":"aegis_auto_install_plan_v1","status":"planned","product_mode":"socks-only","connectivity_verified":false}),
                old_unit_namespace: None,
                new_unit_namespace: None,
                runtime_events: "/dev/null".into(),
                unit_policy_recipe: None,
                unit_records: BTreeMap::new(),
                unit_role_records: BTreeMap::new(),
                unit_pending: None,
                unit_forward_transitions: BTreeMap::new(),
                unit_restorations: BTreeMap::new(),
                unit_restored_manager: None,
                runtime_binding: None,
                installed_receipt_recipe: None,
                service_uid: None,
                service_gid: None,
                state_records: BTreeMap::new(),
                namespace_records: BTreeMap::new(),
                service_was_active: None,
                capture_started: false,
                leaves: BTreeMap::new(),
                input_generation: "0".repeat(64),
                accepted_generation: "0".repeat(64),
                planned_generation: "0".repeat(64),
                render_recipe: "accepted/render-recipe.json".into(),
            }
        }
        fn header_copy(header: &Header) -> Header {
            serde_json::from_slice(&serde_json::to_vec(header).unwrap()).unwrap()
        }
        #[test]
        fn header_serde_round_trip_is_lossless_for_fixture_headers() {
            let mut with_leaves = metadata_header(uid());
            with_leaves
                .leaves
                .insert(PathBuf::from("input/a.json"), "a".repeat(64));
            with_leaves.plan =
                serde_json::json!({"schema":"x","nested":{"z":[1,2.5,"s"],"a":null}});
            with_leaves.service_was_active = Some(true);
            for header in [metadata_header(uid()), with_leaves] {
                let bytes = serde_json::to_vec(&header).unwrap();
                let parsed: Header = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(serde_json::to_vec(&parsed).unwrap(), bytes);
            }
        }
        #[test]
        fn header_bytes_are_returned_exactly_as_saved() {
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            let header = metadata_header(uid());
            store.save_header(&header).unwrap();
            let (loaded, raw) = store.load_header_with_bytes().unwrap();
            assert_eq!(
                raw.as_slice(),
                serde_json::to_vec(&header).unwrap().as_slice()
            );
            assert_eq!(
                serde_json::to_vec(&loaded).unwrap().as_slice(),
                raw.as_slice()
            );
            assert_eq!(
                serde_json::to_vec(&store.load_header().unwrap()).unwrap(),
                raw.as_slice()
            );
        }
        #[test]
        fn header_admission_skips_only_byte_identical_repeats() {
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            let header = metadata_header(uid());
            store.save_header(&header).unwrap();
            let bytes = store.validated_header_bytes().unwrap();
            assert_eq!(
                bytes.as_slice(),
                serde_json::to_vec(&header).unwrap().as_slice()
            );
            assert!(store.header_admission.admitted(&bytes));
            // Parseable bytes that fail Header::validate for this uid are
            // refused on every call, by every reader, and never admitted.
            let mut other = header_copy(&header);
            other.administrator_uid = uid().wrapping_add(1);
            let invalid = serde_json::to_vec(&other).unwrap();
            store
                .replace_record(Path::new("header.json"), &invalid)
                .unwrap();
            for _ in 0..2 {
                assert!(store.validated_header_bytes().is_err());
                assert!(store.load_header_with_bytes().is_err());
                assert!(store.load_header().is_err());
                assert!(store.require_header_equals(&other).is_err());
            }
            assert!(!store.header_admission.admitted(&invalid));
            for malformed in [&b"{"[..], b"", &invalid[..invalid.len() - 1]] {
                store
                    .replace_record(Path::new("header.json"), malformed)
                    .unwrap();
                assert!(store.validated_header_bytes().is_err());
                assert!(store.load_header().is_err());
                assert!(!store.header_admission.admitted(malformed));
            }
            // The admitted bytes are still read fresh and give the same value.
            store
                .replace_record(Path::new("header.json"), &bytes)
                .unwrap();
            let (loaded, raw) = store.load_header_with_bytes().unwrap();
            assert_eq!(raw.as_slice(), bytes.as_slice());
            assert_eq!(
                serde_json::to_vec(&loaded).unwrap().as_slice(),
                bytes.as_slice()
            );
            store.require_header_equals(&header).unwrap();
            // A changed valid header replaces the single admitted value.
            let mut next = header_copy(&header);
            next.capture_started = true;
            store.save_header(&next).unwrap();
            assert!(store.require_header_equals(&header).is_err());
            store.require_header_equals(&next).unwrap();
            assert!(!store.header_admission.admitted(&bytes));
            // Another Store over the same stage starts with nothing admitted.
            let current = serde_json::to_vec(&next).unwrap();
            assert!(store.header_admission.admitted(&current));
            let reopened = Store::reopen(store.path(), uid()).unwrap();
            assert!(!reopened.header_admission.admitted(&current));
            assert_eq!(
                reopened.validated_header_bytes().unwrap().as_slice(),
                current.as_slice()
            );
            assert!(reopened.header_admission.admitted(&current));
        }
        #[test]
        fn header_equality_accepts_exactly_the_parsed_comparison() {
            // Today's predicate, computed independently of any Store memo:
            // the disk bytes parse, validate for this uid, and serialize to
            // the held header's own serialization.
            fn today(disk: &[u8], held: &Header) -> bool {
                serde_json::from_slice::<Header>(disk).is_ok_and(|parsed| {
                    parsed.validate(uid()).is_ok()
                        && serde_json::to_vec(&parsed).unwrap() == serde_json::to_vec(held).unwrap()
                })
            }
            let header = metadata_header(uid());
            let mut changed = header_copy(&header);
            changed
                .leaves
                .insert(PathBuf::from("input/a.json"), "a".repeat(64));
            let mut invalid = header_copy(&header);
            invalid.transaction_nonce = "not-a-nonce".into();
            let canonical = |h: &Header| serde_json::to_vec(h).unwrap();
            let pretty = |h: &Header| serde_json::to_vec_pretty(h).unwrap();
            let mut sparse = serde_json::to_value(&header).unwrap();
            // Absent optional fields parse as None and re-serialize as null.
            sparse.as_object_mut().unwrap().remove("pending");
            sparse.as_object_mut().unwrap().remove("unit_pending");
            let sparse = serde_json::to_vec(&sparse).unwrap();
            let mut unknown = serde_json::to_value(&header).unwrap();
            unknown["extra"] = serde_json::json!(1);
            let unknown = serde_json::to_vec(&unknown).unwrap();
            let disks = [
                canonical(&header),
                pretty(&header),
                sparse.clone(),
                canonical(&changed),
                pretty(&changed),
                canonical(&invalid),
                unknown,
                b"{}".to_vec(),
            ];
            let mut accepted = 0;
            for disk in &disks {
                for held in [&header, &changed, &invalid] {
                    let f = Fixture::new();
                    let store = Store::create(&f.0, uid()).unwrap();
                    store
                        .replace_record(Path::new("header.json"), disk)
                        .unwrap();
                    let expected = today(disk, held);
                    // Twice: the second call may use the admitted bytes.
                    for _ in 0..2 {
                        assert_eq!(store.require_header_equals(held).is_ok(), expected);
                    }
                    accepted += usize::from(expected);
                }
            }
            // canonical, pretty and sparse forms of `header`, and both forms
            // of `changed`; an invalid header is refused even when held.
            assert_eq!(accepted, 5);
            assert_ne!(sparse, canonical(&header));
        }
        #[test]
        fn threaded_leaf_verification_keeps_every_leaf_check() {
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            let mut header = metadata_header(uid());
            for index in 0..7 {
                let path = PathBuf::from(format!("input/leaf-{index}.json"));
                let bytes = format!("leaf-{index}").into_bytes();
                store.write_new(&path, &bytes).unwrap();
                header.leaves.insert(path, digest(&bytes));
            }
            store.verify_payloads(&header).unwrap();
            store.verify_validated_payloads(&header).unwrap();
            // A changed digest, a missing leaf or a relaxed mode in either
            // half refuses; the first and the last leaf cover both workers.
            for name in ["input/leaf-0.json", "input/leaf-6.json"] {
                let mut changed = header_copy(&header);
                changed.leaves.insert(PathBuf::from(name), "0".repeat(64));
                assert!(store.verify_validated_payloads(&changed).is_err());
                let mut missing = header_copy(&header);
                missing.leaves.insert(
                    PathBuf::from(name.replace("leaf", "absent")),
                    "0".repeat(64),
                );
                assert!(store.verify_validated_payloads(&missing).is_err());
                let full = store.path().join(name);
                std::fs::set_permissions(&full, std::fs::Permissions::from_mode(0o640)).unwrap();
                assert!(store.verify_validated_payloads(&header).is_err());
                std::fs::set_permissions(&full, std::fs::Permissions::from_mode(0o600)).unwrap();
                let content = std::fs::read(&full).unwrap();
                std::fs::write(&full, b"LEAF-X").unwrap();
                assert_eq!(content.len(), 6);
                assert!(store.verify_validated_payloads(&header).is_err());
                std::fs::write(&full, &content).unwrap();
            }
            store.verify_validated_payloads(&header).unwrap();
            let mut invalid = header_copy(&header);
            invalid.administrator_uid = uid().wrapping_add(1);
            assert!(store.verify_payloads(&invalid).is_err());
        }
        #[test]
        fn legacy_account_binding_header_remains_recovery_readable_but_not_policy_authority() {
            if uid() != 0 {
                return;
            }
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            let mut header = metadata_header(uid());
            header.runtime_binding = Some(
                crate::profile_auto_runtime_identity::resolve_runtime_binding(
                    crate::profile_auto_runtime_identity::ServiceUser::Root,
                    crate::profile_auto_runtime_identity::RuntimePolicy::Root,
                )
                .unwrap(),
            );
            let mut legacy = serde_json::to_value(&header).unwrap();
            let binding = legacy["runtime_binding"].as_object_mut().unwrap();
            for key in ["passwd_sha256", "group_sha256", "nsswitch_sha256"] {
                binding.remove(key);
            }
            let bytes = serde_json::to_vec(&legacy).unwrap();
            store
                .replace_record(Path::new("header.json"), &bytes)
                .unwrap();
            let reopened = Store::reopen(store.path(), uid()).unwrap();
            let read = reopened.load_header().unwrap();
            reopened.verify_payloads(&read).unwrap();
            assert!(read
                .runtime_binding
                .as_ref()
                .unwrap()
                .revalidate_local_generation()
                .is_err());
            reopened.arm_recovery_only().unwrap();
            assert_eq!(reopened.recovery_ticket(), Ok(RecoveryTicket::IntentOnly));
            assert!(reopened.load_header().is_ok());
        }
        fn owner_send_commitments(binding: OwnerBinding) -> OwnerSendCommitments {
            OwnerSendCommitments {
                binding,
                boot_id: "00000000-0000-0000-0000-000000000001".into(),
                pid1_owner: "pid1:test".into(),
                pid1_connection: 7,
                netns_ino: 8,
                private_unit: format!("aegis-auto@{}.service", "a".repeat(64)),
                fixed_unit: "aegis-client.service".into(),
                launch_ticket_sha256: "b".repeat(64),
                deny_ack_sha256: "c".repeat(64),
                nft_sha256: "d".repeat(64),
                route_rule_sha256: "e".repeat(64),
            }
        }
        #[test]
        fn fresh_stop_retained_mutex_reads_without_writer_authority() {
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            let receipt_dir = Path::new("receipts/unit-target/dropins/forward");
            let receipt = store.sub_store(receipt_dir, true).unwrap();
            receipt
                .write_new(
                    Path::new("publication-receipt.json"),
                    b"read-only-policy-receipt",
                )
                .unwrap();
            let stage_id = store.identity().unwrap();
            let terminal = serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "outcome": "finalized",
                "transaction_nonce": metadata_header(uid()).transaction_nonce,
                "stage": [stage_id.0, stage_id.1],
            }))
            .unwrap();
            store
                .write_new(Path::new(ACTIVATION_OWNER_TERMINAL), &terminal)
                .unwrap();
            let mut header = metadata_header(uid());
            header.phase = Phase::Finalized;
            header
                .leaves
                .insert(PathBuf::from(ACTIVATION_OWNER_TERMINAL), digest(&terminal));
            store.save_header(&header).unwrap();
            let foreign_fixture = Fixture::new();
            let foreign = Store::create(&foreign_fixture.0, uid()).unwrap();
            let publication = store.publication_fence_held(libc::LOCK_EX).unwrap();
            let mutation = store.mutation_guard().unwrap();
            store.exclusive().unwrap();
            let scope = store
                .enter_fresh_stop_read_scope(
                    stage_id,
                    publication._process.as_raw_fd(),
                    mutation._process.as_raw_fd(),
                )
                .unwrap();
            let real_receipt = store.sub_store(receipt_dir, false).unwrap();
            assert_eq!(
                real_receipt
                    .read(Path::new("publication-receipt.json"))
                    .unwrap()
                    .as_slice(),
                b"read-only-policy-receipt"
            );
            assert!(store.sub_store(receipt_dir, true).is_err());
            assert!(store.write_new(Path::new("forbidden.json"), b"x").is_err());
            assert!(store
                .write_new_unchecked(Path::new("unchecked.json"), b"x")
                .is_err());
            assert!(store.parent(Path::new("forbidden/new.json"), true).is_err());
            assert!(foreign.sub_store(Path::new("receipts"), false).is_err());
            std::fs::write(store.path().join(ACTIVATION_OWNER_TERMINAL), b"tampered").unwrap();
            assert!(store.sub_store(receipt_dir, false).is_err());
            drop(scope);
        }
        #[test]
        fn owner_commitment_binds_private_and_fixed_service_names() {
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            store.save_header(&metadata_header(uid())).unwrap();
            let fence = store.begin_owner_marker_fence().unwrap();
            let exact = owner_send_commitments(fence.read_binding().unwrap());
            assert!(exact.shape_valid());
            let mut wrong = exact.clone();
            wrong.fixed_unit = wrong.private_unit.clone();
            assert!(!wrong.shape_valid());
            wrong.fixed_unit = "other-client.service".into();
            assert!(!wrong.shape_valid());
        }
        #[test]
        fn owner_post_marker_claim_is_durable_once_and_revokes_worker_reentry() {
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            store.save_header(&metadata_header(uid())).unwrap();
            let stage = store.path().to_path_buf();
            let mut fence = store.begin_owner_marker_fence().unwrap();
            let exact = owner_send_commitments(fence.read_binding().unwrap());
            let mut held = fence.prepare_post_marker(exact).unwrap();
            assert!(stage.join(ACTIVATION_OWNER_MAY_SEND_V2).exists());
            assert!(matches!(
                Store::reopen_for_worker(&stage, uid()),
                Err(OwnerMarkerState::RecoveryRequired)
            ));
            assert_eq!(held.claim_inert_once(), Ok(()));
            assert!(stage.join(ACTIVATION_OWNER_CLAIM_V2).exists());
            assert_eq!(
                held.claim_inert_once(),
                Err(OwnerMarkerState::RecoveryRequired)
            );
            drop(held);
            drop(fence);
            drop(store);
            assert!(matches!(
                Store::reopen_for_worker(&stage, uid()),
                Err(OwnerMarkerState::RecoveryRequired)
            ));
            let reopened = Store::reopen(&stage, uid()).unwrap();
            assert_eq!(
                reopened.begin_owner_marker_fence().err(),
                Some(OwnerMarkerState::RecoveryRequired)
            );
            assert!(reopened.recovery_ticket().is_err());
        }
        #[test]
        fn post_claim_marker_exact_readback_refuses_tamper() {
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            store.save_header(&metadata_header(uid())).unwrap();
            let mut fence = store.begin_owner_marker_fence().unwrap();
            let commitments = owner_send_commitments(fence.read_binding().unwrap());
            let mut held = fence.prepare_post_marker(commitments).unwrap();
            held.claim_inert_once().unwrap();
            let claim_path = Path::new(ACTIVATION_OWNER_CLAIM_V2);
            let bytes = store.read(claim_path).unwrap();
            let sealed = digest(&bytes);
            assert!(guardian_bridge::validate_claim_marker(&held, &sealed).is_ok());
            assert!(guardian_bridge::validate_claim_marker(&held, &"0".repeat(64)).is_err());
            std::fs::write(store.path().join(claim_path), b"{").unwrap();
            assert!(guardian_bridge::validate_claim_marker(&held, &sealed).is_err());
            assert!(matches!(
                Store::reopen_for_worker(store.path(), uid()),
                Err(OwnerMarkerState::RecoveryRequired)
            ));
        }
        #[test]
        #[ignore = "requires isolated root container"]
        fn guardian_lease_real_lock_to_postclaim_remains_refusal_only() {
            assert_eq!(uid(), 0, "isolated root container required");
            let guard_parent = Path::new("/var/lib/aegis-install/client");
            assert!(
                !guard_parent.exists(),
                "isolated root test requires an unused guard directory"
            );
            std::fs::create_dir_all(guard_parent).unwrap();
            std::fs::set_permissions(guard_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            let guard_lock = guard_parent.join("device-guard.conf.lock");
            std::fs::write(&guard_lock, b"").unwrap();
            std::fs::set_permissions(&guard_lock, std::fs::Permissions::from_mode(0o600)).unwrap();

            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            store.save_header(&metadata_header(uid())).unwrap();
            let stage = store.path().to_path_buf();
            let install_lock = InstallLock::acquire().unwrap();
            let mut fence = store.begin_owner_marker_fence().unwrap();
            let commitments = owner_send_commitments(fence.read_binding().unwrap());
            let mut owner = fence
                .prepare_post_marker_with_install_lock(&install_lock, commitments)
                .unwrap();
            let mut lease = guardian_bridge::GuardianLease::acquire(&mut owner).unwrap();
            assert!(lease.revalidate_preclaim().is_ok());
            let ticket = lease.reserve_inert_ticket().unwrap();
            let mut post = ticket.claim_ambiguity_once().unwrap();
            assert!(post.revalidate().is_ok());
            assert!(InstallLock::acquire().is_err());
            let competing = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&guard_lock)
                .unwrap();
            assert_ne!(
                unsafe { libc::flock(competing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0,
                "separate guard descriptor acquired a supposedly held lease"
            );
            assert_eq!(
                post.refuse_send_once(),
                Err(OwnerMarkerState::RecoveryRequired)
            );
            assert_eq!(
                post.refuse_send_once(),
                Err(OwnerMarkerState::RecoveryRequired)
            );
            std::fs::write(
                guard_parent.join("device-guard.conf.auto-lease-split"),
                b"capture-recovery-in-progress-v1\n",
            )
            .unwrap();
            assert_eq!(post.revalidate(), Err(OwnerMarkerState::RecoveryRequired));
            drop(post);
            drop(lease);
            drop(owner);
            drop(fence);
            drop(install_lock);
            drop(store);
            assert!(matches!(
                Store::reopen_for_worker(&stage, uid()),
                Err(OwnerMarkerState::RecoveryRequired)
            ));
        }
        #[test]
        fn owner_post_marker_tamper_burns_in_memory_claim_without_retry() {
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            store.save_header(&metadata_header(uid())).unwrap();
            let mut fence = store.begin_owner_marker_fence().unwrap();
            let exact = owner_send_commitments(fence.read_binding().unwrap());
            let mut held = fence.prepare_post_marker(exact).unwrap();
            std::fs::write(store.path().join(ACTIVATION_OWNER_MAY_SEND_V2), b"{").unwrap();
            assert_eq!(
                held.claim_inert_once(),
                Err(OwnerMarkerState::RecoveryRequired)
            );
            assert_eq!(
                held.claim_inert_once(),
                Err(OwnerMarkerState::RecoveryRequired)
            );
            assert!(!store.path().join(ACTIVATION_OWNER_CLAIM_V2).exists());
        }
        #[test]
        fn owner_sticky_fault_child_process_helper() {
            let Ok(path) = std::env::var("AEGIS_B02_STICKY_FAULT_CHILD") else {
                return;
            };
            let fault = match std::env::var("AEGIS_B02_STICKY_FAULT_KIND")
                .unwrap()
                .as_str()
            {
                "write" => StickyFault::AfterCreate,
                "fsync" => StickyFault::BeforeFileSync,
                _ => panic!("unexpected sticky fault kind"),
            };
            let store = Store::reopen(Path::new(&path), uid()).unwrap();
            let _fence = store.begin_owner_marker_fence().unwrap();
            assert!(store
                .write_new_sticky_inner(Path::new(ACTIVATION_OWNER_MAY_SEND_V2), b"marker", fault)
                .is_err());
            assert!(store.path().join(ACTIVATION_OWNER_MAY_SEND_V2).exists());
            std::io::stdout()
                .write_all(b"STICKY_FAULT_RETAINED\n")
                .unwrap();
            std::io::stdout().flush().unwrap();
            let mut unexpected = [0u8; 1];
            assert_eq!(std::io::stdin().read(&mut unexpected).unwrap(), 0);
        }
        #[test]
        fn owner_sticky_write_or_fsync_failure_survives_sigkill_and_refuses_worker() {
            for fault in ["write", "fsync"] {
                let f = Fixture::new();
                let store = Store::create(&f.0, uid()).unwrap();
                store.save_header(&metadata_header(uid())).unwrap();
                let stage = store.path().to_path_buf();
                drop(store);
                let harness_module = module_path!()
                    .split_once("::")
                    .map(|(_, module)| module)
                    .expect("test module has a crate prefix");
                let exact = format!("{harness_module}::owner_sticky_fault_child_process_helper");
                let child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &exact, "--nocapture"])
                    .env("AEGIS_B02_STICKY_FAULT_CHILD", &stage)
                    .env("AEGIS_B02_STICKY_FAULT_KIND", fault)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                struct ChildGuard(std::process::Child);
                impl Drop for ChildGuard {
                    fn drop(&mut self) {
                        let _ = self.0.kill();
                        let _ = self.0.wait();
                    }
                }
                let mut child = ChildGuard(child);
                let mut output = child.0.stdout.take().unwrap();
                let mut received = Vec::new();
                let start = std::time::Instant::now();
                loop {
                    if received
                        .windows(b"STICKY_FAULT_RETAINED".len())
                        .any(|w| w == b"STICKY_FAULT_RETAINED")
                    {
                        break;
                    }
                    let remaining = std::time::Duration::from_secs(10)
                        .checked_sub(start.elapsed())
                        .expect("sticky child boundary timeout");
                    let mut pfd = libc::pollfd {
                        fd: output.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ready = unsafe {
                        libc::poll(
                            &mut pfd,
                            1,
                            remaining.as_millis().min(i32::MAX as u128) as i32,
                        )
                    };
                    assert!(ready > 0, "sticky child timeout or poll error");
                    let mut bytes = [0u8; 1024];
                    let n = output.read(&mut bytes).unwrap();
                    assert!(n > 0, "sticky child exited before boundary");
                    received.extend_from_slice(&bytes[..n]);
                    assert!(received.len() < 8192, "sticky child output bound");
                }
                child.0.kill().unwrap();
                child.0.wait().unwrap();
                assert!(stage.join(ACTIVATION_OWNER_MAY_SEND_V2).exists());
                assert!(matches!(
                    Store::reopen_for_worker(&stage, uid()),
                    Err(OwnerMarkerState::RecoveryRequired)
                ));
                let reopened = Store::reopen(&stage, uid()).unwrap();
                assert_eq!(
                    reopened.begin_owner_marker_fence().err(),
                    Some(OwnerMarkerState::RecoveryRequired)
                );
                assert!(reopened.recovery_ticket().is_err());
            }
        }
        #[test]
        fn owner_post_marker_child_process_helper() {
            let Ok(path) = std::env::var("AEGIS_B02_POST_MARKER_CHILD") else {
                return;
            };
            let store = Store::reopen(Path::new(&path), uid()).unwrap();
            let mut fence = store.begin_owner_marker_fence().unwrap();
            let exact = owner_send_commitments(fence.read_binding().unwrap());
            let mut held = fence.prepare_post_marker(exact).unwrap();
            std::io::stdout().write_all(b"V2_MARKER_SYNCED\n").unwrap();
            std::io::stdout().flush().unwrap();
            let mut go = [0u8; 1];
            std::io::stdin().read_exact(&mut go).unwrap();
            assert_eq!(go, [b'G']);
            held.claim_inert_once().unwrap();
            std::io::stdout().write_all(b"V2_CLAIM_SYNCED\n").unwrap();
            std::io::stdout().flush().unwrap();
            assert_eq!(std::io::stdin().read(&mut go).unwrap(), 0);
        }
        #[test]
        fn owner_post_marker_two_process_crash_before_and_after_claim_refuses_reentry() {
            for claim_before_crash in [false, true] {
                let f = Fixture::new();
                let store = Store::create(&f.0, uid()).unwrap();
                store.save_header(&metadata_header(uid())).unwrap();
                let stage = store.path().to_path_buf();
                drop(store);
                let harness_module = module_path!()
                    .split_once("::")
                    .map(|(_, module)| module)
                    .expect("test module has a crate prefix");
                let exact = format!("{harness_module}::owner_post_marker_child_process_helper");
                let child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &exact, "--nocapture"])
                    .env("AEGIS_B02_POST_MARKER_CHILD", &stage)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                struct ChildGuard(std::process::Child);
                impl Drop for ChildGuard {
                    fn drop(&mut self) {
                        let _ = self.0.kill();
                        let _ = self.0.wait();
                    }
                }
                let mut child = ChildGuard(child);
                let mut output = child.0.stdout.take().unwrap();
                let mut received = Vec::new();
                let mut wait_for = |expected: &str| {
                    let start = std::time::Instant::now();
                    loop {
                        if received
                            .windows(expected.len())
                            .any(|w| w == expected.as_bytes())
                        {
                            return;
                        }
                        let remaining = std::time::Duration::from_secs(10)
                            .checked_sub(start.elapsed())
                            .expect("post-marker child boundary timeout");
                        let mut pfd = libc::pollfd {
                            fd: output.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        let ready = unsafe {
                            libc::poll(
                                &mut pfd,
                                1,
                                remaining.as_millis().min(i32::MAX as u128) as i32,
                            )
                        };
                        if ready < 0
                            && std::io::Error::last_os_error().kind()
                                == std::io::ErrorKind::Interrupted
                        {
                            continue;
                        }
                        assert!(ready > 0, "post-marker child timeout or poll error");
                        let mut bytes = [0u8; 1024];
                        let n = output.read(&mut bytes).unwrap();
                        assert!(n > 0, "post-marker child exited before boundary");
                        received.extend_from_slice(&bytes[..n]);
                        assert!(received.len() < 8192, "post-marker child output bound");
                    }
                };
                wait_for("V2_MARKER_SYNCED");
                assert!(matches!(
                    Store::reopen_for_worker(&stage, uid()),
                    Err(OwnerMarkerState::RecoveryRequired)
                ));
                let contender = Store::reopen(&stage, uid()).unwrap();
                assert_eq!(
                    contender.begin_owner_marker_fence().err(),
                    Some(OwnerMarkerState::RecoveryRequired)
                );
                drop(contender);
                if claim_before_crash {
                    child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
                    wait_for("V2_CLAIM_SYNCED");
                }
                child.0.kill().unwrap();
                child.0.wait().unwrap();
                assert!(stage.join(ACTIVATION_OWNER_MAY_SEND_V2).exists());
                assert_eq!(
                    stage.join(ACTIVATION_OWNER_CLAIM_V2).exists(),
                    claim_before_crash
                );
                assert!(matches!(
                    Store::reopen_for_worker(&stage, uid()),
                    Err(OwnerMarkerState::RecoveryRequired)
                ));
                let reopened = Store::reopen(&stage, uid()).unwrap();
                assert_eq!(
                    reopened.begin_owner_marker_fence().err(),
                    Some(OwnerMarkerState::RecoveryRequired)
                );
                assert!(reopened.recovery_ticket().is_err());
            }
        }
        #[test]
        fn owner_lock_bound_child_process_helper() {
            let Ok(path) = std::env::var("AEGIS_B02_LOCK_BOUND_CHILD") else {
                return;
            };
            let lock = InstallLock::acquire().unwrap();
            let store = Store::reopen(Path::new(&path), uid()).unwrap();
            let mut fence = store.begin_owner_marker_fence().unwrap();
            let exact = owner_send_commitments(fence.read_binding().unwrap());
            let mut held = fence
                .prepare_post_marker_with_install_lock(&lock, exact)
                .unwrap();
            std::io::stdout().write_all(b"LOCK_BOUND_MARKER\n").unwrap();
            std::io::stdout().flush().unwrap();
            let mut go = [0u8; 1];
            std::io::stdin().read_exact(&mut go).unwrap();
            assert_eq!(go, [b'G']);
            held.claim_inert_once().unwrap();
            std::io::stdout().write_all(b"LOCK_BOUND_CLAIM\n").unwrap();
            std::io::stdout().flush().unwrap();
            // EOF after the one-use Go means the supervising parent died.
            // Release the global InstallLock instead of orphaning the child.
            assert_eq!(std::io::stdin().read(&mut go).unwrap(), 0);
        }
        #[test]
        #[ignore = "disposable root Linux with trusted /run and no concurrent installer"]
        fn owner_lock_bound_marker_retains_exclusion_and_recovery_across_sigkill() {
            assert_eq!(uid(), 0, "disposable root Linux required");
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            store.save_header(&metadata_header(uid())).unwrap();
            let stage = store.path().to_path_buf();
            drop(store);
            let harness_module = module_path!()
                .split_once("::")
                .map(|(_, module)| module)
                .expect("test module has a crate prefix");
            let exact = format!("{harness_module}::owner_lock_bound_child_process_helper");
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &exact, "--nocapture"])
                .env("AEGIS_B02_LOCK_BOUND_CHILD", &stage)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            struct ChildGuard(std::process::Child);
            impl Drop for ChildGuard {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let mut child = ChildGuard(child);
            let mut output = child.0.stdout.take().unwrap();
            let mut received = Vec::new();
            let mut wait_for = |expected: &[u8]| {
                let start = std::time::Instant::now();
                loop {
                    if received.windows(expected.len()).any(|w| w == expected) {
                        return;
                    }
                    let remaining = std::time::Duration::from_secs(10)
                        .checked_sub(start.elapsed())
                        .expect("lock-bound child boundary timeout");
                    let mut pfd = libc::pollfd {
                        fd: output.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ready = unsafe {
                        libc::poll(
                            &mut pfd,
                            1,
                            remaining.as_millis().min(i32::MAX as u128) as i32,
                        )
                    };
                    assert!(ready > 0, "lock-bound child timeout or poll error");
                    let mut bytes = [0u8; 1024];
                    let n = output.read(&mut bytes).unwrap();
                    assert!(n > 0, "lock-bound child exited before boundary");
                    received.extend_from_slice(&bytes[..n]);
                    assert!(received.len() < 8192, "lock-bound child output bound");
                }
            };
            wait_for(b"LOCK_BOUND_MARKER");
            assert!(
                InstallLock::acquire().is_err(),
                "foreign worker acquired held lock"
            );
            assert!(matches!(
                Store::reopen_for_worker(&stage, uid()),
                Err(OwnerMarkerState::RecoveryRequired)
            ));
            child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
            wait_for(b"LOCK_BOUND_CLAIM");
            assert!(
                InstallLock::acquire().is_err(),
                "foreign worker acquired held lock"
            );
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            let lock_after_kill = InstallLock::acquire().unwrap();
            lock_after_kill.revalidate().unwrap();
            assert!(matches!(
                Store::reopen_for_worker(&stage, uid()),
                Err(OwnerMarkerState::RecoveryRequired)
            ));
            let reopened = Store::reopen(&stage, uid()).unwrap();
            assert_eq!(
                reopened.begin_owner_marker_fence().err(),
                Some(OwnerMarkerState::RecoveryRequired)
            );
        }
        #[test]
        fn owner_marker_child_process_helper() {
            let Ok(path) = std::env::var("AEGIS_B02_OWNER_MARKER_CHILD") else {
                return;
            };
            let store = Store::reopen(Path::new(&path), uid()).unwrap();
            let mut fence = store.begin_owner_marker_fence().unwrap();
            assert_eq!(fence.state(), OwnerMarkerState::Fresh);
            std::io::stdout().write_all(b"LOCK_HELD\n").unwrap();
            std::io::stdout().flush().unwrap();
            let mut go = [0u8; 1];
            std::io::stdin().read_exact(&mut go).unwrap();
            assert_eq!(go, [b'G']);
            fence.write_once().unwrap();
            std::io::stdout().write_all(b"MARKER_SYNCED\n").unwrap();
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park();
            }
        }
        #[test]
        fn owner_marker_real_process_lock_sigkill_torn_and_substituted_reentry() {
            if !cfg!(target_os = "linux") {
                return;
            }
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            store.save_header(&metadata_header(uid())).unwrap();
            let stage = store.path().to_path_buf();
            drop(store);
            let harness_module = module_path!()
                .split_once("::")
                .map(|(_, module)| module)
                .expect("test module has a crate prefix");
            let exact = format!("{harness_module}::owner_marker_child_process_helper");
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &exact, "--nocapture"])
                .env("AEGIS_B02_OWNER_MARKER_CHILD", &stage)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            struct ChildGuard(std::process::Child);
            impl Drop for ChildGuard {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let mut child = ChildGuard(child);
            let mut output = child.0.stdout.take().unwrap();
            let mut child_error = child.0.stderr.take().unwrap();
            let error_flags = unsafe { libc::fcntl(child_error.as_raw_fd(), libc::F_GETFL) };
            assert!(error_flags >= 0, "cannot inspect child stderr flags");
            assert_eq!(
                unsafe {
                    libc::fcntl(
                        child_error.as_raw_fd(),
                        libc::F_SETFL,
                        error_flags | libc::O_NONBLOCK,
                    )
                },
                0,
                "cannot bound child stderr read"
            );
            let mut received = Vec::new();
            let mut wait_for = |expected: &str| {
                let start = std::time::Instant::now();
                loop {
                    if received
                        .windows(expected.len())
                        .any(|w| w == expected.as_bytes())
                    {
                        return;
                    }
                    let remaining = std::time::Duration::from_secs(10)
                        .checked_sub(start.elapsed())
                        .expect("child boundary timeout");
                    let mut pfd = libc::pollfd {
                        fd: output.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ready = unsafe {
                        libc::poll(
                            &mut pfd,
                            1,
                            remaining.as_millis().min(i32::MAX as u128) as i32,
                        )
                    };
                    if ready < 0
                        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    assert!(ready > 0, "child boundary timeout or poll error");
                    let mut bytes = [0u8; 1024];
                    let n = output.read(&mut bytes).unwrap();
                    if n == 0 {
                        let mut stderr = [0u8; 4096];
                        let mut error_poll = libc::pollfd {
                            fd: child_error.as_raw_fd(),
                            events: libc::POLLIN | libc::POLLHUP,
                            revents: 0,
                        };
                        let _ = unsafe { libc::poll(&mut error_poll, 1, 250) };
                        let error_len = match child_error.read(&mut stderr) {
                            Ok(n) => n,
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => 0,
                            Err(_) => 0,
                        };
                        panic!(
                            "child exited before boundary; stdout={:?}, stderr_bytes={}, stderr_sha256={}",
                            String::from_utf8_lossy(&received),
                            error_len,
                            digest(&stderr[..error_len])
                        );
                    }
                    received.extend_from_slice(&bytes[..n]);
                    assert!(received.len() < 8192, "child output exceeded bound");
                }
            };
            wait_for("LOCK_HELD");
            let contender = Store::reopen_for_worker(&stage, uid()).unwrap();
            assert_eq!(
                contender.begin_owner_marker_fence().err(),
                Some(OwnerMarkerState::RecoveryRequired)
            );
            child.0.stdin.as_mut().unwrap().write_all(b"G").unwrap();
            wait_for("MARKER_SYNCED");
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            assert!(stage.join(ACTIVATION_OWNER_MAY_SEND).exists());
            assert!(matches!(
                Store::reopen_for_worker(&stage, uid()),
                Err(OwnerMarkerState::RecoveryRequired)
            ));
            std::fs::write(stage.join(ACTIVATION_OWNER_MAY_SEND), b"{").unwrap();
            assert!(matches!(
                Store::reopen_for_worker(&stage, uid()),
                Err(OwnerMarkerState::RecoveryRequired)
            ));
            assert!(super::super::authority::StageGuard::admit(
                Store::reopen(&stage, uid()).unwrap()
            )
            .is_err());
            std::fs::remove_file(stage.join(PUBLICATION_FENCE)).unwrap();
            assert!(matches!(
                Store::reopen_for_worker(&stage, uid()),
                Err(OwnerMarkerState::RecoveryRequired)
            ));
            let moved = f.0.join("retained");
            std::fs::rename(&stage, &moved).unwrap();
            symlink(&moved, &stage).unwrap();
            assert!(matches!(
                Store::reopen_for_worker(&stage, uid()),
                Err(OwnerMarkerState::RecoveryRequired)
            ));
        }
        #[test]
        fn durable_reentry_owned_bytes_and_mode_are_real() {
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            store
                .write_new(Path::new("input/config/aegis.toml"), b"private captured")
                .unwrap();
            let path = store.path().to_path_buf();
            drop(store);
            let reopened = Store::reopen(&path, uid()).unwrap();
            assert_eq!(
                &reopened.read(Path::new("input/config/aegis.toml")).unwrap()[..],
                b"private captured"
            );
            let mode = std::fs::metadata(path.join("input/config/aegis.toml"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o7777, 0o600);
        }
        #[test]
        fn prior_format_cannot_mint_publication_fence_via_stage_writer() {
            let f = Fixture::new();
            let stage = Store::create(&f.0, uid()).unwrap();
            let path = stage.path().to_path_buf();
            std::fs::remove_file(path.join(PUBLICATION_FENCE)).unwrap();
            drop(stage);
            let prior = Store::reopen(&path, uid()).unwrap();
            assert!(prior.publication_lease().is_err());
            assert!(prior
                .write_new(Path::new(PUBLICATION_FENCE), b"forged lock")
                .is_err());
            assert!(prior
                .write_new(Path::new(".publication-fence.lock/child"), b"forged")
                .is_err());
            assert!(prior.sub_store(Path::new(PUBLICATION_FENCE), true).is_err());
            assert!(!path.join(PUBLICATION_FENCE).exists());
        }
        #[test]
        fn pre_lock_stage_is_readable_but_cannot_be_mutated_or_upgraded() {
            let f = Fixture::new();
            let old = f.0.join("old-stage");
            std::fs::create_dir(&old).unwrap();
            std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(old.join("retained.json"), b"retained").unwrap();
            std::fs::set_permissions(
                old.join("retained.json"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let legacy = Store::reopen(&old, uid()).unwrap();
            assert_eq!(
                &legacy.read(Path::new("retained.json")).unwrap()[..],
                b"retained"
            );
            assert!(legacy.write_new(Path::new("new.json"), b"no").is_err());
            assert!(legacy.sub_store(Path::new("nested"), true).is_err());
            assert!(!old.join("new.json").exists());
            assert!(!old.join("nested").exists());
            assert!(!old.join(MUTATION_LOCK).exists());

            // A suspicious present leaf must never masquerade as legacy.
            symlink(&old, old.join(MUTATION_LOCK)).unwrap();
            assert!(Store::reopen(&old, uid()).is_err());
        }
        #[test]
        fn symlink_and_hardlink_stage_payloads_refuse_victim_untouched() {
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            let victim = f.0.join("victim");
            std::fs::write(&victim, b"unrelated private").unwrap();
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
            symlink(&victim, store.path().join("linked")).unwrap();
            assert!(store.read(Path::new("linked")).is_err());
            std::fs::hard_link(&victim, store.path().join("hard")).unwrap();
            assert!(store.read(Path::new("hard")).is_err());
            assert!(store
                .write_new(Path::new("linked"), b"replacement")
                .is_err());
            assert_eq!(std::fs::read(victim).unwrap(), b"unrelated private");
        }
        #[test]
        fn mutation_refuses_stage_path_substitution_and_reentry_refuses() {
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            let original = store.path().to_path_buf();
            let moved = f.0.join("retained");
            std::fs::rename(&original, &moved).unwrap();
            symlink(&f.0, &original).unwrap();
            assert!(store
                .write_new(Path::new("captured"), b"held original")
                .is_err());
            assert!(!moved.join("captured").exists());
            assert!(!f.0.join("captured").exists());
            assert!(Store::reopen(&original, uid()).is_err());
        }
        #[test]
        fn held_descendant_refuses_orphan_write_after_path_substitution() {
            let f = Fixture::new();
            let stage = Store::create(&f.0, uid()).unwrap();
            let receipt = stage
                .sub_store(Path::new("receipts/config-custody"), true)
                .unwrap();
            let original = stage.path().join("receipts/config-custody");
            let moved = stage.path().join("receipts/moved");
            std::fs::rename(&original, &moved).unwrap();
            std::fs::create_dir(&original).unwrap();
            std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();

            assert!(receipt
                .write_new(Path::new("publication-intent.json"), b"orphan")
                .is_err());
            assert!(!moved.join("publication-intent.json").exists());
            assert!(!original.join("publication-intent.json").exists());
        }
        #[test]
        fn foreign_or_relaxed_stage_refuses_before_writes() {
            let f = Fixture::new();
            let store = Store::create(&f.0, uid()).unwrap();
            let p = store.path().to_path_buf();
            drop(store);
            assert!(Store::reopen(&p, uid().wrapping_add(1)).is_err());
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(Store::reopen(&p, uid()).is_err());
            assert!(Store::create(&p, uid()).is_err());
        }
    }
    include!("profile_auto_finalized_stop.rs");
    pub(super) use finalized_stop::inspect_sealed_start;
    pub(crate) use finalized_stop::FinalizedGuardAnchor;
    pub(super) use finalized_stop::{FreshFinalizedStop, FreshStopPrelocks};
}

#[cfg(target_os = "linux")]
pub(crate) use durable::FinalizedGuardAnchor;
#[cfg(target_os = "linux")]
pub(crate) use durable::PublicationLease;

#[cfg(target_os = "linux")]
#[path = "profile_auto_stage_authority.rs"]
mod authority;
#[cfg(target_os = "linux")]
#[path = "profile_auto_backend.rs"]
mod backend;
#[cfg(target_os = "linux")]
#[path = "profile_auto_namespace.rs"]
mod namespace;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod owner_installed {
    //! Protected installed-source prerequisite for a future one-call AUTO actor.
    //! This module has no manager send, marker write, capture or Finalize caller.
    use super::{receipt_store, store_context::RootContext, unit_store};
    use crate::profile_auto_stopped_service::InstallLock;
    use std::path::Path;

    const INSTALLED: &str = "accepted/install-receipt/installed-generation.json";
    const MANIFEST: &str = "accepted/install-receipt/manifest.json";

    fn verify_pending_inverse_projection(
        stage: &super::authority::StageGuard,
    ) -> super::Result<()> {
        let refuse = || super::refuse();
        let Some((leaf, seal)) = &stage.header.pending else {
            return Ok(());
        };
        if leaf != Path::new("receipts/config-projection/projection-intent.json")
            || seal.role != "config"
            || seal.phase != "projection"
        {
            return Err(refuse());
        }
        let parent = leaf.parent().ok_or_else(refuse)?;
        let projection = stage.store.sub_store(parent, false)?;
        let prior = stage
            .header
            .active_records
            .get("config")
            .and_then(|path| stage.header.current_records.get(path))
            .ok_or_else(refuse)?;
        if (seal.stage_dev, seal.stage_ino) != projection.identity()?
            || seal.predecessor_sha256.as_deref() != Some(prior.sha256.as_str())
            || super::digest(&stage.store.read(leaf)?) != seal.sha256
        {
            return Err(refuse());
        }
        projection.revalidate()?;
        Ok(())
    }

    /// Minted only from an admitted StageGuard, the descriptor-captured installed
    /// binary record and the accepted fixed-unit policy under one retained lock.
    /// These facts cannot certify PID1, a native deny ACK or a launch ticket.
    pub(super) struct ProtectedInstalledFacts<'c, 'r> {
        context: &'c RootContext<'r>,
        lock: &'c InstallLock,
        installed_generation_sha256: String,
        installed_manifest_sha256: String,
        policy_generation: String,
    }

    /// Borrowed view of facts after a fresh protected readback. It cannot outlive
    /// the owner context or the process-held installation lock.
    pub(super) struct CurrentInstalledFacts<'a> {
        pub(super) installed_generation_sha256: &'a str,
        pub(super) installed_manifest_sha256: &'a str,
        pub(super) policy_generation: &'a str,
    }

    impl<'c, 'r> ProtectedInstalledFacts<'c, 'r> {
        /// Reconstruct installed facts only for an already claimed private
        /// unit's inverse. The caller must compare the result with the
        /// original product commitment; this method cannot authorize START.
        pub(super) fn capture_for_inverse(
            context: &'c RootContext<'r>,
            lock: &'c InstallLock,
        ) -> super::Result<Self> {
            let refuse = || super::refuse();
            lock.revalidate().map_err(|_| refuse())?;
            let policy = unit_store::verify_inverse_policy(context)?;
            let stage = context.stage_cell().borrow();
            stage.revalidate_owner_pre_marker()?;
            if !matches!(
                stage.header.phase,
                super::Phase::Metadata | super::Phase::Finalized
            ) || stage.header.unit_pending.is_some()
            {
                return Err(refuse());
            }
            verify_pending_inverse_projection(&stage)?;
            receipt_store::verify_installed(&stage)?;
            let installed_generation_sha256 = stage
                .header
                .leaves
                .get(Path::new(INSTALLED))
                .ok_or_else(refuse)?
                .clone();
            let installed_manifest_sha256 = stage
                .header
                .leaves
                .get(Path::new(MANIFEST))
                .ok_or_else(refuse)?
                .clone();
            stage.store.revalidate()?;
            drop(stage);
            lock.revalidate().map_err(|_| refuse())?;
            Ok(Self {
                context,
                lock,
                installed_generation_sha256,
                installed_manifest_sha256,
                policy_generation: policy.generation().into(),
            })
        }
        /// No caller string/hash constructor. References keep the Context and its
        /// exact worker InstallLock alive for the entire lifetime of these facts.
        pub(super) fn capture(
            context: &'c RootContext<'r>,
            lock: &'c InstallLock,
        ) -> super::Result<Self> {
            let refuse = || super::refuse();
            lock.revalidate().map_err(|_| refuse())?;
            context.admit_active_operation().map_err(|_| refuse())?;
            let policy = unit_store::verify_active_policy(context)?;
            let stage = context.stage_cell().borrow();
            stage.store.revalidate()?;
            receipt_store::verify_activation(&stage)?;
            // This reopens the protected generation and verifies the installed
            // executable's current descriptor/ancestry, not caller-supplied bytes.
            receipt_store::installed_generation(&stage)?;
            let installed_generation_sha256 = stage
                .header
                .leaves
                .get(Path::new(INSTALLED))
                .ok_or_else(refuse)?
                .clone();
            let installed_manifest_sha256 = stage
                .header
                .leaves
                .get(Path::new(MANIFEST))
                .ok_or_else(refuse)?
                .clone();
            stage.store.revalidate()?;
            drop(stage);
            context.admit_active_operation().map_err(|_| refuse())?;
            let current_policy = unit_store::verify_active_policy(context)?;
            if current_policy.generation() != policy.generation() {
                return Err(refuse());
            }
            lock.revalidate().map_err(|_| refuse())?;
            Ok(Self {
                context,
                lock,
                installed_generation_sha256,
                installed_manifest_sha256,
                policy_generation: policy.generation().into(),
            })
        }

        /// Reopen both protected sources and the exact held lock before exposing
        /// a borrowed view. Caller must repeat this check at marker/send/terminal
        /// boundaries; this method is not itself a positive send authority.
        pub(super) fn current(&self) -> super::Result<CurrentInstalledFacts<'_>> {
            let refuse = || super::refuse();
            self.lock.revalidate().map_err(|_| refuse())?;
            self.context
                .admit_active_operation()
                .map_err(|_| refuse())?;
            let policy = unit_store::verify_active_policy(self.context)?;
            if policy.generation() != self.policy_generation {
                return Err(refuse());
            }
            let stage = self.context.stage_cell().borrow();
            stage.store.revalidate()?;
            receipt_store::verify_activation(&stage)?;
            receipt_store::installed_generation(&stage)?;
            if stage.header.leaves.get(Path::new(INSTALLED))
                != Some(&self.installed_generation_sha256)
                || stage.header.leaves.get(Path::new(MANIFEST))
                    != Some(&self.installed_manifest_sha256)
            {
                return Err(refuse());
            }
            stage.store.revalidate()?;
            drop(stage);
            self.context
                .admit_active_operation()
                .map_err(|_| refuse())?;
            let current_policy = unit_store::verify_active_policy(self.context)?;
            if current_policy.generation() != self.policy_generation {
                return Err(refuse());
            }
            self.lock.revalidate().map_err(|_| refuse())?;
            Ok(CurrentInstalledFacts {
                installed_generation_sha256: &self.installed_generation_sha256,
                installed_manifest_sha256: &self.installed_manifest_sha256,
                policy_generation: &self.policy_generation,
            })
        }

        /// StopUnit inverse admission while an owner-held projection intent
        /// may be pending. This is deliberately separate from `current`,
        /// which remains strict for positive activation and finalization.
        pub(super) fn current_for_inverse(&self) -> super::Result<CurrentInstalledFacts<'_>> {
            let refuse = || super::refuse();
            self.lock.revalidate().map_err(|_| refuse())?;
            let policy = unit_store::verify_inverse_policy(self.context)?;
            if policy.generation() != self.policy_generation {
                return Err(refuse());
            }
            let stage = self.context.stage_cell().borrow();
            stage.revalidate_owner_pre_marker()?;
            if !matches!(
                stage.header.phase,
                super::Phase::Metadata | super::Phase::Finalized
            ) || stage.header.unit_pending.is_some()
            {
                return Err(refuse());
            }
            verify_pending_inverse_projection(&stage)?;
            receipt_store::verify_installed(&stage)?;
            if stage.header.leaves.get(Path::new(INSTALLED))
                != Some(&self.installed_generation_sha256)
                || stage.header.leaves.get(Path::new(MANIFEST))
                    != Some(&self.installed_manifest_sha256)
            {
                return Err(refuse());
            }
            stage.store.revalidate()?;
            drop(stage);
            self.lock.revalidate().map_err(|_| refuse())?;
            Ok(CurrentInstalledFacts {
                installed_generation_sha256: &self.installed_generation_sha256,
                installed_manifest_sha256: &self.installed_manifest_sha256,
                policy_generation: &self.policy_generation,
            })
        }
    }
}
#[cfg(target_os = "linux")]
mod installer_v2_boot;
#[cfg(target_os = "linux")]
mod installer_v2_generation;
#[cfg(target_os = "linux")]
#[path = "profile_auto_prepare_admission.rs"]
mod prepare_admission;
#[path = "profile_auto_receipt_store.rs"]
mod receipt_store;
#[cfg(all(target_os = "linux", test))]
#[path = "profile_auto_state_context.rs"]
mod state_context;
#[cfg(target_os = "linux")]
#[path = "profile_auto_store_context.rs"]
mod store_context;
#[path = "profile_auto_unit_binding.rs"]
mod unit_binding;
#[path = "profile_auto_unit_store.rs"]
mod unit_store;
pub(crate) use unit_store::VerifiedFirstArm;
#[path = "profile_auto_v2_state_reader.rs"]
mod v2_state_reader;
pub(crate) fn prepare(
    args: crate::profile_auto_transaction_cli::PrepareArgs,
    lock: Option<&crate::profile_auto_stopped_service::InstallLock>,
) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        backend::prepare(args, lock)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (args, lock);
        Err("Administrative AUTO transaction requires Linux root authority".into())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn complete_boot_prepare_after_crash() -> Result<PathBuf> {
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire().map_err(|_| refuse())?;
    durable::Store::complete_boot_prepare_after_crash(&lock)
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn complete_boot_prepare_after_crash() -> Result<PathBuf> {
    Err("Administrative AUTO boot Prepare recovery requires Linux root authority".into())
}
pub(crate) fn command(
    args: crate::profile_auto_transaction_cli::CommandArgs,
) -> Result<Option<String>> {
    #[cfg(target_os = "linux")]
    {
        backend::command(args)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        Err("Administrative AUTO transaction requires Linux root authority".into())
    }
}

pub(crate) fn worker(stage: &Path) -> Result<()> {
    backend::worker(stage)
}

/// Fresh installed-owner inverse after a successful terminal Finalized stage.
/// The lock is acquired here so a caller cannot substitute a saved receipt or
/// reconstruct the worker's earlier in-process authority.
pub(crate) fn stop_finalized_stage(stage: &Path) -> Result<()> {
    stop_finalized_stage_with_mode(stage, None)
}

pub(crate) fn stop_finalized_socks_stage(stage: &Path) -> Result<()> {
    stop_finalized_stage_with_mode(stage, Some(AutoMode::SocksOnly))
}

/// The first phase of typed AUTO V2 retirement. Stop and retire the exact
/// current pointer under one original InstallLock. Do not expose this as a
/// replacement for guard recovery: that operation has its own durable split
/// marker and deliberately releases the lock during ExecStopPost.
#[cfg(target_os = "linux")]
pub(crate) fn uninstall_stop_and_archive(stage: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_for_uninstall()
        .map_err(|_| refuse())?;
    let intent_bytes = crate::profile_auto_stopped_service::uninstall_intent_bytes()
        .map_err(|_| refuse())?
        .ok_or_else(refuse)?;
    let intent: serde_json::Value = serde_json::from_slice(&intent_bytes).map_err(|_| refuse())?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| refuse())?;
    let candidate_sha = intent["candidate_sha256"].as_str().ok_or_else(refuse)?;
    if intent["schema"] != "aegis_auto_v2_uninstall_intent_v1"
        || intent["stage"] != stage.to_string_lossy().as_ref()
        || intent["boot_id"] != boot.trim()
        || !inspected_hex64(candidate_sha)
    {
        return Err(refuse());
    }
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if recovery_file_hash(running.as_raw_fd(), 256 * 1024 * 1024)?.1 != candidate_sha {
        return Err(refuse());
    }
    if uninstall_pointer_already_archived(stage, &lock)? {
        return Ok(());
    }
    // A process can die after Finalized Stop but before pointer retirement.
    // Admit an already stopped stage through the production inspector first;
    // only an active stage needs a fresh Stop. Any ambiguous state remains a
    // refusal because the fresh Stop's own prelocks and owner bind reject it.
    if seal_stopped_generation_held(stage, &lock).is_err() {
        backend::stop_finalized_stage(stage, &lock, None)?;
        seal_stopped_generation_held(stage, &lock)?;
    }
    archive_stopped_generation_pointer_held(stage, &lock)
}

/// A reboot after uninstall intent invalidates the old /run StageGuard. Use
/// the existing fresh-boot capsule/deny observer instead of reconstructing a
/// fictitious Stop receipt. The pending pointer stays in the protected control
/// tree until the typed owner archive; this verb grants no client activation.
#[cfg(target_os = "linux")]
pub(crate) fn uninstall_observe_reboot() -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_for_uninstall()
        .map_err(|_| refuse())?;
    let intent_bytes = crate::profile_auto_stopped_service::uninstall_intent_bytes()
        .map_err(|_| refuse())?
        .ok_or_else(refuse)?;
    let intent: serde_json::Value = serde_json::from_slice(&intent_bytes).map_err(|_| refuse())?;
    let prior_boot = intent["boot_id"].as_str().ok_or_else(refuse)?;
    let stage = intent["stage"].as_str().ok_or_else(refuse)?;
    let candidate_sha = intent["candidate_sha256"].as_str().ok_or_else(refuse)?;
    let pointer_sha = intent["pointer_sha256"].as_str().ok_or_else(refuse)?;
    let current_boot =
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| refuse())?;
    if intent["schema"] != "aegis_auto_v2_uninstall_intent_v1"
        || prior_boot == current_boot.trim()
        || !inspected_hex64(candidate_sha)
        || !inspected_hex64(pointer_sha)
    {
        return Err(refuse());
    }
    let observed = installer_v2_boot::observe_uninstall_current(&lock)?;
    let report = observed.report();
    if report["stage"]["path"] != stage
        || report["terminal"]["boot_id"] != prior_boot
        || report["input"]["candidate_sha256"] != candidate_sha
        || observed.current_boot_id() != current_boot.trim()
    {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    // `current.json` can have been unlinked after the stopped receipt was
    // fsynced, while the uninstall phase append was still outstanding. The
    // boot observer has already verified the retained stopped receipt and
    // archived pointer through the uninstall-only history reader.
    let pointer_state =
        if recovery_absent(control.as_raw_fd(), "generation-pointer-stopped.json").is_ok() {
            if recovery_absent(control.as_raw_fd(), "generation-stopped.json").is_ok() {
                "pending"
            } else {
                // The uninstall-only history reader has authenticated the
                // immutable stopped seal while the pending pointer remains.
                "stopped-sealed"
            }
        } else {
            let receipt_fd = recovery_open_at(
                control.as_raw_fd(),
                "generation-pointer-stopped.json",
                libc::O_RDONLY,
                0,
            )?;
            let receipt_stat = recovery_stat(receipt_fd.as_raw_fd())?;
            if receipt_stat.st_mode != libc::S_IFREG | 0o600
                || receipt_stat.st_uid != 0
                || receipt_stat.st_gid != 0
                || receipt_stat.st_nlink != 1
                || !(1..=8192).contains(&receipt_stat.st_size)
            {
                return Err(refuse());
            }
            let mut receipt_raw = Vec::new();
            std::fs::File::from(receipt_fd)
                .take(8193)
                .read_to_end(&mut receipt_raw)
                .map_err(|_| refuse())?;
            let receipt: serde_json::Value =
                serde_json::from_slice(&receipt_raw).map_err(|_| refuse())?;
            if receipt_raw.len() != receipt_stat.st_size as usize
                || receipt.as_object().map(|v| v.len()) != Some(7)
                || receipt["schema"] != "aegis_auto_v2_stopped_pointer_archive_v1"
                || receipt["stage"] != stage
                || receipt["boot_id"] != prior_boot
                || receipt["candidate_sha256"] != candidate_sha
                || receipt["pointer_sha256"] != pointer_sha
                || receipt["archive_leaf"] != format!("archived-stopped-{pointer_sha}.json")
            {
                return Err(refuse());
            }
            "stopped-archived"
        };
    let archived_leaf = format!("archived-stopped-{pointer_sha}.json");
    let pointer_leaf = if pointer_state != "stopped-archived" {
        "current.json"
    } else {
        archived_leaf.as_str()
    };
    let pointer_fd = recovery_open_at(control.as_raw_fd(), pointer_leaf, libc::O_RDONLY, 0)?;
    let before = recovery_stat(pointer_fd.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o600
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || !(1..=8192).contains(&before.st_size)
    {
        return Err(refuse());
    }
    let mut pointer_bytes = Vec::new();
    std::fs::File::from(pointer_fd.try_clone().map_err(|_| refuse())?)
        .take(8193)
        .read_to_end(&mut pointer_bytes)
        .map_err(|_| refuse())?;
    let after = recovery_stat(pointer_fd.as_raw_fd())?;
    let pointer: InstallerRecoveryPointer =
        serde_json::from_slice(&pointer_bytes).map_err(|_| refuse())?;
    if pointer_bytes.len() != before.st_size as usize
        || (
            before.st_dev,
            before.st_ino,
            before.st_mtime,
            before.st_mtime_nsec,
            before.st_ctime,
            before.st_ctime_nsec,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mtime,
            after.st_mtime_nsec,
            after.st_ctime,
            after.st_ctime_nsec,
        )
        || digest(&pointer_bytes) != pointer_sha
        || !recovery_pointer_schema(&pointer)
        || pointer.status != "pending"
        || pointer.stage != Path::new(stage)
        || pointer.boot_id != prior_boot
        || pointer.candidate_sha256 != candidate_sha
        || pointer.installed_binary != "/usr/local/bin/aegis-client"
    {
        return Err(refuse());
    }
    if pointer_state != "stopped-archived" {
        recovery_absent(control.as_raw_fd(), "generation-pointer-stopped.json")?;
    } else {
        // With a receipt, a current pointer is allowed only in the fsync to
        // unlink crash window, and it must be byte-for-byte the archive.
        match recovery_open_at(control.as_raw_fd(), "current.json", libc::O_RDONLY, 0) {
            Ok(current) => {
                if recovery_file_hash(current.as_raw_fd(), 8192)?.1 != pointer_sha {
                    return Err(refuse());
                }
            }
            Err(_) => recovery_absent(control.as_raw_fd(), "current.json")?,
        }
    }
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if recovery_file_hash(running.as_raw_fd(), 256 * 1024 * 1024)?.1 != candidate_sha {
        return Err(refuse());
    }
    observed.revalidate(&lock)?;
    lock.revalidate().map_err(|_| refuse())?;
    let boot_proof: serde_json::Value =
        serde_json::from_slice(observed.verified_bytes()).map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_uninstall_reboot_observation_v1",
        "stage": stage,
        "old_boot_id": prior_boot,
        "new_boot_id": current_boot.trim(),
        "candidate_sha256": candidate_sha,
        "pointer_sha256": pointer_sha,
        "pointer_state": pointer_state,
        "active_report_sha256": digest(&serde_json::to_vec(report).map_err(|_| refuse())?),
        "boot_proof": boot_proof,
    }))
    .map_err(|_| refuse())
}

/// A completed pointer retirement is a terminal, retryable subtransaction.
/// Admission binds the retained archive to the stopped report, boot, running
/// installed executable and absence of a new current/successor pointer.
#[cfg(target_os = "linux")]
fn uninstall_pointer_already_archived(
    stage: &Path,
    lock: &crate::profile_auto_stopped_service::InstallLock,
) -> Result<bool> {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    lock.revalidate().map_err(|_| refuse())?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let receipt_fd = match recovery_open_at(
        control.as_raw_fd(),
        "generation-pointer-stopped.json",
        libc::O_RDONLY,
        0,
    ) {
        Ok(fd) => fd,
        Err(_) => {
            recovery_absent(control.as_raw_fd(), "generation-pointer-stopped.json")?;
            return Ok(false);
        }
    };
    let receipt_stat = recovery_stat(receipt_fd.as_raw_fd())?;
    if receipt_stat.st_mode != libc::S_IFREG | 0o600
        || receipt_stat.st_uid != 0
        || receipt_stat.st_gid != 0
        || receipt_stat.st_nlink != 1
        || !(1..=8192).contains(&receipt_stat.st_size)
    {
        return Err(refuse());
    }
    let mut receipt_bytes = Vec::new();
    std::fs::File::from(receipt_fd)
        .take(8193)
        .read_to_end(&mut receipt_bytes)
        .map_err(|_| refuse())?;
    if receipt_bytes.len() != receipt_stat.st_size as usize {
        return Err(refuse());
    }
    let receipt: serde_json::Value =
        serde_json::from_slice(&receipt_bytes).map_err(|_| refuse())?;
    let archive_leaf = receipt["archive_leaf"].as_str().ok_or_else(refuse)?;
    let pointer_sha = receipt["pointer_sha256"].as_str().ok_or_else(refuse)?;
    let candidate_sha = receipt["candidate_sha256"].as_str().ok_or_else(refuse)?;
    let boot_id = receipt["boot_id"].as_str().ok_or_else(refuse)?;
    if receipt.as_object().map(|object| object.len()) != Some(7)
        || receipt["schema"] != "aegis_auto_v2_stopped_pointer_archive_v1"
        || receipt["stage"] != stage.to_string_lossy().as_ref()
        || !inspected_hex64(pointer_sha)
        || !inspected_hex64(candidate_sha)
        || archive_leaf != format!("archived-stopped-{pointer_sha}.json")
        || boot_id
            != std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| refuse())?
                .trim()
    {
        return Err(refuse());
    }
    let canonical_receipt = serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_stopped_pointer_archive_v1",
        "stage": stage, "boot_id": boot_id,
        "candidate_sha256": candidate_sha,
        "pointer_sha256": pointer_sha, "archive_leaf": archive_leaf,
        "stopped_report_sha256": receipt["stopped_report_sha256"],
    }))
    .map_err(|_| refuse())?;
    if canonical_receipt != receipt_bytes {
        return Err(refuse());
    }
    // The pointer archive receipt is fsynced before current.json is unlinked.
    // If a process died in that interval, the ordinary archive helper must
    // revalidate the still-present pointer and finish the unlink.
    match recovery_open_at(control.as_raw_fd(), "current.json", libc::O_RDONLY, 0) {
        Ok(_) => return Ok(false),
        Err(_) => recovery_absent(control.as_raw_fd(), "current.json")?,
    }
    recovery_absent(control.as_raw_fd(), "generation-successor-current.json")?;
    recovery_absent(control.as_raw_fd(), "prepare-current.json")?;
    recovery_absent(control.as_raw_fd(), "prepare-stage-created.json")?;
    let archive_fd = recovery_open_at(control.as_raw_fd(), archive_leaf, libc::O_RDONLY, 0)?;
    let archive_stat = recovery_stat(archive_fd.as_raw_fd())?;
    if archive_stat.st_mode != libc::S_IFREG | 0o600
        || archive_stat.st_uid != 0
        || archive_stat.st_gid != 0
        || archive_stat.st_nlink != 1
        || !(1..=8192).contains(&archive_stat.st_size)
    {
        return Err(refuse());
    }
    let mut archive_bytes = Vec::new();
    std::fs::File::from(archive_fd)
        .take(8193)
        .read_to_end(&mut archive_bytes)
        .map_err(|_| refuse())?;
    if archive_bytes.len() != archive_stat.st_size as usize || digest(&archive_bytes) != pointer_sha
    {
        return Err(refuse());
    }
    let pointer: InstallerRecoveryPointer =
        serde_json::from_slice(&archive_bytes).map_err(|_| refuse())?;
    if !recovery_pointer_schema(&pointer)
        || pointer.status != "pending"
        || pointer.stage != stage
        || pointer.boot_id != boot_id
        || pointer.candidate_sha256 != candidate_sha
        || pointer.installed_binary != "/usr/local/bin/aegis-client"
    {
        return Err(refuse());
    }
    let stopped = installer_v2_generation::stopped_history_report()?;
    let stopped_bytes = serde_json::to_vec(&stopped).map_err(|_| refuse())?;
    if receipt["stopped_report_sha256"] != digest(&stopped_bytes)
        || stopped["terminal"]["outcome"] != "finalized-stopped"
        || stopped["terminal"]["boot_id"] != boot_id
        || stopped["input"]["candidate_sha256"] != candidate_sha
        || stopped["stage"]["path"] != stage.to_string_lossy().as_ref()
    {
        return Err(refuse());
    }
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if recovery_file_hash(running.as_raw_fd(), 256 * 1024 * 1024)?.1 != candidate_sha {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    Ok(true)
}

fn stop_finalized_stage_with_mode(stage: &Path, required_mode: Option<AutoMode>) -> Result<()> {
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire().map_err(|_| refuse())?;
    backend::stop_finalized_stage(stage, &lock, required_mode)
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectedNativeGuard {
    guardian_pid: u32,
    guardian_nonce: String,
    guardian_receipt_sha256: String,
    policy_sha256: String,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectedStartTerminal {
    schema: u32,
    outcome: String,
    transaction_nonce: String,
    stage: (u64, u64),
    private_unit: String,
    may_send_sha256: String,
    claim_sha256: String,
    marker_archive_sha256: String,
    submitted_sha256: String,
    completed_sha256: String,
    launch_consumed_sha256: Option<String>,
    launch_ticket_sha256: String,
    stop_submitted_sha256: Option<String>,
    stop_completed_sha256: Option<String>,
    native_guard: Option<InspectedNativeGuard>,
    native_capture_sha256: Option<String>,
    native_inverse_sha256: Option<String>,
    post_deny_policy_sha256: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectedFinalStop {
    schema: u32,
    outcome: String,
    transaction_nonce: String,
    private_unit: String,
    stage: (u64, u64),
    start_terminal_sha256: String,
    start_submitted_sha256: String,
    start_completed_sha256: String,
    stop_intent_sha256: String,
    stop_submitted_sha256: String,
    stop_completed_sha256: String,
    prior_invocation_id: String,
    boot_id: String,
    installed_generation_sha256: String,
    installed_manifest_sha256: String,
    policy_generation: String,
    native_inverse_sha256: Option<String>,
    post_deny_policy_sha256: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectedJobSubmitted {
    schema: u32,
    kind: String,
    #[serde(default)]
    may_send_sha256: Option<String>,
    #[serde(default)]
    claim_sha256: Option<String>,
    #[serde(default)]
    completed_start_sha256: Option<String>,
    #[serde(default)]
    intent_sha256: Option<String>,
    job_id: u32,
    job_path: String,
    unit: String,
    boot_id: String,
    pid1_socket: (u64, u64),
    pid1_netns: (u64, u64),
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectedJobCompleted {
    schema: u32,
    kind: String,
    #[serde(default)]
    submitted_sha256: Option<String>,
    #[serde(default)]
    stop_submitted_sha256: Option<String>,
    #[serde(default)]
    intent_sha256: Option<String>,
    job_id: u32,
    job_path: String,
    unit: String,
    #[serde(default)]
    invocation_id: Option<String>,
    #[serde(default)]
    prior_invocation_id: Option<String>,
}

#[cfg(target_os = "linux")]
fn inspected_bound(guard: &authority::StageGuard, path: &str) -> Result<(Vec<u8>, String)> {
    let path = Path::new(path);
    let bytes = guard.store.read(path)?;
    if bytes.len() > 64 * 1024 {
        return Err(refuse());
    }
    let hash = digest(&bytes);
    if guard.header.leaves.get(path) != Some(&hash) {
        return Err(refuse());
    }
    Ok((bytes.to_vec(), hash))
}

#[cfg(target_os = "linux")]
fn inspected_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(target_os = "linux")]
fn inspected_stop_socket_admitted(outcome: &str, start: (u64, u64), stop: (u64, u64)) -> bool {
    stop.0 != 0
        && stop.1 != 0
        && match outcome {
            // A fresh finalized Stop opens a new authenticated PID1 socket.
            "finalized" => stop.0 == start.0,
            // Compensation stays on the original owned PID1 connection.
            "compensated-failure" => stop == start,
            _ => false,
        }
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectedLiveLaunch {
    schema: u32,
    kind: String,
    completed_sha256: String,
    ticket_sha256: String,
    private_unit: String,
    invocation_id: String,
    main_pid: u32,
    main_start_tick: u64,
    guardian_pid: u32,
    guardian_invocation_id: String,
}

/// Inspect a live finalized V2 generation without creating a new owner lease.
/// The caller retains this very InstallLock through the durable seal write.
#[cfg(target_os = "linux")]
struct ActiveGenerationObservation {
    bytes: Vec<u8>,
    stage: authority::StageGuard,
}

/// Fresh read-only inspection of a running finalized generation. The stopped
/// history inspector requires Stop receipts and cannot authorize live traffic.
#[cfg(target_os = "linux")]
pub(crate) fn inspect_active_finalized_stage(path: &Path) -> Result<Vec<u8>> {
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    Ok(inspect_active_finalized_stage_held(path, &lock)?.bytes)
}

#[cfg(target_os = "linux")]
fn inspect_active_finalized_stage_held(
    path: &Path,
    lock: &crate::profile_auto_stopped_service::InstallLock,
) -> Result<ActiveGenerationObservation> {
    inspect_active_finalized_stage_readonly(path, ReadOnlyInstallEvidence::Held(lock))
}

#[cfg(target_os = "linux")]
fn inspect_active_finalized_stage_readonly(
    path: &Path,
    lock: ReadOnlyInstallEvidence<'_>,
) -> Result<ActiveGenerationObservation> {
    let phase = std::cell::Cell::new("admission");
    let result = inspect_active_finalized_stage_readonly_inner(path, lock, &phase);
    if result.is_err() {
        eprintln!("AUTO_ACTIVE_STAGE_INSPECT_DIAGNOSTIC phase={}", phase.get());
    }
    result
}

#[cfg(target_os = "linux")]
fn inspect_active_finalized_stage_readonly_inner(
    path: &Path,
    lock: ReadOnlyInstallEvidence<'_>,
    phase: &std::cell::Cell<&'static str>,
) -> Result<ActiveGenerationObservation> {
    use crate::profile_auto_unit_namespace as namespace;
    lock.revalidate().map_err(|_| refuse())?;
    let guard = authority::StageGuard::admit(durable::Store::reopen(path, 0)?)?;
    if guard.header.phase != Phase::Finalized
        || guard.header.pending.is_some()
        || guard.header.unit_pending.is_some()
        || guard.header.leaves.contains_key(Path::new(
            "receipts/activation-owner/finalized-stop-terminal.json",
        ))
    {
        return Err(refuse());
    }
    let stage_id = guard.store.identity()?;
    let (terminal_bytes, terminal_hash) =
        inspected_bound(&guard, "receipts/activation-owner/terminal.json")?;
    let terminal: InspectedStartTerminal =
        serde_json::from_slice(&terminal_bytes).map_err(|_| refuse())?;
    let (submitted_bytes, submitted_hash) =
        inspected_bound(&guard, "receipts/activation-owner/submitted.json")?;
    let submitted: InspectedJobSubmitted =
        serde_json::from_slice(&submitted_bytes).map_err(|_| refuse())?;
    let (completed_bytes, completed_hash) =
        inspected_bound(&guard, "receipts/activation-owner/completed.json")?;
    let completed: InspectedJobCompleted =
        serde_json::from_slice(&completed_bytes).map_err(|_| refuse())?;
    let (launch_bytes, launch_hash) =
        inspected_bound(&guard, "receipts/activation-owner/launch-consumed.json")?;
    let launch: InspectedLiveLaunch =
        serde_json::from_slice(&launch_bytes).map_err(|_| refuse())?;
    phase.set("sealed_start");
    let (_, installed_manifest_sha256, _) = durable::inspect_sealed_start(&guard)?;
    if terminal.schema != 1
        || terminal.outcome != "finalized"
        || terminal.transaction_nonce != guard.header.transaction_nonce
        || terminal.stage != stage_id
        || terminal.submitted_sha256 != submitted_hash
        || terminal.completed_sha256 != completed_hash
        || terminal.launch_consumed_sha256.as_deref() != Some(launch_hash.as_str())
        || terminal.stop_submitted_sha256.is_some()
        || terminal.stop_completed_sha256.is_some()
        || submitted.schema != 1
        || submitted.kind != "owned-start-submitted"
        || submitted.unit != terminal.private_unit
        || completed.schema != 1
        || completed.kind != "owned-start-completed"
        || completed.unit != terminal.private_unit
        || completed.invocation_id.as_deref() != Some(launch.invocation_id.as_str())
        || launch.schema != 1
        || launch.kind != "owned-launch-consumed"
        || launch.completed_sha256 != completed_hash
        || launch.ticket_sha256 != terminal.launch_ticket_sha256
        || launch.private_unit != terminal.private_unit
        || launch.main_pid <= 1
        || launch.main_start_tick == 0
        || launch.guardian_pid <= 1
    {
        return Err(refuse());
    }
    phase.set("private_main");
    let current_main =
        crate::profile_auto_stopped_service::pid1::inspect_active_private(&terminal.private_unit)
            .map_err(|_| refuse())?;
    if current_main.boot_id != submitted.boot_id
        || current_main.unit != terminal.private_unit
        || current_main.invocation_id != launch.invocation_id
        || current_main.main_pid != launch.main_pid
        || current_main.pid1_socket.0 == 0
        || current_main.pid1_socket.1 == 0
        || current_main.pid1_netns != submitted.pid1_netns
    {
        return Err(refuse());
    }
    let native =
        terminal
            .native_guard
            .as_ref()
            .map(|guard| crate::profile_auto_guardian::LiveNativeGuard {
                guardian_nonce: &guard.guardian_nonce,
                guardian_receipt_sha256: &guard.guardian_receipt_sha256,
                policy_sha256: &guard.policy_sha256,
            });
    if native.is_some() != (guard.header.mode != AutoMode::SocksOnly) {
        return Err(refuse());
    }
    phase.set("guardian");
    let manager_binding_sha256 = crate::profile_auto_guardian::inspect_live_guardian(
        launch.guardian_pid,
        &launch.guardian_invocation_id,
        &terminal.private_unit,
        launch.main_pid,
        &launch.invocation_id,
        &submitted.boot_id,
        native,
    )
    .map_err(|_| refuse())?;
    phase.set("role_chain");
    let original = unit_binding::read(&guard, false)?;
    let _policy = unit_store::recipe(&guard)?;
    let forward = unit_store::forward_history(&guard)?;
    let restored = unit_store::restoration_history(&guard)?;
    let (_, final_roles) = namespace::inspect_role_chain(
        &original,
        &forward,
        &restored,
        unit_store::transaction_epoch(&guard)?,
    )
    .map_err(|_| refuse())?;
    phase.set("current_fixed");
    let current = lock.capture_namespace()?;
    let current_fixed = namespace::inspect_record_roles(current.record()).map_err(|_| refuse())?;
    if !namespace::same_role_contents(&final_roles, &current_fixed) {
        return Err(refuse());
    }
    phase.set("current_publications");
    let current_publications = guard.inspect_current_published_roots_with_metadata()?;
    phase.set("input_facts");
    let mut input = receipt_store::active_input_facts(&guard)?;
    input["installed_manifest_sha256"] = serde_json::Value::String(installed_manifest_sha256);
    let output = active_generation_report(
        serde_json::json!({"path": path, "device": stage_id.0, "inode": stage_id.1,
            "transaction_nonce": guard.header.transaction_nonce,
            "mode": guard.header.mode, "phase": guard.header.phase,
            "input_generation": guard.header.input_generation,
            "planned_generation": guard.header.planned_generation}),
        serde_json::json!({"outcome": "finalized", "start_terminal_sha256": terminal_hash,
            "boot_id": submitted.boot_id, "private_unit": terminal.private_unit,
            "invocation_id": launch.invocation_id, "submitted_sha256": submitted_hash,
            "completed_sha256": completed_hash, "launch_consumed_sha256": launch_hash}),
        serde_json::json!({"config_root": guard.header.config_root,
            "state_dir": guard.header.state_dir, "metadata_dir": guard.header.metadata_dir,
            "current_verified": true, "current_publications": current_publications}),
        serde_json::json!(current_fixed),
        serde_json::json!(input),
        serde_json::json!({"active_verified": true, "main_pid": current_main.main_pid,
            "cgroup": current_main.cgroup, "pid1_socket": current_main.pid1_socket,
            "pid1_netns": current_main.pid1_netns}),
        serde_json::json!({"active_verified": true, "guardian_pid": launch.guardian_pid,
            "guardian_invocation_id": launch.guardian_invocation_id,
            "manager_binding_sha256": manager_binding_sha256}),
    );
    let bytes = serde_json::to_vec(&output).map_err(|_| refuse())?;
    if bytes.len() > 128 * 1024 {
        return Err(refuse());
    }
    guard.store.revalidate()?;
    lock.revalidate().map_err(|_| refuse())?;
    Ok(ActiveGenerationObservation {
        bytes,
        stage: guard,
    })
}

#[cfg(target_os = "linux")]
fn active_generation_report(
    stage: serde_json::Value,
    terminal: serde_json::Value,
    published_paths: serde_json::Value,
    current_fixed: serde_json::Value,
    input: serde_json::Value,
    main: serde_json::Value,
    guardian: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({"schema": "aegis_auto_active_stage_inspection_v1", "stage": stage,
        "terminal": terminal, "published_paths": published_paths,
        "current_fixed": current_fixed, "input": input, "main": main,
        "guardian": guardian})
}

#[cfg(target_os = "linux")]
fn stopped_generation_report(
    stage: serde_json::Value,
    terminal: serde_json::Value,
    published_paths: serde_json::Value,
    current_fixed: serde_json::Value,
    input: serde_json::Value,
    main: serde_json::Value,
    guardian: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({"schema": "aegis_auto_v2_stopped_stage_inspection_v1", "stage": stage,
        "terminal": terminal, "published_paths": published_paths,
        "current_fixed": current_fixed, "input": input, "main": main,
        "guardian": guardian})
}

#[cfg(target_os = "linux")]
pub(crate) fn seal_active_generation(path: &Path) -> Result<()> {
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| {
            eprintln!("AUTO_GENERATION_SEAL_DIAGNOSTIC phase=install_lock");
            refuse()
        })?;
    let observed = inspect_active_finalized_stage_held(path, &lock)?;
    let report: serde_json::Value =
        serde_json::from_slice(&observed.bytes).map_err(|_| refuse())?;
    if report["stage"]["path"].as_str() != path.to_str() {
        return Err(refuse());
    }
    let registration = if report["stage"]["mode"] == "socks-only" {
        None
    } else {
        let (generation, manifest, _) = durable::inspect_sealed_start(&observed.stage)?;
        let unit = report["terminal"]["private_unit"]
            .as_str()
            .ok_or_else(refuse)?;
        if !unit.starts_with("aegis-auto@")
            || !unit.ends_with(".service")
            || unit.len() != "aegis-auto@".len() + 64 + ".service".len()
            || !unit.as_bytes()["aegis-auto@".len().."aegis-auto@".len() + 64]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            || report["input"]["installed_manifest_sha256"].as_str() != Some(manifest.as_str())
        {
            return Err(refuse());
        }
        Some((unit.to_owned(), generation, manifest))
    };
    let register = |verb: &str, unit: &str, generation: &str, manifest: &str| -> Result<()> {
        let status = std::process::Command::new("/usr/bin/timeout")
            .args([
                "-k",
                "1s",
                "45s",
                "/usr/bin/python3",
                "-I",
                "-B",
                "/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_register.py",
                verb,
                unit,
                path.to_str().ok_or_else(refuse)?,
                generation,
                manifest,
            ])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|_| refuse())?;
        if !status.success() {
            return Err(refuse());
        }
        Ok(())
    };
    if let Some((unit, generation, manifest)) = &registration {
        register("preseal", unit, generation, manifest).map_err(|_| {
            eprintln!("AUTO_GENERATION_SEAL_DIAGNOSTIC phase=terminal_preseal");
            refuse()
        })?;
    }
    let sealed =
        installer_v2_generation::seal_verified_report(&observed.bytes, &lock, &observed.stage);
    if sealed.is_err() {
        eprintln!("AUTO_ACTIVE_STAGE_INSPECT_DIAGNOSTIC phase=generation_publication");
    }
    sealed?;
    let current = installer_v2_generation::current_active_report_address()?;
    if current != report {
        return Err(refuse());
    }
    if let Some((unit, generation, manifest)) = &registration {
        register("commit", unit, generation, manifest).map_err(|_| {
            eprintln!("AUTO_GENERATION_SEAL_DIAGNOSTIC phase=terminal_registration");
            refuse()
        })?;
    }
    lock.revalidate().map_err(|_| refuse())?;
    Ok(())
}

/// Read-only current Socks authority for a package request or exact retry.
/// The historical seal only supplies the path; the held-lock active inspector
/// proves the same stage, installed source, guardian and live private Main.
#[cfg(target_os = "linux")]
pub(crate) fn verify_current_socks_generation() -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let report = installer_v2_generation::current_active_report_address()?;
    installer_v2_generation::verify_boot_source(&report)?;
    let path = report["stage"]["path"].as_str().ok_or_else(refuse)?;
    if report["stage"]["mode"] != "socks-only" {
        return Err(refuse());
    }
    let observed = inspect_active_finalized_stage_held(Path::new(path), &lock)?;
    let active: serde_json::Value =
        serde_json::from_slice(&observed.bytes).map_err(|_| refuse())?;
    if active["stage"]["path"] != report["stage"]["path"]
        || active["stage"]["mode"] != "socks-only"
        || active["stage"]["device"] != report["stage"]["device"]
        || active["stage"]["inode"] != report["stage"]["inode"]
        || active["input"]["public_payload_root"] != report["input"]["public_payload_root"]
        || active["input"]["candidate_sha256"] != report["input"]["candidate_sha256"]
    {
        return Err(refuse());
    }
    verify_current_active_pointer(control.as_raw_fd(), &active)?;
    lock.revalidate().map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_current_socks_active_v1",
        "stage": path,
        "public_payload_root": report["input"]["public_payload_root"],
        "candidate_sha256": report["input"]["candidate_sha256"],
    }))
    .map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
fn verify_current_active_pointer(
    control: std::os::fd::RawFd,
    active: &serde_json::Value,
) -> Result<()> {
    let bytes = read_passive_compensated(control, "current.json")?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    let fields = value.as_object().ok_or_else(refuse)?;
    if fields.len() != 7
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
        .any(|key| !fields.contains_key(*key))
    {
        return Err(refuse());
    }
    let pointer: InstallerRecoveryPointer = serde_json::from_value(value).map_err(|_| refuse())?;
    if !recovery_pointer_schema(&pointer)
        || pointer.status != "pending"
        || pointer.installed_binary != "/usr/local/bin/aegis-client"
        || pointer.stage.to_string_lossy().as_ref() != active["stage"]["path"]
        || pointer.boot_id != active["terminal"]["boot_id"]
        || pointer.candidate_sha256 != active["input"]["candidate_sha256"]
    {
        return Err(refuse());
    }
    Ok(())
}

/// The inherited descriptor proves only read access to the original install
/// transaction. It cannot be passed to the generation sealer or any actor.
#[cfg(target_os = "linux")]
pub(crate) fn passive_transition_status_inherited(
    raw_lock_fd: std::os::fd::RawFd,
) -> Result<Vec<u8>> {
    use crate::profile_auto_stopped_service::InheritedInstallReadLock;
    let lock = InheritedInstallReadLock::admit(raw_lock_fd).map_err(|_| refuse())?;
    lock.revalidate().map_err(|_| refuse())?;
    let evidence = installer_v2_generation::passive_transition_evidence()?;
    let fresh = if let Some(path) = installer_v2_generation::passive_active_stage_path(&evidence) {
        let observation = inspect_active_finalized_stage_readonly(
            Path::new(path),
            ReadOnlyInstallEvidence::Inherited(&lock),
        )?;
        Some(
            serde_json::from_slice::<serde_json::Value>(&observation.bytes)
                .map_err(|_| refuse())?,
        )
    } else {
        None
    };
    let output = installer_v2_generation::passive_transition_status(&evidence, fresh.as_ref())?;
    if let Some(active) = fresh.as_ref() {
        use std::os::fd::AsRawFd;
        let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
        verify_current_active_pointer(control.as_raw_fd(), active)?;
        let status: serde_json::Value = serde_json::from_slice(&output).map_err(|_| refuse())?;
        verify_resumed_unsealed_history(control.as_raw_fd(), &status)?;
    }
    lock.revalidate().map_err(|_| refuse())?;
    Ok(output)
}

/// Archive only a freshly observed completed passive transition while this
/// function owns the original InstallLock. Inherited read evidence cannot
/// reach this entry point or the generation writer.
#[cfg(target_os = "linux")]
pub(crate) fn advance_completed_passive_transition() -> Result<Vec<u8>> {
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    if !installer_v2_generation::passive_transition_present()? {
        let report = installer_v2_generation::current_active_report_address()?;
        if report["stage"]["mode"] != "socks-only" {
            return Err(refuse());
        }
        let path = report["stage"]["path"].as_str().ok_or_else(refuse)?;
        let observed = inspect_active_finalized_stage_held(Path::new(path), &lock)?;
        let fresh: serde_json::Value =
            serde_json::from_slice(&observed.bytes).map_err(|_| refuse())?;
        if fresh["stage"]["path"] != report["stage"]["path"]
            || fresh["terminal"]["start_terminal_sha256"]
                != report["terminal"]["start_terminal_sha256"]
            || fresh["input"] != report["input"]
        {
            return Err(refuse());
        }
        use std::os::fd::AsRawFd;
        let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
        verify_current_active_pointer(control.as_raw_fd(), &fresh)?;
        lock.revalidate().map_err(|_| refuse())?;
        return serde_json::to_vec(&serde_json::json!({
            "schema": "aegis_auto_v2_passive_transition_advance_v1", "outcome": "no-current",
        }))
        .map_err(|_| refuse());
    }
    let evidence = installer_v2_generation::passive_transition_evidence()?;
    let path = installer_v2_generation::passive_active_stage_path(&evidence).ok_or_else(refuse)?;
    let observed = inspect_active_finalized_stage_held(Path::new(path), &lock)?;
    let fresh: serde_json::Value = serde_json::from_slice(&observed.bytes).map_err(|_| refuse())?;
    use std::os::fd::AsRawFd;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    verify_current_active_pointer(control.as_raw_fd(), &fresh)?;
    let status = installer_v2_generation::passive_transition_status(&evidence, Some(&fresh))?;
    let parsed: serde_json::Value = serde_json::from_slice(&status).map_err(|_| refuse())?;
    verify_resumed_unsealed_history(control.as_raw_fd(), &parsed)?;
    installer_v2_generation::advance_completed_passive_transition(&evidence, &fresh, &lock)
}

#[cfg(target_os = "linux")]
struct InspectedTerminalProjection<'a> {
    outcome: &'a str,
    start_hash: &'a str,
    start: &'a InspectedStartTerminal,
    submitted: &'a InspectedJobSubmitted,
    completed: &'a InspectedJobCompleted,
    installed_generation_sha256: &'a str,
    installed_manifest_sha256: &'a str,
    policy_generation: &'a str,
    stop_terminal_hash: Option<&'a str>,
    stop_submitted_hash: &'a str,
    stop_completed_hash: &'a str,
    native_inverse_sha: Option<&'a str>,
    post_deny_sha: Option<&'a str>,
}

#[cfg(target_os = "linux")]
fn inspected_terminal_projection(value: InspectedTerminalProjection<'_>) -> serde_json::Value {
    serde_json::json!({
        "outcome": value.outcome,
        "start_terminal_sha256": value.start_hash,
        "private_unit": value.start.private_unit,
        "boot_id": value.submitted.boot_id,
        "pid1_socket": value.submitted.pid1_socket,
        "pid1_netns": value.submitted.pid1_netns,
        "prior_invocation_id": value.completed.invocation_id,
        "installed_generation_sha256": value.installed_generation_sha256,
        "installed_manifest_sha256": value.installed_manifest_sha256,
        "policy_generation": value.policy_generation,
        "stop_terminal_sha256": value.stop_terminal_hash,
        "stop_submitted_sha256": value.stop_submitted_hash,
        "stop_completed_sha256": value.stop_completed_hash,
        "native_guardian_receipt_sha256": value.start.native_guard.as_ref().map(|g| g.guardian_receipt_sha256.as_str()),
        "native_capture_sha256": value.start.native_capture_sha256,
        "native_inverse_sha256": value.native_inverse_sha,
        "post_deny_policy_sha256": value.post_deny_sha,
    })
}

#[cfg(all(target_os = "linux", test))]
mod inspected_terminal_contract_tests {
    use super::{
        inspected_stop_socket_admitted, inspected_terminal_projection, InspectedJobCompleted,
        InspectedJobSubmitted, InspectedStartTerminal, InspectedTerminalProjection,
    };

    #[test]
    fn finalized_fresh_stop_socket_and_compensated_owned_socket() {
        // Socket tuples observed in the protected native77 receipts: all
        // finalized Stops reconnect; both compensated Stops reuse Start.
        for (start, stop) in [
            ((8, 15389), (8, 15310)),
            ((8, 69870), (8, 70181)),
            ((8, 34119), (8, 46471)),
            ((8, 66843), (8, 67902)),
            ((8, 17295), (8, 30496)),
        ] {
            assert!(inspected_stop_socket_admitted("finalized", start, stop));
            assert!(!inspected_stop_socket_admitted(
                "compensated-failure",
                start,
                stop
            ));
        }
        for socket in [(8, 49111), (8, 58361)] {
            assert!(inspected_stop_socket_admitted(
                "compensated-failure",
                socket,
                socket
            ));
        }
        assert!(!inspected_stop_socket_admitted("finalized", (8, 1), (8, 0)));
        assert!(!inspected_stop_socket_admitted("finalized", (8, 1), (9, 2)));
        assert!(!inspected_stop_socket_admitted("unknown", (8, 1), (8, 2)));
    }

    #[test]
    fn terminal_wire_is_shared_for_finalized_and_compensated_receipts() {
        let h = |c: char| c.to_string().repeat(64);
        let start_json = serde_json::json!({
            "schema": 1, "outcome": "finalized", "transaction_nonce": "a".repeat(32),
            "stage": [11, 12], "private_unit": format!("aegis-auto@{}.service", h('a')),
            "may_send_sha256": h('a'), "claim_sha256": h('b'),
            "marker_archive_sha256": h('c'), "submitted_sha256": h('d'),
            "completed_sha256": h('e'), "launch_consumed_sha256": h('f'),
            "launch_ticket_sha256": h('a'), "stop_submitted_sha256": null,
            "stop_completed_sha256": null,
            "native_guard": {"guardian_pid": 12, "guardian_nonce": h('a'),
                "guardian_receipt_sha256": h('b'), "policy_sha256": h('c')},
            "native_capture_sha256": h('d'), "native_inverse_sha256": null,
            "post_deny_policy_sha256": null
        });
        let start: InspectedStartTerminal = serde_json::from_value(start_json.clone()).unwrap();
        let submitted: InspectedJobSubmitted = serde_json::from_value(serde_json::json!({
            "schema": 1, "kind": "owned-start-submitted", "may_send_sha256": h('a'),
            "claim_sha256": h('b'), "job_id": 13,
            "job_path": "/org/freedesktop/systemd1/job/13",
            "unit": start.private_unit, "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
            "pid1_socket": [14, 15], "pid1_netns": [16, 17]
        }))
        .unwrap();
        let completed: InspectedJobCompleted = serde_json::from_value(serde_json::json!({
            "schema": 1, "kind": "owned-start-completed", "submitted_sha256": h('d'),
            "job_id": 13, "job_path": "/org/freedesktop/systemd1/job/13",
            "unit": start.private_unit, "invocation_id": "b".repeat(32)
        }))
        .unwrap();
        for (outcome, stop_hash) in [
            ("finalized-stopped", Some(h('f'))),
            ("compensated-failure", None),
        ] {
            let mut source = start_json.clone();
            if outcome == "compensated-failure" {
                source["outcome"] = "compensated-failure".into();
                source["native_capture_sha256"] = serde_json::Value::Null;
                source["native_inverse_sha256"] = h('a').into();
                source["post_deny_policy_sha256"] = h('b').into();
                source["stop_submitted_sha256"] = h('e').into();
                source["stop_completed_sha256"] = h('f').into();
            }
            let branch_start: InspectedStartTerminal = serde_json::from_value(source).unwrap();
            let value = inspected_terminal_projection(InspectedTerminalProjection {
                outcome,
                start_hash: &h('a'),
                start: &branch_start,
                submitted: &submitted,
                completed: &completed,
                installed_generation_sha256: &h('b'),
                installed_manifest_sha256: &h('c'),
                policy_generation: &h('d'),
                stop_terminal_hash: stop_hash.as_deref(),
                stop_submitted_hash: &h('e'),
                stop_completed_hash: &h('f'),
                native_inverse_sha: Some(&h('a')),
                post_deny_sha: Some(&h('b')),
            });
            assert_eq!(value.as_object().unwrap().len(), 17);
            assert_eq!(value["outcome"], outcome);
            assert_eq!(value["stop_terminal_sha256"].is_null(), stop_hash.is_none());
            assert_eq!(value["pid1_socket"], serde_json::json!([14, 15]));
            assert_eq!(
                value["native_capture_sha256"].is_null(),
                outcome == "compensated-failure"
            );
            println!("AUTO_INSPECTOR_TERMINAL_CONTRACT {}", value);
        }
        let mut unknown = serde_json::json!({
            "schema": 1, "kind": "owned-start-completed", "submitted_sha256": h('d'),
            "job_id": 13, "job_path": "/org/freedesktop/systemd1/job/13",
            "unit": start.private_unit, "invocation_id": "b".repeat(32)
        });
        unknown["unexpected"] = true.into();
        assert!(serde_json::from_value::<InspectedJobCompleted>(unknown).is_err());
    }
}

/// An unprivileged caller cannot mint this projection: the CLI requires root,
/// reopens the original protected Store, and authenticates each source record.
/// It never creates a stage, owner marker, publication or PID1 effect.
#[cfg(target_os = "linux")]
pub(crate) fn inspect_finalized_stage(path: &Path, verify_current: bool) -> Result<Vec<u8>> {
    let phase = std::cell::Cell::new("admission");
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    let result = inspect_finalized_stage_inner(path, verify_current, false, &lock, &phase);
    if result.is_err() {
        // Closed, fixed labels only. Protected paths, receipt bytes, and the
        // underlying parser error never enter the journal.
        eprintln!(
            "AUTO_FINALIZED_STAGE_INSPECT_DIAGNOSTIC phase={}",
            phase.get()
        );
    }
    result
}

#[cfg(target_os = "linux")]
fn inspect_finalized_stage_inner(
    path: &Path,
    verify_current: bool,
    mutable_state: bool,
    lock: &crate::profile_auto_stopped_service::InstallLock,
    phase: &std::cell::Cell<&'static str>,
) -> Result<Vec<u8>> {
    inspect_finalized_stage_with_read_lock(
        path,
        verify_current,
        mutable_state,
        ReadOnlyInstallEvidence::Held(lock),
        phase,
    )
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum ReadOnlyInstallEvidence<'a> {
    Held(&'a crate::profile_auto_stopped_service::InstallLock),
    Inherited(&'a crate::profile_auto_stopped_service::InheritedInstallReadLock),
}

#[cfg(target_os = "linux")]
impl ReadOnlyInstallEvidence<'_> {
    fn revalidate(self) -> Result<()> {
        match self {
            Self::Held(lock) => lock.revalidate().map_err(|_| refuse()),
            Self::Inherited(lock) => lock.revalidate().map_err(|_| refuse()),
        }
    }

    fn duplicate_held_fd(self) -> Result<std::os::fd::OwnedFd> {
        match self {
            Self::Held(lock) => lock.duplicate_held_fd().map_err(|_| refuse()),
            Self::Inherited(lock) => lock.duplicate_held_fd().map_err(|_| refuse()),
        }
    }

    fn capture_namespace(
        self,
    ) -> Result<crate::profile_auto_unit_namespace::UnitNamespaceSnapshot> {
        use crate::profile_auto_unit_namespace::UnitNamespaceSnapshot;
        match self {
            Self::Held(lock) => UnitNamespaceSnapshot::capture(lock).map_err(|_| refuse()),
            Self::Inherited(lock) => {
                UnitNamespaceSnapshot::capture_inherited_read_only(lock).map_err(|_| refuse())
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn inspect_finalized_stage_with_read_lock(
    path: &Path,
    verify_current: bool,
    mutable_state: bool,
    lock: ReadOnlyInstallEvidence<'_>,
    phase: &std::cell::Cell<&'static str>,
) -> Result<Vec<u8>> {
    use crate::profile_auto_unit_namespace as unit_namespace;
    lock.revalidate()?;
    let guard = authority::StageGuard::admit(durable::Store::reopen(path, 0)?)?;
    if guard.header.pending.is_some() || guard.header.unit_pending.is_some() {
        return Err(refuse());
    }
    phase.set("start_terminal");
    let stage_id = guard.store.identity()?;
    let (start_bytes, start_hash) =
        inspected_bound(&guard, "receipts/activation-owner/terminal.json")?;
    let start: InspectedStartTerminal =
        serde_json::from_slice(&start_bytes).map_err(|_| refuse())?;
    let private_name = start
        .private_unit
        .strip_prefix("aegis-auto@")
        .and_then(|name| name.strip_suffix(".service"));
    if start.schema != 1
        || start.transaction_nonce != guard.header.transaction_nonce
        || start.stage != stage_id
        || !private_name.is_some_and(inspected_hex64)
        || ![
            &start.may_send_sha256,
            &start.claim_sha256,
            &start.marker_archive_sha256,
            &start.submitted_sha256,
            &start.completed_sha256,
            &start.launch_ticket_sha256,
        ]
        .into_iter()
        .all(|value| inspected_hex64(value))
        || !start
            .launch_consumed_sha256
            .as_deref()
            .is_some_and(inspected_hex64)
        || start.native_inverse_sha256.is_some() != start.post_deny_policy_sha256.is_some()
        || start
            .native_inverse_sha256
            .as_deref()
            .is_some_and(|v| !inspected_hex64(v))
        || start
            .post_deny_policy_sha256
            .as_deref()
            .is_some_and(|v| !inspected_hex64(v))
        || start
            .native_capture_sha256
            .as_deref()
            .is_some_and(|v| !inspected_hex64(v))
        || start.native_guard.as_ref().is_some_and(|guard| {
            guard.guardian_pid <= 1
                || !inspected_hex64(&guard.guardian_nonce)
                || !inspected_hex64(&guard.guardian_receipt_sha256)
                || !inspected_hex64(&guard.policy_sha256)
        })
    {
        return Err(refuse());
    }
    phase.set("start_job");
    let (start_submitted_bytes, start_submitted_hash) =
        inspected_bound(&guard, "receipts/activation-owner/submitted.json")?;
    let (start_completed_bytes, start_completed_hash) =
        inspected_bound(&guard, "receipts/activation-owner/completed.json")?;
    let start_submitted: InspectedJobSubmitted =
        serde_json::from_slice(&start_submitted_bytes).map_err(|_| refuse())?;
    let start_completed: InspectedJobCompleted =
        serde_json::from_slice(&start_completed_bytes).map_err(|_| refuse())?;
    if start_submitted.schema != 1
        || start_submitted.kind != "owned-start-submitted"
        || start_submitted.may_send_sha256.as_deref() != Some(start.may_send_sha256.as_str())
        || start_submitted.claim_sha256.as_deref() != Some(start.claim_sha256.as_str())
        || start_submitted.completed_start_sha256.is_some()
        || start_submitted_hash != start.submitted_sha256
        || start_completed.schema != 1
        || start_completed.kind != "owned-start-completed"
        || start_completed.submitted_sha256.as_deref() != Some(start_submitted_hash.as_str())
        || start_completed.stop_submitted_sha256.is_some()
        || start_completed_hash != start.completed_sha256
        || start_submitted.job_id == 0
        || start_submitted.job_path
            != format!("/org/freedesktop/systemd1/job/{}", start_submitted.job_id)
        || start_submitted.unit != start.private_unit
        || start_completed.job_id != start_submitted.job_id
        || start_completed.job_path != start_submitted.job_path
        || start_completed.unit != start_submitted.unit
        || start_completed
            .invocation_id
            .as_deref()
            .is_none_or(str::is_empty)
        || start_submitted.boot_id.len() != 36
        || !start_submitted
            .boot_id
            .bytes()
            .enumerate()
            .all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                }
            })
        || start_submitted.pid1_socket.0 == 0
        || start_submitted.pid1_socket.1 == 0
        || start_submitted.pid1_netns.0 == 0
        || start_submitted.pid1_netns.1 == 0
    {
        return Err(refuse());
    }
    phase.set("stop_job");
    let (stop_submitted_bytes, stop_submitted_hash) =
        inspected_bound(&guard, "receipts/activation-owner/stop-submitted.json")?;
    let (stop_completed_bytes, stop_completed_hash) =
        inspected_bound(&guard, "receipts/activation-owner/stop-completed.json")?;
    let stop_submitted: InspectedJobSubmitted =
        serde_json::from_slice(&stop_submitted_bytes).map_err(|_| refuse())?;
    let stop_completed: InspectedJobCompleted =
        serde_json::from_slice(&stop_completed_bytes).map_err(|_| refuse())?;
    if stop_submitted.schema != 1
        || stop_submitted.completed_start_sha256.as_deref() != Some(start_completed_hash.as_str())
        || stop_submitted.may_send_sha256.is_some()
        || stop_submitted.claim_sha256.is_some()
        || stop_completed.schema != 1
        || stop_completed.stop_submitted_sha256.as_deref() != Some(stop_submitted_hash.as_str())
        || stop_completed.submitted_sha256.is_some()
        || stop_submitted.job_id == 0
        || stop_submitted.job_path
            != format!("/org/freedesktop/systemd1/job/{}", stop_submitted.job_id)
        || stop_submitted.unit != start.private_unit
        || stop_completed.job_id != stop_submitted.job_id
        || stop_completed.job_path != stop_submitted.job_path
        || stop_completed.unit != stop_submitted.unit
        || stop_completed.prior_invocation_id != start_completed.invocation_id
        || stop_submitted.boot_id != start_submitted.boot_id
        || !inspected_stop_socket_admitted(
            &start.outcome,
            start_submitted.pid1_socket,
            stop_submitted.pid1_socket,
        )
        || stop_submitted.pid1_netns != start_submitted.pid1_netns
        || start
            .stop_submitted_sha256
            .as_deref()
            .is_some_and(|s| s != stop_submitted_hash.as_str())
        || start
            .stop_completed_sha256
            .as_deref()
            .is_some_and(|s| s != stop_completed_hash.as_str())
    {
        return Err(refuse());
    }
    phase.set("sealed_start");
    let (installed_generation_sha256, installed_manifest_sha256, policy_generation) =
        durable::inspect_sealed_start(&guard)?;
    phase.set("terminal_outcome");
    let (outcome, stop_terminal_hash, native_inverse_sha, post_deny_sha) = match start
        .outcome
        .as_str()
    {
        "finalized" => {
            if guard.header.phase != Phase::Finalized
                || start.stop_submitted_sha256.is_some()
                || start.stop_completed_sha256.is_some()
            {
                return Err(refuse());
            }
            let (bytes, hash) = inspected_bound(
                &guard,
                "receipts/activation-owner/finalized-stop-terminal.json",
            )?;
            let stop: InspectedFinalStop = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
            if stop.schema != 1
                || stop.outcome != "finalized-stopped"
                || stop.transaction_nonce != guard.header.transaction_nonce
                || stop.stage != stage_id
                || stop.private_unit != start.private_unit
                || stop.start_terminal_sha256 != start_hash
                || stop.start_submitted_sha256 != start_submitted_hash
                || stop.start_completed_sha256 != start_completed_hash
                || stop.stop_submitted_sha256 != stop_submitted_hash
                || stop.stop_completed_sha256 != stop_completed_hash
                || Some(stop.prior_invocation_id.as_str())
                    != start_completed.invocation_id.as_deref()
                || stop.boot_id != start_submitted.boot_id
                || stop.installed_generation_sha256 != installed_generation_sha256
                || stop.installed_manifest_sha256 != installed_manifest_sha256
                || stop.policy_generation != policy_generation
                || stop.native_inverse_sha256.is_some() != start.native_guard.is_some()
                || stop.native_inverse_sha256.is_some() != stop.post_deny_policy_sha256.is_some()
                || !inspected_hex64(&stop.stop_intent_sha256)
                || stop
                    .native_inverse_sha256
                    .as_deref()
                    .is_some_and(|v| !inspected_hex64(v))
                || stop
                    .post_deny_policy_sha256
                    .as_deref()
                    .is_some_and(|v| !inspected_hex64(v))
                || stop_submitted.kind != "owned-finalized-stop-submitted"
                || stop_completed.kind != "owned-finalized-stop-completed"
                || stop_submitted.intent_sha256.as_deref() != Some(stop.stop_intent_sha256.as_str())
                || stop_completed.intent_sha256.as_deref() != Some(stop.stop_intent_sha256.as_str())
            {
                return Err(refuse());
            }
            (
                "finalized-stopped",
                Some(hash),
                stop.native_inverse_sha256,
                stop.post_deny_policy_sha256,
            )
        }
        "compensated-failure" => {
            if guard.header.phase != Phase::Metadata
                || start.stop_submitted_sha256.as_deref() != Some(stop_submitted_hash.as_str())
                || start.stop_completed_sha256.as_deref() != Some(stop_completed_hash.as_str())
                || guard.header.leaves.contains_key(Path::new(
                    "receipts/activation-owner/finalized-stop-terminal.json",
                ))
                || start.native_inverse_sha256.is_none() && guard.header.mode != AutoMode::SocksOnly
                || stop_submitted.kind != "owned-stop-submitted"
                || stop_completed.kind != "owned-stop-completed"
                || stop_submitted.intent_sha256.is_some()
                || stop_completed.intent_sha256.is_some()
            {
                return Err(refuse());
            }
            (
                "compensated-failure",
                None,
                start.native_inverse_sha256.clone(),
                start.post_deny_policy_sha256.clone(),
            )
        }
        _ => return Err(refuse()),
    };
    phase.set("role_history");
    let original = unit_binding::read(&guard, false)?;
    let _policy = unit_store::recipe(&guard)?;
    let forward = unit_store::forward_history(&guard)?;
    let restored = unit_store::restoration_history(&guard)?;
    let (original_roles, final_roles) = unit_namespace::inspect_role_chain(
        &original,
        &forward,
        &restored,
        unit_store::transaction_epoch(&guard)?,
    )
    .map_err(|_| refuse())?;
    phase.set("current_fixed");
    let current = lock.capture_namespace()?;
    let current_fixed =
        unit_namespace::inspect_record_roles(current.record()).map_err(|_| refuse())?;
    phase.set("current_publications");
    let current_publications = if verify_current {
        if outcome != "finalized-stopped"
            || !unit_namespace::same_role_contents(&final_roles, &current_fixed)
        {
            return Err(refuse());
        }
        Some(if mutable_state {
            guard.inspect_current_published_roots_with_metadata()?
        } else {
            guard.inspect_current_published_roots()?
        })
    } else {
        None
    };
    let role_name = |role| match role {
        unit_namespace::ManagedRole::BaseUnit => "base-unit",
        unit_namespace::ManagedRole::Environment => "environment",
        unit_namespace::ManagedRole::Dropins => "dropins",
    };
    let transition = serde_json::json!({
        "forward": forward.iter().map(|r| serde_json::json!({"role": role_name(r.role()), "generation": r.generation()})).collect::<Vec<_>>(),
        "restored": restored.iter().map(|r| serde_json::json!({"role": role_name(r.role()), "generation": r.generation()})).collect::<Vec<_>>(),
    });
    let terminal = inspected_terminal_projection(InspectedTerminalProjection {
        outcome,
        start_hash: &start_hash,
        start: &start,
        submitted: &start_submitted,
        completed: &start_completed,
        installed_generation_sha256: &installed_generation_sha256,
        installed_manifest_sha256: &installed_manifest_sha256,
        policy_generation: &policy_generation,
        stop_terminal_hash: stop_terminal_hash.as_deref(),
        stop_submitted_hash: &stop_submitted_hash,
        stop_completed_hash: &stop_completed_hash,
        native_inverse_sha: native_inverse_sha.as_deref(),
        post_deny_sha: post_deny_sha.as_deref(),
    });
    phase.set("output");
    let result = serde_json::json!({
        "schema": "aegis_auto_native_stage_inspection_v1",
        "stage": {"path": path, "device": stage_id.0, "inode": stage_id.1,
            "transaction_nonce": guard.header.transaction_nonce,
            "mode": guard.header.mode, "phase": guard.header.phase,
            "input_generation": guard.header.input_generation,
            "planned_generation": guard.header.planned_generation},
        "original_roles": original_roles,
        "final_roles": final_roles,
        "transition": transition,
        "terminal": terminal,
        "published_paths": {"config_root": guard.header.config_root,
            "state_dir": guard.header.state_dir,
            "runtime_events": guard.header.runtime_events,
            "current_verified": verify_current,
            "current_publications": current_publications},
        "current_fixed": current_fixed,
    });
    let bytes = serde_json::to_vec(&result).map_err(|_| refuse())?;
    if bytes.len() > 128 * 1024 {
        return Err(refuse());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn stopped_manager_binding() -> Result<Vec<u8>> {
    use std::{io::Read, os::fd::AsRawFd};
    let parent = recovery_chain(&["var", "lib", "aegis-install", "client"], None)?;
    let fd = recovery_open_at(
        parent.as_raw_fd(),
        "device-guard.conf.manager-binding",
        libc::O_RDONLY,
        0,
    )?;
    let before = recovery_stat(fd.as_raw_fd())?;
    if before.st_mode != (libc::S_IFREG | 0o600)
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size > 4096
    {
        return Err(refuse());
    }
    let mut file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    let after = recovery_stat(file.as_raw_fd())?;
    let named = recovery_open_at(
        parent.as_raw_fd(),
        "device-guard.conf.manager-binding",
        libc::O_RDONLY,
        0,
    )?;
    let current = recovery_stat(named.as_raw_fd())?;
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
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime,
            before.st_mtime_nsec,
            before.st_ctime,
            before.st_ctime_nsec,
        )
    };
    if bytes.len() as i64 != before.st_size || !same(&after) || !same(&current) {
        return Err(refuse());
    }
    Ok(bytes)
}

/// Installed-generation Stop readback: retain every historical typed Stop
/// predicate while allowing only the authenticated service state root to have
/// evolved. Config and administrator metadata remain exact publications.
#[cfg(target_os = "linux")]
struct StoppedGenerationObservation {
    bytes: Vec<u8>,
    stage: authority::StageGuard,
    guard_lease: Option<crate::profile_auto_guardian::StoppedGuardLease>,
}

#[cfg(target_os = "linux")]
impl StoppedGenerationObservation {
    fn ensure_ready(&self, install: ReadOnlyInstallEvidence<'_>) -> Result<()> {
        install.revalidate()?;
        self.stage.store.revalidate()?;
        if let Some(lease) = self.guard_lease.as_ref() {
            lease.revalidate_ready().map_err(|_| refuse())?;
        }
        install.revalidate()?;
        Ok(())
    }

    /// Keep the guardian's guard owner present through the caller's readback
    /// and any archive operation. Drop closes the client's duplicate first.
    fn finish(self, install: ReadOnlyInstallEvidence<'_>) -> Result<()> {
        self.ensure_ready(install)
    }
}

#[cfg(target_os = "linux")]
fn observe_stopped_generation_held(
    path: &Path,
    lock: &crate::profile_auto_stopped_service::InstallLock,
    history: Option<&serde_json::Value>,
) -> Result<StoppedGenerationObservation> {
    observe_stopped_generation_with_read_lock(path, ReadOnlyInstallEvidence::Held(lock), history)
}

#[cfg(target_os = "linux")]
fn observe_stopped_generation_with_read_lock(
    path: &Path,
    lock: ReadOnlyInstallEvidence<'_>,
    history: Option<&serde_json::Value>,
) -> Result<StoppedGenerationObservation> {
    let phase = std::cell::Cell::new("historical_stage");
    observe_stopped_generation_with_phase(path, lock, history, &phase)
}

#[cfg(target_os = "linux")]
fn observe_stopped_generation_with_phase(
    path: &Path,
    lock: ReadOnlyInstallEvidence<'_>,
    history: Option<&serde_json::Value>,
    phase: &std::cell::Cell<&'static str>,
) -> Result<StoppedGenerationObservation> {
    use crate::profile_auto_stopped_service::pid1;
    phase.set("historical_stage");
    let historical = inspect_finalized_stage_with_read_lock(path, true, true, lock, phase)?;
    phase.set("historical_projection");
    let inspected: serde_json::Value = serde_json::from_slice(&historical).map_err(|_| refuse())?;
    let terminal = &inspected["terminal"];
    let unit = terminal["private_unit"].as_str().ok_or_else(refuse)?;
    let invocation = terminal["prior_invocation_id"]
        .as_str()
        .ok_or_else(refuse)?;
    let boot = terminal["boot_id"].as_str().ok_or_else(refuse)?;
    if terminal["outcome"] != "finalized-stopped" {
        return Err(refuse());
    }
    phase.set("private_pid1_first");
    let main = pid1::inspect_stopped_private(unit, invocation, boot).map_err(|_| refuse())?;
    phase.set("stage_reopen");
    let guard = authority::StageGuard::admit(durable::Store::reopen(path, 0)?)?;
    phase.set("launch_receipts");
    let (start_raw, _) = inspected_bound(&guard, "receipts/activation-owner/terminal.json")?;
    let start: InspectedStartTerminal = serde_json::from_slice(&start_raw).map_err(|_| refuse())?;
    let (launch_raw, _) =
        inspected_bound(&guard, "receipts/activation-owner/launch-consumed.json")?;
    let launch: InspectedLiveLaunch = serde_json::from_slice(&launch_raw).map_err(|_| refuse())?;
    if launch.schema != 1
        || launch.kind != "owned-launch-consumed"
        || launch.completed_sha256 != start.completed_sha256
        || launch.ticket_sha256 != start.launch_ticket_sha256
        || launch.private_unit != unit
        || launch.invocation_id != invocation
        || launch.main_pid <= 1
        || launch.main_start_tick == 0
        || launch.guardian_pid <= 1
        || launch.guardian_invocation_id.len() != 32
        || !launch
            .guardian_invocation_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || start
            .native_guard
            .as_ref()
            .is_some_and(|g| g.guardian_pid != launch.guardian_pid)
    {
        return Err(refuse());
    }
    let guardian_pid = launch.guardian_pid;
    let guardian_invocation = launch.guardian_invocation_id.as_str();
    phase.set("active_history_match");
    if history.is_some_and(|prior| {
        inspected["stage"] != prior["stage"]
            || terminal["start_terminal_sha256"] != prior["terminal"]["start_terminal_sha256"]
            || terminal["boot_id"] != prior["terminal"]["boot_id"]
            || prior["guardian"]["guardian_pid"] != guardian_pid
            || prior["guardian"]["guardian_invocation_id"] != guardian_invocation
    }) {
        return Err(refuse());
    }
    phase.set("idle_guardian_first");
    let guardian = pid1::inspect_idle_guardian(guardian_pid, guardian_invocation, boot)
        .map_err(|_| refuse())?;
    phase.set("guardian_peer_first");
    if !main.fdstore_empty_verified
        || !guardian.fdstore_empty_verified
        || main.pid1_netns != guardian.pid1_netns
        || crate::profile_auto_guardian::verify_guardian_peer(guardian_pid).map_err(|_| refuse())?
            != guardian_invocation
    {
        return Err(refuse());
    }
    phase.set("active_input");
    let mut input = receipt_store::active_input_facts(&guard)?;
    input["installed_manifest_sha256"] = terminal["installed_manifest_sha256"].clone();
    let guarded = guard.header.mode != AutoMode::SocksOnly;
    phase.set("guard_lock");
    let mut guard_lease = if guarded {
        let stage_fd = guard.store.duplicate_root()?;
        let install_fd = lock.duplicate_held_fd()?;
        Some(
            crate::profile_auto_guardian::StoppedGuardLease::acquire(
                stage_fd,
                install_fd,
                crate::profile_auto_guardian::StoppedGuardBinding {
                    guardian_pid,
                    guardian_invocation,
                    boot_id: boot,
                    netns_ino: main.pid1_netns.1,
                    unit,
                    prior_invocation_id: invocation,
                    stop_terminal_sha256: terminal["stop_terminal_sha256"]
                        .as_str()
                        .ok_or_else(refuse)?,
                    post_deny_policy_sha256: terminal["post_deny_policy_sha256"]
                        .as_str()
                        .ok_or_else(refuse)?,
                },
            )
            .map_err(|_| refuse())?,
        )
    } else {
        None
    };
    phase.set("deny_policy");
    let mut state_sha = None;
    let manager_sha = if guarded {
        let before = stopped_manager_binding()?;
        let policy = unit_store::guard_policy_readback()?;
        if !inspected_hex64(&policy.state_sha256)
            || !inspected_hex64(&policy.policy_sha256)
            || policy.manager_binding_sha256.as_deref() != Some(digest(&before).as_str())
            || terminal["post_deny_policy_sha256"] != policy.policy_sha256
            || stopped_manager_binding()? != before
        {
            return Err(refuse());
        }
        state_sha = Some(policy.state_sha256);
        Some(digest(&before))
    } else {
        if !terminal["post_deny_policy_sha256"].is_null()
            || history.is_some_and(|prior| !prior["guardian"]["manager_binding_sha256"].is_null())
        {
            return Err(refuse());
        }
        None
    };
    phase.set("private_pid1_second");
    let main_after = pid1::inspect_stopped_private(unit, invocation, boot).map_err(|_| refuse())?;
    phase.set("idle_guardian_second");
    let guardian_after = pid1::inspect_idle_guardian(guardian_pid, guardian_invocation, boot)
        .map_err(|_| refuse())?;
    phase.set("owner_readback_second");
    // Each query authenticates a fresh PID1 socket. Its connection inode is
    // deliberately not an invocation identity and may differ between reads.
    if main_after.boot_id != main.boot_id
        || main_after.unit != main.unit
        || main_after.prior_invocation != main.prior_invocation
        || !main_after.fdstore_empty_verified
        || main_after.pid1_netns != main.pid1_netns
        || guardian_after.boot_id != guardian.boot_id
        || guardian_after.guardian_pid != guardian.guardian_pid
        || guardian_after.guardian_invocation_id != guardian.guardian_invocation_id
        || guardian_after.watchdog_pid != guardian.watchdog_pid
        || !guardian_after.fdstore_empty_verified
        || guardian_after.pid1_netns != guardian.pid1_netns
        || crate::profile_auto_guardian::verify_guardian_peer(guardian_pid).map_err(|_| refuse())?
            != guardian_invocation
    {
        return Err(refuse());
    }
    phase.set("report_build");
    lock.revalidate()?;
    let report = stopped_generation_report(
        serde_json::json!(inspected["stage"]),
        serde_json::json!(terminal),
        serde_json::json!({"config_root": guard.header.config_root,
            "state_dir": guard.header.state_dir, "metadata_dir": guard.header.metadata_dir,
            "current_verified": true,
            "current_publications": guard.inspect_current_published_roots_with_metadata()?}),
        serde_json::json!(inspected["current_fixed"]),
        serde_json::json!(input),
        serde_json::json!({"stopped_verified": true, "no_live_lease_verified": true,
            "fdstore_empty_verified": main.fdstore_empty_verified}),
        serde_json::json!({"deny_verified": true,
            "fdstore_empty_verified": guardian.fdstore_empty_verified,
            "guardian_pid": guardian.guardian_pid,
            "guardian_invocation_id": guardian.guardian_invocation_id,
            "watchdog_pid": guardian.watchdog_pid,
            "prior_manager_binding_sha256": history.map(|prior| prior["guardian"]["manager_binding_sha256"].clone()),
            "manager_binding_sha256": manager_sha}),
    );
    let bytes = serde_json::to_vec(&report).map_err(|_| refuse())?;
    guard.store.revalidate()?;
    lock.revalidate()?;
    if let Some(lease) = guard_lease.as_mut() {
        lease.revalidate().map_err(|_| refuse())?;
        phase.set("deny_policy_final");
        // Re-read denial and the exact manager binding while the shared
        // original guard is still owned by the guardian. No outer source or
        // history mutation has begun at this point.
        let before = stopped_manager_binding()?;
        let policy = unit_store::guard_policy_readback()?;
        if manager_sha.as_deref() != Some(digest(&before).as_str())
            || state_sha.as_deref() != Some(policy.state_sha256.as_str())
            || terminal["post_deny_policy_sha256"] != policy.policy_sha256
            || policy.manager_binding_sha256.as_deref() != Some(digest(&before).as_str())
            || stopped_manager_binding()? != before
        {
            return Err(refuse());
        }
        lock.revalidate()?;
        guard.store.revalidate()?;
        phase.set("guard_ack");
        lease.ack_ready().map_err(|_| refuse())?;
    }
    phase.set("report_ready");
    Ok(StoppedGenerationObservation {
        bytes,
        stage: guard,
        guard_lease,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn seal_stopped_generation(path: &Path) -> Result<Vec<u8>> {
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    seal_stopped_generation_held(path, &lock)
}

#[cfg(target_os = "linux")]
fn seal_stopped_generation_held(
    path: &Path,
    lock: &crate::profile_auto_stopped_service::InstallLock,
) -> Result<Vec<u8>> {
    let phase = std::cell::Cell::new("install_lock");
    let result = (|| -> Result<Vec<u8>> {
        lock.revalidate().map_err(|_| refuse())?;
        phase.set("active_history");
        let history = installer_v2_generation::history_report()?;
        let observed = observe_stopped_generation_with_phase(
            path,
            ReadOnlyInstallEvidence::Held(lock),
            Some(&history),
            &phase,
        )?;
        observed.ensure_ready(ReadOnlyInstallEvidence::Held(lock))?;
        phase.set("archive_stopped_report");
        installer_v2_generation::archive_verified_stopped_report(&observed.bytes, lock)?;
        phase.set("install_lock_recheck");
        lock.revalidate().map_err(|_| refuse())?;
        let bytes = observed.bytes.clone();
        observed.finish(ReadOnlyInstallEvidence::Held(lock))?;
        Ok(bytes)
    })();
    if result.is_err() {
        // Fixed, non-sensitive source coordinates; no paths, receipts or
        // underlying parser/PID1 error ever enter the journal.
        eprintln!("AUTO_STOPPED_SEAL_DIAGNOSTIC phase={}", phase.get());
    }
    result
}

#[cfg(target_os = "linux")]
pub(crate) fn seal_unsealed_stopped_recovery(path: &Path) -> Result<Vec<u8>> {
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    let observed = observe_stopped_generation_held(path, &lock, None)?;
    observed.ensure_ready(ReadOnlyInstallEvidence::Held(&lock))?;
    installer_v2_generation::seal_unsealed_stopped_report(&observed.bytes, &lock)?;
    lock.revalidate().map_err(|_| refuse())?;
    let bytes = observed.bytes.clone();
    observed.finish(ReadOnlyInstallEvidence::Held(&lock))?;
    Ok(bytes)
}

/// Read-only validation for a shell that already holds the real install flock.
/// The inherited descriptor proves exclusion but cannot be passed to a
/// publisher, worker or StageGuard mutator. No stage path is accepted from the
/// caller: the authenticated stopped history names the one to inspect.
#[cfg(target_os = "linux")]
pub(crate) fn verify_stopped_generation_inherited(
    raw_lock_fd: std::os::fd::RawFd,
) -> Result<Vec<u8>> {
    use crate::profile_auto_stopped_service::InheritedInstallReadLock;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let lock = InheritedInstallReadLock::admit(raw_lock_fd).map_err(|_| refuse())?;
    let historical = installer_v2_generation::stopped_history_report()?;
    let stage = Path::new(historical["stage"]["path"].as_str().ok_or_else(refuse)?);
    let active = installer_v2_generation::history_report()?;
    let observed = observe_stopped_generation_with_read_lock(
        stage,
        ReadOnlyInstallEvidence::Inherited(&lock),
        Some(&active),
    )?;
    observed.ensure_ready(ReadOnlyInstallEvidence::Inherited(&lock))?;
    let expected = serde_json::to_vec(&historical).map_err(|_| refuse())?;
    if observed.bytes != expected {
        return Err(refuse());
    }
    // A durable boot interlock and exact retained candidate remain present
    // before the caller may replace installed assets. The archived report by
    // itself is never a source-rotation grant.
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), "generation-successor-current.json")?;
    let marker = recovery_open_at(control.as_raw_fd(), "v2-enabled", libc::O_RDONLY, 0)?;
    let marker_stat = recovery_stat(marker.as_raw_fd())?;
    if marker_stat.st_mode != libc::S_IFREG | 0o600
        || marker_stat.st_uid != 0
        || marker_stat.st_gid != 0
        || marker_stat.st_nlink != 1
        || marker_stat.st_size
            != b"{\"schema\":\"aegis_installer_auto_v2_enabled_v1\"}\n".len() as i64
    {
        return Err(refuse());
    }
    let mut marker_bytes = Vec::new();
    std::fs::File::from(marker)
        .take(128)
        .read_to_end(&mut marker_bytes)
        .map_err(|_| refuse())?;
    if marker_bytes != b"{\"schema\":\"aegis_installer_auto_v2_enabled_v1\"}\n" {
        return Err(refuse());
    }
    let public = Path::new(
        historical["input"]["public_payload_root"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let release_name = public
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    let release = recovery_chain(
        &["var", "lib", "aegis-auto", "releases", release_name],
        Some(0o700),
    )?;
    let release_bin = recovery_directory(release.as_raw_fd(), "bin", None)?;
    let candidate = recovery_open_at(release_bin.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    let candidate_stat = recovery_stat(candidate.as_raw_fd())?;
    if candidate_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || candidate_stat.st_uid != 0
        || candidate_stat.st_gid != 0
        || candidate_stat.st_nlink != 1
        || !matches!(candidate_stat.st_mode & 0o7777, 0o555 | 0o755)
        || recovery_file_hash(candidate.as_raw_fd(), 256 * 1024 * 1024)?.1
            != historical["input"]["candidate_sha256"]
                .as_str()
                .ok_or_else(refuse)?
    {
        return Err(refuse());
    }
    let installed_dir = recovery_chain(&["usr", "local", "bin"], None)?;
    let installed = recovery_open_at(installed_dir.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    let installed_stat = recovery_stat(installed.as_raw_fd())?;
    if installed_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || installed_stat.st_uid != 0
        || installed_stat.st_gid != 0
        || installed_stat.st_nlink != 1
        || !matches!(installed_stat.st_mode & 0o7777, 0o555 | 0o755)
        || recovery_file_hash(installed.as_raw_fd(), 256 * 1024 * 1024)?.1
            != historical["input"]["candidate_sha256"]
                .as_str()
                .ok_or_else(refuse)?
    {
        return Err(refuse());
    }
    let installer = recovery_open_at(release.as_raw_fd(), "install.sh", libc::O_RDONLY, 0)?;
    let installer_stat = recovery_stat(installer.as_raw_fd())?;
    if installer_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || installer_stat.st_uid != 0
        || installer_stat.st_gid != 0
        || installer_stat.st_nlink != 1
        || !matches!(installer_stat.st_mode & 0o7777, 0o555 | 0o755)
        || recovery_file_hash(installer.as_raw_fd(), 8 * 1024 * 1024)?.1
            != digest(include_bytes!("../../install.sh"))
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    if installer_v2_generation::stopped_history_report()? != historical {
        return Err(refuse());
    }
    let bytes = observed.bytes.clone();
    observed.finish(ReadOnlyInstallEvidence::Inherited(&lock))?;
    Ok(bytes)
}

/// Old installed CLI boundary for a staged same-boot successor. The actual
/// InstallLock, stopped StageGuard and guard flock remain held until both
/// archived predecessor seals and the sticky successor intent are durable.
#[cfg(target_os = "linux")]
pub(crate) fn begin_stopped_successor(candidate: &Path, public_root: &Path) -> Result<Vec<u8>> {
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    let history = installer_v2_generation::successor_history()?;
    let stage = Path::new(&history.stage_path);
    let observed = observe_stopped_generation_held(stage, &lock, Some(&history.active))?;
    observed.ensure_ready(ReadOnlyInstallEvidence::Held(&lock))?;
    let result = installer_v2_generation::begin_stopped_successor(
        &history,
        &observed.bytes,
        public_root,
        candidate,
        &lock,
    )?;
    lock.revalidate().map_err(|_| refuse())?;
    observed.finish(ReadOnlyInstallEvidence::Held(&lock))?;
    Ok(result)
}

/// A different boot may consume protected historical evidence only after a
/// new root/namespace/source/kernel-deny observation. No old StageGuard or
/// stopped report is reconstructed for a generation that died at reboot.
#[cfg(target_os = "linux")]
pub(crate) fn begin_boot_successor() -> Result<Vec<u8>> {
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire().map_err(|_| refuse())?;
    let observed = installer_v2_boot::observe_current(&lock)?;
    let bytes = installer_v2_generation::begin_boot_successor(&observed, &lock)?;
    lock.revalidate().map_err(|_| refuse())?;
    Ok(bytes)
}

/// A shell or package preinst may inherit only this read capability. The
/// archived predecessor is freshly inspected; no supplied stage path or
/// caller-provided SHA becomes authority to rotate source or Start a client.
#[cfg(target_os = "linux")]
pub(crate) fn verify_stopped_successor_inherited(
    raw_lock_fd: std::os::fd::RawFd,
) -> Result<Vec<u8>> {
    use crate::profile_auto_stopped_service::InheritedInstallReadLock;
    let lock = InheritedInstallReadLock::admit(raw_lock_fd).map_err(|_| refuse())?;
    let history = installer_v2_generation::successor_history()?;
    let stage = Path::new(&history.stage_path);
    let observed = observe_stopped_generation_with_read_lock(
        stage,
        ReadOnlyInstallEvidence::Inherited(&lock),
        Some(&history.active),
    )?;
    observed.ensure_ready(ReadOnlyInstallEvidence::Inherited(&lock))?;
    let result = installer_v2_generation::verify_stopped_successor(&history, &observed.bytes)?;
    lock.revalidate().map_err(|_| refuse())?;
    observed.finish(ReadOnlyInstallEvidence::Inherited(&lock))?;
    Ok(result)
}

#[cfg(target_os = "linux")]
fn retired_guardian_readback(
    install: &crate::profile_auto_stopped_service::InheritedInstallReadLock,
    guard: &crate::profile_auto_stopped_service::InheritedGuardReadFd,
) -> Result<serde_json::Value> {
    use std::{
        io::{Read, Seek, SeekFrom},
        os::fd::{AsRawFd, FromRawFd},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let passed = guard.duplicate_for_child(install).map_err(|_| refuse())?;
    let output =
        unsafe { libc::memfd_create(c"aegis-retired-guard-read".as_ptr(), libc::MFD_CLOEXEC) };
    if output < 0 {
        return Err(refuse());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(output) };
    let mut child = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-B",
            "/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py",
            "rotation-retired-readback",
            &passed.as_raw_fd().to_string(),
        ])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| refuse())?;
    // S9: wake on the child's exit through its pidfd under the same bound.
    let exit =
        crate::profile_auto_stopped_service::ChildExitWait::open(&child, Duration::from_millis(20));
    let deadline = Instant::now() + Duration::from_secs(35);
    loop {
        if let Some(status) = child.try_wait().map_err(|_| refuse())? {
            if !status.success() {
                return Err(refuse());
            }
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        exit.wait(&[], deadline);
    }
    guard.revalidate(install).map_err(|_| refuse())?;
    if output.metadata().map_err(|_| refuse())?.len() > 4096 {
        return Err(refuse());
    }
    output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
    let mut bytes = Vec::new();
    output
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    if bytes.len() > 4096 {
        return Err(refuse());
    }
    serde_json::from_slice(&bytes).map_err(|_| refuse())
}

/// Package preinst runs after the old guardian actors have been retired.
/// It cannot reuse the pre-rotation live observer; this separate phase binds
/// the protected successor to fresh deny and actor-absence readback while
/// both inherited parent OFDs remain live. Neither FD grants publication.
#[cfg(target_os = "linux")]
pub(crate) fn verify_retired_successor_inherited(
    install_fd: std::os::fd::RawFd,
    guard_fd: std::os::fd::RawFd,
) -> Result<Vec<u8>> {
    use crate::profile_auto_stopped_service::InheritedInstallReadLock;
    let install = InheritedInstallReadLock::admit(install_fd).map_err(|_| refuse())?;
    let guard = install
        .admit_guard_read_fd(guard_fd)
        .map_err(|_| refuse())?;
    let history = installer_v2_generation::successor_history()?;
    let retired = retired_guardian_readback(&install, &guard)?;
    let result = installer_v2_generation::verify_retired_successor(&history, &retired)?;
    guard.revalidate(&install).map_err(|_| refuse())?;
    Ok(result)
}

#[cfg(target_os = "linux")]
fn cold_canonical_child_json(raw: &[u8]) -> Result<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_slice(raw).map_err(|_| refuse())?;
    if !value.is_object() {
        return Err(refuse());
    }
    let mut canonical = serde_json::to_vec(&value).map_err(|_| refuse())?;
    canonical.push(b'\n');
    if raw != canonical {
        return Err(refuse());
    }
    Ok(value)
}

/// Enter B's console recovery only from the separately pinned host kit. The
/// kit authenticates this ELF before exec; this native entry authenticates the
/// old sealed A intent and the exact held B coordinator before Python exec.
/// It does not inspect current routing or grant a recovery outcome.
#[cfg(target_os = "linux")]
pub(crate) fn launch_cold_recovery(root: &Path) -> Result<()> {
    launch_cold_recovery_mode(root, false)
}

#[cfg(target_os = "linux")]
pub(crate) fn launch_cold_rollover(root: &Path) -> Result<()> {
    launch_cold_recovery_mode(root, true)
}

#[cfg(target_os = "linux")]
fn launch_cold_recovery_mode(root: &Path, stale_rollover: bool) -> Result<()> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    if unsafe { libc::geteuid() } != 0 {
        return Err(refuse());
    }
    let stale_source = if stale_rollover {
        Some(installer_v2_generation::cold_stale_source_for_stage(root)?)
    } else {
        None
    };
    let normal_source = if stale_rollover {
        None
    } else {
        Some(installer_v2_generation::cold_bootstrap_source(root)?)
    };
    let source = if let Some(stale) = &stale_source {
        &stale.bootstrap
    } else {
        normal_source.as_ref().ok_or_else(refuse)?
    };
    // The externally pinned ELF may execute retained B Python only after a
    // fresh current-boot denial and source proof. Python repeats that proof
    // under its own locks before any durable mutation.
    if let Some(stale) = &stale_source {
        let proof = verify_cold_stale_preretire_fresh(root, &stale.prior_intent_sha256)?;
        let value: serde_json::Value = serde_json::from_slice(&proof).map_err(|_| refuse())?;
        if value["schema"] != "aegis_auto_v2_cold_stale_preretire_v1"
            || value["prior_intent_sha256"] != stale.prior_intent_sha256
            || value["no_client_grant"] != true
        {
            return Err(refuse());
        }
    }
    let name = root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    let release = recovery_chain(&["var", "lib", "aegis-auto", "releases", name], Some(0o700))?;
    let scripts = recovery_directory(release.as_raw_fd(), "scripts", None)?;
    let lib = recovery_directory(scripts.as_raw_fd(), "lib", None)?;
    let script = recovery_open_at(
        lib.as_raw_fd(),
        "aegis_installer_auto_v2.py",
        libc::O_RDONLY,
        0,
    )?;
    let before = recovery_stat(script.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o444
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size > 4 << 20
        || recovery_file_hash(script.as_raw_fd(), 4 << 20)?.1 != source.coordinator_sha256
    {
        return Err(refuse());
    }
    let named = recovery_open_at(
        lib.as_raw_fd(),
        "aegis_installer_auto_v2.py",
        libc::O_RDONLY,
        0,
    )?;
    let now = recovery_stat(named.as_raw_fd())?;
    if (
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
        now.st_dev,
        now.st_ino,
        now.st_mode,
        now.st_uid,
        now.st_gid,
        now.st_nlink,
        now.st_size,
        now.st_mtime,
        now.st_ctime,
    ) {
        return Err(refuse());
    }
    let stat_raw = std::fs::read_to_string("/proc/self/stat").map_err(|_| refuse())?;
    if stat_raw.len() > 4096 {
        return Err(refuse());
    }
    let tail = stat_raw.rsplit_once(") ").ok_or_else(refuse)?.1;
    let start_tick: u64 = tail
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(refuse)?
        .parse()
        .map_err(|_| refuse())?;
    if start_tick == 0 {
        return Err(refuse());
    }
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| refuse())?;
    let boot = boot.trim_end_matches('\n');
    if boot.len() != 36
        || !boot.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
    {
        return Err(refuse());
    }
    let mut handoff_value = serde_json::json!({
        "schema": if stale_rollover { "aegis_auto_cold_launcher_handoff_v2" } else { "aegis_auto_cold_launcher_handoff_v1" },
        "boot_id": boot,
        "retained_root": root.to_str().ok_or_else(refuse)?,
        "candidate_sha256": &source.candidate_sha256,
        "coordinator_sha256": &source.coordinator_sha256,
        "successor_intent_sha256": &source.successor_intent_sha256,
        "next_bundle_manifest_sha256": &source.bundle_manifest_sha256,
        "next_sums_sha256": &source.sums_sha256,
        "launcher_pid": std::process::id(),
        "launcher_start_tick": start_tick,
    });
    if let Some(stale) = &stale_source {
        let object = handoff_value.as_object_mut().ok_or_else(refuse)?;
        for (key, value) in [
            ("mode", serde_json::json!("stale_rollover")),
            (
                "prior_intent_sha256",
                serde_json::json!(stale.prior_intent_sha256),
            ),
            ("prior_boot_id", serde_json::json!(stale.prior_boot_id)),
            ("current_boot_id", serde_json::json!(boot)),
            (
                "original_intent_sha256",
                serde_json::json!(stale.original_intent_sha256),
            ),
            (
                "prior_pointer_state",
                serde_json::json!(stale.prior_pointer_state),
            ),
        ] {
            object.insert(key.to_owned(), value);
        }
    }
    let mut handoff = serde_json::to_vec(&handoff_value).map_err(|_| refuse())?;
    handoff.push(b'\n');
    if handoff.len() > 2048 {
        return Err(refuse());
    }
    let memfd = unsafe {
        libc::memfd_create(
            c"aegis-cold-launch".as_ptr(),
            libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC,
        )
    };
    if memfd < 0 {
        return Err(refuse());
    }
    let mut handoff_file = unsafe { std::fs::File::from_raw_fd(memfd) };
    handoff_file.write_all(&handoff).map_err(|_| refuse())?;
    handoff_file.sync_all().map_err(|_| refuse())?;
    if unsafe {
        libc::fcntl(
            handoff_file.as_raw_fd(),
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
        )
    } != 0
    {
        return Err(refuse());
    }
    let expected_seals =
        libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(handoff_file.as_raw_fd(), libc::F_GET_SEALS) } != expected_seals {
        return Err(refuse());
    }
    let script_high = unsafe { libc::fcntl(script.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 20) };
    let handoff_high = unsafe { libc::fcntl(handoff_file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 20) };
    if script_high < 0 || handoff_high < 0 {
        if script_high >= 0 {
            unsafe { libc::close(script_high) };
        }
        if handoff_high >= 0 {
            unsafe { libc::close(handoff_high) };
        }
        return Err(refuse());
    }
    let script_high = unsafe { OwnedFd::from_raw_fd(script_high) };
    let handoff_high = unsafe { OwnedFd::from_raw_fd(handoff_high) };
    if unsafe { libc::dup2(script_high.as_raw_fd(), 11) } != 11
        || unsafe { libc::dup2(handoff_high.as_raw_fd(), 12) } != 12
        || unsafe { libc::lseek(11, 0, libc::SEEK_SET) } != 0
        || unsafe { libc::lseek(12, 0, libc::SEEK_SET) } != 0
    {
        return Err(refuse());
    }
    let refreshed_stale = if stale_rollover {
        Some(installer_v2_generation::cold_stale_source_for_stage(root)?)
    } else {
        None
    };
    if let (Some(before), Some(after)) = (&stale_source, &refreshed_stale) {
        if before.original_intent_sha256 != after.original_intent_sha256
            || before.original_state != after.original_state
            || before.prior_intent_sha256 != after.prior_intent_sha256
            || before.prior_boot_id != after.prior_boot_id
            || before.guardian_rotation_intent_sha256 != after.guardian_rotation_intent_sha256
            || before.prior_pointer_state != after.prior_pointer_state
        {
            return Err(refuse());
        }
    }
    let refreshed_normal = if stale_rollover {
        None
    } else {
        Some(installer_v2_generation::cold_bootstrap_source(root)?)
    };
    let refreshed = if let Some(stale) = &refreshed_stale {
        &stale.bootstrap
    } else {
        refreshed_normal.as_ref().ok_or_else(refuse)?
    };
    if refreshed.candidate_sha256 != source.candidate_sha256
        || refreshed.coordinator_sha256 != source.coordinator_sha256
        || refreshed.successor_intent_sha256 != source.successor_intent_sha256
        || recovery_file_hash(11, 4 << 20)?.1 != source.coordinator_sha256
    {
        return Err(refuse());
    }
    if unsafe { libc::lseek(11, 0, libc::SEEK_SET) } != 0 {
        return Err(refuse());
    }
    let error = Command::new("/usr/bin/python3")
        .arg("-I")
        .arg("-B")
        .arg("/proc/self/fd/11")
        .arg("recover-terminal-migration")
        .arg("--retained-root")
        .arg(root)
        .arg("--source-fd")
        .arg("11")
        .arg("--handoff-fd")
        .arg("12")
        .args(if stale_rollover {
            &["--stale-rollover"][..]
        } else {
            &[][..]
        })
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .exec();
    let _ = error;
    Err(refuse())
}

#[cfg(target_os = "linux")]
fn cold_child_script(root: &Path, leaf: &str, expected_sha: &str) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if !matches!(
        leaf,
        "aegis_auto_guardian.py" | "aegis_installer_auto_v2.py" | "aegis_auto_terminal_register.py"
    ) || expected_sha.len() != 64
        || !expected_sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    let release_name = root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    if root != Path::new("/var/lib/aegis-auto/releases").join(release_name) {
        return Err(refuse());
    }
    let release = recovery_chain(
        &["var", "lib", "aegis-auto", "releases", release_name],
        Some(0o700),
    )?;
    let scripts = recovery_directory(release.as_raw_fd(), "scripts", None)?;
    let lib = recovery_directory(scripts.as_raw_fd(), "lib", None)?;
    let held = recovery_open_at(lib.as_raw_fd(), leaf, libc::O_RDONLY, 0)?;
    let before = recovery_stat(held.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o444
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || recovery_file_hash(held.as_raw_fd(), 4 << 20)?.1 != expected_sha
    {
        return Err(refuse());
    }
    let after = recovery_stat(held.as_raw_fd())?;
    let named = recovery_open_at(lib.as_raw_fd(), leaf, libc::O_RDONLY, 0)?;
    let current = recovery_stat(named.as_raw_fd())?;
    let identity = |item: &libc::stat| {
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
        )
    };
    if identity(&before) != identity(&after) || identity(&before) != identity(&current) {
        return Err(refuse());
    }
    let high_fd = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 32) };
    if high_fd < 0 {
        return Err(refuse());
    }
    let pinned = unsafe { std::os::fd::OwnedFd::from_raw_fd(high_fd) };
    if unsafe { libc::lseek(pinned.as_raw_fd(), 0, libc::SEEK_SET) } != 0
        || unsafe { libc::fcntl(pinned.as_raw_fd(), libc::F_SETFD, 0) } != 0
    {
        return Err(refuse());
    }
    Ok(pinned)
}

#[cfg(target_os = "linux")]
fn cold_child_script_stable(
    held: &std::os::fd::OwnedFd,
    root: &Path,
    leaf: &str,
    expected_sha: &str,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    let named = cold_child_script(root, leaf, expected_sha)?;
    let before = recovery_stat(held.as_raw_fd())?;
    let after = recovery_stat(named.as_raw_fd())?;
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime,
        before.st_mtime_nsec,
        before.st_ctime,
        before.st_ctime_nsec,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime,
        after.st_mtime_nsec,
        after.st_ctime,
        after.st_ctime_nsec,
    ) || recovery_file_hash(held.as_raw_fd(), 4 << 20)?.1 != expected_sha
    {
        return Err(refuse());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cold_stale_guardian_readback(
    install: &crate::profile_auto_stopped_service::InheritedInstallReadLock,
    guard: &crate::profile_auto_stopped_service::InheritedGuardReadFd,
    root: &Path,
    source: &installer_v2_generation::ColdStaleSource,
    deadline: std::time::Instant,
) -> Result<serde_json::Value> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    if std::time::Instant::now() >= deadline {
        return Err(refuse());
    }
    install.revalidate().map_err(|_| refuse())?;
    guard.revalidate(install).map_err(|_| refuse())?;
    let preexec = installer_v2_generation::cold_stale_source_for_stage(root)?;
    if preexec.bootstrap.candidate_sha256 != source.bootstrap.candidate_sha256
        || preexec.bootstrap.coordinator_sha256 != source.bootstrap.coordinator_sha256
        || preexec.bootstrap.successor_intent_sha256 != source.bootstrap.successor_intent_sha256
        || preexec.original_intent_sha256 != source.original_intent_sha256
        || preexec.prior_intent_sha256 != source.prior_intent_sha256
        || preexec.guardian_rotation_intent_sha256 != source.guardian_rotation_intent_sha256
        || preexec.guardian_source_sha256 != source.guardian_source_sha256
    {
        return Err(refuse());
    }
    let inherited_install = install.duplicate_held_fd().map_err(|_| refuse())?;
    let inherited_guard = guard.duplicate_for_child(install).map_err(|_| refuse())?;
    for fd in [inherited_install.as_raw_fd(), inherited_guard.as_raw_fd()] {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(refuse());
        }
    }
    let output_fd = unsafe { libc::memfd_create(c"aegis-cold-deny".as_ptr(), libc::MFD_CLOEXEC) };
    if output_fd < 0 {
        return Err(refuse());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(output_fd) };
    let held_script = cold_child_script(
        root,
        "aegis_auto_guardian.py",
        &source.guardian_source_sha256,
    )?;
    let script_fd_path = format!("/proc/self/fd/{}", held_script.as_raw_fd());
    let mut child = Command::new("/usr/bin/python3")
        .arg("-I")
        .arg("-B")
        .arg(&script_fd_path)
        .arg("cold-stale-denied-readback")
        .arg(inherited_install.as_raw_fd().to_string())
        .arg(inherited_guard.as_raw_fd().to_string())
        .arg(root)
        .arg(&source.prior_intent_sha256)
        .arg(&source.guardian_rotation_intent_sha256)
        .arg("--retained-source")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| refuse())?;
    let exit =
        crate::profile_auto_stopped_service::ChildExitWait::open(&child, Duration::from_millis(20));
    loop {
        if output.metadata().map_err(|_| refuse())?.len() > 8192
            || std::time::Instant::now() >= deadline
        {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse());
            }
            Ok(None) => exit.wait(&[], deadline),
        }
    }
    guard.revalidate(install).map_err(|_| refuse())?;
    output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
    let mut raw = Vec::new();
    output
        .take(8193)
        .read_to_end(&mut raw)
        .map_err(|_| refuse())?;
    if raw.is_empty() || raw.len() > 8192 {
        return Err(refuse());
    }
    cold_child_script_stable(
        &held_script,
        root,
        "aegis_auto_guardian.py",
        &source.guardian_source_sha256,
    )?;
    let value = cold_canonical_child_json(&raw)?;
    let object = value.as_object().ok_or_else(refuse)?;
    let keys = [
        "schema",
        "prior_intent_sha256",
        "rotation_intent_sha256",
        "boot_id",
        "selected_manager",
        "guard30_sha256",
        "manager31_sha256",
        "guardian31_sha256",
        "state_sha256",
        "policy_sha256",
        "manager_binding_sha256",
        "observer_state",
        "observer_source_sha256",
        "observer_ready_sha256",
        "infrastructure_rows_sha256",
        "infrastructure_rows",
        "infrastructure_quiescent",
        "infrastructure_qualified",
        "quiesce_state",
        "quiesce_receipt_sha256",
        "quiesce_monotonic_tick",
        "package_repair_receipt_sha256",
        "package_repaired_tick",
        "client_actors_absent",
        "jobs_absent",
        "cgroups_empty",
        "stop_intent_absent",
    ];
    if object.len() != keys.len()
        || keys.iter().any(|key| !object.contains_key(*key))
        || value["schema"] != "aegis_auto_guard_cold_stale_denied_readback_v1"
        || value["prior_intent_sha256"] != source.prior_intent_sha256
        || value["rotation_intent_sha256"] != source.guardian_rotation_intent_sha256
        || value["boot_id"]
            != std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| refuse())?
                .trim_end_matches('\n')
        || !["NetworkManager.service", "systemd-networkd.service"]
            .contains(&value["selected_manager"].as_str().ok_or_else(refuse)?)
        || [
            "guard30_sha256",
            "state_sha256",
            "policy_sha256",
            "infrastructure_rows_sha256",
        ]
        .iter()
        .any(|key| {
            value[*key].as_str().is_none_or(|sha| {
                sha.len() != 64
                    || sha
                        .bytes()
                        .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
            })
        })
        || [
            "client_actors_absent",
            "jobs_absent",
            "cgroups_empty",
            "stop_intent_absent",
            "infrastructure_qualified",
        ]
        .iter()
        .any(|key| value[*key] != true)
    {
        return Err(refuse());
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn cold_stale_site_readback(
    install: &crate::profile_auto_stopped_service::InheritedInstallReadLock,
    guard: &crate::profile_auto_stopped_service::InheritedGuardReadFd,
    root: &Path,
    source: &installer_v2_generation::ColdStaleSource,
    deadline: std::time::Instant,
) -> Result<serde_json::Value> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    if std::time::Instant::now() >= deadline {
        return Err(refuse());
    }
    install.revalidate().map_err(|_| refuse())?;
    guard.revalidate(install).map_err(|_| refuse())?;
    let preexec = installer_v2_generation::cold_stale_source_for_stage(root)?;
    if preexec.bootstrap.candidate_sha256 != source.bootstrap.candidate_sha256
        || preexec.bootstrap.coordinator_sha256 != source.bootstrap.coordinator_sha256
        || preexec.bootstrap.successor_intent_sha256 != source.bootstrap.successor_intent_sha256
        || preexec.original_intent_sha256 != source.original_intent_sha256
        || preexec.prior_intent_sha256 != source.prior_intent_sha256
        || preexec.guardian_rotation_intent_sha256 != source.guardian_rotation_intent_sha256
        || preexec.site_helper_sha256 != source.site_helper_sha256
    {
        return Err(refuse());
    }
    let inherited_install = install.duplicate_held_fd().map_err(|_| refuse())?;
    let inherited_guard = guard.duplicate_for_child(install).map_err(|_| refuse())?;
    for fd in [inherited_install.as_raw_fd(), inherited_guard.as_raw_fd()] {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(refuse());
        }
    }
    let output_fd = unsafe { libc::memfd_create(c"aegis-cold-deny".as_ptr(), libc::MFD_CLOEXEC) };
    if output_fd < 0 {
        return Err(refuse());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(output_fd) };
    let held_script = cold_child_script(
        root,
        "aegis_auto_terminal_register.py",
        &source.site_helper_sha256,
    )?;
    let script_fd_path = format!("/proc/self/fd/{}", held_script.as_raw_fd());
    let mut child = Command::new("/usr/bin/python3")
        .arg("-I")
        .arg("-B")
        .arg(&script_fd_path)
        .arg("cold-stale-site-readback")
        .arg(inherited_install.as_raw_fd().to_string())
        .arg(inherited_guard.as_raw_fd().to_string())
        .arg(root)
        .arg(&source.prior_intent_sha256)
        .arg(source.old_context_sha256.as_deref().unwrap_or("none"))
        .arg("--retained-source")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| refuse())?;
    let exit =
        crate::profile_auto_stopped_service::ChildExitWait::open(&child, Duration::from_millis(20));
    loop {
        if output.metadata().map_err(|_| refuse())?.len() > 8192
            || std::time::Instant::now() >= deadline
        {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse());
            }
            Ok(None) => exit.wait(&[], deadline),
        }
    }
    guard.revalidate(install).map_err(|_| refuse())?;
    output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
    let mut raw = Vec::new();
    output
        .take(8193)
        .read_to_end(&mut raw)
        .map_err(|_| refuse())?;
    if raw.is_empty() || raw.len() > 8192 {
        return Err(refuse());
    }
    cold_child_script_stable(
        &held_script,
        root,
        "aegis_auto_terminal_register.py",
        &source.site_helper_sha256,
    )?;
    let value = cold_canonical_child_json(&raw)?;
    let object = value.as_object().ok_or_else(refuse)?;
    let keys = [
        "schema",
        "boot_id",
        "prior_boot_id",
        "prior_intent_sha256",
        "selected_manager",
        "site_state",
        "migration_state",
        "manager31_state",
        "context_state",
        "old_context_sha256",
        "cold_context_state",
        "cold_old_context_sha256",
        "old_observer_archive_sha256",
        "next_bundle_manifest_sha256",
        "next_sums_sha256",
        "source_config_sha256",
        "store_config_sha256",
        "active_hook_sha256",
        "configure_intent_sha256",
        "configured_sha256",
        "manager31_sha256",
        "guardian31_sha256",
        "no_client_grant",
    ];
    if object.len() != keys.len()
        || keys.iter().any(|key| !object.contains_key(*key))
        || value["schema"] != "aegis_auto_terminal_cold_stale_site_readback_v1"
        || value["prior_boot_id"] != source.prior_boot_id
        || value["prior_intent_sha256"] != source.prior_intent_sha256
        || value["selected_manager"] != source.selected_manager
        || value["next_bundle_manifest_sha256"] != source.bootstrap.bundle_manifest_sha256
        || value["next_sums_sha256"] != source.bootstrap.sums_sha256
        || value["no_client_grant"] != true
        || ![
            "a_exact",
            "a_retiring_prefix",
            "absent",
            "b_prefix",
            "b_complete",
        ]
        .contains(&value["site_state"].as_str().ok_or_else(refuse)?)
    {
        return Err(refuse());
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn cold_stale_double_observation(
    install: &crate::profile_auto_stopped_service::InheritedInstallReadLock,
    guard: &crate::profile_auto_stopped_service::InheritedGuardReadFd,
    root: &Path,
    source: &installer_v2_generation::ColdStaleSource,
    deadline: std::time::Instant,
) -> Result<(serde_json::Value, serde_json::Value, serde_json::Value)> {
    let first_guardian = cold_stale_guardian_readback(install, guard, root, source, deadline)?;
    let first_package = cold_stale_package_readback(install, guard, root, source, deadline)?;
    let first_site = cold_stale_site_readback(install, guard, root, source, deadline)?;
    validate_cold_stale_package_readback(&first_package, source)?;
    validate_cold_infrastructure_rows(&first_guardian, &first_package)?;
    let second_guardian = cold_stale_guardian_readback(install, guard, root, source, deadline)?;
    let second_package = cold_stale_package_readback(install, guard, root, source, deadline)?;
    let second_site = cold_stale_site_readback(install, guard, root, source, deadline)?;
    validate_cold_stale_package_readback(&second_package, source)?;
    validate_cold_infrastructure_rows(&second_guardian, &second_package)?;
    let observer_state = first_guardian["observer_state"]
        .as_str()
        .ok_or_else(refuse)?;
    let observer_admitted = if observer_state == "absent" {
        first_guardian["observer_ready_sha256"].is_null()
    } else if observer_state == "b_ready" {
        let roster = first_package["roster"].as_array().ok_or_else(refuse)?;
        let witness: Vec<_> = roster
            .iter()
            .filter(|row| row["path"] == "helper/aegis_auto_terminal_witness.py")
            .collect();
        witness.len() == 1
            && source.current_head_sha256.is_some()
            && source.current_intent_sha256.is_some()
            && first_package["package_state"] == "new_exact"
            && first_site["site_state"] == "b_complete"
            && witness[0]["sha256"] == first_guardian["observer_source_sha256"]
            && first_guardian["observer_ready_sha256"]
                .as_str()
                .is_some_and(|sha| {
                    sha.len() == 64
                        && sha
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                })
    } else {
        false
    };
    if first_guardian != second_guardian
        || first_package != second_package
        || first_site != second_site
        || !observer_admitted
        || first_guardian["selected_manager"] != first_site["selected_manager"]
        || first_guardian["manager31_sha256"] != first_site["manager31_sha256"]
        || first_guardian["guardian31_sha256"] != first_site["guardian31_sha256"]
        || first_site["boot_id"] != first_guardian["boot_id"]
        || first_package["boot_id"] != first_guardian["boot_id"]
    {
        return Err(refuse());
    }
    guard.revalidate(install).map_err(|_| refuse())?;
    let after = installer_v2_generation::cold_stale_source_for_stage(root)?;
    if after.original_intent_sha256 != source.original_intent_sha256
        || after.prior_intent_sha256 != source.prior_intent_sha256
        || after.prior_boot_id != source.prior_boot_id
        || after.bootstrap.candidate_sha256 != source.bootstrap.candidate_sha256
        || after.bootstrap.bundle_manifest_sha256 != source.bootstrap.bundle_manifest_sha256
        || after.bootstrap.sums_sha256 != source.bootstrap.sums_sha256
        || after.prior_pointer_state != source.prior_pointer_state
        || after.current_head_sha256 != source.current_head_sha256
        || after.current_intent_sha256 != source.current_intent_sha256
        || after.barrier_sha256 != source.barrier_sha256
        || after.old_context_sha256 != source.old_context_sha256
        || after.old_install_sha256 != source.old_install_sha256
        || after.old_candidate_sha256 != source.old_candidate_sha256
        || after.new_package_sha256 != source.new_package_sha256
        || after.selected_manager != source.selected_manager
        || after.guard_shell_sha256 != source.guard_shell_sha256
        || after.guardian_source_sha256 != source.guardian_source_sha256
        || after.package_helper_sha256 != source.package_helper_sha256
        || after.site_helper_sha256 != source.site_helper_sha256
    {
        return Err(refuse());
    }
    Ok((first_guardian, first_package, first_site))
}

#[cfg(target_os = "linux")]
fn cold_stale_projection(
    source: &installer_v2_generation::ColdStaleSource,
    guardian: &serde_json::Value,
    package: &serde_json::Value,
    site: &serde_json::Value,
    retirement_sha: &str,
) -> Result<serde_json::Value> {
    if retirement_sha.len() != 64
        || retirement_sha
            .bytes()
            .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
        || guardian["selected_manager"] != source.selected_manager
        || site["selected_manager"] != source.selected_manager
        || site["prior_intent_sha256"] != source.prior_intent_sha256
        || site["prior_boot_id"] != source.prior_boot_id
        || site["next_bundle_manifest_sha256"] != source.bootstrap.bundle_manifest_sha256
        || site["next_sums_sha256"] != source.bootstrap.sums_sha256
        || site["no_client_grant"] != true
        || !["preparation_absent", "pending_prefix", "completed_edge"]
            .contains(&site["migration_state"].as_str().ok_or_else(refuse)?)
        || ![
            "a_exact",
            "a_retiring_prefix",
            "absent",
            "b_prefix",
            "b_complete",
        ]
        .contains(&site["site_state"].as_str().ok_or_else(refuse)?)
        || !["a_exact", "absent", "b_exact"]
            .contains(&site["manager31_state"].as_str().ok_or_else(refuse)?)
        || site["old_context_sha256"].as_str() != source.old_context_sha256.as_deref()
            && site["cold_old_context_sha256"].as_str() != source.old_context_sha256.as_deref()
    {
        return Err(refuse());
    }
    let roster = package["roster"].as_array().ok_or_else(refuse)?;
    let shell_rows: Vec<_> = roster
        .iter()
        .filter(|row| row["path"] == "helper/aegis-device-egress-guard.sh")
        .collect();
    if shell_rows.len() != 1 {
        return Err(refuse());
    }
    let shell_sha = &shell_rows[0]["sha256"];
    let package_state = package["package_state"].as_str().ok_or_else(refuse)?;
    if source.original_state == "consumed"
        && (package_state != "new_exact"
            || shell_sha.as_str() != Some(source.guard_shell_sha256.as_str()))
    {
        return Err(refuse());
    }
    let mut guardian_raw = serde_json::to_vec(guardian).map_err(|_| refuse())?;
    guardian_raw.push(b'\n');
    let boot_id = guardian["boot_id"].as_str().ok_or_else(refuse)?;
    Ok(serde_json::json!({
        "schema": "aegis_auto_v2_cold_stale_verification_v1",
        "current_boot_id": boot_id,
        "prior_boot_id": source.prior_boot_id,
        "original_intent_sha256": source.original_intent_sha256,
        "prior_intent_sha256": source.prior_intent_sha256,
        "retained_root": source.retained_root,
        "new_candidate_sha256": source.bootstrap.candidate_sha256,
        "next_bundle_manifest_sha256": source.bootstrap.bundle_manifest_sha256,
        "next_sums_sha256": source.bootstrap.sums_sha256,
        "prior_pointer_retirement_sha256": retirement_sha,
        "guard_shell_sha256": shell_sha,
        "guard30_sha256": guardian["guard30_sha256"],
        "deny_policy_sha256": guardian["policy_sha256"],
        "client_actors_absent": guardian["client_actors_absent"],
        "jobs_absent": guardian["jobs_absent"],
        "cgroups_empty": guardian["cgroups_empty"],
        "stop_intent_absent": guardian["stop_intent_absent"],
        "no_client_grant": true,
        "old_root": source.old_root,
        "package_state": package_state,
        "original_intent_state": source.original_state,
        "migration_state": site["migration_state"],
        "site_state": site["site_state"],
        "manager31_state": site["manager31_state"],
        "initial_denied_proof_sha256": digest(&guardian_raw),
        "initial_infrastructure_rows_sha256": guardian["infrastructure_rows_sha256"],
    }))
}

/// Fresh current-boot source, kernel, PID1 and package proof for an old cold
/// attempt. The immutable old phases are lineage only. The caller's held
/// Install→Guard OFDs remain valid across this read-only result.
/// Read-only source and current-boot denial proof before a typed pointer or
/// unpublished-stage retirement. It deliberately makes no claim that either
/// retirement has occurred and returns no grant or clean BOOT authority.
#[cfg(target_os = "linux")]
pub(crate) fn verify_cold_stale_preretire_inherited(
    install_fd: std::os::fd::RawFd,
    guard_fd: std::os::fd::RawFd,
    root: &Path,
    expected_prior_sha: &str,
) -> Result<Vec<u8>> {
    use crate::profile_auto_stopped_service::InheritedInstallReadLock;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(90);
    let install = InheritedInstallReadLock::admit(install_fd).map_err(|_| refuse())?;
    let guard = install
        .admit_guard_read_fd(guard_fd)
        .map_err(|_| refuse())?;
    let source = installer_v2_generation::cold_stale_source_for_stage(root)?;
    if source.prior_intent_sha256 != expected_prior_sha {
        return Err(refuse());
    }
    let (guardian, package, site) =
        cold_stale_double_observation(&install, &guard, root, &source, deadline)?;
    let state = package["package_state"].as_str().ok_or_else(refuse)?;
    let shell_rows: Vec<_> = package["roster"]
        .as_array()
        .ok_or_else(refuse)?
        .iter()
        .filter(|row| row["path"] == "helper/aegis-device-egress-guard.sh")
        .collect();
    if shell_rows.len() != 1
        || guardian["observer_state"] != "absent"
        || guardian["selected_manager"] != source.selected_manager
        || site["selected_manager"] != source.selected_manager
        || source.original_state == "consumed"
            && (state != "new_exact" || shell_rows[0]["sha256"] != source.guard_shell_sha256)
    {
        return Err(refuse());
    }
    let mut raw = serde_json::to_vec(&guardian).map_err(|_| refuse())?;
    raw.push(b'\n');
    guard.revalidate(&install).map_err(|_| refuse())?;
    let after = installer_v2_generation::cold_stale_source_for_stage(root)?;
    if after.original_intent_sha256 != source.original_intent_sha256
        || after.prior_intent_sha256 != source.prior_intent_sha256
        || after.current_head_sha256 != source.current_head_sha256
        || after.current_intent_sha256 != source.current_intent_sha256
        || after.barrier_sha256 != source.barrier_sha256
        || after.prior_pointer_state != source.prior_pointer_state
    {
        return Err(refuse());
    }
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_cold_stale_preretire_v1",
        "current_boot_id": guardian["boot_id"],
        "prior_boot_id": source.prior_boot_id,
        "prior_intent_sha256": source.prior_intent_sha256,
        "original_intent_sha256": source.original_intent_sha256,
        "retained_root": source.retained_root,
        "new_candidate_sha256": source.bootstrap.candidate_sha256,
        "next_bundle_manifest_sha256": source.bootstrap.bundle_manifest_sha256,
        "next_sums_sha256": source.bootstrap.sums_sha256,
        "old_pointer_state": source.prior_pointer_state,
        "package_state": state,
        "deny_policy_sha256": guardian["policy_sha256"],
        "guard30_sha256": guardian["guard30_sha256"],
        "initial_denied_proof_sha256": digest(&raw),
        "initial_infrastructure_rows_sha256": guardian["infrastructure_rows_sha256"],
        "client_actors_absent": true,
        "jobs_absent": true,
        "cgroups_empty": true,
        "stop_intent_absent": true,
        "no_client_grant": true,
    }))
    .map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_cold_stale_inherited(
    install_fd: std::os::fd::RawFd,
    guard_fd: std::os::fd::RawFd,
    root: &Path,
    expected_prior_sha: &str,
) -> Result<Vec<u8>> {
    use crate::profile_auto_stopped_service::InheritedInstallReadLock;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(90);
    let install = InheritedInstallReadLock::admit(install_fd).map_err(|_| refuse())?;
    let guard = install
        .admit_guard_read_fd(guard_fd)
        .map_err(|_| refuse())?;
    let source = installer_v2_generation::cold_stale_source(root)?;
    if source.prior_intent_sha256 != expected_prior_sha {
        return Err(refuse());
    }
    let (guardian, package, site) =
        cold_stale_double_observation(&install, &guard, root, &source, deadline)?;
    let retirement_sha =
        installer_v2_generation::cold_prior_retirement_receipt(&source, &guardian)?;
    let result = cold_stale_projection(&source, &guardian, &package, &site, &retirement_sha)?;
    if installer_v2_generation::cold_prior_retirement_receipt(&source, &guardian)? != retirement_sha
    {
        return Err(refuse());
    }
    guard.revalidate(&install).map_err(|_| refuse())?;
    let final_source = installer_v2_generation::cold_stale_source(root)?;
    if final_source.prior_intent_sha256 != source.prior_intent_sha256
        || final_source.current_head_sha256 != source.current_head_sha256
        || final_source.current_intent_sha256 != source.current_intent_sha256
        || final_source.barrier_sha256 != source.barrier_sha256
    {
        return Err(refuse());
    }
    serde_json::to_vec(&result).map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_cold_attempt_inherited(
    install_fd: std::os::fd::RawFd,
    guard_fd: std::os::fd::RawFd,
    root: &Path,
) -> Result<Vec<u8>> {
    let before = installer_v2_generation::cold_stale_source(root)?;
    let stale_raw =
        verify_cold_stale_inherited(install_fd, guard_fd, root, &before.prior_intent_sha256)?;
    let stale: serde_json::Value = serde_json::from_slice(&stale_raw).map_err(|_| refuse())?;
    let after = installer_v2_generation::cold_stale_source(root)?;
    if before.original_intent_sha256 != after.original_intent_sha256
        || before.prior_intent_sha256 != after.prior_intent_sha256
        || before.prior_boot_id != after.prior_boot_id
        || before.current_head_sha256 != after.current_head_sha256
        || before.current_intent_sha256 != after.current_intent_sha256
        || before.barrier_sha256 != after.barrier_sha256
        || stale["prior_pointer_retirement_sha256"].as_str().is_none()
    {
        return Err(refuse());
    }
    let current_boot = stale["current_boot_id"].as_str().ok_or_else(refuse)?;
    let attempt_dir = format!(
        "/var/lib/aegis-install/client/terminal-migrations/cold-recovery/attempts/{current_boot}-{}",
        before.prior_intent_sha256);
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_cold_attempt_resolution_v1",
        "current_boot_id": current_boot,
        "original_intent_sha256": before.original_intent_sha256,
        "prior_intent_sha256": before.prior_intent_sha256,
        "barrier_sha256": before.barrier_sha256,
        "attempt_intent_sha256": before.current_intent_sha256,
        "attempt_head_sha256": before.current_head_sha256,
        "attempt_dir": attempt_dir,
        "prior_pointer_retirement_sha256": stale["prior_pointer_retirement_sha256"],
        "no_client_grant": true,
    }))
    .map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
fn cold_guardian_readback(
    install: &crate::profile_auto_stopped_service::InheritedInstallReadLock,
    guard: &crate::profile_auto_stopped_service::InheritedGuardReadFd,
    root: &Path,
    history: &installer_v2_generation::ColdRetiredHistory,
    deadline: std::time::Instant,
) -> Result<serde_json::Value> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    if std::time::Instant::now() >= deadline {
        return Err(refuse());
    }
    install.revalidate().map_err(|_| refuse())?;
    guard.revalidate(install).map_err(|_| refuse())?;
    let preexec = installer_v2_generation::cold_retired_history(root)?;
    if preexec.guardian_source_sha256 != history.guardian_source_sha256
        || preexec.observer_source_sha256 != history.observer_source_sha256
        || preexec.package_helper_sha256 != history.package_helper_sha256
        || preexec.successor_intent_sha256 != history.successor_intent_sha256
        || preexec.old_context_sha256 != history.old_context_sha256
        || preexec.cold_old_context_sha256 != history.cold_old_context_sha256
    {
        return Err(refuse());
    }
    let inherited_install = install.duplicate_held_fd().map_err(|_| refuse())?;
    let inherited_guard = guard.duplicate_for_child(install).map_err(|_| refuse())?;
    for fd in [inherited_install.as_raw_fd(), inherited_guard.as_raw_fd()] {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(refuse());
        }
    }
    let output_fd = unsafe { libc::memfd_create(c"aegis-cold-deny".as_ptr(), libc::MFD_CLOEXEC) };
    if output_fd < 0 {
        return Err(refuse());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(output_fd) };
    let held_script = cold_child_script(
        root,
        "aegis_auto_guardian.py",
        &history.guardian_source_sha256,
    )?;
    let source = format!("/proc/self/fd/{}", held_script.as_raw_fd());
    let mut child = Command::new("/usr/bin/python3")
        .arg("-I")
        .arg("-B")
        .arg(&source)
        .arg("cold-denied-readback")
        .arg(inherited_install.as_raw_fd().to_string())
        .arg(inherited_guard.as_raw_fd().to_string())
        .arg(root)
        .arg("--retained-source")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| refuse())?;
    let exit =
        crate::profile_auto_stopped_service::ChildExitWait::open(&child, Duration::from_millis(20));
    loop {
        if output.metadata().map_err(|_| refuse())?.len() > 8192
            || std::time::Instant::now() >= deadline
        {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse());
            }
            Ok(None) => exit.wait(&[], deadline),
        }
    }
    guard.revalidate(install).map_err(|_| refuse())?;
    output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
    let mut raw = Vec::new();
    output
        .take(8193)
        .read_to_end(&mut raw)
        .map_err(|_| refuse())?;
    if raw.is_empty() || raw.len() > 8192 {
        return Err(refuse());
    }
    cold_child_script_stable(
        &held_script,
        root,
        "aegis_auto_guardian.py",
        &history.guardian_source_sha256,
    )?;
    cold_canonical_child_json(&raw)
}

#[cfg(target_os = "linux")]
fn cold_package_readback(
    install: &crate::profile_auto_stopped_service::InheritedInstallReadLock,
    guard: &crate::profile_auto_stopped_service::InheritedGuardReadFd,
    history: &installer_v2_generation::ColdRetiredHistory,
    deadline: std::time::Instant,
) -> Result<serde_json::Value> {
    cold_package_readback_bound(
        install,
        guard,
        (&history.old_root, &history.retained_root),
        (&history.retained_root, "cold-package-readback"),
        &history.package_helper_sha256,
        deadline,
        || {
            let preexec =
                installer_v2_generation::cold_retired_history(Path::new(&history.retained_root))?;
            if preexec.package_helper_sha256 != history.package_helper_sha256
                || preexec.guardian_source_sha256 != history.guardian_source_sha256
                || preexec.observer_source_sha256 != history.observer_source_sha256
                || preexec.successor_intent_sha256 != history.successor_intent_sha256
                || preexec.old_context_sha256 != history.old_context_sha256
                || preexec.cold_old_context_sha256 != history.cold_old_context_sha256
            {
                return Err(refuse());
            }
            Ok(())
        },
    )
}

#[cfg(target_os = "linux")]
fn cold_stale_package_readback(
    install: &crate::profile_auto_stopped_service::InheritedInstallReadLock,
    guard: &crate::profile_auto_stopped_service::InheritedGuardReadFd,
    root: &Path,
    source: &installer_v2_generation::ColdStaleSource,
    deadline: std::time::Instant,
) -> Result<serde_json::Value> {
    cold_package_readback_bound(
        install,
        guard,
        (&source.old_root, root.to_str().ok_or_else(refuse)?),
        (root.to_str().ok_or_else(refuse)?, "cold-package-readback"),
        &source.package_helper_sha256,
        deadline,
        || {
            let after = installer_v2_generation::cold_stale_source_for_stage(root)?;
            if after.bootstrap.candidate_sha256 != source.bootstrap.candidate_sha256
                || after.prior_intent_sha256 != source.prior_intent_sha256
                || after.original_intent_sha256 != source.original_intent_sha256
                || after.package_helper_sha256 != source.package_helper_sha256
                || after.old_root != source.old_root
            {
                return Err(refuse());
            }
            Ok(())
        },
    )
}

#[cfg(target_os = "linux")]
fn cold_package_readback_bound(
    install: &crate::profile_auto_stopped_service::InheritedInstallReadLock,
    guard: &crate::profile_auto_stopped_service::InheritedGuardReadFd,
    roots: (&str, &str),
    script_source: (&str, &str),
    helper_sha: &str,
    deadline: std::time::Instant,
    preexec: impl Fn() -> Result<()>,
) -> Result<serde_json::Value> {
    let (old_root, retained_root) = roots;
    let (script_root, operation) = script_source;
    if !["cold-package-readback", "cold-archive-package-readback"].contains(&operation) {
        return Err(refuse());
    }
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    if std::time::Instant::now() >= deadline {
        return Err(refuse());
    }
    install.revalidate().map_err(|_| refuse())?;
    guard.revalidate(install).map_err(|_| refuse())?;
    preexec()?;
    let passed_install = install.duplicate_held_fd().map_err(|_| refuse())?;
    let passed_guard = guard.duplicate_for_child(install).map_err(|_| refuse())?;
    for fd in [passed_install.as_raw_fd(), passed_guard.as_raw_fd()] {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(refuse());
        }
    }
    let raw_fd = unsafe { libc::memfd_create(c"aegis-cold-package".as_ptr(), libc::MFD_CLOEXEC) };
    if raw_fd < 0 {
        return Err(refuse());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    let held_script = cold_child_script(
        Path::new(script_root),
        "aegis_installer_auto_v2.py",
        helper_sha,
    )?;
    let source = format!("/proc/self/fd/{}", held_script.as_raw_fd());
    let mut child = Command::new("/usr/bin/python3")
        .arg("-I")
        .arg("-B")
        .arg(source)
        .arg(operation)
        .arg("--old-root")
        .arg(old_root)
        .arg("--retained-root")
        .arg(retained_root)
        .arg("--install-fd")
        .arg(passed_install.as_raw_fd().to_string())
        .arg("--guard-fd")
        .arg(passed_guard.as_raw_fd().to_string())
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| refuse())?;
    let exit =
        crate::profile_auto_stopped_service::ChildExitWait::open(&child, Duration::from_millis(20));
    loop {
        if output.metadata().map_err(|_| refuse())?.len() > 65536
            || std::time::Instant::now() >= deadline
        {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse());
            }
            Ok(None) => exit.wait(&[], deadline),
        }
    }
    guard.revalidate(install).map_err(|_| refuse())?;
    output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
    let mut raw = Vec::new();
    output
        .take(65537)
        .read_to_end(&mut raw)
        .map_err(|_| refuse())?;
    if raw.is_empty() || raw.len() > 65536 {
        return Err(refuse());
    }
    cold_child_script_stable(
        &held_script,
        Path::new(script_root),
        "aegis_installer_auto_v2.py",
        helper_sha,
    )?;
    preexec()?;
    cold_canonical_child_json(&raw)
}

#[cfg(target_os = "linux")]
fn cold_site_readback(
    install: &crate::profile_auto_stopped_service::InheritedInstallReadLock,
    guard: &crate::profile_auto_stopped_service::InheritedGuardReadFd,
    history: &installer_v2_generation::ColdRetiredHistory,
    deadline: std::time::Instant,
) -> Result<serde_json::Value> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    if std::time::Instant::now() >= deadline {
        return Err(refuse());
    }
    install.revalidate().map_err(|_| refuse())?;
    guard.revalidate(install).map_err(|_| refuse())?;
    let preexec = installer_v2_generation::cold_retired_history(Path::new(&history.retained_root))?;
    if preexec.site_helper_sha256 != history.site_helper_sha256
        || preexec.successor_intent_sha256 != history.successor_intent_sha256
        || preexec.old_context_sha256 != history.old_context_sha256
        || preexec.cold_old_context_sha256 != history.cold_old_context_sha256
        || preexec.migration_state != history.migration_state
        || preexec.context_state != history.context_state
        || preexec.cold_context_state != history.cold_context_state
    {
        return Err(refuse());
    }
    let install_fd = install.duplicate_held_fd().map_err(|_| refuse())?;
    let guard_fd = guard.duplicate_for_child(install).map_err(|_| refuse())?;
    for fd in [install_fd.as_raw_fd(), guard_fd.as_raw_fd()] {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(refuse());
        }
    }
    let fd = unsafe { libc::memfd_create(c"aegis-cold-site".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(refuse());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(fd) };
    let held_script = cold_child_script(
        Path::new(&history.retained_root),
        "aegis_auto_terminal_register.py",
        &history.site_helper_sha256,
    )?;
    let source = format!("/proc/self/fd/{}", held_script.as_raw_fd());
    let old_context = history.old_context_sha256.as_deref().unwrap_or("none");
    let mut child = Command::new("/usr/bin/python3")
        .arg("-I")
        .arg("-B")
        .arg(&source)
        .arg("cold-site-readback")
        .arg(install_fd.as_raw_fd().to_string())
        .arg(guard_fd.as_raw_fd().to_string())
        .arg(&history.retained_root)
        .arg(old_context)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| refuse())?;
    let exit =
        crate::profile_auto_stopped_service::ChildExitWait::open(&child, Duration::from_millis(20));
    loop {
        if output.metadata().map_err(|_| refuse())?.len() > 8192
            || std::time::Instant::now() >= deadline
        {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse());
            }
            Ok(None) => exit.wait(&[], deadline),
        }
    }
    guard.revalidate(install).map_err(|_| refuse())?;
    output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
    let mut raw = Vec::new();
    output
        .take(8193)
        .read_to_end(&mut raw)
        .map_err(|_| refuse())?;
    if raw.is_empty() || raw.len() > 8192 {
        return Err(refuse());
    }
    cold_child_script_stable(
        &held_script,
        Path::new(&history.retained_root),
        "aegis_auto_terminal_register.py",
        &history.site_helper_sha256,
    )?;
    cold_canonical_child_json(&raw)
}

#[cfg(target_os = "linux")]
fn validate_cold_guardian_readback(
    value: &serde_json::Value,
    history: &installer_v2_generation::ColdRetiredHistory,
) -> Result<()> {
    let object = value.as_object().ok_or_else(refuse)?;
    let keys = [
        "schema",
        "boot_id",
        "selected_manager",
        "guard30_sha256",
        "manager31_sha256",
        "guardian31_sha256",
        "state_sha256",
        "policy_sha256",
        "manager_binding_sha256",
        "observer_state",
        "observer_source_sha256",
        "observer_ready_sha256",
        "infrastructure_rows",
        "infrastructure_rows_sha256",
        "infrastructure_qualified",
        "infrastructure_quiescent",
        "quiesce_state",
        "quiesce_receipt_sha256",
        "quiesce_monotonic_tick",
        "package_repair_receipt_sha256",
        "package_repaired_tick",
        "client_actors_absent",
        "jobs_absent",
        "cgroups_empty",
        "stop_intent_absent",
    ];
    let hex = |value: &serde_json::Value| {
        value.as_str().is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    };
    let optional_hex = |value: &serde_json::Value| value.is_null() || hex(value);
    if object.len() != keys.len()
        || keys.iter().any(|key| !object.contains_key(*key))
        || value["schema"] != "aegis_auto_guard_cold_denied_readback_v2"
        || value["boot_id"] != history.current_boot_id
        || !["NetworkManager.service", "systemd-networkd.service"]
            .contains(&value["selected_manager"].as_str().ok_or_else(refuse)?)
        || [
            "infrastructure_qualified",
            "client_actors_absent",
            "jobs_absent",
            "cgroups_empty",
            "stop_intent_absent",
        ]
        .iter()
        .any(|key| value[*key] != true)
        || [
            "guard30_sha256",
            "state_sha256",
            "policy_sha256",
            "infrastructure_rows_sha256",
        ]
        .iter()
        .any(|key| !hex(&value[*key]))
        || [
            "manager31_sha256",
            "guardian31_sha256",
            "manager_binding_sha256",
        ]
        .iter()
        .any(|key| !optional_hex(&value[*key]))
        || !["absent", "b_ready"].contains(&value["observer_state"].as_str().ok_or_else(refuse)?)
        || !["pre", "post"].contains(&value["quiesce_state"].as_str().ok_or_else(refuse)?)
        || !value["infrastructure_quiescent"].is_boolean()
    {
        return Err(refuse());
    }
    if value["observer_state"] == "absent" {
        if !value["observer_source_sha256"].is_null() || !value["observer_ready_sha256"].is_null() {
            return Err(refuse());
        }
    } else if value["observer_source_sha256"] != history.observer_source_sha256
        || !hex(&value["observer_ready_sha256"])
    {
        return Err(refuse());
    }
    if value["quiesce_state"] == "pre" {
        if !value["quiesce_receipt_sha256"].is_null() || !value["quiesce_monotonic_tick"].is_null()
        {
            return Err(refuse());
        }
    } else if !hex(&value["quiesce_receipt_sha256"])
        || value["quiesce_monotonic_tick"]
            .as_u64()
            .is_none_or(|tick| tick == 0)
    {
        return Err(refuse());
    }
    if value["package_repair_receipt_sha256"].is_null() {
        if !value["package_repaired_tick"].is_null() {
            return Err(refuse());
        }
    } else if !hex(&value["package_repair_receipt_sha256"])
        || value["package_repaired_tick"]
            .as_u64()
            .is_none_or(|tick| tick == 0)
    {
        return Err(refuse());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_cold_site_readback(
    value: &serde_json::Value,
    history: &installer_v2_generation::ColdRetiredHistory,
) -> Result<()> {
    let object = value.as_object().ok_or_else(refuse)?;
    let keys = [
        "schema",
        "boot_id",
        "site_state",
        "context_state",
        "source_config_sha256",
        "store_config_sha256",
        "active_hook_sha256",
        "configure_intent_sha256",
        "configured_sha256",
        "manager31_sha256",
        "guardian31_sha256",
        "old_context_sha256",
        "cold_old_context_sha256",
        "cold_context_state",
        "old_observer_archive_sha256",
        "next_bundle_manifest_sha256",
        "next_sums_sha256",
    ];
    let hex = |value: &serde_json::Value| {
        value.as_str().is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    };
    let optional_hex = |value: &serde_json::Value| value.is_null() || hex(value);
    if object.len() != keys.len()
        || keys.iter().any(|key| !object.contains_key(*key))
        || value["schema"] != "aegis_auto_terminal_cold_site_readback_v1"
        || value["boot_id"] != history.current_boot_id
        || value["context_state"] != history.context_state
        || value["old_context_sha256"].as_str() != history.old_context_sha256.as_deref()
        || value["cold_old_context_sha256"].as_str() != history.cold_old_context_sha256.as_deref()
        || value["cold_context_state"] != history.cold_context_state
        || value["old_observer_archive_sha256"].as_str()
            != history.old_observer_archive_sha256.as_deref()
        || value["next_bundle_manifest_sha256"] != history.bundle_manifest_sha256
        || value["next_sums_sha256"] != history.sums_sha256
        || ![
            "a_exact",
            "a_retiring_prefix",
            "absent",
            "b_prefix",
            "b_complete",
        ]
        .contains(&value["site_state"].as_str().ok_or_else(refuse)?)
        || [
            "source_config_sha256",
            "store_config_sha256",
            "active_hook_sha256",
            "configure_intent_sha256",
            "configured_sha256",
            "manager31_sha256",
            "guardian31_sha256",
        ]
        .iter()
        .any(|key| !optional_hex(&value[*key]))
    {
        return Err(refuse());
    }
    match history.migration_state {
        "preparation_absent" => {
            if history.old_observer_archive_sha256.is_some()
                || history.old_context_sha256.is_some()
                || history.context_state != "absent_not_prepared"
                || (history.cold_context_state == "absent_not_prepared"
                    && (value["site_state"] != "a_exact"
                        || history.cold_old_context_sha256.is_some()))
                || (history.cold_context_state == "missing_reconstructible"
                    && (value["site_state"] != "a_exact"
                        || history.cold_old_context_sha256.is_none()))
                || (history.cold_context_state == "present_exact"
                    && history.cold_old_context_sha256.is_none())
            {
                return Err(refuse());
            }
        }
        "pending_prefix" => {
            if history.cold_old_context_sha256.is_some()
                || history.cold_context_state != "absent_not_prepared"
                || history.context_state == "missing_reconstructible"
                    && (value["site_state"] != "a_exact"
                        || history.old_observer_archive_sha256.is_some())
            {
                return Err(refuse());
            }
        }
        "completed_edge" => {
            if history.cold_old_context_sha256.is_some()
                || history.cold_context_state != "absent_not_prepared"
                || history.context_state != "present_exact"
                || history.old_observer_archive_sha256.is_none()
            {
                return Err(refuse());
            }
        }
        _ => return Err(refuse()),
    }
    if value["site_state"] == "b_complete"
        && (!hex(&value["source_config_sha256"])
            || !hex(&value["store_config_sha256"])
            || !hex(&value["active_hook_sha256"])
            || !hex(&value["configure_intent_sha256"])
            || !hex(&value["configured_sha256"])
            || !hex(&value["manager31_sha256"])
            || !hex(&value["guardian31_sha256"]))
    {
        return Err(refuse());
    }
    if value["site_state"] == "a_exact"
        && value["source_config_sha256"] != history.old_source_sha256
    {
        return Err(refuse());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_cold_package_readback(
    value: &serde_json::Value,
    history: &installer_v2_generation::ColdRetiredHistory,
) -> Result<()> {
    validate_cold_package_readback_bound(
        value,
        (&history.old_root, &history.retained_root),
        (&history.old_candidate_sha256, &history.new_candidate_sha256),
        &history.old_install_sha256,
        &history.new_package_sha256,
        || installer_v2_generation::cold_package_sources(history, value),
    )
}

#[cfg(target_os = "linux")]
fn validate_cold_stale_package_readback(
    value: &serde_json::Value,
    source: &installer_v2_generation::ColdStaleSource,
) -> Result<()> {
    validate_cold_package_readback_bound(
        value,
        (&source.old_root, &source.retained_root),
        (
            &source.old_candidate_sha256,
            &source.bootstrap.candidate_sha256,
        ),
        &source.old_install_sha256,
        &source.new_package_sha256,
        || installer_v2_generation::cold_stale_package_sources(source, value),
    )
}

#[cfg(target_os = "linux")]
fn validate_cold_package_readback_bound(
    value: &serde_json::Value,
    roots: (&str, &str),
    candidates: (&str, &str),
    old_install_sha: &str,
    new_package_sha: &str,
    source_admit: impl Fn() -> Result<()>,
) -> Result<()> {
    let (old_root, retained_root) = roots;
    let (old_candidate_sha, new_candidate_sha) = candidates;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let object = value.as_object().ok_or_else(refuse)?;
    let keys = [
        "schema",
        "boot_id",
        "old_root",
        "new_root",
        "old_package_sha256",
        "new_package_sha256",
        "dpkg_status",
        "dpkg_version",
        "dpkg_arch",
        "installed_elf_sha256",
        "installed_source_sha256",
        "roster_sha256",
        "roster",
        "package_state",
    ];
    if object.len() != keys.len()
        || keys.iter().any(|key| !object.contains_key(*key))
        || value["schema"] != "aegis_auto_v2_cold_package_readback_v1"
        || value["boot_id"]
            != std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| refuse())?
                .trim_end_matches('\n')
        || value["old_root"] != old_root
        || value["new_root"] != retained_root
        || value["new_package_sha256"] != new_package_sha
        || !["old_exact", "new_exact", "known_interrupted"]
            .contains(&value["package_state"].as_str().ok_or_else(refuse)?)
    {
        return Err(refuse());
    }
    let roster = value["roster"].as_array().ok_or_else(refuse)?;
    if roster.is_empty() || roster.len() > 256 {
        return Err(refuse());
    }
    let mut names = std::collections::HashSet::new();
    for row in roster {
        let item = row.as_object().ok_or_else(refuse)?;
        if item.len() != 4
            || ["path", "mode", "sha256", "relation"]
                .iter()
                .any(|key| !item.contains_key(*key))
        {
            return Err(refuse());
        }
        let path = row["path"].as_str().ok_or_else(refuse)?;
        if path.len() > 192
            || !(path.starts_with("helper/") || path.starts_with("unit/"))
            || path.contains("..")
            || !names.insert(path)
        {
            return Err(refuse());
        }
        let relation = row["relation"].as_str().ok_or_else(refuse)?;
        if !["old", "new", "both", "absent"].contains(&relation) {
            return Err(refuse());
        }
        if relation == "absent" {
            if !row["mode"].is_null() || !row["sha256"].is_null() {
                return Err(refuse());
            }
        } else if ![0o500, 0o644, 0o755].contains(&row["mode"].as_u64().ok_or_else(refuse)?)
            || row["sha256"].as_str().is_none_or(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
        {
            return Err(refuse());
        }
    }
    let mut encoded = serde_json::to_vec(roster).map_err(|_| refuse())?;
    encoded.push(b'\n');
    if value["roster_sha256"] != digest(&encoded) {
        return Err(refuse());
    }
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let (current, current_worker) =
        if recovery_absent(guardian.as_raw_fd(), "auto-guardian-install.json").is_ok() {
            (None, None)
        } else {
            let raw = recovery_open_at(
                guardian.as_raw_fd(),
                "auto-guardian-install.json",
                libc::O_RDONLY,
                0,
            )?;
            let stat = recovery_stat(raw.as_raw_fd())?;
            if stat.st_mode != libc::S_IFREG | 0o600
                || stat.st_uid != 0
                || stat.st_gid != 0
                || stat.st_nlink != 1
                || stat.st_size <= 0
                || stat.st_size > 1 << 20
            {
                return Err(refuse());
            }
            let mut bytes = Vec::new();
            std::fs::File::from(raw)
                .take((1 << 20) + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| refuse())?;
            if bytes.is_empty() || bytes.len() > 1 << 20 {
                return Err(refuse());
            }
            let record: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
            let worker = record["worker_sha256"].as_str().ok_or_else(refuse)?;
            if worker != old_candidate_sha && worker != new_candidate_sha {
                return Err(refuse());
            }
            (Some(digest(&bytes)), Some(worker.to_owned()))
        };
    if value["installed_source_sha256"].as_str() != current.as_deref() {
        return Err(refuse());
    }
    let state = value["package_state"].as_str().ok_or_else(refuse)?;
    let elf = value["installed_elf_sha256"].as_str();
    let source = current.as_deref();
    if state == "old_exact" {
        if elf != Some(old_candidate_sha)
            || source != Some(old_install_sha)
            || current_worker.as_deref() != Some(old_candidate_sha)
            || value["dpkg_status"] != "install ok installed"
            || roster
                .iter()
                .any(|row| !["old", "both"].contains(&row["relation"].as_str().unwrap_or("")))
        {
            return Err(refuse());
        }
    } else if state == "new_exact" {
        if elf != Some(new_candidate_sha)
            || source.is_none()
            || current_worker.as_deref() != Some(new_candidate_sha)
            || value["dpkg_status"] != "install ok installed"
            || roster
                .iter()
                .any(|row| !["new", "both"].contains(&row["relation"].as_str().unwrap_or("")))
        {
            return Err(refuse());
        }
    } else if ![
        "install ok unpacked",
        "install ok half-configured",
        "install ok triggers-pending",
        "install ok triggers-awaited",
    ]
    .contains(&value["dpkg_status"].as_str().ok_or_else(refuse)?)
        || elf.is_some_and(|sha| sha != old_candidate_sha && sha != new_candidate_sha)
        || current_worker
            .as_deref()
            .is_some_and(|sha| sha != old_candidate_sha && sha != new_candidate_sha)
    {
        return Err(refuse());
    }
    source_admit()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_cold_infrastructure_rows(
    guardian: &serde_json::Value,
    package: &serde_json::Value,
) -> Result<()> {
    let rows = guardian["infrastructure_rows"]
        .as_array()
        .ok_or_else(refuse)?;
    let roster = package["roster"].as_array().ok_or_else(refuse)?;
    let expected = [
        (
            "aegis-foreign-policy-monitor.service",
            "aegis_auto_foreign_monitor.py",
        ),
        ("aegis-auto-guardian.service", "aegis_auto_guardian.py"),
        (
            "aegis-auto-guardian-watchdog.service",
            "aegis_auto_guardian_watchdog.py",
        ),
        (
            "aegis-auto-witness-topology.service",
            "aegis_auto_witness_topology.py",
        ),
        (
            "aegis-auto-capture-topology.service",
            "aegis_auto_capture_topology.py",
        ),
        (
            "aegis-auto-trace-rollback-actor.service",
            "aegis_auto_trace_rollback.py",
        ),
    ];
    if rows.len() != expected.len() {
        return Err(refuse());
    }
    let hex = |value: &serde_json::Value, n: usize| {
        value.as_str().is_some_and(|s| {
            s.len() == n
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    };
    let mut canonical = Vec::<std::collections::BTreeMap<String, serde_json::Value>>::new();
    let mut quiescent = true;
    for (row, (unit, helper)) in rows.iter().zip(expected) {
        let object = row.as_object().ok_or_else(refuse)?;
        let keys = [
            "unit",
            "active",
            "main_pid",
            "invocation_id",
            "start_tick",
            "source_sha256",
            "unit_sha256",
            "control_group",
        ];
        if object.len() != keys.len()
            || keys.iter().any(|key| !object.contains_key(*key))
            || row["unit"] != unit
        {
            return Err(refuse());
        }
        let active = row["active"].as_bool().ok_or_else(refuse)?;
        let pid = row["main_pid"].as_u64().ok_or_else(refuse)?;
        let group = row["control_group"].as_str().ok_or_else(refuse)?;
        if active {
            quiescent = false;
            if pid <= 1
                || !hex(&row["invocation_id"], 32)
                || row["start_tick"].as_u64().is_none_or(|v| v == 0)
                || group != format!("/system.slice/{unit}")
                || !hex(&row["source_sha256"], 64)
                || !hex(&row["unit_sha256"], 64)
            {
                return Err(refuse());
            }
        } else if pid != 0
            || !row["invocation_id"].is_null()
            || !row["start_tick"].is_null()
            || !(group.is_empty() || group == format!("/system.slice/{unit}"))
        {
            return Err(refuse());
        }
        for (path, sha) in [
            (format!("helper/lib/{helper}"), &row["source_sha256"]),
            (format!("unit/{unit}"), &row["unit_sha256"]),
        ] {
            let matches: Vec<_> = roster.iter().filter(|item| item["path"] == path).collect();
            if matches.len() != 1 || &matches[0]["sha256"] != sha {
                return Err(refuse());
            }
            if active {
                let relation = matches[0]["relation"].as_str().ok_or_else(refuse)?;
                let allowed = match package["package_state"].as_str().ok_or_else(refuse)? {
                    "old_exact" => ["old", "both"].contains(&relation),
                    "new_exact" | "known_interrupted" => ["new", "both"].contains(&relation),
                    _ => false,
                };
                if !allowed {
                    return Err(refuse());
                }
            }
        }
        canonical.push(
            object
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
    }
    let mut encoded = serde_json::to_vec(&canonical).map_err(|_| refuse())?;
    encoded.push(b'\n');
    if guardian["infrastructure_rows_sha256"] != digest(&encoded)
        || guardian["infrastructure_quiescent"] != quiescent
    {
        return Err(refuse());
    }
    Ok(())
}

/// Read-only cold upgrade boundary. An archived old generation is evidence,
/// never a clean BOOT receipt or permission to Start a client or manager.
/// Read-only cold upgrade boundary. An archived old generation is evidence,
/// never a clean BOOT receipt or permission to Start a client or manager.
/// Read-only cold upgrade boundary. An archived old generation is evidence,
/// never a clean BOOT receipt or permission to Start a client or manager.
#[cfg(target_os = "linux")]
fn cold_archive_hex_name(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|tail| tail.strip_suffix(".json"))
        .is_some_and(|sha| {
            sha.len() == 64
                && sha
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
}

#[cfg(target_os = "linux")]
fn cold_archive_boot_hex_name(name: &str, prefix: &str) -> bool {
    let Some(tail) = name
        .strip_prefix(prefix)
        .and_then(|tail| tail.strip_suffix(".json"))
    else {
        return false;
    };
    if tail.len() != 101 || tail.as_bytes()[36] != b'-' {
        return false;
    }
    let (boot, sha) = tail.split_at(36);
    let sha = &sha[1..];
    boot.bytes().enumerate().all(|(i, b)| {
        if [8, 13, 18, 23].contains(&i) {
            b == b'-'
        } else {
            b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
        }
    }) && sha.len() == 64
        && sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(target_os = "linux")]
fn cold_archive_leaf_allowed(name: &str, role: u8) -> bool {
    const PHASE: [&str; 10] = [
        "intent.json",
        "phase-00.json",
        "phase-01.json",
        "phase-02.json",
        "phase-03.json",
        "phase-04.json",
        "phase-05.json",
        "cold-denied-prebind.json",
        "cold-config-intent.json",
        "transition-ready.json",
    ];
    if role == 2 {
        return name == "intent.json";
    }
    if PHASE.contains(&name)
        || cold_archive_hex_name(name, "intent-consumed-")
        || cold_archive_hex_name(name, "pending-consumed-")
    {
        return true;
    }
    if role == 1 {
        return false;
    }
    name == "rollover-barrier.json"
        || cold_archive_hex_name(name, "cold-old-context-")
        || cold_archive_hex_name(name, "rollover-barrier-consumed-")
        || cold_archive_hex_name(name, "barrier-bound-")
        || cold_archive_hex_name(name, "prior-pointer-retire-intent-")
        || cold_archive_hex_name(name, "prior-pointer-retired-")
        || cold_archive_boot_hex_name(name, "prior-pointer-retired-")
        || cold_archive_boot_hex_name(name, "attempt-head-")
        || cold_archive_boot_hex_name(name, "stage-retirement-")
}

#[cfg(target_os = "linux")]
fn cold_archive_dir_names(fd: std::os::fd::RawFd, maximum: usize) -> Result<Vec<String>> {
    let before = recovery_stat(fd)?;
    if before.st_mode != libc::S_IFDIR | 0o700 || before.st_uid != 0 || before.st_gid != 0 {
        return Err(refuse());
    }
    let path = format!("/proc/self/fd/{fd}");
    let mut names = Vec::new();
    for entry in std::fs::read_dir(path).map_err(|_| refuse())? {
        let name = entry
            .map_err(|_| refuse())?
            .file_name()
            .into_string()
            .map_err(|_| refuse())?;
        if name.is_empty()
            || name.len() > 200
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
    let after = recovery_stat(fd)?;
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
    ) {
        return Err(refuse());
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn cold_archive_row(
    parent: std::os::fd::RawFd,
    name: &str,
    logical: &str,
    is_dir: bool,
) -> Result<(serde_json::Value, std::os::fd::OwnedFd)> {
    use std::os::fd::AsRawFd;
    let fd = recovery_open_at(
        parent,
        name,
        libc::O_RDONLY | if is_dir { libc::O_DIRECTORY } else { 0 },
        0,
    )?;
    let before = recovery_stat(fd.as_raw_fd())?;
    if before.st_uid != 0
        || before.st_gid != 0
        || (is_dir && before.st_mode != libc::S_IFDIR | 0o700)
        || (!is_dir
            && (before.st_mode != libc::S_IFREG | 0o600
                || before.st_nlink != 1
                || before.st_size <= 0
                || before.st_size > 1 << 20))
    {
        return Err(refuse());
    }
    let (size, sha) = if is_dir {
        (serde_json::Value::Null, serde_json::Value::Null)
    } else {
        let (size, sha) = recovery_file_hash(fd.as_raw_fd(), 1 << 20)?;
        (serde_json::json!(size), serde_json::json!(sha))
    };
    let current = recovery_open_at(
        parent,
        name,
        libc::O_RDONLY | if is_dir { libc::O_DIRECTORY } else { 0 },
        0,
    )?;
    let after = recovery_stat(current.as_raw_fd())?;
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_nlink,
        before.st_size,
        before.st_mtime,
        before.st_mtime_nsec,
        before.st_ctime,
        before.st_ctime_nsec,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
        after.st_size,
        after.st_mtime,
        after.st_mtime_nsec,
        after.st_ctime,
        after.st_ctime_nsec,
    ) {
        return Err(refuse());
    }
    Ok((
        serde_json::json!({"path":logical,"kind":if is_dir {"dir"} else {"file"},
        "mode":before.st_mode & 0o7777,"uid":before.st_uid,"gid":before.st_gid,
        "nlink":before.st_nlink,"size":size,"sha256":sha}),
        fd,
    ))
}

#[cfg(target_os = "linux")]
fn cold_archive_walk(
    dir: std::os::fd::RawFd,
    logical: &str,
    role: u8,
    rows: &mut Vec<serde_json::Value>,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    for name in cold_archive_dir_names(dir, 512)? {
        let child_role = if role == 0 && name == "attempts" {
            Some(3)
        } else if role == 0
            && name.starts_with("stage-retired-")
            && cold_archive_boot_hex_name(
                &format!("stage-retirement-{}.json", &name["stage-retired-".len()..]),
                "stage-retirement-",
            )
        {
            Some(2)
        } else if role == 3
            && cold_archive_boot_hex_name(&format!("attempt-head-{name}.json"), "attempt-head-")
        {
            Some(1)
        } else {
            None
        };
        let path = format!("{logical}/{name}");
        if let Some(next) = child_role {
            let (row, child) = cold_archive_row(dir, &name, &path, true)?;
            rows.push(row);
            cold_archive_walk(child.as_raw_fd(), &path, next, rows)?;
        } else {
            if role == 3 || !cold_archive_leaf_allowed(&name, role) {
                return Err(refuse());
            }
            let (row, _) = cold_archive_row(dir, &name, &path, false)?;
            rows.push(row);
        }
        if rows.len() > 512 {
            return Err(refuse());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cold_archive_present(parent: std::os::fd::RawFd, name: &str) -> Result<bool> {
    let name = std::ffi::CString::new(name).map_err(|_| refuse())?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let status = unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status == 0 {
        Ok(true)
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(refuse())
    }
}

#[cfg(target_os = "linux")]
fn cold_archive_members(pending_sha: &str) -> Result<(String, bool, Vec<serde_json::Value>)> {
    use std::os::fd::AsRawFd;
    if pending_sha.len() != 64
        || !pending_sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    let client = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let migration = recovery_directory(client.as_raw_fd(), "terminal-migrations", Some(0o700))?;
    let archive_name = format!("terminal-cold-history-{pending_sha}");
    let archive = if !cold_archive_present(client.as_raw_fd(), &archive_name)? {
        None
    } else {
        Some(recovery_directory(
            client.as_raw_fd(),
            &archive_name,
            Some(0o700),
        )?)
    };
    let live = cold_archive_present(migration.as_raw_fd(), "cold-recovery")?;
    let archived = if let Some(dir) = archive.as_ref() {
        cold_archive_present(dir.as_raw_fd(), "cold-recovery")?
    } else {
        false
    };
    if live && archived {
        return Err(refuse());
    }
    if let Some(dir) = archive.as_ref() {
        let names = cold_archive_dir_names(dir.as_raw_fd(), 8)?;
        if names.iter().any(|name| {
            ![
                "archive-intent.json",
                "archive-complete.json",
                "cold-recovery",
                "preseal",
            ]
            .contains(&name.as_str())
        }) || names.contains(&"archive-complete.json".to_owned()) && live
        {
            return Err(refuse());
        }
    }
    let complete = if let Some(dir) = archive.as_ref() {
        cold_archive_present(dir.as_raw_fd(), "archive-complete.json")?
    } else {
        false
    };
    let intent = if let Some(dir) = archive.as_ref() {
        cold_archive_present(dir.as_raw_fd(), "archive-intent.json")?
    } else {
        false
    };
    if complete && !intent || archived && !intent {
        return Err(refuse());
    }
    let mut rows = Vec::new();
    if live || archived {
        let parent = if live {
            migration.as_raw_fd()
        } else {
            archive.as_ref().ok_or_else(refuse)?.as_raw_fd()
        };
        let (root_row, cold) = cold_archive_row(
            parent,
            "cold-recovery",
            "terminal-migrations/cold-recovery",
            true,
        )?;
        rows.push(root_row);
        cold_archive_walk(
            cold.as_raw_fd(),
            "terminal-migrations/cold-recovery",
            0,
            &mut rows,
        )?;
    }
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut live_preseal = 0usize;
    let mut archived_preseal = 0usize;
    let mut collect = |dir: std::os::fd::RawFd, archived: bool| -> Result<()> {
        for name in cold_archive_dir_names(dir, 512)? {
            if !name.starts_with("auto-terminal-activation-preseal-") {
                continue;
            }
            if !cold_archive_hex_name(&name, "auto-terminal-activation-preseal-")
                || !seen.insert(name.clone())
            {
                return Err(refuse());
            }
            let (row, _) = cold_archive_row(dir, &name, &name, false)?;
            rows.push(row);
            if archived {
                archived_preseal += 1;
            } else {
                live_preseal += 1;
            }
        }
        Ok(())
    };
    collect(client.as_raw_fd(), false)?;
    let mut preseal_dir_present = false;
    if let Some(dir) = archive.as_ref() {
        if cold_archive_present(dir.as_raw_fd(), "preseal")? {
            preseal_dir_present = true;
            let preseal = recovery_directory(dir.as_raw_fd(), "preseal", Some(0o700))?;
            for name in cold_archive_dir_names(preseal.as_raw_fd(), 512)? {
                if !cold_archive_hex_name(&name, "auto-terminal-activation-preseal-")
                    || !seen.insert(name.clone())
                {
                    return Err(refuse());
                }
                let (row, _) = cold_archive_row(preseal.as_raw_fd(), &name, &name, false)?;
                rows.push(row);
                archived_preseal += 1;
            }
        }
    }
    if (archived || preseal_dir_present) && !intent {
        return Err(refuse());
    }
    if complete && preseal_dir_present != (archived_preseal > 0) {
        return Err(refuse());
    }
    if complete && (live || live_preseal > 0) {
        return Err(refuse());
    }
    let state = if complete {
        "complete"
    } else if archived || archived_preseal > 0 {
        "archived_prefix"
    } else {
        "source"
    };
    if rows.len() > 512 {
        return Err(refuse());
    }
    rows.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    if rows
        .windows(2)
        .any(|pair| pair[0]["path"] == pair[1]["path"])
        || rows
            .iter()
            .filter_map(|row| row["size"].as_u64())
            .try_fold(0u64, |sum, size| sum.checked_add(size))
            .is_none_or(|total| total > 16 << 20)
    {
        return Err(refuse());
    }
    Ok((state.to_owned(), live || archived, rows))
}

#[cfg(target_os = "linux")]
fn cold_archive_read_bytes(
    parent: std::os::fd::RawFd,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let held = recovery_open_at(parent, name, libc::O_RDONLY, 0)?;
    let before = recovery_stat(held.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o600
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as usize > maximum
    {
        return Err(refuse());
    }
    let (size, _) = recovery_file_hash(held.as_raw_fd(), maximum as u64)?;
    if unsafe { libc::lseek(held.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
        return Err(refuse());
    }
    let mut file = std::fs::File::from(held);
    let mut raw = Vec::new();
    file.by_ref()
        .take((maximum + 1) as u64)
        .read_to_end(&mut raw)
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
    if raw.len() != size as usize
        || identity(&before) != identity(&after)
        || identity(&before) != identity(&current)
    {
        return Err(refuse());
    }
    Ok(raw)
}

#[cfg(target_os = "linux")]
fn cold_archive_manifest_sha(rows: &[serde_json::Value]) -> Result<String> {
    let mut raw = serde_json::to_vec(rows).map_err(|_| refuse())?;
    raw.push(b'\n');
    if raw.len() > 4 << 20 {
        return Err(refuse());
    }
    Ok(digest(&raw))
}

#[cfg(target_os = "linux")]
fn cold_archive_preseal_row(raw: &[u8], token: &str) -> Result<()> {
    let row = cold_canonical_child_json(raw)?;
    let keys = [
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
    ];
    let object = row.as_object().ok_or_else(refuse)?;
    let unit = format!("aegis-auto@{token}.service");
    let hex = |key: &str, len: usize| {
        row[key].as_str().is_some_and(|value| {
            value.len() == len
                && value
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    };
    if object.len() != keys.len()
        || keys.iter().any(|key| !object.contains_key(*key))
        || row["schema"] != "aegis_auto_terminal_activation_preseal_v1"
        || !row["boot_id"].as_str().is_some_and(|boot| {
            boot.len() == 36
                && boot.bytes().enumerate().all(|(index, byte)| {
                    if [8, 13, 18, 23].contains(&index) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                    }
                })
        })
        || row["unit"] != unit
        || !hex("source_sha256", 64)
        || !hex("nonce", 32)
        || !hex("terminal_sha256", 64)
        || !hex("installed_generation_sha256", 64)
        || !hex("installed_manifest_sha256", 64)
        || row["stage_dev"].as_u64().is_none()
        || row["stage_ino"].as_u64().is_none()
        || !row["stage_path"].as_str().is_some_and(|path| {
            path.starts_with("/run/aegis-installer-config-snapshots/")
                && !path.contains("/../")
                && !path.ends_with("/..")
        })
    {
        return Err(refuse());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
type ColdArchiveReceiptPair = (Option<Vec<u8>>, Option<Vec<u8>>);

#[cfg(target_os = "linux")]
fn cold_archive_receipts(
    pending_sha: &str,
    boot_id: &str,
    source_sha: &str,
    manifest_sha: &str,
    deny_sha: &str,
    state: &str,
) -> Result<ColdArchiveReceiptPair> {
    use std::os::fd::AsRawFd;
    let client = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let archive_name = format!("terminal-cold-history-{pending_sha}");
    if !cold_archive_present(client.as_raw_fd(), &archive_name)? {
        if state != "source" {
            return Err(refuse());
        }
        return Ok((None, None));
    }
    let archive = recovery_directory(client.as_raw_fd(), &archive_name, Some(0o700))?;
    let intent = if cold_archive_present(archive.as_raw_fd(), "archive-intent.json")? {
        let raw = cold_archive_read_bytes(archive.as_raw_fd(), "archive-intent.json", 4096)?;
        let row = cold_canonical_child_json(&raw)?;
        let keys = [
            "schema",
            "boot_id",
            "ordinary_pending_sha256",
            "old_source_sha256",
            "member_manifest_sha256",
            "deny_policy_sha256",
            "no_client_grant",
        ];
        let object = row.as_object().ok_or_else(refuse)?;
        if object.len() != keys.len()
            || keys.iter().any(|key| !object.contains_key(*key))
            || row["schema"] != "aegis_auto_terminal_cold_archive_intent_v1"
            || row["boot_id"] != boot_id
            || row["ordinary_pending_sha256"] != pending_sha
            || row["old_source_sha256"] != source_sha
            || row["member_manifest_sha256"] != manifest_sha
            || row["deny_policy_sha256"] != deny_sha
            || row["no_client_grant"] != true
        {
            return Err(refuse());
        }
        Some(raw)
    } else {
        None
    };
    let complete = if cold_archive_present(archive.as_raw_fd(), "archive-complete.json")? {
        let raw = cold_archive_read_bytes(archive.as_raw_fd(), "archive-complete.json", 4096)?;
        let row = cold_canonical_child_json(&raw)?;
        let keys = [
            "schema",
            "boot_id",
            "ordinary_pending_sha256",
            "archive_intent_sha256",
            "old_source_sha256",
            "member_manifest_sha256",
            "no_client_grant",
        ];
        let object = row.as_object().ok_or_else(refuse)?;
        if object.len() != keys.len()
            || keys.iter().any(|key| !object.contains_key(*key))
            || row["schema"] != "aegis_auto_terminal_cold_archive_complete_v1"
            || row["boot_id"] != boot_id
            || row["ordinary_pending_sha256"] != pending_sha
            || row["archive_intent_sha256"]
                != intent.as_ref().map(|raw| digest(raw)).ok_or_else(refuse)?
            || row["old_source_sha256"] != source_sha
            || row["member_manifest_sha256"] != manifest_sha
            || row["no_client_grant"] != true
        {
            return Err(refuse());
        }
        Some(raw)
    } else {
        None
    };
    if (state == "archived_prefix" || state == "complete") && intent.is_none()
        || (state == "complete") != complete.is_some()
    {
        return Err(refuse());
    }
    Ok((intent, complete))
}

#[cfg(target_os = "linux")]
fn cold_archive_old_context(
    migrations: std::os::fd::RawFd,
    client: std::os::fd::RawFd,
    pending: &serde_json::Value,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let context_sha = pending["context_sha256"].as_str().ok_or_else(refuse)?;
    if context_sha.len() != 64
        || !context_sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    let context_raw = cold_archive_read_bytes(
        migrations,
        &format!("context-{context_sha}.json"),
        256 << 10,
    )?;
    if digest(&context_raw) != context_sha {
        return Err(refuse());
    }
    let context = cold_canonical_child_json(&context_raw)?;
    let keys = [
        "schema",
        "old_source_sha256",
        "old_install_sha256",
        "next_bundle_manifest_sha256",
        "next_sums_sha256",
        "leaves",
        "markers",
    ];
    let object = context.as_object().ok_or_else(refuse)?;
    if object.len() != keys.len()
        || keys.iter().any(|key| !object.contains_key(*key))
        || context["schema"] != "aegis_auto_terminal_migration_context_v1"
        || context["old_source_sha256"] != pending["old_source_sha256"]
        || context["next_bundle_manifest_sha256"] != pending["next_bundle_manifest_sha256"]
        || context["next_sums_sha256"] != pending["next_sums_sha256"]
    {
        return Err(refuse());
    }
    let install_sha = context["old_install_sha256"].as_str().ok_or_else(refuse)?;
    if install_sha.len() != 64
        || !install_sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    let old_install_raw = cold_archive_read_bytes(
        client,
        &format!("auto-guardian-install-guarded-{install_sha}.json"),
        1 << 20,
    )?;
    if digest(&old_install_raw) != install_sha {
        return Err(refuse());
    }
    let _ = cold_canonical_child_json(&old_install_raw)?;
    let source_hex = context["leaves"]["/etc/aegis-auto-terminal-source.json"]["hex"]
        .as_str()
        .ok_or_else(refuse)?;
    if source_hex.len() > 8192
        || context["leaves"]["/etc/aegis-auto-terminal-source.json"]["mode"] != 0o600
    {
        return Err(refuse());
    }
    let old_source_raw = hex::decode(source_hex).map_err(|_| refuse())?;
    if old_source_raw.is_empty()
        || old_source_raw.len() > 4096
        || digest(&old_source_raw) != context["old_source_sha256"]
    {
        return Err(refuse());
    }
    Ok((context_raw, old_install_raw, old_source_raw))
}

#[cfg(target_os = "linux")]
fn cold_archive_retired_guardian_readback(
    install: &crate::profile_auto_stopped_service::InheritedInstallReadLock,
    guard: &crate::profile_auto_stopped_service::InheritedGuardReadFd,
    root: &Path,
    pending_sha: &str,
    old_install_raw: &[u8],
    deadline: std::time::Instant,
) -> Result<serde_json::Value> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    let old_install = cold_canonical_child_json(old_install_raw)?;
    let guardian_sha = old_install["guardian_sha256"]
        .as_str()
        .filter(|sha| {
            sha.len() == 64
                && sha
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or_else(refuse)?;
    guard.revalidate(install).map_err(|_| refuse())?;
    let script = cold_child_script(root, "aegis_auto_guardian.py", guardian_sha)?;
    let passed_guard = guard.duplicate_for_child(install).map_err(|_| refuse())?;
    if unsafe { libc::fcntl(passed_guard.as_raw_fd(), libc::F_SETFD, 0) } != 0 {
        return Err(refuse());
    }
    let output_fd =
        unsafe { libc::memfd_create(c"aegis-cold-archive-guard".as_ptr(), libc::MFD_CLOEXEC) };
    if output_fd < 0 {
        return Err(refuse());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(output_fd) };
    let mut child = Command::new("/usr/bin/python3")
        .arg("-I")
        .arg("-B")
        .arg(format!("/proc/self/fd/{}", script.as_raw_fd()))
        .arg("cold-archive-retired-readback")
        .arg(passed_guard.as_raw_fd().to_string())
        .arg(pending_sha)
        .arg(root)
        .arg("--retained-source")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| refuse())?;
    let exit =
        crate::profile_auto_stopped_service::ChildExitWait::open(&child, Duration::from_millis(20));
    loop {
        if output.metadata().map_err(|_| refuse())?.len() > 8192
            || std::time::Instant::now() >= deadline
        {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse());
            }
            Ok(None) => exit.wait(&[], deadline),
        }
    }
    output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
    let mut raw = Vec::new();
    output
        .take(8193)
        .read_to_end(&mut raw)
        .map_err(|_| refuse())?;
    if raw.is_empty() || raw.len() > 8192 {
        return Err(refuse());
    }
    cold_child_script_stable(&script, root, "aegis_auto_guardian.py", guardian_sha)?;
    guard.revalidate(install).map_err(|_| refuse())?;
    let row = cold_canonical_child_json(&raw)?;
    let keys = [
        "schema",
        "boot_id",
        "intent_sha256",
        "denied_sha256",
        "stopped_successor_sha256",
        "retired_sha256",
        "deny_policy_sha256",
        "no_live_actors",
        "missing_units",
    ];
    let object = row.as_object().ok_or_else(refuse)?;
    if object.len() != keys.len()
        || keys.iter().any(|key| !object.contains_key(*key))
        || row["schema"] != "aegis_auto_guard_cold_archive_retired_readback_v1"
        || row["no_live_actors"] != true
    {
        return Err(refuse());
    }
    Ok(row)
}

#[cfg(target_os = "linux")]
fn cold_archive_retired_projection(
    guardian: &serde_json::Value,
    package: &serde_json::Value,
) -> Result<serde_json::Value> {
    let missing = guardian["missing_units"].as_array().ok_or_else(refuse)?;
    let roster = package["roster"].as_array().ok_or_else(refuse)?;
    const ALLOWED: [&str; 8] = [
        "aegis-foreign-policy-monitor.service",
        "aegis-auto-guardian.service",
        "aegis-auto-guardian-watchdog.service",
        "aegis-auto-witness-topology.service",
        "aegis-auto-capture-topology.service",
        "aegis-auto-trace-rollback-actor.service",
        "aegis-auto-trace-rollback.timer",
        "aegis-auto-trace-rollback.service",
    ];
    if missing.len() > ALLOWED.len()
        || !missing.is_empty() && package["package_state"] != "known_interrupted"
    {
        return Err(refuse());
    }
    let mut prior = None::<&str>;
    for value in missing {
        let unit = value.as_str().ok_or_else(refuse)?;
        if !ALLOWED.contains(&unit) || prior.is_some_and(|previous| previous >= unit) {
            return Err(refuse());
        }
        prior = Some(unit);
        let expected_path = format!("unit/{unit}");
        if roster
            .iter()
            .filter(|row| row["path"] == expected_path && row["relation"] == "absent")
            .count()
            != 1
        {
            return Err(refuse());
        }
    }
    let mut projected = guardian.as_object().ok_or_else(refuse)?.clone();
    if projected.remove("missing_units").is_none() {
        return Err(refuse());
    }
    projected.insert(
        "schema".into(),
        serde_json::Value::String("aegis_auto_guard_rotation_retired_readback_v1".into()),
    );
    Ok(serde_json::Value::Object(projected))
}

/// B's read-only custody proof before an ordinary B→A2 package effect.
/// The source-bound registrar validates cold lineage and PID1 terminal
/// absence; this native inspector independently enumerates and hashes the
/// exact bytes that may move. Neither readback grants a route or deletes a
/// source leaf. The caller keeps the same Install→Guard OFDs for the rename.
#[cfg(target_os = "linux")]
pub(crate) fn verify_cold_history_archive_inherited(
    install_fd: std::os::fd::RawFd,
    guard_fd: std::os::fd::RawFd,
    root: &Path,
    pending_sha: &str,
) -> Result<Vec<u8>> {
    use crate::profile_auto_stopped_service::InheritedInstallReadLock;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    if pending_sha.len() != 64
        || !pending_sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    let deadline = Instant::now() + Duration::from_secs(90);
    let install = InheritedInstallReadLock::admit(install_fd).map_err(|_| refuse())?;
    let guard = install
        .admit_guard_read_fd(guard_fd)
        .map_err(|_| refuse())?;
    let client = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    recovery_absent(client.as_raw_fd(), "auto-stop-intent.json")?;
    let migrations = recovery_directory(client.as_raw_fd(), "terminal-migrations", Some(0o700))?;
    let pending_raw = cold_archive_read_bytes(migrations.as_raw_fd(), "pending.json", 8192)?;
    let pending: serde_json::Value = cold_canonical_child_json(&pending_raw)?;
    if digest(&pending_raw) != pending_sha
        || pending["schema"] != "aegis_auto_terminal_migration_pending_v1"
    {
        return Err(refuse());
    }
    let (context_raw, old_install_raw, old_source_raw) =
        cold_archive_old_context(migrations.as_raw_fd(), client.as_raw_fd(), &pending)?;
    let context = cold_canonical_child_json(&context_raw)?;
    let old_source_sha = digest(&old_source_raw);
    let old_install = cold_canonical_child_json(&old_install_raw)?;
    let (state, cold_root_present, before) = cold_archive_members(pending_sha)?;
    let history = if state == "complete" {
        installer_v2_generation::successor_history_sealed()?
    } else {
        installer_v2_generation::successor_history()?
    };
    let incoming = installer_v2_generation::admit_cold_archive_target(&history)?;
    let incoming_root = incoming.public_root.as_str();
    if history.stopped["input"]["public_payload_root"].as_str() != root.to_str()
        || history.stopped["stage"]["mode"] == "socks-only"
    {
        return Err(refuse());
    }
    if state == "complete" {
        installer_v2_generation::verify_old_retained_source(&history)?;
    }
    let retired_full = if state == "complete" {
        cold_archive_retired_guardian_readback(
            &install,
            &guard,
            root,
            pending_sha,
            &old_install_raw,
            deadline,
        )?
    } else {
        retired_guardian_readback(&install, &guard)?
    };
    if retired_full["no_live_actors"] != true
        || pending["boot_id"] != retired_full["boot_id"]
        || retired_full["boot_id"]
            != std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| refuse())?
                .trim_end_matches('\n')
    {
        return Err(refuse());
    }
    let etc = recovery_chain(&["etc"], None)?;
    if state != "complete" {
        let live_source =
            cold_archive_read_bytes(etc.as_raw_fd(), "aegis-auto-terminal-source.json", 4096)?;
        let live_install =
            cold_archive_read_bytes(client.as_raw_fd(), "auto-guardian-install.json", 1 << 20)?;
        if live_source != old_source_raw || live_install != old_install_raw {
            return Err(refuse());
        }
    }
    let helper_sha = old_install["terminal_register_sha256"]
        .as_str()
        .filter(|sha| {
            sha.len() == 64
                && sha
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or_else(refuse)?;
    // Establish the predecessor B SUMS anchor before any archive mutation;
    // the same bytes must remain usable if A2 later replaces installed B.
    let coordinator_sha = installer_v2_generation::cold_archive_old_b_coordinator_sha(&history)?;
    let read_complete_package = || -> Result<serde_json::Value> {
        let old_root = root.to_str().ok_or_else(refuse)?;
        let old_candidate = history.stopped["input"]["candidate_sha256"]
            .as_str()
            .ok_or_else(refuse)?;
        let old_install_sha = context["old_install_sha256"].as_str().ok_or_else(refuse)?;
        let new_package_sha = pending["package_sha256"].as_str().ok_or_else(refuse)?;
        let package = cold_package_readback_bound(
            &install,
            &guard,
            (old_root, incoming_root),
            (old_root, "cold-archive-package-readback"),
            &coordinator_sha,
            deadline,
            || {
                installer_v2_generation::verify_old_retained_source(&history)?;
                if installer_v2_generation::cold_archive_old_b_coordinator_sha(&history)?
                    != coordinator_sha
                {
                    return Err(refuse());
                }
                let (ctx, receipt, source) =
                    cold_archive_old_context(migrations.as_raw_fd(), client.as_raw_fd(), &pending)?;
                if ctx != context_raw || receipt != old_install_raw || source != old_source_raw {
                    return Err(refuse());
                }
                Ok(())
            },
        )?;
        validate_cold_package_readback_bound(
            &package,
            (old_root, incoming_root),
            (old_candidate, incoming.candidate_sha256.as_str()),
            old_install_sha,
            new_package_sha,
            || {
                installer_v2_generation::cold_archive_package_sources(
                    &history, &pending, &context, &package,
                )
            },
        )?;
        Ok(package)
    };
    let complete_package = if state == "complete" {
        Some(read_complete_package()?)
    } else {
        None
    };

    let retired = if state == "complete" {
        cold_archive_retired_projection(
            &retired_full,
            complete_package.as_ref().ok_or_else(refuse)?,
        )?
    } else {
        retired_full.clone()
    };
    let retired_bytes = installer_v2_generation::verify_retired_successor(&history, &retired)?;
    let retired_native: serde_json::Value =
        serde_json::from_slice(&retired_bytes).map_err(|_| refuse())?;
    if retired_native["schema"] != "aegis_auto_v2_retired_successor_verification_v1" {
        return Err(refuse());
    }
    let before_sha = cold_archive_manifest_sha(&before)?;
    let boot_id = retired["boot_id"].as_str().ok_or_else(refuse)?;
    let deny_sha = retired["deny_policy_sha256"].as_str().ok_or_else(refuse)?;
    let receipts_before = cold_archive_receipts(
        pending_sha,
        boot_id,
        &old_source_sha,
        &before_sha,
        deny_sha,
        &state,
    )?;
    for row in &before {
        let Some(name) = row["path"]
            .as_str()
            .and_then(|path| path.strip_prefix("auto-terminal-activation-preseal-"))
            .and_then(|tail| tail.strip_suffix(".json"))
        else {
            continue;
        };
        if name.len() != 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(refuse());
        }
        let leaf = format!("auto-terminal-activation-preseal-{name}.json");
        let holder = if cold_archive_present(client.as_raw_fd(), &leaf)? {
            client.as_raw_fd()
        } else {
            let archive = recovery_directory(
                client.as_raw_fd(),
                &format!("terminal-cold-history-{pending_sha}"),
                Some(0o700),
            )?;
            let preseal = recovery_directory(archive.as_raw_fd(), "preseal", Some(0o700))?;
            let raw = cold_archive_read_bytes(preseal.as_raw_fd(), &leaf, 4096)?;
            cold_archive_preseal_row(&raw, name)?;
            continue;
        };
        let raw = cold_archive_read_bytes(holder, &leaf, 4096)?;
        cold_archive_preseal_row(&raw, name)?;
    }
    if state != "complete" {
        guard.revalidate(&install).map_err(|_| refuse())?;
        let script = cold_child_script(root, "aegis_auto_terminal_register.py", helper_sha)?;
        let passed_install = install.duplicate_held_fd().map_err(|_| refuse())?;
        let passed_guard = guard.duplicate_for_child(&install).map_err(|_| refuse())?;
        for fd in [passed_install.as_raw_fd(), passed_guard.as_raw_fd()] {
            if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
                return Err(refuse());
            }
        }
        let output_fd =
            unsafe { libc::memfd_create(c"aegis-cold-archive".as_ptr(), libc::MFD_CLOEXEC) };
        if output_fd < 0 {
            return Err(refuse());
        }
        let mut output = unsafe { std::fs::File::from_raw_fd(output_fd) };
        let mut child = Command::new("/usr/bin/python3")
            .arg("-I")
            .arg("-B")
            .arg(format!("/proc/self/fd/{}", script.as_raw_fd()))
            .arg("cold-history-archive-readback")
            .arg(passed_install.as_raw_fd().to_string())
            .arg(passed_guard.as_raw_fd().to_string())
            .arg(pending_sha)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|_| refuse())?;
        let exit = crate::profile_auto_stopped_service::ChildExitWait::open(
            &child,
            Duration::from_millis(20),
        );
        loop {
            if output.metadata().map_err(|_| refuse())?.len() > 4 << 20
                || Instant::now() >= deadline
            {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse());
            }
            match child.try_wait() {
                Ok(Some(status)) if status.success() => break,
                Ok(Some(_)) | Err(_) => {
                    unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(refuse());
                }
                Ok(None) => exit.wait(&[], deadline),
            }
        }
        output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
        let mut raw = Vec::new();
        output
            .take((4 << 20) + 1)
            .read_to_end(&mut raw)
            .map_err(|_| refuse())?;
        if raw.is_empty() || raw.len() > 4 << 20 {
            return Err(refuse());
        }
        cold_child_script_stable(&script, root, "aegis_auto_terminal_register.py", helper_sha)?;
        let child_row = cold_canonical_child_json(&raw)?;
        let expected_keys = [
            "schema",
            "ordinary_pending_sha256",
            "old_source_sha256",
            "cold_root",
            "cold_root_present",
            "members",
            "member_manifest_sha256",
            "no_client_grant",
        ];
        let object = child_row.as_object().ok_or_else(refuse)?;
        if object.len() != expected_keys.len()
            || expected_keys.iter().any(|key| !object.contains_key(*key))
            || child_row["schema"] != "aegis_auto_terminal_cold_archive_roster_v1"
            || child_row["ordinary_pending_sha256"] != pending_sha
            || child_row["old_source_sha256"] != old_source_sha
            || child_row["cold_root"] != "terminal-migrations/cold-recovery"
            || child_row["cold_root_present"] != cold_root_present
            || child_row["members"] != serde_json::Value::Array(before.clone())
            || child_row["member_manifest_sha256"] != before_sha
            || child_row["no_client_grant"] != true
        {
            return Err(refuse());
        }
    }
    let retired_again = if state == "complete" {
        cold_archive_retired_guardian_readback(
            &install,
            &guard,
            root,
            pending_sha,
            &old_install_raw,
            deadline,
        )?
    } else {
        retired_guardian_readback(&install, &guard)?
    };
    let after_package = if state == "complete" {
        Some(read_complete_package()?)
    } else {
        None
    };
    let retired_again_projected = if state == "complete" {
        cold_archive_retired_projection(&retired_again, after_package.as_ref().ok_or_else(refuse)?)?
    } else {
        retired_again.clone()
    };
    let (after_context, after_install, after_source) =
        cold_archive_old_context(migrations.as_raw_fd(), client.as_raw_fd(), &pending)?;
    let (after_state, after_cold_root, after) = cold_archive_members(pending_sha)?;
    if after_state != state
        || after_cold_root != cold_root_present
        || after != before
        || retired_again != retired_full
        || after_context != context_raw
        || after_install != old_install_raw
        || after_source != old_source_raw
        || after_package != complete_package
        || cold_archive_receipts(
            pending_sha,
            boot_id,
            &old_source_sha,
            &before_sha,
            deny_sha,
            &state,
        )? != receipts_before
        || cold_archive_read_bytes(migrations.as_raw_fd(), "pending.json", 8192)? != pending_raw
        || state != "complete"
            && (cold_archive_read_bytes(etc.as_raw_fd(), "aegis-auto-terminal-source.json", 4096)?
                != old_source_raw
                || cold_archive_read_bytes(
                    client.as_raw_fd(),
                    "auto-guardian-install.json",
                    1 << 20,
                )? != old_install_raw)
        || (if state == "complete" {
            installer_v2_generation::successor_history_sealed()?
        } else {
            installer_v2_generation::successor_history()?
        })
        .stopped
            != history.stopped
        || installer_v2_generation::verify_retired_successor(&history, &retired_again_projected)?
            != retired_bytes
    {
        return Err(refuse());
    }
    guard.revalidate(&install).map_err(|_| refuse())?;
    if Instant::now() >= deadline {
        return Err(refuse());
    }
    serde_json::to_vec(&serde_json::json!({
        "schema":"aegis_auto_v2_cold_history_archive_verification_v1",
        "current_boot_id":retired["boot_id"],
        "ordinary_pending_sha256":pending_sha,
        "old_source_sha256":old_source_sha,
        "member_manifest_sha256":before_sha,
        "cold_root_present":cold_root_present,
        "deny_policy_sha256":retired["deny_policy_sha256"],
        "state":state,
        "no_client_grant":true,
    }))
    .map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
fn verify_cold_rollover_inherited(
    install_fd: std::os::fd::RawFd,
    guard_fd: std::os::fd::RawFd,
    root: &Path,
) -> Result<Vec<u8>> {
    use crate::profile_auto_stopped_service::InheritedInstallReadLock;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(90);
    let install = InheritedInstallReadLock::admit(install_fd).map_err(|_| refuse())?;
    let guard = install
        .admit_guard_read_fd(guard_fd)
        .map_err(|_| refuse())?;
    let source = installer_v2_generation::cold_stale_source(root)?;
    let original = installer_v2_generation::cold_original_intent(&source)?;
    let (guardian, package, site) =
        cold_stale_double_observation(&install, &guard, root, &source, deadline)?;
    let current_sha = installer_v2_generation::cold_current_intent_sha(
        &source.bootstrap.successor_intent_sha256,
    )?;
    let migration = site["migration_state"].as_str().ok_or_else(refuse)?;
    let site_state = site["site_state"].as_str().ok_or_else(refuse)?;
    let package_state = package["package_state"].as_str().ok_or_else(refuse)?;
    let observer_state = guardian["observer_state"].as_str().ok_or_else(refuse)?;
    let site_admitted = match package_state {
        "old_exact" => {
            ["a_exact", "a_retiring_prefix", "absent"].contains(&site_state)
                && observer_state == "absent"
        }
        "known_interrupted" => {
            (migration == "pending_prefix" || current_sha.is_some()) && observer_state == "absent"
        }
        "new_exact" => {
            (["pending_prefix", "completed_edge"].contains(&migration) || current_sha.is_some())
                && ["a_retiring_prefix", "absent", "b_prefix", "b_complete"].contains(&site_state)
        }
        _ => false,
    };
    if current_sha != source.current_intent_sha256
        || !site_admitted
        || site["context_state"] == "missing_reconstructible"
            && (site_state != "a_exact" || package_state != "old_exact")
        || migration == "preparation_absent"
            && site["cold_context_state"] == "missing_reconstructible"
            && (site_state != "a_exact" || package_state != "old_exact")
        || guardian["selected_manager"] != original["selected_manager"]
        || guardian["guard30_sha256"] != original["guard30_sha256"]
        || guardian["policy_sha256"] != original["deny_policy_sha256"]
        || site["next_bundle_manifest_sha256"] != source.bootstrap.bundle_manifest_sha256
        || site["next_sums_sha256"] != source.bootstrap.sums_sha256
        || package["new_package_sha256"] != source.new_package_sha256
        || guardian["client_actors_absent"] != true
        || guardian["jobs_absent"] != true
        || guardian["cgroups_empty"] != true
        || guardian["stop_intent_absent"] != true
    {
        return Err(refuse());
    }
    let quiesce = if let Some(sha) = current_sha.as_deref() {
        installer_v2_generation::cold_quiesce_receipt(sha)?
    } else {
        None
    };
    if let Some((phase, sha)) = &quiesce {
        if guardian["quiesce_state"] != "post"
            || guardian["quiesce_receipt_sha256"] != *sha
            || guardian["quiesce_monotonic_tick"] != phase["quiesce_monotonic_tick"]
            || guardian["policy_sha256"] != phase["deny_policy_sha256"]
        {
            return Err(refuse());
        }
    } else if guardian["quiesce_state"] != "pre"
        || !guardian["quiesce_receipt_sha256"].is_null()
        || package["package_state"] == "known_interrupted"
            && site["migration_state"] == "preparation_absent"
    {
        return Err(refuse());
    }
    let package_repair =
        if let (Some(sha), Some((phase, _))) = (current_sha.as_deref(), quiesce.as_ref()) {
            installer_v2_generation::cold_package_repair_receipt(
                sha,
                phase["quiesce_monotonic_tick"]
                    .as_u64()
                    .ok_or_else(refuse)?,
            )?
        } else {
            None
        };
    if let Some((phase, sha)) = &package_repair {
        if package["package_state"] != "new_exact"
            || guardian["package_repair_receipt_sha256"] != *sha
            || guardian["package_repaired_tick"] != phase["package_repaired_tick"]
        {
            return Err(refuse());
        }
    } else if !guardian["package_repair_receipt_sha256"].is_null()
        || !guardian["package_repaired_tick"].is_null()
        || quiesce.is_some() && guardian["infrastructure_quiescent"] != true
    {
        return Err(refuse());
    }
    let mut site_raw = serde_json::to_vec(&site).map_err(|_| refuse())?;
    site_raw.push(b'\n');
    let after = installer_v2_generation::cold_stale_source(root)?;
    if after.original_intent_sha256 != source.original_intent_sha256
        || after.prior_intent_sha256 != source.prior_intent_sha256
        || after.current_head_sha256 != source.current_head_sha256
        || after.current_intent_sha256 != source.current_intent_sha256
        || after.barrier_sha256 != source.barrier_sha256
        || installer_v2_generation::cold_current_intent_sha(
            &source.bootstrap.successor_intent_sha256,
        )? != current_sha
        || (if let Some(sha) = current_sha.as_deref() {
            installer_v2_generation::cold_quiesce_receipt(sha)?
        } else {
            None
        }) != quiesce
        || (if let (Some(sha), Some((phase, _))) = (current_sha.as_deref(), quiesce.as_ref()) {
            installer_v2_generation::cold_package_repair_receipt(
                sha,
                phase["quiesce_monotonic_tick"]
                    .as_u64()
                    .ok_or_else(refuse)?,
            )?
        } else {
            None
        }) != package_repair
    {
        return Err(refuse());
    }
    guard.revalidate(&install).map_err(|_| refuse())?;
    if Instant::now() >= deadline {
        return Err(refuse());
    }
    let mut output = serde_json::Map::new();
    output.insert(
        "schema".into(),
        serde_json::json!("aegis_auto_v2_cold_retired_successor_v2"),
    );
    output.insert(
        "old_boot_id".into(),
        serde_json::json!(original["old_boot_id"]),
    );
    output.insert(
        "current_boot_id".into(),
        serde_json::json!(guardian["boot_id"]),
    );
    output.insert(
        "old_active_sha256".into(),
        serde_json::json!(original["old_active_sha256"]),
    );
    output.insert(
        "old_stopped_sha256".into(),
        serde_json::json!(original["old_stopped_sha256"]),
    );
    output.insert(
        "successor_intent_sha256".into(),
        serde_json::json!(source.bootstrap.successor_intent_sha256),
    );
    output.insert(
        "old_install_sha256".into(),
        serde_json::json!(source.old_install_sha256),
    );
    output.insert(
        "old_source_sha256".into(),
        serde_json::json!(original["old_source_sha256"]),
    );
    output.insert(
        "old_context_sha256".into(),
        serde_json::json!(site["old_context_sha256"]),
    );
    output.insert(
        "context_state".into(),
        serde_json::json!(site["context_state"]),
    );
    output.insert(
        "cold_old_context_sha256".into(),
        serde_json::json!(site["cold_old_context_sha256"]),
    );
    output.insert(
        "cold_context_state".into(),
        serde_json::json!(site["cold_context_state"]),
    );
    output.insert(
        "old_observer_archive_sha256".into(),
        serde_json::json!(site["old_observer_archive_sha256"]),
    );
    output.insert(
        "guardian_rotation_intent_sha256".into(),
        serde_json::json!(original["guardian_rotation_intent_sha256"]),
    );
    output.insert(
        "guardian_rotation_denied_sha256".into(),
        serde_json::json!(original["guardian_rotation_denied_sha256"]),
    );
    output.insert(
        "guardian_rotation_retired_sha256".into(),
        serde_json::json!(original["guardian_rotation_retired_sha256"]),
    );
    output.insert(
        "retained_root".into(),
        serde_json::json!(source.retained_root),
    );
    output.insert(
        "new_candidate_sha256".into(),
        serde_json::json!(source.bootstrap.candidate_sha256),
    );
    output.insert(
        "new_package_sha256".into(),
        serde_json::json!(source.new_package_sha256),
    );
    output.insert(
        "package_state".into(),
        serde_json::json!(package["package_state"]),
    );
    output.insert(
        "installed_source_sha256".into(),
        serde_json::json!(package["installed_source_sha256"]),
    );
    output.insert(
        "roster_sha256".into(),
        serde_json::json!(package["roster_sha256"]),
    );
    output.insert(
        "deny_policy_sha256".into(),
        serde_json::json!(guardian["policy_sha256"]),
    );
    output.insert(
        "guard30_sha256".into(),
        serde_json::json!(guardian["guard30_sha256"]),
    );
    output.insert(
        "selected_manager".into(),
        serde_json::json!(guardian["selected_manager"]),
    );
    output.insert(
        "manager31_sha256".into(),
        serde_json::json!(guardian["manager31_sha256"]),
    );
    output.insert(
        "guardian31_sha256".into(),
        serde_json::json!(guardian["guardian31_sha256"]),
    );
    output.insert(
        "migration_state".into(),
        serde_json::json!(site["migration_state"]),
    );
    output.insert("site_state".into(), serde_json::json!(site["site_state"]));
    output.insert(
        "site_readback_sha256".into(),
        serde_json::json!(digest(&site_raw)),
    );
    output.insert(
        "source_config_sha256".into(),
        serde_json::json!(site["source_config_sha256"]),
    );
    output.insert(
        "observer_state".into(),
        serde_json::json!(guardian["observer_state"]),
    );
    output.insert(
        "observer_source_sha256".into(),
        serde_json::json!(guardian["observer_source_sha256"]),
    );
    output.insert(
        "observer_ready_sha256".into(),
        serde_json::json!(guardian["observer_ready_sha256"]),
    );
    output.insert(
        "infrastructure_rows_sha256".into(),
        serde_json::json!(guardian["infrastructure_rows_sha256"]),
    );
    output.insert("infrastructure_qualified".into(), serde_json::json!(true));
    output.insert(
        "infrastructure_quiescent".into(),
        serde_json::json!(guardian["infrastructure_quiescent"]),
    );
    output.insert(
        "quiesce_state".into(),
        serde_json::json!(guardian["quiesce_state"]),
    );
    output.insert(
        "quiesce_receipt_sha256".into(),
        serde_json::json!(guardian["quiesce_receipt_sha256"]),
    );
    output.insert(
        "quiesce_monotonic_tick".into(),
        serde_json::json!(guardian["quiesce_monotonic_tick"]),
    );
    output.insert(
        "package_repair_receipt_sha256".into(),
        serde_json::json!(guardian["package_repair_receipt_sha256"]),
    );
    output.insert(
        "package_repaired_tick".into(),
        serde_json::json!(guardian["package_repaired_tick"]),
    );
    output.insert("client_actors_absent".into(), serde_json::json!(true));
    output.insert("jobs_absent".into(), serde_json::json!(true));
    output.insert("cgroups_empty".into(), serde_json::json!(true));
    output.insert("stop_intent_absent".into(), serde_json::json!(true));
    output.insert("cold_intent_sha256".into(), serde_json::json!(current_sha));
    serde_json::to_vec(&serde_json::Value::Object(output)).map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_cold_retired_successor_inherited(
    install_fd: std::os::fd::RawFd,
    guard_fd: std::os::fd::RawFd,
    root: &Path,
) -> Result<Vec<u8>> {
    use crate::profile_auto_stopped_service::InheritedInstallReadLock;
    use std::time::{Duration, Instant};
    if installer_v2_generation::cold_stale_source(root).is_ok() {
        return verify_cold_rollover_inherited(install_fd, guard_fd, root);
    }
    let deadline = Instant::now() + Duration::from_secs(90);
    let install = InheritedInstallReadLock::admit(install_fd).map_err(|_| refuse())?;
    let guard = install
        .admit_guard_read_fd(guard_fd)
        .map_err(|_| refuse())?;
    let history = installer_v2_generation::cold_retired_history(root)?;
    let first = cold_guardian_readback(&install, &guard, root, &history, deadline)?;
    validate_cold_guardian_readback(&first, &history)?;
    let first_site = cold_site_readback(&install, &guard, &history, deadline)?;
    validate_cold_site_readback(&first_site, &history)?;
    let first_package = cold_package_readback(&install, &guard, &history, deadline)?;
    validate_cold_package_readback(&first_package, &history)?;
    validate_cold_infrastructure_rows(&first, &first_package)?;
    let second = cold_guardian_readback(&install, &guard, root, &history, deadline)?;
    validate_cold_guardian_readback(&second, &history)?;
    let second_site = cold_site_readback(&install, &guard, &history, deadline)?;
    validate_cold_site_readback(&second_site, &history)?;
    let second_package = cold_package_readback(&install, &guard, &history, deadline)?;
    validate_cold_package_readback(&second_package, &history)?;
    validate_cold_infrastructure_rows(&second, &second_package)?;
    if first != second
        || first_site != second_site
        || first_package != second_package
        || first["manager31_sha256"] != first_site["manager31_sha256"]
        || first["guardian31_sha256"] != first_site["guardian31_sha256"]
    {
        return Err(refuse());
    }
    let cold_intent_sha =
        installer_v2_generation::cold_current_intent_sha(&history.successor_intent_sha256)?;
    let quiesce = if let Some(sha) = cold_intent_sha.as_deref() {
        installer_v2_generation::cold_quiesce_receipt(sha)?
    } else {
        None
    };
    if let Some((phase, sha)) = &quiesce {
        if first["quiesce_state"] != "post"
            || first["quiesce_receipt_sha256"] != *sha
            || first["quiesce_monotonic_tick"] != phase["quiesce_monotonic_tick"]
            || first["policy_sha256"] != phase["deny_policy_sha256"]
            || (first_package["package_state"] == "old_exact"
                && (first["infrastructure_quiescent"] != true
                    || first["infrastructure_rows_sha256"]
                        != phase["post_quiesce_infrastructure_sha256"]))
        {
            return Err(refuse());
        }
    } else {
        let state = first_package["package_state"].as_str().ok_or_else(refuse)?;
        let allowed = match state {
            "old_exact" => true,
            "new_exact" => {
                ["pending_prefix", "completed_edge"].contains(&history.migration_state)
                    && ["b_prefix", "b_complete"]
                        .contains(&first_site["site_state"].as_str().ok_or_else(refuse)?)
                    && first["observer_state"] == "absent"
            }
            "known_interrupted" => {
                history.migration_state == "pending_prefix" && first["observer_state"] == "absent"
            }
            _ => false,
        };
        if first["quiesce_state"] != "pre" || !first["quiesce_receipt_sha256"].is_null() || !allowed
        {
            return Err(refuse());
        }
    }
    let package_repair = if let (Some(intent_sha), Some((phase, _))) =
        (cold_intent_sha.as_deref(), quiesce.as_ref())
    {
        installer_v2_generation::cold_package_repair_receipt(
            intent_sha,
            phase["quiesce_monotonic_tick"]
                .as_u64()
                .ok_or_else(refuse)?,
        )?
    } else {
        None
    };
    if let Some((phase, sha)) = &package_repair {
        if first_package["package_state"] != "new_exact"
            || first["quiesce_state"] != "post"
            || first["package_repair_receipt_sha256"] != *sha
            || first["package_repaired_tick"] != phase["package_repaired_tick"]
        {
            return Err(refuse());
        }
    } else if !first["package_repair_receipt_sha256"].is_null()
        || !first["package_repaired_tick"].is_null()
        || (quiesce.is_some() && first["infrastructure_quiescent"] != true)
    {
        return Err(refuse());
    }
    if history.context_state == "missing_reconstructible"
        && (first_site["site_state"] != "a_exact"
            || first_package["package_state"] != "old_exact"
            || first["observer_state"] != "absent")
    {
        return Err(refuse());
    }
    if history.migration_state == "preparation_absent" {
        if cold_intent_sha.is_none() || history.cold_context_state == "missing_reconstructible" {
            if first_site["site_state"] != "a_exact"
                || first_package["package_state"] != "old_exact"
                || first["observer_state"] != "absent"
            {
                return Err(refuse());
            }
        } else if history.cold_context_state != "present_exact" {
            return Err(refuse());
        }
    }
    if first_site["site_state"] == "b_prefix"
        && cold_intent_sha.is_none()
        && history.migration_state != "pending_prefix"
    {
        return Err(refuse());
    }
    let mut site_raw = serde_json::to_vec(&first_site).map_err(|_| refuse())?;
    site_raw.push(b'\n');
    let again = installer_v2_generation::cold_retired_history(root)?;
    if history.old_context_sha256 != again.old_context_sha256
        || history.migration_record_sha256 != again.migration_record_sha256
        || history.successor_intent_sha256 != again.successor_intent_sha256
        || history.current_boot_id != again.current_boot_id
        || history.new_package_sha256 != again.new_package_sha256
        || history.old_observer_archive_sha256 != again.old_observer_archive_sha256
        || history.cold_old_context_sha256 != again.cold_old_context_sha256
        || history.cold_context_state != again.cold_context_state
        || history.migration_state != again.migration_state
        || history.context_state != again.context_state
        || cold_intent_sha
            != installer_v2_generation::cold_current_intent_sha(&history.successor_intent_sha256)?
        || (if let Some(sha) = cold_intent_sha.as_deref() {
            installer_v2_generation::cold_quiesce_receipt(sha)?
        } else {
            None
        }) != quiesce
        || (if let (Some(intent_sha), Some((phase, _))) =
            (cold_intent_sha.as_deref(), quiesce.as_ref())
        {
            installer_v2_generation::cold_package_repair_receipt(
                intent_sha,
                phase["quiesce_monotonic_tick"]
                    .as_u64()
                    .ok_or_else(refuse)?,
            )?
        } else {
            None
        }) != package_repair
    {
        return Err(refuse());
    }
    if Instant::now() >= deadline {
        return Err(refuse());
    }
    guard.revalidate(&install).map_err(|_| refuse())?;
    let mut proof = serde_json::Map::new();
    proof.insert(
        "schema".into(),
        serde_json::to_value("aegis_auto_v2_cold_retired_successor_v2").map_err(|_| refuse())?,
    );
    proof.insert(
        "old_boot_id".into(),
        serde_json::to_value(&history.old_boot_id).map_err(|_| refuse())?,
    );
    proof.insert(
        "current_boot_id".into(),
        serde_json::to_value(&history.current_boot_id).map_err(|_| refuse())?,
    );
    proof.insert(
        "old_active_sha256".into(),
        serde_json::to_value(&history.old_active_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "old_stopped_sha256".into(),
        serde_json::to_value(&history.old_stopped_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "successor_intent_sha256".into(),
        serde_json::to_value(&history.successor_intent_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "old_install_sha256".into(),
        serde_json::to_value(&history.old_install_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "old_source_sha256".into(),
        serde_json::to_value(&history.old_source_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "old_context_sha256".into(),
        serde_json::to_value(&history.old_context_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "context_state".into(),
        serde_json::to_value(history.context_state).map_err(|_| refuse())?,
    );
    proof.insert(
        "cold_old_context_sha256".into(),
        serde_json::to_value(&history.cold_old_context_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "cold_context_state".into(),
        serde_json::to_value(history.cold_context_state).map_err(|_| refuse())?,
    );
    proof.insert(
        "old_observer_archive_sha256".into(),
        serde_json::to_value(&history.old_observer_archive_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "guardian_rotation_intent_sha256".into(),
        serde_json::to_value(&history.guardian_rotation_intent_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "guardian_rotation_denied_sha256".into(),
        serde_json::to_value(&history.guardian_rotation_denied_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "guardian_rotation_retired_sha256".into(),
        serde_json::to_value(&history.guardian_rotation_retired_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "new_candidate_sha256".into(),
        serde_json::to_value(&history.new_candidate_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "new_package_sha256".into(),
        serde_json::to_value(&history.new_package_sha256).map_err(|_| refuse())?,
    );
    proof.insert(
        "retained_root".into(),
        serde_json::to_value(&history.retained_root).map_err(|_| refuse())?,
    );
    proof.insert(
        "package_state".into(),
        serde_json::to_value(&first_package["package_state"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "installed_source_sha256".into(),
        serde_json::to_value(&first_package["installed_source_sha256"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "roster_sha256".into(),
        serde_json::to_value(&first_package["roster_sha256"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "deny_policy_sha256".into(),
        serde_json::to_value(&first["policy_sha256"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "guard30_sha256".into(),
        serde_json::to_value(&first["guard30_sha256"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "selected_manager".into(),
        serde_json::to_value(&first["selected_manager"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "manager31_sha256".into(),
        serde_json::to_value(&first["manager31_sha256"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "guardian31_sha256".into(),
        serde_json::to_value(&first["guardian31_sha256"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "migration_state".into(),
        serde_json::to_value(history.migration_state).map_err(|_| refuse())?,
    );
    proof.insert(
        "site_state".into(),
        serde_json::to_value(&first_site["site_state"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "site_readback_sha256".into(),
        serde_json::to_value(digest(&site_raw)).map_err(|_| refuse())?,
    );
    proof.insert(
        "source_config_sha256".into(),
        serde_json::to_value(&first_site["source_config_sha256"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "observer_state".into(),
        serde_json::to_value(&first["observer_state"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "observer_source_sha256".into(),
        serde_json::to_value(&first["observer_source_sha256"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "observer_ready_sha256".into(),
        serde_json::to_value(&first["observer_ready_sha256"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "infrastructure_rows_sha256".into(),
        serde_json::to_value(&first["infrastructure_rows_sha256"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "infrastructure_qualified".into(),
        serde_json::to_value(true).map_err(|_| refuse())?,
    );
    proof.insert(
        "infrastructure_quiescent".into(),
        serde_json::to_value(&first["infrastructure_quiescent"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "quiesce_state".into(),
        serde_json::to_value(&first["quiesce_state"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "quiesce_receipt_sha256".into(),
        serde_json::to_value(&first["quiesce_receipt_sha256"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "quiesce_monotonic_tick".into(),
        serde_json::to_value(&first["quiesce_monotonic_tick"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "package_repair_receipt_sha256".into(),
        serde_json::to_value(&first["package_repair_receipt_sha256"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "package_repaired_tick".into(),
        serde_json::to_value(&first["package_repaired_tick"]).map_err(|_| refuse())?,
    );
    proof.insert(
        "client_actors_absent".into(),
        serde_json::to_value(true).map_err(|_| refuse())?,
    );
    proof.insert(
        "jobs_absent".into(),
        serde_json::to_value(true).map_err(|_| refuse())?,
    );
    proof.insert(
        "cgroups_empty".into(),
        serde_json::to_value(true).map_err(|_| refuse())?,
    );
    proof.insert(
        "stop_intent_absent".into(),
        serde_json::to_value(true).map_err(|_| refuse())?,
    );
    proof.insert(
        "cold_intent_sha256".into(),
        serde_json::to_value(&cold_intent_sha).map_err(|_| refuse())?,
    );
    serde_json::to_vec(&serde_json::Value::Object(proof)).map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
fn cold_fresh_guard_lock() -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;
    let parent = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let guard = recovery_open_at(
        parent.as_raw_fd(),
        "device-guard.conf.lock",
        libc::O_RDWR,
        0,
    )?;
    let before = recovery_stat(guard.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o600
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || unsafe { libc::flock(guard.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err(refuse());
    }
    let named = recovery_open_at(
        parent.as_raw_fd(),
        "device-guard.conf.lock",
        libc::O_RDONLY,
        0,
    )?;
    let after = recovery_stat(named.as_raw_fd())?;
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
    ) {
        return Err(refuse());
    }
    Ok(guard)
}

#[cfg(target_os = "linux")]
fn cold_proof_from_fresh_locks(
    install: &crate::profile_auto_stopped_service::InstallLock,
    guard: &std::os::fd::OwnedFd,
    root: &Path,
) -> Result<serde_json::Value> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    install.revalidate().map_err(|_| refuse())?;
    let passed_install = install.duplicate_held_fd().map_err(|_| refuse())?;
    let passed_guard = unsafe { libc::fcntl(guard.as_raw_fd(), libc::F_DUPFD, 3) };
    if passed_guard < 3 {
        return Err(refuse());
    }
    let passed_guard = unsafe { std::os::fd::OwnedFd::from_raw_fd(passed_guard) };
    for fd in [passed_install.as_raw_fd(), passed_guard.as_raw_fd()] {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(refuse());
        }
    }
    let output_fd =
        unsafe { libc::memfd_create(c"aegis-cold-native-proof".as_ptr(), libc::MFD_CLOEXEC) };
    if output_fd < 0 {
        return Err(refuse());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(output_fd) };
    let mut child = Command::new("/proc/self/exe")
        .arg("auto-verify-cold-retired-successor")
        .arg("--lock-fd")
        .arg(passed_install.as_raw_fd().to_string())
        .arg("--guard-fd")
        .arg(passed_guard.as_raw_fd().to_string())
        .arg("--retained-root")
        .arg(root)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| refuse())?;
    let deadline = Instant::now() + Duration::from_secs(110);
    let exit =
        crate::profile_auto_stopped_service::ChildExitWait::open(&child, Duration::from_millis(20));
    loop {
        if output.metadata().map_err(|_| refuse())?.len() > 16384 || Instant::now() >= deadline {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse());
            }
            Ok(None) => exit.wait(&[], deadline),
        }
    }
    install.revalidate().map_err(|_| refuse())?;
    output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
    let mut raw = Vec::new();
    output
        .take(16385)
        .read_to_end(&mut raw)
        .map_err(|_| refuse())?;
    if raw.is_empty() || raw.len() > 16384 {
        return Err(refuse());
    }
    let value: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| refuse())?;
    if value["schema"] != "aegis_auto_v2_cold_retired_successor_v2"
        || value["retained_root"].as_str() != root.to_str()
        || value["client_actors_absent"] != true
        || value["jobs_absent"] != true
        || value["cgroups_empty"] != true
        || value["infrastructure_qualified"] != true
    {
        return Err(refuse());
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn cold_stale_proof_from_fresh_locks(
    install: &crate::profile_auto_stopped_service::InstallLock,
    guard: &std::os::fd::OwnedFd,
    root: &Path,
    prior_sha: &str,
    preretire: bool,
) -> Result<serde_json::Value> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    install.revalidate().map_err(|_| refuse())?;
    let passed_install = install.duplicate_held_fd().map_err(|_| refuse())?;
    let passed_guard = unsafe { libc::fcntl(guard.as_raw_fd(), libc::F_DUPFD, 3) };
    if passed_guard < 3 {
        return Err(refuse());
    }
    let passed_guard = unsafe { std::os::fd::OwnedFd::from_raw_fd(passed_guard) };
    for fd in [passed_install.as_raw_fd(), passed_guard.as_raw_fd()] {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(refuse());
        }
    }
    let output_fd =
        unsafe { libc::memfd_create(c"aegis-cold-native-proof".as_ptr(), libc::MFD_CLOEXEC) };
    if output_fd < 0 {
        return Err(refuse());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(output_fd) };
    let mut child = Command::new("/proc/self/exe")
        .arg(if preretire {
            "auto-verify-cold-stale-preretire-inherited"
        } else {
            "auto-verify-cold-stale-inherited"
        })
        .arg("--lock-fd")
        .arg(passed_install.as_raw_fd().to_string())
        .arg("--guard-fd")
        .arg(passed_guard.as_raw_fd().to_string())
        .arg("--retained-root")
        .arg(root)
        .arg("--prior-intent-sha256")
        .arg(prior_sha)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| refuse())?;
    let deadline = Instant::now() + Duration::from_secs(110);
    let exit =
        crate::profile_auto_stopped_service::ChildExitWait::open(&child, Duration::from_millis(20));
    loop {
        if output.metadata().map_err(|_| refuse())?.len() > 16384 || Instant::now() >= deadline {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse());
            }
            Ok(None) => exit.wait(&[], deadline),
        }
    }
    install.revalidate().map_err(|_| refuse())?;
    output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
    let mut raw = Vec::new();
    output
        .take(16385)
        .read_to_end(&mut raw)
        .map_err(|_| refuse())?;
    if raw.is_empty() || raw.len() > 16384 {
        return Err(refuse());
    }
    let value: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| refuse())?;
    if value["schema"]
        != if preretire {
            "aegis_auto_v2_cold_stale_preretire_v1"
        } else {
            "aegis_auto_v2_cold_stale_verification_v1"
        }
        || value["retained_root"].as_str() != root.to_str()
        || value["prior_intent_sha256"].as_str() != Some(prior_sha)
        || preretire && value["old_pointer_state"].as_str().is_none()
        || !preretire && value["prior_pointer_retirement_sha256"].as_str().is_none()
        || value["client_actors_absent"] != true
        || value["jobs_absent"] != true
        || value["cgroups_empty"] != true
        || value["stop_intent_absent"] != true
        || value["no_client_grant"] != true
    {
        return Err(refuse());
    }
    Ok(value)
}

/// Acquires fresh exclusive Install then Guard locks and repeats the complete
/// inherited child proof. This never accepts a caller-supplied proof document.
#[cfg(target_os = "linux")]
fn verify_cold_stale_fresh_mode(root: &Path, prior_sha: &str, preretire: bool) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    if prior_sha.len() != 64
        || !prior_sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    let install = crate::profile_auto_stopped_service::InstallLock::acquire_existing_for_recovery()
        .map_err(|_| refuse())?;
    let guard = cold_fresh_guard_lock()?;
    let first = cold_stale_proof_from_fresh_locks(&install, &guard, root, prior_sha, preretire)?;
    let second = cold_stale_proof_from_fresh_locks(&install, &guard, root, prior_sha, preretire)?;
    install.revalidate().map_err(|_| refuse())?;
    let named = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let held = recovery_stat(guard.as_raw_fd())?;
    let current = recovery_open_at(
        named.as_raw_fd(),
        "device-guard.conf.lock",
        libc::O_RDONLY,
        0,
    )?;
    let fresh = recovery_stat(current.as_raw_fd())?;
    if first != second
        || held.st_dev != fresh.st_dev
        || held.st_ino != fresh.st_ino
        || first["schema"]
            != if preretire {
                "aegis_auto_v2_cold_stale_preretire_v1"
            } else {
                "aegis_auto_v2_cold_stale_verification_v1"
            }
        || first["prior_intent_sha256"] != prior_sha
        || first["client_actors_absent"] != true
        || first["jobs_absent"] != true
        || first["cgroups_empty"] != true
        || first["stop_intent_absent"] != true
        || first["no_client_grant"] != true
    {
        return Err(refuse());
    }
    serde_json::to_vec(&first).map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_cold_stale_fresh(root: &Path, prior_sha: &str) -> Result<Vec<u8>> {
    verify_cold_stale_fresh_mode(root, prior_sha, false)
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_cold_stale_preretire_fresh(root: &Path, prior_sha: &str) -> Result<Vec<u8>> {
    verify_cold_stale_fresh_mode(root, prior_sha, true)
}

/// Archive a single unpublished attempt directory under fresh Install→Guard.
/// Each proof is a child of the held locks; no JSON from Python is authority.
#[cfg(target_os = "linux")]
pub(crate) fn retire_cold_unpublished_stage(root: &Path, prior_sha: &str) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    if prior_sha.len() != 64
        || !prior_sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    let install = crate::profile_auto_stopped_service::InstallLock::acquire_existing_for_recovery()
        .map_err(|_| refuse())?;
    let guard = cold_fresh_guard_lock()?;
    let first = cold_stale_proof_from_fresh_locks(&install, &guard, root, prior_sha, true)?;
    let second = cold_stale_proof_from_fresh_locks(&install, &guard, root, prior_sha, true)?;
    if first != second
        || first["schema"] != "aegis_auto_v2_cold_stale_preretire_v1"
        || first["client_actors_absent"] != true
        || first["jobs_absent"] != true
        || first["cgroups_empty"] != true
        || first["stop_intent_absent"] != true
        || first["no_client_grant"] != true
    {
        return Err(refuse());
    }
    let result =
        installer_v2_generation::retire_cold_unpublished_stage(root, prior_sha, &first, &install)?;
    let after = cold_stale_proof_from_fresh_locks(&install, &guard, root, prior_sha, true)?;
    if after["schema"] != first["schema"]
        || after["current_boot_id"] != first["current_boot_id"]
        || after["prior_intent_sha256"] != first["prior_intent_sha256"]
        || after["original_intent_sha256"] != first["original_intent_sha256"]
        || after["deny_policy_sha256"] != first["deny_policy_sha256"]
        || after["guard30_sha256"] != first["guard30_sha256"]
        || after["client_actors_absent"] != true
        || after["jobs_absent"] != true
        || after["cgroups_empty"] != true
        || after["stop_intent_absent"] != true
        || after["no_client_grant"] != true
    {
        return Err(refuse());
    }
    install.revalidate().map_err(|_| refuse())?;
    let parent = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let current = recovery_open_at(
        parent.as_raw_fd(),
        "device-guard.conf.lock",
        libc::O_RDONLY,
        0,
    )?;
    let held = recovery_stat(guard.as_raw_fd())?;
    let fresh = recovery_stat(current.as_raw_fd())?;
    if held.st_dev != fresh.st_dev || held.st_ino != fresh.st_ino {
        return Err(refuse());
    }
    Ok(result)
}

/// Retire an authenticated old B generation/current pointer, or its exact
/// finalized-stopped unsealed inverse, under a fresh denied boot. Archives are
/// durable before each source-bound unlink; no old lease or BOOT grant follows.
#[cfg(target_os = "linux")]
pub(crate) fn retire_cold_prior_pointer(root: &Path, prior_sha: &str) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    if prior_sha.len() != 64
        || !prior_sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    let install = crate::profile_auto_stopped_service::InstallLock::acquire_existing_for_recovery()
        .map_err(|_| refuse())?;
    let guard = cold_fresh_guard_lock()?;
    let first = cold_stale_proof_from_fresh_locks(&install, &guard, root, prior_sha, true)?;
    let second = cold_stale_proof_from_fresh_locks(&install, &guard, root, prior_sha, true)?;
    if first != second
        || first["schema"] != "aegis_auto_v2_cold_stale_preretire_v1"
        || first["client_actors_absent"] != true
        || first["jobs_absent"] != true
        || first["cgroups_empty"] != true
        || first["stop_intent_absent"] != true
        || first["no_client_grant"] != true
    {
        return Err(refuse());
    }
    let result =
        installer_v2_generation::retire_cold_prior_pointer(root, prior_sha, &first, &install)?;
    let after = cold_stale_proof_from_fresh_locks(&install, &guard, root, prior_sha, true)?;
    for key in [
        "schema",
        "current_boot_id",
        "prior_intent_sha256",
        "original_intent_sha256",
        "old_pointer_state",
        "new_candidate_sha256",
        "deny_policy_sha256",
        "guard30_sha256",
        "no_client_grant",
    ] {
        if after[key] != first[key] {
            return Err(refuse());
        }
    }
    if after["client_actors_absent"] != true
        || after["jobs_absent"] != true
        || after["cgroups_empty"] != true
        || after["stop_intent_absent"] != true
    {
        return Err(refuse());
    }
    install.revalidate().map_err(|_| refuse())?;
    let parent = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let current = recovery_open_at(
        parent.as_raw_fd(),
        "device-guard.conf.lock",
        libc::O_RDONLY,
        0,
    )?;
    let held = recovery_stat(guard.as_raw_fd())?;
    let fresh = recovery_stat(current.as_raw_fd())?;
    if held.st_dev != fresh.st_dev || held.st_ino != fresh.st_ino {
        return Err(refuse());
    }
    Ok(result)
}

/// Explicit console-only native retirement. The Python caller releases its
/// original OFDs first; this command takes fresh exclusive Install then Guard
/// locks and obtains a new read-only proof from its own child under them.
#[cfg(target_os = "linux")]
pub(crate) fn retire_cold_successor(root: &Path, intent_sha: &str) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let install = crate::profile_auto_stopped_service::InstallLock::acquire_existing_for_recovery()
        .map_err(|_| refuse())?;
    let guard = cold_fresh_guard_lock()?;
    let parent = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let named = recovery_open_at(
        parent.as_raw_fd(),
        "device-guard.conf.lock",
        libc::O_RDONLY,
        0,
    )?;
    let guard_id = recovery_stat(guard.as_raw_fd())?;
    if (guard_id.st_dev, guard_id.st_ino) != {
        let current = recovery_stat(named.as_raw_fd())?;
        (current.st_dev, current.st_ino)
    } {
        return Err(refuse());
    }
    let proof = cold_proof_from_fresh_locks(&install, &guard, root)?;
    let result =
        installer_v2_generation::retire_cold_successor(root, intent_sha, &proof, &install)?;
    let again = cold_proof_from_fresh_locks(&install, &guard, root)?;
    if proof != again {
        return Err(refuse());
    }
    let named = recovery_open_at(
        parent.as_raw_fd(),
        "device-guard.conf.lock",
        libc::O_RDONLY,
        0,
    )?;
    let current = recovery_stat(named.as_raw_fd())?;
    if (guard_id.st_dev, guard_id.st_ino) != (current.st_dev, current.st_ino) {
        return Err(refuse());
    }
    install.revalidate().map_err(|_| refuse())?;
    Ok(result)
}

/// Complete only the unique predecessor intent-only directory after the
/// pointer's current-boot denied retirement. The native child proves the
/// old chain and current kernel state while the fresh Install→Guard locks
/// remain held; the historical head is append-only and grants nothing.
#[cfg(target_os = "linux")]
pub(crate) fn complete_cold_orphan_head(root: &Path, prior_sha: &str) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let install = crate::profile_auto_stopped_service::InstallLock::acquire_existing_for_recovery()
        .map_err(|_| refuse())?;
    let guard = cold_fresh_guard_lock()?;
    let first = cold_stale_proof_from_fresh_locks(&install, &guard, root, prior_sha, false)?;
    let second = cold_stale_proof_from_fresh_locks(&install, &guard, root, prior_sha, false)?;
    if first != second
        || first["schema"] != "aegis_auto_v2_cold_stale_verification_v1"
        || first["prior_pointer_retirement_sha256"].as_str().is_none()
        || first["client_actors_absent"] != true
        || first["jobs_absent"] != true
        || first["cgroups_empty"] != true
        || first["stop_intent_absent"] != true
        || first["no_client_grant"] != true
    {
        return Err(refuse());
    }
    let result =
        installer_v2_generation::complete_cold_orphan_head(root, prior_sha, &first, &install)?;
    let after = cold_stale_proof_from_fresh_locks(&install, &guard, root, prior_sha, false)?;
    for key in [
        "schema",
        "current_boot_id",
        "prior_boot_id",
        "prior_intent_sha256",
        "original_intent_sha256",
        "new_candidate_sha256",
        "retained_root",
        "prior_pointer_retirement_sha256",
        "deny_policy_sha256",
        "guard30_sha256",
        "client_actors_absent",
        "jobs_absent",
        "cgroups_empty",
        "stop_intent_absent",
        "no_client_grant",
    ] {
        if after[key] != first[key] {
            return Err(refuse());
        }
    }
    install.revalidate().map_err(|_| refuse())?;
    let parent = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let named = recovery_open_at(
        parent.as_raw_fd(),
        "device-guard.conf.lock",
        libc::O_RDONLY,
        0,
    )?;
    let held = recovery_stat(guard.as_raw_fd())?;
    let fresh = recovery_stat(named.as_raw_fd())?;
    if (held.st_dev, held.st_ino) != (fresh.st_dev, fresh.st_ino) {
        return Err(refuse());
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_cold_prebind(root: &Path, intent_sha: &str) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let install = crate::profile_auto_stopped_service::InstallLock::acquire_existing_for_recovery()
        .map_err(|_| refuse())?;
    let guard = cold_fresh_guard_lock()?;
    let parent = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let named = recovery_open_at(
        parent.as_raw_fd(),
        "device-guard.conf.lock",
        libc::O_RDONLY,
        0,
    )?;
    let before = recovery_stat(guard.as_raw_fd())?;
    let current = recovery_stat(named.as_raw_fd())?;
    if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino) {
        return Err(refuse());
    }
    let proof = cold_proof_from_fresh_locks(&install, &guard, root)?;
    let result = installer_v2_generation::verify_cold_prebind(root, intent_sha, &proof)?;
    let again = cold_proof_from_fresh_locks(&install, &guard, root)?;
    if proof != again {
        return Err(refuse());
    }
    let named = recovery_open_at(
        parent.as_raw_fd(),
        "device-guard.conf.lock",
        libc::O_RDONLY,
        0,
    )?;
    let after = recovery_stat(named.as_raw_fd())?;
    if (before.st_dev, before.st_ino, before.st_mode) != (after.st_dev, after.st_ino, after.st_mode)
    {
        return Err(refuse());
    }
    install.revalidate().map_err(|_| refuse())?;
    Ok(result)
}

/// Registrar variant: the caller holds the same Install then Guard OFDs across
/// this admission and the subsequent B site publication.
#[cfg(target_os = "linux")]
pub(crate) fn verify_cold_prebind_inherited(
    install_fd: std::os::fd::RawFd,
    guard_fd: std::os::fd::RawFd,
    root: &Path,
    intent_sha: &str,
) -> Result<Vec<u8>> {
    let first_raw = verify_cold_retired_successor_inherited(install_fd, guard_fd, root)?;
    let first: serde_json::Value = serde_json::from_slice(&first_raw).map_err(|_| refuse())?;
    installer_v2_generation::verify_cold_prebind(root, intent_sha, &first)
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_cold_transition_inherited(
    install_fd: std::os::fd::RawFd,
    guard_fd: std::os::fd::RawFd,
    root: &Path,
    intent_sha: &str,
) -> Result<Vec<u8>> {
    let raw = verify_cold_retired_successor_inherited(install_fd, guard_fd, root)?;
    let proof: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| refuse())?;
    let exact_hex = |value: &serde_json::Value| {
        value.as_str().is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    };
    if proof["package_state"] != "new_exact"
        || proof["site_state"] != "b_complete"
        || proof["observer_state"] != "b_ready"
        || proof["quiesce_state"] != "post"
        || !exact_hex(&proof["package_repair_receipt_sha256"])
        || !exact_hex(&proof["site_readback_sha256"])
        || !exact_hex(&proof["source_config_sha256"])
        || !exact_hex(&proof["observer_ready_sha256"])
    {
        return Err(refuse());
    }
    let result = installer_v2_generation::verify_cold_prebind(root, intent_sha, &proof)?;
    if installer_v2_generation::cold_stale_source(root).is_ok() {
        installer_v2_generation::verify_cold_rollover_transition_phase(root, intent_sha, &proof)?;
    }
    Ok(result)
}

/// Fresh current-boot cold first-arm handoff after the transition unit has
/// independently revalidated deny. The returned bytes locate an ordinary V2
/// Prepare; this call never Starts the client or grants a route.
#[cfg(target_os = "linux")]
pub(crate) fn begin_cold_first_arm(root: &Path) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let install = crate::profile_auto_stopped_service::InstallLock::acquire_existing_for_recovery()
        .map_err(|_| refuse())?;
    let guard = cold_fresh_guard_lock()?;
    let before = recovery_stat(guard.as_raw_fd())?;
    let proof = cold_proof_from_fresh_locks(&install, &guard, root)?;
    let result = installer_v2_generation::begin_cold_first_arm(root, &proof, &install)?;
    let again = cold_proof_from_fresh_locks(&install, &guard, root)?;
    if proof != again {
        return Err(refuse());
    }
    let guardian = recovery_chain(&["var", "lib", "aegis-install", "client"], Some(0o700))?;
    let named = recovery_open_at(
        guardian.as_raw_fd(),
        "device-guard.conf.lock",
        libc::O_RDONLY,
        0,
    )?;
    let after = recovery_stat(named.as_raw_fd())?;
    if (before.st_dev, before.st_ino, before.st_mode) != (after.st_dev, after.st_ino, after.st_mode)
    {
        return Err(refuse());
    }
    install.revalidate().map_err(|_| refuse())?;
    Ok(result)
}

/// Idempotent readback for a console retry after the ordinary activation has
/// sealed its generation but before the Python cold phase was durably closed.
/// The historical cold receipt locates the generation; the existing active
/// inspector independently proves the live stage and its present source.
#[cfg(target_os = "linux")]
pub(crate) fn verify_cold_active(root: &Path, intent_sha: &str) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    let (report, seal_sha, prebind_sha, registration_sha) =
        installer_v2_generation::cold_active_lineage(root, intent_sha)?;
    if report["stage"]["mode"] != "wide-redirect-safe" && report["stage"]["mode"] != "full-wide-tun"
    {
        return Err(refuse());
    }
    let path = report["stage"]["path"].as_str().ok_or_else(refuse)?;
    let observed = inspect_active_finalized_stage_held(Path::new(path), &lock)?;
    let fresh: serde_json::Value = serde_json::from_slice(&observed.bytes).map_err(|_| refuse())?;
    if fresh != report {
        return Err(refuse());
    }
    installer_v2_generation::verify_boot_source(&report)?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    verify_current_active_pointer(control.as_raw_fd(), &fresh)?;
    let (after, after_seal, after_prebind, after_registration) =
        installer_v2_generation::cold_active_lineage(root, intent_sha)?;
    if after != fresh
        || after_seal != seal_sha
        || after_prebind != prebind_sha
        || after_registration != registration_sha
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_cold_active_verification_v1",
        "boot_id": report["terminal"]["boot_id"],
        "stage": path,
        "active_generation_sha256": seal_sha,
        "intent_sha256": intent_sha,
        "cold_prebind_sha256": prebind_sha,
        "candidate_sha256": report["input"]["candidate_sha256"],
        "private_unit": report["terminal"]["private_unit"],
        "terminal_registration_complete_sha256": registration_sha,
    }))
    .map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
fn passive_retired_readback(
    install: &crate::profile_auto_stopped_service::InheritedInstallReadLock,
    history: &installer_v2_generation::SuccessorHistory,
    deadline: std::time::Instant,
) -> Result<serde_json::Value> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    if Instant::now() >= deadline {
        return Err(refuse());
    }
    install.revalidate().map_err(|_| refuse())?;
    let root = Path::new(
        history.stopped["input"]["public_payload_root"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    if root.parent() != Some(Path::new("/var/lib/aegis-auto/releases")) {
        return Err(refuse());
    }
    let name = root
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(refuse)?;
    let release = recovery_chain(&["var", "lib", "aegis-auto", "releases", name], Some(0o700))?;
    let scripts = recovery_directory(release.as_raw_fd(), "scripts", None)?;
    let old_lib = recovery_directory(scripts.as_raw_fd(), "lib", None)?;
    let old = recovery_open_at(
        old_lib.as_raw_fd(),
        "aegis_installer_auto_v2.py",
        libc::O_RDONLY,
        0,
    )?;
    let installed_dir = recovery_chain(&["usr", "local", "lib", "aegis", "helpers", "lib"], None)?;
    let current = recovery_open_at(
        installed_dir.as_raw_fd(),
        "aegis_installer_auto_v2.py",
        libc::O_RDONLY,
        0,
    )?;
    let before = recovery_stat(current.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o500
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || recovery_file_hash(old.as_raw_fd(), 4 << 20)?.1
            != recovery_file_hash(current.as_raw_fd(), 4 << 20)?.1
    {
        return Err(refuse());
    }
    let output =
        unsafe { libc::memfd_create(c"aegis-passive-retired-read".as_ptr(), libc::MFD_CLOEXEC) };
    if output < 0 {
        return Err(refuse());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(output) };
    if Instant::now() >= deadline {
        return Err(refuse());
    }
    let mut child = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-B",
            "/usr/local/lib/aegis/helpers/lib/aegis_installer_auto_v2.py",
            "passive-retired-readback",
        ])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| refuse())?;
    // S9: wake on the child's exit through its pidfd under the same bound.
    let exit =
        crate::profile_auto_stopped_service::ChildExitWait::open(&child, Duration::from_millis(20));
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                    return Err(refuse());
                }
                break;
            }
            Err(_) => {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse());
            }
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        exit.wait(&[], deadline);
    }
    if output.metadata().map_err(|_| refuse())?.len() > 16384 {
        return Err(refuse());
    }
    output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
    let mut bytes = Vec::new();
    output
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    if bytes.len() > 16384
        || recovery_file_hash(current.as_raw_fd(), 4 << 20)?.1
            != recovery_file_hash(old.as_raw_fd(), 4 << 20)?.1
    {
        return Err(refuse());
    }
    install.revalidate().map_err(|_| refuse())?;
    if Instant::now() >= deadline {
        return Err(refuse());
    }
    serde_json::from_slice(&bytes).map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_retired_passive_successor_inherited(
    raw_lock_fd: std::os::fd::RawFd,
) -> Result<Vec<u8>> {
    use crate::profile_auto_stopped_service::InheritedInstallReadLock;
    use std::time::{Duration, Instant};
    // The package hook has a 30-second outer limit. Share one earlier cutoff
    // across admission, history verification, the Python child, and readback.
    let deadline = Instant::now() + Duration::from_secs(25);
    let lock = InheritedInstallReadLock::admit(raw_lock_fd).map_err(|_| refuse())?;
    let history = installer_v2_generation::successor_history()?;
    if Instant::now() >= deadline {
        return Err(refuse());
    }
    if history.stopped["stage"]["mode"] != "socks-only" {
        return Err(refuse());
    }
    let readback = passive_retired_readback(&lock, &history, deadline)?;
    let result = installer_v2_generation::verify_retired_passive_successor(&history, &readback)?;
    lock.revalidate().map_err(|_| refuse())?;
    if Instant::now() >= deadline {
        return Err(refuse());
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_passive_retirement_intent_inherited(
    raw_lock_fd: std::os::fd::RawFd,
) -> Result<Vec<u8>> {
    use crate::profile_auto_stopped_service::InheritedInstallReadLock;
    let lock = InheritedInstallReadLock::admit(raw_lock_fd).map_err(|_| refuse())?;
    let history = installer_v2_generation::successor_history()?;
    let result = installer_v2_generation::verify_passive_retirement_intent(&history)?;
    lock.revalidate().map_err(|_| refuse())?;
    Ok(result)
}

/// Recovery is limited to an already terminal, pre-activation rollback.  The
/// caller must retain this same install lock through executable restoration.
#[cfg(target_os = "linux")]
fn admit_rolled_back_stage(
    path: &Path,
    lock: &crate::profile_auto_stopped_service::InstallLock,
) -> Result<(u64, u64)> {
    use crate::profile_auto_publication::linux as publication;
    use crate::profile_auto_unit_namespace as unit_namespace;
    lock.revalidate().map_err(|_| refuse())?;
    let guard = authority::StageGuard::admit(durable::Store::reopen(path, 0)?)?;
    if guard.header.phase != Phase::RolledBack
        || guard.header.capture_started
        || guard.header.pending.is_some()
        || guard.header.unit_pending.is_some()
    {
        return Err(refuse());
    }
    let stage_id = guard.store.identity()?;
    let original_namespace = unit_binding::read(&guard, false)?;
    let forward = unit_store::forward_history(&guard)?;
    let restored = unit_store::restoration_history(&guard)?;
    let state = v2_state_reader::PublishedState;
    let context =
        store_context::RootContext::from_stage_with_lock(guard, &state, Some(lock), None, None)
            .map_err(|_| refuse())?;
    if forward.is_empty() && restored.is_empty() {
        let current = unit_namespace::UnitNamespaceSnapshot::capture(lock).map_err(|_| refuse())?;
        if !unit_namespace::same_role_contents(
            &unit_namespace::inspect_record_roles(&original_namespace).map_err(|_| refuse())?,
            &unit_namespace::inspect_record_roles(current.record()).map_err(|_| refuse())?,
        ) {
            return Err(refuse());
        }
    } else {
        if forward.len() != 3 || restored.len() != 3 {
            return Err(refuse());
        }
        unit_store::authenticate_complete_restored_policy(&context)?;
        let manager = unit_store::sealed_restored_manager_receipt(&context)?;
        let current = unit_namespace::UnitNamespaceSnapshot::capture(lock).map_err(|_| refuse())?;
        if !unit_namespace::same_role_contents(
            &unit_namespace::inspect_record_roles(manager.restored_namespace())
                .map_err(|_| refuse())?,
            &unit_namespace::inspect_record_roles(current.record()).map_err(|_| refuse())?,
        ) {
            return Err(refuse());
        }
    }
    let guard = context.stage_cell().borrow();
    guard.verify_completed_withdrawals()?;
    // Rollback can begin after any one of the three publication steps.  Each
    // touched role needs its own sealed rollback or withdrawal proof; a role
    // with no publication record must still match its captured original.
    for (role, target_path) in [
        ("config", &guard.header.config_root),
        ("state", &guard.header.state_dir),
        ("metadata", &guard.header.metadata_dir),
    ] {
        let role_records: Vec<_> = guard
            .header
            .current_records
            .iter()
            .filter(|(_, seal)| seal.role == role)
            .collect();
        if let Some(active) = guard.header.active_records.get(role) {
            let seal = guard
                .header
                .current_records
                .get(active)
                .ok_or_else(refuse)?;
            if seal.phase != "rollback" || seal.role != role {
                return Err(refuse());
            }
            let record = guard.publication_record(role)?;
            let target = publication::Target::open(target_path).map_err(|_| refuse())?;
            let receipt =
                publication::reopen_own_receipt(&target, &record).map_err(|_| refuse())?;
            publication::revalidate_current_receipt(&target, &receipt).map_err(|_| refuse())?;
        } else if role_records.is_empty() {
            guard.revalidate_untouched_original_role(role)?;
        } else if role_records
            .iter()
            .filter(|(leaf, seal)| {
                seal.phase == "rollback"
                    && leaf.file_name() == Some(std::ffi::OsStr::new("withdrawal-receipt.json"))
            })
            .count()
            != 1
        {
            return Err(refuse());
        }
    }
    lock.revalidate().map_err(|_| refuse())?;
    guard.store.revalidate()?;
    Ok(stage_id)
}

#[cfg(target_os = "linux")]
fn fresh_first_package_no_effects(stage: &authority::StageGuard, phase: Phase) -> Result<()> {
    let h = &stage.header;
    if h.phase != phase
        || h.mode != AutoMode::SocksOnly
        || h.capture_started
        || h.pending.is_some()
        || h.unit_pending.is_some()
        || !h.current_records.is_empty()
        || !h.active_records.is_empty()
        || !h.state_records.is_empty()
        || !h.namespace_records.is_empty()
        || !h.unit_records.is_empty()
        || !h.unit_role_records.is_empty()
        || !h.unit_forward_transitions.is_empty()
        || !h.unit_restorations.is_empty()
        || h.new_unit_namespace.is_some()
        || h.unit_policy_recipe.is_some()
        || h.unit_restored_manager.is_some()
        || h.runtime_binding.is_some()
        || h.installed_receipt_recipe.is_some()
        || h.service_uid.is_some()
        || h.service_gid.is_some()
        || h.service_was_active.is_some()
        || stage.manifest.logical_bundle.as_deref()
            != Some(Path::new("/var/lib/aegis-auto/control/fresh-passive-input"))
    {
        return Err(refuse());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn fresh_first_package_stage_path(path: &Path) -> bool {
    path.parent() == Some(Path::new("/run/aegis-installer-config-snapshots"))
        && path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| {
                name.starts_with(".auto-")
                    && name.len() == 38
                    && name[6..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
}

#[cfg(target_os = "linux")]
fn fresh_first_packaged_source_facts(
    stage: &authority::StageGuard,
    pointer_leaf: &str,
    archived: bool,
) -> Result<(String, PathBuf, Vec<u8>, Vec<u8>)> {
    use std::os::fd::AsRawFd;
    let (candidate_path, source_root, candidate_sha, _) =
        receipt_store::prepare_handoff_facts(stage)?;
    if candidate_path != source_root.join("bin/aegis-client")
        || source_root.parent() != Some(Path::new("/var/lib/aegis-auto/releases"))
    {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    if archived {
        recovery_absent(control.as_raw_fd(), "current.json")?;
    } else if pointer_leaf != "current.json" {
        return Err(refuse());
    }
    for leaf in [
        "prepare-current.json",
        "prepare-completed.json",
        "prepare-stage-created.json",
        "fresh-first-arm-intent.json",
        "generation-active-current.json",
        "generation-stopped-current.json",
        "generation-successor-current.json",
        "passive-package-preinst.json",
        "passive-successor-retirement-intent.json",
    ] {
        recovery_absent(control.as_raw_fd(), leaf)?;
    }
    let pointer_raw = read_fresh_rollback_leaf(control.as_raw_fd(), pointer_leaf, 8192)?;
    let pointer: InstallerRecoveryPointer =
        serde_json::from_slice(&pointer_raw).map_err(|_| refuse())?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| refuse())?;
    if !recovery_pointer_schema(&pointer)
        || pointer.status != "pending"
        || pointer.stage != stage.store.path()
        || pointer.boot_id != boot.trim()
        || pointer.installed_binary != "/usr/local/bin/aegis-client"
        || pointer.candidate_sha256 != candidate_sha
    {
        return Err(refuse());
    }
    let previous = pointer.previous_binary.as_ref().ok_or_else(refuse)?;
    if !previous.name.starts_with("backup-")
        || previous.name.len() != 43
        || !previous.name.ends_with(".bin")
        || !previous.name.as_bytes()[7..39]
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !inspected_hex64(&previous.sha256)
        // A pristine packaged install starts with this same package-owned
        // binary already installed. A distinct old binary is an upgrade,
        // outside this first-install retirement proof.
        || previous.sha256 != candidate_sha
        || !matches!(previous.mode, 0o555 | 0o755)
    {
        return Err(refuse());
    }
    let installed_dir = recovery_chain(&["usr", "local", "bin"], None)?;
    let installed = recovery_open_at(installed_dir.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    let installed_stat = recovery_stat(installed.as_raw_fd())?;
    let backup = recovery_open_at(control.as_raw_fd(), &previous.name, libc::O_RDONLY, 0)?;
    let backup_stat = recovery_stat(backup.as_raw_fd())?;
    if installed_stat.st_mode != libc::S_IFREG | previous.mode
        || installed_stat.st_uid != 0
        || installed_stat.st_gid != 0
        || installed_stat.st_nlink != 1
        || backup_stat.st_mode != libc::S_IFREG | 0o600
        || backup_stat.st_uid != 0
        || backup_stat.st_gid != 0
        || backup_stat.st_nlink != 1
        || !recovery_backup_identity(previous, &pointer.schema, &backup_stat)
        || recovery_file_hash(installed.as_raw_fd(), 256 << 20)?
            != (previous.size, previous.sha256.clone())
        || recovery_file_hash(backup.as_raw_fd(), 256 << 20)?
            != (previous.size, previous.sha256.clone())
    {
        return Err(refuse());
    }
    let intent_raw =
        read_fresh_rollback_leaf(control.as_raw_fd(), "fresh-passive-intent.json", 16384)?;
    let intent: serde_json::Value = serde_json::from_slice(&intent_raw).map_err(|_| refuse())?;
    let source = intent.get("source").ok_or_else(refuse)?;
    if intent.as_object().is_none_or(|value| {
        value.len() != 8
            || [
                "schema",
                "boot_id",
                "source",
                "original_bundle",
                "bundle_files",
                "options_sha256",
                "external_refs",
                "fresh_origin",
            ]
            .iter()
            .any(|key| !value.contains_key(*key))
    }) || intent["schema"] != "aegis_auto_v2_fresh_passive_intent_v1"
        || intent["boot_id"] != pointer.boot_id
        || intent["fresh_origin"] != "packaged"
        || source.as_object().is_none_or(|value| {
            value.len() != 6
                || [
                    "public_payload_root",
                    "fresh_origin",
                    "package_sha256",
                    "source_tree_sha256",
                    "candidate_sha256",
                    "installer_sha256",
                ]
                .iter()
                .any(|key| !value.contains_key(*key))
        })
        || source["fresh_origin"] != "packaged"
        || source["public_payload_root"] != source_root.to_string_lossy().as_ref()
        || source["candidate_sha256"] != candidate_sha
        || source["package_sha256"]
            .as_str()
            .is_none_or(|value| !inspected_hex64(value))
        || source["source_tree_sha256"]
            .as_str()
            .is_none_or(|value| !inspected_hex64(value))
        || source["installer_sha256"]
            .as_str()
            .is_none_or(|value| !inspected_hex64(value))
        || intent["options_sha256"]
            .as_str()
            .is_none_or(|value| !inspected_hex64(value))
    {
        return Err(refuse());
    }
    let ready_raw =
        read_fresh_rollback_leaf(control.as_raw_fd(), "fresh-passive-ready.json", 8192)?;
    let ready: serde_json::Value = serde_json::from_slice(&ready_raw).map_err(|_| refuse())?;
    if ready.as_object().is_none_or(|value| {
        value.len() != 4
            || ["schema", "boot_id", "candidate_sha256", "intent_sha256"]
                .iter()
                .any(|key| !value.contains_key(*key))
    }) || ready["schema"] != "aegis_auto_v2_fresh_passive_ready_v1"
        || ready["boot_id"] != pointer.boot_id
        || ready["candidate_sha256"] != candidate_sha
        || ready["intent_sha256"] != digest(&intent_raw)
        || read_fresh_rollback_leaf(control.as_raw_fd(), "v2-enabled", 128)?
            != b"{\"schema\":\"aegis_installer_auto_v2_enabled_v1\"}\n"
    {
        return Err(refuse());
    }
    Ok((candidate_sha, source_root, pointer_raw, intent_raw))
}

/// Read-only proof for the narrowly scoped first packaged installation that
/// rolled back before runtime binding or any publication. The caller retains
/// the original shell InstallLock; this observer cannot turn that OFD into a
/// worker lock or authorize an effect. The old candidate must have completed
/// recover-current before this proof is available.
#[cfg(target_os = "linux")]
pub(crate) fn verify_fresh_rolled_back_inherited(
    path: &Path,
    archive_leaf: &str,
    lock_fd: i32,
) -> Result<Vec<u8>> {
    use crate::profile_auto_unit_namespace as unit_namespace;

    let lock = crate::profile_auto_stopped_service::InheritedInstallReadLock::admit(lock_fd)
        .map_err(|_| refuse())?;
    if !fresh_first_package_stage_path(path)
        || archive_leaf.len() != 46
        || !archive_leaf.starts_with("archived-")
        || !archive_leaf.ends_with(".json")
        || !archive_leaf.as_bytes()[9..41]
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    let stage = authority::StageGuard::admit(durable::Store::reopen(path, 0)?)?;
    // Keep the existing publication, mutation and stage-root fences through
    // the entire readback. This mints no owner marker and performs no effect.
    let _stage_fences = stage
        .store
        .begin_owner_marker_fence()
        .map_err(|_| refuse())?;
    fresh_first_package_no_effects(&stage, Phase::RolledBack)?;
    stage.revalidate_originals()?;
    for role in ["config", "state", "metadata"] {
        stage.revalidate_untouched_original_role(role)?;
    }
    let original = unit_binding::read(&stage, false)?;
    let observed = unit_namespace::UnitNamespaceSnapshot::capture_inherited_read_only(&lock)
        .map_err(|_| refuse())?;
    let original_roles = unit_namespace::inspect_record_roles(&original).map_err(|_| refuse())?;
    let observed_roles =
        unit_namespace::inspect_record_roles(observed.record()).map_err(|_| refuse())?;
    if !unit_namespace::same_role_contents(&original_roles, &observed_roles) {
        return Err(refuse());
    }
    let roles_sha = digest(&serde_json::to_vec(&original_roles).map_err(|_| refuse())?);
    let stage_id = stage.store.identity()?;
    let (candidate_sha, source_root, pointer_raw, intent_raw) =
        fresh_first_packaged_source_facts(&stage, archive_leaf, true)?;
    // The separate Python archiver re-admits the complete private intent and
    // all effect absences. This certificate contains only source-bound hashes.
    stage.store.revalidate()?;
    lock.revalidate().map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_fresh_rolled_back_proof_v1",
        "stage": path,
        "stage_device": stage_id.0,
        "stage_inode": stage_id.1,
        "candidate_sha256": candidate_sha,
        "pointer_archive": archive_leaf,
        "pointer_sha256": digest(&pointer_raw),
        "fresh_intent_sha256": digest(&intent_raw),
        "public_payload_root": source_root,
        "old_unit_roles_sha256": roles_sha,
    }))
    .map_err(|_| refuse())
}

/// Explicit recovery for a first packaged SOCKS install interrupted after
/// Prepare and before Bind. This actor owns a NEW InstallLock; it cannot use
/// the shell's read-only inherited lock as mutation authority. The only
/// durable changes are the Prepared→RolledBack Header transition and an
/// atomic rename of the same protected pointer into its deterministic archive.
/// An already renamed pointer is admitted only after the same complete proof.
#[cfg(target_os = "linux")]
pub(crate) fn rollback_fresh_prebind(path: &Path, incoming_root: &Path) -> Result<()> {
    use crate::profile_auto_unit_namespace as unit_namespace;
    use std::os::fd::AsRawFd;

    if !fresh_first_package_stage_path(path) {
        return Err(refuse());
    }
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_for_recovery()
        .map_err(|_| refuse())?;
    // This command is independently callable; it cannot mutate a stage that
    // the later passive-abort transaction has already admitted for retirement.
    let auto_root = recovery_chain(&["var", "lib", "aegis-auto"], Some(0o700))?;
    recovery_absent(auto_root.as_raw_fd(), "fresh-passive-abort-current.json")?;
    let actor_sha = installer_v2_generation::verify_fresh_prebind_recovery_actor(incoming_root)?;
    let mut stage = authority::StageGuard::admit(durable::Store::reopen(path, 0)?)?;
    let phase = stage.header.phase;
    if !matches!(phase, Phase::Prepared | Phase::RolledBack) {
        return Err(refuse());
    }
    fresh_first_package_no_effects(&stage, phase)?;
    let stage_root = stage.store.duplicate_root()?;
    for leaf in ["receipts", "records"] {
        recovery_absent(stage_root.as_raw_fd(), leaf)?;
    }
    stage.revalidate_originals()?;
    for role in ["config", "state", "metadata"] {
        stage.revalidate_untouched_original_role(role)?;
    }
    let old_namespace = unit_binding::read(&stage, false)?;
    if old_namespace.is_absent() {
        return Err(refuse());
    }
    let observed = unit_namespace::UnitNamespaceSnapshot::reopen(&old_namespace, &lock)
        .map_err(|_| refuse())?;
    let original_roles =
        unit_namespace::inspect_record_roles(&old_namespace).map_err(|_| refuse())?;
    let current_roles =
        unit_namespace::inspect_record_roles(observed.record()).map_err(|_| refuse())?;
    if !unit_namespace::same_role_contents(&original_roles, &current_roles) {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), "fresh-passive-abort-current.json")?;
    let current_absent = recovery_absent(control.as_raw_fd(), "current.json").is_ok();
    let archive_names = fresh_prebind_archives(control.as_raw_fd())?;
    if archive_names.len() > 1
        || (!archive_names.is_empty() && phase != Phase::RolledBack)
        || (current_absent && phase != Phase::RolledBack)
    {
        return Err(refuse());
    }
    let pointer_leaf = if current_absent {
        archive_names.first().ok_or_else(refuse)?.as_str()
    } else {
        "current.json"
    };
    let (old_candidate_sha, old_root, pointer_raw, _) =
        fresh_first_packaged_source_facts(&stage, pointer_leaf, current_absent)?;
    let archive_leaf = archive_names
        .first()
        .cloned()
        .unwrap_or_else(|| fresh_prebind_archive_leaf(&pointer_raw));
    if !fresh_prebind_archive_name(&archive_leaf) {
        return Err(refuse());
    }
    if !current_absent
        && !archive_names.is_empty()
        && read_fresh_rollback_leaf(control.as_raw_fd(), &archive_leaf, 8192)? != pointer_raw
    {
        return Err(refuse());
    }
    let pointer: InstallerRecoveryPointer =
        serde_json::from_slice(&pointer_raw).map_err(|_| refuse())?;
    if !recovery_pointer_schema(&pointer) {
        return Err(refuse());
    }
    let previous = pointer.previous_binary.as_ref().ok_or_else(refuse)?;
    let installed_dir = recovery_chain(&["usr", "local", "bin"], None)?;
    let installed = recovery_open_at(installed_dir.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    let installed_stat = recovery_stat(installed.as_raw_fd())?;
    if (installed_stat.st_dev, installed_stat.st_ino) != (previous.device, previous.inode) {
        return Err(refuse());
    }
    if installer_v2_generation::verify_fresh_prebind_old_source(&old_root)? != old_candidate_sha
        || actor_sha == old_candidate_sha
    {
        return Err(refuse());
    }
    crate::profile_auto_stopped_service::verify_fixed_stopped_for_fresh_prebind(&lock)
        .map_err(|_| refuse())?;
    observed.revalidate(&lock).map_err(|_| refuse())?;
    stage.revalidate_originals()?;
    let (rechecked_sha, rechecked_root, rechecked_pointer, _) =
        fresh_first_packaged_source_facts(&stage, pointer_leaf, current_absent)?;
    if rechecked_sha != old_candidate_sha
        || rechecked_root != old_root
        || rechecked_pointer != pointer_raw
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    recovery_absent(auto_root.as_raw_fd(), "fresh-passive-abort-current.json")?;
    if phase == Phase::Prepared {
        stage.header.phase = Phase::RolledBack;
        stage.persist_header()?;
    }
    // A crash after persist_header or rename is resumed under the same own
    // InstallLock. No second archive can be minted by this command.
    fresh_prebind_retire_pointer(control.as_raw_fd(), &pointer_raw, &archive_leaf)?;
    fresh_first_package_no_effects(&stage, Phase::RolledBack)?;
    let (retired_sha, retired_root, retired_raw, _) =
        fresh_first_packaged_source_facts(&stage, &archive_leaf, true)?;
    if retired_sha != old_candidate_sha || retired_root != old_root || retired_raw != pointer_raw {
        return Err(refuse());
    }
    stage.store.revalidate()?;
    crate::profile_auto_stopped_service::verify_fixed_stopped_for_fresh_prebind(&lock)
        .map_err(|_| refuse())?;
    observed.revalidate(&lock).map_err(|_| refuse())?;
    lock.revalidate().map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
fn fresh_prebind_archive_leaf(pointer_raw: &[u8]) -> String {
    format!("archived-{}.json", &digest(pointer_raw)[..32])
}

#[cfg(target_os = "linux")]
fn fresh_prebind_archive_name(name: &str) -> bool {
    name.len() == 46
        && name.starts_with("archived-")
        && name.ends_with(".json")
        && name.as_bytes()[9..41]
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(target_os = "linux")]
fn fresh_prebind_archives(control: std::os::fd::RawFd) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let path = format!("/proc/self/fd/{control}");
    for entry in std::fs::read_dir(path).map_err(|_| refuse())? {
        let name = entry.map_err(|_| refuse())?.file_name();
        let name = name.to_str().ok_or_else(refuse)?;
        if name.starts_with("archived-") {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn fresh_prebind_retire_pointer(
    control: std::os::fd::RawFd,
    pointer_raw: &[u8],
    archive_leaf: &str,
) -> Result<()> {
    fresh_prebind_retire_pointer_with_cut(control, pointer_raw, archive_leaf, || Ok(()))
}

#[cfg(target_os = "linux")]
fn fresh_prebind_retire_pointer_with_cut(
    control: std::os::fd::RawFd,
    pointer_raw: &[u8],
    archive_leaf: &str,
    after_rename: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if !fresh_prebind_archive_name(archive_leaf) {
        return Err(refuse());
    }
    let archives = fresh_prebind_archives(control)?;
    if archives.len() > 1 || archives.first().is_some_and(|name| name != archive_leaf) {
        return Err(refuse());
    }
    if recovery_absent(control, "current.json").is_ok() {
        if archives.len() != 1
            || read_fresh_rollback_leaf(control, archive_leaf, 8192)? != pointer_raw
            || unsafe { libc::fsync(control) } != 0
        {
            return Err(refuse());
        }
        return Ok(());
    }
    if read_fresh_rollback_leaf(control, "current.json", 8192)? != pointer_raw {
        return Err(refuse());
    }
    if archives.len() == 1 {
        // An older recovery may have written the exact archive before being
        // interrupted. Complete only that existing, byte-identical cut.
        if read_fresh_rollback_leaf(control, archive_leaf, 8192)? != pointer_raw
            || unsafe { libc::fsync(control) } != 0
            || unsafe { libc::unlinkat(control, c"current.json".as_ptr(), 0) } != 0
            || unsafe { libc::fsync(control) } != 0
        {
            return Err(refuse());
        }
    } else {
        if fresh_prebind_archive_leaf(pointer_raw) != archive_leaf {
            return Err(refuse());
        }
        let archive_name = std::ffi::CString::new(archive_leaf).map_err(|_| refuse())?;
        if unsafe {
            libc::renameat2(
                control,
                c"current.json".as_ptr(),
                control,
                archive_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(refuse());
        }
        after_rename()?;
        if unsafe { libc::fsync(control) } != 0 {
            return Err(refuse());
        }
    }
    recovery_absent(control, "current.json")?;
    if read_fresh_rollback_leaf(control, archive_leaf, 8192)? != pointer_raw {
        return Err(refuse());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_fresh_rollback_leaf(
    control: std::os::fd::RawFd,
    leaf: &str,
    maximum: u64,
) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let fd = recovery_open_at(control, leaf, libc::O_RDONLY, 0)?;
    let before = recovery_stat(fd.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o600
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as u64 > maximum
    {
        return Err(refuse());
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd.try_clone().map_err(|_| refuse())?)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    let after = recovery_stat(fd.as_raw_fd())?;
    let named = recovery_open_at(control, leaf, libc::O_RDONLY, 0)?;
    let current = recovery_stat(named.as_raw_fd())?;
    let identity = |stat: &libc::stat| {
        (
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
    if bytes.len() != before.st_size as usize
        || identity(&before) != identity(&after)
        || identity(&before) != identity(&current)
    {
        return Err(refuse());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn passive_compensated_leaf(successor_sha: &str) -> Result<String> {
    if !inspected_hex64(successor_sha) {
        return Err(refuse());
    }
    Ok(format!("passive-compensated-{successor_sha}.json"))
}

#[cfg(target_os = "linux")]
fn passive_unsealed_stopped_leaf(successor_sha: &str) -> Result<String> {
    if !inspected_hex64(successor_sha) {
        return Err(refuse());
    }
    Ok(format!("passive-unsealed-stopped-{successor_sha}.json"))
}

#[cfg(target_os = "linux")]
fn passive_unsealed_stopped_bytes(
    status: &serde_json::Value,
    pointer: &InstallerRecoveryPointer,
    report: &serde_json::Value,
    pointer_bytes: &[u8],
    archive: &str,
) -> Result<Vec<u8>> {
    if status["schema"] != "aegis_auto_v2_passive_transition_status_v1"
        || !matches!(
            status["phase"].as_str(),
            Some("pending-old" | "package-installed")
        )
        || report["stage"]["mode"] != "socks-only"
        || report["stage"]["path"] != pointer.stage.to_string_lossy().as_ref()
        || report["terminal"]["outcome"] != "finalized-stopped"
        || report["terminal"]["boot_id"] != pointer.boot_id
        || report["input"]["candidate_sha256"] != status["candidate_sha256"]
        || report["input"]["public_payload_root"] != status["public_payload_root"]
        || pointer.candidate_sha256 != status["candidate_sha256"]
        || pointer
            .previous_binary
            .as_ref()
            .map(|old| old.sha256.as_str())
            != status["old_candidate_sha256"].as_str()
        || archive.len() != 63
        || !archive.starts_with("archived-unsealed-stopped-")
        || !archive.ends_with(".json")
        || !archive[26..58]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_passive_unsealed_stopped_v1",
        "boot_id": pointer.boot_id,
        "successor_intent_sha256": status["successor_intent_sha256"],
        "preinst_sha256": status["preinst_sha256"],
        "old_candidate_sha256": status["old_candidate_sha256"],
        "candidate_sha256": status["candidate_sha256"],
        "public_payload_root": status["public_payload_root"],
        "stage": pointer.stage,
        "stopped_report_sha256": digest(&serde_json::to_vec(report).map_err(|_| refuse())?),
        "pointer_sha256": digest(pointer_bytes),
        "pointer_archive": archive,
    }))
    .map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
fn verify_resumed_unsealed_history(
    control: std::os::fd::RawFd,
    status: &serde_json::Value,
) -> Result<()> {
    let successor = status["successor_intent_sha256"]
        .as_str()
        .ok_or_else(refuse)?;
    let certificate_leaf = passive_unsealed_stopped_leaf(successor)?;
    let journal_leaf = format!("passive-unsealed-resume-{successor}.json");
    let cert_absent = recovery_absent(control, &certificate_leaf).is_ok();
    let journal_absent = recovery_absent(control, &journal_leaf).is_ok();
    if cert_absent && journal_absent {
        return Ok(());
    }
    if cert_absent || journal_absent {
        return Err(refuse());
    }
    recovery_absent(control, "generation-recovery-stopped.json")?;
    let certificate = read_passive_compensated(control, &certificate_leaf)?;
    let cert: serde_json::Value = serde_json::from_slice(&certificate).map_err(|_| refuse())?;
    let archive = cert["pointer_archive"].as_str().ok_or_else(refuse)?;
    let pointer_bytes = read_passive_compensated(control, archive)?;
    let pointer: InstallerRecoveryPointer =
        serde_json::from_slice(&pointer_bytes).map_err(|_| refuse())?;
    if !recovery_pointer_schema(&pointer) {
        return Err(refuse());
    }
    let journal_bytes = read_passive_compensated(control, &journal_leaf)?;
    let journal: serde_json::Value =
        serde_json::from_slice(&journal_bytes).map_err(|_| refuse())?;
    let recovery_sha = journal["recovery_sha256"].as_str().ok_or_else(refuse)?;
    let recovery = installer_v2_generation::read_passive_unsealed_recovery_archive(recovery_sha)?;
    let report = installer_v2_generation::validate_unsealed_stopped_recovery_bytes(&recovery)?;
    if certificate
        != passive_unsealed_stopped_bytes(status, &pointer, &report, &pointer_bytes, archive)?
        || journal_bytes
            != serde_json::to_vec(&serde_json::json!({
                "schema": "aegis_auto_v2_passive_unsealed_resume_v1",
                "boot_id": pointer.boot_id,
                "successor_intent_sha256": successor,
                "preinst_sha256": status["preinst_sha256"],
                "candidate_sha256": status["candidate_sha256"],
                "recovery_sha256": digest(&recovery),
                "certificate_sha256": digest(&certificate),
                "pointer_sha256": digest(&pointer_bytes),
            }))
            .map_err(|_| refuse())?
    {
        return Err(refuse());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_passive_compensated(control: std::os::fd::RawFd, leaf: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let fd = recovery_open_at(control, leaf, libc::O_RDONLY, 0)?;
    let before = recovery_stat(fd.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o600
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || !(1..=8192).contains(&before.st_size)
    {
        return Err(refuse());
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd.try_clone().map_err(|_| refuse())?)
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    let same_fd = recovery_stat(fd.as_raw_fd())?;
    let named = recovery_open_at(control, leaf, libc::O_RDONLY, 0)?;
    let after = recovery_stat(named.as_raw_fd())?;
    if bytes.len() != before.st_size as usize
        || (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime,
            before.st_mtime_nsec,
            before.st_ctime,
            before.st_ctime_nsec,
        ) != (
            same_fd.st_dev,
            same_fd.st_ino,
            same_fd.st_size,
            same_fd.st_mtime,
            same_fd.st_mtime_nsec,
            same_fd.st_ctime,
            same_fd.st_ctime_nsec,
        )
        || (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime,
            before.st_mtime_nsec,
            before.st_ctime,
            before.st_ctime_nsec,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime,
            after.st_mtime_nsec,
            after.st_ctime,
            after.st_ctime_nsec,
        )
    {
        return Err(refuse());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn passive_compensated_bytes(
    status: &serde_json::Value,
    pointer: &InstallerRecoveryPointer,
    stage_id: (u64, u64),
    pointer_bytes: &[u8],
    archive: &str,
) -> Result<Vec<u8>> {
    if status["schema"] != "aegis_auto_v2_passive_transition_status_v1"
        || status["phase"] != "pending-old"
        || pointer.candidate_sha256 != status["candidate_sha256"]
        || pointer
            .previous_binary
            .as_ref()
            .map(|prior| prior.sha256.as_str())
            != status["old_candidate_sha256"].as_str()
        || archive.len() != 46
        || !archive.starts_with("archived-")
        || !archive.ends_with(".json")
        || !archive[9..41]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_passive_compensated_v1",
        "boot_id": pointer.boot_id,
        "successor_intent_sha256": status["successor_intent_sha256"],
        "preinst_sha256": status["preinst_sha256"],
        "old_candidate_sha256": status["old_candidate_sha256"],
        "candidate_sha256": status["candidate_sha256"],
        "public_payload_root": status["public_payload_root"],
        "old_public_payload_root": status["old_public_payload_root"],
        "stage": pointer.stage,
        "stage_device": stage_id.0,
        "stage_inode": stage_id.1,
        "pointer_sha256": digest(pointer_bytes),
        "pointer_archive": archive,
    }))
    .map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
struct InstallerRecoveryBackup {
    name: String,
    sha256: String,
    /// Identity of the executable before install_candidate replaces it.
    device: u64,
    inode: u64,
    /// Identity of the independent O_EXCL control-directory copy.
    backup_device: Option<u64>,
    backup_inode: Option<u64>,
    size: u64,
    mode: u32,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallerRecoveryBackupWire {
    name: String,
    sha256: String,
    device: u64,
    inode: u64,
    #[serde(default, deserialize_with = "recovery_optional_nonnull_u64")]
    backup_device: Option<u64>,
    #[serde(default, deserialize_with = "recovery_optional_nonnull_u64")]
    backup_inode: Option<u64>,
    size: u64,
    mode: u32,
}

#[cfg(target_os = "linux")]
fn recovery_optional_nonnull_u64<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error> {
    u64::deserialize(deserializer).map(Some)
}

#[cfg(target_os = "linux")]
impl<'de> Deserialize<'de> for InstallerRecoveryBackup {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let wire = InstallerRecoveryBackupWire::deserialize(deserializer)?;
        if wire.backup_device.is_some() != wire.backup_inode.is_some() {
            return Err(D::Error::custom("backup_shape"));
        }
        Ok(Self {
            name: wire.name,
            sha256: wire.sha256,
            device: wire.device,
            inode: wire.inode,
            backup_device: wire.backup_device,
            backup_inode: wire.backup_inode,
            size: wire.size,
            mode: wire.mode,
        })
    }
}

#[cfg(target_os = "linux")]
fn recovery_backup_identity(
    old: &InstallerRecoveryBackup,
    pointer_schema: &str,
    saved: &libc::stat,
) -> bool {
    let backup_identity = match (pointer_schema, old.backup_device, old.backup_inode) {
        ("aegis_installer_auto_v2_stage_v1", None, None) => true,
        (
            "aegis_installer_auto_v2_stage_v2" | "aegis_installer_auto_v2_boot_stage_v3",
            Some(device),
            Some(inode),
        ) => {
            device != 0
                && inode != 0
                && (device, inode) != (old.device, old.inode)
                && (saved.st_dev, saved.st_ino) == (device, inode)
        }
        _ => false,
    };
    old.device != 0
        && old.inode != 0
        && backup_identity
        && saved.st_mode == libc::S_IFREG | 0o600
        && saved.st_uid == 0
        && saved.st_gid == 0
        && saved.st_nlink == 1
        && saved.st_size >= 0
        && saved.st_size as u64 == old.size
}

#[cfg(target_os = "linux")]
fn recovery_pointer_schema(pointer: &InstallerRecoveryPointer) -> bool {
    let boot_fields = [
        pointer.boot_intent_sha256.as_deref(),
        pointer.prepare_intent_sha256.as_deref(),
        pointer.prepare_completed_sha256.as_deref(),
    ];
    match pointer.schema.as_str() {
        "aegis_installer_auto_v2_stage_v1" => {
            pointer
                .previous_binary
                .as_ref()
                .is_none_or(|old| old.backup_device.is_none() && old.backup_inode.is_none())
                && boot_fields.iter().all(Option::is_none)
        }
        "aegis_installer_auto_v2_stage_v2" => {
            pointer.previous_binary.as_ref().is_none_or(|old| {
                matches!((old.backup_device, old.backup_inode), (Some(_), Some(_)))
            }) && boot_fields.iter().all(Option::is_none)
        }
        "aegis_installer_auto_v2_boot_stage_v3" => {
            pointer.previous_binary.as_ref().is_none_or(|old| {
                matches!((old.backup_device, old.backup_inode), (Some(_), Some(_)))
            }) && boot_fields.iter().all(|field| {
                field.is_some_and(|sha| {
                    sha.len() == 64
                        && sha
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                })
            })
        }
        _ => false,
    }
}

#[cfg(all(target_os = "linux", test))]
mod recovery_backup_identity_tests {
    use super::{
        recovery_backup_identity, recovery_pointer_schema, InstallerRecoveryBackup,
        InstallerRecoveryPointer,
    };
    use std::path::PathBuf;

    #[test]
    fn copied_backup_has_its_own_identity_and_versions_cannot_be_mixed() {
        let mut old = InstallerRecoveryBackup {
            name: format!("backup-{}.bin", "a".repeat(32)),
            sha256: "b".repeat(64),
            device: 41,
            inode: 101,
            backup_device: Some(41),
            backup_inode: Some(202),
            size: 30,
            mode: 0o755,
        };
        let mut saved: libc::stat = unsafe { std::mem::zeroed() };
        saved.st_mode = libc::S_IFREG | 0o600;
        saved.st_uid = 0;
        saved.st_gid = 0;
        saved.st_nlink = 1;
        saved.st_dev = 41;
        saved.st_ino = 202;
        saved.st_size = 30;
        let mut pointer = InstallerRecoveryPointer {
            schema: "aegis_installer_auto_v2_stage_v2".into(),
            stage: PathBuf::from("/run/aegis-installer-config-snapshots/stage"),
            status: "pending".into(),
            boot_id: "c".repeat(36),
            installed_binary: "/usr/local/bin/aegis-client".into(),
            candidate_sha256: "d".repeat(64),
            previous_binary: Some(old),
            boot_intent_sha256: None,
            prepare_intent_sha256: None,
            prepare_completed_sha256: None,
        };
        assert!(recovery_pointer_schema(&pointer));
        pointer.schema = "aegis_installer_auto_v2_boot_stage_v3".into();
        pointer.boot_intent_sha256 = Some("a".repeat(64));
        pointer.prepare_intent_sha256 = Some("b".repeat(64));
        pointer.prepare_completed_sha256 = Some("c".repeat(64));
        assert!(recovery_pointer_schema(&pointer));
        pointer.prepare_completed_sha256 = None;
        assert!(!recovery_pointer_schema(&pointer));
        pointer.prepare_completed_sha256 = Some("c".repeat(64));
        pointer.schema = "aegis_installer_auto_v2_stage_v2".into();
        assert!(!recovery_pointer_schema(&pointer));
        pointer.boot_intent_sha256 = None;
        pointer.prepare_intent_sha256 = None;
        pointer.prepare_completed_sha256 = None;
        assert!(recovery_pointer_schema(&pointer));
        old = pointer.previous_binary.take().unwrap();
        assert!(recovery_backup_identity(&old, &pointer.schema, &saved));
        saved.st_ino = 203;
        assert!(!recovery_backup_identity(&old, &pointer.schema, &saved));
        saved.st_ino = 202;
        saved.st_mode = libc::S_IFREG | 0o644;
        assert!(!recovery_backup_identity(&old, &pointer.schema, &saved));
        saved.st_mode = libc::S_IFREG | 0o600;
        pointer.schema = "aegis_installer_auto_v2_stage_v1".into();
        pointer.previous_binary = Some(old);
        assert!(!recovery_pointer_schema(&pointer));
        old = pointer.previous_binary.take().unwrap();
        old.backup_device = None;
        old.backup_inode = None;
        pointer.previous_binary = Some(old);
        assert!(recovery_pointer_schema(&pointer));
        assert!(recovery_backup_identity(
            pointer.previous_binary.as_ref().unwrap(),
            &pointer.schema,
            &saved
        ));
        let mut wire = serde_json::json!({
            "name": format!("backup-{}.bin", "a".repeat(32)),
            "sha256": "b".repeat(64), "device": 41, "inode": 101,
            "size": 30, "mode": 0o755,
        });
        assert!(serde_json::from_value::<InstallerRecoveryBackup>(wire.clone()).is_ok());
        wire["backup_device"] = serde_json::Value::Null;
        wire["backup_inode"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<InstallerRecoveryBackup>(wire.clone()).is_err());
        wire["backup_device"] = serde_json::json!(41);
        assert!(serde_json::from_value::<InstallerRecoveryBackup>(wire.clone()).is_err());
        wire["backup_inode"] = serde_json::json!(202);
        assert!(serde_json::from_value::<InstallerRecoveryBackup>(wire).is_ok());
        let legacy_duplicate = format!(
            "{{\"name\":\"backup-{}.bin\",\"sha256\":\"{}\",\"sha256\":\"{}\",\"device\":41,\"inode\":101,\"size\":30,\"mode\":493}}",
            "a".repeat(32), "b".repeat(64), "b".repeat(64)
        );
        assert!(serde_json::from_str::<InstallerRecoveryBackup>(&legacy_duplicate).is_err());
        let v2_duplicate = format!(
            "{{\"name\":\"backup-{}.bin\",\"sha256\":\"{}\",\"device\":41,\"inode\":101,\"backup_device\":41,\"backup_inode\":202,\"backup_inode\":202,\"size\":30,\"mode\":493}}",
            "a".repeat(32), "b".repeat(64)
        );
        assert!(serde_json::from_str::<InstallerRecoveryBackup>(&v2_duplicate).is_err());
    }
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallerRecoveryPointer {
    schema: String,
    stage: PathBuf,
    status: String,
    boot_id: String,
    installed_binary: String,
    candidate_sha256: String,
    previous_binary: Option<InstallerRecoveryBackup>,
    #[serde(default, deserialize_with = "recovery_optional_nonnull_string")]
    boot_intent_sha256: Option<String>,
    #[serde(default, deserialize_with = "recovery_optional_nonnull_string")]
    prepare_intent_sha256: Option<String>,
    #[serde(default, deserialize_with = "recovery_optional_nonnull_string")]
    prepare_completed_sha256: Option<String>,
}

#[cfg(target_os = "linux")]
fn recovery_optional_nonnull_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

#[cfg(target_os = "linux")]
fn recovery_stat(fd: std::os::fd::RawFd) -> Result<libc::stat> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
        return Err(refuse());
    }
    Ok(unsafe { value.assume_init() })
}

#[cfg(target_os = "linux")]
fn recovery_open_at(
    parent: std::os::fd::RawFd,
    name: &str,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let name = std::ffi::CString::new(name).map_err(|_| refuse())?;
    let raw = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode,
        )
    };
    if raw < 0 {
        return Err(refuse());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) })
}

#[cfg(target_os = "linux")]
fn recovery_directory(
    parent: std::os::fd::RawFd,
    name: &str,
    exact_mode: Option<u32>,
) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;
    let fd = recovery_open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    let s = recovery_stat(fd.as_raw_fd())?;
    if s.st_mode & libc::S_IFMT != libc::S_IFDIR
        || s.st_uid != 0
        || s.st_gid != 0
        || s.st_mode & 0o022 != 0
        || exact_mode.is_some_and(|mode| s.st_mode & 0o7777 != mode)
    {
        return Err(refuse());
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn recovery_absent(parent: std::os::fd::RawFd, name: &str) -> Result<()> {
    let name = std::ffi::CString::new(name).map_err(|_| refuse())?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != -1
        || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
    {
        return Err(refuse());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn recovery_chain(names: &[&str], final_mode: Option<u32>) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root < 0 {
        return Err(refuse());
    }
    let mut held = unsafe { std::os::fd::OwnedFd::from_raw_fd(root) };
    for (index, name) in names.iter().enumerate() {
        held = recovery_directory(
            held.as_raw_fd(),
            name,
            if index + 1 == names.len() {
                final_mode
            } else {
                None
            },
        )?;
    }
    Ok(held)
}

#[cfg(target_os = "linux")]
fn recovery_file_hash(fd: std::os::fd::RawFd, maximum: u64) -> Result<(u64, String)> {
    use std::io::Read;
    use std::os::fd::FromRawFd;
    let before = recovery_stat(fd)?;
    if before.st_size < 0 || before.st_size as u64 > maximum {
        return Err(refuse());
    }
    let copy = unsafe { libc::dup(fd) };
    if copy < 0 || unsafe { libc::lseek(copy, 0, libc::SEEK_SET) } != 0 {
        if copy >= 0 {
            unsafe { libc::close(copy) };
        }
        return Err(refuse());
    }
    let mut reader = unsafe { std::fs::File::from_raw_fd(copy) };
    let mut sha = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = reader.read(&mut buffer).map_err(|_| refuse())?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).ok_or_else(refuse)?;
        if count > maximum {
            return Err(refuse());
        }
        sha.update(&buffer[..n]);
    }
    let after = recovery_stat(fd)?;
    if count != before.st_size as u64
        || (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime,
            before.st_mtime_nsec,
            before.st_ctime,
            before.st_ctime_nsec,
            before.st_uid,
            before.st_gid,
            before.st_mode,
            before.st_nlink,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime,
            after.st_mtime_nsec,
            after.st_ctime,
            after.st_ctime_nsec,
            after.st_uid,
            after.st_gid,
            after.st_mode,
            after.st_nlink,
        )
    {
        return Err(refuse());
    }
    Ok((count, format!("{:x}", sha.finalize())))
}

/// This command is deliberately separate from the accepted worker protocol.
/// It re-admits a completed rollback, then restores the prior executable and
/// archives the protected pending pointer under one original InstallLock.
#[cfg(target_os = "linux")]
pub(crate) fn recover_rolled_back_stage(path: &Path) -> Result<()> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    let stage_id = admit_rolled_back_stage(path, &lock)?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let pointer_fd = recovery_open_at(control.as_raw_fd(), "current.json", libc::O_RDONLY, 0)?;
    let pointer_stat = recovery_stat(pointer_fd.as_raw_fd())?;
    if pointer_stat.st_uid != 0
        || pointer_stat.st_gid != 0
        || pointer_stat.st_nlink != 1
        || pointer_stat.st_mode != libc::S_IFREG | 0o600
        || !(1..=8192).contains(&pointer_stat.st_size)
    {
        return Err(refuse());
    }
    let mut pointer_bytes = Vec::new();
    std::fs::File::from(pointer_fd.try_clone().map_err(|_| refuse())?)
        .take(8193)
        .read_to_end(&mut pointer_bytes)
        .map_err(|_| refuse())?;
    if pointer_bytes.len() != pointer_stat.st_size as usize {
        return Err(refuse());
    }
    let pointer: InstallerRecoveryPointer =
        serde_json::from_slice(&pointer_bytes).map_err(|_| refuse())?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| refuse())?;
    if !recovery_pointer_schema(&pointer)
        || pointer.status != "pending"
        || pointer.stage != path
        || pointer.installed_binary != "/usr/local/bin/aegis-client"
        || pointer.boot_id != boot.trim()
        || !inspected_hex64(&pointer.candidate_sha256)
        || durable::Store::reopen(&pointer.stage, 0)?.identity()? != stage_id
    {
        return Err(refuse());
    }
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if recovery_file_hash(running.as_raw_fd(), 256 * 1024 * 1024)?.1 != pointer.candidate_sha256 {
        return Err(refuse());
    }
    let installed_dir = recovery_chain(&["usr", "local", "bin"], None)?;
    let installed = recovery_open_at(installed_dir.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0);
    let mut installed_matches_candidate = false;
    let mut installed_matches_old = false;
    match &installed {
        Ok(fd) => {
            let s = recovery_stat(fd.as_raw_fd())?;
            if s.st_mode & libc::S_IFMT != libc::S_IFREG
                || s.st_uid != 0
                || s.st_gid != 0
                || s.st_nlink != 1
                || !matches!(s.st_mode & 0o7777, 0o555 | 0o755)
            {
                return Err(refuse());
            }
            let current = recovery_file_hash(fd.as_raw_fd(), 256 * 1024 * 1024)?;
            installed_matches_candidate = current.1 == pointer.candidate_sha256;
            installed_matches_old = pointer.previous_binary.as_ref().is_some_and(|old| {
                current == (old.size, old.sha256.clone()) && s.st_mode & 0o7777 == old.mode
            });
            if !installed_matches_candidate && !installed_matches_old {
                return Err(refuse());
            }
        }
        Err(_) if pointer.previous_binary.is_none() => {
            recovery_absent(installed_dir.as_raw_fd(), "aegis-client")?;
        }
        Err(_) => return Err(refuse()),
    }
    let mut backup = None;
    if let Some(old) = &pointer.previous_binary {
        if !old.name.starts_with("backup-")
            || old.name.len() != 43
            || !old.name.ends_with(".bin")
            || !old.name[7..39]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !inspected_hex64(&old.sha256)
            || old.device == 0
            || old.inode == 0
            || old.size == 0
            || !matches!(old.mode, 0o555 | 0o755)
        {
            return Err(refuse());
        }
        let fd = recovery_open_at(control.as_raw_fd(), &old.name, libc::O_RDONLY, 0)?;
        let s = recovery_stat(fd.as_raw_fd())?;
        if !recovery_backup_identity(old, &pointer.schema, &s)
            || recovery_file_hash(fd.as_raw_fd(), 256 * 1024 * 1024)?
                != (old.size, old.sha256.clone())
        {
            return Err(refuse());
        }
        backup = Some(fd);
    }
    lock.revalidate().map_err(|_| refuse())?;
    if !installed_matches_old {
        if let Some(old) = &pointer.previous_binary {
            let source = backup.as_ref().ok_or_else(refuse)?;
            let mut nonce = [0u8; 16];
            if unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) }
                != nonce.len() as isize
            {
                return Err(refuse());
            }
            let temp = format!(".aegis-auto-recover-{}", hex::encode(nonce));
            let target = recovery_open_at(
                installed_dir.as_raw_fd(),
                &temp,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            let write_result = (|| -> Result<()> {
                if unsafe { libc::lseek(source.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
                    return Err(refuse());
                }
                let mut source = std::fs::File::from(source.try_clone().map_err(|_| refuse())?);
                let mut target_file =
                    std::fs::File::from(target.try_clone().map_err(|_| refuse())?);
                std::io::copy(&mut source, &mut target_file).map_err(|_| refuse())?;
                target_file.flush().map_err(|_| refuse())?;
                if unsafe { libc::fchmod(target.as_raw_fd(), old.mode) } != 0 {
                    return Err(refuse());
                }
                target_file.sync_all().map_err(|_| refuse())?;
                if recovery_file_hash(target.as_raw_fd(), 256 * 1024 * 1024)?
                    != (old.size, old.sha256.clone())
                {
                    return Err(refuse());
                }
                let temp = std::ffi::CString::new(temp.as_str()).map_err(|_| refuse())?;
                if unsafe {
                    libc::renameat(
                        installed_dir.as_raw_fd(),
                        temp.as_ptr(),
                        installed_dir.as_raw_fd(),
                        c"aegis-client".as_ptr(),
                    )
                } != 0
                    || unsafe { libc::fsync(installed_dir.as_raw_fd()) } != 0
                {
                    return Err(refuse());
                }
                Ok(())
            })();
            if write_result.is_err() {
                if let Ok(name) = std::ffi::CString::new(temp) {
                    unsafe { libc::unlinkat(installed_dir.as_raw_fd(), name.as_ptr(), 0) };
                }
            }
            write_result?;
        } else if installed_matches_candidate
            && (unsafe { libc::unlinkat(installed_dir.as_raw_fd(), c"aegis-client".as_ptr(), 0) }
                != 0
                || unsafe { libc::fsync(installed_dir.as_raw_fd()) } != 0)
        {
            return Err(refuse());
        }
    }
    match (
        &pointer.previous_binary,
        recovery_open_at(installed_dir.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0),
    ) {
        (Some(old), Ok(fd)) => {
            let s = recovery_stat(fd.as_raw_fd())?;
            if s.st_mode != libc::S_IFREG | old.mode
                || s.st_uid != 0
                || s.st_gid != 0
                || s.st_nlink != 1
                || recovery_file_hash(fd.as_raw_fd(), 256 * 1024 * 1024)?
                    != (old.size, old.sha256.clone())
            {
                return Err(refuse());
            }
        }
        (None, Err(_)) => recovery_absent(installed_dir.as_raw_fd(), "aegis-client")?,
        _ => return Err(refuse()),
    }
    let again = recovery_open_at(control.as_raw_fd(), "current.json", libc::O_RDONLY, 0)?;
    let current_stat = recovery_stat(again.as_raw_fd())?;
    let mut current_bytes = Vec::new();
    std::fs::File::from(again.try_clone().map_err(|_| refuse())?)
        .take(8193)
        .read_to_end(&mut current_bytes)
        .map_err(|_| refuse())?;
    if (current_stat.st_dev, current_stat.st_ino) != (pointer_stat.st_dev, pointer_stat.st_ino)
        || current_bytes != pointer_bytes
    {
        return Err(refuse());
    }
    let passive_status =
        if recovery_absent(control.as_raw_fd(), "passive-package-preinst.json").is_err() {
            let evidence = installer_v2_generation::passive_transition_evidence()?;
            let bytes = installer_v2_generation::passive_transition_status(&evidence, None)?;
            let status: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
            if status["phase"] != "pending-old" {
                return Err(refuse());
            }
            Some(status)
        } else {
            None
        };
    let certificate_leaf = passive_status
        .as_ref()
        .map(|status| {
            passive_compensated_leaf(
                status["successor_intent_sha256"]
                    .as_str()
                    .ok_or_else(refuse)?,
            )
        })
        .transpose()?;
    let existing_certificate = certificate_leaf
        .as_ref()
        .and_then(|name| {
            if recovery_absent(control.as_raw_fd(), name).is_ok() {
                None
            } else {
                Some(read_passive_compensated(control.as_raw_fd(), name))
            }
        })
        .transpose()?;
    let archive = if let Some(bytes) = &existing_certificate {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| refuse())?;
        value["pointer_archive"]
            .as_str()
            .ok_or_else(refuse)?
            .to_owned()
    } else {
        let mut nonce = [0u8; 16];
        if unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) }
            != nonce.len() as isize
        {
            return Err(refuse());
        }
        format!("archived-{}.json", hex::encode(nonce))
    };
    if archive.len() != 46
        || !archive.starts_with("archived-")
        || !archive.ends_with(".json")
        || !archive[9..41]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    if recovery_absent(control.as_raw_fd(), &archive).is_ok() {
        if existing_certificate.is_some() {
            return Err(refuse());
        }
        if passive_status.is_some() {
            installer_v2_generation::write_passive_atomic(
                control.as_raw_fd(),
                &archive,
                &pointer_bytes,
                8192,
            )?;
        } else {
            let archive_fd = recovery_open_at(
                control.as_raw_fd(),
                &archive,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            let mut archive_file = std::fs::File::from(archive_fd);
            archive_file
                .write_all(&pointer_bytes)
                .map_err(|_| refuse())?;
            archive_file.sync_all().map_err(|_| refuse())?;
        }
    }
    if read_passive_compensated(control.as_raw_fd(), &archive)? != pointer_bytes {
        return Err(refuse());
    }
    if let (Some(status), Some(leaf)) = (&passive_status, &certificate_leaf) {
        let expected =
            passive_compensated_bytes(status, &pointer, stage_id, &pointer_bytes, &archive)?;
        if let Some(bytes) = existing_certificate {
            if bytes != expected {
                return Err(refuse());
            }
        } else {
            installer_v2_generation::write_passive_atomic(
                control.as_raw_fd(),
                leaf,
                &expected,
                8192,
            )?;
            if read_passive_compensated(control.as_raw_fd(), leaf)? != expected {
                return Err(refuse());
            }
        }
    }
    let last = recovery_open_at(control.as_raw_fd(), "current.json", libc::O_RDONLY, 0)?;
    let last_stat = recovery_stat(last.as_raw_fd())?;
    let mut last_bytes = Vec::new();
    std::fs::File::from(last.try_clone().map_err(|_| refuse())?)
        .take(8193)
        .read_to_end(&mut last_bytes)
        .map_err(|_| refuse())?;
    if (last_stat.st_dev, last_stat.st_ino) != (pointer_stat.st_dev, pointer_stat.st_ino)
        || last_bytes != pointer_bytes
    {
        return Err(refuse());
    }
    if unsafe { libc::fsync(control.as_raw_fd()) } != 0
        || unsafe { libc::unlinkat(control.as_raw_fd(), c"current.json".as_ptr(), 0) } != 0
        || unsafe { libc::fsync(control.as_raw_fd()) } != 0
    {
        return Err(refuse());
    }
    Ok(())
}

/// Authenticate the completed rollback cut after the pending pointer was
/// retired. This acquires its own original InstallLock and grants no action.
#[cfg(target_os = "linux")]
pub(crate) fn verify_passive_compensated_stage() -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    let evidence = installer_v2_generation::passive_transition_evidence()?;
    let status_bytes = installer_v2_generation::passive_transition_status(&evidence, None)?;
    let status: serde_json::Value = serde_json::from_slice(&status_bytes).map_err(|_| refuse())?;
    if status["phase"] != "pending-old" {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), "current.json")?;
    let successor = status["successor_intent_sha256"]
        .as_str()
        .ok_or_else(refuse)?;
    let leaf = passive_compensated_leaf(successor)?;
    let raw = read_passive_compensated(control.as_raw_fd(), &leaf)?;
    let record: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| refuse())?;
    let fields = record.as_object().ok_or_else(refuse)?;
    if fields.len() != 13
        || [
            "schema",
            "boot_id",
            "successor_intent_sha256",
            "preinst_sha256",
            "old_candidate_sha256",
            "candidate_sha256",
            "public_payload_root",
            "old_public_payload_root",
            "stage",
            "stage_device",
            "stage_inode",
            "pointer_sha256",
            "pointer_archive",
        ]
        .iter()
        .any(|key| !fields.contains_key(*key))
        || record["schema"] != "aegis_auto_v2_passive_compensated_v1"
        || record["successor_intent_sha256"] != status["successor_intent_sha256"]
        || record["preinst_sha256"] != status["preinst_sha256"]
        || record["old_candidate_sha256"] != status["old_candidate_sha256"]
        || record["candidate_sha256"] != status["candidate_sha256"]
        || record["public_payload_root"] != status["public_payload_root"]
        || record["old_public_payload_root"] != status["old_public_payload_root"]
    {
        return Err(refuse());
    }
    let archive = record["pointer_archive"].as_str().ok_or_else(refuse)?;
    if archive.len() != 46
        || !archive.starts_with("archived-")
        || !archive.ends_with(".json")
        || !archive[9..41]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    let pointer_bytes = read_passive_compensated(control.as_raw_fd(), archive)?;
    let pointer: InstallerRecoveryPointer =
        serde_json::from_slice(&pointer_bytes).map_err(|_| refuse())?;
    if !recovery_pointer_schema(&pointer) {
        return Err(refuse());
    }
    let stage_id = admit_rolled_back_stage(&pointer.stage, &lock)?;
    let expected = passive_compensated_bytes(&status, &pointer, stage_id, &pointer_bytes, archive)?;
    if raw != expected
        || record["boot_id"] != pointer.boot_id
        || pointer.boot_id
            != std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| refuse())?
                .trim()
        || record["pointer_sha256"] != digest(&pointer_bytes)
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_passive_compensated_readback_v1",
        "successor_intent_sha256": successor,
        "preinst_sha256": status["preinst_sha256"],
        "candidate_sha256": status["candidate_sha256"],
        "old_candidate_sha256": status["old_candidate_sha256"],
        "public_payload_root": status["public_payload_root"],
        "stage": pointer.stage,
        "stage_device": stage_id.0,
        "stage_inode": stage_id.1,
        "pointer_sha256": digest(&pointer_bytes),
        "certificate_sha256": digest(&raw),
    }))
    .map_err(|_| refuse())
}

/// Distinct Finalized-and-stopped continuation. The B publication and typed
/// Stop remain live evidence; this never grants rolled-back Prepare authority.
#[cfg(target_os = "linux")]
pub(crate) fn verify_passive_unsealed_stopped_stage() -> Result<Vec<u8>> {
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    verify_passive_unsealed_stopped_stage_held(&lock)
}

/// Consume only a source-bound, freshly observed stopped B recovery. The
/// hash-named journal makes a crash after exact retirement retryable without
/// treating missing recovery state as authority.
#[cfg(target_os = "linux")]
pub(crate) fn resume_passive_unsealed_stopped_stage() -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    let evidence = installer_v2_generation::passive_transition_evidence_with_unsealed()?;
    let status_bytes = installer_v2_generation::passive_transition_status(&evidence, None)?;
    let status: serde_json::Value = serde_json::from_slice(&status_bytes).map_err(|_| refuse())?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), "current.json")?;
    let successor = status["successor_intent_sha256"]
        .as_str()
        .ok_or_else(refuse)?;
    let certificate_leaf = passive_unsealed_stopped_leaf(successor)?;
    let certificate = read_passive_compensated(control.as_raw_fd(), &certificate_leaf)?;
    let certified: serde_json::Value =
        serde_json::from_slice(&certificate).map_err(|_| refuse())?;
    let pointer_archive = certified["pointer_archive"].as_str().ok_or_else(refuse)?;
    let pointer_bytes = read_passive_compensated(control.as_raw_fd(), pointer_archive)?;
    let pointer: InstallerRecoveryPointer =
        serde_json::from_slice(&pointer_bytes).map_err(|_| refuse())?;
    if !recovery_pointer_schema(&pointer) {
        return Err(refuse());
    }
    let observed = observe_stopped_generation_held(&pointer.stage, &lock, None)?;
    observed.ensure_ready(ReadOnlyInstallEvidence::Held(&lock))?;
    let fresh: serde_json::Value = serde_json::from_slice(&observed.bytes).map_err(|_| refuse())?;
    if certificate
        != passive_unsealed_stopped_bytes(
            &status,
            &pointer,
            &fresh,
            &pointer_bytes,
            pointer_archive,
        )?
    {
        return Err(refuse());
    }
    let journal_leaf = format!("passive-unsealed-resume-{successor}.json");
    let old_journal = if recovery_absent(control.as_raw_fd(), &journal_leaf).is_ok() {
        None
    } else {
        Some(read_passive_compensated(
            control.as_raw_fd(),
            &journal_leaf,
        )?)
    };
    let recovery_bytes =
        if recovery_absent(control.as_raw_fd(), "generation-recovery-stopped.json").is_err() {
            installer_v2_generation::read_current_unsealed_recovery_bytes()?
        } else {
            let journal_raw = old_journal.as_ref().ok_or_else(refuse)?;
            let journal: serde_json::Value =
                serde_json::from_slice(journal_raw).map_err(|_| refuse())?;
            let sha = journal["recovery_sha256"].as_str().ok_or_else(refuse)?;
            installer_v2_generation::read_passive_unsealed_recovery_archive(sha)?
        };
    let report =
        installer_v2_generation::validate_unsealed_stopped_recovery_bytes(&recovery_bytes)?;
    if fresh != report {
        return Err(refuse());
    }
    let journal_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_passive_unsealed_resume_v1",
        "boot_id": pointer.boot_id,
        "successor_intent_sha256": successor,
        "preinst_sha256": status["preinst_sha256"],
        "candidate_sha256": status["candidate_sha256"],
        "recovery_sha256": digest(&recovery_bytes),
        "certificate_sha256": digest(&certificate),
        "pointer_sha256": digest(&pointer_bytes),
    }))
    .map_err(|_| refuse())?;
    if let Some(old) = old_journal {
        if old != journal_bytes {
            return Err(refuse());
        }
    } else {
        installer_v2_generation::write_passive_atomic(
            control.as_raw_fd(),
            &journal_leaf,
            &journal_bytes,
            8192,
        )?;
    }
    installer_v2_generation::archive_passive_unsealed_recovery(&recovery_bytes)?;
    if recovery_absent(control.as_raw_fd(), "generation-recovery-stopped.json").is_err() {
        installer_v2_generation::retire_current_unsealed_recovery_bytes(&recovery_bytes)?;
    }
    recovery_absent(control.as_raw_fd(), "generation-recovery-stopped.json")?;
    lock.revalidate().map_err(|_| refuse())?;
    observed.finish(ReadOnlyInstallEvidence::Held(&lock))?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_passive_unsealed_resume_readback_v1",
        "outcome": "resumed",
        "successor_intent_sha256": successor,
        "preinst_sha256": status["preinst_sha256"],
        "candidate_sha256": status["candidate_sha256"],
        "stage": pointer.stage,
        "recovery_sha256": digest(&recovery_bytes),
        "certificate_sha256": digest(&certificate),
        "journal_sha256": digest(&journal_bytes),
    }))
    .map_err(|_| refuse())
}

#[cfg(target_os = "linux")]
fn verify_passive_unsealed_stopped_stage_held(
    lock: &crate::profile_auto_stopped_service::InstallLock,
) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let evidence = installer_v2_generation::passive_transition_evidence_with_unsealed()?;
    let status_bytes = installer_v2_generation::passive_transition_status(&evidence, None)?;
    let status: serde_json::Value = serde_json::from_slice(&status_bytes).map_err(|_| refuse())?;
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), "current.json")?;
    let successor = status["successor_intent_sha256"]
        .as_str()
        .ok_or_else(refuse)?;
    let leaf = passive_unsealed_stopped_leaf(successor)?;
    let raw = read_passive_compensated(control.as_raw_fd(), &leaf)?;
    let record: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| refuse())?;
    let fields = record.as_object().ok_or_else(refuse)?;
    if fields.len() != 11
        || [
            "schema",
            "boot_id",
            "successor_intent_sha256",
            "preinst_sha256",
            "old_candidate_sha256",
            "candidate_sha256",
            "public_payload_root",
            "stage",
            "stopped_report_sha256",
            "pointer_sha256",
            "pointer_archive",
        ]
        .iter()
        .any(|key| !fields.contains_key(*key))
        || record["schema"] != "aegis_auto_v2_passive_unsealed_stopped_v1"
    {
        return Err(refuse());
    }
    let archive = record["pointer_archive"].as_str().ok_or_else(refuse)?;
    let pointer_bytes = read_passive_compensated(control.as_raw_fd(), archive)?;
    let pointer: InstallerRecoveryPointer =
        serde_json::from_slice(&pointer_bytes).map_err(|_| refuse())?;
    if !recovery_pointer_schema(&pointer) {
        return Err(refuse());
    }
    let certified = installer_v2_generation::unsealed_stopped_recovery_report()?;
    let observed = observe_stopped_generation_held(&pointer.stage, lock, None)?;
    observed.ensure_ready(ReadOnlyInstallEvidence::Held(lock))?;
    let fresh: serde_json::Value = serde_json::from_slice(&observed.bytes).map_err(|_| refuse())?;
    let expected =
        passive_unsealed_stopped_bytes(&status, &pointer, &fresh, &pointer_bytes, archive)?;
    if fresh != certified
        || raw != expected
        || record["boot_id"]
            != std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| refuse())?
                .trim()
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    observed.finish(ReadOnlyInstallEvidence::Held(lock))?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_passive_unsealed_stopped_readback_v1",
        "kind": "unsealed-finalized-stopped",
        "successor_intent_sha256": successor,
        "preinst_sha256": status["preinst_sha256"],
        "candidate_sha256": status["candidate_sha256"],
        "old_candidate_sha256": status["old_candidate_sha256"],
        "public_payload_root": status["public_payload_root"],
        "stage": pointer.stage,
        "stopped_report_sha256": record["stopped_report_sha256"],
        "pointer_sha256": digest(&pointer_bytes),
        "certificate_sha256": digest(&raw),
    }))
    .map_err(|_| refuse())
}

/// Retire a stopped Finalized generation that never acquired an active seal.
/// The installed candidate and its published roots remain in place.  This is
/// a recovery-only history transition, never an installed-success receipt.
#[cfg(target_os = "linux")]
pub(crate) fn recover_unsealed_finalized_stage(path: &Path) -> Result<()> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;

    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    let observed = observe_stopped_generation_held(path, &lock, None)?;
    observed.ensure_ready(ReadOnlyInstallEvidence::Held(&lock))?;
    let certified = installer_v2_generation::unsealed_stopped_recovery_report()?;
    let actual: serde_json::Value =
        serde_json::from_slice(&observed.bytes).map_err(|_| refuse())?;
    if actual != certified
        || certified["stage"]["path"] != path.to_string_lossy().as_ref()
        || certified["terminal"]["outcome"] != "finalized-stopped"
        || certified["main"]["stopped_verified"] != true
        || certified["guardian"]["deny_verified"] != true
    {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let pointer_fd = recovery_open_at(control.as_raw_fd(), "current.json", libc::O_RDONLY, 0)?;
    let before = recovery_stat(pointer_fd.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o600
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || !(1..=8192).contains(&before.st_size)
    {
        return Err(refuse());
    }
    let mut pointer_bytes = Vec::new();
    std::fs::File::from(pointer_fd.try_clone().map_err(|_| refuse())?)
        .take(8193)
        .read_to_end(&mut pointer_bytes)
        .map_err(|_| refuse())?;
    let after = recovery_stat(pointer_fd.as_raw_fd())?;
    if pointer_bytes.len() != before.st_size as usize
        || (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime,
            before.st_mtime_nsec,
            before.st_ctime,
            before.st_ctime_nsec,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime,
            after.st_mtime_nsec,
            after.st_ctime,
            after.st_ctime_nsec,
        )
    {
        return Err(refuse());
    }
    let pointer: InstallerRecoveryPointer =
        serde_json::from_slice(&pointer_bytes).map_err(|_| refuse())?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| refuse())?;
    if !recovery_pointer_schema(&pointer)
        || pointer.status != "pending"
        || pointer.stage != path
        || pointer.installed_binary != "/usr/local/bin/aegis-client"
        || pointer.boot_id != boot.trim()
        || certified["terminal"]["boot_id"] != pointer.boot_id
        || certified["input"]["candidate_sha256"] != pointer.candidate_sha256
        || !inspected_hex64(&pointer.candidate_sha256)
    {
        return Err(refuse());
    }
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if recovery_file_hash(running.as_raw_fd(), 256 * 1024 * 1024)?.1 != pointer.candidate_sha256 {
        return Err(refuse());
    }
    let public = Path::new(
        certified["input"]["public_payload_root"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let release_name = public
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(refuse)?;
    let release = recovery_chain(
        &["var", "lib", "aegis-auto", "releases", release_name],
        Some(0o700),
    )?;
    let release_bin = recovery_directory(release.as_raw_fd(), "bin", None)?;
    let candidate = recovery_open_at(release_bin.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    let candidate_stat = recovery_stat(candidate.as_raw_fd())?;
    if certified["input"]["candidate_binary"]
        != public.join("bin/aegis-client").to_string_lossy().as_ref()
        || candidate_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || candidate_stat.st_uid != 0
        || candidate_stat.st_gid != 0
        || candidate_stat.st_nlink != 1
        || !matches!(candidate_stat.st_mode & 0o7777, 0o555 | 0o755)
        || recovery_file_hash(candidate.as_raw_fd(), 256 * 1024 * 1024)?.1
            != pointer.candidate_sha256
    {
        return Err(refuse());
    }
    let installer = recovery_open_at(release.as_raw_fd(), "install.sh", libc::O_RDONLY, 0)?;
    let installer_stat = recovery_stat(installer.as_raw_fd())?;
    if installer_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || installer_stat.st_uid != 0
        || installer_stat.st_gid != 0
        || installer_stat.st_nlink != 1
        || !matches!(installer_stat.st_mode & 0o7777, 0o555 | 0o755)
        || recovery_file_hash(installer.as_raw_fd(), 8 * 1024 * 1024)?.1
            != digest(include_bytes!("../../install.sh"))
    {
        return Err(refuse());
    }
    let installed_dir = recovery_chain(&["usr", "local", "bin"], None)?;
    let installed = recovery_open_at(installed_dir.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    let installed_stat = recovery_stat(installed.as_raw_fd())?;
    if installed_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || installed_stat.st_uid != 0
        || installed_stat.st_gid != 0
        || installed_stat.st_nlink != 1
        || !matches!(installed_stat.st_mode & 0o7777, 0o555 | 0o755)
        || recovery_file_hash(installed.as_raw_fd(), 256 * 1024 * 1024)?.1
            != pointer.candidate_sha256
    {
        return Err(refuse());
    }
    if let Some(old) = &pointer.previous_binary {
        if !old.name.starts_with("backup-")
            || old.name.len() != 43
            || !old.name.ends_with(".bin")
            || !old.name[7..39]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || !inspected_hex64(&old.sha256)
            || old.device == 0
            || old.inode == 0
            || old.size == 0
            || !matches!(old.mode, 0o555 | 0o755)
        {
            return Err(refuse());
        }
        let backup = recovery_open_at(control.as_raw_fd(), &old.name, libc::O_RDONLY, 0)?;
        let s = recovery_stat(backup.as_raw_fd())?;
        if !recovery_backup_identity(old, &pointer.schema, &s)
            || recovery_file_hash(backup.as_raw_fd(), 256 * 1024 * 1024)?
                != (old.size, old.sha256.clone())
        {
            return Err(refuse());
        }
    }
    lock.revalidate().map_err(|_| refuse())?;
    let named = recovery_open_at(control.as_raw_fd(), "current.json", libc::O_RDONLY, 0)?;
    let named_stat = recovery_stat(named.as_raw_fd())?;
    let mut named_bytes = Vec::new();
    std::fs::File::from(named)
        .take(8193)
        .read_to_end(&mut named_bytes)
        .map_err(|_| refuse())?;
    if (named_stat.st_dev, named_stat.st_ino) != (before.st_dev, before.st_ino)
        || named_bytes != pointer_bytes
    {
        return Err(refuse());
    }
    let passive = if recovery_absent(control.as_raw_fd(), "passive-package-preinst.json").is_err() {
        let evidence = installer_v2_generation::passive_transition_evidence_with_unsealed()?;
        let status_bytes = installer_v2_generation::passive_transition_status(&evidence, None)?;
        let status: serde_json::Value =
            serde_json::from_slice(&status_bytes).map_err(|_| refuse())?;
        if certified["stage"]["mode"] != "socks-only"
            || certified["input"]["candidate_sha256"] != status["candidate_sha256"]
        {
            return Err(refuse());
        }
        Some(status)
    } else {
        None
    };
    let certificate_leaf = passive
        .as_ref()
        .map(|status| {
            passive_unsealed_stopped_leaf(
                status["successor_intent_sha256"]
                    .as_str()
                    .ok_or_else(refuse)?,
            )
        })
        .transpose()?;
    let existing_certificate = certificate_leaf
        .as_ref()
        .and_then(|leaf| {
            if recovery_absent(control.as_raw_fd(), leaf).is_ok() {
                None
            } else {
                Some(read_passive_compensated(control.as_raw_fd(), leaf))
            }
        })
        .transpose()?;
    let archive = if let Some(raw) = &existing_certificate {
        let value: serde_json::Value = serde_json::from_slice(raw).map_err(|_| refuse())?;
        value["pointer_archive"]
            .as_str()
            .ok_or_else(refuse)?
            .to_owned()
    } else {
        let mut nonce = [0u8; 16];
        if unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) }
            != nonce.len() as isize
        {
            return Err(refuse());
        }
        format!("archived-unsealed-stopped-{}.json", hex::encode(nonce))
    };
    if archive.len() != 63
        || !archive.starts_with("archived-unsealed-stopped-")
        || !archive.ends_with(".json")
        || !archive[26..58]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    if recovery_absent(control.as_raw_fd(), &archive).is_ok() {
        if existing_certificate.is_some() {
            return Err(refuse());
        }
        if passive.is_some() {
            installer_v2_generation::write_passive_atomic(
                control.as_raw_fd(),
                &archive,
                &pointer_bytes,
                8192,
            )?;
        } else {
            let archive_fd = recovery_open_at(
                control.as_raw_fd(),
                &archive,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            let mut file = std::fs::File::from(archive_fd);
            file.write_all(&pointer_bytes).map_err(|_| refuse())?;
            file.sync_all().map_err(|_| refuse())?;
            if unsafe { libc::fsync(control.as_raw_fd()) } != 0 {
                return Err(refuse());
            }
        }
    }
    if read_passive_compensated(control.as_raw_fd(), &archive)? != pointer_bytes {
        return Err(refuse());
    }
    if let (Some(status), Some(leaf)) = (&passive, &certificate_leaf) {
        let expected =
            passive_unsealed_stopped_bytes(status, &pointer, &certified, &pointer_bytes, &archive)?;
        if let Some(raw) = existing_certificate {
            if raw != expected {
                return Err(refuse());
            }
        } else {
            installer_v2_generation::write_passive_atomic(
                control.as_raw_fd(),
                leaf,
                &expected,
                8192,
            )?;
            if read_passive_compensated(control.as_raw_fd(), leaf)? != expected {
                return Err(refuse());
            }
        }
    }
    let last = recovery_open_at(control.as_raw_fd(), "current.json", libc::O_RDONLY, 0)?;
    let last_stat = recovery_stat(last.as_raw_fd())?;
    let mut last_bytes = Vec::new();
    std::fs::File::from(last)
        .take(8193)
        .read_to_end(&mut last_bytes)
        .map_err(|_| refuse())?;
    if (last_stat.st_dev, last_stat.st_ino) != (before.st_dev, before.st_ino)
        || last_bytes != pointer_bytes
        || installer_v2_generation::unsealed_stopped_recovery_report()? != certified
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    if unsafe { libc::unlinkat(control.as_raw_fd(), c"current.json".as_ptr(), 0) } != 0
        || unsafe { libc::fsync(control.as_raw_fd()) } != 0
    {
        return Err(refuse());
    }
    observed.finish(ReadOnlyInstallEvidence::Held(&lock))?;
    Ok(())
}

/// Retire the pending installer pointer for a normally sealed Finalized Stop.
/// The stopped StageGuard, guard flock, and original InstallLock remain held
/// until the exact pointer is archived and unlinked. A second caller cannot
/// retire a newer generation using an earlier Stop observation.
#[cfg(target_os = "linux")]
pub(crate) fn archive_stopped_generation_pointer(path: &Path) -> Result<()> {
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire_existing_read_only()
        .map_err(|_| refuse())?;
    archive_stopped_generation_pointer_held(path, &lock)
}

#[cfg(target_os = "linux")]
fn archive_stopped_generation_pointer_held(
    path: &Path,
    lock: &crate::profile_auto_stopped_service::InstallLock,
) -> Result<()> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;

    let active = installer_v2_generation::history_report()?;
    let stopped = installer_v2_generation::stopped_history_report()?;
    let observed = observe_stopped_generation_held(path, lock, Some(&active))?;
    observed.ensure_ready(ReadOnlyInstallEvidence::Held(lock))?;
    let stopped_bytes = serde_json::to_vec(&stopped).map_err(|_| refuse())?;
    if observed.bytes != stopped_bytes
        || stopped["stage"]["path"] != path.to_string_lossy().as_ref()
        || stopped["terminal"]["outcome"] != "finalized-stopped"
        || stopped["main"]["stopped_verified"] != true
        || stopped["guardian"]["deny_verified"] != true
    {
        return Err(refuse());
    }

    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    recovery_absent(control.as_raw_fd(), "generation-successor-current.json")?;
    let pointer_fd = recovery_open_at(control.as_raw_fd(), "current.json", libc::O_RDONLY, 0)?;
    let before = recovery_stat(pointer_fd.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o600
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || !(1..=8192).contains(&before.st_size)
    {
        return Err(refuse());
    }
    let mut pointer_bytes = Vec::new();
    std::fs::File::from(pointer_fd.try_clone().map_err(|_| refuse())?)
        .take(8193)
        .read_to_end(&mut pointer_bytes)
        .map_err(|_| refuse())?;
    let after = recovery_stat(pointer_fd.as_raw_fd())?;
    if pointer_bytes.len() != before.st_size as usize
        || (
            before.st_dev,
            before.st_ino,
            before.st_mtime,
            before.st_mtime_nsec,
            before.st_ctime,
            before.st_ctime_nsec,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mtime,
            after.st_mtime_nsec,
            after.st_ctime,
            after.st_ctime_nsec,
        )
    {
        return Err(refuse());
    }
    let pointer: InstallerRecoveryPointer =
        serde_json::from_slice(&pointer_bytes).map_err(|_| refuse())?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| refuse())?;
    if !recovery_pointer_schema(&pointer)
        || pointer.status != "pending"
        || pointer.stage != path
        || pointer.boot_id != boot.trim()
        || pointer.installed_binary != "/usr/local/bin/aegis-client"
        || !inspected_hex64(&pointer.candidate_sha256)
        || stopped["terminal"]["boot_id"] != pointer.boot_id
        || stopped["input"]["candidate_sha256"] != pointer.candidate_sha256
    {
        return Err(refuse());
    }
    let running = std::fs::File::open("/proc/self/exe").map_err(|_| refuse())?;
    if recovery_file_hash(running.as_raw_fd(), 256 * 1024 * 1024)?.1 != pointer.candidate_sha256 {
        return Err(refuse());
    }
    let public = Path::new(
        stopped["input"]["public_payload_root"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let release_name = public
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(refuse)?;
    if public != Path::new("/var/lib/aegis-auto/releases").join(release_name) {
        return Err(refuse());
    }
    let release = recovery_chain(
        &["var", "lib", "aegis-auto", "releases", release_name],
        Some(0o700),
    )?;
    let release_bin = recovery_directory(release.as_raw_fd(), "bin", None)?;
    let candidate = recovery_open_at(release_bin.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    let candidate_stat = recovery_stat(candidate.as_raw_fd())?;
    if stopped["input"]["candidate_binary"]
        != public.join("bin/aegis-client").to_string_lossy().as_ref()
        || candidate_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || candidate_stat.st_uid != 0
        || candidate_stat.st_gid != 0
        || candidate_stat.st_nlink != 1
        || !matches!(candidate_stat.st_mode & 0o7777, 0o555 | 0o755)
        || recovery_file_hash(candidate.as_raw_fd(), 256 * 1024 * 1024)?.1
            != pointer.candidate_sha256
    {
        return Err(refuse());
    }
    let installer = recovery_open_at(release.as_raw_fd(), "install.sh", libc::O_RDONLY, 0)?;
    let installer_stat = recovery_stat(installer.as_raw_fd())?;
    if installer_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || installer_stat.st_uid != 0
        || installer_stat.st_gid != 0
        || installer_stat.st_nlink != 1
        || !matches!(installer_stat.st_mode & 0o7777, 0o555 | 0o755)
        || recovery_file_hash(installer.as_raw_fd(), 8 * 1024 * 1024)?.1
            != digest(include_bytes!("../../install.sh"))
    {
        return Err(refuse());
    }
    let installed_dir = recovery_chain(&["usr", "local", "bin"], None)?;
    let installed = recovery_open_at(installed_dir.as_raw_fd(), "aegis-client", libc::O_RDONLY, 0)?;
    let installed_stat = recovery_stat(installed.as_raw_fd())?;
    if installed_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || installed_stat.st_uid != 0
        || installed_stat.st_gid != 0
        || installed_stat.st_nlink != 1
        || !matches!(installed_stat.st_mode & 0o7777, 0o555 | 0o755)
        || recovery_file_hash(installed.as_raw_fd(), 256 * 1024 * 1024)?.1
            != pointer.candidate_sha256
    {
        return Err(refuse());
    }
    if let Some(old) = &pointer.previous_binary {
        if !old.name.starts_with("backup-")
            || old.name.len() != 43
            || !old.name.ends_with(".bin")
            || !old.name[7..39]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !inspected_hex64(&old.sha256)
            || old.device == 0
            || old.inode == 0
            || old.size == 0
            || !matches!(old.mode, 0o555 | 0o755)
        {
            return Err(refuse());
        }
        let backup = recovery_open_at(control.as_raw_fd(), &old.name, libc::O_RDONLY, 0)?;
        let s = recovery_stat(backup.as_raw_fd())?;
        if !recovery_backup_identity(old, &pointer.schema, &s)
            || recovery_file_hash(backup.as_raw_fd(), 256 * 1024 * 1024)?
                != (old.size, old.sha256.clone())
        {
            return Err(refuse());
        }
    }

    let pointer_sha = digest(&pointer_bytes);
    let archive = format!("archived-stopped-{pointer_sha}.json");
    let receipt = serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_v2_stopped_pointer_archive_v1",
        "stage": path, "boot_id": pointer.boot_id,
        "candidate_sha256": pointer.candidate_sha256,
        "pointer_sha256": pointer_sha, "archive_leaf": archive,
        "stopped_report_sha256": digest(&stopped_bytes),
    }))
    .map_err(|_| refuse())?;
    let receipt_leaf = "generation-pointer-stopped.json".to_owned();
    for (leaf, expected) in [
        (&archive, pointer_bytes.as_slice()),
        (&receipt_leaf, receipt.as_slice()),
    ] {
        match recovery_open_at(control.as_raw_fd(), leaf, libc::O_RDONLY, 0) {
            Ok(fd) => {
                let s = recovery_stat(fd.as_raw_fd())?;
                if s.st_mode != libc::S_IFREG | 0o600
                    || s.st_uid != 0
                    || s.st_gid != 0
                    || s.st_nlink != 1
                    || s.st_size != expected.len() as i64
                    || recovery_file_hash(fd.as_raw_fd(), 8192)?.1 != digest(expected)
                {
                    return Err(refuse());
                }
            }
            Err(_) => {
                recovery_absent(control.as_raw_fd(), leaf)?;
                let fd = recovery_open_at(
                    control.as_raw_fd(),
                    leaf,
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    0o600,
                )?;
                let mut file = std::fs::File::from(fd);
                file.write_all(expected).map_err(|_| refuse())?;
                file.sync_all().map_err(|_| refuse())?;
                if unsafe { libc::fsync(control.as_raw_fd()) } != 0 {
                    return Err(refuse());
                }
                let named = recovery_open_at(control.as_raw_fd(), leaf, libc::O_RDONLY, 0)?;
                let s = recovery_stat(named.as_raw_fd())?;
                if s.st_mode != libc::S_IFREG | 0o600
                    || s.st_uid != 0
                    || s.st_gid != 0
                    || s.st_nlink != 1
                    || s.st_size != expected.len() as i64
                    || recovery_file_hash(named.as_raw_fd(), 8192)?.1 != digest(expected)
                {
                    return Err(refuse());
                }
            }
        }
    }
    lock.revalidate().map_err(|_| refuse())?;
    let last = recovery_open_at(control.as_raw_fd(), "current.json", libc::O_RDONLY, 0)?;
    let last_stat = recovery_stat(last.as_raw_fd())?;
    if (
        last_stat.st_dev,
        last_stat.st_ino,
        last_stat.st_size,
        last_stat.st_mtime,
        last_stat.st_mtime_nsec,
        last_stat.st_ctime,
        last_stat.st_ctime_nsec,
    ) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime,
        before.st_mtime_nsec,
        before.st_ctime,
        before.st_ctime_nsec,
    ) || recovery_file_hash(last.as_raw_fd(), 8192)?.1 != pointer_sha
        || installer_v2_generation::stopped_history_report()? != stopped
    {
        return Err(refuse());
    }
    if unsafe { libc::unlinkat(control.as_raw_fd(), c"current.json".as_ptr(), 0) } != 0
        || unsafe { libc::fsync(control.as_raw_fd()) } != 0
    {
        return Err(refuse());
    }
    observed.finish(ReadOnlyInstallEvidence::Held(lock))?;
    Ok(())
}
