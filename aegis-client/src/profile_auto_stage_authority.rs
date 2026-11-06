//! PRIVATE UNAPPLIED: concrete admission of one protected AUTO stage.
//! Protected root-owned bytes establish recipe authority. Public profile JSON,
//! supplied hashes, arbitrary path strings and other stages cannot mint capabilities.
use super::durable::Store;
use super::{absolute, digest, refuse, relative, AutoMode, Header, Phase, RecordSeal, Result};
#[cfg(test)]
use crate::profile_auto_capture::OwnPublicationAuthority;
use crate::profile_auto_capture::SealedStageAuthority;
use crate::profile_auto_capture::{self as capture, GenerationRecord, InputRole};
use crate::profile_auto_publication::linux::{self as publisher, PhaseAuthority, RecordClaim};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceBinding {
    pub stage_bytes: PathBuf,
    pub generation_leaf: PathBuf,
    pub original_path: PathBuf,
    pub final_path: PathBuf,
    pub expected_uid: Option<u32>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceBinding {
    pub role: String,
    pub original_path: PathBuf,
    pub generation_leaf: PathBuf,
    // Captured at PREPARE while the original capture guard remains admitted.
    // This is metadata only; never substitute a later inspect as the witness.
    pub publication_witness_leaf: Option<PathBuf>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub schema: u32,
    pub config_root: PathBuf,
    pub state_dir: PathBuf,
    pub metadata_dir: PathBuf,
    pub service_uid: u32,
    pub operator_uid: u32,
    pub logical_bundle: Option<PathBuf>,
    pub render_context: crate::profile_auto_render::RenderContext,
    pub sources: Vec<SourceBinding>,
    pub references: Vec<ReferenceBinding>,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Administrative AUTO stage authority refused",
    )
}
#[cfg(test)]
fn sha(raw: &str) -> io::Result<[u8; 32]> {
    let bytes = hex::decode(raw).map_err(|_| invalid())?;
    bytes.try_into().map_err(|_| invalid())
}
pub(super) fn receipt_chain(
    header: &Header,
    role: &str,
    phase: &str,
    predecessor: Option<&str>,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"aegis-auto-publication-chain-v1\0");
    for bytes in [
        header.transaction_nonce.as_bytes(),
        header.input_generation.as_bytes(),
        header.planned_generation.as_bytes(),
        role.as_bytes(),
        phase.as_bytes(),
        predecessor.unwrap_or("").as_bytes(),
    ] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    format!("{:x}", hash.finalize())
}
impl Manifest {
    pub(super) fn validate(&self, h: &Header) -> Result<()> {
        let expected_mode = match h.mode {
            AutoMode::SocksOnly => crate::profile_auto_render::SelectedMode::SocksOnly,
            AutoMode::WideRedirectSafe => {
                crate::profile_auto_render::SelectedMode::WideRedirectSafe
            }
            AutoMode::FullWideTun => crate::profile_auto_render::SelectedMode::FullWideTun,
        };
        if self.render_context.mode != expected_mode
            || self.render_context.logical_final_base != h.config_root
            || self.render_context.logical_original_base
                != self
                    .logical_bundle
                    .as_ref()
                    .unwrap_or(&h.config_root)
                    .as_path()
        {
            return Err(refuse());
        }
        if self.logical_bundle.as_ref().is_some_and(|p| {
            !absolute(p)
                || [&h.config_root, &h.state_dir, &h.metadata_dir]
                    .iter()
                    .any(|q| p.starts_with(q) || q.starts_with(p))
        }) {
            return Err(refuse());
        }
        if self.schema != 1
            || self.config_root != h.config_root
            || self.state_dir != h.state_dir
            || self.metadata_dir != h.metadata_dir
            || self.sources.len() > 1030
            || self.references.len() > 64
        {
            return Err(refuse());
        }
        let mut generations = BTreeSet::new();
        let mut names = BTreeSet::new();
        for src in &self.sources {
            if !matches!(
                src.role.as_str(),
                "config"
                    | "state"
                    | "metadata"
                    | "bundle-main"
                    | "bundle-ca"
                    | "bundle-supplementary"
                    | "bundle-masque"
                    | "prior-state"
                    | "reference"
            ) || !absolute(&src.original_path)
                || !relative(&src.generation_leaf)
                || !src.generation_leaf.starts_with("input/generations")
                || !generations.insert(src.generation_leaf.clone())
            {
                return Err(refuse());
            }
            if src.role != "reference" && !names.insert(src.role.clone()) {
                return Err(refuse());
            }
            if src.role.starts_with("bundle-")
                && self
                    .logical_bundle
                    .as_ref()
                    .is_none_or(|b| src.original_path.parent() != Some(b.as_path()))
            {
                return Err(refuse());
            }
            let expected = match src.role.as_str() {
                "config" => Some(&h.config_root),
                "state" => Some(&h.state_dir),
                "metadata" => Some(&h.metadata_dir),
                _ => None,
            };
            if expected.is_some_and(|p| p != &src.original_path) {
                return Err(refuse());
            }
            if src
                .publication_witness_leaf
                .as_ref()
                .is_some_and(|p| !relative(p) || !p.starts_with("input/publication-witnesses"))
            {
                return Err(refuse());
            }
        }
        if !["config", "state", "metadata"]
            .iter()
            .all(|n| names.contains(*n))
        {
            return Err(refuse());
        }
        let mut originals = BTreeSet::new();
        let mut finals = BTreeSet::new();
        for (index, r) in self.references.iter().enumerate() {
            if r.stage_bytes != Path::new(&format!("input/references/{index:04}/bytes"))
                || !absolute(&r.original_path)
                || !absolute(&r.final_path)
                || !originals.insert(r.original_path.clone())
                || !finals.insert(r.final_path.clone())
                || !generations.contains(&r.generation_leaf)
                || (r.final_path != r.original_path && !r.final_path.starts_with(&h.config_root))
            {
                return Err(refuse());
            }
            let src = self
                .sources
                .iter()
                .find(|s| s.generation_leaf == r.generation_leaf)
                .ok_or_else(refuse)?;
            if src.role != "reference" || src.original_path != r.original_path {
                return Err(refuse());
            }
        }
        Ok(())
    }
}
/// Expected root comes from independently admitted protected Header, never
/// from the serialized record alone. Generic records retain their original API.
pub(super) fn revalidate_record(
    record: &GenerationRecord,
    expected_config_root: &Path,
) -> Result<()> {
    match record.service_root() {
        Some(root)
            if root == expected_config_root
                && record.original_source().starts_with(expected_config_root)
                && matches!(record.role(), InputRole::ServiceInput { .. })
                && matches!(record.kind(), 1 | 3) =>
        {
            capture::reopen_service_generation(record, expected_config_root)
                .and_then(|g| g.revalidate())
                .map_err(|_| refuse())
        }
        Some(_) => Err(refuse()),
        None => capture::reopen_generation(record)
            .and_then(|g| g.revalidate())
            .map_err(|_| refuse()),
    }
}
/// Validate typed projection lineage against the exact retained protected
/// predecessor bytes. A record-provided SHA or generation is never authority.
pub(super) fn validate_projection_lineage(
    store: &Store,
    h: &Header,
    leaf: &Path,
    seal: &RecordSeal,
) -> Result<()> {
    if seal.phase != "projection" {
        return Ok(());
    }
    if seal.role != "config"
        || leaf.file_name() != Some(std::ffi::OsStr::new("projection-receipt.json"))
    {
        return Err(refuse());
    }
    let expected = seal.predecessor_sha256.as_ref().ok_or_else(refuse)?;
    let candidates: Vec<_> = h
        .current_records
        .iter()
        .filter(|(_, prior)| prior.role == "config" && prior.sha256 == *expected)
        .collect();
    if candidates.len() != 1 {
        return Err(refuse());
    }
    let (prior_leaf, prior_seal) = candidates[0];
    if prior_seal.phase != "config" {
        return Err(refuse());
    }
    let bytes = store.read(leaf)?;
    let prior_bytes = store.read(prior_leaf)?;
    if digest(&bytes) != seal.sha256 || digest(&prior_bytes) != *expected {
        return Err(refuse());
    }
    let projected: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    let prior: serde_json::Value = serde_json::from_slice(&prior_bytes).map_err(|_| refuse())?;
    if projected["kind"] != "projection"
        || prior["kind"] != "publication"
        || projected["base_record_sha256"] != *expected
        || projected["intent"] != prior["intent"]
        || projected["base_current"] != prior["current"]
        || projected["binding"]["transaction_nonce"] != h.transaction_nonce
        || projected["binding"]["phase"] != "projection"
        || projected["binding"]["chain_sha256"] != seal.chain_sha256
    {
        return Err(refuse());
    }
    store.revalidate()?;
    Ok(())
}
/// Holds the root stage, immutable header generation, all original-role records
/// and private payload hash binding during a single CLI invocation. No descriptor
/// lifetime is represented as durable across CLI calls.
pub(super) struct StageGuard {
    pub store: Store,
    pub header: Header,
    pub manifest: Manifest,
    records: BTreeMap<PathBuf, GenerationRecord>,
    header_sha: String,
}
impl StageGuard {
    /// The actor may borrow this exact admitted StageGuard when binding its
    /// pre-acquired locks. This remains pre-marker only; ordinary StageGuard
    /// methods are deliberately revoked once an activation leaf exists.
    #[allow(dead_code)]
    pub(super) fn revalidate_owner_pre_marker(&self) -> Result<()> {
        self.verify_self()
    }
    pub(super) fn admit(store: Store) -> Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(refuse());
        }
        Self::admit_actor(store, 0)
    }
    #[cfg(test)]
    pub(super) fn admit_fixture(store: Store, uid: u32) -> Result<Self> {
        if unsafe { libc::geteuid() } != uid {
            return Err(refuse());
        }
        Self::admit_actor(store, uid)
    }
    fn admit_actor(store: Store, uid: u32) -> Result<Self> {
        store.exclusive()?;
        store.revalidate()?;
        if store.activation_leaf_present()? {
            return Err(refuse());
        }
        let before = store.read(Path::new("header.json"))?;
        let header: Header = serde_json::from_slice(&before).map_err(|_| refuse())?;
        header.validate(uid)?;
        store.verify_payloads(&header)?;
        let leaf = Path::new("input/authority.json");
        let bytes = store.read(leaf)?;
        if header.leaves.get(leaf) != Some(&digest(&bytes)) {
            return Err(refuse());
        }
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
        manifest.validate(&header)?;
        let mut records = BTreeMap::new();
        for s in &manifest.sources {
            let bytes = store.read(&s.generation_leaf)?;
            if header.leaves.get(&s.generation_leaf) != Some(&digest(&bytes)) {
                return Err(refuse());
            }
            let r: GenerationRecord = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
            if r.original_source() != s.original_path
                || r.limits().depth > 8
                || r.limits().files > 1024
                || r.limits().directories > 1024
                || r.limits().file_bytes > 16 * 1024 * 1024
                || r.limits().tree_bytes > 64 * 1024 * 1024
            {
                return Err(refuse());
            }
            let role_ok = match (s.role.as_str(), r.role()) {
                ("metadata", InputRole::AdministratorMetadata { administrator_uid }) => {
                    administrator_uid == uid
                }
                (
                    "config" | "state" | "prior-state",
                    InputRole::ServiceInput {
                        service_uid,
                        administrator_uid,
                    },
                ) => service_uid == manifest.service_uid && administrator_uid == uid,
                (
                    "bundle-main" | "bundle-ca" | "bundle-supplementary" | "bundle-masque",
                    InputRole::ExplicitBundleData {
                        operator_uid,
                        administrator_uid,
                    },
                ) => operator_uid == manifest.operator_uid && administrator_uid == uid,
                ("reference", InputRole::PrivateCredential { expected_uid }) => {
                    manifest.references.iter().any(|b| {
                        b.generation_leaf == s.generation_leaf
                            && b.expected_uid == Some(expected_uid)
                    })
                }
                (
                    "reference",
                    InputRole::ServiceInput {
                        service_uid,
                        administrator_uid,
                    },
                ) => service_uid == manifest.service_uid && administrator_uid == uid,
                (
                    "reference",
                    InputRole::ExplicitBundleData {
                        operator_uid,
                        administrator_uid,
                    },
                ) => operator_uid == manifest.operator_uid && administrator_uid == uid,
                _ => false,
            };
            let kind_ok = match s.role.as_str() {
                "config" | "state" | "metadata" => matches!(r.kind(), 0 | 2),
                "prior-state"
                | "bundle-main"
                | "bundle-ca"
                | "bundle-supplementary"
                | "bundle-masque" => matches!(r.kind(), 1 | 3),
                "reference" => r.kind() == 1,
                _ => false,
            };
            if !role_ok || !kind_ok {
                return Err(refuse());
            }
            if let Some(boundary) = r.service_root() {
                if s.role != "reference"
                    || boundary != header.config_root.as_path()
                    || !r.original_source().starts_with(&header.config_root)
                    || !matches!(r.role(), InputRole::ServiceInput { .. })
                    || !matches!(r.kind(), 1 | 3)
                {
                    return Err(refuse());
                }
            }
            records.insert(s.generation_leaf.clone(), r);
        }
        let after = store.read(Path::new("header.json"))?;
        store.revalidate()?;
        if *before != *after {
            return Err(refuse());
        }
        Ok(Self {
            store,
            header,
            manifest,
            records,
            header_sha: digest(&before),
        })
    }
    pub(super) fn pending_intent_record(&self) -> Result<publisher::AuthenticatedIntent> {
        self.verify_self()?;
        let (leaf, seal) = self.header.pending.as_ref().ok_or_else(refuse)?;
        if leaf.file_name() != Some(std::ffi::OsStr::new("publication-intent.json")) {
            return Err(refuse());
        }
        let directory = leaf.parent().ok_or_else(refuse)?.to_path_buf();
        let sub = self.store.sub_store(&directory, false)?;
        let authority = RoleReceiptGuard {
            stage: self,
            role: seal.role.clone(),
            relative: directory,
        };
        publisher::authenticate_intent(sub.duplicate_root()?, &authority).map_err(|_| refuse())
    }
    /// Owns the descriptor publisher interval until the exact effect and
    /// protected receipt have both completed or the attempt has failed.
    pub(super) fn publication_lease(&self) -> Result<super::PublicationLease> {
        self.verify_self()?;
        self.store.publication_lease()
    }
    pub(super) fn begin_publication(
        &mut self,
        role: &str,
        phase: &str,
        intent: &publisher::PublicationIntent,
    ) -> Result<()> {
        self.verify_self()?;
        let expected = match (role, phase) {
            ("config", "custody") => Phase::Prepared,
            ("config", "config") => Phase::State,
            ("state", "state") => Phase::Custody,
            ("metadata", "metadata") => Phase::Config,
            ("config" | "state" | "metadata", "rollback") if !self.header.capture_started => {
                self.header.phase
            }
            _ => return Err(refuse()),
        };
        if self.header.phase != expected || self.header.pending.is_some() {
            return Err(refuse());
        }
        let directory = PathBuf::from(format!("receipts/{role}-{phase}"));
        let sub = self.store.sub_store(&directory, true)?;
        let (dev, ino) = sub.identity()?;
        let predecessor = self
            .header
            .active_records
            .get(role)
            .and_then(|p| self.header.current_records.get(p))
            .map(|r| r.sha256.clone());
        let chain = receipt_chain(&self.header, role, phase, predecessor.as_deref());
        let binding = publisher::RecordBinding {
            transaction_stage: publisher::Identity { dev, ino },
            transaction_nonce: self.header.transaction_nonce.clone(),
            phase: phase.into(),
            chain_sha256: chain.clone(),
        };
        let bytes = intent.durable_bytes(binding).map_err(|_| refuse())?;
        sub.write_new(Path::new("publication-intent.json"), &bytes)?;
        self.header.pending = Some((
            directory.join("publication-intent.json"),
            RecordSeal {
                role: role.into(),
                phase: phase.into(),
                predecessor_sha256: predecessor,
                chain_sha256: chain,
                sha256: digest(&bytes),
                stage_dev: dev,
                stage_ino: ino,
            },
        ));
        self.persist_header()
    }
    /// Only a descriptor-minted completed receipt may advance the phase. A lost
    /// final record never changes an intent into a public boolean success claim.
    pub(super) fn accept_publication(
        &mut self,
        role: &str,
        receipt: &publisher::PublicationReceipt,
    ) -> Result<()> {
        self.verify_self()?;
        let (intent_leaf, pending) = self.header.pending.as_ref().ok_or_else(refuse)?;
        if pending.role != role {
            return Err(refuse());
        }
        let directory = intent_leaf.parent().ok_or_else(refuse)?.to_path_buf();
        let sub = self.store.sub_store(&directory, false)?;
        let binding = publisher::RecordBinding {
            transaction_stage: publisher::Identity {
                dev: pending.stage_dev,
                ino: pending.stage_ino,
            },
            transaction_nonce: self.header.transaction_nonce.clone(),
            phase: pending.phase.clone(),
            chain_sha256: pending.chain_sha256.clone(),
        };
        let intent_bytes = receipt
            .intent()
            .durable_bytes(binding.clone())
            .map_err(|_| refuse())?;
        if digest(&intent_bytes) != pending.sha256 {
            return Err(refuse());
        }
        let bytes = receipt.durable_bytes(binding).map_err(|_| refuse())?;
        sub.write_new(Path::new("publication-receipt.json"), &bytes)?;
        let leaf = directory.join("publication-receipt.json");
        let mut seal = pending.clone();
        seal.sha256 = digest(&bytes);
        let next = match (role, pending.phase.as_str()) {
            ("config", "custody") => Phase::Custody,
            ("config", "config") => Phase::Config,
            ("state", "state") => Phase::State,
            ("metadata", "metadata") => Phase::Metadata,
            ("config" | "state" | "metadata", "rollback") if !self.header.capture_started => {
                self.header.phase
            }
            _ => return Err(refuse()),
        };
        self.header.current_records.insert(leaf.clone(), seal);
        self.header.active_records.insert(role.into(), leaf);
        self.header.pending = None;
        self.header.phase = next;
        self.persist_header()
    }
    pub(super) fn clear_unpublished_pending(&mut self, role: &str) -> Result<()> {
        self.verify_self()?;
        let (_, pending) = self.header.pending.as_ref().ok_or_else(refuse)?;
        if pending.role != role {
            return Err(refuse());
        }
        // Caller MUST have classified the authenticated held namespace as
        // BeforeRename/BeforeRetirement. Preserve the exact old envelope and
        // advance only the private ordinal; never overwrite a failed attempt.
        if let Some((leaf, seal)) = &self.header.pending {
            if leaf.file_name() == Some(std::ffi::OsStr::new("withdrawal-intent.json")) {
                self.header.leaves.insert(leaf.clone(), seal.sha256.clone());
            }
        }
        self.header.pending = None;
        self.persist_header()
    }
    /// Recovery is typed by the protected pending filename, not by an
    /// untrusted JSON shape or an assertion that the namespace is absent.
    pub(super) fn recover_pending_withdrawal(&mut self, role: &str) -> Result<()> {
        let _publication_lease = self.publication_lease()?;
        self.verify_self()?;
        let (leaf, seal) = self.header.pending.as_ref().ok_or_else(refuse)?;
        if self.header.capture_started
            || seal.role != role
            || seal.phase != "rollback"
            || leaf.file_name() != Some(std::ffi::OsStr::new("withdrawal-intent.json"))
        {
            return Err(refuse());
        }
        let active = self.header.active_records.get(role).ok_or_else(refuse)?;
        if self.header.current_records.get(active).map(|s| &s.sha256)
            != seal.predecessor_sha256.as_ref()
        {
            return Err(refuse());
        }
        let target_path = match role {
            "config" => &self.header.config_root,
            "state" => &self.header.state_dir,
            "metadata" => &self.header.metadata_dir,
            _ => return Err(refuse()),
        };
        let target = publisher::Target::open(target_path).map_err(|_| refuse())?;
        let relative = leaf.parent().ok_or_else(refuse)?.to_path_buf();
        let result = {
            let sub = self.store.sub_store(&relative, false)?;
            let authority = RoleReceiptGuard {
                stage: self,
                role: role.into(),
                relative,
            };
            let pending =
                publisher::authenticate_withdrawal_intent(sub.duplicate_root()?, &authority)
                    .map_err(|_| refuse())?;
            publisher::recover_withdrawal_receipt(&target, &pending, &authority)
                .map_err(|_| refuse())?
        };
        match result {
            Some(receipt) => self.accept_withdrawal(role, &receipt),
            None => self.clear_unpublished_pending(role),
        }
    }
    pub(super) fn begin_withdrawal(
        &mut self,
        role: &str,
        intent: &publisher::WithdrawalIntent,
    ) -> Result<()> {
        self.verify_self()?;
        if self.header.capture_started
            || self.header.pending.is_some()
            || !matches!(role, "config" | "state" | "metadata")
        {
            return Err(refuse());
        }
        if role == "state" {
            let source = self
                .manifest
                .sources
                .iter()
                .find(|s| s.role == "state")
                .ok_or_else(refuse)?;
            let original = self
                .records
                .get(&source.generation_leaf)
                .ok_or_else(refuse)?;
            if original.kind() != 2
                || original.original_source() != self.header.state_dir
                || source.original_path != self.header.state_dir
                || intent.target() != self.header.state_dir
            {
                return Err(refuse());
            }
            let admitted = self.publication_record("state")?;
            let target = publisher::Target::open(&self.header.state_dir).map_err(|_| refuse())?;
            let current =
                publisher::reopen_own_receipt(&target, &admitted).map_err(|_| refuse())?;
            if current.intent().epoch() != intent.publication_epoch() {
                return Err(refuse());
            }
            publisher::revalidate_current_receipt(&target, &current).map_err(|_| refuse())?;
        }
        let active = self.header.active_records.get(role).ok_or_else(refuse)?;
        let predecessor = self
            .header
            .current_records
            .get(active)
            .ok_or_else(refuse)?
            .sha256
            .clone();
        // Preserve every previous interrupted intent; a fresh attempt receives
        // a closed, ordinal stage under the same protected transaction.
        let ordinal = self.header.current_records.len() + self.header.leaves.len();
        let directory = PathBuf::from(format!("receipts/{role}-withdrawal-{ordinal:04}"));
        let sub = self.store.sub_store(&directory, true)?;
        let (dev, ino) = sub.identity()?;
        let chain = receipt_chain(&self.header, role, "rollback", Some(&predecessor));
        let binding = publisher::RecordBinding {
            transaction_stage: publisher::Identity { dev, ino },
            transaction_nonce: self.header.transaction_nonce.clone(),
            phase: "rollback".into(),
            chain_sha256: chain.clone(),
        };
        let bytes = intent.durable_bytes(binding).map_err(|_| refuse())?;
        sub.write_new(Path::new("withdrawal-intent.json"), &bytes)?;
        self.header.pending = Some((
            directory.join("withdrawal-intent.json"),
            RecordSeal {
                role: role.into(),
                phase: "rollback".into(),
                predecessor_sha256: Some(predecessor),
                chain_sha256: chain,
                sha256: digest(&bytes),
                stage_dev: dev,
                stage_ino: ino,
            },
        ));
        self.persist_header()
    }
    pub(super) fn accept_withdrawal(
        &mut self,
        role: &str,
        receipt: &publisher::WithdrawalReceipt,
    ) -> Result<()> {
        self.accept_withdrawal_inner(
            role,
            receipt,
            #[cfg(test)]
            false,
        )
    }
    fn accept_withdrawal_inner(
        &mut self,
        role: &str,
        receipt: &publisher::WithdrawalReceipt,
        #[cfg(test)] interrupt_before_header: bool,
    ) -> Result<()> {
        self.verify_self()?;
        let (leaf, pending) = self.header.pending.as_ref().ok_or_else(refuse)?;
        if self.header.capture_started
            || pending.role != role
            || pending.phase != "rollback"
            || leaf.file_name() != Some(std::ffi::OsStr::new("withdrawal-intent.json"))
        {
            return Err(refuse());
        }
        let active = self.header.active_records.get(role).ok_or_else(refuse)?;
        if self
            .header
            .current_records
            .get(active)
            .map(|seal| &seal.sha256)
            != pending.predecessor_sha256.as_ref()
        {
            return Err(refuse());
        }
        let directory = leaf.parent().ok_or_else(refuse)?.to_path_buf();
        let sub = self.store.sub_store(&directory, false)?;
        // Re-admit exactly this actual pending envelope/attempt, never a
        // historical digest or the mere existence of an unsealed receipt.
        let pending_authority = RoleReceiptGuard {
            stage: self,
            role: role.into(),
            relative: directory.clone(),
        };
        let admitted_pending =
            publisher::authenticate_withdrawal_intent(sub.duplicate_root()?, &pending_authority)
                .map_err(|_| refuse())?;
        admitted_pending
            .revalidate_authority(&pending_authority)
            .map_err(|_| refuse())?;
        let binding = publisher::RecordBinding {
            transaction_stage: publisher::Identity {
                dev: pending.stage_dev,
                ino: pending.stage_ino,
            },
            transaction_nonce: self.header.transaction_nonce.clone(),
            phase: pending.phase.clone(),
            chain_sha256: pending.chain_sha256.clone(),
        };
        let actual_intent = receipt
            .intent()
            .durable_bytes(binding.clone())
            .map_err(|_| refuse())?;
        if digest(&actual_intent) != pending.sha256 {
            return Err(refuse());
        }
        let target_path = match role {
            "config" => &self.header.config_root,
            "state" => &self.header.state_dir,
            "metadata" => &self.header.metadata_dir,
            _ => return Err(refuse()),
        };
        if receipt.intent().target() != target_path {
            return Err(refuse());
        }
        let target = publisher::Target::open(target_path).map_err(|_| refuse())?;
        publisher::revalidate_withdrawal(&target, receipt).map_err(|_| refuse())?;
        let bytes = receipt.durable_bytes(binding).map_err(|_| refuse())?;
        sub.write_or_verify_withdrawal_receipt(&bytes)?;
        admitted_pending
            .revalidate_authority(&pending_authority)
            .map_err(|_| refuse())?;
        publisher::revalidate_withdrawal(&target, receipt).map_err(|_| refuse())?;
        #[cfg(test)]
        if interrupt_before_header {
            return Err(refuse());
        }
        // Receipt check on interrupted-reentry must use actual WithdrawalIntent
        // identity/epoch; don't turn a raw serialized shape into absence proof.
        let result = directory.join("withdrawal-receipt.json");
        let mut seal = pending.clone();
        seal.sha256 = digest(&bytes);
        self.header.current_records.insert(result.clone(), seal);
        self.header.active_records.remove(role);
        self.header.pending = None;
        self.persist_header()?;
        publisher::revalidate_withdrawal(&target, receipt).map_err(|_| refuse())
    }
    pub(super) fn begin_projection(
        &mut self,
        intent: &publisher::ProjectionIntent,
        rendered: &crate::profile_auto_render::PreparedRender,
    ) -> Result<()> {
        self.verify_self()?;
        if self.header.phase != Phase::Metadata
            || !self.header.capture_started
            || self.header.pending.is_some()
            || matches!(self.header.mode, AutoMode::SocksOnly)
            || serde_json::to_vec(&rendered.context).map_err(|_| refuse())?
                != serde_json::to_vec(&self.manifest.render_context).map_err(|_| refuse())?
        {
            return Err(refuse());
        }
        let active = self
            .header
            .active_records
            .get("config")
            .ok_or_else(refuse)?;
        let prior = self.header.current_records.get(active).ok_or_else(refuse)?;
        if prior.role != "config" || prior.phase != "config" {
            return Err(refuse());
        }
        let predecessor = prior.sha256.clone();
        let directory = PathBuf::from("receipts/config-projection");
        let sub = self.store.sub_store(&directory, true)?;
        let (dev, ino) = sub.identity()?;
        let chain = receipt_chain(&self.header, "config", "projection", Some(&predecessor));
        let binding = publisher::RecordBinding {
            transaction_stage: publisher::Identity { dev, ino },
            transaction_nonce: self.header.transaction_nonce.clone(),
            phase: "projection".into(),
            chain_sha256: chain.clone(),
        };
        let encoded = intent.durable_bytes(binding).map_err(|_| refuse())?;
        let proposed: serde_json::Value = serde_json::from_slice(&encoded).map_err(|_| refuse())?;
        let prior_bytes = self.store.read(active)?;
        if digest(&prior_bytes) != predecessor {
            return Err(refuse());
        }
        let old: serde_json::Value = serde_json::from_slice(&prior_bytes).map_err(|_| refuse())?;
        if proposed["projection"]["base_record_sha256"] != predecessor
            || proposed["projection"]["intent"] != old["intent"]
            || proposed["projection"]["base_current"] != old["current"]
        {
            return Err(refuse());
        }
        let recipe = rendered.export_private_recipe().map_err(|_| refuse())?;
        let recipe_leaf = PathBuf::from("accepted/final-render-recipe.json");
        if self.header.leaves.contains_key(&recipe_leaf) {
            return Err(refuse());
        }
        // Formatting can enlarge the final encoded recipe. Enforce the exact
        // unchanged aggregate cap before appending any new private payload;
        // original-generation bytes are never reread here.
        let mut total = recipe.len();
        for (leaf, expected) in &self.header.leaves {
            let bytes = self.store.read(leaf)?;
            if digest(&bytes) != *expected {
                return Err(refuse());
            }
            total = total.checked_add(bytes.len()).ok_or_else(refuse)?;
            if total > super::MAX_STAGE {
                return Err(refuse());
            }
        }
        self.store.write_new(&recipe_leaf, &recipe)?;
        self.header.leaves.insert(recipe_leaf, digest(&recipe));
        sub.write_new(Path::new("projection-intent.json"), &encoded)?;
        self.header.pending = Some((
            directory.join("projection-intent.json"),
            RecordSeal {
                role: "config".into(),
                phase: "projection".into(),
                predecessor_sha256: Some(predecessor),
                chain_sha256: chain,
                sha256: digest(&encoded),
                stage_dev: dev,
                stage_ino: ino,
            },
        ));
        self.persist_header()
    }
    pub(super) fn accept_projection(
        &mut self,
        receipt: &publisher::ProjectionReceipt,
        rendered: &crate::profile_auto_render::PreparedRender,
    ) -> Result<()> {
        self.verify_self()?;
        let (intent_leaf, pending) = self.header.pending.as_ref().ok_or_else(refuse)?;
        if self.header.phase != Phase::Metadata
            || !self.header.capture_started
            || pending.role != "config"
            || pending.phase != "projection"
            || intent_leaf != Path::new("receipts/config-projection/projection-intent.json")
            || pending.predecessor_sha256.as_deref() != Some(receipt.source_record_sha256())
        {
            return Err(refuse());
        }
        let binding = publisher::RecordBinding {
            transaction_stage: publisher::Identity {
                dev: pending.stage_dev,
                ino: pending.stage_ino,
            },
            transaction_nonce: self.header.transaction_nonce.clone(),
            phase: "projection".into(),
            chain_sha256: pending.chain_sha256.clone(),
        };
        let encoded_intent = receipt
            .intent()
            .durable_bytes(binding.clone())
            .map_err(|_| refuse())?;
        if digest(&encoded_intent) != pending.sha256 {
            return Err(refuse());
        }
        let recipe_leaf = PathBuf::from("accepted/final-render-recipe.json");
        let recipe = rendered.export_private_recipe().map_err(|_| refuse())?;
        if self.header.leaves.get(&recipe_leaf) != Some(&digest(&recipe)) {
            return Err(refuse());
        }
        let sub = self
            .store
            .sub_store(Path::new("receipts/config-projection"), false)?;
        let bytes = receipt.durable_bytes(binding).map_err(|_| refuse())?;
        sub.write_new(Path::new("projection-receipt.json"), &bytes)?;
        let leaf = PathBuf::from("receipts/config-projection/projection-receipt.json");
        let mut seal = pending.clone();
        seal.sha256 = digest(&bytes);
        self.header
            .current_records
            .insert(leaf.clone(), seal.clone());
        self.header
            .active_records
            .insert("config".into(), leaf.clone());
        validate_projection_lineage(&self.store, &self.header, &leaf, &seal)?;
        self.header.pending = None;
        self.header.render_recipe = recipe_leaf;
        self.persist_header()
    }
    pub(super) fn persist_header(&mut self) -> Result<()> {
        self.store.save_header(&self.header)?;
        self.header_sha = digest(&self.store.read(Path::new("header.json"))?);
        self.verify_self()
    }
    pub(super) fn revalidate_originals(&self) -> Result<()> {
        self.verify_self()?;
        for record in self.records.values() {
            revalidate_record(record, &self.header.config_root)?;
        }
        self.verify_self()
    }
    /// Post-rollback readback for a role that has no publication record at all.
    /// The role and path come from the protected Manifest, never a caller path.
    pub(super) fn revalidate_untouched_original_role(&self, role: &str) -> Result<()> {
        self.verify_self()?;
        if !matches!(role, "config" | "state" | "metadata")
            || self
                .header
                .current_records
                .values()
                .any(|record| record.role == role)
            || self.header.active_records.contains_key(role)
        {
            return Err(refuse());
        }
        let mut matching = self
            .manifest
            .sources
            .iter()
            .filter(|source| source.role == role);
        let source = matching.next().ok_or_else(refuse)?;
        if matching.next().is_some() {
            return Err(refuse());
        }
        let record = self
            .records
            .get(&source.generation_leaf)
            .ok_or_else(refuse)?;
        revalidate_record(record, &self.header.config_root)?;
        self.verify_self()
    }
    fn verify_self(&self) -> Result<()> {
        self.store.revalidate()?;
        // A held guard is revoked too: an orphan intent/consumption must not
        // permit normal publication through an already admitted descriptor.
        if self.store.activation_leaf_present()? && !self.store.owner_effect_active()? {
            return Err(refuse());
        }
        if digest(&self.store.read(Path::new("header.json"))?) != self.header_sha {
            return Err(refuse());
        }
        self.store.verify_payloads(&self.header)
    }
    #[cfg(test)]
    fn binding(
        &self,
        path: &Path,
        original: &GenerationRecord,
        uid: u32,
    ) -> Result<&ReferenceBinding> {
        let relative = path.strip_prefix(self.store.path()).map_err(|_| refuse())?;
        let b = self
            .manifest
            .references
            .iter()
            .find(|b| {
                b.stage_bytes == relative
                    && b.expected_uid == Some(uid)
                    && b.original_path == original.original_source()
            })
            .ok_or_else(refuse)?;
        let r = self.records.get(&b.generation_leaf).ok_or_else(refuse)?;
        if !matches!(r.role(),InputRole::PrivateCredential{expected_uid} if expected_uid==uid)
            || r.kind() != 1
            || serde_json::to_vec(r).map_err(|_| refuse())?
                != serde_json::to_vec(original).map_err(|_| refuse())?
        {
            return Err(refuse());
        }
        Ok(b)
    }
    #[cfg(test)]
    pub(super) fn private_record(&self, index: usize) -> Result<&GenerationRecord> {
        let b = self.manifest.references.get(index).ok_or_else(refuse)?;
        self.records.get(&b.generation_leaf).ok_or_else(refuse)
    }
    /// Reopen completed withdrawal receipts through protected journals and
    /// held retired descriptors. An unrelated new target refuses completion.
    pub(super) fn verify_completed_withdrawals(&self) -> Result<()> {
        self.verify_self()?;
        if self.header.pending.is_some() || self.header.capture_started {
            return Err(refuse());
        }
        for (leaf, seal) in &self.header.current_records {
            if leaf.file_name() != Some(std::ffi::OsStr::new("withdrawal-receipt.json")) {
                continue;
            }
            if seal.phase != "rollback" || self.header.active_records.contains_key(&seal.role) {
                return Err(refuse());
            }
            let target_path = match seal.role.as_str() {
                "config" => &self.header.config_root,
                "state" => &self.header.state_dir,
                "metadata" => &self.header.metadata_dir,
                _ => return Err(refuse()),
            };
            let directory = leaf.parent().ok_or_else(refuse)?.to_path_buf();
            let sub = self.store.sub_store(&directory, false)?;
            let guard = RoleReceiptGuard {
                stage: self,
                role: seal.role.clone(),
                relative: directory,
            };
            let admitted = publisher::authenticate_record(
                sub.duplicate_root()?,
                "withdrawal-receipt.json",
                &guard,
            )
            .map_err(|_| refuse())?;
            let target = publisher::Target::open(target_path).map_err(|_| refuse())?;
            let own =
                publisher::reopen_withdrawal_receipt(&target, &admitted).map_err(|_| refuse())?;
            publisher::revalidate_withdrawal(&target, &own).map_err(|_| refuse())?;
        }
        self.verify_self()
    }
    pub(super) fn publication_record(&self, role: &str) -> Result<publisher::AuthenticatedRecord> {
        self.verify_self()?;
        if !matches!(role, "config" | "state" | "metadata") {
            return Err(refuse());
        }
        let current = self.header.active_records.get(role).ok_or_else(refuse)?;
        let directory = current.parent().ok_or_else(refuse)?.to_path_buf();
        let sub = self.store.sub_store(&directory, false)?;
        let role_guard = RoleReceiptGuard {
            stage: self,
            role: role.into(),
            relative: directory,
        };
        let seal = self
            .header
            .current_records
            .get(current)
            .ok_or_else(refuse)?;
        validate_projection_lineage(&self.store, &self.header, current, seal)?;
        let filename = current
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(refuse)?;
        publisher::authenticate_record(sub.duplicate_root()?, filename, &role_guard)
            .map_err(|_| refuse())
    }

    /// Postterminal inspection only: re-open the authenticated live target
    /// against its protected receipt. This grants no publication operation.
    pub(super) fn inspect_current_published_roots(&self) -> Result<BTreeMap<String, String>> {
        self.inspect_current_published_roles(&[
            ("config", self.header.config_root.as_path()),
            ("state", self.header.state_dir.as_path()),
        ])
    }

    /// Active generation: configuration and metadata stay byte-for-byte
    /// immutable. The state tree belongs to the running Main and may change;
    /// bind its protected publication record to the same live root directory.
    /// The caller must also validate typed Main and guardian lifecycle proof.
    /// Keep the historical stopped-stage inspector's two-role wire shape.
    pub(super) fn inspect_current_published_roots_with_metadata(
        &self,
    ) -> Result<BTreeMap<String, String>> {
        let mut result = self.inspect_current_published_roles(&[
            ("config", self.header.config_root.as_path()),
            ("metadata", self.header.metadata_dir.as_path()),
        ])?;
        let admitted = self.publication_record("state")?;
        let target = publisher::Target::open(&self.header.state_dir).map_err(|_| refuse())?;
        result.insert(
            "state".into(),
            admitted
                .live_mutable_root_binding_sha256(&target)
                .map_err(|_| refuse())?,
        );
        self.verify_self()?;
        Ok(result)
    }

    fn inspect_current_published_roles(
        &self,
        roles: &[(&str, &Path)],
    ) -> Result<BTreeMap<String, String>> {
        let mut result = BTreeMap::new();
        for &(role, path) in roles {
            let admitted = self.publication_record(role)?;
            let target = publisher::Target::open(path).map_err(|_| refuse())?;
            let current =
                publisher::reopen_own_receipt(&target, &admitted).map_err(|_| refuse())?;
            publisher::revalidate_current_receipt(&target, &current).map_err(|_| refuse())?;
            let generation = serde_json::to_vec(current.generation()).map_err(|_| refuse())?;
            result.insert(role.to_owned(), digest(&generation));
        }
        self.verify_self()?;
        Ok(result)
    }
}
impl SealedStageAuthority for StageGuard {
    fn revalidate(&self) -> io::Result<()> {
        self.verify_self().map_err(|_| invalid())
    }
    #[cfg(test)]
    fn admitted_stage_sha256(&self, path: &Path) -> io::Result<[u8; 32]> {
        self.verify_self().map_err(|_| invalid())?;
        let relative = path
            .strip_prefix(self.store.path())
            .map_err(|_| invalid())?;
        if !self
            .manifest
            .references
            .iter()
            .any(|r| r.stage_bytes == relative)
        {
            return Err(invalid());
        }
        sha(self.header.leaves.get(relative).ok_or_else(invalid)?)
    }
    #[cfg(test)]
    fn admit_private_original(
        &self,
        path: &Path,
        original: &GenerationRecord,
        uid: u32,
    ) -> io::Result<()> {
        self.verify_self().map_err(|_| invalid())?;
        self.binding(path, original, uid).map_err(|_| invalid())?;
        Ok(())
    }
}
#[cfg(test)]
impl OwnPublicationAuthority for StageGuard {
    fn source_stage_authority(&self) -> &dyn SealedStageAuthority {
        self
    }
    fn admit_retired_private_original(
        &self,
        path: &Path,
        original: &GenerationRecord,
        uid: u32,
    ) -> io::Result<()> {
        self.verify_self().map_err(|_| invalid())?;
        let b = self.binding(path, original, uid).map_err(|_| invalid())?;
        if !matches!(
            self.header.phase,
            Phase::Custody
                | Phase::State
                | Phase::Config
                | Phase::Metadata
                | Phase::Finalized
                | Phase::NativeRecoveryRequired
        ) || !b.original_path.starts_with(&self.header.config_root)
            || b.original_path == self.header.config_root
        {
            return Err(invalid());
        }
        let accepted = self.publication_record("config").map_err(|_| invalid())?;
        let target = publisher::Target::open(&self.header.config_root).map_err(|_| invalid())?;
        let receipt = publisher::reopen_own_receipt(&target, &accepted).map_err(|_| invalid())?;
        publisher::revalidate_current_receipt(&target, &receipt).map_err(|_| invalid())?;
        self.verify_self().map_err(|_| invalid())
    }
}
struct RoleReceiptGuard<'a> {
    stage: &'a StageGuard,
    role: String,
    relative: PathBuf,
}
impl PhaseAuthority for RoleReceiptGuard<'_> {
    fn validate_record_claim(&self, c: &RecordClaim) -> publisher::Result<()> {
        self.stage
            .verify_self()
            .map_err(|_| "AUTO receipt authority refused")?;
        let leaf = self.relative.join(&c.record_leaf);
        let pending = matches!(
            c.record_leaf.as_str(),
            "publication-intent.json" | "withdrawal-intent.json"
        );
        let seal = if pending {
            match &self.stage.header.pending {
                Some((p, seal)) if p == &leaf => seal,
                _ => return Err("AUTO pending authority refused"),
            }
        } else {
            self.stage
                .header
                .current_records
                .get(&leaf)
                .ok_or("AUTO receipt authority refused")?
        };
        let sub = self
            .stage
            .store
            .sub_store(&self.relative, false)
            .map_err(|_| "AUTO receipt authority refused")?;
        let (dev, ino) = sub
            .identity()
            .map_err(|_| "AUTO receipt authority refused")?;
        if c.administrator_uid != self.stage.header.administrator_uid
            || c.actual_stage.dev != dev
            || c.actual_stage.ino != ino
            || seal.stage_dev != dev
            || seal.stage_ino != ino
            || seal.role != self.role
            || seal.sha256 != c.record_sha256
            || c.binding.transaction_stage != c.actual_stage
            || c.binding.transaction_nonce != self.stage.header.transaction_nonce
            || c.binding.phase != seal.phase
            || c.binding.chain_sha256 != seal.chain_sha256
            || seal.chain_sha256
                != receipt_chain(
                    &self.stage.header,
                    &seal.role,
                    &seal.phase,
                    seal.predecessor_sha256.as_deref(),
                )
        {
            return Err("AUTO receipt authority refused");
        }
        if pending {
            let prior = match seal.phase.as_str() {
                "custody" => Phase::Prepared,
                "config" => Phase::State,
                "state" => Phase::Custody,
                "metadata" => Phase::Config,
                "rollback" => self.stage.header.phase,
                _ => return Err("AUTO pending phase refused"),
            };
            if self.stage.header.phase != prior {
                return Err("AUTO pending phase refused");
            }
            return Ok(());
        }
        // Only operations already committed in the stage's phase may retire an input.
        let admitted = match self.role.as_str() {
            "config" => match seal.phase.as_str() {
                "custody" => self.stage.header.phase != Phase::Prepared,
                "config" => matches!(
                    self.stage.header.phase,
                    Phase::Config
                        | Phase::Metadata
                        | Phase::Finalized
                        | Phase::NativeRecoveryRequired
                ),
                "projection" => matches!(
                    self.stage.header.phase,
                    Phase::Metadata | Phase::Finalized | Phase::NativeRecoveryRequired
                ),
                "rollback" => {
                    !self.stage.header.capture_started && self.stage.header.phase != Phase::Prepared
                }
                _ => false,
            },
            "state" => matches!(
                self.stage.header.phase,
                Phase::State
                    | Phase::Config
                    | Phase::Metadata
                    | Phase::Finalized
                    | Phase::NativeRecoveryRequired
            ),
            "metadata" => {
                (seal.phase == "metadata"
                    && matches!(
                        self.stage.header.phase,
                        Phase::Metadata | Phase::Finalized | Phase::NativeRecoveryRequired
                    ))
                    || (seal.phase == "rollback"
                        && !self.stage.header.capture_started
                        && self.stage.header.phase != Phase::Prepared)
            }
            _ => false,
        };
        if !admitted {
            return Err("AUTO receipt authority refused");
        }
        Ok(())
    }
}

impl crate::profile_auto_render::SealedRenderAuthority for StageGuard {
    fn revalidate(&self) -> std::result::Result<(), &'static str> {
        self.verify_self()
            .map_err(|_| "AUTO private render authority refused")
    }
    fn read_recipe(&self) -> std::result::Result<zeroize::Zeroizing<Vec<u8>>, &'static str> {
        self.verify_self()
            .map_err(|_| "AUTO private render authority refused")?;
        let bytes = self
            .store
            .read(&self.header.render_recipe)
            .map_err(|_| "AUTO private render authority refused")?;
        if self.header.leaves.get(&self.header.render_recipe) != Some(&digest(&bytes)) {
            return Err("AUTO private render authority refused");
        }
        Ok(bytes)
    }
    fn accepted_context(
        &self,
    ) -> std::result::Result<crate::profile_auto_render::RenderContext, &'static str> {
        self.verify_self()
            .map_err(|_| "AUTO private render authority refused")?;
        Ok(self.manifest.render_context.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_auto_capture::{CaptureLimits, CapturedTree};
    use std::os::unix::fs::PermissionsExt;
    struct Fixture {
        root: PathBuf,
        stage: Option<StageGuard>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn fixture() -> Fixture {
        fixture_with_absent_state(false)
    }
    fn fixture_with_absent_state(absent_state: bool) -> Fixture {
        let uid = unsafe { libc::geteuid() };
        let root =
            std::env::temp_dir().join(format!(".auto-authority-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut sources = Vec::new();
        let mut references = Vec::new();
        let mut values = BTreeMap::new();
        let config = root.join("config");
        let state = root.join("state");
        let metadata = root.join("metadata");
        for (role, path) in [
            ("config", &config),
            ("state", &state),
            ("metadata", &metadata),
        ] {
            if !(absent_state && role == "state") {
                std::fs::create_dir(path).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            if role == "config" {
                std::fs::write(path.join("private.key"), b"synthetic secret").unwrap();
                std::fs::set_permissions(
                    path.join("private.key"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            let admission = if role == "metadata" {
                InputRole::AdministratorMetadata {
                    administrator_uid: uid,
                }
            } else {
                InputRole::ServiceInput {
                    service_uid: uid,
                    administrator_uid: uid,
                }
            };
            let cap = CapturedTree::capture_optional(
                path,
                path.to_path_buf(),
                admission,
                CaptureLimits::default(),
                true,
            )
            .unwrap();
            let leaf = PathBuf::from(format!("input/generations/{role}.json"));
            values.insert(
                leaf.clone(),
                serde_json::to_vec(&cap.export_private_generation().unwrap()).unwrap(),
            );
            sources.push(SourceBinding {
                role: role.into(),
                original_path: path.to_path_buf(),
                generation_leaf: leaf,
                publication_witness_leaf: None,
            });
        }
        let key = config.join("private.key");
        let cap = CapturedTree::capture_file(
            &key,
            config.clone(),
            InputRole::PrivateCredential { expected_uid: uid },
            CaptureLimits::default(),
        )
        .unwrap();
        let generation_leaf = PathBuf::from("input/generations/reference-0000.json");
        let stage_bytes = PathBuf::from("input/references/0000/bytes");
        values.insert(
            generation_leaf.clone(),
            serde_json::to_vec(&cap.export_private_generation().unwrap()).unwrap(),
        );
        values.insert(stage_bytes.clone(), b"synthetic secret".to_vec());
        sources.push(SourceBinding {
            role: "reference".into(),
            original_path: key.clone(),
            generation_leaf: generation_leaf.clone(),
            publication_witness_leaf: None,
        });
        references.push(ReferenceBinding {
            stage_bytes,
            generation_leaf,
            original_path: key.clone(),
            final_path: key,
            expected_uid: Some(uid),
        });
        let manifest = Manifest {
            schema: 1,
            config_root: config.clone(),
            state_dir: state.clone(),
            metadata_dir: metadata.clone(),
            service_uid: uid,
            operator_uid: uid,
            logical_bundle: None,
            render_context: crate::profile_auto_render::RenderContext {
                mode: crate::profile_auto_render::SelectedMode::SocksOnly,
                logical_original_base: config.clone(),
                logical_final_base: config.clone(),
                final_state: state.join("state.json"),
                wide_interface: Some("eth0".into()),
            },
            sources,
            references,
        };
        values.insert(
            "input/authority.json".into(),
            serde_json::to_vec(&manifest).unwrap(),
        );
        let store = Store::create(&root, uid).unwrap();
        let hashes = values.iter().map(|(p, b)| (p.clone(), digest(b))).collect();
        for (p, b) in values {
            store.write_new(&p, &b).unwrap();
        }
        let header = Header {
            protocol: super::super::PROTOCOL.into(),
            administrator_uid: uid,
            config_root: config,
            state_dir: state,
            metadata_dir: metadata,
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
            leaves: hashes,
            input_generation: "01".repeat(32),
            accepted_generation: "02".repeat(32),
            planned_generation: "02".repeat(32),
            render_recipe: "accepted/render-recipe.json".into(),
        };
        store.save_header(&header).unwrap();
        let stage = StageGuard::admit_actor(store, uid).unwrap();
        Fixture {
            root,
            stage: Some(stage),
        }
    }
    #[test]
    fn owner_stage_prelocks_retain_the_same_store_instance() {
        let mut fixture = fixture();
        let uid = unsafe { libc::geteuid() };
        let initial = fixture.stage.as_mut().unwrap();
        initial.header.phase = Phase::Metadata;
        initial.persist_header().unwrap();
        let path = initial.store.path().to_path_buf();
        drop(fixture.stage.take());

        let store = Store::reopen_for_worker(&path, uid).unwrap();
        let expected = store.identity().unwrap();
        let locks = store.begin_owner_stage_locks().unwrap();
        let reopened_same_stage = Store::reopen_for_worker(&path, uid).unwrap();
        let mut session = if uid == 0 {
            locks.admit().unwrap()
        } else {
            locks.admit_fixture(uid).unwrap()
        };
        assert!(StageGuard::admit_actor(reopened_same_stage, uid).is_err());
        let fence = session.bind().unwrap();
        let binding = fence.read_binding().unwrap();
        assert_eq!(binding.stage, expected);
        drop(fence);
        assert!(session.bind().is_err());
        drop(session);
        Store::reopen(&path, uid)
            .unwrap()
            .arm_recovery_only()
            .unwrap();
        assert!(Store::reopen_for_worker(&path, uid).is_err());
    }
    #[test]
    fn owner_split_retains_original_stage_lock_until_both_parts_drop() {
        let mut fixture = fixture();
        let uid = unsafe { libc::geteuid() };
        let initial = fixture.stage.as_mut().unwrap();
        initial.header.phase = Phase::Metadata;
        initial.persist_header().unwrap();
        let path = initial.store.path().to_path_buf();
        drop(fixture.stage.take());

        let locks = Store::reopen_for_worker(&path, uid)
            .unwrap()
            .begin_owner_stage_locks()
            .unwrap();
        let session = if uid == 0 {
            locks.admit().unwrap()
        } else {
            locks.admit_fixture(uid).unwrap()
        };
        let (stage, owner) = session.split().unwrap();
        assert_eq!(stage.store.identity().unwrap(), owner.stage_identity());
        assert!(StageGuard::admit_actor(Store::reopen(&path, uid).unwrap(), uid).is_err());
        drop(owner);
        assert!(StageGuard::admit_actor(Store::reopen(&path, uid).unwrap(), uid).is_err());
        drop(stage);
        StageGuard::admit_actor(Store::reopen(&path, uid).unwrap(), uid).unwrap();
    }
    #[test]
    fn owner_pre_marker_scope_reuses_original_locks_for_stage_persistence() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let mut fixture = fixture();
        let initial = fixture.stage.as_mut().unwrap();
        initial.header.phase = Phase::Metadata;
        initial.persist_header().unwrap();
        let path = initial.store.path().to_path_buf();
        drop(fixture.stage.take());
        let session = Store::reopen_for_worker(&path, 0)
            .unwrap()
            .begin_owner_stage_locks()
            .unwrap()
            .admit()
            .unwrap();
        let (mut stage, owner) = session.split().unwrap();
        let lock = crate::profile_auto_stopped_service::InstallLock::acquire().unwrap();
        owner
            .with_pre_marker_effect(&lock, || {
                let leaf = Path::new("receipts/owner-scope-probe.json");
                let bytes = b"held original owner";
                stage.store.write_new(leaf, bytes)?;
                stage
                    .header
                    .leaves
                    .insert(leaf.to_path_buf(), digest(bytes));
                stage.persist_header()
            })
            .unwrap();
        assert_eq!(
            stage
                .store
                .read(Path::new("receipts/owner-scope-probe.json"))
                .unwrap()
                .as_slice(),
            b"held original owner"
        );
        // A second ordinary writer waits for the original mutation lock; the
        // owner remains held here. The persisted leaf proves that the scoped
        // path used the original locks without trying to acquire them again.
    }
    #[test]
    fn owner_stage_production_admission_refuses_nonroot() {
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            return;
        }
        let mut fixture = fixture();
        let initial = fixture.stage.as_mut().unwrap();
        initial.header.phase = Phase::Metadata;
        initial.persist_header().unwrap();
        let path = initial.store.path().to_path_buf();
        drop(fixture.stage.take());
        let store = Store::reopen_for_worker(&path, uid).unwrap();
        assert!(store.begin_owner_stage_locks().unwrap().admit().is_err());
    }
    #[test]
    fn consumed_activation_revokes_held_and_descendant_stage_writers() {
        let mut f = fixture();
        let stage = f.stage.as_mut().unwrap();
        stage.header.phase = Phase::Metadata;
        stage.persist_header().unwrap();
        let child = stage
            .store
            .sub_store(Path::new("receipts/activation-control"), true)
            .unwrap();
        let before = stage.store.read(Path::new("header.json")).unwrap();
        let path = stage.store.path().to_path_buf();
        assert!(child.arm_recovery_only().is_err());
        stage.store.arm_recovery_only().unwrap();
        assert!(stage.store.arm_recovery_only().is_err());
        assert_eq!(
            stage.store.recovery_ticket().unwrap(),
            super::super::durable::RecoveryTicket::IntentOnly
        );
        assert!(stage.verify_self().is_err());
        assert!(stage.persist_header().is_err());
        assert!(child
            .write_new(Path::new("forbidden.json"), b"unexpected")
            .is_err());
        assert!(stage
            .store
            .sub_store(Path::new("receipts/other"), true)
            .is_err());
        assert_eq!(stage.store.read(Path::new("header.json")).unwrap(), before);
        stage.store.consume_recovery_only().unwrap();
        assert_eq!(
            stage.store.recovery_ticket().unwrap(),
            super::super::durable::RecoveryTicket::Consumed
        );
        assert!(stage.store.consume_recovery_only().is_err());
        f.stage.take();
        let reopened = Store::reopen(&path, unsafe { libc::geteuid() }).unwrap();
        assert_eq!(
            reopened.recovery_ticket().unwrap(),
            super::super::durable::RecoveryTicket::Consumed
        );
        assert!(StageGuard::admit_actor(reopened, unsafe { libc::geteuid() }).is_err());
        assert!(!path
            .join("receipts/activation-control/forbidden.json")
            .exists());
    }
    #[test]
    fn concurrent_writer_finishes_before_recovery_seal_and_reopened_writer_refuses() {
        use std::sync::mpsc;
        use std::time::Duration;

        let mut f = fixture();
        let stage = f.stage.as_mut().unwrap();
        stage.header.phase = Phase::Metadata;
        stage.persist_header().unwrap();
        let path = stage.store.path().to_path_buf();
        let uid = unsafe { libc::geteuid() };
        let child = stage
            .store
            .sub_store(Path::new("receipts/race"), true)
            .unwrap();
        let participated = std::thread::scope(|scope| {
            let jobs: Vec<_> = (0..4)
                .map(|i| {
                    let path = path.clone();
                    scope.spawn(move || {
                        let writer = Store::reopen(&path, uid).unwrap();
                        writer
                            .write_new(
                                Path::new(&format!("receipts/race/participated-{i}.json")),
                                b"participated",
                            )
                            .is_ok()
                    })
                })
                .collect();
            jobs.into_iter()
                .map(|j| j.join().unwrap())
                .filter(|won| *won)
                .count()
        });
        assert!(participated > 0, "race must include a successful writer");

        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let (sealer_started_tx, sealer_started_rx) = mpsc::channel();
        let (sealed_tx, sealed_rx) = mpsc::channel();
        let child_ref = &child;
        let store = &stage.store;
        std::thread::scope(|scope| {
            let writer = scope.spawn(move || {
                child_ref.write_new_paused_for_race_test(
                    Path::new("in-flight.json"),
                    b"before seal",
                    entered_tx,
                    resume_rx,
                )
            });
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let sealer = scope.spawn(move || {
                sealer_started_tx.send(()).unwrap();
                sealed_tx.send(store.arm_recovery_only()).unwrap();
            });
            sealer_started_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            assert!(
                matches!(
                    sealed_rx.recv_timeout(Duration::from_millis(100)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ),
                "seal must wait for an in-flight checked writer"
            );
            resume_tx.send(()).unwrap();
            writer.join().unwrap().unwrap();
            sealer.join().unwrap();
        });
        sealed_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert_eq!(
            child.read(Path::new("in-flight.json")).unwrap().as_slice(),
            b"before seal"
        );
        assert!(child
            .write_new(Path::new("after-seal.json"), b"forbidden")
            .is_err());
        let reopened = Store::reopen(&path, uid).unwrap();
        assert!(reopened
            .write_new(
                Path::new("receipts/race/reopened-after-seal.json"),
                b"forbidden"
            )
            .is_err());
        assert!(!path.join("receipts/race/after-seal.json").exists());
        assert!(!path.join("receipts/race/reopened-after-seal.json").exists());
    }
    #[test]
    fn stage_guard_publication_lease_blocks_seal_until_reopened_leases_release() {
        use std::sync::mpsc;
        use std::time::Duration;

        let mut f = fixture();
        let stage = f.stage.as_mut().unwrap();
        stage.header.phase = Phase::Metadata;
        stage.persist_header().unwrap();
        let path = stage.store.path().to_path_buf();
        let uid = unsafe { libc::geteuid() };
        let reopened = Store::reopen(&path, uid).unwrap();
        let first = stage.publication_lease().unwrap();
        let second = reopened.publication_lease().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let store = &stage.store;
            let attempt = scope.spawn(move || {
                started_tx.send(()).unwrap();
                store.arm_recovery_only()
            });
            started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(attempt.join().unwrap().is_err());
        });
        assert!(!stage.store.activation_leaf_present().unwrap());
        drop(first);
        assert!(stage.store.arm_recovery_only().is_err());
        drop(second);
        stage.store.arm_recovery_only().unwrap();
        assert!(stage.store.publication_lease().is_err());
        assert!(reopened.publication_lease().is_err());
        assert_eq!(
            stage.store.recovery_ticket().unwrap(),
            super::super::durable::RecoveryTicket::IntentOnly
        );
    }
    #[test]
    fn malformed_and_orphan_activation_leaves_are_recovery_only_refusals() {
        for marker in [
            "activation-intent.json",
            "activation-consumed.json",
            "activation-intent-once",
        ] {
            let mut f = fixture();
            let stage = f.stage.as_mut().unwrap();
            let path = stage.store.path().to_path_buf();
            let child = stage
                .store
                .sub_store(Path::new("receipts/orphan-probe"), true)
                .unwrap();
            let before = stage.store.read(Path::new("header.json")).unwrap();
            if marker == "activation-intent-once" {
                // Simulate a foreign/torn supervisor leaf. Ordinary Store
                // mutation is deliberately forbidden from minting it.
                std::fs::write(path.join(marker), b"truncated").unwrap();
            } else {
                stage
                    .store
                    .write_new(Path::new(marker), b"truncated")
                    .unwrap();
            }
            assert!(stage.verify_self().is_err());
            assert!(stage.store.recovery_ticket().is_err());
            assert!(stage.persist_header().is_err());
            assert!(child.write_new(Path::new("forbidden"), b"x").is_err());
            assert_eq!(stage.store.read(Path::new("header.json")).unwrap(), before);
            f.stage.take();
            let reopened = Store::reopen(&path, unsafe { libc::geteuid() }).unwrap();
            assert!(StageGuard::admit_actor(reopened, unsafe { libc::geteuid() }).is_err());
        }
        for marker in ["activation-consumed.json", "activation-intent-once"] {
            let mut f = fixture();
            let stage = f.stage.as_mut().unwrap();
            let path = stage.store.path().to_path_buf();
            std::os::unix::fs::symlink("/dev/null", path.join(marker)).unwrap();
            assert!(stage.verify_self().is_err());
            assert!(stage.store.recovery_ticket().is_err());
            assert!(stage.store.write_new(Path::new("forbidden"), b"x").is_err());
        }
    }
    #[test]
    fn supervisor_marker_store_mint_refuses_and_canonical_recovery_is_ambiguous() {
        for consumed in [false, true] {
            let mut f = fixture();
            let stage = f.stage.as_mut().unwrap();
            let marker = Path::new("activation-intent-once");
            let path = stage.store.path().to_path_buf();
            assert!(stage.store.write_new(marker, b"untrusted").is_err());
            assert!(stage.store.sub_store(marker, true).is_err());
            assert!(!path.join(marker).exists());

            stage.header.phase = Phase::Metadata;
            stage.persist_header().unwrap();
            stage.store.arm_recovery_only().unwrap();
            if consumed {
                stage.store.consume_recovery_only().unwrap();
            }
            assert_eq!(
                stage.store.recovery_ticket().unwrap(),
                if consumed {
                    super::super::durable::RecoveryTicket::Consumed
                } else {
                    super::super::durable::RecoveryTicket::IntentOnly
                }
            );
            // A preexisting valid canonical ticket cannot absorb a foreign
            // supervisor marker into either of its recovery variants.
            std::fs::write(path.join(marker), b"torn").unwrap();
            assert!(stage.store.recovery_ticket().is_err());
            assert!(stage.verify_self().is_err());
        }
    }
    #[test]
    #[ignore = "Actual Linux Store/filesystem interruption control; root QA explicitly admits this new method"]
    fn actual_withdrawal_receipt_before_header_reentry_and_foreign_leaf_refusal() {
        use crate::profile_auto_capture::{GenerationGuard, InputRole};
        use std::cell::RefCell;
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "requires disposable root Linux; never silently skip"
        );
        struct ActualCapture {
            path: PathBuf,
            original: GenerationGuard,
            witness: Option<Vec<u8>>,
        }
        impl publisher::CaptureGuard for ActualCapture {
            fn validate_captured_generation(
                &self,
                path: &Path,
                generation: Option<&publisher::Generation>,
            ) -> publisher::Result<()> {
                self.original
                    .revalidate()
                    .map_err(|_| "actual fixture capture refused")?;
                if path != self.path || generation.map(|g| g.witness()).transpose()? != self.witness
                {
                    return Err("actual fixture target generation refused");
                }
                Ok(())
            }
        }
        for foreign_receipt in [false, true] {
            let mut fixture = fixture_with_absent_state(true);
            let stage = RefCell::new(fixture.stage.take().unwrap());
            let uid = unsafe { libc::geteuid() };
            let gid = unsafe { libc::getegid() };
            // Real config custody advances the protected phase; no Header-phase
            // assignment or supplied witness Boolean substitutes for publication.
            for (role, phase, mode) in [
                ("config", "custody", publisher::RootMode::ServiceConfig0750),
                ("state", "state", publisher::RootMode::RuntimeState0700),
            ] {
                let (path, original) = {
                    let st = stage.borrow();
                    let source = st.manifest.sources.iter().find(|s| s.role == role).unwrap();
                    (
                        source.original_path.clone(),
                        capture::reopen_generation(&st.records[&source.generation_leaf]).unwrap(),
                    )
                };
                let target = publisher::Target::open(&path).unwrap();
                let generation = target.inspect().unwrap();
                let guard = ActualCapture {
                    path: path.clone(),
                    original,
                    witness: generation.as_ref().map(|g| g.witness().unwrap()),
                };
                let input = fixture.root.join(format!("new-{role}"));
                std::fs::create_dir(&input).unwrap();
                std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o700)).unwrap();
                std::fs::write(input.join("value"), b"never-issued Store fixture").unwrap();
                std::fs::set_permissions(
                    input.join("value"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                let captured = CapturedTree::capture(
                    &input,
                    path.clone(),
                    InputRole::ServiceInput {
                        service_uid: uid,
                        administrator_uid: uid,
                    },
                    CaptureLimits::default(),
                )
                .unwrap();
                captured.revalidate_original_generation().unwrap();
                let tree = publisher::CapturedTree::new(
                    captured
                        .entries()
                        .map(|(p, bytes)| (p.to_path_buf(), bytes.to_vec()))
                        .collect(),
                    captured
                        .directories()
                        .into_iter()
                        .filter(|p| !p.as_os_str().is_empty())
                        .map(Path::to_path_buf)
                        .collect(),
                )
                .unwrap();
                captured.revalidate_original_generation().unwrap();
                let prepared = publisher::Prepared::build_policy_captured(
                    target,
                    generation,
                    &tree,
                    uid,
                    gid,
                    mode,
                    |_| Ok(()),
                    &guard,
                )
                .unwrap();
                let receipt = prepared
                    .publish_captured(
                        |intent| {
                            stage
                                .borrow_mut()
                                .begin_publication(role, phase, intent)
                                .map_err(|_| "actual Store intent refused")
                        },
                        &guard,
                    )
                    .unwrap();
                stage
                    .borrow_mut()
                    .accept_publication(role, &receipt)
                    .unwrap();
            }
            let path = stage.borrow().header.state_dir.clone();
            let target = publisher::Target::open(&path).unwrap();
            let admitted = stage.borrow().publication_record("state").unwrap();
            let current = publisher::reopen_own_receipt(&target, &admitted).unwrap();
            // Shared test-only direct-absence constructor still uses actual current
            // receipt and pre-syscall protected state-kind2 admission.
            let retired = publisher::restore_original_absence(&target, &current, |intent| {
                stage
                    .borrow_mut()
                    .begin_withdrawal("state", intent)
                    .map_err(|_| "actual Store withdrawal refused")
            })
            .unwrap();
            assert!(stage
                .borrow_mut()
                .accept_withdrawal_inner("state", &retired, true)
                .is_err());
            let (stage_path, pending_leaf, pending_hash) = {
                let st = stage.borrow();
                let (p, s) = st.header.pending.as_ref().unwrap();
                (st.store.path().to_path_buf(), p.clone(), s.sha256.clone())
            };
            let receipt_leaf = pending_leaf
                .parent()
                .unwrap()
                .join("withdrawal-receipt.json");
            assert!(stage.borrow().header.active_records.contains_key("state"));
            assert!(!path.exists());
            if foreign_receipt {
                std::fs::write(stage_path.join(&receipt_leaf), b"foreign receipt").unwrap();
            }
            drop(stage); // release actual Store flock and rebuild all admission
            let mut reopened =
                StageGuard::admit_fixture(Store::reopen(&stage_path, uid).unwrap(), uid).unwrap();
            assert_eq!(
                reopened.header.pending.as_ref().unwrap().1.sha256,
                pending_hash
            );
            let recovered = reopened.recover_pending_withdrawal("state");
            if foreign_receipt {
                assert!(recovered.is_err());
                assert!(reopened.header.pending.is_some());
                assert!(reopened.header.active_records.contains_key("state"));
            } else {
                recovered.unwrap();
                assert!(reopened.header.pending.is_none());
                assert!(!reopened.header.active_records.contains_key("state"));
                reopened.verify_completed_withdrawals().unwrap();
            }
            assert!(!path.exists());
            publisher::revalidate_withdrawal(&target, &retired).unwrap();
        }
    }
    #[test]
    fn actual_stage_role_and_private_record_are_bound_not_caller_hashes() {
        let f = fixture();
        let s = f.stage.as_ref().unwrap();
        let uid = s.manifest.service_uid;
        let record = s.private_record(0).unwrap();
        let path = s.store.path().join("input/references/0000/bytes");
        assert!(s.admit_private_original(&path, record, uid).is_ok());
        assert!(s
            .admit_private_original(&path, record, uid.wrapping_add(1))
            .is_err());
        assert!(s.admitted_stage_sha256(&path).is_ok());
        assert!(s
            .admitted_stage_sha256(&s.store.path().join("input/authority.json"))
            .is_err());
        assert!(s
            .admit_retired_private_original(&path, record, uid)
            .is_err());
    }
    #[test]
    fn actual_other_stage_bytes_cannot_mint_this_stage_private_capability() {
        let a = fixture();
        let b = fixture();
        let aa = a.stage.as_ref().unwrap();
        let bb = b.stage.as_ref().unwrap();
        let path = bb.store.path().join("input/references/0000/bytes");
        let record = aa.private_record(0).unwrap();
        assert!(aa
            .admit_private_original(&path, record, aa.manifest.service_uid)
            .is_err());
        assert!(aa.admitted_stage_sha256(&path).is_err());
    }
    #[test]
    fn actual_header_mutation_and_payload_substitution_refuse_without_original_reread() {
        let f = fixture();
        let s = f.stage.as_ref().unwrap();
        let path = s.store.path().join("input/references/0000/bytes");
        std::fs::write(&path, b"changed synthetic").unwrap();
        assert!(s.revalidate().is_err());
        assert_eq!(
            std::fs::read(s.header.config_root.join("private.key")).unwrap(),
            b"synthetic secret"
        );
    }
    #[test]
    fn own_retirement_proof_requires_committed_receipt_and_real_namespace() {
        let mut f = fixture();
        let mut s = f.stage.take().unwrap();
        s.header.phase = Phase::Custody;
        s.store.save_header(&s.header).unwrap();
        s.header_sha = digest(&s.store.read(Path::new("header.json")).unwrap());
        let record = s.private_record(0).unwrap();
        let path = s.store.path().join("input/references/0000/bytes");
        assert!(s
            .admit_retired_private_original(&path, record, s.manifest.service_uid)
            .is_err());
        assert!(s.header.config_root.join("private.key").is_file());
    }
    #[test]
    fn source_ancestry_role_generation_is_revalidated_metadata_only() {
        let f = fixture();
        let s = f.stage.as_ref().unwrap();
        s.revalidate_originals().unwrap();
        let key = s.header.config_root.join("private.key");
        std::fs::rename(&key, s.header.config_root.join("retained.key")).unwrap();
        std::fs::write(&key, b"external replacement").unwrap();
        assert!(s.revalidate_originals().is_err());
        assert_eq!(
            std::fs::read(s.header.config_root.join("retained.key")).unwrap(),
            b"synthetic secret"
        );
    }
    #[test]
    fn untouched_role_readback_uses_exact_manifest_role() {
        let f = fixture();
        let s = f.stage.as_ref().unwrap();
        for role in ["config", "state", "metadata"] {
            s.revalidate_untouched_original_role(role).unwrap();
        }
        assert!(s.revalidate_untouched_original_role("reference").is_err());
        let state = s.header.state_dir.join("state.bin");
        std::fs::write(&state, b"changed").unwrap();
        assert!(s.revalidate_untouched_original_role("state").is_err());
        s.revalidate_untouched_original_role("metadata").unwrap();
    }
}
