//! PRIVATE UNAPPLIED concrete Context, nested under profile_auto_transaction.
//! Constructor consumes already admitted/exclusive protected StageGuard. No
//! caller JSON constructor or success-only trait implementation exists here.
//! Uses parent's protected service_gid/namespace_records Header plus actual
//! pending/publication/withdrawal StageGuard and namespace admission methods.
use super::{
    authority::{
        receipt_chain, revalidate_record, validate_projection_lineage, Manifest, StageGuard,
    },
    digest,
    durable::Store,
    namespace, Header, Phase, PublicationLease, RecordSeal,
};
use crate::profile_auto_capture::GenerationRecord;
use crate::profile_auto_prepare::{OwnedTree, Role};
use crate::profile_auto_publication::linux as fs;
use crate::profile_auto_runtime_publication::linux::{Basis, Context, Operation, ServiceIdentity};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, &'static str>;
const REFUSED: &str = "Administrative protected Store context refused";
fn fail<T>(_: T) -> &'static str {
    REFUSED
}
fn key(role: Role) -> String {
    match role {
        Role::Config => "config".into(),
        Role::StateTarget => "state".into(),
        Role::StateSource => "prior-state".into(),
        Role::AdministratorMetadata => "metadata".into(),
        Role::BundleMain => "bundle-main".into(),
        Role::BundleCa => "bundle-ca".into(),
        Role::BundleSupplementary => "bundle-supplementary".into(),
        Role::BundleMasque => "bundle-masque".into(),
        Role::Reference(i) => format!("reference-{i}"),
    }
}
fn root_role(role: Role) -> Result<&'static str> {
    match role {
        Role::Config => Ok("config"),
        Role::StateTarget => Ok("state"),
        Role::AdministratorMetadata => Ok("metadata"),
        _ => Err(REFUSED),
    }
}
fn phase(operation: Operation) -> Result<&'static str> {
    match operation {
        Operation::ConfigCustody => Ok("custody"),
        Operation::FinalConfig => Ok("config"),
        Operation::RuntimeState => Ok("state"),
        Operation::AdministrativeMetadata => Ok("metadata"),
        Operation::Rollback => Ok("rollback"),
        _ => Err(REFUSED),
    }
}
fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path.components().count() <= 8
        && path.components().all(|p| matches!(p, Component::Normal(_)))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
}
fn source_role(guard: &StageGuard, index: usize) -> Result<Role> {
    let source = guard.manifest.sources.get(index).ok_or(REFUSED)?;
    Ok(match source.role.as_str() {
        "config" => Role::Config,
        "state" => Role::StateTarget,
        "prior-state" => Role::StateSource,
        "metadata" => Role::AdministratorMetadata,
        "bundle-main" => Role::BundleMain,
        "bundle-ca" => Role::BundleCa,
        "bundle-supplementary" => Role::BundleSupplementary,
        "bundle-masque" => Role::BundleMasque,
        "reference" => Role::Reference(
            guard
                .manifest
                .references
                .iter()
                .position(|r| r.generation_leaf == source.generation_leaf)
                .ok_or(REFUSED)?,
        ),
        _ => return Err(REFUSED),
    })
}
fn read_bound(guard: &StageGuard, leaf: &Path) -> Result<Zeroizing<Vec<u8>>> {
    guard.store.revalidate().map_err(fail)?;
    let bytes = guard.store.read(leaf).map_err(fail)?;
    if guard.header.leaves.get(leaf) != Some(&digest(&bytes)) {
        return Err(REFUSED);
    }
    Ok(bytes)
}
fn load_tree(guard: &StageGuard, role: Role, accepted: bool) -> Result<OwnedTree> {
    if accepted
        && role == Role::AdministratorMetadata
        && guard.header.installed_receipt_recipe.is_some()
    {
        return super::receipt_store::accepted_metadata_tree(guard).map_err(fail);
    }
    let side = if accepted { "accepted" } else { "input" };
    let normalized = key(role);
    let prefix = PathBuf::from(format!("{side}/payload/{normalized}"));
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    for leaf in guard.header.leaves.keys() {
        if let Ok(relative) = leaf.strip_prefix(&prefix) {
            if !safe_relative(relative) || files.len() >= 1024 {
                return Err(REFUSED);
            }
            let bytes = read_bound(guard, leaf)?;
            total = total.checked_add(bytes.len()).ok_or(REFUSED)?;
            if total > 64 * 1024 * 1024 {
                return Err(REFUSED);
            }
            files.insert(relative.to_path_buf(), bytes);
        }
    }
    let directory_leaf = PathBuf::from(format!("{side}/directories/{normalized}.json"));
    let encoded = read_bound(guard, &directory_leaf)?;
    if encoded.len() > 1024 * 1024 {
        return Err(REFUSED);
    }
    let directory_vec: Vec<PathBuf> = serde_json::from_slice(&encoded).map_err(fail)?;
    let mut directories = BTreeSet::new();
    for p in directory_vec {
        if p.as_os_str().is_empty() {
            continue;
        }
        if !safe_relative(&p) || !directories.insert(p) {
            return Err(REFUSED);
        }
    }
    if files.len() + directories.len() > 1024 || files.keys().any(|p| directories.contains(p)) {
        return Err(REFUSED);
    }
    // Membership manifest must explicitly carry every intermediate directory.
    for leaf in files.keys().chain(directories.iter()) {
        let mut parent = leaf.parent();
        while let Some(p) = parent {
            if p.as_os_str().is_empty() {
                break;
            }
            if !directories.contains(p) {
                return Err(REFUSED);
            }
            parent = p.parent();
        }
    }
    Ok(OwnedTree { files, directories })
}
/// Separate own FD Store for each guard; reads current protected Header every
/// invocation. Never obtains authority from a later current target inspection.
struct Guard {
    store: Store,
    role: Role,
    basis: Basis,
    nonce: String,
    input: String,
    planned: String,
    generation_leaf: PathBuf,
    generation_sha: String,
    authority_sha: String,
    witness_leaf: Option<PathBuf>,
    witness_sha: Option<String>,
    target: PathBuf,
}
impl Guard {
    fn current_header(&self) -> Result<Header> {
        self.store.revalidate().map_err(fail)?;
        let h = self.store.load_header().map_err(fail)?;
        if h.transaction_nonce != self.nonce
            || h.input_generation != self.input
            || h.planned_generation != self.planned
            || h.administrator_uid != 0
            || h.leaves.get(&self.generation_leaf) != Some(&self.generation_sha)
            || h.leaves.get(Path::new("input/authority.json")) != Some(&self.authority_sha)
        {
            return Err(REFUSED);
        }
        if let (Some(p), Some(expected)) = (&self.witness_leaf, &self.witness_sha) {
            if h.leaves.get(p) != Some(expected) {
                return Err(REFUSED);
            }
        }
        let path = match self.role {
            Role::Config => &h.config_root,
            Role::StateTarget => &h.state_dir,
            Role::AdministratorMetadata => &h.metadata_dir,
            _ => return Err(REFUSED),
        };
        if path != &self.target {
            return Err(REFUSED);
        }
        Ok(h)
    }
}
struct CurrentAuthority<'a> {
    header: &'a Header,
    seal: &'a RecordSeal,
    leaf: &'a Path,
    store_identity: fs::Identity,
}
impl fs::PhaseAuthority for CurrentAuthority<'_> {
    fn validate_record_claim(&self, claim: &fs::RecordClaim) -> Result<()> {
        if claim.administrator_uid != 0
            || claim.actual_stage != self.store_identity
            || claim.actual_stage.dev != self.seal.stage_dev
            || claim.actual_stage.ino != self.seal.stage_ino
            || claim.record_leaf
                != self
                    .leaf
                    .file_name()
                    .and_then(|x| x.to_str())
                    .ok_or(REFUSED)?
            || claim.record_sha256 != self.seal.sha256
            || claim.binding.transaction_stage != claim.actual_stage
            || claim.binding.transaction_nonce != self.header.transaction_nonce
            || claim.binding.phase != self.seal.phase
            || claim.binding.chain_sha256 != self.seal.chain_sha256
            || receipt_chain(
                self.header,
                &self.seal.role,
                &self.seal.phase,
                self.seal.predecessor_sha256.as_deref(),
            ) != self.seal.chain_sha256
        {
            return Err(REFUSED);
        }
        Ok(())
    }
}
fn load_current(store: &Store, h: &Header, role: &str) -> Result<fs::AuthenticatedRecord> {
    let leaf = h.active_records.get(role).ok_or(REFUSED)?;
    let seal = h.current_records.get(leaf).ok_or(REFUSED)?;
    if seal.role != role {
        return Err(REFUSED);
    }
    let directory = leaf.parent().ok_or(REFUSED)?;
    let sub = store.sub_store(directory, false).map_err(fail)?;
    let (dev, ino) = sub.identity().map_err(fail)?;
    let auth = CurrentAuthority {
        header: h,
        seal,
        leaf,
        store_identity: fs::Identity { dev, ino },
    };
    validate_projection_lineage(store, h, leaf, seal).map_err(fail)?;
    let filename = leaf.file_name().and_then(|v| v.to_str()).ok_or(REFUSED)?;
    fs::authenticate_record(sub.duplicate_root().map_err(fail)?, filename, &auth)
}
impl fs::CaptureGuard for Guard {
    fn validate_captured_generation(
        &self,
        target: &Path,
        expected: Option<&fs::Generation>,
    ) -> Result<()> {
        if target != self.target {
            return Err(REFUSED);
        }
        let h = self.current_header()?;
        match self.basis {
            Basis::SealedInitial => {
                let raw = self.store.read(&self.generation_leaf).map_err(fail)?;
                if digest(&raw) != self.generation_sha {
                    return Err(REFUSED);
                }
                let original: GenerationRecord = serde_json::from_slice(&raw).map_err(fail)?;
                if original.original_source() != target {
                    return Err(REFUSED);
                }
                let namespace_leaf = PathBuf::from(format!(
                    "receipts/namespaces/{}-parents.json",
                    root_role(self.role)?
                ));
                if original.kind() == 2 && h.namespace_records.contains_key(&namespace_leaf) {
                    let authority_bytes = self
                        .store
                        .read(Path::new("input/authority.json"))
                        .map_err(fail)?;
                    if digest(&authority_bytes) != self.authority_sha {
                        return Err(REFUSED);
                    }
                    let manifest: Manifest =
                        serde_json::from_slice(&authority_bytes).map_err(fail)?;
                    namespace::validate_sealed_parent_parts(
                        &self.store,
                        &h,
                        &manifest,
                        root_role(self.role)?,
                        true,
                    )
                    .map_err(fail)?;
                } else {
                    revalidate_record(&original, &h.config_root).map_err(fail)?;
                }
                match (
                    original.kind(),
                    expected,
                    &self.witness_leaf,
                    &self.witness_sha,
                ) {
                    (2, None, None, None) => (),
                    (0, Some(g), Some(p), Some(hash)) => {
                        let bytes = self.store.read(p).map_err(fail)?;
                        if digest(&bytes) != *hash || g.witness()?.as_slice() != bytes.as_slice() {
                            return Err(REFUSED);
                        }
                    }
                    _ => return Err(REFUSED),
                }
            }
            Basis::CurrentOwnReceipt => {
                let admitted = load_current(&self.store, &h, root_role(self.role)?)?;
                let t = fs::Target::open(target)?;
                let current = fs::reopen_own_receipt(&t, &admitted)?;
                if expected != Some(current.generation()) {
                    return Err(REFUSED);
                }
                fs::revalidate_current_receipt(&t, &current)?;
            }
        }
        let after = self.current_header()?;
        if serde_json::to_vec(&h).map_err(fail)? != serde_json::to_vec(&after).map_err(fail)? {
            return Err(REFUSED);
        }
        Ok(())
    }
}
/// Concrete state sibling MUST be supplied by coordinator, not a no-op fallback.
/// It owns actual singleton receipts, target descriptors and phase checks.
pub(super) trait StateContext {
    fn read_owned_published_state(
        &self,
        stage: &StageGuard,
        relative: &Path,
    ) -> Result<Zeroizing<Vec<u8>>>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum UnitOperation {
    Publish,
    Reload,
    Rollback,
    // Selected only from the exact protected singleton publication intent.
    RecoverPendingPublish,
    RestoreAcceptedManager,
}
#[derive(PartialEq, Eq)]
pub(super) enum DropinRecordRoute {
    Forward,
    OriginalRestoration,
    AcceptedRestoration,
}
/// Closed routing facts only. AcceptedRestoration is not a proof; the actual
/// consumer must still admit the protected accepted-manager receipt/identity.
pub(super) fn dropin_record_route(
    h: &Header,
    operation: Option<UnitOperation>,
    restored: bool,
) -> Result<DropinRecordRoute> {
    if h.capture_started || h.pending.is_some() || h.unit_restored_manager.is_some() {
        return Err(REFUSED);
    }
    let pending = if restored {
        "receipts/unit-target/dropins/restored/publication-intent.json"
    } else {
        "receipts/unit-target/dropins/forward/publication-intent.json"
    };
    if h.unit_pending.as_deref() != Some(Path::new(pending)) {
        return Err(REFUSED);
    }
    if restored && h.new_unit_namespace.is_some() {
        if operation != Some(UnitOperation::RestoreAcceptedManager)
            || !matches!(h.phase, Phase::Config | Phase::Metadata | Phase::Finalized)
        {
            return Err(REFUSED);
        }
        return Ok(DropinRecordRoute::AcceptedRestoration);
    }
    if h.phase != Phase::Config
        || h.new_unit_namespace.is_some()
        || operation
            != Some(if restored {
                UnitOperation::Rollback
            } else {
                UnitOperation::Publish
            })
    {
        return Err(REFUSED);
    }
    Ok(if restored {
        DropinRecordRoute::OriginalRestoration
    } else {
        DropinRecordRoute::Forward
    })
}
pub(super) struct RootContext<'a> {
    install_lock: Option<&'a crate::profile_auto_stopped_service::InstallLock>,
    prepared_operation: Option<crate::profile_auto_stopped_service::PreparedOperation>,
    unit_operation: Cell<Option<UnitOperation>>,
    recovering_publication_role: Option<crate::profile_auto_unit_policy::linux::LeafRole>,
    stage: RefCell<StageGuard>,
    state: &'a dyn StateContext,
    targets: BTreeMap<Role, PathBuf>,
    records: BTreeMap<Role, GenerationRecord>,
    raw: BTreeMap<Role, OwnedTree>,
    accepted: BTreeMap<Role, OwnedTree>,
    witnesses: BTreeMap<Role, Zeroizing<Vec<u8>>>,
    guards: BTreeMap<(Role, u8), Guard>,
    external: BTreeMap<PathBuf, (Role, Zeroizing<Vec<u8>>)>,
}
impl<'a> RootContext<'a> {
    pub(super) fn from_stage_with_lock(
        stage: StageGuard,
        state: &'a dyn StateContext,
        install_lock: Option<&'a crate::profile_auto_stopped_service::InstallLock>,
        prepared_operation: Option<crate::profile_auto_stopped_service::PreparedOperation>,
        unit_operation: Option<UnitOperation>,
    ) -> Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(REFUSED);
        }
        stage.store.revalidate().map_err(fail)?;
        stage.store.verify_payloads(&stage.header).map_err(fail)?;
        let recovering_publication_role =
            if unit_operation == Some(UnitOperation::RecoverPendingPublish) {
                Some(
                    super::unit_store::admitted_pending_publication(&stage)
                        .map_err(fail)?
                        .ok_or(REFUSED)?,
                )
            } else {
                None
            };
        let mut targets = BTreeMap::new();
        let mut records = BTreeMap::new();
        let mut raw = BTreeMap::new();
        let mut accepted = BTreeMap::new();
        let mut witnesses = BTreeMap::new();
        let mut guards = BTreeMap::new();
        for (index, source) in stage.manifest.sources.iter().enumerate() {
            let role = source_role(&stage, index)?;
            let bytes = read_bound(&stage, &source.generation_leaf)?;
            let record: GenerationRecord = serde_json::from_slice(&bytes).map_err(fail)?;
            if record.original_source() != source.original_path
                || records.insert(role, record).is_some()
            {
                return Err(REFUSED);
            }
            targets.insert(role, source.original_path.clone());
            raw.insert(role, load_tree(&stage, role, false)?);
            accepted.insert(role, load_tree(&stage, role, true)?);
            if matches!(
                role,
                Role::Config | Role::StateTarget | Role::AdministratorMetadata
            ) {
                let witness_hash = source
                    .publication_witness_leaf
                    .as_ref()
                    .map(|p| stage.header.leaves.get(p).cloned().ok_or(REFUSED))
                    .transpose()?;
                if let Some(p) = &source.publication_witness_leaf {
                    witnesses.insert(role, read_bound(&stage, p)?);
                }
                for (id, basis) in [(0, Basis::SealedInitial), (1, Basis::CurrentOwnReceipt)] {
                    guards.insert(
                        (role, id),
                        Guard {
                            store: Store::reopen(stage.store.path(), 0).map_err(fail)?,
                            role,
                            basis,
                            nonce: stage.header.transaction_nonce.clone(),
                            input: stage.header.input_generation.clone(),
                            planned: stage.header.planned_generation.clone(),
                            generation_leaf: source.generation_leaf.clone(),
                            generation_sha: digest(&bytes),
                            authority_sha: stage
                                .header
                                .leaves
                                .get(Path::new("input/authority.json"))
                                .cloned()
                                .ok_or(REFUSED)?,
                            witness_leaf: source.publication_witness_leaf.clone(),
                            witness_sha: witness_hash.clone(),
                            target: source.original_path.clone(),
                        },
                    );
                }
            }
        }
        let mut external = BTreeMap::new();
        for (index, r) in stage.manifest.references.iter().enumerate() {
            let bytes = read_bound(&stage, &r.stage_bytes)?;
            let role = Role::Reference(index);
            let record = records.get(&role).ok_or(REFUSED)?;
            if record.original_source() != r.original_path {
                return Err(REFUSED);
            }
            let payload = raw.get(&role).ok_or(REFUSED)?;
            if payload.files.len() != 1
                || payload.files.values().next().ok_or(REFUSED)?.as_slice() != bytes.as_slice()
            {
                return Err(REFUSED);
            }
            if external
                .insert(r.final_path.clone(), (role, bytes))
                .is_some()
            {
                return Err(REFUSED);
            }
        }
        Ok(Self {
            install_lock,
            prepared_operation,
            unit_operation: Cell::new(unit_operation),
            recovering_publication_role,
            stage: RefCell::new(stage),
            state,
            targets,
            records,
            raw,
            accepted,
            witnesses,
            guards,
            external,
        })
    }
    fn fresh_header(&self) -> Result<Header> {
        let stage = self.stage.borrow();
        stage.store.revalidate().map_err(fail)?;
        // The held header is serialized fresh on every call, never cached,
        // so a save_header between calls is always seen. Exact equality of
        // the on-disk bytes with it implies today's condition (serialize of
        // the parsed bytes equals it) through the lossless serde round trip,
        // so only the second serialization is skipped; otherwise compare as
        // before.
        let expected = serde_json::to_vec(&stage.header).map_err(fail)?;
        let (h, raw) = stage.store.load_header_with_bytes().map_err(fail)?;
        if raw.as_slice() != expected.as_slice()
            && serde_json::to_vec(&h).map_err(fail)? != expected
        {
            return Err(REFUSED);
        }
        // load_header_with_bytes has just validated this same value.
        stage.store.verify_validated_payloads(&h).map_err(fail)?;
        Ok(h)
    }
    fn protect_tree_reads(&self) -> Result<()> {
        self.fresh_header().map(|_| ())
    }
    /// Shared actual stage cell for the concrete singleton state backend.
    /// Parent-private only; this does not mint a public caller capability.
    /// Select exactly the actor epoch bound by protected phase state. A failed
    /// old observation is never retried against a different identity.
    pub(super) fn admit_reload_operation(&self) -> Result<()> {
        let h = self.fresh_header()?;
        if self.unit_operation.get() != Some(UnitOperation::Reload)
            || h.phase != Phase::Config
            || h.capture_started
            || h.pending.is_some()
            || h.new_unit_namespace.is_some()
        {
            return Err(REFUSED);
        }
        super::unit_store::verify_published_policy(self).map_err(fail)
    }
    pub(super) fn admit_final_base_publication(
        &self,
        transition: &crate::profile_auto_unit_namespace::OwnedTransition,
    ) -> Result<()> {
        let h = self.fresh_header()?;
        if h.phase != Phase::Config
            || h.capture_started
            || h.pending.is_some()
            || h.new_unit_namespace.is_some()
        {
            return Err(REFUSED);
        }
        match self.unit_operation.get() {
            Some(UnitOperation::Publish) => {
                super::unit_store::validate_final_base_publication(self, transition).map_err(fail)
            }
            Some(UnitOperation::RecoverPendingPublish) => {
                super::unit_store::validate_recovered_final_base_publication(self, transition)
                    .map_err(fail)
            }
            _ => Err(REFUSED),
        }
    }
    pub(super) fn stopped_phase<T>(&self, mutate: impl FnOnce() -> Result<T>) -> Result<T> {
        let h = self.fresh_header()?;
        if h.capture_started || matches!(h.phase, Phase::NativeRecoveryRequired | Phase::RolledBack)
        {
            return Err(REFUSED);
        }
        if h.unit_restored_manager.is_some() {
            // Protected completed restoration selects the original actor. A
            // failed accepted-new actor proof is never retried against old IDs.
            return crate::profile_auto_stopped_service::execute_restored_manager_stopped(
                self, mutate,
            );
        }
        let prepared = match h.phase {
            Phase::Config => h.new_unit_namespace.is_some(),
            Phase::Metadata | Phase::Finalized => {
                if h.new_unit_namespace.is_none() {
                    return Err(REFUSED);
                }
                true
            }
            Phase::Prepared | Phase::Custody | Phase::State => {
                if h.new_unit_namespace.is_some() {
                    return Err(REFUSED);
                }
                false
            }
            Phase::NativeRecoveryRequired | Phase::RolledBack => return Err(REFUSED),
        };
        if prepared {
            // Provider independently authenticates the sealed new namespace and
            // phase-specific runtime identity before entering the actual closure.
            let operation = self.prepared_operation.ok_or(REFUSED)?;
            crate::profile_auto_stopped_service::execute_prepared_runtime_stopped(
                self, operation, mutate,
            )
        } else {
            crate::profile_auto_stopped_service::execute_stopped(self, mutate)
        }
    }
    pub(super) fn recovering_publication_role(
        &self,
    ) -> Result<crate::profile_auto_unit_policy::linux::LeafRole> {
        let h = self.fresh_header()?;
        if self.unit_operation.get() != Some(UnitOperation::RecoverPendingPublish)
            || h.phase != Phase::Config
            || h.capture_started
            || h.unit_pending.is_some()
            || h.pending.is_some()
            || h.new_unit_namespace.is_some()
            || h.unit_restored_manager.is_some()
        {
            return Err(REFUSED);
        }
        self.recovering_publication_role.ok_or(REFUSED)
    }
    pub(super) fn finish_publication_recovery_for_rollback(
        &self,
        completion: super::unit_store::PublicationRecoveryCompletion,
    ) -> Result<()> {
        let role = self.recovering_publication_role()?;
        self.install_lock
            .ok_or(REFUSED)?
            .revalidate()
            .map_err(fail)?;
        super::unit_store::validate_publication_recovery_completion(self, &completion, role)
            .map_err(fail)?;
        self.fresh_header()?;
        self.install_lock
            .ok_or(REFUSED)?
            .revalidate()
            .map_err(fail)?;
        self.unit_operation.set(Some(UnitOperation::Rollback));
        Ok(())
    }
    pub(super) fn admit_accepted_manager_restoration(&self) -> Result<()> {
        let h = self.fresh_header()?;
        self.install_lock
            .ok_or(REFUSED)?
            .revalidate()
            .map_err(fail)?;
        if self.unit_operation.get() != Some(UnitOperation::RestoreAcceptedManager)
            || self.prepared_operation
                != Some(crate::profile_auto_stopped_service::PreparedOperation::StaticRollback)
            || h.unit_restored_manager.is_some()
        {
            return Err(REFUSED);
        }
        super::unit_store::admit_accepted_manager_restoration(&self.stage.borrow()).map_err(fail)
    }
    pub(super) fn admit_dropin_publication_record(&self, restored: bool) -> Result<()> {
        let h = self.fresh_header()?;
        self.install_lock
            .ok_or(REFUSED)?
            .revalidate()
            .map_err(fail)?;
        match dropin_record_route(&h, self.unit_operation.get(), restored)? {
            DropinRecordRoute::AcceptedRestoration => self.admit_accepted_manager_restoration(),
            DropinRecordRoute::Forward | DropinRecordRoute::OriginalRestoration => Ok(()),
        }
    }
    pub(super) fn unitrestoration_phase<T>(&self, mutate: impl FnOnce() -> Result<T>) -> Result<T> {
        self.admit_accepted_manager_restoration()?;
        crate::profile_auto_stopped_service::execute_accepted_manager_stopped(self, mutate)
    }
    pub(super) fn admit_active_operation(&self) -> Result<()> {
        let h = self.fresh_header()?;
        self.install_lock
            .ok_or(REFUSED)?
            .revalidate()
            .map_err(fail)?;
        if !matches!(h.phase, Phase::Metadata | Phase::Finalized)
            || h.pending.is_some()
            || h.unit_pending.is_some()
            || h.new_unit_namespace.is_none()
        {
            return Err(REFUSED);
        }
        h.runtime_binding
            .as_ref()
            .ok_or(REFUSED)?
            .revalidate_local_generation()
            .map_err(fail)?;
        Ok(())
    }
    pub(super) fn unit_pending_recovery<T>(&self, mutate: impl FnOnce() -> Result<T>) -> Result<T> {
        crate::profile_auto_stopped_service::execute_pending_unit_stopped(self, mutate)
    }
    pub(super) fn stage_cell(&self) -> &RefCell<StageGuard> {
        &self.stage
    }
}
impl Context for RootContext<'_> {
    fn publication_lease(&self) -> Result<PublicationLease> {
        self.stage.borrow().publication_lease().map_err(fail)
    }
    fn admit(&self, role: Role, operation: Operation) -> Result<()> {
        let h = self.fresh_header()?;
        let accepted = match (role, operation) {
            (Role::Config, Operation::ConfigCustody) => {
                h.phase == Phase::Prepared && h.pending.is_none()
            }
            (Role::StateTarget, Operation::RuntimeState) => {
                h.phase == Phase::Custody && h.pending.is_none() && !h.capture_started
            }
            (Role::Config, Operation::FinalConfig) => {
                h.phase == Phase::State && h.pending.is_none()
            }
            (Role::AdministratorMetadata, Operation::AdministrativeMetadata) => {
                h.phase == Phase::Config && h.pending.is_none()
            }
            (
                Role::Config | Role::StateTarget | Role::AdministratorMetadata,
                Operation::Rollback,
            ) => {
                matches!(
                    h.phase,
                    Phase::Custody
                        | Phase::State
                        | Phase::Config
                        | Phase::Metadata
                        | Phase::Finalized
                        | Phase::NativeRecoveryRequired
                ) && h.pending.is_none()
                    && !h.capture_started
            }
            (
                Role::Config | Role::StateTarget | Role::AdministratorMetadata,
                Operation::RecoverPending,
            ) => h
                .pending
                .as_ref()
                .is_none_or(|(_, s)| Some(s.role.as_str()) == root_role(role).ok()),
            (Role::Config, Operation::Projection) => {
                h.phase == Phase::Metadata
                    && h.capture_started
                    && !matches!(h.mode, super::AutoMode::SocksOnly)
                    && h.pending
                        .as_ref()
                        .is_none_or(|(_, seal)| seal.role == "config" && seal.phase == "projection")
            }
            (Role::Config | Role::StateTarget, Operation::ReadPublished) => {
                matches!(
                    h.phase,
                    Phase::State
                        | Phase::Config
                        | Phase::Metadata
                        | Phase::Finalized
                        | Phase::NativeRecoveryRequired
                ) && h.pending.is_none()
            }
            _ => false,
        };
        if accepted {
            Ok(())
        } else {
            Err(REFUSED)
        }
    }
    fn ensure_sealed_parent(&self, role: Role) -> Result<()> {
        self.protect_tree_reads()?;
        namespace::ensure_sealed_parent(&mut self.stage.borrow_mut(), root_role(role)?)
            .map_err(fail)
    }
    fn sealed_target(&self, role: Role) -> Result<&Path> {
        self.protect_tree_reads()?;
        self.targets.get(&role).map(PathBuf::as_path).ok_or(REFUSED)
    }
    fn original_generation(&self, role: Role) -> Result<&GenerationRecord> {
        self.protect_tree_reads()?;
        self.records.get(&role).ok_or(REFUSED)
    }
    fn guarded_initial_witness(&self, role: Role) -> Result<Option<&[u8]>> {
        self.protect_tree_reads()?;
        Ok(self.witnesses.get(&role).map(|b| b.as_slice()))
    }
    fn raw_tree(&self, role: Role) -> Result<&OwnedTree> {
        self.protect_tree_reads()?;
        self.raw.get(&role).ok_or(REFUSED)
    }
    fn accepted_tree(&self, role: Role) -> Result<&OwnedTree> {
        self.protect_tree_reads()?;
        self.accepted.get(&role).ok_or(REFUSED)
    }
    fn service_identity(&self) -> Result<ServiceIdentity> {
        let h = self.fresh_header()?;
        Ok(ServiceIdentity {
            uid: h.service_uid.ok_or(REFUSED)?,
            gid: h.service_gid.ok_or(REFUSED)?,
            was_active: h.service_was_active.ok_or(REFUSED)?,
        })
    }
    fn assert_old_actor_stopped(&self) -> Result<()> {
        self.stopped_phase(|| Ok(()))
    }
    fn runtime_identity(&self) -> Result<ServiceIdentity> {
        let h = self.fresh_header()?;
        let binding = h.runtime_binding.as_ref().ok_or(REFUSED)?;
        binding.revalidate_local_generation().map_err(fail)?;
        Ok(ServiceIdentity {
            uid: binding.identity().uid(),
            gid: binding.identity().gid(),
            was_active: false,
        })
    }
    fn runtime_config_policy(&self) -> Result<fs::ConfigPolicy> {
        let h = self.fresh_header()?;
        let binding = h.runtime_binding.as_ref().ok_or(REFUSED)?;
        binding.revalidate_local_generation().map_err(fail)?;
        let stage = self.stage.borrow();
        let rendered = crate::profile_auto_render::PreparedRender::restore_private_recipe(&*stage)
            .map_err(fail)?;
        let settings: aegis_core::Settings =
            toml::from_str(&rendered.config.bytes).map_err(fail)?;
        let computed = crate::profile_auto_runtime_identity::runtime_policy(h.mode, &settings)
            .map_err(fail)?;
        if computed != binding.policy() {
            return Err(REFUSED);
        }
        let accepted = self.accepted.get(&Role::Config).ok_or(REFUSED)?;
        let mut leaves: BTreeMap<PathBuf, fs::ConfigLeafRole> = accepted
            .files
            .keys()
            .map(|p| (p.clone(), fs::ConfigLeafRole::AdministratorPrivate))
            .collect();
        let mut classify = |path: &Path, role| -> Result<()> {
            if !safe_relative(path) || !accepted.files.contains_key(path) {
                return Err(REFUSED);
            }
            let old = leaves.insert(path.to_path_buf(), role).ok_or(REFUSED)?;
            if old != fs::ConfigLeafRole::AdministratorPrivate && old != role {
                return Err(REFUSED);
            }
            Ok(())
        };
        classify(rendered.config_leaf(), fs::ConfigLeafRole::Public)?;
        for leaf in &rendered.supplementary {
            classify(&leaf.relative_leaf, fs::ConfigLeafRole::Public)?;
        }
        for reference in &stage.manifest.references {
            if let Ok(relative) = reference.final_path.strip_prefix(&h.config_root) {
                classify(
                    relative,
                    if reference.expected_uid.is_some() {
                        fs::ConfigLeafRole::RuntimePrivate
                    } else {
                        fs::ConfigLeafRole::Public
                    },
                )?;
            } else if reference.expected_uid.is_some()
                && reference.expected_uid != Some(binding.identity().uid())
            {
                return Err(REFUSED);
            }
        }
        Ok(fs::ConfigPolicy {
            runtime_uid: binding.identity().uid(),
            runtime_gid: binding.identity().gid(),
            root_policy: computed == crate::profile_auto_runtime_identity::RuntimePolicy::Root,
            leaves,
        })
    }
    fn capture_guard(&self, role: Role, basis: Basis) -> Result<&dyn fs::CaptureGuard> {
        self.protect_tree_reads()?;
        let id = match basis {
            Basis::SealedInitial => 0,
            Basis::CurrentOwnReceipt => 1,
        };
        self.guards
            .get(&(role, id))
            .map(|g| g as &dyn fs::CaptureGuard)
            .ok_or(REFUSED)
    }
    fn persist_stage(
        &self,
        role: Role,
        operation: Operation,
        receipt: &fs::StageReceipt,
    ) -> Result<()> {
        self.admit(role, operation)?;
        if self.sealed_target(role)? != receipt.target
            || !receipt.stage.starts_with(".auto-config-")
            || receipt.stage.len() != 45
            || !receipt.stage[13..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(REFUSED);
        }
        let mut stage = self.stage.borrow_mut();
        let leaf = PathBuf::from(format!(
            "records/new-stages/{}-{}-{}.json",
            root_role(role)?,
            phase(operation)?,
            receipt.stage
        ));
        let bytes = serde_json::to_vec(receipt).map_err(fail)?;
        stage.store.write_new(&leaf, &bytes).map_err(fail)?;
        stage.header.leaves.insert(leaf, digest(&bytes));
        stage.persist_header().map_err(fail)
    }
    fn persist_intent(
        &self,
        role: Role,
        operation: Operation,
        intent: &fs::PublicationIntent,
    ) -> Result<()> {
        self.admit(role, operation)?;
        self.stage
            .borrow_mut()
            .begin_publication(root_role(role)?, phase(operation)?, intent)
            .map_err(fail)
    }
    fn commit_actual_receipt(
        &self,
        role: Role,
        _: Operation,
        receipt: &fs::PublicationReceipt,
    ) -> Result<()> {
        self.stage
            .borrow_mut()
            .accept_publication(root_role(role)?, receipt)
            .map_err(fail)
    }
    fn authenticated_current_receipt(&self, role: Role) -> Result<fs::AuthenticatedRecord> {
        self.protect_tree_reads()?;
        self.stage
            .borrow()
            .publication_record(root_role(role)?)
            .map_err(fail)
    }
    fn authenticated_pending_intent(&self, role: Role) -> Result<Option<fs::AuthenticatedIntent>> {
        let h = self.fresh_header()?;
        match h.pending {
            Some((_, s)) if s.role == root_role(role)? => self
                .stage
                .borrow()
                .pending_intent_record()
                .map(Some)
                .map_err(fail),
            Some(_) => Err(REFUSED),
            None => Ok(None),
        }
    }
    fn pending_operation(&self, role: Role) -> Result<Operation> {
        let h = self.fresh_header()?;
        let (_, s) = h.pending.ok_or(REFUSED)?;
        if s.role != root_role(role)? {
            return Err(REFUSED);
        }
        match s.phase.as_str() {
            "custody" => Ok(Operation::ConfigCustody),
            "config" => Ok(Operation::FinalConfig),
            "state" => Ok(Operation::RuntimeState),
            "metadata" => Ok(Operation::AdministrativeMetadata),
            "rollback" => Ok(Operation::Rollback),
            _ => Err(REFUSED),
        }
    }
    fn record_pending_not_published(&self, role: Role, _: Operation) -> Result<()> {
        self.stage
            .borrow_mut()
            .clear_unpublished_pending(root_role(role)?)
            .map_err(fail)
    }
    fn persist_withdrawal_intent(&self, role: Role, intent: &fs::WithdrawalIntent) -> Result<()> {
        self.admit(role, Operation::Rollback)?;
        self.stage
            .borrow_mut()
            .begin_withdrawal(root_role(role)?, intent)
            .map_err(fail)
    }
    fn commit_withdrawal_receipt(&self, role: Role, receipt: &fs::WithdrawalReceipt) -> Result<()> {
        self.stage
            .borrow_mut()
            .accept_withdrawal(root_role(role)?, receipt)
            .map_err(fail)
    }
    fn validate_original_absence_chain(
        &self,
        role: Role,
        target: &Path,
        epoch: &str,
    ) -> Result<()> {
        let h = self.fresh_header()?;
        let original = self.records.get(&role).ok_or(REFUSED)?;
        if original.kind() != 2 || original.original_source() != target {
            return Err(REFUSED);
        }
        let name = root_role(role)?;
        let mut leaf = if let Some(active) = h.active_records.get(name) {
            active.clone()
        } else {
            // Completed withdrawal removes the active publication pointer. Its
            // protected exact predecessor remains the historical absence chain;
            // this does not assert the target is currently absent.
            let withdrawn: Vec<_> = h
                .current_records
                .iter()
                .filter(|(path, seal)| {
                    seal.role == name
                        && seal.phase == "rollback"
                        && path.file_name() == Some(std::ffi::OsStr::new("withdrawal-receipt.json"))
                })
                .collect();
            if withdrawn.len() != 1 {
                return Err(REFUSED);
            }
            let (path, seal) = withdrawn[0];
            let stage = self.stage.borrow();
            let bytes = stage.store.read(path).map_err(fail)?;
            if digest(&bytes) != seal.sha256
                || receipt_chain(&h, name, "rollback", seal.predecessor_sha256.as_deref())
                    != seal.chain_sha256
            {
                return Err(REFUSED);
            }
            let record: serde_json::Value = serde_json::from_slice(&bytes).map_err(fail)?;
            if record["kind"] != "withdrawal"
                || record["binding"]["transaction_nonce"] != h.transaction_nonce
                || record["binding"]["phase"] != "rollback"
                || record["binding"]["chain_sha256"] != seal.chain_sha256
                || record["intent"]["target"]
                    != serde_json::Value::String(target.to_str().ok_or(REFUSED)?.into())
                || record["intent"]["publication_epoch"] != epoch
            {
                return Err(REFUSED);
            }
            let hash = seal.predecessor_sha256.as_ref().ok_or(REFUSED)?;
            let parent: Vec<_> = h
                .current_records
                .iter()
                .filter(|(_, entry)| entry.role == name && &entry.sha256 == hash)
                .collect();
            if parent.len() != 1 {
                return Err(REFUSED);
            }
            parent[0].0.clone()
        };
        let mut child_old_root: Option<serde_json::Value> = None;
        let mut seen = BTreeSet::new();
        for step in 0..16 {
            if !seen.insert(leaf.clone()) {
                return Err(REFUSED);
            }
            let seal = h.current_records.get(&leaf).ok_or(REFUSED)?;
            if seal.role != name
                || receipt_chain(&h, name, &seal.phase, seal.predecessor_sha256.as_deref())
                    != seal.chain_sha256
            {
                return Err(REFUSED);
            }
            let stage = self.stage.borrow();
            let bytes = stage.store.read(&leaf).map_err(fail)?;
            if digest(&bytes) != seal.sha256 {
                return Err(REFUSED);
            }
            let record: serde_json::Value = serde_json::from_slice(&bytes).map_err(fail)?;
            let intent = &record["intent"];
            if record["kind"] != "publication"
                || intent["protocol"] != "auto-config-publication-v1"
                || intent["epoch"] != intent["stage"]
                || intent["new_root"]["dev"].as_u64().is_none()
                || intent["new_root"]["ino"].as_u64().is_none_or(|n| n == 0)
                || intent["target"]
                    != serde_json::Value::String(target.to_str().ok_or(REFUSED)?.into())
                || record["binding"]["transaction_nonce"] != h.transaction_nonce
                || record["binding"]["phase"] != seal.phase
                || record["binding"]["chain_sha256"] != seal.chain_sha256
            {
                return Err(REFUSED);
            }
            let sub = stage
                .store
                .sub_store(leaf.parent().ok_or(REFUSED)?, false)
                .map_err(fail)?;
            let (dev, ino) = sub.identity().map_err(fail)?;
            if dev != seal.stage_dev
                || ino != seal.stage_ino
                || record["binding"]["transaction_stage"]["dev"] != dev
                || record["binding"]["transaction_stage"]["ino"] != ino
            {
                return Err(REFUSED);
            }
            if step == 0 && intent["epoch"] != epoch {
                return Err(REFUSED);
            }
            if let Some(expected) = child_old_root.take() {
                if intent["new_root"] != expected {
                    return Err(REFUSED);
                }
            }
            match &seal.predecessor_sha256 {
                None => {
                    if !intent["old"].is_null()
                        || (role == Role::Config && seal.phase != "custody")
                        || (role == Role::AdministratorMetadata && seal.phase != "metadata")
                    {
                        return Err(REFUSED);
                    }
                    return Ok(());
                }
                Some(parent_hash) => {
                    child_old_root = Some(intent["old"]["entries"][""]["id"].clone());
                    if child_old_root
                        .as_ref()
                        .is_some_and(serde_json::Value::is_null)
                    {
                        return Err(REFUSED);
                    }
                    let matches: Vec<_> = h
                        .current_records
                        .iter()
                        .filter(|(_, r)| r.role == name && &r.sha256 == parent_hash)
                        .collect();
                    if matches.len() != 1 {
                        return Err(REFUSED);
                    }
                    leaf = matches[0].0.clone();
                }
            }
        }
        Err(REFUSED)
    }
    fn admit_projection(
        &self,
        expected: &crate::profile_auto_render::RenderContext,
        source: &fs::ProjectionSource,
    ) -> Result<()> {
        self.admit(Role::Config, Operation::Projection)?;
        let stage = self.stage.borrow();
        let h = &stage.header;
        if serde_json::to_vec(expected).map_err(fail)?
            != serde_json::to_vec(&stage.manifest.render_context).map_err(fail)?
            || source.target() != h.config_root.as_path()
        {
            return Err(REFUSED);
        }
        let leaf = h.active_records.get("config").ok_or(REFUSED)?;
        let seal = h.current_records.get(leaf).ok_or(REFUSED)?;
        if seal.role != "config"
            || seal.phase != "config"
            || seal.sha256 != source.base_record_sha256()
        {
            return Err(REFUSED);
        }
        let bytes = stage.store.read(leaf).map_err(fail)?;
        if digest(&bytes) != seal.sha256 {
            return Err(REFUSED);
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(fail)?;
        if value["kind"] != "publication"
            || value["intent"]["epoch"] != source.epoch()
            || value["intent"]["new_root"]["dev"] != source.root().dev
            || value["intent"]["new_root"]["ino"] != source.root().ino
        {
            return Err(REFUSED);
        }
        if let Some((_, pending)) = &h.pending {
            if pending.predecessor_sha256.as_deref() != Some(source.base_record_sha256()) {
                return Err(REFUSED);
            }
        }
        stage.store.revalidate().map_err(fail)
    }
    fn persist_projection_intent(
        &self,
        intent: &fs::ProjectionIntent,
        rendered: &crate::profile_auto_render::PreparedRender,
    ) -> Result<()> {
        self.stage
            .borrow_mut()
            .begin_projection(intent, rendered)
            .map_err(fail)
    }
    fn commit_projected_receipt(
        &self,
        receipt: &fs::ProjectionReceipt,
        rendered: &crate::profile_auto_render::PreparedRender,
    ) -> Result<()> {
        self.stage
            .borrow_mut()
            .accept_projection(receipt, rendered)
            .map_err(fail)
    }
    fn admit_external_reference(&self, final_path: &Path) -> Result<()> {
        self.protect_tree_reads()?;
        let (role, _) = self.external.get(final_path).ok_or(REFUSED)?;
        let original = self.records.get(role).ok_or(REFUSED)?;
        revalidate_record(original, &self.stage.borrow().header.config_root).map_err(fail)
    }
    fn sealed_external_reference_bytes(&self, final_path: &Path) -> Result<&[u8]> {
        self.protect_tree_reads()?;
        self.external
            .get(final_path)
            .map(|(_, b)| b.as_slice())
            .ok_or(REFUSED)
    }
    fn read_owned_published_state(&self, relative: &Path) -> Result<Zeroizing<Vec<u8>>> {
        self.state
            .read_owned_published_state(&self.stage.borrow(), relative)
    }
}

impl crate::profile_auto_unit_namespace::TransitionAuthority for RootContext<'_> {
    fn transaction_epoch(&self) -> Result<[u8; 32]> {
        self.fresh_header()?;
        super::unit_store::transaction_epoch(&self.stage.borrow()).map_err(fail)
    }
    fn authenticate_owned_transition(
        &self,
        transition: &crate::profile_auto_unit_namespace::OwnedTransition,
    ) -> Result<()> {
        self.fresh_header()?;
        super::unit_store::authenticate_forward(&self.stage.borrow(), transition).map_err(fail)
    }
    fn sealed_daemon_reload_receipt(
        &self,
    ) -> Result<Option<crate::profile_auto_stopped_service::DaemonReloadReceipt>> {
        self.fresh_header()?;
        super::unit_store::sealed_reload_receipt(&self.stage.borrow()).map_err(fail)
    }
    fn authenticate_daemon_reload_receipt(
        &self,
        receipt: &crate::profile_auto_stopped_service::DaemonReloadReceipt,
    ) -> Result<()> {
        self.fresh_header()?;
        super::unit_store::authenticate_reload_receipt(&self.stage.borrow(), receipt).map_err(fail)
    }
}
impl crate::profile_auto_unit_namespace::RestorationAuthority for RootContext<'_> {
    fn authenticate_owned_restoration(
        &self,
        restoration: &crate::profile_auto_unit_namespace::OwnedRestoration,
    ) -> Result<()> {
        self.fresh_header()?;
        super::unit_store::authenticate_restoration(&self.stage.borrow(), restoration).map_err(fail)
    }
}
impl crate::profile_auto_stopped_service::StopAuthority for RootContext<'_> {
    fn revalidate(&self) -> Result<()> {
        self.install_lock.ok_or(REFUSED)?;
        self.fresh_header()?;
        Ok(())
    }
    fn epoch(&self) -> Result<crate::profile_auto_stopped_service::Epoch> {
        let h = self.fresh_header()?;
        let phase = match h.phase {
            Phase::Prepared => "Prepared",
            Phase::Custody => "Custody",
            Phase::State => "State",
            Phase::Config => "Config",
            Phase::Metadata => "Metadata",
            Phase::Finalized => "Finalized",
            Phase::RolledBack => "RolledBack",
            Phase::NativeRecoveryRequired => "NativeRecoveryRequired",
        };
        Ok(crate::profile_auto_stopped_service::Epoch {
            transaction_nonce: h.transaction_nonce,
            original_generation: h.input_generation,
            planned_generation: h.planned_generation,
            phase: phase.into(),
            old_uid: h.service_uid.ok_or(REFUSED)?,
            old_gid: h.service_gid.ok_or(REFUSED)?,
        })
    }
    fn sealed_owned_unit_transitions(
        &self,
    ) -> Result<Vec<crate::profile_auto_unit_namespace::OwnedTransition>> {
        self.fresh_header()?;
        super::unit_store::forward_history(&self.stage.borrow()).map_err(fail)
    }
    fn sealed_owned_unit_restorations(
        &self,
    ) -> Result<Vec<crate::profile_auto_unit_namespace::OwnedRestoration>> {
        self.fresh_header()?;
        super::unit_store::restoration_history(&self.stage.borrow()).map_err(fail)
    }
    fn sealed_unit_namespace_record(
        &self,
    ) -> Result<crate::profile_auto_unit_namespace::NamespaceRecord> {
        self.fresh_header()?;
        super::unit_binding::read(&self.stage.borrow(), false).map_err(fail)
    }
    fn install_lock(&self) -> Result<&crate::profile_auto_stopped_service::InstallLock> {
        self.install_lock.ok_or(REFUSED)
    }
}
impl crate::profile_auto_stopped_service::RuntimeAuthority for RootContext<'_> {
    fn admit_prepared_operation(
        &self,
        operation: crate::profile_auto_stopped_service::PreparedOperation,
    ) -> Result<()> {
        use crate::profile_auto_stopped_service::PreparedOperation;
        let h = self.fresh_header()?;
        if self.prepared_operation != Some(operation)
            || h.capture_started
            || h.new_unit_namespace.is_none()
        {
            return Err(REFUSED);
        }
        let allowed = match operation {
            PreparedOperation::PublishMetadata => {
                matches!(h.phase, Phase::Config | Phase::Metadata)
            }
            PreparedOperation::BeforeActivation => h.phase == Phase::Metadata,
            PreparedOperation::StaticRollback => {
                matches!(h.phase, Phase::Config | Phase::Metadata | Phase::Finalized)
            }
        };
        if !allowed {
            return Err(REFUSED);
        }
        let binding = h.runtime_binding.as_ref().ok_or(REFUSED)?;
        binding.revalidate_local_generation().map_err(fail)?;
        super::unit_store::validate_accepted_policy_epoch(self, operation).map_err(fail)
    }
    fn sealed_prepared_unit_namespace_record(
        &self,
    ) -> Result<crate::profile_auto_unit_namespace::NamespaceRecord> {
        self.fresh_header()?;
        super::unit_binding::read(&self.stage.borrow(), true).map_err(fail)
    }
    fn prepared_runtime_identity(&self) -> Result<(u32, u32)> {
        let h = self.fresh_header()?;
        match self.unit_operation.get() {
            Some(UnitOperation::Publish | UnitOperation::Reload) => {
                if h.phase != Phase::Config
                    || h.capture_started
                    || h.new_unit_namespace.is_some()
                    || self.prepared_operation.is_some()
                {
                    return Err(REFUSED);
                }
                // Identity admission for the COMPLETE actual staged new policy,
                // before checked reload mints its accepted manager namespace.
                // This does not declare the original actor stopped.
                super::unit_store::verify_published_policy(self).map_err(fail)?;
                if self.unit_operation.get() == Some(UnitOperation::Reload) {
                    RootContext::admit_reload_operation(self)?;
                }
            }
            _ => self.admit_prepared_operation(self.prepared_operation.ok_or(REFUSED)?)?,
        }
        let b = h.runtime_binding.as_ref().ok_or(REFUSED)?;
        b.revalidate_local_generation().map_err(fail)?;
        Ok((b.identity().uid(), b.identity().gid()))
    }
}

impl crate::profile_auto_stopped_service::CompletePolicyAuthority for RootContext<'_> {
    fn authenticate_complete_published_policy(
        &self,
        records: &[crate::profile_auto_unit_namespace::OwnedTransition],
    ) -> Result<()> {
        super::unit_store::authenticate_complete_published_policy(self, records).map_err(fail)
    }
    fn expected_dropin_paths(&self) -> Result<BTreeSet<PathBuf>> {
        self.fresh_header()?;
        super::unit_store::expected_dropin_paths(&self.stage.borrow()).map_err(fail)
    }
    fn policy_identity(&self) -> Result<String> {
        self.fresh_header()?;
        super::unit_store::policy_identity(&self.stage.borrow()).map_err(fail)
    }
    fn admit_reload_operation(&self) -> Result<()> {
        RootContext::admit_reload_operation(self)
    }
    fn admit_final_base_publication(
        &self,
        incoming: &crate::profile_auto_unit_namespace::OwnedTransition,
    ) -> Result<()> {
        RootContext::admit_final_base_publication(self, incoming)
    }
}
impl crate::profile_auto_stopped_service::PendingUnitAuthority for RootContext<'_> {
    fn authenticated_pending_unit_namespace(
        &self,
    ) -> Result<crate::profile_auto_unit_namespace::PendingSingletonNamespaceView> {
        self.fresh_header()?;
        super::unit_store::authenticate_pending_namespace(self).map_err(fail)
    }
    fn revalidate_pending_unit_namespace(
        &self,
        view: &crate::profile_auto_unit_namespace::PendingSingletonNamespaceView,
    ) -> Result<()> {
        self.fresh_header()?;
        super::unit_store::revalidate_pending_namespace(self, view).map_err(fail)
    }
}

impl crate::profile_auto_stopped_service::ManagerRestorationAuthority for RootContext<'_> {
    fn authenticated_restoration_manager_epoch(
        &self,
    ) -> Result<crate::profile_auto_unit_namespace::RestorationManagerEpoch> {
        self.admit_accepted_manager_restoration()?;
        super::unit_store::authenticate_restoration_manager_epoch(self).map_err(fail)
    }
    fn revalidate_restoration_manager_epoch(
        &self,
        epoch: &crate::profile_auto_unit_namespace::RestorationManagerEpoch,
    ) -> Result<()> {
        self.admit_accepted_manager_restoration()?;
        super::unit_store::revalidate_restoration_manager_epoch(self, epoch).map_err(fail)
    }
    fn admit_manager_restore_reload(&self) -> Result<()> {
        self.admit_accepted_manager_restoration()?;
        super::unit_store::admit_manager_restore_reload(self).map_err(fail)
    }
    fn authenticate_complete_restored_policy(&self) -> Result<()> {
        self.admit_accepted_manager_restoration()?;
        super::unit_store::authenticate_complete_restored_policy(self).map_err(fail)
    }
}
impl crate::profile_auto_stopped_service::RestoredManagerAuthority for RootContext<'_> {
    fn sealed_restored_manager_receipt(
        &self,
    ) -> Result<crate::profile_auto_stopped_service::RestoredManagerReceipt> {
        self.fresh_header()?;
        super::unit_store::sealed_restored_manager_receipt(self).map_err(fail)
    }
    fn authenticate_restored_manager_receipt(
        &self,
        receipt: &crate::profile_auto_stopped_service::RestoredManagerReceipt,
    ) -> Result<()> {
        self.fresh_header()?;
        super::unit_store::authenticate_restored_manager_receipt(self, receipt).map_err(fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalized_roles_keep_config_and_state_names_separate() {
        assert_eq!(key(Role::Config), "config");
        assert_eq!(key(Role::StateTarget), "state");
        assert_eq!(key(Role::StateSource), "prior-state");
        assert_eq!(key(Role::AdministratorMetadata), "metadata");
        assert_eq!(key(Role::Reference(7)), "reference-7");
        assert_ne!(
            format!("input/payload/{}/state.json", key(Role::Config)),
            format!("input/payload/{}/state.json", key(Role::StateTarget))
        );
    }
    #[test]
    fn payload_relative_authority_refuses_escape_or_unbounded_depth() {
        for p in [
            "",
            "../other",
            "/etc/secret",
            "a/../../other",
            "a/./b",
            "a/b/c/d/e/f/g/h/i",
        ] {
            assert!(!safe_relative(Path::new(p)));
        }
        assert!(safe_relative(Path::new("nested/empty/config.toml")));
    }
    #[test]
    fn operation_and_root_role_names_are_closed() {
        assert_eq!(root_role(Role::Config).unwrap(), "config");
        assert_eq!(root_role(Role::StateTarget).unwrap(), "state");
        assert_eq!(root_role(Role::AdministratorMetadata).unwrap(), "metadata");
        assert!(root_role(Role::Reference(0)).is_err());
        assert_eq!(phase(Operation::Rollback).unwrap(), "rollback");
        assert!(phase(Operation::ReadPublished).is_err());
    }
}
