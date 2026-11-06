//! PRIVATE UNAPPLIED: actual FD config/adminmetadata publication adapter.
//! Required Context is supplied by protected typed Store/phase authority. This
//! module supplies no default/fake context and performs no service/network IO.
#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use crate::profile_auto_capture::GenerationRecord;
    use crate::profile_auto_prepare::{OwnedTree, Role};
    use crate::profile_auto_publication::linux as fs;
    use crate::profile_auto_render::{PreparedRender, PublishedTree, RenderContext, SelectedMode};
    use crate::profile_auto_transaction::PublicationLease;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::path::{Component, Path, PathBuf};
    use zeroize::Zeroizing;
    type Result<T> = std::result::Result<T, &'static str>;
    const REFUSED: &str = "Administrative AUTO owned publication refused";
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Operation {
        ConfigCustody,
        FinalConfig,
        RuntimeState,
        AdministrativeMetadata,
        Rollback,
        RecoverPending,
        ReadPublished,
        Projection,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Basis {
        SealedInitial,
        CurrentOwnReceipt,
    }
    pub(crate) struct ServiceIdentity {
        pub uid: u32,
        pub gid: u32,
        pub was_active: bool,
    }

    /// Actual protected Store must implement every method. No public JSON
    /// authority, arbitrary claimed initial generation or success-only adapter.
    /// Methods use shared access so synchronous phase updates can use an internal
    /// protected Header cell; guards must recheck actual durable phase/chain.
    pub(crate) trait Context {
        /// Retain through the complete external target effect and durable
        /// receipt. Recovery-only sealing excludes this protected lease.
        fn publication_lease(&self) -> Result<PublicationLease>;
        fn admit(&self, role: Role, operation: Operation) -> Result<()>;
        fn sealed_target(&self, role: Role) -> Result<&Path>;
        /// Actual typed NamespaceAdmission creates/adopts ONLY own proven parent
        /// chain; target leaf remains absent until publication. No blind mkdir.
        fn ensure_sealed_parent(&self, role: Role) -> Result<()>;
        fn original_generation(&self, role: Role) -> Result<&GenerationRecord>;
        fn guarded_initial_witness(&self, role: Role) -> Result<Option<&[u8]>>;
        fn raw_tree(&self, role: Role) -> Result<&OwnedTree>;
        fn accepted_tree(&self, role: Role) -> Result<&OwnedTree>;
        /// Immutable OLD actor used only for custody and restoration.
        fn service_identity(&self) -> Result<ServiceIdentity>;
        /// Separately admitted final account, never inferred from OLD actor.
        fn runtime_identity(&self) -> Result<ServiceIdentity>;
        /// Rechecks the SAME worker-held lock/sample boundary; backend retains
        /// actual provider admission through the entire mutation closure.
        fn assert_old_actor_stopped(&self) -> Result<()>;
        fn runtime_config_policy(&self) -> Result<fs::ConfigPolicy>;
        /// Initial binds actual byte capture and sealed initial witness. Current
        /// binds exact active OWN descriptor-minted receipt and successor chain.
        fn capture_guard(&self, role: Role, basis: Basis) -> Result<&dyn fs::CaptureGuard>;
        fn persist_stage(
            &self,
            role: Role,
            operation: Operation,
            stage: &fs::StageReceipt,
        ) -> Result<()>;
        /// Must persist/sync exact descriptor-minted intent + Header.pending
        /// role/operation/pinned hash BEFORE rename; never advance active phase.
        fn persist_intent(
            &self,
            role: Role,
            operation: Operation,
            intent: &fs::PublicationIntent,
        ) -> Result<()>;
        /// Seal/sync actual receipt and its exact hash before active record/phase
        /// advancement. Failure retains pending intent and all filesystem trees.
        fn commit_actual_receipt(
            &self,
            role: Role,
            operation: Operation,
            receipt: &fs::PublicationReceipt,
        ) -> Result<()>;
        fn authenticated_current_receipt(&self, role: Role) -> Result<fs::AuthenticatedRecord>;
        fn authenticated_pending_intent(
            &self,
            role: Role,
        ) -> Result<Option<fs::AuthenticatedIntent>>;
        fn pending_operation(&self, role: Role) -> Result<Operation>;
        /// Only after authenticated BeforeRename classification; retain stage.
        fn record_pending_not_published(&self, role: Role, operation: Operation) -> Result<()>;
        fn persist_withdrawal_intent(
            &self,
            role: Role,
            intent: &fs::WithdrawalIntent,
        ) -> Result<()>;
        fn commit_withdrawal_receipt(
            &self,
            role: Role,
            receipt: &fs::WithdrawalReceipt,
        ) -> Result<()>;
        /// Must bind protected original kind2/source record, first custody oldNone
        /// receipt, and EVERY protected successor predecessorSHA to currentepoch.
        fn validate_original_absence_chain(
            &self,
            role: Role,
            target: &Path,
            current_epoch: &str,
        ) -> Result<()>;
        /// For external refs, bind final->original map to sealed captured bytes
        /// AND metadata-only original generation guard. Never reread source bytes.
        fn admit_external_reference(&self, final_path: &Path) -> Result<()>;
        fn sealed_external_reference_bytes(&self, final_path: &Path) -> Result<&[u8]>;
        /// State singleton publisher (separate owner) must provide an actual held
        /// owned-receipt-guarded published-file read, not original path read/fake.
        /// Concrete protected mode/Metadata/capture lifecycle + accepted recipe
        /// context + actual ACTIVE predecessor hash/epoch/root admission.
        fn admit_projection(
            &self,
            expected: &RenderContext,
            source: &fs::ProjectionSource,
        ) -> Result<()>;
        /// Seal immutable projection intent and pending exact source hash before
        /// accepting projected generation; never pretend another directory rename.
        fn persist_projection_intent(
            &self,
            intent: &fs::ProjectionIntent,
            rendered: &PreparedRender,
        ) -> Result<()>;
        fn commit_projected_receipt(
            &self,
            receipt: &fs::ProjectionReceipt,
            rendered: &PreparedRender,
        ) -> Result<()>;
        fn read_owned_published_state(&self, relative: &Path) -> Result<Zeroizing<Vec<u8>>>;
    }
    pub(crate) struct RuntimePublication<'a, C: Context + ?Sized> {
        context: &'a C,
    }
    impl<'a, C: Context + ?Sized> RuntimePublication<'a, C> {
        pub fn new(context: &'a C) -> Self {
            Self { context }
        }
        fn target(&self, role: Role) -> Result<fs::Target> {
            if unsafe { libc::geteuid() } != 0 {
                return Err(REFUSED);
            }
            if !matches!(
                role,
                Role::Config | Role::StateTarget | Role::AdministratorMetadata
            ) {
                return Err(REFUSED);
            }
            self.context.ensure_sealed_parent(role)?;
            let path = self.context.sealed_target(role)?;
            let original = self.context.original_generation(role)?;
            if original.original_source() != path || !matches!(original.kind(), 0 | 2) {
                return Err(REFUSED);
            }
            fs::Target::open(path)
        }
        fn initial(&self, role: Role) -> Result<Option<fs::Generation>> {
            let source = self.context.original_generation(role)?;
            let witness = self.context.guarded_initial_witness(role)?;
            match (source.kind(), witness) {
                (2, None) => {
                    let guard = self.context.capture_guard(role, Basis::SealedInitial)?;
                    guard.validate_captured_generation(self.context.sealed_target(role)?, None)?;
                    Ok(None)
                }
                (0, Some(bytes)) => Ok(Some(fs::Generation::from_guarded_witness(
                    self.context.sealed_target(role)?,
                    bytes,
                    self.context.capture_guard(role, Basis::SealedInitial)?,
                )?)),
                _ => Err(REFUSED),
            }
        }
        fn owned_tree(&self, role: Role, accepted: bool) -> Result<fs::CapturedTree> {
            let owned = if accepted {
                self.context.accepted_tree(role)?
            } else {
                self.context.raw_tree(role)?
            };
            fs::CapturedTree::new(
                owned
                    .files
                    .iter()
                    .map(|(p, b)| (p.clone(), b.to_vec()))
                    .collect(),
                owned.directories.clone(),
            )
        }
        fn own_current(&self, role: Role, target: &fs::Target) -> Result<fs::PublicationReceipt> {
            let admitted = self.context.authenticated_current_receipt(role)?;
            fs::reopen_own_receipt(target, &admitted)
        }
        /// Old captured config becomes service-owned via a NEW full directory;
        /// prior directory is retained unchanged. Root/service identity and
        /// was-active marker are captured/sealed by actual Context first.
        pub fn commit_custody(&self) -> Result<()> {
            let _publication_lease = self.context.publication_lease()?;
            let role = Role::Config;
            let operation = Operation::ConfigCustody;
            self.context.admit(role, operation)?;
            let identity = self.context.service_identity()?;
            let _captured_was_active = identity.was_active;
            let target = self.target(role)?;
            let expected = self.initial(role)?;
            let tree = self.owned_tree(role, false)?;
            let guard = self.context.capture_guard(role, Basis::SealedInitial)?;
            let prepared = fs::Prepared::build_policy_captured(
                target,
                expected,
                &tree,
                identity.uid,
                identity.gid,
                fs::RootMode::ServiceConfig0750,
                |stage| self.context.persist_stage(role, operation, stage),
                guard,
            )?;
            let actual = prepared.publish_captured(
                |intent| self.context.persist_intent(role, operation, intent),
                guard,
            )?;
            self.context.commit_actual_receipt(role, operation, &actual)
        }
        /// Uses current OWN receipt after custody; obsolete original guard may
        /// not authorize a target intentionally changed by this transaction.
        pub fn commit_config(&self) -> Result<()> {
            let _publication_lease = self.context.publication_lease()?;
            let role = Role::Config;
            let operation = Operation::FinalConfig;
            self.context.admit(role, operation)?;
            let policy = self.context.runtime_config_policy()?;
            let target = self.target(role)?;
            let current = self.own_current(role, &target)?;
            let tree = self.owned_tree(role, true)?;
            let expected = Some(current.generation().clone());
            let guard = self.context.capture_guard(role, Basis::CurrentOwnReceipt)?;
            let prepared = fs::Prepared::build_runtime_config_captured(
                target,
                expected,
                &tree,
                &policy,
                |stage| self.context.persist_stage(role, operation, stage),
                guard,
            )?;
            let actual = prepared.publish_captured(
                |intent| self.context.persist_intent(role, operation, intent),
                guard,
            )?;
            self.context.commit_actual_receipt(role, operation, &actual)
        }
        pub fn verify_final_runtime_config(&self) -> Result<()> {
            self.context.admit(Role::Config, Operation::ReadPublished)?;
            let target = self.target(Role::Config)?;
            let receipt = self.own_current(Role::Config, &target)?;
            let policy = self.context.runtime_config_policy()?;
            fs::verify_runtime_config_policy(&target, &receipt, &policy)
        }
        /// Administrator metadata has closed admin0700 directory policy and
        /// uid/gid0/0; it never inherits service identity or service0750 mode.
        pub fn publish_metadata(&self) -> Result<()> {
            let _publication_lease = self.context.publication_lease()?;
            let role = Role::AdministratorMetadata;
            let operation = Operation::AdministrativeMetadata;
            self.context.admit(role, operation)?;
            let target = self.target(role)?;
            let expected = self.initial(role)?;
            let tree = self.owned_tree(role, true)?;
            let guard = self.context.capture_guard(role, Basis::SealedInitial)?;
            let prepared = fs::Prepared::build_policy_captured(
                target,
                expected,
                &tree,
                0,
                0,
                fs::RootMode::AdministratorMetadata0700,
                |stage| self.context.persist_stage(role, operation, stage),
                guard,
            )?;
            let actual = prepared.publish_captured(
                |intent| self.context.persist_intent(role, operation, intent),
                guard,
            )?;
            self.context.commit_actual_receipt(role, operation, &actual)
        }
        /// Reentry must reconcile admitted pending syscall outcome before any
        /// new operation. Never assume Header.phase means no filesystem change.
        pub fn recover_pending(&self, role: Role) -> Result<bool> {
            let _publication_lease = self.context.publication_lease()?;
            self.context.admit(role, Operation::RecoverPending)?;
            let Some(intent) = self.context.authenticated_pending_intent(role)? else {
                return Ok(false);
            };
            let operation = self.context.pending_operation(role)?;
            if !matches!(
                (role, operation),
                (
                    Role::Config,
                    Operation::ConfigCustody | Operation::FinalConfig | Operation::Rollback
                ) | (
                    Role::StateTarget,
                    Operation::RuntimeState | Operation::Rollback
                ) | (
                    Role::AdministratorMetadata,
                    Operation::AdministrativeMetadata | Operation::Rollback
                )
            ) {
                return Err(REFUSED);
            }
            let target = self.target(role)?;
            match fs::recover_own_receipt(&target, &intent)? {
                Some(actual) => self
                    .context
                    .commit_actual_receipt(role, operation, &actual)?,
                None => self.context.record_pending_not_published(role, operation)?,
            };
            Ok(true)
        }
        /// Config/metadata-only rollback from immutable captured old bytes.
        /// Does not touch service state, routing, private guards or binaries.
        pub fn rollback_role(&self, role: Role) -> Result<()> {
            let _publication_lease = self.context.publication_lease()?;
            self.context.admit(role, Operation::Rollback)?;
            let target = self.target(role)?;
            let current = self.own_current(role, &target)?;
            if self.context.original_generation(role)?.kind() == 2 {
                let chain = AbsenceChain {
                    context: self.context,
                    role,
                };
                let actual = fs::restore_original_absence_after_own_chain(
                    &target,
                    &current,
                    &chain,
                    |intent| self.context.persist_withdrawal_intent(role, intent),
                )?;
                self.context.commit_withdrawal_receipt(role, &actual)
            } else {
                let tree = self.owned_tree(role, false)?;
                let identity = if role == Role::AdministratorMetadata {
                    ServiceIdentity {
                        uid: 0,
                        gid: 0,
                        was_active: false,
                    }
                } else {
                    self.context.service_identity()?
                };
                let actual = fs::restore_captured(
                    target,
                    &current,
                    &tree,
                    identity.uid,
                    identity.gid,
                    |stage| self.context.persist_stage(role, Operation::Rollback, stage),
                    |intent| {
                        self.context
                            .persist_intent(role, Operation::Rollback, intent)
                    },
                )?;
                self.context
                    .commit_actual_receipt(role, Operation::Rollback, &actual)
            }
        }
        /// Installed helper may normalize main TOML. Scope is fixed main only;
        /// actual renderer owns whole-document semantic acceptance and recipe
        /// final-generation refresh. No free-form key list or success callback.
        pub fn preflight_projection(&self, rendered: &PreparedRender) -> Result<()> {
            if matches!(rendered.context.mode, SelectedMode::SocksOnly) {
                return Ok(());
            }
            let _publication_lease = self.context.publication_lease()?;
            self.context.admit(Role::Config, Operation::Projection)?;
            let target = self.target(Role::Config)?;
            let record = self.context.authenticated_current_receipt(Role::Config)?;
            let admission = ConcreteProjectionAdmission {
                context: self.context,
                expected: &rendered.context,
            };
            let provisional = fs::ProjectionView::admit(&target, &record, &admission)?;
            let published = ProjectionPublishedView {
                context: self.context,
                target: &target,
                provisional: &provisional,
            };
            rendered.validate_installer_projection(&published)?;
            provisional.revalidate(&target, &admission)
        }

        pub fn finalize_projection(&self, rendered: &mut PreparedRender) -> Result<()> {
            if matches!(rendered.context.mode, SelectedMode::SocksOnly) {
                return rendered.verify_published_tree(&self.published_view()?);
            }
            let _publication_lease = self.context.publication_lease()?;
            self.context.admit(Role::Config, Operation::Projection)?;
            let target = self.target(Role::Config)?;
            let record = self.context.authenticated_current_receipt(Role::Config)?;
            let admission = ConcreteProjectionAdmission {
                context: self.context,
                expected: &rendered.context,
            };
            let provisional = fs::ProjectionView::admit(&target, &record, &admission)?;
            let source = &provisional;
            let published = ProjectionPublishedView {
                context: self.context,
                target: &target,
                provisional: source,
            };
            match rendered.context.mode {
                SelectedMode::WideRedirectSafe => rendered.finalize_dns_projection(&published)?,
                SelectedMode::FullWideTun => rendered.finalize_installer_projection(&published)?,
                SelectedMode::SocksOnly => return Err(REFUSED),
            }
            // Semantic verifier succeeded on exactly the bounded snapshot read
            // through retained OWN root. Only this module can construct proof.
            let proof = VerifiedProjection {
                target: provisional.source().target().to_path_buf(),
                base_record_sha256: provisional.source().base_record_sha256().into(),
                epoch: provisional.source().epoch().into(),
                root: provisional.source().root().clone(),
                main_sha256: format!("{:x}", Sha256::digest(provisional.main_bytes())),
            };
            // Refresh admission with updated recipe bytes but unchanged typed
            // RenderContext after verifier (no mutation of admission context).
            let admission = ConcreteProjectionAdmission {
                context: self.context,
                expected: &rendered.context,
            };
            provisional.revalidate(&target, &admission)?;
            self.context
                .persist_projection_intent(&provisional.intent(), rendered)?;
            provisional.revalidate(&target, &admission)?;
            let actual = provisional.accept(&target, &admission, &proof)?;
            // Keep the updated descriptor-owned current generation live and
            // exact until the protected Store commits the actual projected seal.
            fs::revalidate_current_receipt(&target, actual.owned_current())?;
            self.context.commit_projected_receipt(&actual, rendered)
        }
        pub fn published_view(&self) -> Result<PublishedView<'a, C>> {
            self.context.admit(Role::Config, Operation::ReadPublished)?;
            let target = self.target(Role::Config)?;
            let receipt = self.own_current(Role::Config, &target)?;
            Ok(PublishedView {
                context: self.context,
                target,
                receipt,
            })
        }
    }
    /// Public type with private fields/constructor; no caller JSON/bool proof.
    pub(crate) struct VerifiedProjection {
        target: PathBuf,
        base_record_sha256: String,
        epoch: String,
        root: fs::Identity,
        main_sha256: String,
    }
    impl VerifiedProjection {
        pub(crate) fn matches_source(
            &self,
            source: &fs::ProjectionSource,
            main_sha256: &str,
        ) -> Result<()> {
            if self.target != source.target()
                || self.base_record_sha256 != source.base_record_sha256()
                || self.epoch != source.epoch()
                || self.root != *source.root()
                || self.main_sha256 != main_sha256
            {
                return Err(REFUSED);
            }
            Ok(())
        }
    }
    struct ConcreteProjectionAdmission<'a, C: Context + ?Sized> {
        context: &'a C,
        expected: &'a RenderContext,
    }
    impl<C: Context + ?Sized> fs::ProjectionAdmission for ConcreteProjectionAdmission<'_, C> {
        fn admit_projection_source(&self, source: &fs::ProjectionSource) -> Result<()> {
            if matches!(self.expected.mode, SelectedMode::SocksOnly)
                || self.expected.logical_final_base != source.target()
            {
                return Err(REFUSED);
            }
            self.context.admit_projection(self.expected, source)
        }
    }
    struct ProjectionPublishedView<'a, C: Context + ?Sized> {
        context: &'a C,
        target: &'a fs::Target,
        provisional: &'a fs::ProjectionView,
    }
    impl<C: Context + ?Sized> PublishedTree for ProjectionPublishedView<'_, C> {
        fn config_leaf_names(&self) -> Result<BTreeSet<PathBuf>> {
            self.provisional.leaf_names(self.target)
        }
        fn read_config_leaf(&self, relative: &Path) -> Result<Zeroizing<Vec<u8>>> {
            self.provisional.read_leaf(self.target, relative)
        }
        fn read_reference(&self, final_path: &Path) -> Result<Zeroizing<Vec<u8>>> {
            if let Ok(relative) = final_path.strip_prefix(self.context.sealed_target(Role::Config)?)
            {
                return self.provisional.read_leaf(self.target, relative);
            }
            self.context.admit_external_reference(final_path)?;
            let bytes = self.context.sealed_external_reference_bytes(final_path)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err(REFUSED);
            }
            let owned = Zeroizing::new(bytes.to_vec());
            self.context.admit_external_reference(final_path)?;
            Ok(owned)
        }
        fn read_state_leaf(&self, relative: &Path) -> Result<Zeroizing<Vec<u8>>> {
            if relative.is_absolute()
                || relative.as_os_str().is_empty()
                || relative.components().count() > 8
                || relative
                    .components()
                    .any(|p| !matches!(p, Component::Normal(_)))
            {
                return Err(REFUSED);
            }
            let bytes = self.context.read_owned_published_state(relative)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err(REFUSED);
            }
            Ok(bytes)
        }
    }
    struct AbsenceChain<'a, C: Context + ?Sized> {
        context: &'a C,
        role: Role,
    }
    impl<C: Context + ?Sized> fs::OwnAbsenceChainAuthority for AbsenceChain<'_, C> {
        fn validate_original_absence_and_chain(
            &self,
            target: &Path,
            current_epoch: &str,
        ) -> Result<()> {
            if self.context.original_generation(self.role)?.kind() != 2
                || self
                    .context
                    .original_generation(self.role)?
                    .original_source()
                    != target
            {
                return Err(REFUSED);
            }
            self.context
                .validate_original_absence_chain(self.role, target, current_epoch)
        }
    }
    pub(crate) struct PublishedView<'a, C: Context + ?Sized> {
        context: &'a C,
        target: fs::Target,
        receipt: fs::PublicationReceipt,
    }
    impl<C: Context + ?Sized> PublishedTree for PublishedView<'_, C> {
        fn config_leaf_names(&self) -> Result<BTreeSet<PathBuf>> {
            self.context.admit(Role::Config, Operation::ReadPublished)?;
            fs::current_leaf_names(&self.target, &self.receipt)
        }
        fn read_config_leaf(&self, relative: &Path) -> Result<Zeroizing<Vec<u8>>> {
            self.context.admit(Role::Config, Operation::ReadPublished)?;
            fs::read_current_leaf(&self.target, &self.receipt, relative)
        }
        fn read_reference(&self, final_path: &Path) -> Result<Zeroizing<Vec<u8>>> {
            if !final_path.is_absolute()
                || final_path
                    .components()
                    .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            {
                return Err(REFUSED);
            }
            self.context.admit(Role::Config, Operation::ReadPublished)?;
            if let Ok(relative) = final_path.strip_prefix(self.context.sealed_target(Role::Config)?)
            {
                return fs::read_current_leaf(&self.target, &self.receipt, relative);
            }
            // Validate metadata-only original guard before AND after owned sealed
            // byte retrieval; do not open external original secret paths for bytes.
            self.context.admit_external_reference(final_path)?;
            let bytes = self.context.sealed_external_reference_bytes(final_path)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err(REFUSED);
            }
            let owned = Zeroizing::new(bytes.to_vec());
            self.context.admit_external_reference(final_path)?;
            Ok(owned)
        }
        fn read_state_leaf(&self, relative: &Path) -> Result<Zeroizing<Vec<u8>>> {
            if relative.as_os_str().is_empty()
                || relative.is_absolute()
                || relative.components().count() > 8
                || relative
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(REFUSED);
            }
            self.context
                .admit(Role::StateTarget, Operation::ReadPublished)?;
            let bytes = self.context.read_owned_published_state(relative)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err(REFUSED);
            }
            Ok(bytes)
        }
    }
}
