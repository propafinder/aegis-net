// Fresh, one-use inverse of a successfully finalized AUTO activation.  This
// module is included as a child of transaction::durable so it can borrow the
// protected Store while its publication, mutation and stage locks stay held.
mod finalized_stop {
    use super::super::{
        authority::StageGuard, owner_installed::ProtectedInstalledFacts, store_context::RootContext,
    };
    use super::*;
    use crate::profile_auto_stopped_service::pid1::{
        CompletedStop, FinalizedStopAuthority, ManagerIdentity, SubmittedJob,
    };

    pub(super) const INTENT: &str = "activation-owner-deactivation-intent-v1.json";
    const FINAL_STOP: &str = "receipts/activation-owner/finalized-stop-terminal.json";

    #[derive(Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct NativeGuard {
        guardian_pid: u32,
        guardian_nonce: String,
        guardian_receipt_sha256: String,
        policy_sha256: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StartTerminal {
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
        native_guard: Option<NativeGuard>,
        native_capture_sha256: Option<String>,
        native_inverse_sha256: Option<String>,
        post_deny_policy_sha256: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StartSubmitted {
        schema: u32,
        kind: String,
        may_send_sha256: String,
        claim_sha256: String,
        job_id: u32,
        job_path: String,
        unit: String,
        boot_id: String,
        pid1_socket: (u64, u64),
        pid1_netns: (u64, u64),
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StartCompleted {
        schema: u32,
        kind: String,
        submitted_sha256: String,
        job_id: u32,
        job_path: String,
        unit: String,
        invocation_id: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SealedMaySend {
        schema: u32,
        commitments: SealedCommitments,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SealedCommitments {
        binding: SealedBinding,
        mode: AutoMode,
        boot_id: String,
        pid1_socket: (u64, u64),
        pid1_netns: (u64, u64),
        installed_generation_sha256: String,
        installed_manifest_sha256: String,
        policy_generation: String,
        native_guard: Option<NativeGuard>,
        private_unit: String,
        fixed_unit: String,
        launch_ticket_sha256: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SealedBinding {
        transaction_nonce: String,
        planned_generation: String,
        stage: (u64, u64),
        header_sha256: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SealedClaim {
        schema: u32,
        may_send_sha256: String,
        nonce: String,
        stage: (u64, u64),
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LaunchConsumed {
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

    fn validate_start_job_chain(
        terminal: &StartTerminal,
        submitted: &StartSubmitted,
        completed: &StartCompleted,
    ) -> Result<()> {
        if submitted.schema != 1
            || submitted.kind != "owned-start-submitted"
            || submitted.may_send_sha256 != terminal.may_send_sha256
            || submitted.claim_sha256 != terminal.claim_sha256
            || submitted.job_id == 0
            || submitted.job_path != format!("/org/freedesktop/systemd1/job/{}", submitted.job_id)
            || submitted.unit != terminal.private_unit
            || submitted.pid1_socket.0 == 0
            || submitted.pid1_socket.1 == 0
            || submitted.pid1_netns.0 == 0
            || submitted.pid1_netns.1 == 0
            || completed.schema != 1
            || completed.kind != "owned-start-completed"
            || completed.submitted_sha256 != terminal.submitted_sha256
            || completed.job_id != submitted.job_id
            || completed.job_path != submitted.job_path
            || completed.unit != submitted.unit
            || !hex32(&completed.invocation_id)
        {
            return Err(refuse());
        }
        Ok(())
    }

    struct SealedStartSource<'a> {
        terminal: &'a StartTerminal,
        mode: AutoMode,
        archive_bytes: &'a [u8],
        launch_bytes: &'a [u8],
        submitted: &'a StartSubmitted,
        completed: &'a StartCompleted,
        installed_generation_sha256: &'a str,
        installed_manifest_sha256: &'a str,
        policy_generation: &'a str,
    }

    fn validate_sealed_start(source: SealedStartSource<'_>) -> Result<()> {
        let SealedStartSource {
            terminal,
            mode,
            archive_bytes,
            launch_bytes,
            submitted,
            completed,
            installed_generation_sha256,
            installed_manifest_sha256,
            policy_generation,
        } = source;
        let archive: OwnerMarkerArchive =
            serde_json::from_slice(archive_bytes).map_err(|_| refuse())?;
        let may_bytes = hex::decode(&archive.may_send_hex).map_err(|_| refuse())?;
        let claim_bytes = hex::decode(&archive.claim_hex).map_err(|_| refuse())?;
        if archive.schema != 1
            || hex::encode(&may_bytes) != archive.may_send_hex
            || hex::encode(&claim_bytes) != archive.claim_hex
            || digest(archive_bytes) != terminal.marker_archive_sha256
            || digest(&may_bytes) != archive.may_send_sha256
            || digest(&claim_bytes) != archive.claim_sha256
            || archive.may_send_sha256 != terminal.may_send_sha256
            || archive.claim_sha256 != terminal.claim_sha256
        {
            return Err(refuse());
        }
        let may: SealedMaySend = serde_json::from_slice(&may_bytes).map_err(|_| refuse())?;
        let claim: SealedClaim = serde_json::from_slice(&claim_bytes).map_err(|_| refuse())?;
        let c = &may.commitments;
        if may.schema != 3
            || claim.schema != 3
            || claim.may_send_sha256 != terminal.may_send_sha256
            || claim.nonce != terminal.transaction_nonce
            || claim.stage != terminal.stage
            || c.binding.transaction_nonce != terminal.transaction_nonce
            || c.binding.stage != terminal.stage
            || !hex64(&c.binding.planned_generation)
            || !hex64(&c.binding.header_sha256)
            || c.mode != mode
            || c.boot_id != submitted.boot_id
            || c.pid1_socket != submitted.pid1_socket
            || c.pid1_netns != submitted.pid1_netns
            || c.installed_generation_sha256 != installed_generation_sha256
            || c.installed_manifest_sha256 != installed_manifest_sha256
            || c.policy_generation != policy_generation
            || c.native_guard != terminal.native_guard
            || c.private_unit != terminal.private_unit
            || c.fixed_unit != "aegis-client.service"
            || c.launch_ticket_sha256 != terminal.launch_ticket_sha256
        {
            return Err(refuse());
        }
        let launch: LaunchConsumed = serde_json::from_slice(launch_bytes).map_err(|_| refuse())?;
        if launch.schema != 1
            || launch.kind != "owned-launch-consumed"
            || digest(launch_bytes)
                != *terminal
                    .launch_consumed_sha256
                    .as_ref()
                    .ok_or_else(refuse)?
            || launch.completed_sha256 != terminal.completed_sha256
            || launch.ticket_sha256 != terminal.launch_ticket_sha256
            || launch.private_unit != terminal.private_unit
            || launch.invocation_id != completed.invocation_id
            || launch.main_pid <= 1
            || launch.main_start_tick == 0
            || launch.guardian_pid <= 1
            || !hex32(&launch.guardian_invocation_id)
            || terminal
                .native_guard
                .as_ref()
                .is_some_and(|guard| guard.guardian_pid != launch.guardian_pid)
        {
            return Err(refuse());
        }
        Ok(())
    }

    /// Historical positive Start proof for the postcohort inspector. It only
    /// reads Header-bound receipts; no owner scope or Stop capability is made.
    pub(in super::super) fn inspect_sealed_start(
        stage: &StageGuard,
    ) -> Result<(String, String, String)> {
        let store = &stage.store;
        store.revalidate()?;
        let header = &stage.header;
        let terminal_bytes = store.read(Path::new(ACTIVATION_OWNER_TERMINAL))?;
        let submitted_bytes = store.read(Path::new(ACTIVATION_OWNER_SUBMITTED))?;
        let completed_bytes = store.read(Path::new(ACTIVATION_OWNER_COMPLETED))?;
        let archive_bytes = store.read(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))?;
        let launch_bytes = store.read(Path::new(ACTIVATION_OWNER_LAUNCH_CONSUMED))?;
        let terminal: StartTerminal =
            serde_json::from_slice(&terminal_bytes).map_err(|_| refuse())?;
        let submitted: StartSubmitted =
            serde_json::from_slice(&submitted_bytes).map_err(|_| refuse())?;
        let completed: StartCompleted =
            serde_json::from_slice(&completed_bytes).map_err(|_| refuse())?;
        if terminal.schema != 1
            || !matches!(
                terminal.outcome.as_str(),
                "finalized" | "compensated-failure"
            )
            || terminal.transaction_nonce != header.transaction_nonce
            || terminal.stage != store.identity()?
            || header.leaves.get(Path::new(ACTIVATION_OWNER_TERMINAL))
                != Some(&digest(&terminal_bytes))
            || header.leaves.get(Path::new(ACTIVATION_OWNER_SUBMITTED))
                != Some(&digest(&submitted_bytes))
            || header.leaves.get(Path::new(ACTIVATION_OWNER_COMPLETED))
                != Some(&digest(&completed_bytes))
            || header
                .leaves
                .get(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))
                != Some(&digest(&archive_bytes))
            || header
                .leaves
                .get(Path::new(ACTIVATION_OWNER_LAUNCH_CONSUMED))
                != Some(&digest(&launch_bytes))
            || digest(&submitted_bytes) != terminal.submitted_sha256
            || digest(&completed_bytes) != terminal.completed_sha256
            || terminal.launch_consumed_sha256.as_deref() != Some(digest(&launch_bytes).as_str())
        {
            return Err(refuse());
        }
        let archive: OwnerMarkerArchive =
            serde_json::from_slice(&archive_bytes).map_err(|_| refuse())?;
        let may_bytes = hex::decode(&archive.may_send_hex).map_err(|_| refuse())?;
        let may: SealedMaySend = serde_json::from_slice(&may_bytes).map_err(|_| refuse())?;
        let commitments = &may.commitments;
        if header.leaves.get(Path::new(
            "accepted/install-receipt/installed-generation.json",
        )) != Some(&commitments.installed_generation_sha256)
            || header
                .leaves
                .get(Path::new("accepted/install-receipt/manifest.json"))
                != Some(&commitments.installed_manifest_sha256)
        {
            return Err(refuse());
        }
        validate_start_job_chain(&terminal, &submitted, &completed)?;
        validate_sealed_start(SealedStartSource {
            terminal: &terminal,
            mode: header.mode,
            archive_bytes: &archive_bytes,
            launch_bytes: &launch_bytes,
            submitted: &submitted,
            completed: &completed,
            installed_generation_sha256: &commitments.installed_generation_sha256,
            installed_manifest_sha256: &commitments.installed_manifest_sha256,
            policy_generation: &commitments.policy_generation,
        })?;
        Ok((
            commitments.installed_generation_sha256.clone(),
            commitments.installed_manifest_sha256.clone(),
            commitments.policy_generation.clone(),
        ))
    }

    /// Acquired before StageGuard or RootContext exists. This preserves the
    /// publication -> mutation -> stage-root order across a fresh worker.
    pub(in super::super) struct FreshStopPrelocks {
        store: Store,
        publication: PublicationLease,
        mutation: MutationGuard,
        stage_id: (u64, u64),
        activation_id: (u64, u64),
    }

    pub(in super::super) struct FreshStopFences {
        publication: PublicationLease,
        mutation: MutationGuard,
        stage_id: (u64, u64),
        activation_id: (u64, u64),
    }

    impl FreshStopPrelocks {
        pub(in super::super) fn acquire(store: Store, lock: &InstallLock) -> Result<Self> {
            lock.revalidate().map_err(|_| refuse())?;
            store.require_activation_root()?;
            if store.activation_leaf_present()?
                || !store.leaf_present(ACTIVATION_OWNER_TERMINAL)?
                || store.leaf_present(FINAL_STOP)?
                || store.leaf_present(ACTIVATION_OWNER_STOP_SUBMITTED)?
                || store.leaf_present(ACTIVATION_OWNER_STOP_COMPLETED)?
            {
                return Err(refuse());
            }
            let publication = store.publication_fence_held(libc::LOCK_EX)?;
            let mutation = store.mutation_guard()?;
            store.require_activation_root()?;
            if store.activation_leaf_present()?
                || !store.leaf_present(ACTIVATION_OWNER_TERMINAL)?
                || store.leaf_present(FINAL_STOP)?
                || store.leaf_present(ACTIVATION_OWNER_STOP_SUBMITTED)?
                || store.leaf_present(ACTIVATION_OWNER_STOP_COMPLETED)?
            {
                return Err(refuse());
            }
            let stage_id = store.identity()?;
            let activation = stat(store.activation_root.as_raw_fd())?;
            let activation_id = (activation.st_dev as u64, activation.st_ino as u64);
            if stage_id != activation_id || store.uid != 0 {
                return Err(refuse());
            }
            Ok(Self {
                store,
                publication,
                mutation,
                stage_id,
                activation_id,
            })
        }

        pub(in super::super) fn enter_read_scope(&self) -> Result<RestoreFreshStopReadScope> {
            if self.stage_id != self.activation_id {
                return Err(refuse());
            }
            self.store.enter_fresh_stop_read_scope(
                self.stage_id,
                self.publication._process.as_raw_fd(),
                self.mutation._process.as_raw_fd(),
            )
        }

        pub(in super::super) fn admit(self) -> Result<(StageGuard, FreshStopFences)> {
            let stage = StageGuard::admit(self.store)?;
            if stage.store.identity()? != self.stage_id {
                return Err(refuse());
            }
            Ok((
                stage,
                FreshStopFences {
                    publication: self.publication,
                    mutation: self.mutation,
                    stage_id: self.stage_id,
                    activation_id: self.activation_id,
                },
            ))
        }
    }

    /// This is an in-process authority, never deserialized or reconstructed
    /// from a terminal receipt. The original terminal records are evidence to
    /// bind a fresh installation lock and current installed source, not a
    /// replayable manager capability.
    pub(in super::super) struct FreshFinalizedStop<'c, 'r> {
        context: &'c RootContext<'r>,
        installed: &'c ProtectedInstalledFacts<'c, 'r>,
        lock: &'c InstallLock,
        publication: PublicationLease,
        mutation: MutationGuard,
        preclaim_read_scope: Option<RestoreFreshStopReadScope>,
        stage_id: (u64, u64),
        activation_id: (u64, u64),
        header_sha256: String,
        transaction_nonce: String,
        terminal_sha256: String,
        start_submitted_sha256: String,
        start_completed_sha256: String,
        start_job: (u32, String),
        start_boot_id: String,
        private_unit: String,
        start_netns: (u64, u64),
        start_invocation: String,
        mode: AutoMode,
        native_guard: Option<NativeGuard>,
        native_capture_sha256: Option<String>,
        installed_generation_sha256: String,
        installed_manifest_sha256: String,
        policy_generation: String,
        claimed_sha256: Option<String>,
        manager: Option<ManagerIdentity>,
        stop_submitted_sha256: Option<String>,
        stop_job: Option<(u32, String)>,
        stop_completed_sha256: Option<String>,
    }

    /// A borrowed, live source for the installed guardian's fresh inverse.
    /// No JSON constructor and no ownership transfer of the stage/lock exist.
    pub(crate) struct FinalizedGuardAnchor<'a, 'c, 'r> {
        owner: &'a FreshFinalizedStop<'c, 'r>,
    }

    impl FinalizedGuardAnchor<'_, '_, '_> {
        pub(crate) fn revalidate(&self) -> Result<()> {
            self.owner.revalidate_current(None)?;
            if self.owner.claimed_sha256.is_none()
                || self.owner.stop_submitted_sha256.is_none()
                || self.owner.stop_completed_sha256.is_none()
                || self.owner.native_guard.is_none()
            {
                return Err(refuse());
            }
            Ok(())
        }
        pub(crate) fn stage_identity(&self) -> (u64, u64) {
            self.owner.stage_id
        }
        pub(crate) fn mode(&self) -> &'static str {
            self.owner.mode.name()
        }
        pub(crate) fn unit(&self) -> &str {
            &self.owner.private_unit
        }
        pub(crate) fn stop_job_id(&self) -> u32 {
            self.owner.stop_job.as_ref().map_or(0, |j| j.0)
        }
        pub(crate) fn stop_job_path(&self) -> &str {
            self.owner.stop_job.as_ref().map_or("", |j| j.1.as_str())
        }
        pub(crate) fn terminal_sha256(&self) -> &str {
            &self.owner.terminal_sha256
        }
        pub(crate) fn prior_invocation_id(&self) -> &str {
            &self.owner.start_invocation
        }
        pub(crate) fn boot_id(&self) -> &str {
            &self.owner.start_boot_id
        }
        pub(crate) fn netns_ino(&self) -> u64 {
            self.owner.start_netns.1
        }
        pub(crate) fn installed_generation_sha256(&self) -> &str {
            &self.owner.installed_generation_sha256
        }
        pub(crate) fn installed_manifest_sha256(&self) -> &str {
            &self.owner.installed_manifest_sha256
        }
        pub(crate) fn policy_generation(&self) -> &str {
            &self.owner.policy_generation
        }
        pub(crate) fn original_guardian_pid(&self) -> u32 {
            self.owner
                .native_guard
                .as_ref()
                .map_or(0, |g| g.guardian_pid)
        }
        pub(crate) fn original_guardian_nonce(&self) -> &str {
            self.owner
                .native_guard
                .as_ref()
                .map_or("", |g| g.guardian_nonce.as_str())
        }
        pub(crate) fn original_guardian_receipt_sha256(&self) -> &str {
            self.owner
                .native_guard
                .as_ref()
                .map_or("", |g| g.guardian_receipt_sha256.as_str())
        }
        pub(crate) fn original_guardian_policy_sha256(&self) -> &str {
            self.owner
                .native_guard
                .as_ref()
                .map_or("", |g| g.policy_sha256.as_str())
        }
        pub(crate) fn native_capture_sha256(&self) -> &str {
            self.owner.native_capture_sha256.as_deref().unwrap_or("")
        }
        pub(crate) fn stop_intent_sha256(&self) -> &str {
            self.owner.claimed_sha256.as_deref().unwrap_or("")
        }
        pub(crate) fn stop_submitted_sha256(&self) -> &str {
            self.owner.stop_submitted_sha256.as_deref().unwrap_or("")
        }
        pub(crate) fn stop_completed_sha256(&self) -> &str {
            self.owner.stop_completed_sha256.as_deref().unwrap_or("")
        }
        pub(crate) fn duplicate_stage_fd(&self) -> Result<OwnedFd> {
            self.revalidate()?;
            self.owner.with_store(Store::duplicate_root)
        }
        pub(crate) fn duplicate_install_lock_fd(&self) -> Result<OwnedFd> {
            self.revalidate()?;
            self.owner.lock.duplicate_held_fd().map_err(|_| refuse())
        }
    }

    impl<'c, 'r> FreshFinalizedStop<'c, 'r> {
        pub(in super::super) fn guard_anchor(&self) -> Result<FinalizedGuardAnchor<'_, 'c, 'r>> {
            let anchor = FinalizedGuardAnchor { owner: self };
            anchor.revalidate()?;
            Ok(anchor)
        }

        pub(in super::super) fn bind(
            context: &'c RootContext<'r>,
            installed: &'c ProtectedInstalledFacts<'c, 'r>,
            lock: &'c InstallLock,
            fences: FreshStopFences,
            read_scope: RestoreFreshStopReadScope,
        ) -> Result<Self> {
            lock.revalidate().map_err(|_| refuse())?;
            context.admit_active_operation().map_err(|_| refuse())?;
            let current = installed.current()?;
            let installed_generation_sha256 = current.installed_generation_sha256.to_owned();
            let installed_manifest_sha256 = current.installed_manifest_sha256.to_owned();
            let policy_generation = current.policy_generation.to_owned();
            let stage = context.stage_cell().borrow();
            stage.revalidate_owner_pre_marker()?;
            let store = &stage.store;
            if store.activation_leaf_present()?
                || store.leaf_present(INTENT)?
                || store.leaf_present(FINAL_STOP)?
                || store.leaf_present(ACTIVATION_OWNER_STOP_SUBMITTED)?
                || store.leaf_present(ACTIVATION_OWNER_STOP_COMPLETED)?
            {
                return Err(refuse());
            }
            // Fences were acquired before StageGuard and RootContext. No new
            // process lock is acquired while the stage-root flock is held.
            store.require_activation_root()?;
            if store.activation_leaf_present()?
                || store.leaf_present(INTENT)?
                || store.leaf_present(FINAL_STOP)?
                || store.leaf_present(ACTIVATION_OWNER_STOP_SUBMITTED)?
                || store.leaf_present(ACTIVATION_OWNER_STOP_COMPLETED)?
            {
                return Err(refuse());
            }
            let header_bytes = store.read(Path::new("header.json"))?;
            let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| refuse())?;
            header.validate(store.uid)?;
            store.verify_payloads(&header)?;
            if header.phase != Phase::Finalized
                || header.pending.is_some()
                || header.unit_pending.is_some()
                || header.transaction_nonce != stage.header.transaction_nonce
                || header.leaves.get(Path::new(
                    "accepted/install-receipt/installed-generation.json",
                )) != Some(&installed_generation_sha256)
                || header
                    .leaves
                    .get(Path::new("accepted/install-receipt/manifest.json"))
                    != Some(&installed_manifest_sha256)
                || header
                    .leaves
                    .contains_key(Path::new(ACTIVATION_OWNER_STOP_SUBMITTED))
                || header
                    .leaves
                    .contains_key(Path::new(ACTIVATION_OWNER_STOP_COMPLETED))
            {
                return Err(refuse());
            }
            let stage_id = store.identity()?;
            let activation = stat(store.activation_root.as_raw_fd())?;
            let activation_id = (activation.st_dev as u64, activation.st_ino as u64);
            if activation_id != stage_id
                || stage_id != fences.stage_id
                || activation_id != fences.activation_id
                || Store::lock_identity(fences.publication._process.as_raw_fd(), store.uid)?
                    != store.publication_fence_identity.ok_or_else(refuse)?
                || Store::lock_identity(fences.mutation._process.as_raw_fd(), store.uid)?
                    != store.mutation_lock_identity.ok_or_else(refuse)?
            {
                return Err(refuse());
            }
            let terminal_bytes = store.read(Path::new(ACTIVATION_OWNER_TERMINAL))?;
            let terminal_sha256 = digest(&terminal_bytes);
            if header.leaves.get(Path::new(ACTIVATION_OWNER_TERMINAL)) != Some(&terminal_sha256) {
                return Err(refuse());
            }
            let terminal: StartTerminal =
                serde_json::from_slice(&terminal_bytes).map_err(|_| refuse())?;
            if terminal.schema != 1
                || terminal.outcome != "finalized"
                || terminal.transaction_nonce != header.transaction_nonce
                || terminal.stage != stage_id
                || terminal.stop_submitted_sha256.is_some()
                || terminal.stop_completed_sha256.is_some()
                || terminal.native_inverse_sha256.is_some()
                || terminal.post_deny_policy_sha256.is_some()
                || !terminal
                    .private_unit
                    .strip_prefix("aegis-auto@")
                    .and_then(|name| name.strip_suffix(".service"))
                    .is_some_and(hex64)
                || !hex64(&terminal.may_send_sha256)
                || !hex64(&terminal.claim_sha256)
                || !hex64(&terminal.marker_archive_sha256)
                || !terminal
                    .launch_consumed_sha256
                    .as_deref()
                    .is_some_and(hex64)
                || !hex64(&terminal.launch_ticket_sha256)
            {
                return Err(refuse());
            }
            match header.mode {
                AutoMode::SocksOnly
                    if terminal.native_guard.is_some()
                        || terminal.native_capture_sha256.is_some() =>
                {
                    return Err(refuse())
                }
                AutoMode::WideRedirectSafe | AutoMode::FullWideTun
                    if terminal.native_guard.is_none()
                        || !terminal.native_capture_sha256.as_deref().is_some_and(hex64) =>
                {
                    return Err(refuse())
                }
                _ => {}
            }
            if let Some(guard) = &terminal.native_guard {
                if guard.guardian_pid <= 1
                    || !hex64(&guard.guardian_nonce)
                    || !hex64(&guard.guardian_receipt_sha256)
                    || !hex64(&guard.policy_sha256)
                {
                    return Err(refuse());
                }
            }
            let submitted_bytes = store.read(Path::new(ACTIVATION_OWNER_SUBMITTED))?;
            let completed_bytes = store.read(Path::new(ACTIVATION_OWNER_COMPLETED))?;
            let archive_bytes = store.read(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))?;
            let launch_bytes = store.read(Path::new(ACTIVATION_OWNER_LAUNCH_CONSUMED))?;
            if digest(&submitted_bytes) != terminal.submitted_sha256
                || digest(&completed_bytes) != terminal.completed_sha256
                || digest(&archive_bytes) != terminal.marker_archive_sha256
                || digest(&launch_bytes)
                    != *terminal
                        .launch_consumed_sha256
                        .as_ref()
                        .ok_or_else(refuse)?
                || header.leaves.get(Path::new(ACTIVATION_OWNER_SUBMITTED))
                    != Some(&terminal.submitted_sha256)
                || header.leaves.get(Path::new(ACTIVATION_OWNER_COMPLETED))
                    != Some(&terminal.completed_sha256)
                || header
                    .leaves
                    .get(Path::new(ACTIVATION_OWNER_MARKER_ARCHIVE))
                    != Some(&terminal.marker_archive_sha256)
                || header
                    .leaves
                    .get(Path::new(ACTIVATION_OWNER_LAUNCH_CONSUMED))
                    != terminal.launch_consumed_sha256.as_ref()
            {
                return Err(refuse());
            }
            let submitted: StartSubmitted =
                serde_json::from_slice(&submitted_bytes).map_err(|_| refuse())?;
            let completed: StartCompleted =
                serde_json::from_slice(&completed_bytes).map_err(|_| refuse())?;
            validate_start_job_chain(&terminal, &submitted, &completed)?;
            validate_sealed_start(SealedStartSource {
                terminal: &terminal,
                mode: header.mode,
                archive_bytes: &archive_bytes,
                launch_bytes: &launch_bytes,
                submitted: &submitted,
                completed: &completed,
                installed_generation_sha256: &installed_generation_sha256,
                installed_manifest_sha256: &installed_manifest_sha256,
                policy_generation: &policy_generation,
            })?;
            let result = Self {
                context,
                installed,
                lock,
                publication: fences.publication,
                mutation: fences.mutation,
                preclaim_read_scope: Some(read_scope),
                stage_id,
                activation_id,
                header_sha256: digest(&header_bytes),
                transaction_nonce: header.transaction_nonce,
                terminal_sha256,
                start_submitted_sha256: terminal.submitted_sha256,
                start_completed_sha256: terminal.completed_sha256,
                start_job: (submitted.job_id, submitted.job_path),
                start_boot_id: submitted.boot_id,
                private_unit: terminal.private_unit,
                start_netns: submitted.pid1_netns,
                start_invocation: completed.invocation_id,
                mode: header.mode,
                native_guard: terminal.native_guard,
                native_capture_sha256: terminal.native_capture_sha256,
                installed_generation_sha256,
                installed_manifest_sha256,
                policy_generation,
                claimed_sha256: None,
                manager: None,
                stop_submitted_sha256: None,
                stop_job: None,
                stop_completed_sha256: None,
            };
            result.revalidate_current(None)?;
            Ok(result)
        }

        fn with_store<T>(&self, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
            let stage = self.context.stage_cell().borrow();
            let store = &stage.store;
            self.lock.revalidate().map_err(|_| refuse())?;
            store.require_activation_root()?;
            if store.identity()? != self.stage_id
                || store.uid != 0
                || {
                    let s = stat(store.activation_root.as_raw_fd())?;
                    (s.st_dev as u64, s.st_ino as u64) != self.activation_id
                }
                || Store::lock_identity(self.publication._process.as_raw_fd(), store.uid)?
                    != store.publication_fence_identity.ok_or_else(refuse)?
                || Store::lock_identity(self.mutation._process.as_raw_fd(), store.uid)?
                    != store.mutation_lock_identity.ok_or_else(refuse)?
            {
                return Err(refuse());
            }
            f(store)
        }

        fn revalidate_current(&self, manager: Option<&ManagerIdentity>) -> Result<()> {
            let verify_installed = || -> Result<()> {
                let current = self.installed.current()?;
                if current.installed_generation_sha256 != self.installed_generation_sha256
                    || current.installed_manifest_sha256 != self.installed_manifest_sha256
                    || current.policy_generation != self.policy_generation
                {
                    return Err(refuse());
                }
                Ok(())
            };
            if self.claimed_sha256.is_some() {
                self.with_marker_scope(verify_installed)?;
            } else {
                verify_installed()?;
            }
            self.with_store(|store| {
                let header = store.load_header()?;
                if header.phase != Phase::Finalized
                    || header.pending.is_some()
                    || header.unit_pending.is_some()
                    || header.transaction_nonce != self.transaction_nonce
                    || header.leaves.get(Path::new(ACTIVATION_OWNER_TERMINAL))
                        != Some(&self.terminal_sha256)
                    || header.leaves.get(Path::new(ACTIVATION_OWNER_SUBMITTED))
                        != Some(&self.start_submitted_sha256)
                    || header.leaves.get(Path::new(ACTIVATION_OWNER_COMPLETED))
                        != Some(&self.start_completed_sha256)
                    || digest(&store.read(Path::new(ACTIVATION_OWNER_TERMINAL))?)
                        != self.terminal_sha256
                    || digest(&store.read(Path::new("header.json"))?) != self.header_sha256
                    || store.leaf_present(FINAL_STOP)?
                {
                    return Err(refuse());
                }
                let intent = store.leaf_present(INTENT)?;
                match &self.claimed_sha256 {
                    Some(sha) if !intent || digest(&store.read(Path::new(INTENT))?) != *sha => {
                        return Err(refuse());
                    }
                    None if intent => return Err(refuse()),
                    _ => {}
                }
                store.verify_payloads(&header)
            })?;
            if let Some(manager) = manager {
                if manager.boot_id() != self.start_boot_id
                    || manager.netns_identity() != self.start_netns
                    || manager.socket_identity().0 == 0
                    || manager.socket_identity().1 == 0
                {
                    return Err(refuse());
                }
                if let Some(original) = &self.manager {
                    if original != manager {
                        return Err(refuse());
                    }
                }
            }
            Ok(())
        }

        fn with_marker_scope<T>(&self, effect: impl FnOnce() -> Result<T>) -> Result<T> {
            let sha = self.claimed_sha256.as_ref().ok_or_else(refuse)?;
            let reset = self.with_store(|store| {
                let scope = OwnerScope {
                    activation_id: self.activation_id,
                    stage_id: self.stage_id,
                    stage_path: store.path.clone(),
                    marker: Some(OwnerScopeMarker {
                        may_send_sha256: sha.clone(),
                        claim_sha256: sha.clone(),
                        may_send_leaf: INTENT,
                        claim_leaf: INTENT,
                    }),
                    inverse_after_terminal: false,
                    publication_fd: self.publication._process.as_raw_fd(),
                    mutation_fd: self.mutation._process.as_raw_fd(),
                };
                store.verify_owner_scope(&scope)?;
                CURRENT_OWNER.with(|current| {
                    let mut current = current.borrow_mut();
                    if current.is_some() {
                        return Err(refuse());
                    }
                    *current = Some(scope);
                    Ok(())
                })?;
                Ok(RestoreOwnerScope)
            })?;
            let result = effect();
            drop(reset);
            result
        }

        fn with_owned_effect<T>(&self, effect: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
            self.revalidate_current(None)?;
            self.with_marker_scope(|| self.with_store(effect))
        }

        fn admit_job(&self, job: &SubmittedJob) -> Result<()> {
            let manager = self.manager.as_ref().ok_or_else(refuse)?;
            if job.id() == 0
                || job.unit() != self.private_unit
                || job.path() != format!("/org/freedesktop/systemd1/job/{}", job.id())
                || job.manager() != manager
                || self.start_job == (job.id(), job.path().to_owned())
            {
                return Err(refuse());
            }
            Ok(())
        }

        fn write_stop_receipt(&self, leaf: &str, bytes: &[u8]) -> Result<String> {
            self.with_owned_effect(|store| {
                store.write_new_sticky_unchecked(Path::new(leaf), bytes)?;
                if store.read(Path::new(leaf))?.as_slice() != bytes {
                    return Err(refuse());
                }
                Ok(())
            })?;
            Ok(digest(bytes))
        }

        /// Only SOCKS has no native capture inverse. The typed CompletedStop
        /// came from this exact verified PID1 connection and both job receipts
        /// were durably written before this terminal transition.
        pub(in super::super) fn finish_socks(&self, completed: &CompletedStop) -> Result<()> {
            if self.mode != AutoMode::SocksOnly || self.native_guard.is_some() {
                return Err(refuse());
            }
            self.finish_common(completed, None, None, None)
        }

        pub(in super::super) fn finish_wide(
            &self,
            completed: &CompletedStop,
            inverse: &mut crate::profile_auto_guardian::CompletedCaptureInverse,
        ) -> Result<()> {
            let original = self.native_guard.as_ref().ok_or_else(refuse)?;
            if !matches!(
                self.mode,
                AutoMode::WideRedirectSafe | AutoMode::FullWideTun
            ) || inverse.prior_invocation_id() != self.start_invocation
                || inverse.stage_identity() != self.stage_id
                || inverse.boot_id() != self.start_boot_id
                || inverse.netns_ino() != self.start_netns.1
                || inverse.stop_job_id() != completed.facts().0.id()
                || inverse.stop_job_path() != completed.facts().0.path()
                || inverse.stop_unit() != self.private_unit
                || completed.facts().0.unit() != self.private_unit
                || inverse.guardian_nonce() != original.guardian_nonce
                || !hex64(inverse.post_deny_policy_sha256())
                || !hex64(inverse.native_inverse_sha256())
            {
                return Err(refuse());
            }
            let native_inverse = inverse.native_inverse_sha256().to_owned();
            let post_deny_policy = inverse.post_deny_policy_sha256().to_owned();
            self.finish_common(
                completed,
                Some(&native_inverse),
                Some(&post_deny_policy),
                Some(inverse),
            )
        }

        fn finish_common(
            &self,
            completed: &CompletedStop,
            native_inverse: Option<&str>,
            post_deny_policy: Option<&str>,
            mut inverse: Option<&mut crate::profile_auto_guardian::CompletedCaptureInverse>,
        ) -> Result<()> {
            let (job, prior_invocation) = completed.facts();
            self.admit_job(job)?;
            self.revalidate_current(Some(job.manager()))?;
            if self.stop_job.as_ref() != Some(&(job.id(), job.path().to_owned()))
                || prior_invocation != self.start_invocation
                || self.claimed_sha256.is_none()
                || self.stop_submitted_sha256.is_none()
                || self.stop_completed_sha256.is_none()
                || (self.mode == AutoMode::SocksOnly) != native_inverse.is_none()
                || native_inverse.is_some() != post_deny_policy.is_some()
                || native_inverse.is_some() != inverse.is_some()
            {
                return Err(refuse());
            }
            let terminal = serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "outcome": "finalized-stopped",
                "transaction_nonce": self.transaction_nonce,
                "private_unit": self.private_unit,
                "stage": self.stage_id,
                "start_terminal_sha256": self.terminal_sha256,
                "start_submitted_sha256": self.start_submitted_sha256,
                "start_completed_sha256": self.start_completed_sha256,
                "stop_intent_sha256": self.claimed_sha256,
                "stop_submitted_sha256": self.stop_submitted_sha256,
                "stop_completed_sha256": self.stop_completed_sha256,
                "prior_invocation_id": self.start_invocation,
                "boot_id": self.start_boot_id,
                "installed_generation_sha256": self.installed_generation_sha256,
                "installed_manifest_sha256": self.installed_manifest_sha256,
                "policy_generation": self.policy_generation,
                "native_inverse_sha256": native_inverse,
                "post_deny_policy_sha256": post_deny_policy,
            }))
            .map_err(|_| refuse())?;
            if let Some(proof) = inverse.as_deref_mut() {
                proof.revalidate().map_err(|_| refuse())?;
            }
            self.with_owned_effect(|store| {
                for (leaf, expected) in [
                    (
                        ACTIVATION_OWNER_STOP_SUBMITTED,
                        self.stop_submitted_sha256.as_ref(),
                    ),
                    (
                        ACTIVATION_OWNER_STOP_COMPLETED,
                        self.stop_completed_sha256.as_ref(),
                    ),
                ] {
                    if digest(&store.read(Path::new(leaf))?) != *expected.ok_or_else(refuse)? {
                        return Err(refuse());
                    }
                }
                store.write_new_sticky_unchecked(Path::new(FINAL_STOP), &terminal)?;
                if store.read(Path::new(FINAL_STOP))?.as_slice() != terminal {
                    return Err(refuse());
                }
                let mut header = store.load_header()?;
                if header.phase != Phase::Finalized
                    || header.pending.is_some()
                    || header.unit_pending.is_some()
                {
                    return Err(refuse());
                }
                header.leaves.insert(
                    PathBuf::from(ACTIVATION_OWNER_STOP_SUBMITTED),
                    self.stop_submitted_sha256.clone().ok_or_else(refuse)?,
                );
                header.leaves.insert(
                    PathBuf::from(ACTIVATION_OWNER_STOP_COMPLETED),
                    self.stop_completed_sha256.clone().ok_or_else(refuse)?,
                );
                header
                    .leaves
                    .insert(PathBuf::from(FINAL_STOP), digest(&terminal));
                store.save_header(&header)?;
                store.verify_payloads(&store.load_header()?)
            })?;
            if let Some(proof) = inverse {
                proof.complete_effect().map_err(|_| refuse())?;
            }
            // Keep the recovery-only leaf until every terminal byte and its
            // Header binding has been synced and read back. A failed unlink is
            // recovery-only, never a success or another StopUnit grant.
            self.with_store(|store| {
                let header = store.load_header()?;
                store.verify_payloads(&header)?;
                if header.leaves.get(Path::new(FINAL_STOP)) != Some(&digest(&terminal))
                    || digest(&store.read(Path::new(INTENT))?)
                        != *self.claimed_sha256.as_ref().ok_or_else(refuse)?
                {
                    return Err(refuse());
                }
                let (parent, name) = store.parent(Path::new(INTENT), false)?;
                if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0
                    || unsafe { libc::fsync(parent.as_raw_fd()) } != 0
                    || store.activation_leaf_present()?
                {
                    return Err(refuse());
                }
                self.lock.revalidate().map_err(|_| refuse())
            })
        }
    }

    impl FinalizedStopAuthority for FreshFinalizedStop<'_, '_> {
        fn unit(&self) -> &str {
            &self.private_unit
        }

        fn admit_current(
            &self,
            manager: &ManagerIdentity,
            invocation: &str,
        ) -> std::result::Result<(), &'static str> {
            if invocation != self.start_invocation
                || self.claimed_sha256.is_some()
                || self.revalidate_current(Some(manager)).is_err()
            {
                Err("AUTO finalized stop requires native recovery")
            } else {
                Ok(())
            }
        }

        fn claim_before_send(
            &mut self,
            manager: &ManagerIdentity,
            invocation: &str,
        ) -> std::result::Result<(), &'static str> {
            self.admit_current(manager, invocation)?;
            // All pre-claim reads are complete. The following sticky INTENT
            // is a typed writer operation under the same retained fences.
            self.preclaim_read_scope.take();
            let nonce: [u8; 16] = rand::random();
            let bytes = serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "kind": "owned-finalized-stop-intent",
                "nonce": hex::encode(nonce),
                "transaction_nonce": self.transaction_nonce,
                "private_unit": self.private_unit,
                "stage": self.stage_id,
                "header_sha256": self.header_sha256,
                "terminal_sha256": self.terminal_sha256,
                "start_completed_sha256": self.start_completed_sha256,
                "invocation_id": invocation,
                "boot_id": manager.boot_id(),
                "pid1_socket": manager.socket_identity(),
                "pid1_netns": manager.netns_identity(),
                "pid1_namespaces": manager.namespace_identities(),
                "pid1_root": manager.root_identity(),
                "installed_generation_sha256": self.installed_generation_sha256,
                "installed_manifest_sha256": self.installed_manifest_sha256,
                "policy_generation": self.policy_generation,
            }))
            .map_err(|_| "AUTO finalized stop requires native recovery")?;
            self.with_store(|store| {
                store.write_new_sticky_unchecked(Path::new(INTENT), &bytes)?;
                if store.read(Path::new(INTENT))?.as_slice() != bytes {
                    return Err(refuse());
                }
                Ok(())
            })
            .map_err(|_| "AUTO finalized stop requires native recovery")?;
            self.claimed_sha256 = Some(digest(&bytes));
            self.manager = Some(manager.clone());
            self.revalidate_current(Some(manager))
                .map_err(|_| "AUTO finalized stop requires native recovery")
        }

        fn record_stop_submitted(
            &mut self,
            job: &SubmittedJob,
        ) -> std::result::Result<(), &'static str> {
            if self.stop_submitted_sha256.is_some() || self.admit_job(job).is_err() {
                return Err("AUTO finalized stop requires native recovery");
            }
            let bytes = serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "kind": "owned-finalized-stop-submitted",
                "intent_sha256": self.claimed_sha256,
                "completed_start_sha256": self.start_completed_sha256,
                "job_id": job.id(),
                "job_path": job.path(),
                "unit": job.unit(),
                "boot_id": job.manager().boot_id(),
                "pid1_socket": job.manager().socket_identity(),
                "pid1_netns": job.manager().netns_identity(),
            }))
            .map_err(|_| "AUTO finalized stop requires native recovery")?;
            let sha = self
                .write_stop_receipt(ACTIVATION_OWNER_STOP_SUBMITTED, &bytes)
                .map_err(|_| "AUTO finalized stop requires native recovery")?;
            self.stop_submitted_sha256 = Some(sha);
            self.stop_job = Some((job.id(), job.path().to_owned()));
            Ok(())
        }

        fn record_stop_completed(
            &mut self,
            completed: &CompletedStop,
        ) -> std::result::Result<(), &'static str> {
            let (job, prior_invocation) = completed.facts();
            if self.stop_completed_sha256.is_some()
                || self.admit_job(job).is_err()
                || self.stop_job.as_ref() != Some(&(job.id(), job.path().to_owned()))
                || prior_invocation != self.start_invocation
            {
                return Err("AUTO finalized stop requires native recovery");
            }
            let submitted_sha256 = self
                .stop_submitted_sha256
                .as_ref()
                .ok_or("AUTO finalized stop requires native recovery")?;
            let bytes = serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "kind": "owned-finalized-stop-completed",
                "intent_sha256": self.claimed_sha256,
                "stop_submitted_sha256": submitted_sha256,
                "job_id": job.id(),
                "job_path": job.path(),
                "unit": job.unit(),
                "prior_invocation_id": prior_invocation,
            }))
            .map_err(|_| "AUTO finalized stop requires native recovery")?;
            let sha = self
                .write_stop_receipt(ACTIVATION_OWNER_STOP_COMPLETED, &bytes)
                .map_err(|_| "AUTO finalized stop requires native recovery")?;
            self.stop_completed_sha256 = Some(sha);
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn finalized_stop_rejects_mixed_or_public_start_job_receipts() {
            let unit = format!("aegis-auto@{}.service", "a".repeat(64));
            let terminal = StartTerminal {
                schema: 1,
                outcome: "finalized".into(),
                transaction_nonce: "b".repeat(32),
                stage: (1, 2),
                private_unit: unit.clone(),
                may_send_sha256: "c".repeat(64),
                claim_sha256: "d".repeat(64),
                marker_archive_sha256: "0".repeat(64),
                submitted_sha256: "e".repeat(64),
                completed_sha256: "f".repeat(64),
                launch_consumed_sha256: Some("1".repeat(64)),
                launch_ticket_sha256: "2".repeat(64),
                stop_submitted_sha256: None,
                stop_completed_sha256: None,
                native_guard: None,
                native_capture_sha256: None,
                native_inverse_sha256: None,
                post_deny_policy_sha256: None,
            };
            let mut submitted = StartSubmitted {
                schema: 1,
                kind: "owned-start-submitted".into(),
                may_send_sha256: terminal.may_send_sha256.clone(),
                claim_sha256: terminal.claim_sha256.clone(),
                job_id: 17,
                job_path: "/org/freedesktop/systemd1/job/17".into(),
                unit: unit.clone(),
                boot_id: "00000000-0000-0000-0000-000000000001".into(),
                pid1_socket: (3, 4),
                pid1_netns: (5, 6),
            };
            let mut completed = StartCompleted {
                schema: 1,
                kind: "owned-start-completed".into(),
                submitted_sha256: terminal.submitted_sha256.clone(),
                job_id: 17,
                job_path: submitted.job_path.clone(),
                unit,
                invocation_id: "1".repeat(32),
            };
            assert!(validate_start_job_chain(&terminal, &submitted, &completed).is_ok());
            completed.job_id = 18;
            assert!(validate_start_job_chain(&terminal, &submitted, &completed).is_err());
            completed.job_id = 17;
            submitted.unit = "aegis-client.service".into();
            assert!(validate_start_job_chain(&terminal, &submitted, &completed).is_err());
        }

        #[test]
        fn finalized_stop_requires_sealed_marker_and_launch_chain() {
            let unit = format!("aegis-auto@{}.service", "a".repeat(64));
            let stage = (1, 2);
            let nonce = "b".repeat(32);
            let ticket = "c".repeat(64);
            let completed_sha = "d".repeat(64);
            let boot = "00000000-0000-0000-0000-000000000001";
            let submitted = StartSubmitted {
                schema: 1,
                kind: "owned-start-submitted".into(),
                may_send_sha256: String::new(),
                claim_sha256: String::new(),
                job_id: 17,
                job_path: "/org/freedesktop/systemd1/job/17".into(),
                unit: unit.clone(),
                boot_id: boot.into(),
                pid1_socket: (3, 4),
                pid1_netns: (5, 6),
            };
            let completed = StartCompleted {
                schema: 1,
                kind: "owned-start-completed".into(),
                submitted_sha256: "e".repeat(64),
                job_id: 17,
                job_path: submitted.job_path.clone(),
                unit: unit.clone(),
                invocation_id: "f".repeat(32),
            };
            let may = serde_json::to_vec(&serde_json::json!({
                "schema": 3,
                "commitments": {
                    "binding": {"transaction_nonce": nonce, "planned_generation": "0".repeat(64),
                        "stage": stage, "header_sha256": "1".repeat(64)},
                    "mode": AutoMode::SocksOnly,
                    "boot_id": boot, "pid1_socket": submitted.pid1_socket,
                    "pid1_netns": submitted.pid1_netns,
                    "installed_generation_sha256": "2".repeat(64),
                    "installed_manifest_sha256": "3".repeat(64),
                    "policy_generation": "4".repeat(64),
                    "native_guard": null, "private_unit": unit,
                    "fixed_unit": "aegis-client.service", "launch_ticket_sha256": ticket,
                }
            }))
            .unwrap();
            let may_sha = digest(&may);
            let claim = serde_json::to_vec(&serde_json::json!({
                "schema": 3, "may_send_sha256": may_sha, "nonce": nonce, "stage": stage,
            }))
            .unwrap();
            let claim_sha = digest(&claim);
            let archive = serde_json::to_vec(&OwnerMarkerArchive {
                schema: 1,
                may_send_hex: hex::encode(&may),
                claim_hex: hex::encode(&claim),
                may_send_sha256: may_sha.clone(),
                claim_sha256: claim_sha.clone(),
            })
            .unwrap();
            let launch = serde_json::to_vec(&serde_json::json!({
                "schema": 1, "kind": "owned-launch-consumed",
                "completed_sha256": completed_sha, "ticket_sha256": ticket,
                "private_unit": unit, "invocation_id": completed.invocation_id,
                "main_pid": 123, "main_start_tick": 456,
                "guardian_pid": 789, "guardian_invocation_id": "0".repeat(32),
            }))
            .unwrap();
            let mut terminal = StartTerminal {
                schema: 1,
                outcome: "finalized".into(),
                transaction_nonce: nonce,
                stage,
                private_unit: unit,
                may_send_sha256: may_sha,
                claim_sha256: claim_sha,
                marker_archive_sha256: digest(&archive),
                submitted_sha256: "e".repeat(64),
                completed_sha256: completed_sha,
                launch_consumed_sha256: Some(digest(&launch)),
                launch_ticket_sha256: ticket.clone(),
                stop_submitted_sha256: None,
                stop_completed_sha256: None,
                native_guard: None,
                native_capture_sha256: None,
                native_inverse_sha256: None,
                post_deny_policy_sha256: None,
            };
            let check = |terminal: &StartTerminal, archive: &[u8], launch: &[u8]| {
                validate_sealed_start(SealedStartSource {
                    terminal,
                    mode: AutoMode::SocksOnly,
                    archive_bytes: archive,
                    launch_bytes: launch,
                    submitted: &submitted,
                    completed: &completed,
                    installed_generation_sha256: &"2".repeat(64),
                    installed_manifest_sha256: &"3".repeat(64),
                    policy_generation: &"4".repeat(64),
                })
            };
            assert!(check(&terminal, &archive, &launch).is_ok());
            terminal.launch_ticket_sha256 = "5".repeat(64);
            assert!(check(&terminal, &archive, &launch).is_err());
            terminal.launch_ticket_sha256 = ticket;
            let mut changed_archive = archive.clone();
            changed_archive.push(b' ');
            assert!(check(&terminal, &changed_archive, &launch).is_err());
        }
    }
}
