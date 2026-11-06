//! The original AUTO worker owns this activation session until a terminal
//! receipt. A JSON request can select a phase, but cannot reconstruct the
//! held stage, installation, manager, or native guardian authority.

use super::{fail, finalize_owned_projection, preflight_owned_projection, PreparedRender, Result};
use crate::profile_auto_guardian::{
    CaptureReady, GuardDenyLease, GuardianBinding, GuardianRefusal,
};
use crate::profile_auto_launch_service::{LaunchBinding, LaunchOwnerLease, LaunchProof};
use crate::profile_auto_stopped_service::{pid1, InstallLock};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};

use super::super::{
    durable::{OwnerContinuation, OwnerProductCommitments, Store},
    owner_installed::ProtectedInstalledFacts,
    store_context::RootContext,
    v2_state_reader::PublishedState,
    AutoMode, Phase,
};

const RECOVERY: &str = super::ACTIVATION_RECOVERY_REQUIRED;

fn capture_failure(error: GuardianRefusal) -> String {
    match error.capture_coordinate() {
        Some((reason, source, line)) => {
            format!("{}{reason}:{source}:{line}", super::CAPTURE_FAILURE_PREFIX)
        }
        None => fail(error),
    }
}

pub(super) fn private_unit_name(unit: &str) -> bool {
    unit.strip_prefix("aegis-auto@")
        .and_then(|value| value.strip_suffix(".service"))
        .is_some_and(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

pub(super) struct Session<'a> {
    owner: OwnerContinuation,
    context: RootContext<'a>,
    rendered: PreparedRender,
    started: pid1::OwnedStart,
    launch: Option<LaunchProof>,
    guardian: Option<GuardDenyLease>,
    capture: Option<CaptureReady>,
    terminal_private_unit: String,
}

fn terminal_register(operation: &str, unit: &str, extra: &[&str]) -> Result<()> {
    if !matches!(
        operation,
        "configure" | "recover-incomplete" | "prepare" | "activate" | "commit" | "cleanup"
    ) || !private_unit_name(unit)
        || (operation == "commit") != (extra.len() == 3)
    {
        return Err(super::super::refuse());
    }
    let result = Command::new("/usr/bin/timeout")
        .args([
            "-k",
            "1s",
            "45s",
            "/usr/bin/python3",
            "-I",
            "-B",
            "/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_register.py",
            operation,
            unit,
        ])
        .args(extra)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(fail)?;
    if !result.success() {
        return Err(super::super::refuse());
    }
    Ok(())
}

fn native_anchor() -> Result<(String, u64)> {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(fail)?;
    let boot = boot.trim();
    if boot.len() != 36 || !boot.is_ascii() {
        return Err(super::super::refuse());
    }
    let netns = std::fs::metadata("/proc/1/ns/net").map_err(fail)?;
    if netns.ino() == 0 {
        return Err(super::super::refuse());
    }
    Ok((boot.to_owned(), netns.ino()))
}

fn mode_name(mode: AutoMode) -> &'static str {
    match mode {
        AutoMode::SocksOnly => "socks-only",
        AutoMode::WideRedirectSafe => "wide-redirect-safe",
        AutoMode::FullWideTun => "full-wide-tun",
    }
}

struct StartAdapter<'a, 'c, 'r> {
    owner: &'a mut OwnerContinuation,
    installed: &'a ProtectedInstalledFacts<'c, 'r>,
    lock: &'a InstallLock,
    guardian: Option<&'a GuardDenyLease>,
    launch: &'a LaunchOwnerLease,
    mode: AutoMode,
    boot: &'a str,
    netns: u64,
    manager: pid1::ManagerIdentity,
    private_unit: String,
}

impl pid1::StartAuthority for StartAdapter<'_, '_, '_> {
    fn requires_terminal_host_source_proof(&self) -> bool {
        self.mode != AutoMode::SocksOnly
    }

    fn admit_pre_marker(
        &self,
        manager: &pid1::ManagerIdentity,
        unit: &pid1::PrivateUnit,
    ) -> std::result::Result<(), &'static str> {
        if manager != &self.manager
            || manager.boot_id() != self.boot
            || manager.netns_identity().1 != self.netns
            || unit.name() != self.private_unit
            || !private_unit_name(unit.name())
        {
            return Err("AUTO PID1 host identity changed");
        }
        self.owner
            .binding(self.lock)
            .map_err(|_| "AUTO original stage owner changed")?;
        self.owner
            .with_pre_marker_effect(self.lock, || self.installed.current().map(|_| ()))
            .map_err(|_| "AUTO installed source changed")?;
        if let Some(guardian) = self.guardian {
            guardian
                .revalidate()
                .map_err(|_| "AUTO native deny lease changed")?;
            if guardian.boot_id() != manager.boot_id()
                || guardian.netns_ino() != manager.netns_identity().1
            {
                return Err("AUTO native deny manager binding changed");
            }
        } else if self.mode != AutoMode::SocksOnly {
            return Err("AUTO wide mode lacks native deny lease");
        }
        self.launch
            .revalidate()
            .map_err(|_| "AUTO launch lease changed")?;
        Ok(())
    }

    fn claim_may_send(
        &mut self,
        manager: &pid1::ManagerIdentity,
        unit: &pid1::PrivateUnit,
    ) -> std::result::Result<(), &'static str> {
        self.admit_pre_marker(manager, unit)?;
        let binding = self
            .owner
            .binding(self.lock)
            .map_err(|_| "AUTO original stage owner changed")?;
        let commitments = self
            .owner
            .with_pre_marker_effect(self.lock, || {
                if let Some(guardian) = self.guardian {
                    OwnerProductCommitments::from_wide_verified(
                        binding,
                        manager,
                        unit,
                        self.installed,
                        self.launch,
                        guardian,
                        self.mode,
                    )
                } else {
                    OwnerProductCommitments::from_socks_verified(
                        binding,
                        manager,
                        unit,
                        self.installed,
                        self.launch,
                    )
                }
            })
            .map_err(|_| "AUTO product commitment refused")?;
        self.owner
            .claim_product_once(self.lock, commitments, self.installed)
            .map_err(|_| "AUTO one-use activation marker requires recovery")
    }

    fn admit_post_marker(
        &self,
        manager: &pid1::ManagerIdentity,
        unit: &pid1::PrivateUnit,
    ) -> std::result::Result<(), &'static str> {
        if manager != &self.manager
            || manager.boot_id() != self.boot
            || manager.netns_identity().1 != self.netns
            || unit.name() != self.private_unit
        {
            return Err("AUTO PID1 identity changed after marker");
        }
        if let Some(guardian) = self.guardian {
            guardian
                .revalidate()
                .map_err(|_| "AUTO native deny lease changed after marker")?;
        }
        self.launch
            .revalidate()
            .map_err(|_| "AUTO launch lease changed after marker")?;
        let outcome = self
            .owner
            .with_owned_effect(self.lock, || self.installed.current().map(|_| ()))
            .map_err(|_| "AUTO installed source changed after marker");
        outcome
    }

    fn record_submitted(
        &mut self,
        job: &pid1::SubmittedJob,
    ) -> std::result::Result<(), &'static str> {
        self.owner
            .record_submitted(self.lock, job)
            .map_err(|_| "AUTO submitted job receipt requires recovery")
    }

    fn record_completed(
        &mut self,
        job: &pid1::CompletedStart,
    ) -> std::result::Result<(), &'static str> {
        self.owner
            .record_completed(self.lock, job)
            .map_err(|_| "AUTO completed job receipt requires recovery")
    }
}

struct StopAdapter<'a, 'r> {
    owner: &'a mut OwnerContinuation,
    context: &'a RootContext<'r>,
    lock: &'a InstallLock,
    guardian: Option<&'a GuardDenyLease>,
}

impl pid1::StopAuthority for StopAdapter<'_, '_> {
    fn admit_compensation(
        &self,
        completed: &pid1::CompletedStart,
    ) -> std::result::Result<(), &'static str> {
        let (job, _) = completed.facts();
        if !private_unit_name(job.unit()) {
            return Err("AUTO stop job no longer owns private unit");
        }
        if let Some(guardian) = self.guardian {
            guardian
                .revalidate()
                .map_err(|_| "AUTO deny changed before compensation")?;
            if guardian.boot_id() != job.manager().boot_id()
                || guardian.netns_ino() != job.manager().netns_identity().1
            {
                return Err("AUTO deny manager binding changed before compensation");
            }
        }
        self.owner
            .verify_inverse_installed(self.lock, self.context)
            .map_err(|_| "AUTO protected compensation context changed")
    }

    fn record_stop_submitted(
        &mut self,
        job: &pid1::SubmittedJob,
    ) -> std::result::Result<(), &'static str> {
        self.owner
            .record_stop_submitted(self.lock, job)
            .map_err(|_| "AUTO submitted stop receipt requires recovery")
    }

    fn record_stop_completed(
        &mut self,
        job: &pid1::CompletedStop,
    ) -> std::result::Result<(), &'static str> {
        self.owner
            .record_stop_completed(self.lock, job)
            .map_err(|_| "AUTO completed stop receipt requires recovery")
    }
}

impl<'a> Session<'a> {
    pub(super) fn start(
        stage_path: &Path,
        lock: &'a InstallLock,
        state: &'a PublishedState,
        begin_capture: bool,
    ) -> Result<Self> {
        let mut step = "stage_reopen";
        let attempt = Self::start_inner(stage_path, lock, state, begin_capture, &mut step);
        if begin_capture {
            attempt.map_err(|error| super::begin_capture_step_error(step, error))
        } else {
            attempt
        }
    }

    fn start_inner(
        stage_path: &Path,
        lock: &'a InstallLock,
        state: &'a PublishedState,
        begin_capture: bool,
        step: &mut &'static str,
    ) -> Result<Self> {
        lock.revalidate().map_err(fail)?;
        let store = Store::reopen_for_worker(stage_path, 0).map_err(|_| RECOVERY.to_owned())?;
        *step = "stage_admit";
        let (stage, mut owner) = store
            .begin_owner_stage_locks()
            .map_err(|_| RECOVERY.to_owned())?
            .admit()
            .map_err(|_| RECOVERY.to_owned())?
            .split()
            .map_err(|_| RECOVERY.to_owned())?;
        if stage.header.phase != Phase::Metadata
            || stage.header.pending.is_some()
            || stage.header.unit_pending.is_some()
            || stage.header.capture_started
            || (begin_capture == (stage.header.mode == AutoMode::SocksOnly))
        {
            return Err(super::super::refuse());
        }
        let mode = stage.header.mode;
        *step = "recipe_restore";
        let rendered = PreparedRender::restore_private_recipe(&stage).map_err(fail)?;
        let context = RootContext::from_stage_with_lock(stage, state, Some(lock), None, None)
            .map_err(fail)?;
        *step = "installed_facts";
        let installed = owner
            .with_pre_marker_effect(lock, || ProtectedInstalledFacts::capture(&context, lock))?;
        *step = "publication_verify";
        owner.with_pre_marker_effect(lock, || {
            let publication =
                crate::profile_auto_runtime_publication::linux::RuntimePublication::new(&context);
            publication.verify_final_runtime_config().map_err(fail)?;
            let view = publication.published_view().map_err(fail)?;
            rendered.verify_published_tree(&view).map_err(fail)
        })?;
        *step = "policy_prepare";
        let transient = owner.with_pre_marker_effect(lock, || {
            super::super::unit_store::transient_policy(&context, lock)
        })?;
        let mut prepared = pid1::prepare_owned(transient).map_err(fail)?;
        *step = "manager_identity";
        let manager = prepared.manager().map_err(fail)?;
        let private_unit = prepared.unit().name().to_owned();
        if !private_unit_name(&private_unit) {
            return Err(super::super::refuse());
        }
        let (boot, netns) = native_anchor()?;
        if manager.boot_id() != boot || manager.netns_identity().1 != netns {
            return Err(super::super::refuse());
        }
        if mode != AutoMode::SocksOnly {
            *step = "terminal_configure";
            terminal_register("configure", &private_unit, &[])?;
            *step = "terminal_recover_incomplete";
            terminal_register("recover-incomplete", &private_unit, &[])?;
            *step = "terminal_prepare";
            terminal_register("prepare", &private_unit, &[])?;
        }
        *step = "guard_handoff";
        let guardian = if mode == AutoMode::SocksOnly {
            None
        } else {
            let binding = owner.binding(lock)?;
            let native = GuardianBinding {
                header_sha256: binding.header_sha256,
                transaction_nonce: binding.transaction_nonce,
                planned_generation: binding.planned_generation,
                boot_id: boot.clone(),
                netns_ino: netns,
                private_unit: private_unit.clone(),
                mode: mode_name(mode).into(),
            };
            let stage_fd = owner.duplicate_stage_fd(lock)?;
            let install_fd = lock.duplicate_held_fd().map_err(fail)?;
            let guard_fd = GuardDenyLease::open_guard_for_handoff().map_err(fail)?;
            Some(GuardDenyLease::acquire(stage_fd, install_fd, guard_fd, native).map_err(fail)?)
        };
        *step = "launch_register";
        let binding = owner.binding(lock)?;
        let launch_binding = LaunchBinding {
            private_unit: prepared.unit(),
            mode: mode_name(mode),
            header_sha256: &binding.header_sha256,
            transaction_nonce: &binding.transaction_nonce,
            planned_generation: &binding.planned_generation,
            boot_id: &boot,
            netns_ino: netns,
        };
        let stage_fd = owner.duplicate_stage_fd(lock)?;
        let install_fd = lock.duplicate_held_fd().map_err(fail)?;
        let actor_fd = prepared.duplicate_launch_fd().map_err(fail)?;
        let launch = LaunchOwnerLease::register(
            &launch_binding,
            stage_fd.as_raw_fd(),
            install_fd.as_raw_fd(),
            actor_fd,
        )
        .map_err(fail)?;
        *step = "pid1_start";
        let started = {
            let mut authority = StartAdapter {
                owner: &mut owner,
                installed: &installed,
                lock,
                guardian: guardian.as_ref(),
                launch: &launch,
                mode,
                boot: &boot,
                netns,
                manager,
                private_unit: private_unit.clone(),
            };
            prepared.start(&mut authority)?
        };
        *step = "launch_prove";
        let proof = launch.prove(started.completed());
        let mut session = Self {
            owner,
            context,
            rendered,
            started,
            launch: None,
            guardian,
            capture: None,
            terminal_private_unit: private_unit,
        };
        match proof {
            Ok(proof) => session.launch = Some(proof),
            Err(_) => {
                session.compensate_formatter_failure(lock)?;
                return Err(RECOVERY.to_owned());
            }
        }
        *step = "launch_record";
        if session
            .owner
            .record_launch_consumed(
                lock,
                session.launch.as_ref().ok_or_else(super::super::refuse)?,
            )
            .is_err()
        {
            session.compensate_formatter_failure(lock)?;
            return Err(RECOVERY.to_owned());
        }
        if session.guardian.is_some() {
            let name = mode_name(mode);
            *step = "capture_precheck";
            let proof = (|| -> Result<()> {
                let guard = session.guardian.as_mut().ok_or_else(super::super::refuse)?;
                guard.revalidate().map_err(fail)?;
                *step = "capture_ready";
                guard
                    .capture_ready(&mut session.started, name, &mut session.capture)
                    .map_err(capture_failure)?;
                *step = "capture_revalidate";
                session
                    .capture
                    .as_ref()
                    .ok_or_else(super::super::refuse)?
                    .revalidate(guard, &mut session.started)
                    .map_err(fail)?;
                Ok(())
            })();
            if proof.is_ok() {
                *step = "capture_mark";
            }
            let mark = match proof {
                Ok(()) => session.owner.with_owned_effect(lock, || {
                    let mut stage = session.context.stage_cell().borrow_mut();
                    if stage.header.phase != Phase::Metadata || stage.header.capture_started {
                        return Err(super::super::refuse());
                    }
                    stage.header.capture_started = true;
                    stage.persist_header()
                }),
                Err(error) => Err(error),
            };
            match mark {
                Ok(()) => (),
                Err(error) => {
                    session.compensate_formatter_failure(lock)?;
                    return Err(error);
                }
            }
        }
        if session.guardian.is_some() {
            *step = "terminal_activate";
            if terminal_register("activate", &session.terminal_private_unit, &[]).is_err() {
                session.compensate_formatter_failure(lock)?;
                return Err(RECOVERY.to_owned());
            }
        }
        Ok(session)
    }

    pub(super) fn finalize(mut self, lock: &InstallLock) -> Result<()> {
        let attempt = (|| -> Result<()> {
            self.launch
                .as_ref()
                .ok_or_else(super::super::refuse)?
                .revalidate()
                .map_err(fail)?;
            if self.guardian.is_some() {
                self.owner.with_owned_effect(lock, || {
                    preflight_owned_projection(&self.context, &self.rendered)
                })?;
            }
            if let Some(guardian) = &self.guardian {
                guardian.revalidate().map_err(fail)?;
                self.capture
                    .as_ref()
                    .ok_or_else(super::super::refuse)?
                    .revalidate(guardian, &mut self.started)
                    .map_err(fail)?;
            }
            self.owner.with_owned_effect(lock, || {
                finalize_owned_projection(
                    &self.context,
                    &mut self.rendered,
                    lock,
                    &mut self.started,
                )
            })?;
            self.launch
                .as_ref()
                .ok_or_else(super::super::refuse)?
                .revalidate()
                .map_err(fail)?;
            if let Some(guardian) = self.guardian.as_mut() {
                let capture = self.capture.as_ref().ok_or_else(super::super::refuse)?;
                let launch = self.launch.as_mut().ok_or_else(super::super::refuse)?;
                capture
                    .revalidate(guardian, &mut self.started)
                    .map_err(fail)?;
                self.owner.terminal_success_wide(
                    lock,
                    guardian,
                    launch,
                    capture,
                    &mut self.started,
                )?;
                Ok(())
            } else {
                let launch = self.launch.as_mut().ok_or_else(super::super::refuse)?;
                self.owner.terminal_success_socks(lock, launch)
            }
        })();
        match attempt {
            Ok(()) => Ok(()),
            Err(error) => {
                // Once PID1 accepted the private job, even a projection or
                // terminal receipt failure must attempt the exact inverse.
                // An uncertain inverse leaves sticky recovery markers.
                self.compensate_formatter_failure(lock)?;
                Err(error)
            }
        }
    }

    fn compensate_formatter_failure(self, lock: &InstallLock) -> Result<()> {
        let Self {
            mut owner,
            context,
            started,
            mut guardian,
            capture,
            terminal_private_unit,
            launch: _launch,
            ..
        } = self;
        owner
            .begin_postterminal_inverse(lock)
            .map_err(|_| RECOVERY.to_owned())?;
        let completed = {
            let mut stop = StopAdapter {
                owner: &mut owner,
                context: &context,
                lock,
                guardian: guardian.as_ref(),
            };
            started
                .stop_owned(&mut stop)
                .map_err(|_| RECOVERY.to_owned())?
        };
        let final_result = if let Some(guardian) = guardian.as_mut() {
            let mut inverse = guardian
                .complete_compensated_failure(&completed, capture.as_ref())
                .map_err(fail)?;
            owner.terminal_compensated_failure_wide(lock, guardian, &mut inverse)
        } else {
            owner.terminal_compensated_failure_socks(lock)
        };
        if guardian.is_some() {
            terminal_register("cleanup", &terminal_private_unit, &[])?;
        }
        final_result
    }

    pub(super) fn compensate_abandon(self, lock: &InstallLock) -> Result<()> {
        self.compensate_formatter_failure(lock)
    }
}

#[cfg(test)]
mod capture_failure_tests {
    use super::{capture_failure, GuardianRefusal};

    #[test]
    fn only_authenticated_capture_coordinates_survive_error_conversion() {
        let value = capture_failure(GuardianRefusal::CaptureFailed {
            reason: "os_error",
            source: "endpoint",
            line: 412,
        });
        assert_eq!(
            value,
            "AUTO authenticated capture refusal:os_error:endpoint:412"
        );
        assert_eq!(
            capture_failure(GuardianRefusal::Untrusted),
            super::super::super::refuse()
        );
    }
}
