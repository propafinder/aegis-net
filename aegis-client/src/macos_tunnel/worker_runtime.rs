//! Private inherited-capability entry. This child owns identity/network work;
//! it never opens utun, routes, PF, OS accounts or privileged policy.
use super::{
    worker_ipc::CancelHandle,
    worker_launch::{self, AuthenticatedPolicyAck, RuntimeParts, WorkerBootstrap},
    TerminationOwner,
};
use crate::{
    device_bundle::online::{self, OnlineProfile},
    device_identity::store,
    device_renewal::{PreparedIdentity, Supervisor},
    ingress::wide::ip_tunnel::{self, TunnelStats},
};
use aegis_core::{
    secure_channel::registry,
    wide_product::{self, WideProductMode},
    Mode, Settings,
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::File,
    io::{self, Read, Seek},
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
const SELECTOR: &str = "--macos-network-worker-internal";
const MAX_PROFILE: u64 = 1024 * 1024;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RenewalPolicy {
    ExistingLeaseOnly,
    AutomaticRenewal,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    identity: PathBuf,
    online_bundle: PathBuf,
    authority_server: SocketAddr,
    renewal: RenewalPolicy,
    settings: Settings,
    run_seconds: u64,
    max_flows: usize,
    idle_seconds: u64,
    mtu: usize,
    dns_upstream: SocketAddr,
}
/// Read-only public view. Native owner/digest admission precedes parsing; this
/// view never opens an identity key, lock, record, renewal file or credential.
pub(crate) struct WorkerRuntimeProfile {
    envelope: Envelope,
    authority: [SocketAddr; 1],
    relays: Vec<SocketAddr>,
}
impl WorkerRuntimeProfile {
    pub(crate) fn open(path: &Path, sha256: &[u8; 32]) -> Result<Self> {
        Self::read(&mut worker_launch::open_public_profile(path, sha256)?)
    }
    pub(super) fn read(file: &mut File) -> Result<Self> {
        file.rewind()?;
        let mut bytes = Vec::new();
        file.take(MAX_PROFILE + 1).read_to_end(&mut bytes)?;
        ensure!(
            !bytes.is_empty() && bytes.len() as u64 <= MAX_PROFILE,
            "worker public profile size rejected"
        );
        let envelope: Envelope = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("worker public profile rejected"))?;
        Self::validate(envelope)
    }
    fn validate(e: Envelope) -> Result<Self> {
        e.settings
            .validate_privacy_plan()
            .map_err(anyhow::Error::msg)?;
        ensure!(
            e.version == 1
                && (1..=300).contains(&e.run_seconds)
                && (1..=512).contains(&e.max_flows)
                && (1..=600).contains(&e.idle_seconds)
                && (1280..=1500).contains(&e.mtu)
                && e.dns_upstream.port() > 0
                && !e.dns_upstream.ip().is_unspecified()
                && !e.dns_upstream.ip().is_multicast(),
            "worker runtime limits rejected"
        );
        for path in [&e.identity, &e.online_bundle] {
            clean_absolute(path)?;
        }
        ensure!(
            matches!(e.settings.mode, Mode::Relay)
                && e.settings.windows_tunnel.is_none()
                && e.settings.socks.auth_token.is_none()
                && e.settings.socks.auth_user.is_none(),
            "worker public runtime intent rejected"
        );
        wide_product::validate_inner_tls_device_settings(
            WideProductMode::FullWideTun,
            true,
            &e.settings,
        )
        .map_err(anyhow::Error::msg)?;
        e.settings.validate_ech().map_err(anyhow::Error::msg)?;
        ensure!(
            e.settings.relay.outer_geneva.is_none(),
            "worker outer Geneva is unsupported"
        );
        let tls = e
            .settings
            .relay
            .inner_tls
            .as_ref()
            .context("worker requires inner TLS")?;
        ensure!(
            tls.key == e.identity.join("device.key") && tls.cert == e.identity.join("device.pem"),
            "worker identity paths differ from custody"
        );
        for path in [
            tls.key.as_path(),
            tls.cert.as_path(),
            tls.server_ca.as_path(),
            e.settings
                .relay
                .ca_cert
                .as_deref()
                .context("worker outer trust missing")?,
        ] {
            clean_absolute(path)?;
        }
        if let Some(path) = &e.settings.relay.ech_config_list {
            clean_absolute(path)?;
        }
        if let Some(bridge) = &e.settings.relay.https_bridge {
            clean_absolute(&bridge.credential_file)?;
        }
        let relays = super::admitted_relay_pins(&Default::default(), &e.settings.relay)
            .map_err(anyhow::Error::msg)?;
        let expected_authority = online::full_wide_authority_pin(&e.online_bundle)?;
        ensure!(
            e.authority_server == expected_authority,
            "worker authority differs from immutable public intent"
        );
        let authority = [e.authority_server];
        Ok(Self {
            envelope: e,
            authority,
            relays,
        })
    }
    pub(crate) fn identity(&self) -> &Path {
        &self.envelope.identity
    }
    pub(crate) fn authority_pins(&self) -> &[SocketAddr] {
        &self.authority
    }
    pub(crate) fn relay_pins(&self) -> &[SocketAddr] {
        &self.relays
    }
    pub(crate) fn mtu(&self) -> usize {
        self.envelope.mtu
    }
    pub(crate) fn run_seconds(&self) -> u64 {
        self.envelope.run_seconds
    }
    fn checked_online(&self, inherited_identity: &Path) -> Result<OnlineProfile> {
        ensure!(
            self.identity() == inherited_identity,
            "worker inherited custody differs from profile"
        );
        let (profile, identity) =
            OnlineProfile::for_runtime(&self.envelope.online_bundle, &self.envelope.settings)?;
        ensure!(
            identity == inherited_identity
                && profile.carrier().server.parse::<SocketAddr>().ok() == Some(self.authority[0]),
            "worker runtime identity or authority changed"
        );
        Ok(profile)
    }
}
fn clean_absolute(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.as_os_str().len() <= 4096
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "worker absolute path required"
    );
    Ok(())
}
fn selector(args: impl IntoIterator<Item = OsString>) -> Option<Result<()>> {
    let args: Vec<_> = args.into_iter().collect();
    if !args
        .iter()
        .any(|a| a.to_string_lossy().starts_with(SELECTOR))
    {
        return None;
    }
    Some(if args.len() == 1 && args[0] == SELECTOR {
        Ok(())
    } else {
        Err(anyhow::anyhow!("worker internal selector rejected"))
    })
}
pub(crate) fn dispatch(args: impl IntoIterator<Item = OsString>) -> Option<Result<()>> {
    let accepted = selector(args)?;
    crate::runtime_jsonl::set_private_logs(true);
    crate::runtime_jsonl::set_forensic_redact(true);
    Some(accepted.and_then(|_| {
        // This exact branch is the sole inherited-descriptor consumer, before
        // Tokio, Clap or network setup. Plain invocation has no capabilities.
        let bootstrap = unsafe { worker_launch::accept_inherited(Duration::from_secs(3)) }?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(run(bootstrap))
    }))
}

async fn wait_until_native(deadline: u64) -> Result<()> {
    loop {
        let now = worker_launch::monotonic_ns()?;
        if now >= deadline {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_nanos((deadline - now).min(100_000_000))).await;
    }
}
struct EngineOwner {
    thread: Option<std::thread::JoinHandle<io::Result<TunnelStats>>>,
    stop: Arc<AtomicBool>,
    cancel: CancelHandle,
}
impl EngineOwner {
    async fn finish(&mut self) -> Result<io::Result<TunnelStats>> {
        self.stop.store(true, Ordering::Release);
        self.cancel.cancel();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while self.thread.as_ref().is_some_and(|t| !t.is_finished()) {
            ensure!(
                tokio::time::Instant::now() < deadline,
                "owned packet engine exit unconfirmed"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        self.thread
            .take()
            .context("owned packet engine missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("owned packet engine panicked"))
    }
}
impl Drop for EngineOwner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.cancel.cancel();
    }
}
// Pin every field of the issuance whose startup ACK admitted this session.
// A refresh for a newly observed issuance cannot silently replace that custody.
fn same_session_issuance(
    admitted: &store::OnlineExpectation,
    current: &store::OnlineExpectation,
) -> Result<()> {
    ensure!(
        aegis_client::issuance_binding::same_issuance(admitted.binding(), current.binding()),
        "worker issuance changed; authenticated restart required"
    );
    Ok(())
}
fn active_session_issuance(
    profile: &WorkerRuntimeProfile,
    identity: &Path,
    online: &OnlineProfile,
    admitted: &store::OnlineExpectation,
) -> Result<store::OnlineExpectation> {
    let fresh = profile.checked_online(identity)?;
    ensure!(
        fresh.digest() == online.digest(),
        "worker public profile changed"
    );
    let now = registry::unix_now()?;
    ensure!(
        crate::device_renewal::monitor_at(
            identity,
            online.digest(),
            &admitted.certificate_sha256,
            now
        )
        .is_none(),
        "worker identity restart required"
    );
    let current = store::online_expectation(identity, online.digest(), now)?;
    same_session_issuance(admitted, &current)?;
    Ok(current)
}
async fn run(bootstrap: WorkerBootstrap) -> Result<()> {
    let parts = bootstrap.into_runtime()?;
    run_parts(parts).await.map(|_| ())
}
pub(crate) async fn run_parts(parts: RuntimeParts) -> Result<TunnelStats> {
    let RuntimeParts {
        port,
        cancel,
        identity,
        mut profile,
        mut control,
    } = parts;
    let profile = WorkerRuntimeProfile::read(&mut profile)?;
    let online = profile.checked_online(&identity)?;
    let e = &profile.envelope;
    let started = worker_launch::monotonic_ns()?;
    let total = started
        .checked_add((e.run_seconds + 30) * 1_000_000_000)
        .context("worker total clock overflow")?;
    let startup = started
        .checked_add(20_000_000_000)
        .context("worker startup clock overflow")?;
    let mut signals = TerminationOwner::new()?;
    let prepared = tokio::select! {
        result = PreparedIdentity::prepare(&e.online_bundle, &e.settings, matches!(e.renewal, RenewalPolicy::AutomaticRenewal)) => result?,
        result = control.unexpected() => { result?; anyhow::bail!("worker control stopped"); },
        _ = signals.cancelled() => anyhow::bail!("worker terminated"),
        _ = wait_until_native(startup) => anyhow::bail!("worker identity startup deadline"),
    };
    control.require_idle()?;
    let fingerprint = prepared.fingerprint().to_owned();
    let admitted = store::online_expectation(&identity, online.digest(), registry::unix_now()?)?;
    ensure!(
        admitted.certificate_sha256 == fingerprint,
        "worker prepared identity changed"
    );
    let phase = control.identity_prepared().await?;
    tokio::select! {
        result = control.relay_permission(&phase) => result?,
        _ = signals.cancelled() => anyhow::bail!("worker terminated"),
        _ = wait_until_native(startup) => anyhow::bail!("worker relay permission deadline"),
    };
    let mut supervisor: Supervisor = tokio::select! {
        result = prepared.confirm() => result?,
        result = control.unexpected() => { result?; anyhow::bail!("worker control stopped"); },
        _ = signals.cancelled() => anyhow::bail!("worker terminated"),
        _ = wait_until_native(startup) => anyhow::bail!("worker initial ACK deadline"),
    };
    control.require_idle()?;
    let lease = aegis_client::capture_lease_gate::CaptureLeaseDeadline::default();
    let mut gate = aegis_client::capture_lease_gate::CaptureLeaseGate::new(
        port,
        lease.clone(),
        worker_launch::monotonic_ns,
    );
    let settings = e.settings.relay.clone();
    let stop = signals.stopped.clone();
    let flag = stop.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
    let (max_flows, idle, mtu, dns) = (
        e.max_flows,
        Duration::from_secs(e.idle_seconds),
        e.mtu,
        e.dns_upstream,
    );
    let thread = std::thread::Builder::new()
        .name("aegis-owned-ip-engine".into())
        .spawn(move || {
            let result =
                ip_tunnel::run_ready(&mut gate, settings, flag, max_flows, idle, mtu, dns, || {
                    let _ = ready_tx.send(());
                });
            let _ = done_tx.send(());
            result
        })?;
    let mut engine = EngineOwner {
        thread: Some(thread),
        stop,
        cancel,
    };
    let session = async {
        tokio::select! {
            result = ready_rx => result.context("worker engine construction failed")?,
            result = control.unexpected() => { result?; anyhow::bail!("worker control stopped"); },
            reason = supervisor.failure() => anyhow::bail!(reason),
            _ = signals.cancelled() => anyhow::bail!("worker terminated"),
            _ = wait_until_native(startup) => anyhow::bail!("worker engine startup deadline"),
        }
        active_session_issuance(&profile, &identity, &online, &admitted)?;
        control.engine_constructed().await?;
        let mut lease_deadline = startup;
        let mut monitor_deadline = worker_launch::monotonic_deadline(Duration::from_secs(5))?;
        loop {
            let challenge = tokio::select! {
                result = control.challenge() => result?,
                _ = wait_until_native(monitor_deadline) => {
                    active_session_issuance(&profile, &identity, &online, &admitted)?;
                    monitor_deadline = worker_launch::monotonic_deadline(Duration::from_secs(5))?;
                    continue;
                },
                reason = supervisor.failure() => anyhow::bail!(reason),
                _ = &mut done_rx => anyhow::bail!("worker engine stopped"),
                _ = signals.cancelled() => anyhow::bail!("worker terminated"),
                _ = wait_until_native(lease_deadline.min(total)) => anyhow::bail!("worker capture grant deadline"),
            };
            ensure!(worker_launch::monotonic_ns()? < lease_deadline.min(total), "worker capture grant deadline");
            let expected = active_session_issuance(&profile, &identity, &online, &admitted)?;
            let ack_deadline = worker_launch::monotonic_ns()?.saturating_add(3_000_000_000).min(lease_deadline).min(total);
            let ack = tokio::select! {
                result = AuthenticatedPolicyAck::confirm(&e.settings.relay, &expected) => result?,
                result = control.unexpected() => { result?; anyhow::bail!("worker control stopped"); },
                reason = supervisor.failure() => anyhow::bail!(reason),
                _ = &mut done_rx => anyhow::bail!("worker engine stopped"),
                _ = signals.cancelled() => anyhow::bail!("worker terminated"),
                _ = wait_until_native(ack_deadline) => anyhow::bail!("worker live ACK deadline"),
            };
            control.require_idle()?;
            active_session_issuance(&profile, &identity, &online, &admitted)?;
            let expires = control.policy_confirmed(challenge, &ack).await?;
            lease.replace(Some(expires))?;
            lease_deadline = expires;
        }
    }.await;
    // No error or control EOF can silently detach a healthy capture engine.
    // A synchronous native stall yields explicit unconfirmed exit; parent must
    // terminate/reap its exact process before authorizing policy rollback.
    let finished = engine.finish().await;
    let monitor_joined = supervisor.stop_monitor_and_join().await;
    let result = finished.context("owned packet engine exit unconfirmed")?;
    monitor_joined.context("owned renewal monitor exit unconfirmed")?;
    session?;
    Ok(result?)
}

#[cfg(test)]
#[path = "worker_runtime_tests.rs"]
mod tests;
