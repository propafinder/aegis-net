//! Explicit macOS VM packet-tunnel runtime. Reuses the Windows packet engine.
//! System policy is privileged and separate from packet/relay processing.
mod policy;
// Explicit VM-only parent owns native policy/device; the dedicated non-root
// child owns private identity and all relay processing.
pub(crate) mod parent_runtime;
#[allow(dead_code)]
mod worker_accounts;
#[allow(dead_code)]
pub(crate) mod worker_ipc;
#[allow(dead_code)]
pub(crate) mod worker_launch;
mod worker_pump;
pub(crate) mod worker_runtime;
#[cfg(test)]
use crate::Args;
use aegis_client::macos_relay_pins::admitted_relay_pins;
#[cfg(test)]
use aegis_core::tunnel_policy::WindowsTunnelSettings;
#[cfg(test)]
use aegis_core::{Mode, Settings};
use anyhow::Context;
pub(crate) use policy::ReceiptOwner;
use rand::RngCore;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::watch;

/// Register both signals before any privileged mutation or child spawn. A
/// supervisor uses the flag in its blocking loop; a worker also waits on the
/// channel during readiness and capture. Dropping the owner cancels its worker.
struct TerminationOwner {
    stopped: Arc<AtomicBool>,
    receiver: watch::Receiver<bool>,
    task: tokio::task::JoinHandle<()>,
}
impl TerminationOwner {
    fn new() -> std::io::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        let stopped = Arc::new(AtomicBool::new(false));
        let flag = stopped.clone();
        let (sender, receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = terminate.recv() => {},
                _ = interrupt.recv() => {},
            }
            flag.store(true, Ordering::Release);
            let _ = sender.send(true);
        });
        Ok(Self {
            stopped,
            receiver,
            task,
        })
    }
    async fn cancelled(&mut self) {
        while !*self.receiver.borrow_and_update() {
            if self.receiver.changed().await.is_err() {
                break;
            }
        }
    }
}
impl Drop for TerminationOwner {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        self.task.abort();
    }
}

/// Own exactly the process returned by spawn. An error cannot simply drop a
/// live std::process::Child (which neither kills nor reaps it).
struct OwnedPacketChild(Option<std::process::Child>);
impl OwnedPacketChild {
    fn new(child: std::process::Child) -> Self {
        Self(Some(child))
    }
    fn wait(
        &mut self,
        stopped: &AtomicBool,
        deadline: Duration,
    ) -> std::io::Result<(std::process::ExitStatus, bool)> {
        let deadline = worker_launch::monotonic_ns()?
            .checked_add(
                u64::try_from(deadline.as_nanos()).map_err(|_| std::io::ErrorKind::InvalidInput)?,
            )
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        let mut termination_deadline = None;
        let child = self
            .0
            .as_mut()
            .expect("owned child is present until reaped");
        loop {
            if let Some(status) = child.try_wait()? {
                self.0 = None;
                return Ok((status, termination_deadline.is_some()));
            }
            let now = worker_launch::monotonic_ns()?;
            if termination_deadline.is_none()
                && (stopped.load(Ordering::Acquire) || now >= deadline)
            {
                // Let the root parent's TERM handler stop/reap its network
                // child and persist the typed retained guard. This PID belongs
                // to the held, unreaped Child; no process/group search occurs.
                if unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) } != 0 {
                    let error = std::io::Error::last_os_error();
                    if let Some(status) = child.try_wait()? {
                        self.0 = None;
                        return Ok((status, true));
                    }
                    return Err(error);
                }
                termination_deadline = Some(now.saturating_add(15_000_000_000));
            }
            if termination_deadline.is_some_and(|until| now >= until) {
                // kill/wait use only this owned process handle, never a PID
                // search, a process group or a name shared with another client.
                if let Err(error) = child.kill() {
                    // A natural exit can race the cancellation check.
                    if let Some(status) = child.try_wait()? {
                        self.0 = None;
                        return Ok((status, true));
                    }
                    return Err(error);
                }
                let reap_until = worker_launch::monotonic_ns()?.saturating_add(2_000_000_000);
                loop {
                    if let Some(status) = child.try_wait()? {
                        self.0 = None;
                        return Ok((status, true));
                    }
                    if worker_launch::monotonic_ns()? >= reap_until {
                        return Err(std::io::Error::other("owned parent exit unconfirmed after forced termination; guard retained"));
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
impl Drop for OwnedPacketChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let deadline = worker_launch::monotonic_ns()
                .ok()
                .and_then(|now| now.checked_add(2_000_000_000));
            loop {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return;
                }
                if deadline.is_none_or(|until| {
                    worker_launch::monotonic_ns().map_or(true, |now| now >= until)
                }) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            // Background ownership cleanup cannot mint exit/rollback proof.
            let _ = std::thread::Builder::new()
                .name("aegis-owned-parent-reap".into())
                .spawn(move || {
                    let _ = child.wait();
                });
        }
    }
}

fn spawn_owned_packet_child(
    command: &mut std::process::Command,
    owner: &str,
) -> std::io::Result<OwnedPacketChild> {
    // This tag identifies one supervisor's receipt; it is not a device or TLS
    // credential. Override any inherited tag only in this owned child's env.
    command.env("AEGIS_MACOS_UTUN_SUPERVISOR_OWNER", owner);
    command.spawn().map(OwnedPacketChild::new)
}

fn supervise_owned_child(
    mut child: OwnedPacketChild,
    stopped: &AtomicBool,
    deadline: Duration,
    inspection_interval: Duration,
    rollback: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let (status, interrupted) = child
        .wait(stopped, deadline)
        .context("could not confirm owned packet child's exit; guard retained")?;
    eprintln!("Packet worker exited; guard inspection interval before independent rollback.");
    // The control-handshake deadline helper deliberately caps calls at five
    // seconds. Inspection has its own separate thirty-second budget.
    let inspection_deadline = worker_launch::monotonic_ns()
        .context("inspection clock unavailable; guard retained")?
        .checked_add(
            u64::try_from(inspection_interval.as_nanos())
                .context("inspection interval exceeds native clock range; guard retained")?,
        )
        .context("inspection deadline overflow; guard retained")?;
    // Cancellation during capture or during inspection requests prompt rollback.
    // A normal completed capture retains the bounded inspection interval.
    while !stopped.load(Ordering::Acquire)
        && worker_launch::monotonic_ns().context("inspection clock unavailable; guard retained")?
            < inspection_deadline
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    rollback()?;
    if interrupted || stopped.load(Ordering::Acquire) || !status.success() {
        anyhow::bail!("packet child failed, was cancelled or exceeded its bounded deadline");
    }
    Ok(())
}

pub(crate) fn disconnect(owner: Option<&ReceiptOwner>) -> anyhow::Result<()> {
    dispatch_disconnect(owner, policy::disconnect, policy::disconnect_owned).map_err(Into::into)
}

fn dispatch_disconnect(
    owner: Option<&ReceiptOwner>,
    manual: impl FnOnce() -> std::io::Result<()>,
    owned: impl FnOnce(&str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    match owner {
        Some(owner) => owned(owner.as_str()),
        None => manual(),
    }
}

/// A separate parent owns the policy parent's process handle. Its cooperative
/// deadline includes readiness/capture; TERM grants 15s cleanup before force,
/// then confirmed exit precedes the retained-guard inspection interval.
/// The rollback needs no relay config, credentials or successful child runtime.
pub(crate) async fn supervise(seconds: u64) -> anyhow::Result<()> {
    policy::root_vm()?;
    if !(10..=300).contains(&seconds) {
        anyhow::bail!("VM packet-tunnel interval must be 10..300 seconds");
    }
    let executable = std::env::current_exe()?;
    use std::os::unix::fs::MetadataExt;
    for path in executable.ancestors() {
        let metadata = std::fs::metadata(path)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            anyhow::bail!("VM supervisor executable and ancestors must be root-owned and not writable by others");
        }
    }
    let arguments: Vec<_> = std::env::args_os()
        .skip(1)
        .filter(|arg| arg != "--macos-utun-supervise")
        .collect();
    // An earlier attempt may own a retained guard. Never start over it or run
    // global rollback after a new child fails to publish its own receipt.
    policy::ensure_no_active_receipt()
        .context("VM supervisor refuses an existing policy receipt")?;
    let mut owner_bytes = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut owner_bytes)
        .context("generate VM supervisor ownership tag")?;
    let owner = hex::encode(owner_bytes);
    let termination = TerminationOwner::new().context("install VM termination handlers")?;
    let cancelled = termination.stopped.clone();
    // Public ownership tag, not a credential. A separately staged local
    // rollback controller can bind even a setup failure to this attempt.
    eprintln!("VM supervisor receipt owner: {owner}");
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        if cancelled.load(Ordering::Acquire) {
            anyhow::bail!("VM supervisor cancelled before starting packet child");
        }
        let mut command = std::process::Command::new(executable);
        command.args(arguments);
        let child = spawn_owned_packet_child(&mut command, &owner)?;
        supervise_owned_child(
            child,
            &cancelled,
            Duration::from_secs(seconds + 90),
            Duration::from_secs(30),
            || {
                // The exact tag must match before disconnect examines/removes
                // any policy state. A missing/mismatched receipt is an error.
                match policy::disconnect_owned(&owner) {
                    Ok(()) => {
                        eprintln!("Independent VM rollback completed; previous proxy/DNS restored.")
                    }
                    Err(e) => {
                        return Err(e).context("independent rollback failed; guard may remain")
                    }
                }
                Ok(())
            },
        )
    })
    .await
    .context("VM supervisor failed");
    drop(termination);
    result?
}

// Historical admission regressions only. The production CLI enters
// parent_runtime before ordinary configuration/private identity loading.
#[cfg(test)]
async fn run(
    cfg: Settings,
    args: &Args,
    _shutdown: Option<watch::Receiver<bool>>,
) -> anyhow::Result<()> {
    if args.macos_utun_disconnect {
        return disconnect(args.macos_utun_disconnect_owner.as_ref());
    }
    if args.macos_utun_disconnect_owner.is_some() {
        anyhow::bail!("owned macOS disconnect requires --macos-utun-disconnect");
    }
    if !matches!(cfg.mode, Mode::Relay) || cfg.ingress.allow_fallback {
        anyhow::bail!("macOS packet tunnel requires relay mode with no ingress fallback");
    }
    let seconds = args.macos_utun_seconds;
    if !(10..=300).contains(&seconds) {
        anyhow::bail!("VM packet-tunnel interval must be 10..300 seconds");
    }
    let service = args
        .macos_utun_service
        .clone()
        .context("--macos-utun-service is required")?;
    let settings = WindowsTunnelSettings::default();
    let pins = admitted_relay_pins(&settings, &cfg.relay)
        .map_err(anyhow::Error::msg)
        .context("macOS relay protocol admission")?;
    // This helper preserves historical admission regressions only. Even an
    // admitted profile cannot open utun or activate the retired generic policy.
    // The production CLI uses parent_runtime and its dedicated WorkerPolicy.
    policy::refuse_generic_policy("unopened-utun", &service, &pins).map_err(Into::into)
}

#[cfg(test)]
enum CaptureReadiness {
    Ready,
    Unavailable,
    Cancelled,
}

#[cfg(test)]
async fn wait_readiness(
    ready: tokio::sync::oneshot::Receiver<()>,
    termination: &mut TerminationOwner,
    shutdown: &mut Option<watch::Receiver<bool>>,
) -> CaptureReadiness {
    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(30), ready) => {
            if matches!(result, Ok(Ok(()))) {
                CaptureReadiness::Ready
            } else {
                CaptureReadiness::Unavailable
            }
        },
        _ = termination.cancelled() => CaptureReadiness::Cancelled,
        _ = external_shutdown(shutdown) => CaptureReadiness::Cancelled,
    }
}

#[cfg(test)]
async fn external_shutdown(shutdown: &mut Option<watch::Receiver<bool>>) {
    match shutdown {
        Some(receiver) => {
            while !*receiver.borrow_and_update() && receiver.changed().await.is_ok() {}
        }
        None => std::future::pending::<()>().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{RelayTlsBackend, TunnelTransportFamily, WireMimicryMode};
    use clap::Parser;
    use std::{
        fs,
        path::{Path, PathBuf},
        process::{Command, Stdio},
    };

    #[test]
    fn macos_utun_owned_disconnect_cli_requires_explicit_mode_and_exact_nonce() {
        const OWNER: &str = "0123456789abcdef0123456789abcdef";
        let args = Args::try_parse_from([
            "aegis-client",
            "--macos-utun-disconnect",
            "--macos-utun-disconnect-owner",
            OWNER,
        ])
        .unwrap();
        assert!(args.macos_utun_disconnect);
        assert_eq!(args.macos_utun_disconnect_owner.unwrap().as_str(), OWNER);
        for invalid_mode in [
            vec!["aegis-client", "--macos-utun-disconnect-owner", OWNER],
            vec![
                "aegis-client",
                "--macos-utun",
                "--macos-utun-disconnect",
                "--macos-utun-disconnect-owner",
                OWNER,
            ],
            vec![
                "aegis-client",
                "--macos-utun",
                "--macos-utun-supervise",
                "--macos-utun-disconnect",
                "--macos-utun-disconnect-owner",
                OWNER,
            ],
        ] {
            assert!(Args::try_parse_from(invalid_mode).is_err());
        }
        for invalid_nonce in ["", "bad", "0123456789ABCDEF0123456789abcdef"] {
            assert!(Args::try_parse_from([
                "aegis-client",
                "--macos-utun-disconnect",
                "--macos-utun-disconnect-owner",
                invalid_nonce,
            ])
            .is_err());
        }
        assert!(Args::try_parse_from([
            "aegis-client",
            "--macos-utun-disconnect",
            "--macos-utun-disconnect-owner",
        ])
        .is_err());
        let manual = Args::try_parse_from(["aegis-client", "--macos-utun-disconnect"]).unwrap();
        assert!(manual.macos_utun_disconnect);
        assert!(manual.macos_utun_disconnect_owner.is_none());
    }

    #[tokio::test]
    async fn macos_utun_owned_disconnect_direct_helper_rejects_wrong_mode_before_activation() {
        let mut args = Args::try_parse_from(["aegis-client"]).unwrap();
        args.macos_utun_disconnect_owner =
            Some("0123456789abcdef0123456789abcdef".parse().unwrap());
        let error = run(Settings::default(), &args, None).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("requires --macos-utun-disconnect"));
    }

    #[test]
    fn macos_utun_owned_disconnect_rejection_never_falls_back_to_manual_cleanup() {
        let args = Args::try_parse_from([
            "aegis-client",
            "--macos-utun-disconnect",
            "--macos-utun-disconnect-owner",
            "0123456789abcdef0123456789abcdef",
        ])
        .unwrap();
        let error = dispatch_disconnect(
            args.macos_utun_disconnect_owner.as_ref(),
            || panic!("owned rejection must not invoke manual cleanup"),
            |owner| {
                assert_eq!(owner, "0123456789abcdef0123456789abcdef");
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "different receipt; guard retained",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        dispatch_disconnect(
            None,
            || Ok(()),
            |_| panic!("manual operator command must retain the manual path"),
        )
        .unwrap();
    }

    fn authenticated_h2_relay() -> aegis_core::RelaySettings {
        aegis_core::RelaySettings {
            server: "203.0.113.9:443".into(),
            server_name: "relay.test".into(),
            ca_cert: Some("unused-outer-ca.pem".into()),
            inner_tls: Some(aegis_core::secure_channel::ClientSettings {
                server_name: "relay.test".into(),
                server_ca: "unused-device-ca.pem".into(),
                cert: "unused-device.pem".into(),
                key: "unused-device-key.pem".into(),
            }),
            transport_priority: vec![TunnelTransportFamily::GrpcStream],
            udp_transport_priority: Some(vec![TunnelTransportFamily::GrpcDatagram]),
            tls_backend: RelayTlsBackend::Rustls,
            wire_mimicry_mode: WireMimicryMode::Disabled,
            ..Default::default()
        }
    }

    #[test]
    fn macos_utun_relay_protocol_pins_ignore_masque_metadata_and_dedup_both_families() {
        let mut relay = authenticated_h2_relay();
        relay.masque_server = Some("unused.invalid:443".into());
        assert_eq!(
            admitted_relay_pins(&WindowsTunnelSettings::default(), &relay).unwrap(),
            vec!["203.0.113.9:443".parse::<std::net::SocketAddr>().unwrap()]
        );
        relay.server = "unused-primary.invalid:443".into();
        relay.endpoints = [
            "203.0.113.10:8443",
            "[2001:db8::10]:443",
            "203.0.113.10:8443",
        ]
        .into_iter()
        .map(|server| aegis_core::RelayEndpointSettings {
            server: server.into(),
            server_name: "relay.test".into(),
            masque_server: Some("another-unused.invalid:8443".into()),
            masque_server_name: None,
        })
        .collect();
        assert_eq!(
            admitted_relay_pins(&WindowsTunnelSettings::default(), &relay).unwrap(),
            vec![
                "203.0.113.10:8443".parse::<std::net::SocketAddr>().unwrap(),
                "[2001:db8::10]:443"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
            ]
        );
    }

    #[test]
    fn macos_utun_relay_protocol_pins_preserve_address_count_and_trust_admission() {
        let mut relay = authenticated_h2_relay();
        for rejected in [
            "relay.invalid:443",
            "0.0.0.0:443",
            "[::]:443",
            "224.0.0.1:443",
            "[ff02::1]:443",
            "198.19.0.1:443",
            "[::ffff:192.0.2.1]:443",
            "[fd00:ae61::1]:443",
            "203.0.113.9:0",
        ] {
            relay.server = rejected.into();
            assert!(admitted_relay_pins(&WindowsTunnelSettings::default(), &relay).is_err());
        }
        relay = authenticated_h2_relay();
        relay.ca_cert = None;
        assert!(admitted_relay_pins(&WindowsTunnelSettings::default(), &relay).is_err());
        relay = authenticated_h2_relay();
        relay.endpoints = (1..=129)
            .map(|last| aegis_core::RelayEndpointSettings {
                server: format!("[2001:db8::{last:x}]:443"),
                server_name: "relay.test".into(),
                masque_server: None,
                masque_server_name: None,
            })
            .collect();
        assert!(
            admitted_relay_pins(&WindowsTunnelSettings::default(), &relay)
                .unwrap_err()
                .contains("endpoint count")
        );
    }

    #[tokio::test]
    async fn macos_utun_relay_protocol_non_h2_profiles_refuse_before_native_activation() {
        let args = Args::try_parse_from([
            "aegis-client",
            "--macos-utun",
            "--macos-utun-service",
            "Ethernet",
            "--macos-utun-seconds",
            "10",
        ])
        .unwrap();
        let mut rejected = Vec::new();
        let mut legacy = authenticated_h2_relay();
        legacy.inner_tls = None;
        rejected.push(legacy);
        for family in [
            TunnelTransportFamily::LegacyTls,
            TunnelTransportFamily::HttpsWs,
            TunnelTransportFamily::MasqueDerived,
        ] {
            let mut relay = authenticated_h2_relay();
            relay.transport_priority = vec![family];
            rejected.push(relay);
            let mut fallback = authenticated_h2_relay();
            fallback.transport_priority.push(family);
            rejected.push(fallback);
        }
        for udp in [
            vec![],
            vec![TunnelTransportFamily::MasqueDerived],
            vec![
                TunnelTransportFamily::GrpcDatagram,
                TunnelTransportFamily::MasqueDerived,
            ],
        ] {
            let mut relay = authenticated_h2_relay();
            relay.udp_transport_priority = Some(udp);
            rejected.push(relay);
        }
        let mut unspecified_udp = authenticated_h2_relay();
        unspecified_udp.udp_transport_priority = None;
        rejected.push(unspecified_udp);
        for relay in rejected {
            let mut cfg = Settings {
                mode: Mode::Relay,
                relay,
                ..Default::default()
            };
            cfg.ingress.allow_fallback = false;
            // Invoke the actual entry point. Pure protocol admission must fail
            // before signal registration, utun/socket open or policy.prepare.
            let error = run(cfg, &args, None).await.unwrap_err();
            assert!(
                format!("{error:#}").contains("macOS relay protocol admission"),
                "{error:#}"
            );
        }
    }

    #[tokio::test]
    async fn macos_utun_historical_helper_refuses_admitted_profile_before_native_activation() {
        let args = Args::try_parse_from([
            "aegis-client",
            "--macos-utun",
            "--macos-utun-service",
            "Ethernet",
            "--macos-utun-seconds",
            "10",
        ])
        .unwrap();
        let mut cfg = Settings {
            mode: Mode::Relay,
            relay: authenticated_h2_relay(),
            ..Default::default()
        };
        cfg.ingress.allow_fallback = false;
        let error = run(cfg, &args, None).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(error
            .to_string()
            .contains("dedicated owned worker policy is required"));
    }

    fn process_exists(pid: u32) -> bool {
        // Only inspect a PID obtained from our own Child handle. This does not
        // enumerate, signal or terminate any unrelated process.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    fn sleep_child() -> OwnedPacketChild {
        OwnedPacketChild::new(Command::new("/bin/sleep").arg("60").spawn().unwrap())
    }

    fn wait_for(path: &Path, predicate: impl Fn(&str) -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if fs::read_to_string(path).is_ok_and(|text| predicate(&text)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("isolated process fixture did not become ready");
    }

    fn signal_process_contract(phase: &str, signal: libc::c_int) {
        let temporary = tempfile::tempdir().unwrap();
        let log = temporary.path().join("fixture.log");
        let output = fs::File::create(&log).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "macos_tunnel::tests::macos_utun_signal_process_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("AEGIS_UTUN_SIGNAL_FIXTURE", temporary.path())
            .env("AEGIS_UTUN_SIGNAL_PHASE", phase)
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output));
        let mut fixture = OwnedPacketChild::new(command.spawn().unwrap());
        let spectator = sleep_child();
        let spectator_pid = spectator.0.as_ref().unwrap().id();
        let ready = temporary.path().join("ready");
        wait_for(&ready, |text| !text.is_empty());
        if phase == "inspection" {
            wait_for(&log, |text| text.contains("Packet worker exited;"));
        }
        let worker_pid = fs::read_to_string(&ready).unwrap().parse::<u32>().unwrap();
        let fixture_pid = fixture.0.as_ref().unwrap().id();
        // This is the known isolated fixture owned by this test, never the
        // calling app, an installed Aegis client or a process found by name.
        assert_eq!(unsafe { libc::kill(fixture_pid as libc::pid_t, signal) }, 0);
        let (status, deadline_reached) = fixture
            .wait(&AtomicBool::new(false), Duration::from_secs(10))
            .unwrap();
        assert!(!deadline_reached, "termination did not complete promptly");
        assert!(
            status.success(),
            "fixture failed: {}",
            fs::read_to_string(log).unwrap()
        );
        assert_eq!(
            fs::read_to_string(temporary.path().join("rollback")).unwrap(),
            "owned-worker-reaped"
        );
        if worker_pid != 0 {
            assert!(!process_exists(worker_pid));
        }
        assert!(process_exists(spectator_pid));
        drop(spectator);
    }

    #[test]
    fn macos_utun_sigterm_supervisor_kills_reaps_and_rolls_back() {
        signal_process_contract("active", libc::SIGTERM);
    }

    #[test]
    fn macos_utun_sigterm_during_inspection_rolls_back_promptly() {
        signal_process_contract("inspection", libc::SIGTERM);
    }

    #[test]
    fn macos_utun_sigint_supervisor_still_rolls_back() {
        signal_process_contract("active", libc::SIGINT);
    }

    #[test]
    fn macos_utun_sigterm_worker_readiness_is_cancelled() {
        signal_process_contract("worker-readiness", libc::SIGTERM);
    }

    #[test]
    fn macos_utun_owned_child_deadline_and_drop_reap_only_owned_process() {
        let child = sleep_child();
        let pid = child.0.as_ref().unwrap().id();
        let spectator = sleep_child();
        let spectator_pid = spectator.0.as_ref().unwrap().id();
        let result = supervise_owned_child(
            child,
            &AtomicBool::new(false),
            Duration::from_millis(20),
            Duration::ZERO,
            || {
                assert!(!process_exists(pid));
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(process_exists(spectator_pid));
        drop(spectator);
        assert!(!process_exists(spectator_pid));
    }

    #[test]
    fn macos_utun_supervisor_term_allows_owned_parent_to_reap_network_child() {
        let temporary = tempfile::tempdir().unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "macos_tunnel::tests::macos_utun_signal_process_fixture",
                "--ignored",
                "--test-threads=1",
            ])
            .env_clear()
            .env("AEGIS_UTUN_SIGNAL_FIXTURE", temporary.path())
            .env("AEGIS_UTUN_SIGNAL_PHASE", "owned-parent-cleanup")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut parent = OwnedPacketChild::new(command.spawn().unwrap());
        let ready = temporary.path().join("ready");
        wait_for(&ready, |text| !text.is_empty());
        let network_pid = fs::read_to_string(ready).unwrap().parse::<u32>().unwrap();
        let spectator = sleep_child();
        let spectator_pid = spectator.0.as_ref().unwrap().id();
        let (status, cancelled) = parent
            .wait(&AtomicBool::new(true), Duration::from_secs(60))
            .unwrap();
        assert!(
            cancelled && status.success(),
            "owned parent did not complete graceful cleanup"
        );
        assert_eq!(
            fs::read_to_string(temporary.path().join("rollback")).unwrap(),
            "owned-network-child-reaped"
        );
        assert!(!process_exists(network_pid));
        assert!(process_exists(spectator_pid));
        drop(spectator);
    }

    #[test]
    fn macos_utun_owned_child_receives_exact_owner_without_changing_parent_env() {
        const OWNER: &str = "1234567890abcdef1234567890abcdef";
        let before = std::env::var_os("AEGIS_MACOS_UTUN_SUPERVISOR_OWNER");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "test \"$AEGIS_MACOS_UTUN_SUPERVISOR_OWNER\" = \"$AEGIS_EXPECTED_OWNER\"",
            ])
            .env("AEGIS_MACOS_UTUN_SUPERVISOR_OWNER", "inherited-stale-tag")
            .env("AEGIS_EXPECTED_OWNER", OWNER);
        let mut child = spawn_owned_packet_child(&mut command, OWNER).unwrap();
        let (status, timed_out) = child
            .wait(&AtomicBool::new(false), Duration::from_secs(5))
            .unwrap();
        assert!(!timed_out);
        assert!(status.success());
        assert_eq!(
            std::env::var_os("AEGIS_MACOS_UTUN_SUPERVISOR_OWNER"),
            before
        );
    }

    /// Runs only in an isolated subprocess created by the above process
    /// contracts. No root check, utun, PF, DNS or route command is executed.
    #[test]
    #[ignore = "isolated signal-process fixture"]
    fn macos_utun_signal_process_fixture() {
        let directory = PathBuf::from(std::env::var_os("AEGIS_UTUN_SIGNAL_FIXTURE").unwrap());
        let phase = std::env::var("AEGIS_UTUN_SIGNAL_PHASE").unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let mut termination = TerminationOwner::new().unwrap();
            if phase == "owned-parent-cleanup" {
                let mut network = sleep_child();
                fs::write(
                    directory.join("ready"),
                    network.0.as_ref().unwrap().id().to_string(),
                )
                .unwrap();
                termination.cancelled().await;
                let result = tokio::task::spawn_blocking(move || {
                    network.wait(&AtomicBool::new(true), Duration::from_secs(60))
                })
                .await
                .unwrap()
                .unwrap();
                assert!(result.1);
                fs::write(directory.join("rollback"), "owned-network-child-reaped").unwrap();
                return;
            }
            if phase == "worker-readiness" {
                let (_sender, receiver) = tokio::sync::oneshot::channel();
                fs::write(directory.join("ready"), "0").unwrap();
                assert!(matches!(
                    wait_readiness(receiver, &mut termination, &mut None).await,
                    CaptureReadiness::Cancelled
                ));
                assert!(termination.stopped.load(Ordering::Acquire));
                fs::write(directory.join("rollback"), "owned-worker-reaped").unwrap();
                return;
            }
            let cancelled = termination.stopped.clone();
            let result = tokio::task::spawn_blocking(move || {
                let mut command = Command::new("/bin/sleep");
                command.arg(if phase == "inspection" { "0" } else { "60" });
                let child = command.spawn().unwrap();
                let pid = child.id();
                fs::write(directory.join("ready"), pid.to_string()).unwrap();
                supervise_owned_child(
                    OwnedPacketChild::new(child),
                    &cancelled,
                    Duration::from_secs(60),
                    Duration::from_secs(30),
                    || {
                        assert!(!process_exists(pid));
                        fs::write(directory.join("rollback"), "owned-worker-reaped")?;
                        Ok(())
                    },
                )
            })
            .await
            .unwrap();
            assert!(
                result.is_err(),
                "cancellation must not become a completed capture"
            );
        });
    }
}
