//! Root policy/device owner. Public reviewed intent crosses into this process;
//! private identity, renewal and actual relay processing stay in its child.
use super::{
    policy, worker_accounts,
    worker_launch::{self, VerifiedLaunch},
    worker_pump::PacketPump,
    worker_runtime::WorkerRuntimeProfile,
    ReceiptOwner, TerminationOwner,
};
use crate::{ingress::wide::macos_utun::Utun, Args};
use anyhow::{ensure, Context, Result};
use rand::RngCore;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

pub(crate) fn parse_digest(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected a canonical SHA-256 digest".into());
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| "digest rejected".to_owned())?;
    Ok(bytes)
}

fn validate_intent(args: &Args) -> Result<()> {
    ensure!(
        args.macos_utun
            && !args.macos_utun_disconnect
            && args.macos_utun_disconnect_owner.is_none()
            && args.command.is_none()
            && !args.version
            && !args.validate_config
            && args.device_online_bundle.is_none(),
        "the policy parent requires only its public worker profile"
    );
    ensure!(
        args.macos_utun_worker_profile.is_some()
            && args.macos_utun_worker_profile_sha256.is_some()
            && args.macos_utun_worker_executable_sha256.is_some()
            && args.macos_utun_worker_account.is_some()
            && args.macos_utun_service.is_some(),
        "the policy parent requires an explicit worker profile, reviewed hashes, account and network service"
    );
    Ok(())
}

pub(crate) async fn run(args: &Args) -> Result<()> {
    validate_intent(args)?;
    policy::root_vm()?;
    let args = args.clone();
    let termination = TerminationOwner::new().context("install parent termination handlers")?;
    let stopped = termination.stopped.clone();
    let result = tokio::task::spawn_blocking(move || run_blocking(&args, stopped))
        .await
        .context("owned policy parent failed")?;
    drop(termination);
    result
}

fn owner() -> Result<ReceiptOwner> {
    if let Some(owner) = std::env::var_os("AEGIS_MACOS_UTUN_SUPERVISOR_OWNER") {
        return owner
            .to_str()
            .context("supervisor ownership tag rejected")?
            .parse()
            .map_err(Into::into);
    }
    let mut bytes = [0; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .context("generate policy owner")?;
    hex::encode(bytes).parse().map_err(Into::into)
}

/// Recheck after every potentially slow admission operation. Grant checks are
/// separate and cannot authorize frames beyond the parent's capture interval.
fn capture_running(stopped: &AtomicBool, until_ns: u64) -> Result<bool> {
    ensure!(
        !stopped.load(Ordering::Acquire),
        "owned capture cancelled during check"
    );
    Ok(worker_launch::monotonic_ns()? < until_ns)
}

fn completed_cutoff(
    error: &std::io::Error,
    cutoff_observed_by_admission: bool,
    stopped: &AtomicBool,
    until_ns: u64,
) -> std::io::Result<bool> {
    Ok(cutoff_observed_by_admission
        && error.kind() == std::io::ErrorKind::TimedOut
        && !stopped.load(Ordering::Acquire)
        && worker_launch::monotonic_ns()? >= until_ns)
}

fn run_blocking(args: &Args, stopped: Arc<AtomicBool>) -> Result<()> {
    let profile_path = args
        .macos_utun_worker_profile
        .as_deref()
        .context("--macos-utun-worker-profile is required")?;
    let profile_digest = args
        .macos_utun_worker_profile_sha256
        .context("worker profile digest required")?;
    let executable_digest = args
        .macos_utun_worker_executable_sha256
        .context("worker executable digest required")?;
    let account_name = args
        .macos_utun_worker_account
        .as_deref()
        .context("dedicated worker account required")?;
    let service = args
        .macos_utun_service
        .as_deref()
        .context("--macos-utun-service is required")?;
    let profile = WorkerRuntimeProfile::open(profile_path, &profile_digest)?;
    ensure!(
        profile.run_seconds() == args.macos_utun_seconds
            && (10..=300).contains(&profile.run_seconds()),
        "parent and worker capture intervals differ or exceed the VM budget"
    );
    ensure!(
        profile.mtu() == 1280,
        "this reviewed VM policy requires MTU 1280"
    );
    let executable = std::env::current_exe()?;
    let launch = VerifiedLaunch::prepare(
        account_name,
        &executable,
        executable_digest,
        profile.identity(),
        profile_path,
        profile_digest,
    )?;
    let account = worker_accounts::discover(account_name)?;
    let owner = owner()?;
    ensure!(
        !stopped.load(Ordering::Acquire),
        "parent cancelled before policy setup"
    );
    policy::ensure_no_active_receipt()?;
    let mut device = Utun::open()?;
    let mut policy = policy::WorkerPolicy::prepare_worker(
        &device.name,
        service,
        &account,
        owner.as_str(),
        profile.authority_pins(),
        profile.relay_pins(),
    )?;
    eprintln!(
        "Owned VM policy prepared; receipt owner: {}",
        owner.as_str()
    );
    if stopped.load(Ordering::Acquire) {
        // No launch was attempted; do not mint an absent Child's exit proof.
        let guard = policy.retain_guard(owner.as_str());
        anyhow::bail!(if guard.is_ok() {
            "parent cancelled during policy setup; unbound retained receipt requires reconciliation"
        } else {
            "parent cancelled during policy setup; guard restriction unconfirmed, INCOMPLETE"
        });
    }
    let mut worker = match launch.spawn(Duration::from_secs(3)) {
        Ok(worker) => worker,
        Err(error) => {
            // A launch error does not prove that no process briefly existed.
            // Close network exceptions, retain the unconfirmed receipt.
            let guard = policy.retain_guard(owner.as_str());
            return Err(error).context(if guard.is_ok() {
                "worker launch failed; retained guard requires reconciliation"
            } else {
                "worker launch and guard restriction unconfirmed; INCOMPLETE"
            });
        }
    };
    let mut pump = PacketPump::new();
    let session = (|| -> Result<_> {
        policy.bind_worker(owner.as_str(), &account, &worker)?;
        ensure!(
            !stopped.load(Ordering::Acquire),
            "parent cancelled before identity readiness"
        );
        let prepared = worker.await_identity_prepared(Duration::from_secs(25))?;
        ensure!(
            !stopped.load(Ordering::Acquire),
            "parent cancelled during identity preparation"
        );
        policy.authorize_relay(owner.as_str(), &account, &prepared, &mut worker)?;
        ensure!(
            !stopped.load(Ordering::Acquire),
            "parent cancelled during relay permission setup"
        );
        worker.permit_relay(&prepared, Duration::from_secs(3))?;
        ensure!(
            !stopped.load(Ordering::Acquire),
            "parent cancelled before live relay ACK"
        );
        let mut grant = worker.await_capture_admission(Duration::from_secs(5))?;
        let ready_ns = worker_launch::monotonic_ns()?;
        ensure!(
            !stopped.load(Ordering::Acquire),
            "parent cancelled before capture"
        );
        policy.activate_capture(owner.as_str(), &account, &grant, &mut worker)?;
        policy.check_capture(owner.as_str(), &account, &grant, &mut worker)?;
        ensure!(
            !stopped.load(Ordering::Acquire),
            "parent cancelled during capture activation"
        );
        let capture_started_ns = worker_launch::monotonic_ns()?;
        let capture_until_ns = capture_started_ns
            .checked_add(
                profile
                    .run_seconds()
                    .checked_mul(1_000_000_000)
                    .context("capture interval overflow")?,
            )
            .context("capture deadline overflow")?;
        let mut refreshed_ns = capture_started_ns;
        let mut checked_ns = capture_started_ns;
        let pins: Vec<IpAddr> = profile
            .authority_pins()
            .iter()
            .chain(profile.relay_pins())
            .map(|p| p.ip())
            .collect();
        let routable = policy.routable_ips();
        eprintln!("Owned VM packet capture active; bounded interval {}s. Guard requires explicit owned disconnect.", profile.run_seconds());
        loop {
            ensure!(!stopped.load(Ordering::Acquire), "owned capture cancelled");
            ensure!(
                grant.is_current_for(&mut worker)?,
                "owned capture grant expired or child exited"
            );
            let now = worker_launch::monotonic_ns()?;
            if now >= capture_until_ns {
                break;
            }
            if now.saturating_sub(refreshed_ns) >= 1_000_000_000 {
                grant = worker.await_capture_admission(Duration::from_secs(5))?;
                policy.check_capture(owner.as_str(), &account, &grant, &mut worker)?;
                refreshed_ns = worker_launch::monotonic_ns()?;
                checked_ns = refreshed_ns;
            } else if now.saturating_sub(checked_ns) >= 2_000_000_000 {
                policy.check_capture(owner.as_str(), &account, &grant, &mut worker)?;
                checked_ns = worker_launch::monotonic_ns()?;
            }
            // A slow native policy check or ACK never extends either process's
            // grant. Check again immediately before admitting any next frame.
            ensure!(
                grant.is_current_for(&mut worker)?,
                "owned capture grant expired during check"
            );
            if !capture_running(&stopped, capture_until_ns)? {
                break;
            }
            let mut watched = PinnedDevice {
                device: &mut device,
                pins: &pins,
                routable: &routable,
            };
            let mut cutoff_observed = false;
            let step = pump.step_admitted(&mut watched, &mut worker.port, || {
                if stopped.load(Ordering::Acquire) {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                if worker_launch::monotonic_ns()? >= capture_until_ns {
                    cutoff_observed = true;
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                if !grant.is_unexpired()? {
                    return Err(std::io::ErrorKind::PermissionDenied.into());
                }
                Ok(())
            });
            if let Err(error) = step {
                // Only the independently observed configured cutoff ends a
                // successful interval; revocation/cancellation/I/O stay errors.
                if completed_cutoff(&error, cutoff_observed, &stopped, capture_until_ns)? {
                    break;
                }
                return Err(error.into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(serde_json::json!({
            "schema": "aegis_macos_owned_capture_interval_v1",
            "clock": "darwin_continuous_monotonic_ns",
            "live_policy_ack_ready_ns": ready_ns,
            "capture_started_ns": capture_started_ns,
            "capture_end_observed_ns": worker_launch::monotonic_ns()?,
            "configured_seconds": profile.run_seconds(),
            "target_delivery_verified": false,
            "independent_capture_verified": false
        }))
    })();
    // Stop accepting/holding frames first. Confirm exact owned child reap and
    // persist its typed receipt before independent disconnect can remove PF.
    pump.stop();
    let exit = worker.cancel_owned(Duration::from_secs(2));
    let confirmation = exit.as_ref().map_err(|_| ()).and_then(|exit| {
        policy
            .confirm_worker_exit(owner.as_str(), &account, exit)
            .map_err(|_| ())
    });
    // Restrict exceptions even on an unconfirmed exit. The typed receipt stays
    // unconfirmed and an independent rollback must then refuse restoration.
    let guard = policy.retain_guard(owner.as_str());
    ensure!(
        exit.is_ok() && confirmation.is_ok() && guard.is_ok(),
        "owned worker exit or retained guard unconfirmed; INCOMPLETE, no disconnect authorized"
    );
    let report = session?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

struct PinnedDevice<'a> {
    device: &'a mut Utun,
    pins: &'a [IpAddr],
    routable: &'a [IpAddr],
}
impl crate::ingress::wide::ip_tunnel::PacketIo for PinnedDevice<'_> {
    fn receive(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let packet = self.device.receive()?;
        if let Some(destination) = packet
            .as_ref()
            .and_then(|p| crate::ingress::wide::linux_nfqueue::decode_packet(p).ok())
            .map(|p| p.dst())
            .filter(|ip| self.pins.contains(ip))
        {
            if !self.routable.contains(&destination) {
                return Ok(None);
            }
            return Err(std::io::Error::other(
                "physical pin entered utun; recursive dial refused",
            ));
        }
        Ok(packet)
    }
    fn send(&mut self, packet: &[u8]) -> std::io::Result<()> {
        self.device.send(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ingress::wide::ip_tunnel::PacketIo,
        macos_tunnel::worker_ipc::{Limits, PacketPort, Role},
    };
    use clap::Parser;
    use std::{io, os::unix::net::UnixStream};

    fn explicit_args() -> Args {
        Args::try_parse_from([
            "aegis-client",
            "--macos-utun",
            "--macos-utun-worker-profile",
            "/var/db/aegis-worker/public.json",
            "--macos-utun-worker-profile-sha256",
            &"ab".repeat(32),
            "--macos-utun-worker-executable-sha256",
            &"cd".repeat(32),
            "--macos-utun-worker-account",
            "_aegis_example",
            "--macos-utun-service",
            "Ethernet",
        ])
        .unwrap()
    }

    #[test]
    fn explicit_public_intent_refuses_private_bundle_or_missing_launch_proof() {
        let mut args = explicit_args();
        validate_intent(&args).unwrap();
        args.device_online_bundle = Some("/unread/private/bundle.json".into());
        assert!(validate_intent(&args).is_err());
        args.device_online_bundle = None;
        args.macos_utun_worker_executable_sha256 = None;
        assert!(validate_intent(&args).is_err());
        assert!(
            validate_intent(&Args::try_parse_from(["aegis-client", "--macos-utun"]).unwrap())
                .is_err()
        );
    }

    #[test]
    fn cli_worker_hashes_require_capture_and_canonical_digest() {
        assert!(Args::try_parse_from([
            "aegis-client",
            "--macos-utun-worker-profile-sha256",
            &"ab".repeat(32)
        ])
        .is_err());
        for digest in ["AB".repeat(32), "ab".repeat(31), "gg".repeat(32)] {
            assert!(Args::try_parse_from([
                "aegis-client",
                "--macos-utun",
                "--macos-utun-worker-executable-sha256",
                &digest
            ])
            .is_err());
        }
    }

    struct UnreadDevice(usize);
    impl PacketIo for UnreadDevice {
        fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
            self.0 += 1;
            let mut packet = vec![0; 20];
            packet[0] = 0x40;
            Ok(Some(packet))
        }
        fn send(&mut self, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn native_clock_cutoff_after_slow_check_leaves_real_packet_peer_empty() {
        let (a, b) = UnixStream::pair().unwrap();
        let (mut parent, _) = PacketPort::new(a, Role::Parent, Limits::default()).unwrap();
        let (mut peer, _) = PacketPort::new(b, Role::Worker, Limits::default()).unwrap();
        let stopped = AtomicBool::new(false);
        let until = worker_launch::monotonic_ns()
            .unwrap()
            .checked_add(1_000_000)
            .unwrap();
        // A slow ACK/policy operation can consume the remaining interval.
        std::thread::sleep(Duration::from_millis(20));
        let mut device = UnreadDevice(0);
        let mut pump = PacketPump::new();
        if capture_running(&stopped, until).unwrap() {
            pump.step(&mut device, &mut parent).unwrap();
        }
        assert_eq!(device.0, 0);
        assert!(peer.receive().unwrap().is_none());
    }

    #[test]
    fn cancellation_during_check_refuses_before_reading_an_owned_frame() {
        let stopped = AtomicBool::new(false);
        let until = worker_launch::monotonic_deadline(Duration::from_secs(1)).unwrap();
        stopped.store(true, Ordering::Release);
        assert!(capture_running(&stopped, until).is_err());
    }

    #[test]
    fn slow_device_operation_expires_native_cutoff_before_queued_peer_delivery() {
        use std::sync::atomic::AtomicU64;
        struct SlowDevice<'a> {
            cutoff: &'a AtomicU64,
            delivered: usize,
        }
        impl PacketIo for SlowDevice<'_> {
            fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
                self.cutoff.store(
                    worker_launch::monotonic_ns()?
                        .checked_add(1_000_000)
                        .unwrap(),
                    Ordering::Release,
                );
                std::thread::sleep(Duration::from_millis(20));
                Ok(None)
            }
            fn send(&mut self, _: &[u8]) -> io::Result<()> {
                self.delivered += 1;
                Ok(())
            }
        }
        let (a, b) = UnixStream::pair().unwrap();
        let (mut parent, _) = PacketPort::new(a, Role::Parent, Limits::default()).unwrap();
        let (mut peer, _) = PacketPort::new(b, Role::Worker, Limits::default()).unwrap();
        let mut packet = vec![0; 40];
        packet[0] = 0x60;
        peer.send(&packet).unwrap();
        let cutoff = AtomicU64::new(u64::MAX);
        let mut device = SlowDevice {
            cutoff: &cutoff,
            delivered: 0,
        };
        let mut pump = PacketPump::new();
        let error = pump
            .step_admitted(&mut device, &mut parent, || {
                if worker_launch::monotonic_ns()? >= cutoff.load(Ordering::Acquire) {
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(device.delivered, 0);
        assert_eq!(
            pump.step(&mut device, &mut parent).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[test]
    fn genuine_slow_io_timeout_is_not_a_successful_admission_cutoff() {
        use std::sync::atomic::AtomicU64;
        struct TimeoutDevice<'a>(&'a AtomicU64);
        impl PacketIo for TimeoutDevice<'_> {
            fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
                self.0
                    .store(worker_launch::monotonic_ns()?, Ordering::Release);
                std::thread::sleep(Duration::from_millis(20));
                Err(io::ErrorKind::TimedOut.into())
            }
            fn send(&mut self, _: &[u8]) -> io::Result<()> {
                panic!("timed out device must not deliver queued responses")
            }
        }
        let (a, b) = UnixStream::pair().unwrap();
        let (mut parent, _) = PacketPort::new(a, Role::Parent, Limits::default()).unwrap();
        let (_peer, _) = PacketPort::new(b, Role::Worker, Limits::default()).unwrap();
        let cutoff = AtomicU64::new(u64::MAX);
        let stopped = AtomicBool::new(false);
        let mut cutoff_observed = false;
        let mut device = TimeoutDevice(&cutoff);
        let error = PacketPump::new()
            .step_admitted(&mut device, &mut parent, || {
                if worker_launch::monotonic_ns()? >= cutoff.load(Ordering::Acquire) {
                    cutoff_observed = true;
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        let until = cutoff.load(Ordering::Acquire);
        assert!(worker_launch::monotonic_ns().unwrap() >= until);
        assert!(!cutoff_observed);
        assert!(!completed_cutoff(&error, cutoff_observed, &stopped, until).unwrap());
        assert!(completed_cutoff(&error, true, &stopped, until).unwrap());
        stopped.store(true, Ordering::Release);
        assert!(!completed_cutoff(&error, true, &stopped, until).unwrap());
    }
}
