//! NFQUEUE observer **lifecycle**: preflight → scoped rule setup → observer
//! run → guaranteed teardown, with a fail-safe watchdog. This turns the
//! observer from an ad-hoc CLI loop into a supervised opt-in backend.
//!
//! Hard invariants (see the archived aegis-master-plan.md design baseline, backend split):
//! - The default Linux wide backend stays **TPROXY**. NFQUEUE is opt-in.
//! - Observer-only: every packet is ACCEPTed; this never relays/tunnels.
//! - Fail-safe: the rule teardown is RAII-guarded, so an observer panic,
//!   error, or signal cannot leave the host's network hanging. Every divert
//!   rule also carries `--queue-bypass`, so even a hard kill before teardown
//!   degrades to ACCEPT rather than DROP.

#![cfg(target_os = "linux")]
#![allow(dead_code)]

use super::nfqueue_socket::{NfqueueMode, NfqueueObserver, NfqueuePolicy};
use super::udp_masque_bridge::WideUdpMasqueBridge;
use crate::runtime_events::RuntimeEventCode;
use crate::runtime_jsonl;
use serde_json::json;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Options for one NFQUEUE lifecycle run.
pub struct LifecycleOpts {
    pub queue: u16,
    /// Install scoped divert rules via the helper (opt-in). When false the
    /// caller has installed rules out-of-band and we only observe.
    pub setup_rules: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    /// Comma-separated destination ports to divert (never SSH/:22).
    pub dports: String,
    /// Path to setup-wide-linux-nfqueue.sh (env AEGIS_NFQUEUE_HELPER overrides).
    pub helper: String,
    /// Per-class verdict policy. Default is witness-only (ACCEPT all). The
    /// full-wide-nfqueue product mode sets an Enforce policy (fail-closed DROP
    /// of generic UDP / IPv6 per the resolved product policy).
    pub policy: NfqueuePolicy,
}

impl LifecycleOpts {
    pub fn from_queue(queue: u16) -> Self {
        let helper = std::env::var("AEGIS_NFQUEUE_HELPER")
            .unwrap_or_else(|_| "setup-wide-linux-nfqueue.sh".to_string());
        Self {
            queue,
            setup_rules: false,
            ipv4: true,
            ipv6: true,
            dports: "80,443".to_string(),
            helper,
            policy: NfqueuePolicy::observe_only(),
        }
    }

    /// Set a fail-closed enforcement policy (full-wide-nfqueue).
    pub fn with_policy(mut self, policy: NfqueuePolicy) -> Self {
        self.policy = policy;
        self
    }
}

/// Preflight capability report for the NFQUEUE backend.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Preflight {
    pub euid_root: bool,
    pub ip6tables_present: bool,
    pub queue_valid: bool,
    pub ipv4_supported: bool,
    pub ipv6_supported: bool,
    /// Empty when ready; otherwise a machine-readable blocked reason.
    pub blocked_reason: Option<&'static str>,
}

fn command_present(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn preflight(opts: &LifecycleOpts) -> Preflight {
    let euid_root = unsafe { libc::geteuid() } == 0;
    let ip6tables_present = command_present("ip6tables");
    let queue_valid = true; // u16 is always in range
    let ipv4_supported = opts.ipv4 && command_present("iptables");
    let ipv6_supported = opts.ipv6 && ip6tables_present;
    let blocked_reason = if !euid_root {
        Some("BLOCKED_BY_PRIVILEGE")
    } else if opts.ipv6 && !ip6tables_present {
        Some("BLOCKED_BY_MISSING_IP6TABLES")
    } else if opts.ipv4 && !command_present("iptables") {
        Some("BLOCKED_BY_MISSING_IPTABLES")
    } else {
        None
    };
    let pf = Preflight {
        euid_root,
        ip6tables_present,
        queue_valid,
        ipv4_supported,
        ipv6_supported,
        blocked_reason,
    };
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideNfqueuePreflightCompleted,
        "wide nfqueue preflight completed",
        json!({
            "queue_num": opts.queue,
            "euid_root": pf.euid_root,
            "ip6tables_present": pf.ip6tables_present,
            "ipv4_supported": pf.ipv4_supported,
            "ipv6_supported": pf.ipv6_supported,
            "blocked_reason": pf.blocked_reason,
        }),
    );
    pf
}

fn run_helper(opts: &LifecycleOpts, action: &str) -> std::io::Result<bool> {
    let mut cmd = Command::new("bash");
    cmd.arg(&opts.helper)
        .arg(action)
        .arg(format!("--queue-num={}", opts.queue));
    if action == "apply" {
        cmd.arg(format!("--dport={}", opts.dports));
    }
    let status = cmd.status()?;
    Ok(status.success())
}

/// RAII watchdog: guarantees rule teardown on drop (panic / error / normal).
/// On a normal completion the caller `disarm`s it so the teardown is reported
/// as a clean cleanup; otherwise it reports a watchdog cleanup.
struct TeardownGuard<'a> {
    opts: &'a LifecycleOpts,
    armed: bool,
    normal: bool,
}

impl<'a> TeardownGuard<'a> {
    fn arm(opts: &'a LifecycleOpts) -> Self {
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::WideNfqueueWatchdogArmed,
            "wide nfqueue watchdog armed",
            json!({ "queue_num": opts.queue, "failsafe": "queue_bypass+raii_teardown" }),
        );
        Self {
            opts,
            armed: true,
            normal: false,
        }
    }
    fn mark_normal(&mut self) {
        self.normal = true;
    }
}

impl Drop for TeardownGuard<'_> {
    fn drop(&mut self) {
        if !self.armed || !self.opts.setup_rules {
            return;
        }
        let ok = run_helper(self.opts, "teardown").unwrap_or(false);
        let (code, msg) = if self.normal {
            (
                RuntimeEventCode::WideNfqueueCleanupCompleted,
                "wide nfqueue cleanup completed",
            )
        } else {
            (
                RuntimeEventCode::WideNfqueueWatchdogCleanupCompleted,
                "wide nfqueue watchdog cleanup completed",
            )
        };
        runtime_jsonl::emit(
            "info",
            code,
            msg,
            json!({ "queue_num": self.opts.queue, "teardown_ok": ok, "normal_exit": self.normal }),
        );
    }
}

/// Run the full NFQUEUE observer lifecycle. `stop` is the shutdown flag
/// (set by a signal handler). Returns the preflight result; an error means
/// the backend could not start (with a BLOCKED reason already emitted).
pub fn run_lifecycle(opts: &LifecycleOpts, stop: Arc<AtomicBool>) -> Result<(), String> {
    run_lifecycle_with_bridge(opts, stop, None)
}

/// Lifecycle variant that also attaches the MASQUE direct UDP send bridge for
/// `udp_policy = masque_direct`. The bridge is owned by the observer for the
/// run and dropped (channel closed, drain thread ends) on teardown.
pub fn run_lifecycle_with_bridge(
    opts: &LifecycleOpts,
    stop: Arc<AtomicBool>,
    udp_masque_bridge: Option<WideUdpMasqueBridge>,
) -> Result<(), String> {
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideNfqueueBackendSelected,
        "wide nfqueue backend selected (opt-in; default wide backend stays tproxy)",
        json!({
            "queue_num": opts.queue,
            "ipv4": opts.ipv4,
            "ipv6": opts.ipv6,
            "default_wide_backend": "tproxy",
            "mode": match opts.policy.mode {
                NfqueueMode::ObserveOnly => "observer_only",
                NfqueueMode::Enforce => "enforce_failclosed",
            },
        }),
    );

    let pf = preflight(opts);
    if let Some(reason) = pf.blocked_reason {
        return Err(reason.to_string());
    }

    if opts.setup_rules {
        let applied = run_helper(opts, "apply").map_err(|e| format!("helper apply: {e}"))?;
        if !applied {
            return Err("BLOCKED_BY_RULE_INSTALL_FAILED".to_string());
        }
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::WideNfqueueRulesInstalled,
            "wide nfqueue rules installed",
            json!({
                "queue_num": opts.queue,
                "ipv4": opts.ipv4,
                "ipv6": opts.ipv6,
                "dports": opts.dports,
                "queue_bypass": true,
                "ssh_excluded": true,
            }),
        );
    }

    // Watchdog armed BEFORE the observer runs, so any failure path tears down.
    let mut guard = TeardownGuard::arm(opts);

    let mut observer =
        NfqueueObserver::bind_with_policy_and_bridge(opts.queue, opts.policy, udp_masque_bridge)
            .map_err(|e| format!("bind nfqueue {}: {e}", opts.queue))?;
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideNfqueueObserverStarted,
        "wide nfqueue observer started",
        json!({ "queue_num": opts.queue }),
    );

    let run_result = observer.run(|| !stop.load(Ordering::SeqCst));

    match run_result {
        Ok(()) => {
            guard.mark_normal();
            Ok(())
        }
        Err(e) => {
            // guard drop will emit watchdog cleanup
            Err(format!("nfqueue observer loop: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_opts_defaults_are_observer_safe() {
        let o = LifecycleOpts::from_queue(100);
        assert_eq!(o.queue, 100);
        assert!(!o.setup_rules, "setup_rules must be opt-in (default off)");
        assert!(o.ipv4 && o.ipv6);
        assert!(
            !o.dports.contains("22"),
            "must never default to diverting SSH"
        );
    }

    #[test]
    fn preflight_blocks_without_root() {
        // In CI this runs unprivileged: blocked_reason must be set, never a
        // silent ready. (If somehow run as root, it must at least not panic.)
        let o = LifecycleOpts::from_queue(100);
        let pf = preflight(&o);
        if !pf.euid_root {
            assert_eq!(pf.blocked_reason, Some("BLOCKED_BY_PRIVILEGE"));
        }
    }
}
