//! IPv6 TUN route policy: prefix-lab planning + a GUARDED default-route dry-run.
//!
//! This moves the controlled IPv6 TUN beyond a single `/128` toward a
//! production-like route policy WITHOUT ever applying a default (`::/0`) route by
//! default. The dry-run computes exactly which routes WOULD change, how the
//! relay/control endpoints are excluded to prevent a relay loop, and the precise
//! rollback — then applies nothing. It is the safe gate before any guarded live
//! `::/0` test.

#![cfg(target_os = "linux")]
#![allow(dead_code)]

use serde::Serialize;
use std::net::IpAddr;

/// Route policy modes (vocabulary shared with the operator selector).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6RoutePolicy {
    /// Proven single controlled /128 (point-to-point peer).
    Controlled,
    /// Controlled ULA prefix (e.g. fd00:ae61::/64), multiple controlled peers.
    PrefixLab,
    /// Compute intended ::/0 changes + rollback; apply NOTHING (artifact only).
    DefaultDryRun,
    /// Optional live ::/0 — only with explicit approval + watchdog (not here).
    DefaultGuarded,
}

impl Ipv6RoutePolicy {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Controlled => "ipv6-tun-controlled",
            Self::PrefixLab => "ipv6-tun-prefix-lab",
            Self::DefaultDryRun => "ipv6-tun-default-dry-run",
            Self::DefaultGuarded => "ipv6-tun-default-guarded",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DefaultRouteDryRun {
    pub policy: &'static str,
    pub verdict: &'static str,
    /// Exact commands that WOULD be run to capture IPv6 via the TUN.
    pub planned_route_commands: Vec<String>,
    /// More-specific exclusion routes that keep the relay/control endpoints off
    /// the TUN (relay-loop prevention).
    pub relay_loop_prevention: Vec<String>,
    /// Exact rollback commands to restore the prior default route.
    pub rollback_commands: Vec<String>,
    /// Always false here: the dry-run NEVER changes a default route.
    pub default_route_changed: bool,
    pub ifname: String,
    pub notes: Vec<String>,
}

/// Compute the guarded default-route dry-run. Pure: no command is executed, no
/// route is changed. `relay_excludes` are the relay/server/control endpoints
/// that must stay on their normal path to avoid a tunnel-through-itself loop.
pub fn default_route_dry_run(ifname: &str, relay_excludes: &[IpAddr]) -> DefaultRouteDryRun {
    let mut planned = vec![
        format!("ip link add {ifname} type tun  # AEGIS-owned, non-persistent in practice"),
        format!("ip link set {ifname} up"),
        format!("ip -6 addr add fd00:ae61::1/128 dev {ifname}"),
        // Two /1 halves are the standard "default but lower priority than a host
        // exclusion" trick so excludes win without deleting the real ::/0.
        format!("ip -6 route add ::/1 dev {ifname} metric 100"),
        format!("ip -6 route add 8000::/1 dev {ifname} metric 100"),
    ];
    planned.push(
        "# NOTE: applied only under ipv6-tun-default-guarded with explicit approval + watchdog"
            .into(),
    );

    let mut prevention: Vec<String> = Vec::new();
    for ex in relay_excludes {
        match ex {
            IpAddr::V6(v6) => prevention.push(format!(
                "ip -6 route add {v6}/128 via <current-gw> dev <wan>  # keep relay/control off the tun"
            )),
            IpAddr::V4(v4) => prevention.push(format!(
                "# relay endpoint {v4} is IPv4 — unaffected by the IPv6 ::/0 policy"
            )),
        }
    }
    if prevention.is_empty() {
        prevention
            .push("# no relay excludes supplied — a guarded live run MUST supply them".into());
    }

    let rollback = vec![
        format!("ip -6 route del ::/1 dev {ifname} metric 100"),
        format!("ip -6 route del 8000::/1 dev {ifname} metric 100"),
        format!("ip link del {ifname}"),
        "# original ::/0 default route is never deleted, so nothing to restore".into(),
    ];

    DefaultRouteDryRun {
        policy: Ipv6RoutePolicy::DefaultDryRun.slug(),
        verdict: "DRY_RUN_PASS",
        planned_route_commands: planned,
        relay_loop_prevention: prevention,
        rollback_commands: rollback,
        default_route_changed: false,
        ifname: ifname.to_string(),
        notes: vec![
            "Uses ::/1 + 8000::/1 (not literal ::/0) so host-specific relay excludes win and the real ::/0 default is never deleted.".into(),
            "Relay/control endpoints excluded to prevent the tunnel from capturing its own egress (relay loop).".into(),
            "No command here is executed; this is a plan + rollback record only.".into(),
            "Not a production claim: live ::/0 requires ipv6-tun-default-guarded with explicit approval, watchdog rollback, and soak/perf.".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_never_changes_default_route() {
        let r = default_route_dry_run("aegis-tun0", &["2606:4700:4700::1111".parse().unwrap()]);
        assert!(!r.default_route_changed);
        assert_eq!(r.verdict, "DRY_RUN_PASS");
        // Must not emit a literal `route add ::/0` (we use the ::/1 split).
        assert!(!r
            .planned_route_commands
            .iter()
            .any(|c| c.contains("::/0 dev")));
        assert!(r
            .relay_loop_prevention
            .iter()
            .any(|c| c.contains("off the tun") || c.contains("unaffected")));
    }

    #[test]
    fn rollback_is_recorded() {
        let r = default_route_dry_run("aegis-tun0", &[]);
        assert!(r.rollback_commands.iter().any(|c| c.contains("link del")));
    }
}
