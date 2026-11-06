use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The tunnel interface's own addresses. They are never a DNS server.
pub const INTERFACE_V4: Ipv4Addr = Ipv4Addr::new(198, 19, 255, 1);
pub const INTERFACE_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xae61, 0, 0, 0, 0, 0, 1);
/// The in-tunnel DNS anchors the engine answers. The only DNS values admitted
/// inside the reserved tunnel ranges.
pub const DNS_ANCHOR_V4: Ipv4Addr = Ipv4Addr::new(198, 19, 255, 2);
pub const DNS_ANCHOR_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xae61, 0, 0, 0, 0, 0, 2);
/// B-06 S16j-2: the utun's IPv6 network prefix length. The v21 window applied
/// fd00:ae61::1/128 with the IPv6 default route, yet macOS installed no IPv6
/// route on the utun: no unscoped IPv6 default remained, nothing reached
/// fd00:ae61::2, and IPv6 was blocked rather than tunneled. A /128 has no
/// on-link prefix and the IPv6 side has no peer. A /120 (WireGuard's Apple
/// client clamps longer prefixes the same way) puts DNS_ANCHOR_V6 on-link
/// through the utun and stays inside the reserved fd00:ae61::/32.
pub const INTERFACE_V6_PREFIX: u8 = 120;
const _: () = assert!(interface_v6_prefix_admitted(INTERFACE_V6_PREFIX));

/// A utun IPv6 prefix length is admitted when INTERFACE_V6/`prefix` contains
/// DNS_ANCHOR_V6 (so the anchor is on-link) and lies inside fd00:ae61::/32.
pub const fn interface_v6_prefix_admitted(prefix: u8) -> bool {
    if prefix < 32 || prefix > 127 {
        return false;
    }
    let mask = u128::MAX << (128 - prefix as u32);
    let interface = u128::from_be_bytes(INTERFACE_V6.octets());
    let anchor = u128::from_be_bytes(DNS_ANCHOR_V6.octets());
    interface & mask == anchor & mask
}

/// B-06 S16j-2: whether a native packet from packetFlow may enter the engine.
/// With both default routes and the on-link IPv6 prefix, the kernel sends
/// every destination in 198.19.255.0/24 and fd00:ae61::/32 into the utun.
/// The engine serves only DNS there (UDP or TCP to port 53 on a DNS anchor)
/// and would forward any other such flow to the relay as a literal address,
/// so it is dropped here: another tunnel-local address, another port or
/// protocol on an anchor, and an anchor packet whose transport ports are not
/// in it (an IPv6 extension header). Every fragment to an anchor is dropped,
/// the first one included: the engine reassembles before it decodes, so the
/// whole datagram has to be judged, and later fragments carry no ports. A
/// first fragment alone would only wait out the reassembly expiry, and
/// admitting every fragment would let a reassembled datagram to another
/// anchor port reach the relay. Fragmented DNS to an anchor is therefore
/// unanswerable, over IPv4 as over IPv6 (Fragment header). Fake IPs
/// (198.18.0.0/16) and every other destination pass. A packet the bridge
/// refuses (`validate_packet`) passes too, so the bridge still decides it
/// exactly as before.
pub fn native_packet_admitted(packet: &[u8]) -> bool {
    if crate::bridge::validate_packet(packet).is_err() {
        return true;
    }
    let (destination, protocol, transport) = match packet[0] >> 4 {
        4 => {
            let header = usize::from(packet[0] & 15) * 4;
            // More Fragments (0x2000) or a non-zero offset (0x1fff).
            let unfragmented = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff == 0;
            let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let transport = unfragmented.then(|| &packet[header..]);
            (IpAddr::V4(destination), packet[9], transport)
        }
        _ => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            (
                IpAddr::V6(Ipv6Addr::from(octets)),
                packet[6],
                Some(&packet[40..]),
            )
        }
    };
    if !tunnel_local(destination) {
        return true;
    }
    let anchor =
        destination == IpAddr::V4(DNS_ANCHOR_V4) || destination == IpAddr::V6(DNS_ANCHOR_V6);
    let port = transport
        .filter(|_| protocol == 6 || protocol == 17)
        .and_then(|t| t.get(2..4))
        .map(|p| u16::from_be_bytes([p[0], p[1]]));
    anchor && port == Some(53)
}

// The tunnel's own interface and anchor ranges, without the fake-IP pool.
fn tunnel_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            (a, b, c) == (198, 19, 255)
        }
        IpAddr::V6(v6) => {
            let [a, b, ..] = v6.segments();
            (a, b) == (0xfd00, 0xae61)
        }
    }
}

// 198.19.255.0/24 (interface and anchors), 198.18.0.0/16 and fd00:ae61::/32
// belong to the tunnel. A relay there would route its own carrier into the
// tunnel; a DNS server there other than an anchor is unanswered.
fn tunnel_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            (a, b) == (198, 18) || (a, b, c) == (198, 19, 255)
        }
        IpAddr::V6(v6) => {
            let [a, b, ..] = v6.segments();
            (a, b) == (0xfd00, 0xae61)
        }
    }
}

fn admitted_relay(ip: IpAddr) -> bool {
    usable_unscoped_endpoint(ip) && !tunnel_reserved(ip)
}

fn admitted_dns(ip: IpAddr) -> bool {
    usable_unscoped_endpoint(ip)
        && (!tunnel_reserved(ip)
            || ip == IpAddr::V4(DNS_ANCHOR_V4)
            || ip == IpAddr::V6(DNS_ANCHOR_V6))
}

// The manager serializes these as numeric, unscoped addresses. An IPv4-mapped
// IPv6 value can hide an IPv4 loopback/unspecified address from IpAddr's
// top-level predicates, and a link-local address needs interface scope that
// this policy cannot carry.
fn usable_unscoped_endpoint(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_multicast()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            !v6.is_unspecified()
                && !v6.is_multicast()
                && !v6.is_loopback()
                && !v6.is_unicast_link_local()
                && v6.to_ipv4_mapped().is_none()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullWide {
    relay: IpAddr,
    mtu: u16,
    dns: Vec<IpAddr>,
}
impl FullWide {
    pub fn new(relay: IpAddr, dns: Vec<IpAddr>, mtu: u16) -> Result<Self, &'static str> {
        if !admitted_relay(relay)
            || !(1280..=1500).contains(&mtu)
            || dns.is_empty()
            || dns.len() > 2
            || dns.iter().any(|ip| !admitted_dns(*ip))
        {
            return Err("invalid_fullwide_policy");
        }
        Ok(Self { relay, dns, mtu })
    }
    /// Lib-test relay on 127.0.0.1 only. A signed full-wide profile pins an
    /// IPv4 relay, so ::1 could never pair with an admitted bundle. Production
    /// manager and runtime parsing use `new`, which refuses every loopback.
    #[cfg(test)]
    pub(crate) fn for_test_loopback(
        relay: IpAddr,
        dns: Vec<IpAddr>,
        mtu: u16,
    ) -> Result<Self, &'static str> {
        if relay != IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
            return Err("invalid_fullwide_policy");
        }
        let checked = Self::new("192.0.2.1".parse().expect("fixed address"), dns, mtu)?;
        Ok(Self { relay, ..checked })
    }
    pub fn relay(&self) -> IpAddr {
        self.relay
    }
    pub fn mtu(&self) -> u16 {
        self.mtu
    }
    pub fn dns(&self) -> &[IpAddr] {
        &self.dns
    }
    // Full IPv4 and IPv6 inclusion. DNS catch-all applies to all domains.
    pub fn routes(&self) -> [&'static str; 2] {
        ["0.0.0.0/0", "::/0"]
    }
    pub fn dns_match_domains(&self) -> [&'static str; 1] {
        [""]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    // Admitted: the session exists and is Constructing; start is pending.
    Admitted,
    // The session reported Ready; network settings are being applied.
    Applying,
    Running,
    // S17: the running session was lost recoverably. The applied network
    // settings stay, so nothing leaves outside the tunnel; packets are dropped
    // while a fresh session is built. Never re-applies settings.
    Reasserting,
    // Stopping or failed: waiting for the session's join.
    Blocking,
    Stopped,
}

/// What the provider performs after a transition. The provider holds the
/// completion blocks; the lifecycle decides when each one may run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    /// setTunnelNetworkSettings, at most once per generation.
    ApplySettings,
    /// Complete the pending start with failure, at most once per generation.
    FailStart,
    /// Complete the pending start with success.
    CompleteStart,
    /// Complete Apple's stop. Only a join produces it.
    CompleteStop,
    /// S17: keep the applied settings, set `reasserting`, rebuild a session.
    Reassert,
    /// S17: swap the packet path to the rebuilt session, clear `reasserting`.
    /// Settings are not applied again.
    Reasserted,
}

/// Pure start/stop state of one provider. Every native callback names the
/// generation it belongs to, and a stale generation changes nothing.
#[derive(Debug)]
pub struct Lifecycle {
    pub phase: Phase,
    pub generation: u64,
    start_pending: bool,
    stop_pending: bool,
    // The generation reached Running: its failure waits for Apple's stop.
    ran: bool,
}
impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            generation: 0,
            start_pending: false,
            stop_pending: false,
            ran: false,
        }
    }
}
impl Lifecycle {
    fn current(&self, generation: u64) -> bool {
        self.generation == generation
    }

    fn take_start(&mut self) -> bool {
        std::mem::replace(&mut self.start_pending, false)
    }

    /// A new start: the session is constructed outside any provider lock.
    pub fn admit(&mut self) -> Result<u64, &'static str> {
        if !matches!(self.phase, Phase::Idle | Phase::Stopped) {
            return Err("start_in_progress");
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or("generation_exhausted")?;
        self.phase = Phase::Admitted;
        self.start_pending = true;
        self.stop_pending = false;
        self.ran = false;
        Ok(self.generation)
    }

    /// The constructing session reported Ready.
    pub fn session_ready(&mut self, generation: u64) -> Effect {
        if !self.current(generation) || self.phase != Phase::Admitted || !self.start_pending {
            return Effect::None;
        }
        self.phase = Phase::Applying;
        Effect::ApplySettings
    }

    /// Settings were applied and the output drain is installed.
    pub fn ready(&mut self, generation: u64) -> Result<Effect, &'static str> {
        if !self.current(generation) || self.phase != Phase::Applying {
            return Err("stale_ready");
        }
        self.phase = Phase::Running;
        self.ran = true;
        Ok(if self.take_start() {
            Effect::CompleteStart
        } else {
            Effect::None
        })
    }

    /// S17: the running session was lost recoverably. Only a Running
    /// generation without a pending stop reasserts; the settings stay applied.
    pub fn reassert(&mut self, generation: u64) -> Result<Effect, &'static str> {
        if !self.current(generation) || self.phase != Phase::Running || self.stop_pending {
            return Err("stale_reassert");
        }
        self.phase = Phase::Reasserting;
        Ok(Effect::Reassert)
    }

    /// S17: a rebuilt session is Ready. Back to Running without applying
    /// settings or completing any start again.
    pub fn rebuilt(&mut self, generation: u64) -> Result<Effect, &'static str> {
        if !self.current(generation) || self.phase != Phase::Reasserting {
            return Err("stale_rebuilt");
        }
        self.phase = Phase::Running;
        Ok(Effect::Reasserted)
    }

    /// The session sealed, or the provider refused this generation. Only the
    /// first failure of a live generation acts; the caller then seals and
    /// joins the session.
    pub fn fail(&mut self, generation: u64) -> Result<Effect, &'static str> {
        if !self.current(generation)
            || !matches!(
                self.phase,
                Phase::Admitted | Phase::Applying | Phase::Running | Phase::Reasserting
            )
        {
            return Err("stale_fail");
        }
        self.phase = Phase::Blocking;
        Ok(if self.take_start() {
            Effect::FailStart
        } else {
            Effect::None
        })
    }

    /// Apple's stopTunnel. A duplicate stop is refused. The caller then seals
    /// and joins the session for the returned generation.
    pub fn stop(&mut self) -> Option<(u64, Effect)> {
        if self.stop_pending {
            return None;
        }
        self.stop_pending = true;
        self.phase = Phase::Blocking;
        let effect = if self.take_start() {
            Effect::FailStart
        } else {
            Effect::None
        };
        Some((self.generation, effect))
    }

    /// The session has joined (or none was constructed). A pending stop then
    /// completes; a failed start ends the generation; a failed running
    /// generation waits for Apple's stop.
    pub fn joined(&mut self, generation: u64) -> Effect {
        if !self.current(generation) || self.phase != Phase::Blocking {
            return Effect::None;
        }
        if self.stop_pending {
            self.stop_pending = false;
            self.phase = Phase::Stopped;
            return Effect::CompleteStop;
        }
        if !self.ran {
            self.phase = Phase::Stopped;
        }
        Effect::None
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn running(l: &mut Lifecycle) -> u64 {
        let g = l.admit().unwrap();
        assert_eq!(l.session_ready(g), Effect::ApplySettings);
        assert_eq!(l.ready(g), Ok(Effect::CompleteStart));
        g
    }

    #[test]
    fn stale_settings_completion_cannot_reopen_stopped_owner() {
        let mut l = Lifecycle::default();
        let g = l.admit().unwrap();
        assert_eq!(l.session_ready(g), Effect::ApplySettings);
        assert_eq!(l.stop(), Some((g, Effect::FailStart)));
        assert_eq!(l.joined(g), Effect::CompleteStop);
        assert!(l.ready(g).is_err());
        let next = l.admit().unwrap();
        assert_eq!(l.session_ready(next), Effect::ApplySettings);
        assert!(l.ready(g).is_err());
        assert_eq!(l.session_ready(g), Effect::None);
        assert_eq!(l.phase, Phase::Applying);
    }

    #[test]
    fn lifecycle_constructing_to_ready_applies_settings_exactly_once() {
        let mut l = Lifecycle::default();
        let g = l.admit().unwrap();
        assert_eq!(l.phase, Phase::Admitted);
        // A join observation outside Blocking ends nothing.
        assert_eq!(l.joined(g), Effect::None);
        assert_eq!(l.phase, Phase::Admitted);
        // The notifier and the start path may both report Ready.
        assert_eq!(l.session_ready(g), Effect::ApplySettings);
        for _ in 0..3 {
            assert_eq!(l.session_ready(g), Effect::None);
        }
        assert_eq!(l.ready(g), Ok(Effect::CompleteStart));
        assert!(l.ready(g).is_err());
        assert_eq!(l.session_ready(g), Effect::None);
        assert_eq!(l.phase, Phase::Running);
        assert_eq!(l.joined(g), Effect::None);
        assert_eq!(l.phase, Phase::Running);
        // A stale generation's Ready applies nothing to the current one.
        assert_eq!(l.session_ready(g - 1), Effect::None);
        assert_eq!(l.session_ready(g + 1), Effect::None);
    }

    #[test]
    fn lifecycle_stop_during_constructing_completes_only_after_join() {
        let mut l = Lifecycle::default();
        let g = l.admit().unwrap();
        assert_eq!(l.stop(), Some((g, Effect::FailStart)));
        assert_eq!(l.stop(), None);
        // While the session has not joined, nothing completes the stop and a
        // late Ready or seal applies nothing.
        for _ in 0..3 {
            assert_eq!(l.session_ready(g), Effect::None);
            assert!(l.ready(g).is_err());
            assert!(l.fail(g).is_err());
            assert_eq!(l.phase, Phase::Blocking);
            assert!(l.admit().is_err());
        }
        assert_eq!(l.joined(g - 1), Effect::None);
        assert_eq!(l.phase, Phase::Blocking);
        assert_eq!(l.joined(g), Effect::CompleteStop);
        assert_eq!(l.joined(g), Effect::None);
        assert_eq!(l.phase, Phase::Stopped);
        assert_eq!(l.admit(), Ok(g + 1));
    }

    #[test]
    fn lifecycle_sealed_during_constructing_fails_the_start_exactly_once() {
        let mut l = Lifecycle::default();
        let g = l.admit().unwrap();
        assert_eq!(l.fail(g), Ok(Effect::FailStart));
        assert!(l.fail(g).is_err());
        assert_eq!(l.session_ready(g), Effect::None);
        // A later stop neither fails the start again nor completes unjoined.
        assert_eq!(l.stop(), Some((g, Effect::None)));
        assert_eq!(l.phase, Phase::Blocking);
        assert_eq!(l.joined(g), Effect::CompleteStop);

        // Without Apple's stop, the joined failed start ends its generation.
        let g = l.admit().unwrap();
        assert_eq!(l.fail(g), Ok(Effect::FailStart));
        assert!(l.admit().is_err());
        assert_eq!(l.joined(g), Effect::None);
        assert_eq!(l.phase, Phase::Stopped);
        assert_eq!(l.stop(), Some((g, Effect::None)));
        assert_eq!(l.joined(g), Effect::CompleteStop);

        // A failure while applying settings also fails the start once.
        let g = l.admit().unwrap();
        assert_eq!(l.session_ready(g), Effect::ApplySettings);
        assert_eq!(l.fail(g), Ok(Effect::FailStart));
        assert!(l.ready(g).is_err());
        assert_eq!(l.stop(), Some((g, Effect::None)));
        assert_eq!(l.joined(g), Effect::CompleteStop);
    }

    #[test]
    fn lifecycle_running_failure_waits_for_apple_stop() {
        let mut l = Lifecycle::default();
        let g = running(&mut l);
        assert_eq!(l.fail(g), Ok(Effect::None));
        assert_eq!(l.joined(g), Effect::None);
        assert_eq!(l.phase, Phase::Blocking);
        assert!(l.admit().is_err());
        assert_eq!(l.stop(), Some((g, Effect::None)));
        assert_eq!(l.joined(g), Effect::CompleteStop);
        let g = running(&mut l);
        assert_eq!(l.stop(), Some((g, Effect::None)));
        assert_eq!(l.joined(g), Effect::CompleteStop);
        // A stop before any start completes once its (absent) session joins.
        let mut idle = Lifecycle::default();
        assert_eq!(idle.stop(), Some((0, Effect::None)));
        assert_eq!(idle.joined(0), Effect::CompleteStop);
    }

    #[test]
    fn rebuild_lifecycle_reasserts_and_returns_to_running_without_applying_settings() {
        let mut l = Lifecycle::default();
        let g = running(&mut l);
        assert_eq!(l.reassert(g), Ok(Effect::Reassert));
        assert_eq!(l.phase, Phase::Reasserting);
        // Already reasserting, stale generations and start transitions refuse.
        assert!(l.reassert(g).is_err());
        assert!(l.rebuilt(g - 1).is_err());
        assert!(l.rebuilt(g + 1).is_err());
        assert_eq!(l.session_ready(g), Effect::None);
        assert!(l.ready(g).is_err());
        assert!(l.admit().is_err());
        assert_eq!(l.joined(g), Effect::None);
        assert_eq!(l.phase, Phase::Reasserting);
        // A rebuilt session returns to Running: never ApplySettings again,
        // and no start completion.
        assert_eq!(l.rebuilt(g), Ok(Effect::Reasserted));
        assert_eq!(l.phase, Phase::Running);
        assert!(l.rebuilt(g).is_err());
        assert_eq!(l.session_ready(g), Effect::None);
        assert!(l.ready(g).is_err());
        // Lost again: the same cycle repeats with no give-up.
        for _ in 0..3 {
            assert_eq!(l.reassert(g), Ok(Effect::Reassert));
            assert_eq!(l.rebuilt(g), Ok(Effect::Reasserted));
        }
        // Only Running reasserts.
        let mut fresh = Lifecycle::default();
        let g = fresh.admit().unwrap();
        assert!(fresh.reassert(g).is_err());
        assert_eq!(fresh.session_ready(g), Effect::ApplySettings);
        assert!(fresh.reassert(g).is_err());
        assert_eq!(fresh.phase, Phase::Applying);
    }

    #[test]
    fn rebuild_lifecycle_terminal_failure_while_reasserting_fails_once() {
        let mut l = Lifecycle::default();
        let g = running(&mut l);
        assert_eq!(l.reassert(g), Ok(Effect::Reassert));
        assert_eq!(l.fail(g), Ok(Effect::None));
        assert_eq!(l.phase, Phase::Blocking);
        // Exactly one failure acts: no second cancel, no rebuild after it.
        assert!(l.fail(g).is_err());
        assert!(l.rebuilt(g).is_err());
        assert!(l.reassert(g).is_err());
        // A failed running generation waits for Apple's stop.
        assert_eq!(l.joined(g), Effect::None);
        assert_eq!(l.stop(), Some((g, Effect::None)));
        assert_eq!(l.joined(g), Effect::CompleteStop);
    }

    #[test]
    fn rebuild_lifecycle_stop_while_reasserting_completes_only_after_join() {
        let mut l = Lifecycle::default();
        let g = running(&mut l);
        assert_eq!(l.reassert(g), Ok(Effect::Reassert));
        assert_eq!(l.stop(), Some((g, Effect::None)));
        assert_eq!(l.stop(), None);
        assert_eq!(l.phase, Phase::Blocking);
        // A rebuild finishing after the stop never returns to Running.
        assert!(l.rebuilt(g).is_err());
        assert!(l.reassert(g).is_err());
        assert!(l.fail(g).is_err());
        assert_eq!(l.joined(g - 1), Effect::None);
        assert_eq!(l.joined(g), Effect::CompleteStop);
        assert_eq!(l.phase, Phase::Stopped);
        assert_eq!(l.admit(), Ok(g + 1));
    }

    #[test]
    fn policy_requires_both_families_and_catchall_dns() {
        let p = FullWide::new(
            "192.0.2.1".parse().unwrap(),
            vec!["198.19.255.2".parse().unwrap()],
            1280,
        )
        .unwrap();
        assert_eq!(p.routes(), ["0.0.0.0/0", "::/0"]);
        assert_eq!(p.dns_match_domains(), [""]);
        assert!(FullWide::new(p.relay, vec![], 1280).is_err());
        assert!(FullWide::new(p.relay, p.dns, 1279).is_err());
    }

    #[test]
    fn policy_loopback_relay_is_test_only_and_exact() {
        let dns: Vec<IpAddr> = vec![
            "198.19.255.2".parse().unwrap(),
            "fd00:ae61::2".parse().unwrap(),
        ];
        let v4: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(FullWide::new(v4, dns.clone(), 1280).is_err());
        let policy = FullWide::for_test_loopback(v4, dns.clone(), 1280).unwrap();
        assert_eq!(policy.relay(), v4);
        assert_eq!(policy.dns(), dns.as_slice());
        assert_eq!(policy.mtu(), 1280);
        for refused in [
            "::1",
            "127.0.0.2",
            "::ffff:127.0.0.1",
            "192.0.2.1",
            "0.0.0.0",
        ] {
            assert!(
                FullWide::for_test_loopback(refused.parse().unwrap(), dns.clone(), 1280).is_err(),
                "test loopback accepted {refused}"
            );
        }
        assert!(FullWide::for_test_loopback(v4, vec![v4], 1280).is_err());
        assert!(FullWide::for_test_loopback(v4, vec![], 1280).is_err());
        assert!(FullWide::for_test_loopback(v4, dns, 1279).is_err());
    }

    #[test]
    fn policy_interface_addresses_never_overlap_dns_or_anchors() {
        let interfaces = [IpAddr::V4(INTERFACE_V4), IpAddr::V6(INTERFACE_V6)];
        let anchors = [IpAddr::V4(DNS_ANCHOR_V4), IpAddr::V6(DNS_ANCHOR_V6)];
        assert_eq!(INTERFACE_V4, "198.19.255.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(INTERFACE_V6, "fd00:ae61::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(DNS_ANCHOR_V4, "198.19.255.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(DNS_ANCHOR_V6, "fd00:ae61::2".parse::<Ipv6Addr>().unwrap());
        let relay: IpAddr = "192.0.2.1".parse().unwrap();
        let policy = FullWide::new(relay, anchors.to_vec(), 1280).unwrap();
        for interface in interfaces {
            assert!(!anchors.contains(&interface));
            assert!(!policy.dns().contains(&interface));
            // An interface address is never admitted as DNS or as the relay.
            assert!(FullWide::new(relay, vec![interface], 1280).is_err());
            assert!(FullWide::new(interface, anchors.to_vec(), 1280).is_err());
        }
        // The anchors stay valid DNS, alone or together.
        for anchor in anchors {
            assert!(FullWide::new(relay, vec![anchor], 1280).is_ok());
            assert!(FullWide::new(anchor, vec![anchor], 1280).is_err());
        }
        assert!(
            FullWide::for_test_loopback("127.0.0.1".parse().unwrap(), anchors.to_vec(), 1280)
                .is_ok()
        );
    }

    #[test]
    fn policy_refuses_relay_and_non_anchor_dns_inside_tunnel_ranges() {
        let dns: IpAddr = "2001:db8::53".parse().unwrap();
        let relay: IpAddr = "192.0.2.1".parse().unwrap();
        for refused in [
            "198.19.255.1",
            "198.18.0.5",
            "fd00:ae61::9",
            "198.19.255.0",
            "198.19.255.2",
            "198.19.255.254",
            "198.18.0.0",
            "198.18.255.255",
            "fd00:ae61::",
            "fd00:ae61::2",
            "fd00:ae61:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            let address: IpAddr = refused.parse().unwrap();
            assert!(
                FullWide::new(address, vec![dns], 1280).is_err(),
                "relay accepted {refused}"
            );
            if address != IpAddr::V4(DNS_ANCHOR_V4) && address != IpAddr::V6(DNS_ANCHOR_V6) {
                assert!(
                    FullWide::new(relay, vec![address], 1280).is_err(),
                    "DNS accepted {refused}"
                );
                assert!(
                    FullWide::new(relay, vec![IpAddr::V4(DNS_ANCHOR_V4), address], 1280).is_err(),
                    "DNS accepted {refused} beside an anchor"
                );
            }
        }
        // Neighbours of the reserved ranges stay admitted.
        for admitted in [
            "198.19.254.255",
            "198.19.0.1",
            "198.17.255.255",
            "fd00:ae60::1",
            "fd00:ae62::1",
        ] {
            let address: IpAddr = admitted.parse().unwrap();
            assert!(
                FullWide::new(address, vec![dns], 1280).is_ok(),
                "relay refused {admitted}"
            );
            assert!(
                FullWide::new(relay, vec![address], 1280).is_ok(),
                "DNS refused {admitted}"
            );
        }
    }

    #[test]
    fn unscoped_policy_rejects_mapped_and_link_local_endpoints() {
        let valid: IpAddr = "192.0.2.1".parse().unwrap();
        for refused in [
            "::ffff:127.0.0.1",
            "::ffff:192.0.2.1",
            "fe80::1",
            "169.254.1.1",
            "255.255.255.255",
        ] {
            let address = refused.parse().unwrap();
            assert!(
                FullWide::new(address, vec![valid], 1280).is_err(),
                "relay accepted {refused}"
            );
            assert!(
                FullWide::new(valid, vec![address], 1280).is_err(),
                "DNS accepted {refused}"
            );
        }
        assert!(FullWide::new(valid, vec!["2001:db8::53".parse().unwrap()], 1280).is_ok());
    }

    #[test]
    fn interface_v6_prefix_is_120_and_puts_the_anchor_on_link_inside_the_reserved_range() {
        assert_eq!(INTERFACE_V6_PREFIX, 120);
        assert!(interface_v6_prefix_admitted(INTERFACE_V6_PREFIX));
        // v21's /128 (and /127: fd00:ae61::/127 holds ::0 and ::1 only) leaves
        // the anchor off-link; a prefix wider than /32 leaves the reserved range.
        for refused in [0, 31, 127, 128, 129, 255] {
            assert!(
                !interface_v6_prefix_admitted(refused),
                "admitted /{refused}"
            );
        }
        for admitted in [32, 64, 120, 126] {
            assert!(
                interface_v6_prefix_admitted(admitted),
                "refused /{admitted}"
            );
        }
        // The anchor is inside INTERFACE_V6/120, the last address of that
        // prefix is still reserved, and no admitted relay can fall inside it.
        let anchor = u128::from_be_bytes(DNS_ANCHOR_V6.octets());
        let base = u128::from_be_bytes(INTERFACE_V6.octets()) & (u128::MAX << 8);
        assert_eq!(anchor & (u128::MAX << 8), base);
        let last = Ipv6Addr::from((base | 0xff).to_be_bytes());
        assert!(tunnel_reserved(IpAddr::V6(last)));
        let dns = vec![IpAddr::V4(DNS_ANCHOR_V4)];
        assert!(FullWide::new(IpAddr::V6(last), dns.clone(), 1280).is_err());
        assert!(FullWide::new(IpAddr::V6(INTERFACE_V6), dns, 1280).is_err());
    }

    // A valid IPv4 packet (IHL 5, or 6 with `options`) carrying a transport
    // header of `protocol` to `port`.
    fn v4_packet_to(destination: Ipv4Addr, protocol: u8, port: u16, options: bool) -> Vec<u8> {
        let header = if options { 24 } else { 20 };
        let mut p = vec![0u8; header + 20];
        p[0] = 0x40 | (header / 4) as u8;
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[9] = protocol;
        p[12..16].copy_from_slice(&INTERFACE_V4.octets());
        p[16..20].copy_from_slice(&destination.octets());
        p[header..header + 2].copy_from_slice(&40000u16.to_be_bytes());
        p[header + 2..header + 4].copy_from_slice(&port.to_be_bytes());
        p
    }

    fn v6_packet_to(destination: Ipv6Addr, next_header: u8, port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&20u16.to_be_bytes());
        p[6] = next_header;
        p[8..24].copy_from_slice(&INTERFACE_V6.octets());
        p[24..40].copy_from_slice(&destination.octets());
        p[40..42].copy_from_slice(&40000u16.to_be_bytes());
        p[42..44].copy_from_slice(&port.to_be_bytes());
        p
    }

    fn v4_packet(destination: Ipv4Addr) -> Vec<u8> {
        v4_packet_to(destination, 17, 53, false)
    }

    fn v6_packet(destination: Ipv6Addr) -> Vec<u8> {
        v6_packet_to(destination, 17, 53)
    }

    #[test]
    fn native_packets_to_tunnel_local_addresses_other_than_an_anchor_are_dropped() {
        for dropped in [
            "fd00:ae61::3",
            "fd00:ae61::ff",
            "fd00:ae61::1",
            "fd00:ae61:1::2",
            "fd00:ae61:ffff::2",
        ] {
            let ip: Ipv6Addr = dropped.parse().unwrap();
            assert!(!native_packet_admitted(&v6_packet(ip)), "{dropped}");
        }
        for dropped in [
            "198.19.255.3",
            "198.19.255.1",
            "198.19.255.0",
            "198.19.255.255",
        ] {
            let ip: Ipv4Addr = dropped.parse().unwrap();
            assert!(!native_packet_admitted(&v4_packet(ip)), "{dropped}");
        }
        assert!(native_packet_admitted(&v6_packet(DNS_ANCHOR_V6)));
        assert!(native_packet_admitted(&v4_packet(DNS_ANCHOR_V4)));
        // Fake IPs, global and neighbouring destinations still reach the engine,
        // on any port and protocol.
        for passed in ["198.18.0.9", "198.19.254.3", "198.20.255.3", "192.0.2.7"] {
            let ip: Ipv4Addr = passed.parse().unwrap();
            assert!(native_packet_admitted(&v4_packet(ip)), "{passed}");
            assert!(
                native_packet_admitted(&v4_packet_to(ip, 6, 443, false)),
                "{passed}"
            );
            assert!(
                native_packet_admitted(&v4_packet_to(ip, 1, 0, false)),
                "{passed}"
            );
        }
        for passed in [
            "2001:db8::7",
            "fd00:ae60::3",
            "fd00:ae62::3",
            "fc00:ae61::3",
            "ff02::2",
        ] {
            let ip: Ipv6Addr = passed.parse().unwrap();
            assert!(native_packet_admitted(&v6_packet(ip)), "{passed}");
            assert!(
                native_packet_admitted(&v6_packet_to(ip, 6, 443)),
                "{passed}"
            );
            assert!(native_packet_admitted(&v6_packet_to(ip, 58, 0)), "{passed}");
        }
        // The family comes from the version nibble: an IPv6 header carrying the
        // IPv4 anchor at IPv4's destination offset is still judged as IPv6.
        let mut cross = v6_packet("fd00:ae61::3".parse().unwrap());
        cross[16..20].copy_from_slice(&DNS_ANCHOR_V4.octets());
        assert!(!native_packet_admitted(&cross));
        // A packet the bridge refuses is left to the bridge's validation, even
        // when it names a tunnel-local destination.
        let mut wrong_length = v4_packet("198.19.255.3".parse().unwrap());
        wrong_length[3] += 1;
        let mut truncated6 = v6_packet("fd00:ae61::3".parse().unwrap());
        truncated6.pop();
        for refused in [
            &[][..],
            &[0x45; 19][..],
            &[0x60; 39][..],
            &[0x15; 40][..],
            &wrong_length,
            &truncated6,
        ] {
            assert!(crate::bridge::validate_packet(refused).is_err());
            assert!(native_packet_admitted(refused));
        }
    }

    #[test]
    fn native_packets_to_an_anchor_are_admitted_only_as_udp_or_tcp_to_port_53() {
        for anchor in [IpAddr::V4(DNS_ANCHOR_V4), IpAddr::V6(DNS_ANCHOR_V6)] {
            let packet = |protocol: u8, port: u16| match anchor {
                IpAddr::V4(ip) => v4_packet_to(ip, protocol, port, false),
                IpAddr::V6(ip) => v6_packet_to(ip, protocol, port),
            };
            assert!(native_packet_admitted(&packet(17, 53)), "{anchor} udp/53");
            assert!(native_packet_admitted(&packet(6, 53)), "{anchor} tcp/53");
            for (protocol, port) in [(17, 54), (6, 54), (17, 5353), (6, 853), (17, 0), (6, 13568)] {
                assert!(
                    !native_packet_admitted(&packet(protocol, port)),
                    "{anchor} {protocol}/{port}"
                );
            }
            // ICMP, ICMPv6, SCTP and an IPv6 extension header (hop-by-hop,
            // fragment) carry no DNS port the engine serves.
            for protocol in [1, 58, 132, 0, 44] {
                assert!(
                    !native_packet_admitted(&packet(protocol, 53)),
                    "{anchor} {protocol}"
                );
            }
        }
        // The IPv4 header length is honoured: options before UDP/53 still pass,
        // and port 53 at the unoptioned offset does not.
        let with_options = v4_packet_to(DNS_ANCHOR_V4, 17, 53, true);
        assert!(native_packet_admitted(&with_options));
        let mut misplaced = v4_packet_to(DNS_ANCHOR_V4, 17, 54, true);
        misplaced[22..24].copy_from_slice(&53u16.to_be_bytes());
        assert!(!native_packet_admitted(&misplaced));
        // Every IPv4 fragment to an anchor is dropped as a whole datagram: the
        // first one (MF, offset 0) included, which alone would only sit in the
        // engine's reassembly buffer, the middle and last ones (no ports: the
        // payload at port 53's offset is data). DF and the reserved bit are not
        // fragmentation and still pass. Off the anchors, fragments still pass.
        for (flags, admitted) in [
            (0x0000u16, true),
            (0x4000, true),
            (0x8000, true),
            (0x2000, false),
            (0x2001, false),
            (0x0001, false),
            (0x1fff, false),
            (0x6000, false),
            (0x0100, false),
        ] {
            let mut fragment = v4_packet(DNS_ANCHOR_V4);
            fragment[6..8].copy_from_slice(&flags.to_be_bytes());
            assert_eq!(native_packet_admitted(&fragment), admitted, "{flags:#06x}");
            let mut fake = v4_packet("198.18.0.9".parse().unwrap());
            fake[6..8].copy_from_slice(&flags.to_be_bytes());
            assert!(native_packet_admitted(&fake), "fake {flags:#06x}");
        }
        // The same for IPv6: a Fragment header (next header 44) to the anchor
        // is dropped whatever its offset or M flag; off the anchor it passes.
        for offset_and_m in [0x0001u16, 0x0000, 0x0008, 0x0009] {
            let mut fragment = vec![0u8; 68];
            fragment[0] = 0x60;
            fragment[4..6].copy_from_slice(&28u16.to_be_bytes());
            fragment[6] = 44;
            fragment[8..24].copy_from_slice(&INTERFACE_V6.octets());
            fragment[24..40].copy_from_slice(&DNS_ANCHOR_V6.octets());
            fragment[40] = 17;
            fragment[42..44].copy_from_slice(&offset_and_m.to_be_bytes());
            fragment[48..50].copy_from_slice(&40000u16.to_be_bytes());
            fragment[50..52].copy_from_slice(&53u16.to_be_bytes());
            assert!(crate::bridge::validate_packet(&fragment).is_ok());
            assert!(!native_packet_admitted(&fragment), "{offset_and_m:#06x}");
            fragment[24..40].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
            assert!(
                native_packet_admitted(&fragment),
                "global {offset_and_m:#06x}"
            );
        }
        // An anchor packet whose transport header is cut short is dropped.
        let mut short = vec![0u8; 42];
        short[0] = 0x60;
        short[4..6].copy_from_slice(&2u16.to_be_bytes());
        short[6] = 17;
        short[24..40].copy_from_slice(&DNS_ANCHOR_V6.octets());
        assert!(crate::bridge::validate_packet(&short).is_ok());
        assert!(!native_packet_admitted(&short));
    }
}
