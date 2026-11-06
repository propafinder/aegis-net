//! Runtime glue for ordered carrier failover (carrier program D3).
//!
//! One process-wide controller per admitted relay profile orders the explicit
//! endpoint pool for every TCP and UDP session and learns from typed carrier
//! signals. Only the order changes: each attempt keeps its outer verification,
//! inner device authentication, admission and no-replay rules, and when every
//! carrier fails the existing fail-closed terminal applies. There is no
//! native-egress branch here.
use super::EffectiveRelayEndpoint;
use aegis_core::brain::carrier_failover::{
    CarrierFailover, CarrierFailoverSettings, CarrierOutcome, CarrierSignal, CarrierTransition,
    NetworkKey,
};
use aegis_core::RelaySettings;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Profiles with live controllers. An installed client normally has one; the
/// least recently used profile is evicted beyond this bound.
const MAX_PROFILES: usize = 32;
type Shared = Arc<Mutex<CarrierFailover>>;
type Registry = Vec<([u8; 32], Shared, Instant)>;
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

fn profile_identity(settings: &RelaySettings, endpoints: &[EffectiveRelayEndpoint]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"aegis.carrier-failover.profile.v1\0");
    for endpoint in endpoints {
        for part in [&endpoint.server, &endpoint.server_name] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
    }
    let identity = serde_json::json!({
        "ca": settings.ca_cert,
        "inner": settings.inner_tls.as_ref().map(|inner| (&inner.server_name, &inner.cert)),
        "ech": (&settings.ech_config_list, &settings.ech_config_list_base64),
        "policy": settings.carrier_failover,
    });
    hash.update(identity.to_string().as_bytes());
    hash.finalize().into()
}

fn controller(
    identity: [u8; 32],
    policy: &CarrierFailoverSettings,
    carriers: usize,
) -> anyhow::Result<Shared> {
    let mut registry = REGISTRY
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .map_err(|_| anyhow::anyhow!("carrier failover registry unavailable"))?;
    let now = Instant::now();
    if let Some((_, shared, used)) = registry.iter_mut().find(|(key, _, _)| *key == identity) {
        *used = now;
        return Ok(shared.clone());
    }
    if registry.len() >= MAX_PROFILES {
        if let Some(oldest) = registry
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, _, used))| *used)
            .map(|(index, _)| index)
        {
            registry.swap_remove(oldest);
        }
    }
    let shared = Arc::new(Mutex::new(
        CarrierFailover::new(policy.clone(), carriers).map_err(anyhow::Error::msg)?,
    ));
    registry.push((identity, shared.clone(), now));
    Ok(shared)
}

/// Access-network identity. Linux derives it from the default IPv4 route and
/// its gateway's link-layer address with a per-process salt; other platforms
/// (and unreadable routing state) share `NetworkKey::UNKNOWN`. The macOS
/// provider supplies its own key from the system path monitor.
pub(super) fn current_network() -> NetworkKey {
    static CACHE: Mutex<Option<(Instant, NetworkKey)>> = Mutex::new(None);
    let now = Instant::now();
    if let Ok(cache) = CACHE.lock() {
        if let Some((at, key)) = *cache {
            if now.duration_since(at) < Duration::from_secs(2) {
                return key;
            }
        }
    }
    let key = observe_network();
    if let Ok(mut cache) = CACHE.lock() {
        *cache = Some((now, key));
    }
    key
}

#[cfg(target_os = "linux")]
fn observe_network() -> NetworkKey {
    static SALT: OnceLock<[u8; 32]> = OnceLock::new();
    let salt = SALT.get_or_init(rand::random);
    match std::fs::read_to_string("/proc/net/route") {
        Ok(routes) => network_from_tables(
            salt,
            &routes,
            &std::fs::read_to_string("/proc/net/arp").unwrap_or_default(),
        ),
        Err(_) => NetworkKey::UNKNOWN,
    }
}

#[cfg(not(target_os = "linux"))]
fn observe_network() -> NetworkKey {
    NetworkKey::UNKNOWN
}

/// Network key from Linux `/proc/net/route` and `/proc/net/arp` contents:
/// default-route interface, gateway address and gateway link-layer address.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn network_from_tables(salt: &[u8; 32], routes: &str, arp: &str) -> NetworkKey {
    let Some((interface, gateway)) = default_route(routes) else {
        return NetworkKey::UNKNOWN;
    };
    let hardware = gateway_hardware(arp, gateway).unwrap_or_default();
    let octets = gateway.octets();
    let parts: [&[u8]; 3] = [interface.as_bytes(), &octets, hardware.as_bytes()];
    NetworkKey::derive(salt, &parts)
}

/// Lowest-metric 0.0.0.0/0 route with a gateway from `/proc/net/route`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn default_route(table: &str) -> Option<(String, std::net::Ipv4Addr)> {
    const RTF_UP: u32 = 0x1;
    const RTF_GATEWAY: u32 = 0x2;
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 8 {
                return None;
            }
            let destination = u32::from_str_radix(fields[1], 16).ok()?;
            let gateway = u32::from_str_radix(fields[2], 16).ok()?;
            let flags = u32::from_str_radix(fields[3], 16).ok()?;
            let metric: u32 = fields[6].parse().ok()?;
            let mask = u32::from_str_radix(fields[7], 16).ok()?;
            (destination == 0
                && mask == 0
                && flags & (RTF_UP | RTF_GATEWAY) == RTF_UP | RTF_GATEWAY)
                .then(|| {
                    (
                        metric,
                        fields[0].to_owned(),
                        std::net::Ipv4Addr::from(gateway.swap_bytes()),
                    )
                })
        })
        .min_by_key(|(metric, _, _)| *metric)
        .map(|(_, interface, gateway)| (interface, gateway))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn gateway_hardware(table: &str, gateway: std::net::Ipv4Addr) -> Option<String> {
    let gateway = gateway.to_string();
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        (fields.len() >= 4 && fields[0] == gateway).then(|| fields[3].to_ascii_lowercase())
    })
}

#[cfg(test)]
static TEST_NETWORKS: Mutex<Vec<([u8; 32], NetworkKey)>> = Mutex::new(Vec::new());

/// Test-only: pin the network key observed by one profile.
#[cfg(test)]
pub(super) fn set_test_network(settings: &RelaySettings, key: NetworkKey) {
    let endpoints = super::effective_relay_endpoints(settings);
    let identity = profile_identity(settings, &endpoints);
    let mut networks = TEST_NETWORKS.lock().unwrap();
    networks.retain(|(id, _)| *id != identity);
    networks.push((identity, key));
}

/// Test-only view of the shared controller for one profile.
#[cfg(test)]
pub(super) fn inspect<T>(settings: &RelaySettings, view: impl FnOnce(&CarrierFailover) -> T) -> T {
    let endpoints = super::effective_relay_endpoints(settings);
    let identity = profile_identity(settings, &endpoints);
    let policy = settings.carrier_failover.as_ref().expect("failover policy");
    let shared = controller(identity, policy, endpoints.len()).unwrap();
    let guard = shared.lock().unwrap();
    view(&guard)
}

fn network_for(identity: &[u8; 32]) -> NetworkKey {
    #[cfg(test)]
    if let Some((_, key)) = TEST_NETWORKS
        .lock()
        .unwrap()
        .iter()
        .find(|(id, _)| id == identity)
    {
        return *key;
    }
    let _ = identity;
    current_network()
}

struct SessionShared {
    controller: Shared,
    network: NetworkKey,
    policy: CarrierFailoverSettings,
    /// Authenticated shaping owns the outer wire schedule; an unshaped
    /// periodic PING record would be visible beside it, so liveness is off.
    liveness_allowed: bool,
    labels: Vec<String>,
}

/// One relay session's attempt order. Dropping it releases a reserved
/// recovery trial that was never attempted.
pub(super) struct Session {
    shared: Arc<SessionShared>,
    order: Vec<usize>,
    trial: Option<(usize, Arc<AtomicBool>)>,
}

impl Session {
    /// `None` when the profile has no failover policy (fixed pool order).
    pub(super) fn prepare(
        settings: &RelaySettings,
        endpoints: &[EffectiveRelayEndpoint],
    ) -> anyhow::Result<Option<Self>> {
        let Some(policy) = &settings.carrier_failover else {
            return Ok(None);
        };
        anyhow::ensure!(
            settings.endpoint_bandit.is_none() && settings.inner_tls.is_some(),
            "carrier failover requires device inner TLS and no endpoint bandit"
        );
        let identity = profile_identity(settings, endpoints);
        let shared = controller(identity, policy, endpoints.len())?;
        let network = network_for(&identity);
        let plan = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("carrier failover state unavailable"))?
            .plan(network, Instant::now());
        Ok(Some(Self {
            shared: Arc::new(SessionShared {
                controller: shared,
                network,
                policy: policy.clone(),
                liveness_allowed: settings.authenticated_shaping.is_none(),
                labels: endpoints.iter().map(|e| e.server.clone()).collect(),
            }),
            order: plan.order,
            trial: plan
                .trial
                .map(|carrier| (carrier, Arc::new(AtomicBool::new(false)))),
        }))
    }

    pub(super) fn order(&self) -> &[usize] {
        &self.order
    }

    pub(super) fn ticket(&self, carrier: usize) -> Ticket {
        let trial = self
            .trial
            .as_ref()
            .filter(|(index, _)| *index == carrier)
            .map(|(_, settled)| settled.clone());
        Ticket(Arc::new(TicketInner {
            shared: self.shared.clone(),
            carrier,
            trial,
            state: AtomicU8::new(0),
            degraded: AtomicBool::new(false),
        }))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some((carrier, settled)) = &self.trial {
            if !settled.swap(true, Ordering::AcqRel) {
                self.shared.record(*carrier, CarrierOutcome::Neutral);
            }
        }
    }
}

impl SessionShared {
    fn record(&self, carrier: usize, outcome: CarrierOutcome) {
        let transitions = match self.controller.lock() {
            Ok(mut controller) => controller.record(self.network, carrier, outcome, Instant::now()),
            Err(_) => return,
        };
        for transition in transitions {
            super::events::emit_relay_carrier_state_changed(
                &self.network.label(),
                &self.labels,
                &transition,
            );
        }
    }
}

const PENDING: u8 = 0;
const OPENED: u8 = 1;
const SETTLED: u8 = 2;

struct TicketInner {
    shared: Arc<SessionShared>,
    carrier: usize,
    trial: Option<Arc<AtomicBool>>,
    state: AtomicU8,
    degraded: AtomicBool,
}

/// One carrier attempt. Exactly one terminal outcome is recorded; an
/// unsettled ticket records `Neutral` on drop.
#[derive(Clone)]
pub(crate) struct Ticket(Arc<TicketInner>);

impl Ticket {
    fn settle_trial(&self) {
        if let Some(settled) = &self.0.trial {
            settled.store(true, Ordering::Release);
        }
    }

    /// Outer carrier and inner authentication succeeded.
    pub(crate) fn opened(&self) {
        if self
            .0
            .state
            .compare_exchange(PENDING, OPENED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.settle_trial();
            self.0.shared.record(self.0.carrier, CarrierOutcome::Opened);
        }
    }

    /// The attempt failed before an authenticated session existed.
    pub(super) fn failed_before_open(&self, error: &anyhow::Error) {
        let outcome = match super::secure::pre_auth_signal(error) {
            Some(signal) => CarrierOutcome::Failed(signal),
            None => CarrierOutcome::Neutral,
        };
        self.finish_with(outcome);
    }

    /// An open session observed a degradation; it is recorded once.
    pub(crate) fn degraded(&self, signal: CarrierSignal) {
        if !self.0.degraded.swap(true, Ordering::AcqRel) {
            self.0
                .shared
                .record(self.0.carrier, CarrierOutcome::Failed(signal));
        }
    }

    /// An open session ended. A clean end with response bytes and no
    /// degradation clears post-authentication degradation; a failed outer
    /// carrier connection is a carrier reset.
    pub(crate) fn closed(&self, carrier_failed: bool, response_observed: bool) {
        if carrier_failed {
            self.degraded(CarrierSignal::SessionReset);
        }
        let outcome = if !self.0.degraded.load(Ordering::Acquire) && response_observed {
            CarrierOutcome::Healthy
        } else {
            CarrierOutcome::Neutral
        };
        self.finish_with(outcome);
    }

    fn finish_with(&self, outcome: CarrierOutcome) {
        if self.0.state.swap(SETTLED, Ordering::AcqRel) != SETTLED {
            self.settle_trial();
            self.0.shared.record(self.0.carrier, outcome);
        }
    }

    pub(crate) fn liveness(&self) -> Option<Liveness> {
        let policy = &self.0.shared.policy;
        (self.0.shared.liveness_allowed && policy.liveness_enabled()).then(|| Liveness {
            interval: Duration::from_millis(policy.liveness_interval_ms),
            timeout: Duration::from_millis(policy.liveness_timeout_ms),
            collapse: Duration::from_millis(policy.collapse_rtt_ms),
        })
    }
}

impl Drop for TicketInner {
    fn drop(&mut self) {
        if self.state.swap(SETTLED, Ordering::AcqRel) != SETTLED {
            if let Some(settled) = &self.trial {
                settled.store(true, Ordering::Release);
            }
            self.shared.record(self.carrier, CarrierOutcome::Neutral);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Liveness {
    pub(crate) interval: Duration,
    pub(crate) timeout: Duration,
    pub(crate) collapse: Duration,
}

pub(super) fn transition_fields(
    labels: &[String],
    transition: &CarrierTransition,
) -> serde_json::Value {
    let label = |index: usize| labels.get(index).cloned();
    match transition {
        CarrierTransition::CooldownStarted {
            carrier,
            signal,
            cooldown,
        } => serde_json::json!({
            "transition": "cooldown_started",
            "carrier_index": carrier,
            "carrier_server": label(*carrier),
            "signal": signal.as_str(),
            "signal_scope": if signal.pre_auth() { "pre_auth" } else { "post_auth" },
            "cooldown_ms": u64::try_from(cooldown.as_millis()).unwrap_or(u64::MAX),
        }),
        CarrierTransition::ActiveSwitched { from, to } => serde_json::json!({
            "transition": "active_switched",
            "from_index": from,
            "from_server": from.and_then(label),
            "carrier_index": to,
            "carrier_server": label(*to),
        }),
        CarrierTransition::Recovered { carrier } => serde_json::json!({
            "transition": "recovered",
            "carrier_index": carrier,
            "carrier_server": label(*carrier),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_route_picks_lowest_metric_gateway_route_and_ignores_capture_halves() {
        let table =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            aegis0\t00000000\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0\n\
            aegis0\t00000080\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0\n\
            wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
            eth0\t00000000\t010010AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t000010AC\t00000000\t0001\t0\t0\t100\t0000FFFF\t0\t0\t0\n";
        let (interface, gateway) = default_route(table).unwrap();
        assert_eq!(interface, "eth0");
        assert_eq!(gateway, std::net::Ipv4Addr::new(172, 16, 0, 1));
        assert!(default_route("Iface\tDestination\n").is_none());
        let arp =
            "IP address       HW type     Flags       HW address            Mask     Device\n\
            172.16.0.1       0x1         0x2         AA:BB:CC:00:11:22     *        eth0\n";
        assert_eq!(
            gateway_hardware(arp, gateway).as_deref(),
            Some("aa:bb:cc:00:11:22")
        );
        assert_eq!(gateway_hardware(arp, std::net::Ipv4Addr::LOCALHOST), None);

        // The derived key is stable for the same network, distinguishes a
        // different gateway device, and is UNKNOWN without a default route.
        let salt = [3; 32];
        let key = network_from_tables(&salt, table, arp);
        assert_ne!(key, NetworkKey::UNKNOWN);
        assert_eq!(key, network_from_tables(&salt, table, arp));
        let other_router = arp.replace("AA:BB:CC:00:11:22", "AA:BB:CC:00:11:23");
        assert_ne!(key, network_from_tables(&salt, table, &other_router));
        assert_ne!(key, network_from_tables(&[4; 32], table, arp));
        assert_eq!(
            network_from_tables(&salt, "Iface\tDestination\n", arp),
            NetworkKey::UNKNOWN
        );
    }

    fn pool(shaping: bool) -> RelaySettings {
        let endpoint = |server: &str, name: &str| aegis_core::RelayEndpointSettings {
            server: server.into(),
            server_name: name.into(),
            masque_server: None,
            masque_server_name: None,
        };
        RelaySettings {
            server: "192.0.2.10:443".into(),
            server_name: "relay.test".into(),
            endpoints: vec![
                endpoint("192.0.2.10:443", "relay.test"),
                endpoint("198.51.100.20:443", "edge.test"),
            ],
            inner_tls: Some(aegis_core::secure_channel::ClientSettings {
                server_name: "inner.test".into(),
                server_ca: "/nonexistent/inner-ca.pem".into(),
                cert: format!("/nonexistent/{shaping}/device.pem").into(),
                key: "/nonexistent/device.key".into(),
            }),
            carrier_failover: Some(CarrierFailoverSettings::default()),
            authenticated_shaping: shaping.then_some(
                aegis_core::carrier_runtime::PrivacySettings {
                    payload_bytes: 1024,
                    cadence_ms: 10,
                    buffer_bytes: 4096,
                    max_wire_bytes: 8_388_608,
                    io_timeout_ms: 1000,
                    session_timeout_ms: 10_000,
                    max_queue_delay_ms: 10_000,
                    poisson_pacing: None,
                    net_shaper: None,
                    adaptive_channel: None,
                    arrival_envelope: None,
                    cover_stream: None,
                    bit_traps: None,
                    liu_channel: None,
                },
            ),
            ..RelaySettings::default()
        }
    }

    #[test]
    fn liveness_probe_is_off_for_authenticated_shaping_profiles() {
        for shaping in [false, true] {
            let settings = pool(shaping);
            let endpoints = super::super::effective_relay_endpoints(&settings);
            let session = Session::prepare(&settings, &endpoints).unwrap().unwrap();
            assert_eq!(session.order(), &[0, 1]);
            assert_eq!(session.ticket(0).liveness().is_some(), !shaping);
        }
        let mut absent = pool(false);
        absent.carrier_failover = None;
        let endpoints = super::super::effective_relay_endpoints(&absent);
        assert!(Session::prepare(&absent, &endpoints).unwrap().is_none());
    }

    #[test]
    fn transition_fields_name_carrier_and_scope_without_targets() {
        let labels = vec!["192.0.2.1:443".to_owned(), "198.51.100.2:443".to_owned()];
        let fields = transition_fields(
            &labels,
            &CarrierTransition::CooldownStarted {
                carrier: 0,
                signal: CarrierSignal::HandshakeReset,
                cooldown: Duration::from_millis(5_000),
            },
        );
        assert_eq!(fields["carrier_server"], "192.0.2.1:443");
        assert_eq!(fields["signal_scope"], "pre_auth");
        assert_eq!(fields["cooldown_ms"], 5_000);
        let fields = transition_fields(
            &labels,
            &CarrierTransition::ActiveSwitched {
                from: Some(0),
                to: 1,
            },
        );
        assert_eq!(fields["from_server"], "192.0.2.1:443");
        assert_eq!(fields["carrier_server"], "198.51.100.2:443");
    }
}
