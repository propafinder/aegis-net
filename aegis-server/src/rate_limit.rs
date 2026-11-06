//! Per-IP rate limiting for auth failures.
//!
//! Tracks failed auth attempts per IP. After `max_failures` within `ban_duration`,
//! the IP is banned (connections dropped immediately). History has a fixed
//! cardinality limit. When full, untracked identities are denied until expiry
//! reclaims space; this availability tradeoff does not prove bad authentication.
//! IPv4/IPv6 identity and trusted-proxy policy remain per full IP address.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MAX_TRACKED_AUTH_IDENTITIES: usize = 4096;

/// Rate limiter state.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<RateLimiterInner>>,
    max_failures: u32,
    ban_duration: Duration,
    enabled: bool,
    trusted_proxies: Arc<Vec<IpCidr>>,
    forwarded_ip_header: Arc<http::header::HeaderName>,
    operational_log: crate::operational_log::OperationalLogPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    fn parse(value: &str) -> Result<Self, String> {
        let (network, prefix) = value
            .split_once('/')
            .ok_or_else(|| format!("trusted proxy CIDR must contain '/': {value}"))?;
        let network: IpAddr = network
            .parse()
            .map_err(|_| format!("invalid trusted proxy address: {network}"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("invalid trusted proxy prefix: {prefix}"))?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("trusted proxy prefix /{prefix} exceeds /{max}"));
        }
        Ok(Self { network, prefix })
    }

    fn contains(self, candidate: IpAddr) -> bool {
        match (self.network, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let shift = 32 - u32::from(self.prefix);
                let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
                u32::from(network) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let shift = 128 - u32::from(self.prefix);
                let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
                u128::from(network) & mask == u128::from(candidate) & mask
            }
            _ => false,
        }
    }
}

struct RateLimiterInner {
    /// IP → (failure_count, first_failure_time)
    entries: HashMap<IpAddr, (u32, Instant)>,
    // Exactly one expiry key per retained identity. This avoids full-map scans
    // on every new address while keeping the expiry index bounded as well.
    expiry: BTreeSet<(Instant, IpAddr)>,
    saturation_warned: bool,
}

impl RateLimiterInner {
    fn prune_expired(&mut self, now: Instant, lifetime: Duration) {
        while let Some((first, ip)) = self.expiry.first().copied() {
            if now.saturating_duration_since(first) < lifetime {
                break;
            }
            self.expiry.pop_first();
            self.entries.remove(&ip);
        }
        if self.entries.len() < MAX_TRACKED_AUTH_IDENTITIES {
            self.saturation_warned = false;
        }
    }

    fn note_saturation(&mut self) {
        if !self.saturation_warned {
            tracing::warn!(
                event_code = "auth_failure_history_saturated",
                tracked_identities = self.entries.len(),
                maximum = MAX_TRACKED_AUTH_IDENTITIES,
                "auth failure history full; untracked identities denied until expiry"
            );
            self.saturation_warned = true;
        }
    }
}

impl RateLimiter {
    pub fn new(max_failures: u32, ban_duration_secs: u64, enabled: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RateLimiterInner {
                entries: HashMap::new(),
                expiry: BTreeSet::new(),
                saturation_warned: false,
            })),
            max_failures,
            ban_duration: Duration::from_secs(ban_duration_secs),
            enabled,
            trusted_proxies: Arc::new(Vec::new()),
            forwarded_ip_header: Arc::new(http::header::HeaderName::from_static(
                "cf-connecting-ip",
            )),
            operational_log: crate::operational_log::OperationalLogPolicy::default(),
        }
    }

    pub(crate) fn with_operational_log(
        mut self,
        policy: crate::operational_log::OperationalLogPolicy,
    ) -> Self {
        self.operational_log = policy;
        self
    }

    pub fn with_trusted_proxies(
        mut self,
        cidrs: &[String],
        forwarded_ip_header: &str,
    ) -> anyhow::Result<Self> {
        let parsed = cidrs
            .iter()
            .map(|cidr| IpCidr::parse(cidr).map_err(anyhow::Error::msg))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let header = http::header::HeaderName::from_bytes(forwarded_ip_header.as_bytes())
            .map_err(|error| anyhow::anyhow!("invalid rate_limit.forwarded_ip_header: {error}"))?;
        self.trusted_proxies = Arc::new(parsed);
        self.forwarded_ip_header = Arc::new(header);
        Ok(self)
    }

    pub fn is_trusted_proxy(&self, peer: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|cidr| cidr.contains(peer))
    }

    /// Connection-level identity is available only for direct peers. A trusted
    /// proxy is intentionally not put into a shared ban bucket before an HTTP
    /// request supplies the end-client identity.
    pub fn socket_identity(&self, peer: SocketAddr) -> Option<IpAddr> {
        (!self.is_trusted_proxy(peer.ip())).then_some(peer.ip())
    }

    pub fn http_identity(&self, peer: SocketAddr, headers: &http::HeaderMap) -> Option<IpAddr> {
        let forwarded = headers
            .get(self.forwarded_ip_header.as_ref())
            .and_then(|value| value.to_str().ok());
        self.forwarded_identity(peer, forwarded)
    }

    pub fn http1_identity(&self, peer: SocketAddr, request: &[u8]) -> Option<IpAddr> {
        if !self.is_trusted_proxy(peer.ip()) {
            return Some(peer.ip());
        }
        let Ok(request) = std::str::from_utf8(request) else {
            return None;
        };
        let wanted = self.forwarded_ip_header.as_str();
        let forwarded = request.lines().skip(1).find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case(wanted)
                .then_some(value.trim())
        });
        self.forwarded_identity(peer, forwarded)
    }

    fn forwarded_identity(&self, peer: SocketAddr, forwarded: Option<&str>) -> Option<IpAddr> {
        if !self.is_trusted_proxy(peer.ip()) {
            return Some(peer.ip());
        }
        match forwarded.and_then(|value| value.trim().parse::<IpAddr>().ok()) {
            Some(client) => Some(client),
            None => {
                crate::operational_log::warn_failure(
                    self.operational_log,
                    crate::operational_log::FailureStage::RateLimit,
                    crate::operational_log::FailureReason::RequestFailed,
                    Some(peer),
                    &self.forwarded_ip_header,
                );
                // Keep malformed trusted-proxy requests outside valid client
                // buckets. The edge itself must never become the fallback key.
                None
            }
        }
    }

    pub async fn is_socket_banned(&self, peer: SocketAddr) -> bool {
        match self.socket_identity(peer) {
            Some(identity) => self.is_banned(identity).await,
            None => false,
        }
    }

    pub async fn record_socket_failure(&self, peer: SocketAddr) {
        if let Some(identity) = self.socket_identity(peer) {
            self.record_failure(identity).await;
        }
    }

    /// Deny a current auth ban or an untracked identity while history is full.
    /// Saturation denial preserves retained windows at the cost of new-client
    /// availability; it is not evidence of an auth failure from that identity.
    pub async fn is_banned(&self, ip: IpAddr) -> bool {
        self.is_banned_at(ip, Instant::now()).await
    }

    async fn is_banned_at(&self, ip: IpAddr, now: Instant) -> bool {
        if !self.enabled {
            return false;
        }
        let mut inner = self.inner.lock().await;
        inner.prune_expired(now, self.ban_duration);
        if let Some((count, _)) = inner.entries.get(&ip) {
            return *count >= self.max_failures;
        }
        if inner.entries.len() >= MAX_TRACKED_AUTH_IDENTITIES {
            inner.note_saturation();
            return true;
        }
        false
    }

    /// Record an auth failure from IP.
    pub async fn record_failure(&self, ip: IpAddr) {
        self.record_failure_at(ip, Instant::now()).await;
    }

    async fn record_failure_at(&self, ip: IpAddr, now: Instant) {
        if !self.enabled {
            return;
        }
        let mut inner = self.inner.lock().await;
        inner.prune_expired(now, self.ban_duration);
        if !inner.entries.contains_key(&ip) {
            if inner.entries.len() >= MAX_TRACKED_AUTH_IDENTITIES {
                inner.note_saturation();
                return;
            }
            inner.entries.insert(ip, (0, now));
            inner.expiry.insert((now, ip));
        }
        let entry = inner.entries.get_mut(&ip).expect("retained auth identity");
        entry.0 = entry.0.saturating_add(1);
        if entry.0 >= self.max_failures {
            crate::operational_log::warn_counted(
                self.operational_log,
                crate::operational_log::FailureStage::RateLimit,
                crate::operational_log::FailureReason::AuthFailureLimit,
                Some(SocketAddr::new(ip, 0)),
                entry.0 as usize,
                &ip,
            );
        }
    }

    /// Periodic cleanup of expired entries (call from background task).
    pub async fn cleanup(&self) {
        self.cleanup_at(Instant::now()).await;
    }

    async fn cleanup_at(&self, now: Instant) {
        self.inner
            .lock()
            .await
            .prune_expired(now, self.ban_duration);
    }
}

#[cfg(test)]
mod history_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn not_banned_initially() {
        let rl = RateLimiter::new(3, 300, true);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(!rl.is_banned(ip).await);
    }

    #[tokio::test]
    async fn banned_after_max_failures() {
        let rl = RateLimiter::new(3, 300, true);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        rl.record_failure(ip).await;
        rl.record_failure(ip).await;
        assert!(!rl.is_banned(ip).await);
        rl.record_failure(ip).await; // 3rd failure
        assert!(rl.is_banned(ip).await);
    }

    #[tokio::test]
    async fn different_ips_independent() {
        let rl = RateLimiter::new(2, 300, true);
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        rl.record_failure(ip1).await;
        rl.record_failure(ip1).await;
        assert!(rl.is_banned(ip1).await);
        assert!(!rl.is_banned(ip2).await);
    }

    #[tokio::test]
    async fn disabled_never_bans() {
        let rl = RateLimiter::new(1, 300, false);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        rl.record_failure(ip).await;
        rl.record_failure(ip).await;
        assert!(!rl.is_banned(ip).await);
    }

    #[tokio::test]
    async fn cleanup_removes_expired() {
        let rl = RateLimiter::new(3, 0, true); // ban_duration = 0 = instant expiry
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        rl.record_failure(ip).await;
        rl.cleanup().await;
        let inner = rl.inner.lock().await;
        assert!(inner.entries.is_empty());
    }

    #[tokio::test]
    async fn trusted_proxy_clients_have_independent_ban_buckets() {
        let rl = RateLimiter::new(2, 300, true)
            .with_trusted_proxies(&["203.0.113.0/24".into()], "cf-connecting-ip")
            .unwrap();
        let edge: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let mut first_headers = http::HeaderMap::new();
        first_headers.insert("cf-connecting-ip", "198.51.100.10".parse().unwrap());
        let mut second_headers = http::HeaderMap::new();
        second_headers.insert("cf-connecting-ip", "198.51.100.11".parse().unwrap());
        let first = rl.http_identity(edge, &first_headers).unwrap();
        let second = rl.http_identity(edge, &second_headers).unwrap();
        assert_ne!(first, second);
        rl.record_failure(first).await;
        rl.record_failure(first).await;
        assert!(rl.is_banned(first).await);
        assert!(!rl.is_banned(second).await);
        assert!(!rl.is_banned(edge.ip()).await);
        assert!(!rl.is_socket_banned(edge).await);
    }

    #[test]
    fn direct_peer_cannot_spoof_forwarded_identity() {
        let rl = RateLimiter::new(2, 300, true)
            .with_trusted_proxies(&["203.0.113.0/24".into()], "cf-connecting-ip")
            .unwrap();
        let direct: SocketAddr = "192.0.2.55:443".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("cf-connecting-ip", "1.1.1.1".parse().unwrap());
        assert_eq!(rl.http_identity(direct, &headers), Some(direct.ip()));
    }

    #[test]
    fn trusted_proxy_without_valid_identity_never_falls_back_to_edge_key() {
        let rl = RateLimiter::new(2, 300, true)
            .with_trusted_proxies(&["203.0.113.0/24".into()], "cf-connecting-ip")
            .unwrap();
        let edge: SocketAddr = "203.0.113.10:443".parse().unwrap();
        assert_eq!(rl.http_identity(edge, &http::HeaderMap::new()), None);
        assert_eq!(rl.http1_identity(edge, b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(rl.socket_identity(edge), None);
    }

    #[test]
    fn invalid_trusted_proxy_config_fails_closed() {
        assert!(RateLimiter::new(2, 300, true)
            .with_trusted_proxies(&["203.0.113.0/99".into()], "cf-connecting-ip")
            .is_err());
        assert!(RateLimiter::new(2, 300, true)
            .with_trusted_proxies(&[], "bad header")
            .is_err());
    }
}
