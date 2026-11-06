// macOS/Windows reuse the allocator and packet DNS parser. The Linux socket
// owner remains here and is exercised by shared resolver tests on every host.
// DNS-preview fake-IP listener.
//
// Architecture: when `--dns=preview` is enabled in wide mode, aegis-client
// spawns a synthetic DNS server on `dns_preview_listen` (typically
// 127.0.0.1:53 after stopping systemd-resolved). The server answers `A`
// queries with a fake IP allocated from `dns_preview_fake_ip_pool`
// (default 198.18.0.0/15, RFC 2544 reserved). A shared `FakeIpMap` records
// the fake_ip ↔ hostname mapping. TCP and generic UDP ingress share this map
// when it accepts a connection whose original destination IP falls inside
// the pool: it substitutes `target.host` with the original hostname and
// the relay session opens against `hostname:port` instead of the fake IP.
//
// This deliberately AVOIDS the unreliable kernel-side patterns we tried
// in earlier batches: UDP nat REDIRECT (TCP-only conntrack preservation,
// loses original-dst for UDP) and OUTPUT-mark + policy-route + lo PREROUTING
// TPROXY (does not reliably fire on locally-originated UDP across the
// kernel versions we tested). Fake-IP is a resolver-based architecture
// — explicit, predictable, and cleanly reversible.

use crate::runtime_event_stream as runtime_jsonl;
use crate::runtime_events::RuntimeEventCode;
#[cfg(any(target_os = "linux", test))]
use aegis_core::{RelaySettings, TunnelTransportFamily, WideIngressSettings};
use serde_json::json;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
#[cfg(any(target_os = "linux", test))]
use tokio::net::UdpSocket;
#[cfg(any(target_os = "linux", test))]
use tokio::sync::oneshot;
#[cfg(any(target_os = "linux", test))]
use tokio::task::{JoinHandle, JoinSet};

#[cfg(any(target_os = "linux", test))]
const DNS_RCODE_SERVFAIL: u8 = 2;
include!("../../packet_engine/dns_core_body.rs");

// This private helper belongs to the original binary DNS test consumer.
#[cfg(test)]
impl FakeIpMap {
    /// `ip`'s binding has been unused for longer than the map's recycle idle.
    pub(super) fn expire_mapping_for_test(&self, ip: Ipv4Addr) {
        self.inner
            .lock()
            .expect("dns_preview map lock")
            .by_ip
            .get_mut(&u32::from(ip))
            .expect("test mapping exists")
            .last_used = FakeIpInstant::now() - self.recycle_idle - Duration::from_secs(1);
    }

    /// What an answer for another name could recycle while `last_lease`, the
    /// last hold of `ip`'s binding, ends: this thread holds the map lock, as
    /// that answer does, while the lease is dropped on the runtime's blocking
    /// pool (the session's end on another worker). It reads the map once the
    /// lease's count is zero, so the end is waiting for the lock to mark the
    /// binding used, and returns after that end has run.
    #[cfg(target_os = "linux")]
    pub(super) async fn recyclable_while_last_lease_ends_for_test<L: Send + 'static>(
        &self,
        ip: Ipv4Addr,
        last_lease: L,
    ) -> Option<Ipv4Addr> {
        let holders = |inner: &FakeIpMapInner| {
            inner.by_ip[&u32::from(ip)]
                .lease
                .as_ref()
                .map_or(0, |(_, core)| core.strong_count())
        };
        let (recyclable, ending) = {
            let inner = self.inner.lock().expect("dns_preview map lock");
            assert_ne!(holders(&inner), 0, "a lease holds {ip}'s binding");
            let ending = tokio::task::spawn_blocking(move || drop(last_lease));
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while holders(&inner) != 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "a hold of {ip} other than the last lease remains"
                );
                std::thread::yield_now();
            }
            let recyclable = self.recyclable(&inner, FakeIpInstant::now());
            (recyclable.map(Ipv4Addr::from), ending)
        };
        ending.await.expect("the last lease's end ran");
        recyclable
    }
}

/// Owns the listener and every DNS forwarding task. Drop cancels even during
/// startup unwinding; explicit shutdown also waits for socket/task release.
#[cfg(any(target_os = "linux", test))]
pub struct DnsPreviewListener {
    #[cfg(target_os = "linux")]
    pub map: Arc<FakeIpMap>,
    #[cfg(test)]
    pub listen: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    failure: tokio::sync::watch::Receiver<()>,
}

#[cfg(any(target_os = "linux", test))]
impl DnsPreviewListener {
    pub fn failure_receiver(&self) -> tokio::sync::watch::Receiver<()> {
        self.failure.clone()
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.as_mut() {
            if tokio::time::timeout(Duration::from_secs(2), &mut *task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
        self.task.take();
    }
}

#[cfg(any(target_os = "linux", test))]
impl Drop for DnsPreviewListener {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// How long an address the preview answered must be unused (no answer that
/// carries it, no flow, no queued reply) before it may go to another name,
/// and then only once the pool has no address left that was never given out
/// (`FakeIpMap::assign`). The answers keep `dns_preview_fake_ip_ttl_secs` as
/// their TTL, but a resolver or an application may use an answer past it
/// (B-06 build 37: a cached 60 s answer was used 67.6 s after it arrived), so
/// the TTL is never the binding's lifetime: the packet engine's hour, and at
/// least 60 answer TTLs.
#[cfg(any(target_os = "linux", test))]
fn preview_recycle_idle(ttl_secs: u32) -> Duration {
    aegis_client::packet_engine::engine::FAKE_IP_RECYCLE_IDLE
        .max(Duration::from_secs(u64::from(ttl_secs).saturating_mul(60)))
}

/// Start the optional resolver-based fake-IP listener. An explicitly configured
/// listener must bind successfully before its caller can report startup ready.
#[cfg(test)]
pub async fn spawn_dns_preview(
    settings: &WideIngressSettings,
    relay: Option<RelaySettings>,
) -> io::Result<Option<DnsPreviewListener>> {
    spawn_dns_preview_gated(settings, relay, None).await
}

#[cfg(any(target_os = "linux", test))]
pub(crate) async fn spawn_dns_preview_gated(
    settings: &WideIngressSettings,
    relay: Option<RelaySettings>,
    gate: Option<super::forward_gate::ForwardGate>,
) -> io::Result<Option<DnsPreviewListener>> {
    let listen = match settings.dns_preview_listen {
        Some(addr) => addr,
        None => return Ok(None),
    };
    if let Some(relay) = relay.as_ref() {
        validate_dns_preview_config(settings, relay)?;
    }
    // One listener per client process. Its never-used addresses start at a
    // random offset, so a restarted client does not first give the previous
    // process's answers, which applications may still cache, to other names.
    let map = Arc::new(
        FakeIpMap::new(
            &settings.dns_preview_fake_ip_pool,
            preview_recycle_idle(settings.dns_preview_fake_ip_ttl_secs),
        )
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("pool {}: {error}", settings.dns_preview_fake_ip_pool),
            )
        })?
        .starting_at(rand::random()),
    );
    let socket = UdpSocket::bind(listen)
        .await
        .map_err(|error| io::Error::new(error.kind(), format!("bind {listen}: {error}")))?;
    let listen = socket.local_addr()?;
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::DnsPreviewEnabled,
        "dns preview fake-ip listener started",
        json!({
            "listen": listen.to_string(),
            "fake_ip_pool": settings.dns_preview_fake_ip_pool,
            "ttl_secs": settings.dns_preview_fake_ip_ttl_secs,
        }),
    );
    let map_for_task = Arc::clone(&map);
    let ttl_secs = settings.dns_preview_fake_ip_ttl_secs;
    let upstream = settings.dns_relay_upstream;
    let (shutdown, stopped) = oneshot::channel();
    let (lifetime, failure) = tokio::sync::watch::channel(());
    let task = tokio::spawn(async move {
        run_dns_listener(
            socket,
            map_for_task,
            ttl_secs,
            relay,
            upstream,
            stopped,
            forward_dns_request,
            gate,
        )
        .await;
        // Closure (including task cancellation/panic) is the failure signal.
        // No owner outside this required task keeps the sender alive.
        drop(lifetime);
    });
    Ok(Some(DnsPreviewListener {
        #[cfg(target_os = "linux")]
        map,
        #[cfg(test)]
        listen,
        shutdown: Some(shutdown),
        task: Some(task),
        failure,
    }))
}

#[cfg(any(target_os = "linux", test))]
async fn forward_dns_request(
    relay: Arc<RelaySettings>,
    upstream: SocketAddr,
    request: Vec<u8>,
) -> Vec<u8> {
    crate::relay::run_relay_udp_datagram_once(
        &relay,
        crate::socks5::ConnectTarget {
            host: upstream.ip().to_string(),
            port: upstream.port(),
        },
        &request,
    )
    .await
    .ok()
    .filter(|response| valid_dns_relay_response(&request, response))
    .unwrap_or_else(|| dns_error_response(&request, DNS_RCODE_SERVFAIL))
}

#[cfg(any(target_os = "linux", test))]
#[allow(clippy::too_many_arguments)] // Socket owner, shutdown and injected forwarding seam.
async fn run_dns_listener<F, Fut>(
    socket: UdpSocket,
    map: Arc<FakeIpMap>,
    ttl_secs: u32,
    relay: Option<RelaySettings>,
    upstream: SocketAddr,
    mut shutdown: oneshot::Receiver<()>,
    forward: F,
    gate: Option<super::forward_gate::ForwardGate>,
) where
    F: Fn(Arc<RelaySettings>, SocketAddr, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Vec<u8>> + Send + 'static,
{
    let socket = Arc::new(socket);
    let relay = relay.map(Arc::new);
    let mut forwards = JoinSet::new();
    let mut buf = vec![0u8; 1500];
    loop {
        let received = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = forwards.join_next(), if !forwards.is_empty() => continue,
            received = socket.recv_from(&mut buf) => received,
        };
        let (n, peer) = match received {
            Ok(x) => x,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                continue
            }
            Err(_) => break,
        };
        if gate.as_ref().is_some_and(|gate| !gate.is_open()) {
            continue; // discard, never retain requests across admission
        }
        let req = &buf[..n];
        if question_type(req).is_some_and(|qtype| qtype != QTYPE_A) {
            if let Some(relay) = relay.as_ref() {
                if forwards.len() >= 64 {
                    let response = dns_error_response(req, DNS_RCODE_SERVFAIL);
                    let _ = super::forward_gate::run_optional(
                        gate.as_ref(),
                        socket.send_to(&response, peer),
                    )
                    .await;
                    continue;
                }
                let socket = Arc::clone(&socket);
                let response = forward(Arc::clone(relay), upstream, req.to_vec());
                let gate = gate.clone();
                forwards.spawn(async move {
                    let _ = super::forward_gate::run_optional(gate.as_ref(), async move {
                        let response = response.await;
                        let _ = socket.send_to(&response, peer).await;
                    })
                    .await;
                });
                continue;
            }
        }
        let response = match gate.as_ref() {
            Some(gate) => gate.with_open(|| build_response(req, &map, ttl_secs)),
            None => Some(build_response(req, &map, ttl_secs)),
        };
        if let Some(response) = response {
            let _ =
                super::forward_gate::run_optional(gate.as_ref(), socket.send_to(&response, peer))
                    .await;
        }
    }
    forwards.shutdown().await;
}

#[cfg(any(target_os = "linux", test))]
fn valid_dns_relay_response(request: &[u8], response: &[u8]) -> bool {
    aegis_core::dns_response::is_valid_relay_response(request, response)
}

pub(super) fn build_response(req: &[u8], map: &Arc<FakeIpMap>, ttl_secs: u32) -> Vec<u8> {
    build_response_with_sink(
        req,
        map,
        ttl_secs,
        &super::packet_engine_services::ClientRelayServices,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn controlled_dns_listener_discards_closed_requests_and_cancels_relay_on_revoke() {
        struct Dropped(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let gate = super::super::forward_gate::ForwardGate::closed();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_dropped = dropped.clone();
        let (started_tx, mut started_rx) = tokio::sync::mpsc::channel(1);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen = socket.local_addr().unwrap();
        let map = Arc::new(FakeIpMap::new("198.18.0.0/15", Duration::from_secs(60)).unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(run_dns_listener(
            socket,
            map,
            60,
            Some(RelaySettings::default()),
            "127.0.0.1:9".parse().unwrap(),
            shutdown_rx,
            move |_, _, _| {
                let guard = Dropped(task_dropped.clone());
                let started = started_tx.clone();
                async move {
                    let _guard = guard;
                    started.send(()).await.unwrap();
                    std::future::pending::<Vec<u8>>().await
                }
            },
            Some(gate.clone()),
        ));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
        let mut response = [0u8; 1500];
        // Both fake-IP answers and real relay requests stay absent while closed.
        client.send_to(&query, listen).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), client.recv_from(&mut response))
                .await
                .is_err()
        );
        query[16] = 28;
        client.send_to(&query, listen).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), started_rx.recv())
                .await
                .is_err()
        );
        assert!(gate.open());
        query[16] = 1;
        client.send_to(&query, listen).await.unwrap();
        let (size, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
        assert!(size > query.len());
        query[16] = 28;
        client.send_to(&query, listen).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), started_rx.recv())
            .await
            .unwrap()
            .unwrap();
        gate.revoke();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!gate.open());
        query[16] = 1;
        client.send_to(&query, listen).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), client.recv_from(&mut response))
                .await
                .is_err()
        );
        query[16] = 28;
        client.send_to(&query, listen).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), started_rx.recv())
                .await
                .is_err()
        );
        shutdown_tx.send(()).unwrap();
        task.await.unwrap();
    }

    #[test]
    fn active_mapping_lease_prevents_reuse_until_last_owner_drops_and_idles() {
        let map = FakeIpMap::new("198.19.255.252/30", Duration::from_secs(60)).unwrap();
        let (ip, _) = map.assign("old.test").unwrap();
        let destination = SocketAddr::from((ip, 443));
        let (host, lease) = lease_target_host(destination, Some(&map)).unwrap();
        assert_eq!(host, "old.test");
        let reply_owner = lease.clone();
        map.expire_mapping_for_test(ip);
        assert!(
            map.assign("new.test").is_none(),
            "active tuple keeps the only synthetic address"
        );
        assert_eq!(
            resolve_target_host(destination, Some(&map)).unwrap(),
            "old.test"
        );
        drop(lease);
        map.expire_mapping_for_test(ip);
        assert!(
            map.assign("new.test").is_none(),
            "queued replies also retain the same lease"
        );
        drop(reply_owner);
        assert!(
            map.assign("new.test").is_none(),
            "the last owner's end restarts the binding's idle time"
        );
        map.expire_mapping_for_test(ip);
        assert_eq!(
            lease_target_host(destination, Some(&map)).unwrap().0,
            "old.test",
            "an idle unleased IP keeps its own name until it is rebound"
        );
        map.expire_mapping_for_test(ip);
        assert_eq!(map.assign("new.test").unwrap().0, ip);
        assert_eq!(
            lease_target_host(destination, Some(&map)).unwrap().0,
            "new.test"
        );
    }

    #[test]
    fn new_flow_after_an_idle_tcp_lease_reaches_the_same_name_and_address() {
        let map = FakeIpMap::new("198.18.0.0/16", Duration::from_secs(60)).unwrap();
        let (old_ip, _) = map.assign("same.test").unwrap();
        let (_, tcp_lease) =
            lease_target_host(SocketAddr::from((old_ip, 443)), Some(&map)).unwrap();
        map.expire_mapping_for_test(old_ip);
        assert_eq!(map.lookup_hostname(old_ip).as_deref(), Some("same.test"));
        drop(tcp_lease);
        map.expire_mapping_for_test(old_ip);
        let (host, _udp_lease) =
            lease_target_host(SocketAddr::from((old_ip, 53)), Some(&map)).unwrap();
        assert_eq!(host, "same.test");
        assert_eq!(map.assign("same.test"), Some((old_ip, false)));
    }

    #[test]
    fn dns_refresh_of_leased_hostname_extends_ttl_without_allocating_another_ip() {
        let map = FakeIpMap::new("198.19.255.252/30", Duration::from_secs(60)).unwrap();
        let (ip, _) = map.assign("same.test").unwrap();
        let (_, lease) = lease_target_host(SocketAddr::from((ip, 443)), Some(&map)).unwrap();
        map.expire_mapping_for_test(ip);
        assert_eq!(map.assign("same.test"), Some((ip, false)));
        assert_eq!(map.snapshot_size(), 1);
        drop(lease);
        assert_eq!(map.lookup_hostname(ip).as_deref(), Some("same.test"));
        assert!(
            map.assign("other.test").is_none(),
            "refreshed TTL remains authoritative"
        );
    }

    #[test]
    fn pool_validation_is_checked_canonical_and_synthetic_only() {
        for invalid in [
            "0.0.0.0/0",
            "198.18.0.0/14",
            "198.18.0.0/31",
            "198.18.0.0/32",
            "198.18.0.0/33",
            "198.18.0.0/255",
            "198.18.0.1/24",
            "198.19.0.0/15",
            "127.0.0.0/24",
            "10.0.0.0/24",
            "224.0.0.0/24",
            "203.0.113.0/24",
            "[::1]/24",
        ] {
            assert!(
                FakeIpMap::new(invalid, Duration::from_secs(60)).is_err(),
                "{invalid}"
            );
        }
        for valid in ["198.18.0.0/15", "198.19.0.0/16", "198.19.255.252/30"] {
            let map = FakeIpMap::new(valid, Duration::from_secs(60)).expect(valid);
            let (ip, _) = map.assign("example.test").expect("capacity");
            assert!(map.ip_in_pool(ip));
        }
        let small = FakeIpMap::new("198.19.255.252/30", Duration::from_secs(60)).unwrap();
        assert_eq!(
            small.assign("one.test").unwrap().0,
            Ipv4Addr::new(198, 19, 255, 254)
        );
        assert!(small.assign("two.test").is_none());
    }

    #[test]
    fn target_recovery_rejects_unknown_and_unowned_synthetic_ips() {
        let map = FakeIpMap::new("198.18.0.0/24", Duration::from_secs(60)).unwrap();
        let (ip, _) = map.assign("example.test").unwrap();
        let target = SocketAddr::from((ip, 443));
        assert_eq!(
            resolve_target_host(target, Some(&map)).unwrap(),
            "example.test"
        );
        assert_eq!(
            resolve_target_host(target, None).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(resolve_target_host("198.19.0.2:443".parse().unwrap(), Some(&map)).is_err());
        assert!(resolve_target_host("[::ffff:198.18.0.2]:443".parse().unwrap(), None).is_err());
        assert_eq!(
            resolve_target_host("198.18.0.3:443".parse().unwrap(), Some(&map))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound,
            "an address never answered fails closed"
        );
        map.expire_mapping_for_test(ip);
        assert_eq!(
            resolve_target_host(target, Some(&map)).unwrap(),
            "example.test",
            "an idle binding never resolves to anything but its own name"
        );
        assert_eq!(
            resolve_target_host("127.0.0.1:443".parse().unwrap(), None).unwrap(),
            "127.0.0.1"
        );
    }

    #[test]
    fn preview_bootstrap_requires_selected_numeric_control_endpoints() {
        let mut wide = WideIngressSettings {
            dns_preview_listen: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let mut relay = RelaySettings {
            server: "relay.example.test:443".into(),
            server_name: "relay.example.test".into(),
            transport_priority: vec![TunnelTransportFamily::LegacyTls],
            ..Default::default()
        };
        assert!(validate_dns_preview_config(&wide, &relay).is_err());
        for invalid in [
            "198.18.0.2:443",
            "[::ffff:198.18.0.2]:443",
            "0.0.0.0:443",
            "127.0.0.1:0",
        ] {
            relay.server = invalid.into();
            assert!(
                validate_dns_preview_config(&wide, &relay).is_err(),
                "{invalid}"
            );
        }
        relay.server = "127.0.0.1:443".into();
        validate_dns_preview_config(&wide, &relay).expect("pinned dial");
        assert_eq!(relay.server_name, "relay.example.test");
        relay.server = "unresolved.test:443".into();
        wide.enabled = false;
        validate_dns_preview_config(&wide, &relay).expect("disabled preview");
        wide.enabled = true;
        wide.dns_preview_listen = None;
        validate_dns_preview_config(&wide, &relay).expect("preview not requested");
    }

    #[test]
    fn preview_bootstrap_checks_tcp_pool_and_independent_udp_settings() {
        let wide = WideIngressSettings {
            dns_preview_listen: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let mut relay = RelaySettings {
            server: "unpinned-top.test:443".into(),
            transport_priority: vec![TunnelTransportFamily::LegacyTls],
            endpoints: vec![aegis_core::RelayEndpointSettings {
                server: "127.0.0.1:443".into(),
                server_name: "relay.test".into(),
                masque_server: None,
                masque_server_name: None,
            }],
            ..Default::default()
        };
        validate_dns_preview_config(&wide, &relay).expect("TCP uses only pinned pool");
        relay.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
        validate_dns_preview_config(&wide, &relay).expect("UDP also uses pinned pool");
        relay.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);
        relay.masque_server = Some("127.0.0.1:8443".into());
        validate_dns_preview_config(&wide, &relay).expect("separate numeric UDP dial");
        relay.endpoints[0].server = "unpinned-pool.test:443".into();
        assert!(validate_dns_preview_config(&wide, &relay).is_err());
    }

    #[tokio::test]
    async fn aborted_required_dns_task_notifies_owner_without_dns_traffic() {
        let settings = WideIngressSettings {
            dns_preview_listen: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let listener = spawn_dns_preview(&settings, None).await.unwrap().unwrap();
        let mut failed = listener.failure_receiver();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), failed.changed())
                .await
                .is_err()
        );
        listener.task.as_ref().unwrap().abort();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), failed.changed())
                .await
                .unwrap()
                .is_err()
        );
        assert!(failed.has_changed().is_err());
        listener.shutdown().await;
    }

    #[tokio::test]
    async fn listener_shutdown_and_drop_release_socket_in_same_runtime() {
        let settings = WideIngressSettings {
            dns_preview_listen: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let listener = spawn_dns_preview(&settings, None).await.unwrap().unwrap();
        let listen = listener.listen;
        listener.shutdown().await;
        let rebound = UdpSocket::bind(listen)
            .await
            .expect("shutdown releases bind");
        drop(rebound);
        let settings = WideIngressSettings {
            dns_preview_listen: Some(listen),
            ..settings
        };
        let listener = spawn_dns_preview(&settings, None).await.unwrap().unwrap();
        let finished = listener.task.as_ref().unwrap().abort_handle();
        drop(listener);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !finished.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped owner terminates listener");
        UdpSocket::bind(listen).await.expect("drop releases bind");
    }

    #[tokio::test]
    async fn shutdown_cancels_owned_pending_forwarders() {
        // A real loopback DNS request; only the non-A relay call is replaced by
        // a pending local future so this cannot touch external DNS/transport.
        struct Dropped(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_dropped = dropped.clone();
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen = socket.local_addr().unwrap();
        let map = Arc::new(FakeIpMap::new("198.18.0.0/15", Duration::from_secs(60)).unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(run_dns_listener(
            socket,
            map,
            60,
            Some(RelaySettings::default()),
            "127.0.0.1:9".parse().unwrap(),
            shutdown_rx,
            move |_, _, _| {
                let guard = Dropped(task_dropped.clone());
                let started = started_tx.clone();
                async move {
                    let _guard = guard;
                    started.send(()).unwrap();
                    std::future::pending::<Vec<u8>>().await
                }
            },
            None,
        ));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 28, 0, 1];
        client.send_to(&query, listen).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
            .await
            .unwrap()
            .unwrap();
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        UdpSocket::bind(listen)
            .await
            .expect("forwarder released listener socket");
    }

    #[tokio::test]
    async fn disabled_listener_ignores_unused_pool_settings() {
        let settings = WideIngressSettings {
            dns_preview_listen: None,
            dns_preview_fake_ip_pool: "invalid-unused-pool".to_string(),
            ..WideIngressSettings::default()
        };

        assert!(spawn_dns_preview(&settings, None)
            .await
            .expect("disabled listener")
            .is_none());
    }

    #[tokio::test]
    async fn configured_listener_preserves_occupied_socket_error_kind() {
        let occupied = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("occupy loopback UDP port");
        let listen = occupied.local_addr().expect("occupied address");
        let settings = WideIngressSettings {
            dns_preview_listen: Some(listen),
            ..WideIngressSettings::default()
        };

        let error = spawn_dns_preview(&settings, None)
            .await
            .err()
            .expect("configured listener must fail");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error.to_string().contains(&listen.to_string()));
    }

    #[tokio::test]
    async fn configured_listener_rejects_invalid_pool() {
        let settings = WideIngressSettings {
            dns_preview_listen: Some("127.0.0.1:0".parse().expect("listen")),
            dns_preview_fake_ip_pool: "invalid-pool".to_string(),
            ..WideIngressSettings::default()
        };

        let error = spawn_dns_preview(&settings, None)
            .await
            .err()
            .expect("configured pool must be valid");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("pool invalid-pool"));
    }

    #[tokio::test]
    async fn configured_listener_binds_ephemeral_loopback_socket() {
        let settings = WideIngressSettings {
            dns_preview_listen: Some("127.0.0.1:0".parse().expect("listen")),
            capture_dns: false,
            ..WideIngressSettings::default()
        };

        assert!(spawn_dns_preview(&settings, None)
            .await
            .expect("bind configured listener")
            .is_some());
    }

    #[test]
    fn pool_parse_ok() {
        let m = FakeIpMap::new("198.18.0.0/15", Duration::from_secs(60)).unwrap();
        assert!(m.ip_in_pool("198.18.0.5".parse().unwrap()));
        assert!(m.ip_in_pool("198.19.255.254".parse().unwrap()));
        assert!(!m.ip_in_pool("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn assign_is_stable_within_ttl() {
        let m = FakeIpMap::new("198.18.0.0/24", Duration::from_secs(60)).unwrap();
        let (a, new_a) = m.assign("example.com").unwrap();
        let (b, new_b) = m.assign("example.com").unwrap();
        assert_eq!(a, b);
        assert!(new_a);
        assert!(!new_b);
        let host = m.lookup_hostname(a).unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn assign_distinct_hosts_get_distinct_ips() {
        let m = FakeIpMap::new("198.18.0.0/29", Duration::from_secs(60)).unwrap();
        let (a, _) = m.assign("a.com").unwrap();
        let (b, _) = m.assign("b.com").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn qname_parse_basic() {
        // 7 example 3 com 0
        let bytes = [
            7u8, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let (n, len) = parse_qname(&bytes).unwrap();
        assert_eq!(n, "example.com");
        assert_eq!(len, bytes.len());
    }

    #[test]
    fn build_response_a_query_synthesizes_fake_ip() {
        let map = Arc::new(FakeIpMap::new("198.18.0.0/16", Duration::from_secs(60)).unwrap());
        // build a minimal A query for example.com
        let mut req = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        req.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        req.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A QCLASS=IN
        let resp = build_response(&req, &map, 60);
        assert_eq!(resp[0], 0xab);
        assert_eq!(resp[1], 0xcd);
        // ANCOUNT at offset 6..8 should be 1
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        // RDATA at end: last 4 bytes = fake IP
        let ip = Ipv4Addr::new(
            resp[resp.len() - 4],
            resp[resp.len() - 3],
            resp[resp.len() - 2],
            resp[resp.len() - 1],
        );
        assert!(map.ip_in_pool(ip));
        let hostname = map.lookup_hostname(ip).unwrap();
        assert_eq!(hostname, "example.com");
    }

    #[test]
    fn build_response_aaaa_returns_nodata() {
        let map = Arc::new(FakeIpMap::new("198.18.0.0/16", Duration::from_secs(60)).unwrap());
        let mut req = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        req.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        req.extend_from_slice(&[0, 28, 0, 1]); // QTYPE=AAAA QCLASS=IN
        let resp = build_response(&req, &map, 60);
        // RCODE NOERROR, ANCOUNT = 0
        assert_eq!(resp[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[test]
    fn relayed_dns_servfail_discards_edns_bytes_with_zero_additional_count() {
        let mut request = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        request.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]);
        request.extend_from_slice(&[0, 28, 0, 1]);
        let question_end = request.len();
        // Root owner, OPT, UDP payload 1232, DO, no option data.
        request.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]);
        let response = dns_error_response(&request, 2);
        assert_eq!(response.len(), question_end);
        assert_eq!(&response[6..12], &[0; 6]);
        assert_eq!(response[3] & 0x0f, 2);
        assert!(aegis_core::dns_response::is_valid_relay_response(
            &request, &response
        ));
    }

    #[test]
    fn relayed_dns_response_must_match_transaction_and_be_a_response() {
        let mut request = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        request.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]);
        request.extend_from_slice(&[0, 28, 0, 1]);
        let mut response = request.clone();
        response[2] = 0x81;
        response[3] = 0x80;
        assert!(valid_dns_relay_response(&request, &response));
        response[1] = 0xce;
        assert!(!valid_dns_relay_response(&request, &response));
        response[1] = 0xcd;
        response[2] &= !DNS_QR_RESPONSE;
        assert!(!valid_dns_relay_response(&request, &response));
        response[2] |= DNS_QR_RESPONSE;
        response[13] = b'x';
        assert!(!valid_dns_relay_response(&request, &response));
    }

    #[test]
    fn dns_relay_failure_is_servfail_and_preserves_question() {
        let mut req = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        req.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]);
        req.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
        req.extend_from_slice(&QCLASS_IN.to_be_bytes());
        let response = dns_error_response(&req, DNS_RCODE_SERVFAIL);
        assert_eq!(&response[0..2], &req[0..2]);
        assert_ne!(response[2] & DNS_QR_RESPONSE, 0);
        assert_eq!(response[3] & 0x0f, DNS_RCODE_SERVFAIL);
        assert_eq!(&response[12..], &req[12..]);
    }

    /// An A query for `name` (id 1, one question).
    #[cfg(target_os = "linux")]
    fn preview_a_query(name: &str) -> Vec<u8> {
        let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]);
        query
    }

    /// The address and TTL of a one-answer A response; None without an answer.
    #[cfg(target_os = "linux")]
    fn preview_answer(response: &[u8]) -> Option<(Ipv4Addr, u32)> {
        if response[6..8] != [0, 1] {
            return None;
        }
        let n = response.len();
        let ttl = u32::from_be_bytes(response[n - 10..n - 6].try_into().unwrap());
        let ip = Ipv4Addr::new(
            response[n - 4],
            response[n - 3],
            response[n - 2],
            response[n - 1],
        );
        Some((ip, ttl))
    }

    /// The map the Linux listener builds (one per client process) never gives
    /// an answered address to another name within an hour of its last use,
    /// however short the answers' TTL: a resolver or an application may still
    /// use the answer (B-06 build 37: a 60 s answer used 67.6 s after it
    /// arrived; macOS keeps a 60 s answer about 77 s), and that answer would
    /// then reach the other name.
    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn preview_keeps_an_answered_address_from_other_names_for_the_recycle_idle() {
        // One usable address: a second name can only get it by recycling.
        let settings = WideIngressSettings {
            dns_preview_listen: Some("127.0.0.1:0".parse().unwrap()),
            dns_preview_fake_ip_pool: "198.19.255.252/30".into(),
            dns_preview_fake_ip_ttl_secs: 60,
            ..Default::default()
        };
        let listener = spawn_dns_preview(&settings, None).await.unwrap().unwrap();
        let map = Arc::clone(&listener.map);
        let (ip, ttl) = preview_answer(&build_response(&preview_a_query("old.test"), &map, 60))
            .expect("old.test is answered");
        assert_eq!(ttl, 60, "answers keep the configured TTL");
        let mut elapsed = 0;
        for at in [61, 77, 600, 3599] {
            tokio::time::advance(Duration::from_secs(at - elapsed)).await;
            elapsed = at;
            let other = build_response(&preview_a_query("new.test"), &map, 60);
            assert_eq!(
                preview_answer(&other),
                None,
                "{at} s after old.test's answer its address went to new.test"
            );
            assert_eq!(
                other[3] & 0x0f,
                DNS_RCODE_SERVFAIL,
                "a full pool fails the answer"
            );
        }
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            preview_answer(&build_response(&preview_a_query("new.test"), &map, 60)),
            Some((ip, 60)),
            "an idle hour recycles the address"
        );
        listener.shutdown().await;
    }

    /// Each listener is one client process's map. A restarted client that
    /// started where the previous one did would first give that process's
    /// answers, which applications may still cache, to other names.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_new_preview_listener_starts_its_addresses_at_a_random_offset() {
        let settings = WideIngressSettings {
            dns_preview_listen: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let mut firsts = Vec::new();
        for _ in 0..3 {
            let listener = spawn_dns_preview(&settings, None).await.unwrap().unwrap();
            let (ip, _) = preview_answer(&build_response(
                &preview_a_query("first.test"),
                &listener.map,
                60,
            ))
            .expect("first.test is answered");
            assert!(listener.map.ip_in_pool(ip));
            firsts.push(ip);
            listener.shutdown().await;
        }
        // Three runs at one start by chance: about 1 in 1.7e10.
        assert!(
            firsts.iter().any(|ip| *ip != firsts[0]),
            "every run started at {}",
            firsts[0]
        );
    }
}
