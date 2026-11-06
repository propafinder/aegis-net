//! Windows system ingress. Privileged setup is completed before SCM readiness;
//! TCP, UDP and DNS use the existing authenticated relay transports.
use crate::{ingress::wide::ip_tunnel, Args};
use aegis_core::{
    tunnel_policy::{Prefix, ANCHOR_V4},
    windows_tunnel::{
        firewall, lifecycle,
        network::{self, NetworkGuard},
        wintun::Wintun,
    },
    Mode, Settings,
};
use anyhow::Context;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::watch;
struct WatchedDevice<'a> {
    tun: &'a mut Wintun,
    pins: Vec<std::net::SocketAddr>,
    routable_pins: Vec<std::net::SocketAddr>,
    signature: Vec<(u64, String, u32)>,
    checked: std::time::Instant,
}
impl ip_tunnel::PacketIo for WatchedDevice<'_> {
    fn receive(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.checked.elapsed() >= Duration::from_secs(2) {
            self.checked = std::time::Instant::now();
            if network::default_route_signature(self.tun.luid)? != self.signature {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "physical gateway changed",
                ));
            }
        }
        let packet = self.tun.receive()?;
        if let Some(destination) = packet
            .as_ref()
            .and_then(|p| crate::ingress::wide::linux_nfqueue::decode_packet(p).ok())
            .map(|p| p.dst())
            .filter(|dst| self.pins.iter().any(|pin| pin.ip() == *dst))
        {
            if !self.routable_pins.iter().any(|pin| pin.ip() == destination) {
                // The configured relay family has no physical route. Never
                // recursively send that dial through the relay packet engine.
                // Its bounded opening failure can use another pool endpoint.
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "relay exclusion needs rebuilding",
            ));
        }
        Ok(packet)
    }
    fn send(&mut self, p: &[u8]) -> std::io::Result<()> {
        self.tun.send(p)
    }
}

fn relay_routes(
    pins: &[std::net::SocketAddr],
    mut query: impl FnMut(std::net::IpAddr) -> std::io::Result<network::Route>,
) -> std::io::Result<Vec<(std::net::SocketAddr, network::Route)>> {
    let mut available = Vec::new();
    for pin in pins {
        match query(pin.ip()) {
            Ok(route) => available.push((*pin, route)),
            Err(error) if matches!(error.raw_os_error(), Some(1168 | 1231 | 1232)) => {}
            Err(error) => return Err(error),
        }
    }
    if available.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NetworkUnreachable,
            "no relay has a physical route",
        ));
    }
    Ok(available)
}

async fn wait_stopped(stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub(crate) async fn run(
    cfg: Settings,
    args: &Args,
    mut shutdown: Option<watch::Receiver<bool>>,
    config: &Path,
) -> anyhow::Result<()> {
    let mut tunnel = cfg
        .windows_tunnel
        .clone()
        .context("Windows tunnel settings missing")?;
    tunnel.validate().map_err(anyhow::Error::msg)?;
    if !matches!(cfg.mode, Mode::Relay) || cfg.ingress.allow_fallback {
        anyhow::bail!("Windows system tunnel requires relay mode without ingress fallback");
    }
    let mut pins = tunnel.relay_pins(&cfg.relay).map_err(anyhow::Error::msg)?;
    let online_bundle = args.device_online_bundle.clone();
    if let Some(bundle) = online_bundle.as_deref() {
        let (profile, _) = crate::device_bundle::online::OnlineProfile::for_runtime(bundle, &cfg)?;
        let authority: std::net::SocketAddr = profile
            .carrier()
            .server
            .parse()
            .context("Windows renewal requires a pinned authority endpoint")?;
        if !pins.contains(&authority) {
            pins.push(authority);
        }
    }
    if !crate::relay::runtime_udp_fallback_ready(&cfg.relay) {
        anyhow::bail!("UDP relay configuration is not executable");
    }
    if tunnel.driver.is_relative() {
        tunnel.driver = std::env::current_exe()?
            .parent()
            .context("executable directory")?
            .join(&tunnel.driver);
    }
    let journal = lifecycle::journal_path(config);
    if args.ingress_preflight {
        // Hash verification without loading a driver or changing networking.
        use sha2::{Digest, Sha256};
        aegis_core::windows_file::reject_reparse_ancestry(&tunnel.driver)?;
        let mut file = std::fs::File::open(&tunnel.driver).context("open pinned Wintun DLL")?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > 2 * 1024 * 1024 {
            anyhow::bail!("Wintun DLL is not a bounded regular file");
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(&mut file, 2 * 1024 * 1024 + 1),
            &mut bytes,
        )?;
        if format!("{:x}", Sha256::digest(&bytes)) != aegis_core::windows_tunnel::wintun::DLL_SHA256
        {
            anyhow::bail!("Wintun DLL integrity rejected");
        }
        println!(
            "{}",
            serde_json::json!({"ok":true,"backend":"windows_wintun","scope":if tunnel.include_routes.is_empty(){"full"}else{"split"},"tcp":true,"udp":true,"dns":"relay_fake_ip","kill_switch":tunnel.kill_switch,"driver_integrity":true,"network_mutated":false})
        );
        return Ok(());
    }
    let probe = args.ingress_startup_probe;
    let service = args.windows_service;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    struct Stop(Arc<AtomicBool>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let _cancel = Stop(stop.clone());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let runtime = tokio::runtime::Handle::current();
    let mut worker = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let _exclusive = lifecycle::Exclusive::acquire()?;
        let mut ready_tx = Some(ready_tx);
        loop {
            if thread_stop.load(Ordering::Acquire) {
                return Ok(());
            }
            lifecycle::recover_routes(&journal).context("recover previous owned routes")?;
            // Hold the thread-owned machine mutex throughout issuance and
            // capture. Arm only the executable's exact relay/authority tuples
            // before opening an online control connection; no adapter permit.
            if online_bundle.is_some() && !probe {
                firewall::protect_control(&std::env::current_exe()?, &pins)
                    .context("protect certificate recovery control path")?;
            }
            let supervisor = if probe {
                None
            } else {
                let initialized = runtime.block_on(async {
                    tokio::select! {
                        result = crate::device_renewal::Supervisor::start(online_bundle.as_deref(), &cfg) => result.map(Some),
                        _ = wait_stopped(&thread_stop) => Ok(None),
                    }
                })?;
                let Some(supervisor) = initialized else {
                    return Ok(());
                };
                Some(supervisor)
            };
            // A probe deliberately exercises only adapter creation and interface
            // configuration, never default routes or machine-wide firewall policy.
            let mut tun =
                Wintun::open(&tunnel.driver, &tunnel.adapter_name).context("open signed Wintun")?;
            let mut network =
                NetworkGuard::configure(tun.luid, tunnel.mtu, !probe && tunnel.configure_dns)
                    .context("configure tunnel interface")?;
            if probe {
                println!(
                    "{}",
                    serde_json::json!({"ok":true,"backend":"windows_wintun","adapter_created":true,"default_routes_changed":false})
                );
                return Ok(());
            }
            let mut intended = vec![];
            let available = relay_routes(&pins, network::native_route)
                .context("snapshot relay native routes")?;
            let routable_pins = available.iter().map(|(pin, _)| *pin).collect();
            for (_, route) in available {
                if !route.exists()?
                    && !intended
                        .iter()
                        .any(|r: &network::Route| r.prefix == route.prefix)
                {
                    intended.push(route);
                }
            }
            // DNS and synthetic addresses must also be captured in an explicit
            // split profile. The pool excludes the adapter's own subnet.
            let mut routes = tunnel.routes().map_err(anyhow::Error::msg)?;
            for value in ["198.18.0.0/16".to_string(), format!("{ANCHOR_V4}/32")] {
                let prefix = Prefix::parse(&value).map_err(anyhow::Error::msg)?;
                if !routes
                    .iter()
                    .any(|p| p.contains(prefix.address) && p.length <= prefix.length)
                {
                    routes.push(prefix);
                }
            }
            for prefix in routes {
                let next_hop = if prefix.address.is_ipv4() {
                    "0.0.0.0"
                } else {
                    "::"
                }
                .parse()?;
                let route = network::Route {
                    luid: tun.luid,
                    index: network.index,
                    prefix,
                    next_hop,
                    scope_id: 0,
                    metric: 0,
                };
                if route.exists()? {
                    anyhow::bail!("capture route already exists; refusing to adopt it");
                }
                intended.push(route);
            }
            lifecycle::prepare(&journal)?;
            network.handoff_cleanup_to_journal();
            // Protection persists on setup failure, normal service stop and crash.
            // Explicit winctl tunnel disconnect restores unprotected networking.
            let protection = if tunnel.kill_switch {
                Some(
                    firewall::install(tun.luid, &std::env::current_exe()?, &pins, None)
                        .context("install persistent kill switch and live interface permit")?,
                )
            } else {
                None
            };
            for route in intended {
                // The durable pending record refuses ambiguous recovery if the
                // process dies between native creation and ownership commit.
                lifecycle::begin_route(&journal, route.clone())
                    .context("record pending tunnel route")?;
                network.add(route).context("install owned tunnel route")?;
                lifecycle::commit_route(&journal).context("commit owned tunnel route")?;
            }
            let signature = network::default_route_signature(tun.luid)?;
            if let Some(supervisor) = &supervisor {
                let confirmed = runtime.block_on(async {
                    tokio::select! {
                        result = supervisor.confirm_before_ready() => result.map(|()| true),
                        _ = wait_stopped(&thread_stop) => Ok(false),
                    }
                })?;
                if !confirmed {
                    return Ok(());
                }
            }
            // A due/invalid identity only asks this worker to stop. Issuance
            // happens on the next SCM startup, after owned routes recover and
            // with the persistent block still in force.
            let renewal_failure = Arc::new(std::sync::Mutex::new(None));
            struct Monitor(Option<tokio::task::JoinHandle<()>>);
            impl Drop for Monitor {
                fn drop(&mut self) {
                    if let Some(task) = self.0.take() {
                        task.abort();
                    }
                }
            }
            let _monitor = Monitor(supervisor.map(|mut supervisor| {
                let reason = renewal_failure.clone();
                let stopped = thread_stop.clone();
                runtime.spawn(async move {
                    let failure = supervisor.failure().await;
                    if let Ok(mut reason) = reason.lock() {
                        *reason = Some(failure);
                    }
                    stopped.store(true, Ordering::Release);
                })
            }));
            let result = ip_tunnel::run_ready(
                &mut WatchedDevice {
                    tun: &mut tun,
                    pins: pins.clone(),
                    routable_pins,
                    signature,
                    checked: std::time::Instant::now(),
                },
                cfg.relay.clone(),
                thread_stop.clone(),
                tunnel.max_flows,
                Duration::from_secs(tunnel.idle_timeout_secs),
                tunnel.mtu as usize,
                tunnel.dns_upstream,
                || {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }
                },
            );
            // Remove the dynamic exception before routes or adapter identity
            // can disappear or be reused, retaining the persistent block.
            drop(protection);
            lifecycle::recover_routes(&journal).context("remove journal-owned tunnel routes")?;
            network.routes.clear();
            if let Some(reason) = *renewal_failure
                .lock()
                .map_err(|_| anyhow::anyhow!("renewal monitor lock failed"))?
            {
                anyhow::bail!("{reason}");
            }
            if result
                .as_ref()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::Interrupted)
            {
                drop(network);
                drop(tun);
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
            let stats = result.context("system tunnel packet engine")?;
            tracing::info!(
                packets_received = stats.packets_received,
                packets_sent = stats.packets_sent,
                packets_dropped = stats.packets_dropped,
                "Windows system tunnel stopped"
            );
            return Ok(());
        }
    });
    if probe {
        return worker.await?;
    }
    let signal = async {
        if let Some(receiver) = shutdown.as_mut() {
            while !*receiver.borrow() {
                if receiver.changed().await.is_err() {
                    break;
                }
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    };
    let mut stdin = crate::spawn_stdin_eof_shutdown(args.exit_on_stdin_eof);
    let eof = async {
        if let Some(receiver) = stdin.as_mut() {
            while !*receiver.borrow() {
                if receiver.changed().await.is_err() {
                    break;
                }
            }
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(signal);
    tokio::pin!(eof);
    tokio::select! {
        ready=ready_rx => { if ready.is_err() { return worker.await?; } },
        result=&mut worker => return result?,
        _=&mut signal => { stop.store(true,Ordering::Release); return worker.await?; },
        _=&mut eof => { stop.store(true,Ordering::Release); return worker.await?; },
    }
    if service {
        crate::windows_service::ready();
    }
    tokio::select! {result=&mut worker=>return result?,_=&mut signal=>{stop.store(true,Ordering::Release);},_=&mut eof=>{stop.store(true,Ordering::Release);}}
    worker.await?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relay_pool_keeps_routable_family_and_rejects_unexpected_os_errors() {
        let pins = [
            "192.0.2.7:443".parse().unwrap(),
            "[2001:db8::7]:443".parse().unwrap(),
        ];
        let route = network::Route {
            luid: 7,
            index: 7,
            prefix: Prefix::parse("192.0.2.7/32").unwrap(),
            next_hop: "192.0.2.1".parse().unwrap(),
            scope_id: 0,
            metric: 0,
        };
        let available = relay_routes(&pins, |ip| {
            if ip.is_ipv4() {
                Ok(route.clone())
            } else {
                Err(std::io::Error::from_raw_os_error(1168))
            }
        })
        .unwrap();
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].0, pins[0]);
        assert_eq!(
            relay_routes(&pins, |_| Err(std::io::Error::from_raw_os_error(1231)))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NetworkUnreachable
        );
        assert_eq!(
            relay_routes(&pins, |_| Err(std::io::Error::from_raw_os_error(5)))
                .unwrap_err()
                .raw_os_error(),
            Some(5)
        );
    }
}
