//! Actual packet-worker Store custody with permanently refusing relay services.
//! This is a source-only prerequisite, not a provider factory or packet grant.
//! No authenticated H2/ACK/renewal owner is present, so no native callback may
//! use the bridge even while this inert worker runs.
#![allow(dead_code)]

use crate::{
    bridge::LeasedPacketBridge,
    packet_engine::{PacketEngineConfig, PacketEngineOwner},
    store_last_thread::StoreLastThreadOwner,
};
use aegis_client::{
    packet_engine::services::{EngineEvent, EventSink, RelayServices, RelayWork},
    protected_online_expectation::ProtectedOnlineExpectation,
    relay_runtime_types::{ConnectTarget, UdpPacket},
};
use aegis_core::RelaySettings;
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};
use tokio::{net::TcpStream, sync::mpsc as tokio_mpsc};

fn denied() -> anyhow::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "relay service closed").into()
}

/// The real packet engine's injected service trait is closed in every method.
/// No dial, bridge credential use, UDP datagram or traffic relay is possible.
pub(crate) struct ClosedRelayServices;
impl EventSink for ClosedRelayServices {
    fn emit(&self, _: &'static str, _: EngineEvent, _: &'static str, _: serde_json::Value) {}
}
impl RelayServices for ClosedRelayServices {
    fn tcp<'a>(
        &'a self,
        local: TcpStream,
        _: &'a RelaySettings,
        _: String,
        _: u16,
    ) -> RelayWork<'a, ()> {
        Box::pin(async move {
            drop(local);
            Err(denied())
        })
    }
    fn udp_once<'a>(
        &'a self,
        _: &'a RelaySettings,
        _: ConnectTarget,
        _: &'a [u8],
    ) -> RelayWork<'a, Vec<u8>> {
        Box::pin(async { Err(denied()) })
    }
    fn udp_flow<'a>(
        &'a self,
        _: &'a RelaySettings,
        _: &'a str,
        _: u16,
        outgoing: tokio_mpsc::Receiver<Vec<u8>>,
        incoming: tokio_mpsc::Sender<UdpPacket>,
    ) -> RelayWork<'a, ()> {
        Box::pin(async move {
            drop((outgoing, incoming));
            Err(denied())
        })
    }
}

/// One bounded join observation of `packet_terminal`'s wait (S16j-3: it
/// counts against the provider's stop budget).
pub(crate) const PACKET_JOIN_SLICE: Duration = Duration::from_millis(100);

pub(crate) fn packet_terminal(mut packet: PacketEngineOwner) -> io::Result<()> {
    packet.cancel();
    let mut terminal_error = None;
    loop {
        if let Err(error) = packet.try_join(PACKET_JOIN_SLICE) {
            if error.kind() != io::ErrorKind::TimedOut {
                terminal_error.get_or_insert(error);
            }
        }
        if packet.owned_children_joined() {
            break;
        }
        // A stuck actual worker may keep this supervisor and its Store alive
        // indefinitely. The controller has a bounded wait and cannot release
        // Store or report successful terminal shutdown before a real join.
        thread::sleep(Duration::from_millis(2));
    }
    // `try_join` may have returned TimedOut while relay work was still active,
    // then the final work lease dropped before the physical-barrier read.
    // Re-read the retained terminal result after the barrier: a worker error
    // must never be converted into an apparently successful Store release.
    if let Err(error) = packet.try_join(Duration::ZERO) {
        terminal_error.get_or_insert(error);
    }
    terminal_error.map_or(Ok(()), Err)
}

/// R53's OS supervisor opens the *real* PacketEngineOwner only after it owns
/// the exact protected Store expectation. The permanent closed service keeps
/// this a negative/inert prerequisite. There is no native packetFlow caller.
#[must_use = "retain the packet supervisor until actual terminal join"]
pub(crate) struct StoreScopedPacketOwner {
    bridge: LeasedPacketBridge,
    supervisor: StoreLastThreadOwner,
    ready: mpsc::Receiver<io::Result<()>>,
    packet_joined: Arc<AtomicBool>,
}

impl StoreScopedPacketOwner {
    pub(crate) fn spawn(
        store: ProtectedOnlineExpectation<'static>,
        bridge: LeasedPacketBridge,
        config: PacketEngineConfig,
    ) -> io::Result<Self> {
        let outer_bridge = bridge.clone();
        let (ready, received) = mpsc::sync_channel(1);
        let joined = Arc::new(AtomicBool::new(false));
        let joined_worker = joined.clone();
        let supervisor = match StoreLastThreadOwner::spawn(store, move |_store, stop| {
            let mut packet =
                match PacketEngineOwner::spawn(bridge, config, Arc::new(ClosedRelayServices)) {
                    Ok(owner) => owner,
                    Err(error) => {
                        let _ = ready.send(Err(io::Error::new(error.kind(), error.to_string())));
                        return Err(error);
                    }
                };
            let constructed = packet.wait_engine_constructed(Duration::from_secs(2));
            let _ = ready.send(
                constructed
                    .as_ref()
                    .map(|_| ())
                    .map_err(|error| io::Error::new(error.kind(), error.to_string())),
            );
            if constructed.is_ok() {
                while !stop.load(Ordering::Acquire) && !packet.terminal_signal_observed() {
                    thread::sleep(Duration::from_millis(2));
                }
            }
            let result = packet_terminal(packet);
            joined_worker.store(true, Ordering::Release);
            result
        }) {
            Ok(supervisor) => supervisor,
            Err(error) => {
                // No packet owner was started if this OS-thread spawn failed.
                outer_bridge.stop();
                return Err(error);
            }
        };
        Ok(Self {
            bridge: outer_bridge,
            supervisor,
            ready: received,
            packet_joined: joined,
        })
    }

    pub(crate) fn wait_constructed(&self, budget: Duration) -> io::Result<()> {
        self.ready
            .recv_timeout(budget)
            .map_err(|_| io::ErrorKind::TimedOut)?
    }

    pub(crate) fn stop_and_join(&mut self, budget: Duration) -> io::Result<()> {
        if budget > Duration::from_secs(2) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.bridge.stop();
        self.supervisor.stop_and_join(budget)
    }
}

impl Drop for StoreScopedPacketOwner {
    fn drop(&mut self) {
        self.bridge.stop();
        // R53 asks the supervisor to stop; the Store stays in that OS thread
        // until packet_terminal observes a real mechanics join.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::PacketBridge;
    use aegis_client::{
        capture_lease_gate::CaptureLeaseDeadline, protected_identity_store::ProtectedIdentityStore,
    };
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, time::Instant};
    static FIXTURE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "aegis-ne-store-packet-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let identity = dir.join("identity");
            fs::create_dir_all(&identity).unwrap();
            fs::set_permissions(&identity, fs::Permissions::from_mode(0o700)).unwrap();
            for (name, data) in [(".lock", b"".as_slice()), ("identity.json", b"fixture")] {
                let path = identity.join(name);
                fs::write(&path, data).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            Self(identity)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.0.parent().unwrap());
        }
    }

    fn config() -> PacketEngineConfig {
        PacketEngineConfig {
            relay: RelaySettings::default(),
            max_flows: 2,
            idle: Duration::from_secs(1),
            mtu: 1280,
            dns_upstream: "127.0.0.1:9".parse().unwrap(),
        }
    }
    fn inert_bridge() -> LeasedPacketBridge {
        // Local-only mechanics fixture; no NetworkExtension packetFlow uses it.
        // A production deadline must come from the exact live ACK owner.
        let lease = CaptureLeaseDeadline::default();
        lease.replace(Some(u64::MAX)).unwrap();
        LeasedPacketBridge::new(PacketBridge::default(), lease)
    }

    #[test]
    fn actual_packet_worker_joins_before_protected_store_reopens() {
        let fixture = Fixture::new();
        let store =
            ProtectedOnlineExpectation::open_existing(fixture.path(), &"d".repeat(64)).unwrap();
        let bridge = inert_bridge();
        let mut owner = StoreScopedPacketOwner::spawn(store, bridge.clone(), config()).unwrap();
        owner.wait_constructed(Duration::from_secs(2)).unwrap();
        assert!(ProtectedIdentityStore::open_existing(fixture.path()).is_err());
        let stopped = owner.stop_and_join(Duration::from_secs(2));
        if let Err(error) = stopped {
            // Actual queue seal can surface as an original non-cancel error.
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        }
        assert!(owner.packet_joined.load(Ordering::Acquire));
        assert!(bridge.is_sealed());
        ProtectedIdentityStore::open_existing(fixture.path()).unwrap();
    }

    #[test]
    fn controller_drop_seals_bridge_and_worker_keeps_store_until_join() {
        let fixture = Fixture::new();
        let store =
            ProtectedOnlineExpectation::open_existing(fixture.path(), &"e".repeat(64)).unwrap();
        let bridge = inert_bridge();
        let owner = StoreScopedPacketOwner::spawn(store, bridge.clone(), config()).unwrap();
        owner.wait_constructed(Duration::from_secs(2)).unwrap();
        let joined = owner.packet_joined.clone();
        assert!(ProtectedIdentityStore::open_existing(fixture.path()).is_err());
        drop(owner);
        assert!(bridge.is_sealed());
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match ProtectedIdentityStore::open_existing(fixture.path()) {
                Ok(open) => {
                    drop(open);
                    break;
                }
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                Err(error) => panic!("actual packet join did not release Store: {error}"),
            }
        }
        assert!(joined.load(Ordering::Acquire));
    }

    #[test]
    fn external_bridge_terminal_joins_children_without_controller_stop() {
        let fixture = Fixture::new();
        let store =
            ProtectedOnlineExpectation::open_existing(fixture.path(), &"f".repeat(64)).unwrap();
        let bridge = inert_bridge();
        let owner = StoreScopedPacketOwner::spawn(store, bridge.clone(), config()).unwrap();
        owner.wait_constructed(Duration::from_secs(2)).unwrap();
        assert!(ProtectedIdentityStore::open_existing(fixture.path()).is_err());
        bridge.stop();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match ProtectedIdentityStore::open_existing(fixture.path()) {
                Ok(open) => {
                    drop(open);
                    break;
                }
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                Err(error) => panic!("terminal bridge did not join packet children: {error}"),
            }
        }
        assert!(owner.packet_joined.load(Ordering::Acquire));
    }
}
