//! One signed enrolled H3 connection, bound to the current physical epoch.
//!
//! Its exact UDP permission and an extra WorkGate permit remain alive in
//! every Quinn reactor until that reactor's future actually drops. Neither a
//! dropped dial nor an unpolled driver can release the permission early.
use crate::{
    held_relay_services::WorkGate,
    provider_session_body::{EpochPins, UdpMediaLease},
    relay_socket::{bound_udp_socket, RelayInterface},
};
use aegis_client::prepared_enrolled_quic::{
    HeldQuicConnection, HeldQuicDriver, PreparedQuicClient,
};
use std::{future::Future, pin::Pin};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::{oneshot, OwnedSemaphorePermit};

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "held QUIC epoch refused")
}

struct QuicLifetime {
    // Drop the exact permissions before the last permit returns. WorkGate's
    // drain therefore includes socket/driver disposal and permission release.
    _permissions: Vec<UdpMediaLease<'static>>,
    _permit: OwnedSemaphorePermit,
}

/// The monitor can retain its ACK channel while the WorkGate stops. The
/// actual pump is a gate task, so stopping the gate aborts it and its Quinn
/// reactors without waiting for that monitor to release the channel. The
/// watcher also aborts its own task on ordinary channel drop.
pub(crate) fn own_driver(
    driver: HeldQuicDriver,
    gate: &WorkGate,
) -> io::Result<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let (done, ended) = oneshot::channel::<()>();
    let task = gate.spawn(async move {
        let _ = driver.await;
        drop(done);
    })?;
    Ok(Box::pin(async move {
        let _abort_on_drop = task;
        let _ = ended.await;
    }))
}

#[allow(clippy::too_many_arguments)] // Every argument binds a distinct security owner.
pub(crate) async fn connect(
    crypto: &PreparedQuicClient,
    peer: SocketAddr,
    tls_name: &str,
    interface: &RelayInterface,
    pins: &EpochPins,
    generation: u64,
    gate: &WorkGate,
    budget: Duration,
) -> anyhow::Result<HeldQuicConnection> {
    if budget.is_zero()
        || peer.port() == 0
        || peer.ip().is_unspecified()
        || peer.ip().is_multicast()
        || pins.generation() != generation
        || pins.get().as_ref() != Some(interface)
        || !crate::leak_guard::LEAK_GUARD.guarding_now()
    {
        return Err(refused().into());
    }
    let permit = gate.admit()?;
    // The sole candidate is the caller's exact signed endpoint. This does
    // not turn on udp_relay or permit UDP to other TCP pins.
    let permissions = pins
        .authorize_udp_media(generation, interface, &[peer])
        .ok_or_else(refused)?;
    let lifetime = Arc::new(QuicLifetime {
        _permissions: permissions,
        _permit: permit,
    });
    let socket = bound_udp_socket(peer, interface)?;
    if pins.generation() != generation
        || pins.get().as_ref() != Some(interface)
        || !crate::leak_guard::LEAK_GUARD.guarding_now()
    {
        return Err(refused().into());
    }
    crypto
        .connect(peer, tls_name, socket, budget, lifetime)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FutureLifetime {
        dropped: Arc<AtomicBool>,
        _permit: OwnedSemaphorePermit,
    }

    impl Drop for FutureLifetime {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    fn pending_driver(gate: &WorkGate, dropped: Arc<AtomicBool>) -> HeldQuicDriver {
        let lifetime = FutureLifetime {
            dropped,
            _permit: gate.admit().unwrap(),
        };
        Box::pin(async move {
            let _lifetime = lifetime;
            std::future::pending::<()>().await;
            Ok(())
        })
    }

    #[tokio::test]
    async fn retained_ack_watcher_cannot_block_gate_stop() {
        let gate = WorkGate::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let mut retained_channel =
            own_driver(pending_driver(&gate, dropped.clone()), &gate).unwrap();
        assert_eq!(gate.flows(), 1);
        gate.stop_async(Duration::from_secs(1)).await.unwrap();
        assert!(gate.drained());
        assert!(dropped.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(1), &mut retained_channel)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn pre_ready_drop_before_first_poll_releases_owned_driver() {
        let gate = WorkGate::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let channel = own_driver(pending_driver(&gate, dropped.clone()), &gate).unwrap();
        drop(channel);
        gate.stop_async(Duration::from_secs(1)).await.unwrap();
        assert!(gate.drained());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn closed_gate_refuses_and_drops_unspawned_driver() {
        let gate = WorkGate::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let driver = pending_driver(&gate, dropped.clone());
        assert!(gate.stop_async(Duration::ZERO).await.is_err());
        assert!(own_driver(driver, &gate).is_err());
        gate.stop_async(Duration::from_secs(1)).await.unwrap();
        assert!(gate.drained());
        assert!(dropped.load(Ordering::SeqCst));
    }
}
