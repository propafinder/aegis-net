//! Selected relay-only Geneva dialing. A failed selected driver is terminal;
//! there is no call to ordinary TCP connect in that branch.
use aegis_core::{relay_geneva::RelayProtectedTcp, RelaySettings};
#[cfg(target_os = "linux")]
use std::net::SocketAddrV4;
use std::{io, net::SocketAddr};

#[cfg(target_os = "linux")]
struct Selected {
    digest: [u8; 32],
    endpoints: Vec<SocketAddrV4>,
    runtime: std::sync::Arc<aegis_core::relay_geneva::linux::LinuxRuntime>,
}
#[cfg(target_os = "linux")]
static SELECTED: std::sync::OnceLock<Result<Selected, &'static str>> = std::sync::OnceLock::new();
#[cfg(target_os = "linux")]
static STOPPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Observe an already selected runtime without starting it or acquiring authority.
/// The caller owns this future; cancelling it creates no detached monitor task.
pub(crate) async fn failure(selected: bool) -> &'static str {
    #[cfg(target_os = "linux")]
    {
        wait_for_failure(selected, || {
            selected_terminal(&SELECTED, |value| value.runtime.is_failed())
        })
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = selected;
        std::future::pending().await
    }
}

#[cfg(any(target_os = "linux", test))]
fn selected_terminal<T>(
    cell: &std::sync::OnceLock<Result<T, &'static str>>,
    failed: impl FnOnce(&T) -> bool,
) -> bool {
    match cell.get() {
        Some(Ok(value)) => failed(value),
        Some(Err(_)) => true,
        None => false,
    }
}

#[cfg(any(target_os = "linux", test))]
async fn wait_for_failure(selected: bool, mut failed: impl FnMut() -> bool) -> &'static str {
    if !selected {
        return std::future::pending().await;
    }
    loop {
        if failed() {
            return "selected relay Geneva runtime became terminal; explicit recovery required";
        }
        // Read-only userspace observation, not a hard native shutdown deadline.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Called after the selected ingress/session scope drops its protected streams.
/// A selected instance never restarts after a failed or orderly terminal state.
pub(crate) async fn shutdown() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        STOPPED.store(true, std::sync::atomic::Ordering::Release);
        tokio::task::spawn_blocking(|| {
            match SELECTED.get_or_init(|| Err("relay Geneva selected instance is terminal")) {
                Ok(selected) => selected.runtime.quiesce(),
                Err(_) => Ok(()),
            }
        })
        .await
        .map_err(|_| refused("relay Geneva shutdown worker refused"))?
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

pub(super) async fn connect(settings: &RelaySettings) -> io::Result<RelayProtectedTcp> {
    let Some(request) = &settings.outer_geneva else {
        return super::connect_relay_tcp(&settings.server)
            .await
            .map(Into::into);
    };
    let SocketAddr::V4(addr) = settings
        .server
        .parse::<SocketAddr>()
        .map_err(|_| refused("relay Geneva requires a literal IPv4 endpoint"))?
    else {
        return Err(refused("relay Geneva IPv6 dial is unsupported"));
    };
    // Defense for callers constructing RelaySettings without config::load_config.
    if settings.inner_tls.is_none() || settings.validate_inner_tls_transport().is_err() {
        return Err(refused(
            "relay Geneva requires its authenticated TCP carrier",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        use aegis_core::relay_geneva::linux::LinuxRuntime;
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(
            serde_json::to_vec(request)
                .map_err(|_| refused("relay Geneva request serialization refused"))?,
        )
        .into();
        let request = request.clone();
        if STOPPED.load(std::sync::atomic::Ordering::Acquire) {
            return Err(refused("relay Geneva selected instance is terminal"));
        }
        // Initialization runs to completion in an owned blocking task even if
        // the requesting dial future is cancelled. Tokio OnceCell's cancelled
        // initializer would otherwise leave a live native worker unregistered.
        let selected = tokio::task::spawn_blocking(move || {
            owned_initialization(&SELECTED, &STOPPED, || {
                let (endpoints, authorization) =
                    crate::profile_relay_geneva::runtime_authorization(&request, addr)
                        .map_err(|_| "installed relay Geneva authorization refused")?;
                let started = LinuxRuntime::start_with_installed_guard(
                    &request,
                    endpoints.clone(),
                    authorization,
                );
                match started {
                    // The shutdown initializer waits on this same OnceLock.
                    // Retain the actual runtime even if STOPPED raced startup so
                    // terminal cleanup can report its checked quiescence result.
                    Ok(runtime) => Ok(Selected {
                        digest,
                        endpoints,
                        runtime,
                    }),
                    Err(_) => Err("relay Geneva driver startup failed closed"),
                }
            })
        })
        .await
        .map_err(|_| refused("relay Geneva startup task refused"))?
        .as_ref()
        .map_err(|message| refused(message))?;
        if STOPPED.load(std::sync::atomic::Ordering::Acquire) {
            return Err(refused("relay Geneva selected instance is terminal"));
        }
        if selected.digest != digest || !selected.endpoints.contains(&addr) {
            return Err(refused(
                "relay Geneva runtime ownership differs from requested endpoint",
            ));
        }
        let (tcp, guard) = selected.runtime.connect(addr).await?;
        RelayProtectedTcp::protected(tcp, Box::new(guard))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (request, addr);
        Err(refused(
            "relay Geneva native driver is unavailable on this platform",
        ))
    }
}
#[cfg(any(target_os = "linux", test))]
fn owned_initialization<'a, T>(
    cell: &'a std::sync::OnceLock<Result<T, &'static str>>,
    stopped: &std::sync::atomic::AtomicBool,
    factory: impl FnOnce() -> Result<T, &'static str>,
) -> &'a Result<T, &'static str> {
    cell.get_or_init(|| {
        if stopped.load(std::sync::atomic::Ordering::Acquire) {
            Err("relay Geneva startup refused after shutdown")
        } else {
            factory()
        }
    })
}

fn refused(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.to_owned())
}

#[cfg(test)]
mod lifecycle_tests {
    use super::owned_initialization;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, OnceLock,
    };
    #[test]
    fn failed_factory_is_terminal_and_never_restarted() {
        let cell = OnceLock::<Result<(), &'static str>>::new();
        let stopped = AtomicBool::new(false);
        let calls = AtomicUsize::new(0);
        assert!(owned_initialization(&cell, &stopped, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err("failed")
        })
        .is_err());
        assert!(owned_initialization(&cell, &stopped, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn shutdown_before_factory_never_creates_owned_resources() {
        let cell = OnceLock::<Result<(), &'static str>>::new();
        let stopped = AtomicBool::new(true);
        assert!(owned_initialization(&cell, &stopped, || panic!(
            "factory after terminal shutdown"
        ))
        .is_err());
    }
    #[test]
    fn shutdown_waits_for_owned_initializer_and_retains_actual_resource() {
        let cell = Arc::new(OnceLock::<Result<u64, &'static str>>::new());
        let stopped = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let c = Arc::clone(&cell);
        let stop = Arc::clone(&stopped);
        let initializer = std::thread::spawn(move || {
            *owned_initialization(&c, &stop, || {
                ready_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(37)
            })
        });
        ready_rx.recv().unwrap();
        stopped.store(true, Ordering::Release);
        let (cleanup_tx, cleanup_rx) = std::sync::mpsc::channel();
        let c = Arc::clone(&cell);
        let cleanup = std::thread::spawn(move || {
            let resource = *c.get_or_init(|| Err("terminal"));
            cleanup_tx.send(resource).unwrap();
        });
        assert!(cleanup_rx.try_recv().is_err());
        release_tx.send(()).unwrap();
        assert_eq!(cleanup_rx.recv().unwrap(), Ok(37));
        assert_eq!(initializer.join().unwrap(), Ok(37));
        cleanup.join().unwrap();
    }
}

#[cfg(test)]
mod supervisor_tests {
    use super::{selected_terminal, wait_for_failure};
    use std::{
        cell::Cell,
        future::{poll_fn, Future},
        pin::Pin,
        sync::{
            atomic::{AtomicBool, Ordering},
            OnceLock,
        },
        task::Poll,
        time::Duration,
    };

    async fn pending_once<F: Future>(mut future: Pin<&mut F>) {
        poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn nonselected_runtime_stays_pending_without_probing_cached_failure() {
        let mut wait = Box::pin(wait_for_failure(false, || {
            panic!("unselected runtime must not be observed")
        }));
        pending_once(wait.as_mut()).await;
    }

    #[tokio::test]
    async fn uninitialized_selected_runtime_stays_pending_without_initialization() {
        let cell = OnceLock::<Result<AtomicBool, &'static str>>::new();
        let mut wait = Box::pin(wait_for_failure(true, || {
            selected_terminal(&cell, |_| panic!("no runtime was initialized"))
        }));
        pending_once(wait.as_mut()).await;
        assert!(cell.get().is_none());
    }

    #[tokio::test]
    async fn healthy_selected_runtime_stays_pending() {
        let cell = OnceLock::new();
        cell.set(Ok::<_, &'static str>(AtomicBool::new(false)))
            .unwrap();
        let mut wait = Box::pin(wait_for_failure(true, || {
            selected_terminal(&cell, |failed| failed.load(Ordering::Acquire))
        }));
        pending_once(wait.as_mut()).await;
    }

    #[tokio::test]
    async fn failed_startup_is_terminal_without_another_dial() {
        let cell = OnceLock::<Result<AtomicBool, &'static str>>::new();
        cell.set(Err("owned startup failed")).unwrap();
        let reason = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_failure(true, || {
                selected_terminal(&cell, |_| panic!("failed startup has no runtime"))
            }),
        )
        .await
        .unwrap();
        assert!(reason.contains("terminal"));
    }

    #[tokio::test]
    async fn terminal_after_start_wakes_idle_supervision_without_another_dial() {
        let cell = OnceLock::new();
        cell.set(Ok::<_, &'static str>(AtomicBool::new(false)))
            .unwrap();
        let probes = Cell::new(0);
        let mut idle = Box::pin(async {
            tokio::select! {
                reason = wait_for_failure(true, || {
                    probes.set(probes.get() + 1);
                    selected_terminal(&cell, |failed| failed.load(Ordering::Acquire))
                }) => reason,
                _ = std::future::pending::<()>() => panic!("idle ingress cannot wake"),
            }
        });
        pending_once(idle.as_mut()).await;
        assert_eq!(probes.get(), 1);
        cell.get()
            .unwrap()
            .as_ref()
            .unwrap()
            .store(true, Ordering::Release);
        let reason = tokio::time::timeout(Duration::from_secs(1), idle)
            .await
            .unwrap();
        assert!(reason.contains("terminal"));
        assert!(probes.get() >= 2);
    }

    #[tokio::test]
    async fn cancelled_watch_rechecks_terminal_on_next_wait() {
        let cell = OnceLock::new();
        cell.set(Ok::<_, &'static str>(AtomicBool::new(false)))
            .unwrap();
        let mut wait = Box::pin(wait_for_failure(true, || {
            selected_terminal(&cell, |failed| failed.load(Ordering::Acquire))
        }));
        pending_once(wait.as_mut()).await;
        drop(wait);
        cell.get()
            .unwrap()
            .as_ref()
            .unwrap()
            .store(true, Ordering::Release);
        let reason = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_failure(true, || {
                selected_terminal(&cell, |failed| failed.load(Ordering::Acquire))
            }),
        )
        .await
        .unwrap();
        assert!(reason.contains("terminal"));
    }
}
