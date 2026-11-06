//! systemd readiness acknowledges initialized local ingress, not relay reachability.

use std::io;

/// Recheck required local listeners and workers after the last awaited live ACK.
/// No async work may separate this check from the readiness notification.
pub(crate) async fn after_confirmation<F, C>(confirmation: F, check: C) -> anyhow::Result<()>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
    C: FnOnce() -> anyhow::Result<()>,
{
    confirm_then_notify(confirmation, check, notify).await
}

async fn confirm_then_notify<F, C, N>(confirmation: F, check: C, notify: N) -> anyhow::Result<()>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
    C: FnOnce() -> anyhow::Result<()>,
    N: FnOnce() -> io::Result<()>,
{
    use anyhow::Context;
    confirmation.await?;
    check()?;
    notify().context("service readiness notification failed")
}

pub(crate) fn notify() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    return notify_at(std::env::var_os("NOTIFY_SOCKET").as_deref());
    #[cfg(not(target_os = "linux"))]
    Ok(())
}

#[cfg(target_os = "linux")]
fn notify_at(address: Option<&std::ffi::OsStr>) -> io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    use std::path::Path;
    use std::time::Duration;

    let Some(address) = address else {
        return Ok(());
    };
    let raw = address.as_bytes();
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid service notify socket");
    if raw.contains(&0) {
        return Err(invalid());
    }
    let target = match raw.first() {
        Some(b'@') if raw.len() > 1 => SocketAddr::from_abstract_name(&raw[1..])?,
        Some(b'/') => SocketAddr::from_pathname(Path::new(address))?,
        _ => return Err(invalid()),
    };
    let socket = UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    socket.connect_addr(&target)?;
    let message = b"READY=1\nSTATUS=Ingress workers ready";
    if socket.send(message)? != message.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short readiness datagram",
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    use std::time::Duration;

    fn assert_ready(receiver: &UnixDatagram) {
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut data = [0; 128];
        let n = receiver.recv(&mut data).unwrap();
        assert_eq!(&data[..n], b"READY=1\nSTATUS=Ingress workers ready");
    }

    #[test]
    fn filesystem_socket_receives_ready() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let receiver = UnixDatagram::bind(&path).unwrap();
        notify_at(Some(path.as_os_str())).unwrap();
        assert_ready(&receiver);
    }

    #[test]
    fn abstract_socket_receives_ready() {
        let dir = tempfile::tempdir().unwrap();
        let name = dir.path().as_os_str().as_bytes();
        let receiver =
            UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name).unwrap()).unwrap();
        let mut notify_name = vec![b'@'];
        notify_name.extend_from_slice(name);
        notify_at(Some(OsStr::from_bytes(&notify_name))).unwrap();
        assert_ready(&receiver);
    }

    #[test]
    fn absent_socket_is_optional_but_bad_config_is_not() {
        notify_at(None).unwrap();
        for raw in [b"".as_slice(), b"@", b"relative/path", b"/bad\0path"] {
            assert_eq!(
                notify_at(Some(OsStr::from_bytes(raw))).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let dir = tempfile::tempdir().unwrap();
        assert!(notify_at(Some(dir.path().join("missing").as_os_str())).is_err());
    }
}

#[cfg(test)]
mod confirmation_tests {
    use super::*;
    use crate::wide_workers::WideWorkers;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::{oneshot, watch};

    #[tokio::test]
    async fn required_dns_lifetime_closes_during_gated_ack_never_notifies_ready() {
        let (lifetime, failure) = watch::channel(());
        let (started, wait_started) = oneshot::channel();
        let (acknowledge, acknowledged) = oneshot::channel();
        let actor = tokio::spawn(async move {
            wait_started.await.unwrap();
            drop(lifetime);
            acknowledge.send(()).unwrap();
        });
        let calls = AtomicUsize::new(0);
        let result = confirm_then_notify(
            async {
                started.send(()).unwrap();
                acknowledged.await.unwrap();
                Ok(())
            },
            || {
                // This is the actual required DNS listener's lifetime predicate.
                anyhow::ensure!(
                    failure.has_changed().is_ok(),
                    "required DNS listener stopped"
                );
                Ok(())
            },
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        actor.await.unwrap();
        assert!(
            result.is_err(),
            "terminal DNS listener received READY after ACK"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn actual_owned_worker_fails_during_gated_ack_never_notifies_ready() {
        let mut workers = WideWorkers::new();
        let (release, wait) = std::sync::mpsc::channel();
        let (stopped, terminal) = oneshot::channel();
        workers
            .start(
                "ready-test-owned-worker",
                Duration::from_secs(1),
                move |_, ready| {
                    let failure = ready.failure_signal();
                    ready.signal().unwrap();
                    wait.recv().unwrap();
                    failure.report();
                    assert!(stopped.send(()).is_ok());
                },
            )
            .await
            .unwrap();
        assert!(workers.pending_failure().is_none());
        let calls = AtomicUsize::new(0);
        let result = confirm_then_notify(
            async {
                release.send(()).unwrap();
                terminal.await.unwrap();
                Ok(())
            },
            || {
                anyhow::ensure!(
                    workers.pending_failure().is_none(),
                    "required capture worker stopped"
                );
                Ok(())
            },
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(
            result.is_err(),
            "terminal owned worker received READY after ACK"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn successful_ack_and_live_listener_notify_exactly_once() {
        let (_owner, failure) = watch::channel(());
        let calls = AtomicUsize::new(0);
        confirm_then_notify(
            async { Ok(()) },
            || {
                anyhow::ensure!(failure.has_changed().is_ok(), "listener stopped");
                Ok(())
            },
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_ack_never_checks_or_notifies() {
        let checks = AtomicUsize::new(0);
        let calls = AtomicUsize::new(0);
        let error = confirm_then_notify(
            async { anyhow::bail!("controlled ACK refused") },
            || {
                checks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "controlled ACK refused");
        assert_eq!(checks.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
