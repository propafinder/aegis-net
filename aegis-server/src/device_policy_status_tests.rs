use super::*;
use aegis_core::secure_channel::{registry, ServerSettings};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in(if cfg!(target_os = "macos") {
        "/private/tmp"
    } else {
        "/tmp"
    })
    .unwrap();
    // BSD inherits /private/tmp's wheel group even without setgid. Model the
    // explicitly provisioned service group, as systemd RuntimeDirectory does.
    std::os::unix::fs::chown(dir.path(), None, Some(gid())).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).unwrap();
    dir
}

pub(super) fn fixture(dir: &Path) -> (Server, registry::DeviceRegistry) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["fixture.test".into()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let cert = params.self_signed(&key).unwrap();
    for (name, contents) in [("cert.pem", cert.pem()), ("key.pem", key.serialize_pem())] {
        fs::write(dir.join(name), contents).unwrap();
        fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let registry = registry::DeviceRegistry::new(registry::unix_now().unwrap(), 30).unwrap();
    registry::publish_snapshot(&dir.join("registry.json"), &registry).unwrap();
    let server = Server::load(&ServerSettings {
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
        client_ca: dir.join("cert.pem"),
        device_registry: Some(dir.join("registry.json")),
        allowed_client_sha256: vec![],
        admission: Default::default(),
        handshake_timeout_ms: 1000,
        idle_timeout_ms: 1000,
    })
    .unwrap();
    (server, registry)
}

fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn gid() -> u32 {
    unsafe { libc::getegid() }
}

#[tokio::test]
async fn real_socket_reports_live_watcher_update_and_refuses_after_watcher_stops() {
    let dir = directory();
    let (server, mut snapshot) = fixture(dir.path());
    let watcher = server.start_registry_watcher().unwrap();
    let path = dir.path().join("status.sock");
    let _status = StatusServer::start(Some(&path), Some(&server)).unwrap();
    let Response::Ready { policy, process } = query(&path, uid(), gid(), std::process::id())
        .await
        .unwrap()
    else {
        panic!("live status expected")
    };
    assert_eq!(policy.generation, 1);
    assert_eq!(process.pid, std::process::id());
    assert_eq!(
        process.process_start_ticks,
        process_start_ticks(std::process::id()).unwrap()
    );
    snapshot
        .refresh_validity(registry::unix_now().unwrap(), 30)
        .unwrap();
    registry::publish_snapshot(&dir.path().join("registry.json"), &snapshot).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(query(&path, uid(), gid(), std::process::id()).await.unwrap(), Response::Ready { policy, .. } if policy.generation == 2) { break; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.unwrap();
    drop(watcher);
    assert!(matches!(
        query(&path, uid(), gid(), std::process::id())
            .await
            .unwrap(),
        Response::Unavailable
    ));
    let _recovery = server.start_registry_watcher().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(query(&path, uid(), gid(), std::process::id()).await.unwrap(), Response::Ready { policy, .. } if policy.generation == 2) { break; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.unwrap();
}

#[tokio::test]
async fn actual_peer_pid_uid_permissions_and_unknown_socket_ownership_are_checked() {
    let dir = directory();
    let (server, _) = fixture(dir.path());
    let _watcher = server.start_registry_watcher().unwrap();
    let path = dir.path().join("status.sock");
    let status = StatusServer::start(Some(&path), Some(&server)).unwrap();
    assert!(query(&path, uid(), gid(), std::process::id() + 1)
        .await
        .is_err());
    assert!(
        query(&path, uid().wrapping_add(1), gid(), std::process::id())
            .await
            .is_err()
    );
    assert!(StatusServer::start(Some(&path), Some(&server)).is_err());
    assert!(query(&path, uid(), gid(), std::process::id()).await.is_ok());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(query(&path, uid(), gid(), std::process::id())
        .await
        .is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    // Drop must not delete an unrelated replacement at the configured path.
    fs::remove_file(&path).unwrap();
    fs::write(&path, "replacement").unwrap();
    drop(status);
    assert_eq!(fs::read_to_string(&path).unwrap(), "replacement");
}

#[tokio::test]
async fn malformed_multiple_and_stalled_requests_are_bounded_then_valid_requests_work() {
    let dir = directory();
    let (server, _) = fixture(dir.path());
    let _watcher = server.start_registry_watcher().unwrap();
    let path = dir.path().join("status.sock");
    let _status = StatusServer::start(Some(&path), Some(&server)).unwrap();
    for request in [
        b"wrong\n".to_vec(),
        [REQUEST, REQUEST].concat(),
        vec![b'x'; 4096],
    ] {
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        stream.write_all(&request).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut reply))
            .await
            .unwrap();
        assert!(reply.is_empty());
    }
    let mut stalled = tokio::net::UnixStream::connect(&path).await.unwrap();
    stalled.write_all(b"AEGIS").await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stalled.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert!(reply.is_empty());
    assert!(matches!(
        query(&path, uid(), gid(), std::process::id())
            .await
            .unwrap(),
        Response::Ready { .. }
    ));
}

#[tokio::test]
async fn query_refuses_oversized_malformed_and_stalled_responses_from_actual_peer() {
    for bytes in [
        Some(vec![b'x'; RESPONSE_BYTES as usize + 1]),
        Some(b"not json".to_vec()),
        None,
    ] {
        let dir = directory();
        let path = dir.path().join("status.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, REQUEST);
            if let Some(bytes) = bytes {
                let _ = stream.write_all(&bytes).await;
            } else {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        assert!(query(&path, uid(), gid(), std::process::id())
            .await
            .is_err());
        peer.abort();
        let _ = peer.await;
    }
}

#[tokio::test]
async fn configured_listener_failure_is_observable_and_owned_cleanup_removes_only_its_socket() {
    let dir = directory();
    let path = dir.path().join("status.sock");
    let (server, _) = fixture(dir.path());
    let mut status = StatusServer::start(Some(&path), Some(&server)).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), status.stopped())
            .await
            .unwrap()
            .is_err()
    );
    drop(status);
    assert!(!path.exists());
    // Listener may start while the existing authorization state is unavailable;
    // this preserves the process needed for registry recovery.
    let _replacement = StatusServer::start(Some(&path), Some(&server)).unwrap();
    assert!(matches!(
        query(&path, uid(), gid(), std::process::id())
            .await
            .unwrap(),
        Response::Unavailable
    ));
}
