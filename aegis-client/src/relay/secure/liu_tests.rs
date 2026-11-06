use super::*;
fn profile() -> aegis_core::carrier_runtime::PrivacySettings {
    serde_json::from_value(serde_json::json!({"payload_bytes":2,"cadence_ms":1,"buffer_bytes":1024,"max_wire_bytes":100000,"io_timeout_ms":2000,"session_timeout_ms":10000,"max_queue_delay_ms":3000000,"liu_channel":{"class_weights":[1,3],"client_to_server_counts":[[3,1],[1,3]],"server_to_client_counts":[[3,1],[1,3]],"target_classes":[],"unmatched_traffic_class":0,"policy_ack_class":1,"distortion_microunits":125000,"optimizer_iterations":2000,"optimizer_gap_millibits":1,"optimizer_timeout_ms":3000,"buffer_bytes":1024,"wire_batch_bytes":1024,"max_wire_bytes":100000,"io_timeout_ms":2000,"session_timeout_ms":10000,"max_queue_delay_ms":3000000}})).unwrap()
}
#[tokio::test]
async fn liu_shrink_support_and_unmapped_target_refuse_before_identity_or_socket() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut s, _) = configs(dir.path(), &listener.local_addr().unwrap().to_string());
    s.relay.inner_tls.as_mut().unwrap().key = dir.path().join("ABSENT-PRIVATE-IDENTITY");
    for badsupport in [false, true] {
        let mut p = profile();
        let liu = p.liu_channel.as_mut().unwrap();
        if badsupport {
            liu.class_weights = vec![3, 1];
        } else {
            liu.unmatched_traffic_class = None;
        }
        s.relay.authenticated_shaping = Some(p);
        let error = open(
            &s.relay,
            "unknown.test".into(),
            443,
            secure_channel::Transport::Tcp,
        )
        .await
        .err()
        .unwrap();
        let text = format!("{error:#}");
        assert!(
            text.contains(if badsupport {
                "physically impossible"
            } else {
                "no declared class"
            }),
            "{text}"
        );
        assert!(!retryable_pre_auth_failure(&error));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }
}
#[tokio::test]
async fn liu_installed_client_actual_outer_tls_inner_device_tls_and_target_transfer() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap().to_string();
    let (mut s, mut server) = configs(dir.path(), &address);
    drop(reservation);
    s.relay.authenticated_shaping = Some(profile());
    server.transport.authenticated_shaping = Some(profile());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let mut serving = Driver(tokio::spawn(async move {
        aegis_server::run_server_with_shutdown(server, Some(ready_tx), async {
            let _ = stop_rx.await;
        })
        .await
        .unwrap();
    }));
    tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut target = Driver(tokio::spawn(async move {
        let (mut t, _) = listener.accept().await.unwrap();
        let mut x = Vec::new();
        t.read_to_end(&mut x).await.unwrap();
        assert_eq!(x, b"installed-Liu");
        t.write_all(b"response").await.unwrap();
        t.shutdown().await.unwrap();
    }));
    let (mut stream, _h2_owner) = open(
        &s.relay,
        "127.0.0.1".into(),
        port,
        secure_channel::Transport::Tcp,
    )
    .await
    .unwrap();
    stream.write_all(b"installed-Liu").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"response");
    tokio::time::timeout(std::time::Duration::from_secs(2), &mut target.0)
        .await
        .unwrap()
        .unwrap();
    drop(stream);
    drop(_h2_owner);
    stop_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), &mut serving.0)
        .await
        .unwrap()
        .unwrap();
}
