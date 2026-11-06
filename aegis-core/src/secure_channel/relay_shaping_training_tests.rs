//! Real core training-owner regressions; no archived-binary or network claim.
use crate::traffic_privacy::liu_channel::training_test_probe::{
    self as probe, PreparationProbe, Snapshot, SolverOutcome,
};
use crate::{
    carrier_runtime::{OwnedCarrier, PrivacySettings},
    secure_channel::relay_shaping,
};
use std::{io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
    time::{timeout_at, Instant},
};

fn adaptive_profile() -> PrivacySettings {
    serde_json::from_value(serde_json::json!({
        "payload_bytes":32,"cadence_ms":1,"buffer_bytes":64,"max_wire_bytes":100000,
        "io_timeout_ms":300,"session_timeout_ms":2000,"max_queue_delay_ms":30000,
        "adaptive_channel":{"joint_counts":[[10,0],[0,10]],"length_bin_upper":[16,32],
        "actions":[{"padded_bytes":16,"delay_ms":1},{"padded_bytes":32,"delay_ms":1}],
        "delay_cost_per_ms":0,"cost_budget":32,"optimizer_iterations":1000,
        "optimizer_gap_millibits":1,"optimizer_timeout_ms":1000,"buffer_bytes":64,
        "max_wire_bytes":100000,"io_timeout_ms":300,"session_timeout_ms":2000,
        "max_queue_delay_ms":30000}
    }))
    .unwrap()
}
fn liu_profile() -> PrivacySettings {
    serde_json::from_value(serde_json::json!({
        "payload_bytes":2,"cadence_ms":1,"buffer_bytes":1024,"max_wire_bytes":100000,
        "io_timeout_ms":300,"session_timeout_ms":3000,"max_queue_delay_ms":400000,
        "liu_channel":{"class_weights":[1,3],"client_to_server_counts":[[3,1],[1,3]],
        "server_to_client_counts":[[3,1],[1,3]],"target_classes":[],"unmatched_traffic_class":0,
        "policy_ack_class":1,"distortion_microunits":125000,"optimizer_iterations":2000,
        "optimizer_gap_millibits":1,"optimizer_timeout_ms":3000,"buffer_bytes":1024,
        "wire_batch_bytes":1024,"max_wire_bytes":100000,"io_timeout_ms":300,
        "session_timeout_ms":3000,"max_queue_delay_ms":400000}
    }))
    .unwrap()
}
fn successful(snapshot: Snapshot, directions: usize) {
    assert_eq!(snapshot.task_created, 1, "INVALID: actual creation missing");
    assert_eq!(snapshot.worker_entered, 1, "INVALID: actual worker missing");
    assert_eq!(
        snapshot.worker_exited, 1,
        "INVALID: actual closure not finished"
    );
    assert_eq!(
        snapshot.optimizer_entered, directions,
        "INVALID: numerical body did not run"
    );
    assert!(
        !snapshot.gate_expired,
        "INVALID: artificial gate consumed original cutoff"
    );
    assert_eq!(
        snapshot.directional_outcomes[0],
        Some(SolverOutcome::Succeeded)
    );
    assert_eq!(
        snapshot.directional_outcomes[1],
        if directions == 2 {
            Some(SolverOutcome::Succeeded)
        } else {
            None
        }
    );
}
async fn exchange(a: OwnedCarrier, b: OwnedCarrier, cutoff: Instant) {
    let mut a = a;
    let mut b = b;
    timeout_at(cutoff, async {
        tokio::try_join!(
            async {
                a.write_all(b"request").await?;
                a.shutdown().await?;
                let mut data = Vec::new();
                a.read_to_end(&mut data).await?;
                assert_eq!(data, b"response", "INVALID: actual response differs");
                io::Result::Ok(())
            },
            async {
                let mut data = Vec::new();
                b.read_to_end(&mut data).await?;
                assert_eq!(data, b"request", "INVALID: actual request differs");
                b.write_all(b"response").await?;
                b.shutdown().await?;
                io::Result::Ok(())
            }
        )
    })
    .await
    .expect("INVALID: actual exchange cutoff")
    .expect("INVALID: actual exchange failed");
}
// Parent owns a private unique marker path and independent process supervisor.
// Emit only after actual positive controls; neither compilation nor a missed
// test selector can create this witness. Failure to write is INVALID.
fn validity(case: &str, directions: usize, server_jobs: usize) {
    use std::io::Write;
    let Some(path) = std::env::var_os("AEGIS_COLD_VALIDITY_FILE") else {
        // Ordinary unit-test runs still execute the complete fixture. Paired
        // proof additionally requires a parent-owned path and this witness.
        return;
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("INVALID: parent validity path unavailable or reused");
    writeln!(file,"AEGIS_COLD_VALIDITY_V1:{case}:startup={directions}:client={directions}:server={server_jobs}")
        .expect("INVALID: validity write failed");
    file.sync_all().expect("INVALID: validity flush failed");
}
struct OwnedCall<T> {
    task: JoinHandle<io::Result<T>>,
    witness: Arc<PreparationProbe>,
}
impl<T> Drop for OwnedCall<T> {
    fn drop(&mut self) {
        self.witness.release();
        self.task.abort();
    }
}

#[tokio::test]
async fn prepared_adaptive_keeps_unchanged_cold_client_wire_order_without_server_solve() {
    let p = adaptive_profile();
    p.validate().unwrap();
    let warm = PreparationProbe::released();
    let trained = probe::scope(warm.clone(), relay_shaping::ServerTraining::prepare(&p))
        .await
        .expect("INVALID: startup preparation failed")
        .expect("INVALID: missing prepared owner");
    successful(warm.snapshot(), 1);
    let (a, b) = tokio::io::duplex(8192);
    let original = Instant::now();
    let cutoff = original + Duration::from_secs(2);
    let cold = PreparationProbe::held();
    let client_profile = p.clone();
    // This is the unchanged source-pinned v1 client function. It really solves
    // before HELLO; an archived full old binary remains a separate acceptance.
    let mut client = OwnedCall {
        witness: cold.clone(),
        task: tokio::spawn(probe::scope(cold.clone(), async move {
            relay_shaping::client(a, Some(&client_profile), cutoff).await
        })),
    };
    cold.wait_for(cutoff, |s| s.worker_entered == 1).await;
    let server_probe = PreparationProbe::released();
    let server = probe::scope(
        server_probe.clone(),
        relay_shaping::server_bound_with_training(b, Some(&p), original, cutoff, Some(&trained)),
    );
    tokio::pin!(server);
    // A real cold solver is still held when server negotiation is first polled.
    // No timeout is fabricated or extended; release and run its actual math.
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(server.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    cold.release();
    let (client_result, server_result) = tokio::join!(timeout_at(cutoff, &mut client.task), server);
    let a = client_result
        .expect("INVALID: client cutoff")
        .expect("INVALID: client task")
        .expect("INVALID: client agreement");
    let (b, context) = server_result.expect("INVALID: server agreement");
    assert!(context.is_none());
    exchange(a, b, cutoff).await;
    successful(cold.snapshot(), 1);
    let observed = server_probe.snapshot();
    if observed.task_created > 0 {
        successful(observed, 1);
    }
    validity("adaptive_unchanged_cold_order", 1, observed.task_created);
    // All validity and real bidirectional completion precede the causal target.
    assert_eq!(
        observed.task_created, 0,
        "prepared profile must avoid per-session adaptive creation"
    );
}

#[tokio::test]
async fn prepared_liu_keeps_real_pre_socket_client_training_and_exact_two_kernels() {
    let p = liu_profile();
    p.validate().unwrap();
    let warm = PreparationProbe::released();
    let trained = probe::scope(warm.clone(), relay_shaping::ServerTraining::prepare(&p))
        .await
        .expect("INVALID: startup preparation failed")
        .expect("INVALID: missing prepared owner");
    successful(warm.snapshot(), 2);
    let original = Instant::now();
    let cutoff = original + Duration::from_secs(3);
    let context = p.liu_channel.as_ref().unwrap().policy_context().unwrap();
    let cold = PreparationProbe::held();
    let client_profile = p.clone();
    let mut pending_admission = OwnedCall {
        witness: cold.clone(),
        task: tokio::spawn(probe::scope(cold.clone(), async move {
            relay_shaping::prepare_liu_admission(&client_profile, context, original, cutoff).await
        })),
    };
    cold.wait_for(cutoff, |s| s.worker_entered == 1).await;
    cold.release();
    let admission = timeout_at(cutoff, &mut pending_admission.task)
        .await
        .expect("INVALID: cold client cutoff")
        .expect("INVALID: cold task")
        .expect("INVALID: cold admission");
    successful(cold.snapshot(), 2);
    // Matches source-pinned open_with_endpoint: finish Liu training before
    // constructing transport/identity. The server has no client-origin clock.
    let (a, b) = tokio::io::duplex(8192);
    let server_origin = Instant::now();
    let server_probe = PreparationProbe::released();
    let (a, b) = tokio::join!(
        relay_shaping::client_admitted(a, Some(&p), cutoff, Some(admission)),
        probe::scope(
            server_probe.clone(),
            relay_shaping::server_bound_with_training(
                b,
                Some(&p),
                server_origin,
                cutoff,
                Some(&trained)
            )
        )
    );
    let (b, context) = b.expect("INVALID: actual Liu server agreement");
    assert!(context.is_some(), "INVALID: Liu purpose was dropped");
    exchange(a.expect("INVALID: actual Liu client agreement"), b, cutoff).await;
    let observed = server_probe.snapshot();
    if observed.task_created > 0 {
        successful(observed, 2);
    }
    validity("liu_real_pre_socket_cold_order", 2, observed.task_created);
    assert_eq!(
        observed.task_created, 0,
        "prepared profile must avoid per-session Liu creation"
    );
}

#[tokio::test]
async fn prepared_training_cannot_restart_expired_original_establishment() {
    for p in [adaptive_profile(), liu_profile()] {
        let trained = relay_shaping::ServerTraining::prepare(&p)
            .await
            .unwrap()
            .unwrap();
        let (a, mut peer) = tokio::io::duplex(8192);
        let origin = Instant::now() - Duration::from_secs(10);
        let witness = PreparationProbe::released();
        let result = probe::scope(
            witness.clone(),
            relay_shaping::server_bound_with_training(
                a,
                Some(&p),
                origin,
                origin + Duration::from_secs(1),
                Some(&trained),
            ),
        )
        .await;
        assert!(matches!(result,Err(e)if e.kind()==io::ErrorKind::TimedOut));
        assert_eq!(witness.snapshot().task_created, 0);
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn full_profile_mismatch_refuses_without_retraining_or_plain_fallback() {
    for p in [adaptive_profile(), liu_profile()] {
        let trained = relay_shaping::ServerTraining::prepare(&p)
            .await
            .unwrap()
            .unwrap();
        let mut changed = p.clone();
        changed.max_wire_bytes += 1;
        changed.validate().unwrap();
        let cutoff = Instant::now() + Duration::from_secs(3);
        let original = Instant::now();
        let witness = PreparationProbe::released();
        let (a, b) = tokio::io::duplex(8192);
        if let Some(settings) = &changed.liu_channel {
            let context = settings.policy_context().unwrap();
            let client_probe = PreparationProbe::released();
            let admission = probe::scope(
                client_probe.clone(),
                relay_shaping::prepare_liu_admission(&changed, context, original, cutoff),
            )
            .await
            .unwrap();
            successful(client_probe.snapshot(), 2);
            let (client, server) = tokio::join!(
                relay_shaping::client_admitted(a, Some(&changed), cutoff, Some(admission)),
                probe::scope(
                    witness.clone(),
                    relay_shaping::server_bound_with_training(
                        b,
                        Some(&changed),
                        original,
                        cutoff,
                        Some(&trained)
                    )
                )
            );
            assert!(client.is_err(), "mismatch cannot produce a client carrier");
            assert!(matches!(server, Err(error) if error.kind() == io::ErrorKind::InvalidData));
        } else {
            let result = probe::scope(
                witness.clone(),
                relay_shaping::server_bound_with_training(
                    b,
                    Some(&changed),
                    original,
                    cutoff,
                    Some(&trained),
                ),
            )
            .await;
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
            let mut peer = a;
            assert_eq!(
                timeout_at(cutoff, peer.read(&mut [0; 1]))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
        assert_eq!(witness.snapshot().task_created, 0);
    }
}

// Observe only bounded successful writes of the actual in-memory handshake.
// No entropy or wire bytes are printed, persisted, or injected into production.
struct CaptureWire {
    stream: tokio::io::DuplexStream,
    written: Arc<std::sync::Mutex<Vec<u8>>>,
}
impl tokio::io::AsyncRead for CaptureWire {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.stream), cx, buf)
    }
}
impl tokio::io::AsyncWrite for CaptureWire {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let result =
            tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.stream), cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = result {
            let mut written = self.written.lock().unwrap();
            let keep = n.min(16384usize.saturating_sub(written.len()));
            written.extend_from_slice(&buf[..keep]);
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.stream), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.stream), cx)
    }
}
fn contribution(writes: &Arc<std::sync::Mutex<Vec<u8>>>) -> [u8; 32] {
    let writes = writes.lock().unwrap();
    assert!(
        writes.len() >= 2,
        "INVALID: actual Liu typed header missing"
    );
    let length = usize::from(u16::from_be_bytes([writes[0], writes[1]]));
    assert!(length > 0 && length <= super::MAX_CONTROL_BYTES);
    let agreement: serde_json::Value = serde_json::from_slice(&writes[2..2 + length]).unwrap();
    assert_eq!(agreement["version"], 2);
    assert_eq!(agreement["operation"], "liu_traffic_or_policy_ack");
    writes[2 + length..2 + length + 32]
        .try_into()
        .expect("INVALID: actual session contribution missing")
}
async fn trained_liu_pair(
    p: &PrivacySettings,
    trained: &relay_shaping::ServerTraining,
    cutoff: Instant,
) -> (OwnedCarrier, OwnedCarrier, [u8; 32], Arc<PreparationProbe>) {
    let original = Instant::now();
    let context = p.liu_channel.as_ref().unwrap().policy_context().unwrap();
    let client_probe = PreparationProbe::released();
    let admission = probe::scope(
        client_probe.clone(),
        relay_shaping::prepare_liu_admission(p, context, original, cutoff),
    )
    .await
    .unwrap();
    successful(client_probe.snapshot(), 2);
    let (a, b) = tokio::io::duplex(8192);
    let written = Arc::new(std::sync::Mutex::new(Vec::new()));
    let b = CaptureWire {
        stream: b,
        written: written.clone(),
    };
    let witness = PreparationProbe::released();
    let (client, server) = tokio::join!(
        relay_shaping::client_admitted(a, Some(p), cutoff, Some(admission)),
        probe::scope(
            witness.clone(),
            relay_shaping::server_bound_with_training(b, Some(p), original, cutoff, Some(trained))
        )
    );
    let (server, context) = server.unwrap();
    assert!(context.is_some());
    (client.unwrap(), server, contribution(&written), witness)
}

#[tokio::test]
async fn completed_liu_model_reuse_keeps_fresh_entropy_and_independent_session_drop() {
    let p = liu_profile();
    let warm = PreparationProbe::released();
    let trained = probe::scope(warm.clone(), relay_shaping::ServerTraining::prepare(&p))
        .await
        .unwrap()
        .unwrap();
    successful(warm.snapshot(), 2);
    let cutoff = Instant::now() + Duration::from_secs(3);
    let first = trained_liu_pair(&p, &trained, cutoff).await;
    let second = trained_liu_pair(&p, &trained, cutoff).await;
    // Real OsRng contributions, not a synthetic model seed or fake sampler.
    assert!(
        first.2 != second.2,
        "separate sessions reused an entropy contribution"
    );
    drop(first.0);
    drop(first.1);
    exchange(second.0, second.1, cutoff).await;
    for witness in [first.3, second.3] {
        if witness.snapshot().task_created > 0 {
            successful(witness.snapshot(), 2);
        }
    }
}
