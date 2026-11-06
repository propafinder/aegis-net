//! Real paired CLI processes with explicitly owned localhost applications.
//! Synthetic identities/controlled source do not establish Poisson or M/M/1.
#[path = "support/poisson_refusal.rs"]
mod refusal_diagnostics;
#[path = "support/poisson_source_witness.rs"]
mod source_diagnostics;
#[path = "support/poisson_windows_source.rs"]
mod windows_source;
use aegis_core::secret_file;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io,
    net::SocketAddr,
    path::Path,
    process::{ExitStatus, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, BufReader},
    net::UdpSocket,
    process::{Child, ChildStderr, ChildStdout, Command},
    sync::{oneshot, Notify},
    task::JoinHandle,
    time::{sleep_until, timeout_at, Instant},
};

const MAX_LINE: usize = 16 * 1024;
const MAX_PACKETS: usize = 8192;

fn write(path: &Path, bytes: &[u8]) {
    secret_file::write_private_new(path, bytes).unwrap();
}

fn identities(dir: &Path) -> (Value, Value) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = params.self_signed(&key).unwrap();
    write(&dir.join("ca.pem"), ca.pem().as_bytes());
    let mut fingerprints = Vec::new();
    for (name, usage) in [
        ("inner.test", ExtendedKeyUsagePurpose::ServerAuth),
        ("device.test", ExtendedKeyUsagePurpose::ClientAuth),
    ] {
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.extended_key_usages = vec![usage];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let local = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.signed_by(&local, &ca, &key).unwrap();
        write(&dir.join(format!("{name}.pem")), cert.pem().as_bytes());
        write(
            &dir.join(format!("{name}.key")),
            local.serialize_pem().as_bytes(),
        );
        fingerprints.push(format!("{:x}", Sha256::digest(cert.der())));
    }
    (
        json!({"role":"client","settings":{"server_name":"inner.test","server_ca":"ca.pem","cert":"device.test.pem","key":"device.test.key"}}),
        json!({"role":"server","settings":{"cert":"inner.test.pem","key":"inner.test.key","client_ca":"ca.pem","allowed_client_sha256":[fingerprints[1]],"handshake_timeout_ms":1000,"idle_timeout_ms":1000}}),
    )
}

struct OwnedTask<T>(Option<JoinHandle<T>>);
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}
impl<T> OwnedTask<T> {
    async fn finish(&mut self, end: Instant) -> T {
        let value = timeout_at(end, self.0.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap();
        self.0.take();
        value
    }
}

struct Operator {
    child: Child,
    stdout: BufReader<ChildStdout>,
    stderr: ChildStderr,
}
impl Operator {
    fn spawn(config: &Path, file_option: &str, file: &Path) -> Self {
        let mut command = Command::new(
            std::env::var_os("AEGIS_TEST_RESEARCH_OPERATOR_EXECUTABLE")
                .or_else(|| {
                    option_env!("CARGO_BIN_EXE_aegis-research-measure")
                        .map(std::ffi::OsString::from)
                })
                .expect("compiled restricted research source or explicit paired source required"),
        );
        command
            .arg("poisson-control")
            .arg("--config-json")
            .arg(config)
            .arg(file_option)
            .arg(file)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // Only this directly spawned CLI gets the new group. Normal success
        // observes/reaps its exact Child; no process-name/group-search cleanup.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.as_std_mut().process_group(0);
        }
        let mut child = command.spawn().unwrap();
        assert!(child.id().is_some());
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let stderr = child.stderr.take().unwrap();
        Self {
            child,
            stdout,
            stderr,
        }
    }

    async fn json_line(&mut self, end: Instant) -> Value {
        // Bound each actual line before allocating or parsing a whole value.
        // Neither stderr nor arbitrary operator text is printed by the test.
        let bytes = timeout_at(end, async {
            let mut bytes = Vec::new();
            loop {
                let byte = self.stdout.read_u8().await?;
                if byte == b'\n' {
                    return Ok::<_, io::Error>(bytes);
                }
                if bytes.len() == MAX_LINE {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line cap"));
                }
                bytes.push(byte);
            }
        })
        .await
        .unwrap()
        .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn finish(&mut self, end: Instant) -> (ExitStatus, Value) {
        let receipt = self.json_line(end).await;
        let status = timeout_at(end, self.child.wait()).await.unwrap().unwrap();
        let mut stdout_tail = Vec::new();
        let mut stderr = Vec::new();
        timeout_at(end, async {
            (&mut self.stdout)
                .take((MAX_LINE + 1) as u64)
                .read_to_end(&mut stdout_tail)
                .await?;
            (&mut self.stderr)
                .take((MAX_LINE + 1) as u64)
                .read_to_end(&mut stderr)
                .await?;
            Ok::<_, io::Error>(())
        })
        .await
        .unwrap()
        .unwrap();
        assert!(stdout_tail.len() <= MAX_LINE && stderr.len() <= MAX_LINE);
        assert!(stdout_tail.iter().all(u8::is_ascii_whitespace));
        if status.success() {
            assert!(stderr.is_empty());
        }
        (status, receipt)
    }
}

fn number(value: &Value, field: &str) -> usize {
    value[field].as_u64().unwrap().try_into().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_paired_timing_cli_ready_udp_fifo_and_authenticated_output() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (client_tls, server_tls) = identities(d);
    let mut reserved = Vec::new();
    for _ in 0..6 {
        reserved.push(Some(UdpSocket::bind("127.0.0.1:0").await.unwrap()));
    }
    let addresses: Vec<SocketAddr> = reserved
        .iter()
        .map(|socket| socket.as_ref().unwrap().local_addr().unwrap())
        .collect();
    let source = reserved[1].take().unwrap();
    let sink = reserved[5].take().unwrap();
    let source_destination = addresses[0];
    sink.connect(addresses[4]).await.unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    // Exactly the bounded public settings of the genuine fresh TLS SDK
    // positive. This deterministic application is not a legitimate Poisson
    // source and this OS/network is not asserted to be an M/M/1 service.
    let resource_sha256 = [1u8; 32];
    let profile = json!({
        "resource_sha256":resource_sha256,
        "sender_application_bind":addresses[0],
        "sender_application_peer":addresses[1],
        "sender_packet_bind":addresses[2],
        "receiver_packet_bind":addresses[3],
        "receiver_application_bind":addresses[4],
        "receiver_application_peer":addresses[5],
        "timing":{
            "lambda_pps":200,"delta_pps":20,"reference_epsilon_milli":500,
            "service_mu_pps":2000,"buffering_ms":200,"block_ms":100,
            "bits_per_block":6,"payload_capacity":1,"max_word_events":128,
            "fifo_packets":2048,"total_packets":8192,"packet_bytes":128,
            "ready_lead_ms":200,"clock_uncertainty_us":10000,
            "release_lateness_us":10000,"drain_ms":200,"finalize_ms":1000,
            "precision_poll_budget":2000000
        }
    });
    let client_config = d.join("client.json");
    let server_config = d.join("server.json");
    for (path, tls) in [(&client_config, client_tls), (&server_config, server_tls)] {
        write(
            path,
            &serde_json::to_vec(&json!({
                "endpoint":endpoint,"deadline_ms":12000,"tls":tls,"profile":profile
            }))
            .unwrap(),
        );
    }
    let input = d.join("control-input");
    let output = d.join("control-output");
    write(&input, b"z");
    // Drop only the reserved CLI sockets before the CLI binds them. Keep the
    // two actual application sockets owned for the complete operation.
    drop(reserved);
    drop(listener);
    let end = Instant::now() + Duration::from_secs(16);
    let mut receiver = Operator::spawn(&server_config, "--output-file", &output);
    let listening = receiver.json_line(end).await;
    assert_eq!(listening["operation"], "poisson_control");
    assert_eq!(listening["state"], "control_listening");
    assert_eq!(listening["cover_armed"], false);
    let mut sender = Operator::spawn(&client_config, "--input-file", &input);
    let armed = sender.json_line(end).await;
    let observed = Instant::now();
    assert_eq!(armed["operation"], "poisson_control");
    assert_eq!(armed["state"], "application_resources_armed");
    assert_eq!(armed["poisson_legitimacy_verified"], false);
    let lead = armed["starts_in_ns"].as_u64().unwrap();
    let horizon = armed["covers_for_ns"].as_u64().unwrap();
    assert!(lead > 0 && lead <= 1_000_000_000);
    assert_eq!(horizon, 2_800_000_000);
    // Relative READY is a genuine callback, not a fabricated cross-process
    // clock certificate: reading/dispatch delay remains an observed fixture
    // uncertainty. No child origin/cutoff is reset by this calculation.
    // Offer the explicitly owned application FIFO as soon as it is armed.
    // Waiting for an inferred child start would make source availability depend
    // on stdout observation lag and a fresh schedule's first sampled point.
    // The actor keeps its own original start and timestamps actual reads; this
    // early offered prefix is not a measured Poisson process or arrival trace.
    let start = observed;
    let covers_until = observed + Duration::from_nanos(lead) + Duration::from_nanos(horizon);
    let (stop_source, source_stop) = oneshot::channel::<()>();
    #[cfg(not(windows))]
    let mut source_stop = source_stop;
    let (stop_sink, mut sink_stop) = oneshot::channel::<()>();
    let count = Arc::new(AtomicUsize::new(0));
    let progress = Arc::new(Notify::new());
    let received_count = count.clone();
    let received_progress = progress.clone();
    #[cfg(windows)]
    let mut producer = OwnedTask(Some(windows_source::spawn(
        source,
        source_destination,
        start,
        covers_until,
        end,
        source_stop,
    )));
    #[cfg(not(windows))]
    let mut producer = OwnedTask(Some(tokio::task::spawn_blocking(move || {
        // The application source owns a thread independent of the two Tokio
        // I/O workers. The child may use a Mach timing policy; source tick
        // dispatch no longer depends on the parent reactor's scheduling.
        let source = source.into_std().unwrap();
        let start = start.into_std();
        let covers_until = covers_until.into_std();
        let end = end.into_std();
        let period = Duration::from_millis(2);
        let mut nominal = start;
        let mut offered = 0u64;
        let mut witness = source_diagnostics::SourceWitness::default();
        // Parent-relative aggregate clocks may perturb the fixture; they do
        // not certify child READY emission, source arrival or packet departure.
        let elapsed = |at: std::time::Instant| {
            u64::try_from(at.saturating_duration_since(start).as_nanos()).unwrap_or(u64::MAX)
        };
        loop {
            if !matches!(
                source_stop.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ) {
                return (
                    offered,
                    Some(io::ErrorKind::Interrupted),
                    false,
                    witness.report(),
                );
            }
            let now = std::time::Instant::now();
            if now >= covers_until {
                return (offered, None, true, witness.report());
            }
            if now >= end {
                return (
                    offered,
                    Some(io::ErrorKind::TimedOut),
                    false,
                    witness.report(),
                );
            }
            if now < nominal {
                std::thread::sleep((nominal - now).min(Duration::from_millis(1)));
                continue;
            }
            // Keep this bound source unconnected across independently owned
            // input teardown. Every actual send error still fails this case.
            // Accepted FIFO counts below require application delivery.
            let dispatched = elapsed(now);
            witness.tick(elapsed(nominal), dispatched);
            match source.send_to(&offered.to_be_bytes(), source_destination) {
                Ok(8) => {
                    witness.sent(dispatched, elapsed(std::time::Instant::now()));
                    offered += 1;
                }
                Ok(_) => {
                    return (
                        offered,
                        Some(io::ErrorKind::WriteZero),
                        false,
                        witness.report(),
                    )
                }
                Err(error) => return (offered, Some(error.kind()), false, witness.report()),
            }
            // Preserve every nominal offer when the source thread is delayed.
            // A late tick is sent immediately, retaining the finite 2 ms grid
            // and actual send-return observations without claiming that its
            // packet departed or arrived at the nominal instant.
            nominal += period;
        }
    })));
    let mut consumer = OwnedTask(Some(tokio::spawn(async move {
        let mut original = Vec::new();
        let mut bytes = [0; 129];
        loop {
            tokio::select! { biased;
                _ = &mut sink_stop => return original,
                _ = sleep_until(end) => panic!("owned application receive phase expired"),
                result = sink.recv(&mut bytes) => {
                    let n = result.unwrap();
                    assert_eq!(n, 8);
                    assert!(original.len() < MAX_PACKETS);
                    let sequence = u64::from_be_bytes(bytes[..8].try_into().unwrap());
                    assert_eq!(sequence, original.len() as u64);
                    original.push(sequence);
                    received_count.store(original.len(), Ordering::Release);
                    received_progress.notify_one();
                }
            }
        }
    })));
    let (left, right) = tokio::join!(sender.finish(end), receiver.finish(end));
    if !left.0.success() || !right.0.success() {
        // An actual refusal remains a failed positive test. Stop only the
        // owned application actors and retain content-free counts/kinds.
        stop_source.send(()).ok();
        stop_sink.send(()).ok();
        let offered = producer.finish(end).await;
        let delivered = consumer.finish(end).await;
        println!(
            "timing_cli_positive_refusal sender_ok={} receiver_ok={} offered={} producer_kind={:?} delivered={}",
            left.0.success(), right.0.success(), offered.0, offered.1, delivered.len()
        );
        println!("timing_cli_application_source_observations={}", offered.3);
        // Exact children and owned application actors have already terminated.
        // Only static labels/counts/custody facts from parsed failure receipts;
        // do not expose child error text, stderr, payload, keys or addresses.
        if !left.0.success() {
            println!(
                "timing_cli_sender_refusal={}",
                refusal_diagnostics::content_free_refusal(&left.1)
            );
        }
        if !right.0.success() {
            println!(
                "timing_cli_receiver_refusal={}",
                refusal_diagnostics::content_free_refusal(&right.1)
            );
        }
        panic!("actual CLI timing positive refused; no conditional PASS");
    }
    assert!(left.0.success() && right.0.success());
    let sent = &left.1;
    let received = &right.1;
    assert_eq!(sent["timing_control_authenticated"], true);
    assert_eq!(received["timing_control_authenticated"], true);
    assert_eq!(sent["installed_full_wide"], false);
    assert_eq!(received["installed_full_wide"], false);
    assert_eq!(sent["observations"]["service_queue_contract_v2"], true);
    assert_eq!(sent["observations"]["release_thread_terminal"], true);
    assert_eq!(sent["observations"]["release_thread_joined"], true);
    assert_eq!(received["observations"]["collector_joined"], true);
    assert_eq!(received["collector_terminal"], true);
    for receipt in [sent, received] {
        assert_eq!(
            receipt["conditional_reference"]["actual_poisson_process_verified"],
            false
        );
        assert_eq!(
            receipt["conditional_reference"]["actual_mm1_service_verified"],
            false
        );
        assert_eq!(receipt["observations"]["service_model_verified"], false);
        assert_eq!(
            receipt["application_origin_and_unique_sequence_verified"],
            false
        );
        assert!(receipt.get("payload").is_none());
    }
    let accepted = number(&sent["observations"], "accepted_packets");
    assert!(accepted > 0 && accepted <= MAX_PACKETS);
    assert_eq!(number(&sent["observations"], "sent_packets"), accepted);
    assert_eq!(number(&sent["observations"], "retained_packets"), 0);
    assert_eq!(
        number(&received["observations"], "received_packets"),
        accepted
    );
    assert_eq!(
        number(&received["observations"], "delivered_packets"),
        accepted
    );
    assert_eq!(number(&received["observations"], "retained_packets"), 0);
    let (offered, producer_terminal, complete_horizon, source_witness) = producer.finish(end).await;
    assert_eq!(producer_terminal, None);
    assert!(complete_horizon);
    assert!(offered as usize >= accepted);
    // The successful UDP write/receipt is not substituted for observation by
    // the application. Wait for that actual packet-count barrier as well.
    timeout_at(end, async {
        while count.load(Ordering::Acquire) < accepted {
            progress.notified().await;
        }
    })
    .await
    .unwrap();
    stop_sink.send(()).ok();
    let original = consumer.finish(end).await;
    assert_eq!(original.len(), accepted);
    assert!(original.iter().copied().eq(0..accepted as u64));
    assert_eq!(secret_file::read(&output, 1).unwrap().as_slice(), b"z");
    println!("timing_cli_application_source_observations={source_witness}");
    println!(
        "timing_cli_positive sender_reaped=true receiver_reaped=true offered={offered} accepted={accepted} actual_application_delivered={} control_authenticated=true source_poisson_verified=false service_mm1_verified=false",
        original.len()
    );
}
