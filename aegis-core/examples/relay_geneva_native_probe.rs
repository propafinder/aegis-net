//! Controlled native CI probe. No application target, identity, or fallback dial.
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("controlled relay Geneva probe requires Linux");
    std::process::exit(2);
}

#[cfg(any(target_os = "linux", test))]
mod completion {
    use std::{error::Error, fmt, io};

    #[derive(Clone, Copy, Debug)]
    pub enum Phase {
        Ready,
        Permit,
        TcpConnect,
        DropCheck,
        TlsConfiguration,
        TlsHandshake,
        TlsWrite,
        TlsRead,
        EchoCheck,
        PacketCheck,
        CaptureStop,
        Quiesce,
    }
    impl Phase {
        fn label(self) -> &'static str {
            match self {
                Self::Ready => "ready",
                Self::Permit => "permit",
                Self::TcpConnect => "tcp_connect",
                Self::DropCheck => "drop_check",
                Self::TlsConfiguration => "tls_configuration",
                Self::TlsHandshake => "tls_handshake",
                Self::TlsWrite => "tls_write",
                Self::TlsRead => "tls_read",
                Self::EchoCheck => "echo_check",
                Self::PacketCheck => "packet_check",
                Self::CaptureStop => "capture_stop",
                Self::Quiesce => "quiesce",
            }
        }
    }

    pub struct Failure {
        pub phase: Phase,
        error: Box<dyn Error>,
        category: &'static str,
    }
    impl Failure {
        pub fn new(phase: Phase, error: Box<dyn Error>) -> Self {
            let category = if error.is::<io::Error>() {
                "io"
            } else {
                "other"
            };
            Self {
                phase,
                error,
                category,
            }
        }
        pub fn timeout(phase: Phase, error: Box<dyn Error>) -> Self {
            Self {
                phase,
                error,
                category: "timeout",
            }
        }
        pub fn task_join(phase: Phase, error: Box<dyn Error>) -> Self {
            Self {
                phase,
                error,
                category: "task_join",
            }
        }
        pub fn protocol(phase: Phase, message: &'static str) -> Self {
            Self {
                phase,
                error: message.into(),
                category: "protocol",
            }
        }
        // Metadata only: error text, paths, certificates and transport frames
        // are deliberately excluded, including from the final Rust main Debug.
        pub fn diagnostic(&self, event: &'static str) -> String {
            let (kind, code) = self.error.downcast_ref::<io::Error>().map_or(
                ("null".to_owned(), "null".to_owned()),
                |error| {
                    (
                        format!("\"{:?}\"", error.kind()),
                        error
                            .raw_os_error()
                            .map_or("null".to_owned(), |code| code.to_string()),
                    )
                },
            );
            format!("{{\"phase\":\"{event}\",\"stage\":\"{}\",\"failure_category\":\"{}\",\"io_kind\":{kind},\"raw_os_error\":{code}}}\n", self.phase.label(), self.category)
        }
    }
    impl fmt::Debug for Failure {
        fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
            out.write_str(self.diagnostic("failure").trim_end())
        }
    }

    pub struct AttemptError {
        operation: Option<Box<Failure>>,
        capture_stop: Option<Box<Failure>>,
        cleanup: Option<Box<Failure>>,
        diagnostic_write_failed: bool,
    }
    impl fmt::Debug for AttemptError {
        fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
            out.debug_struct("AttemptError")
                .field("operation", &self.operation)
                .field("capture_stop", &self.capture_stop)
                .field("cleanup", &self.cleanup)
                .field("diagnostic_write_failed", &self.diagnostic_write_failed)
                .finish()
        }
    }
    impl fmt::Display for AttemptError {
        fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                out,
                "controlled native probe failed at {}",
                self.primary().phase.label()
            )
        }
    }
    impl Error for AttemptError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(self.primary().error.as_ref())
        }
    }
    impl AttemptError {
        fn primary(&self) -> &Failure {
            self.operation
                .as_ref()
                .or(self.capture_stop.as_ref())
                .or(self.cleanup.as_ref())
                .expect("AttemptError always contains an actual failure")
        }
    }

    pub fn record_failure<T>(
        result: &Result<T, Failure>,
        event: &'static str,
        writer: &mut impl io::Write,
    ) -> io::Result<()> {
        if let Err(failure) = result {
            writer.write_all(failure.diagnostic(event).as_bytes())?;
            writer.flush()?;
        }
        Ok(())
    }

    pub fn finish<T>(
        operation: Result<T, Failure>,
        capture_stop: Result<(), Failure>,
        cleanup: Result<(), Failure>,
        diagnostic_write_failed: bool,
    ) -> Result<T, AttemptError> {
        // The primary operation remains first even when quiesce fails later.
        // Successful operation/capture cannot suppress an actual cleanup error.
        match (operation, capture_stop, cleanup) {
            (Ok(row), Ok(()), Ok(())) => Ok(row),
            (operation, capture_stop, cleanup) => Err(AttemptError {
                operation: operation.err().map(Box::new),
                capture_stop: capture_stop.err().map(Box::new),
                cleanup: cleanup.err().map(Box::new),
                diagnostic_write_failed,
            }),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn operation_error_is_recorded_before_cleanup_and_retained_as_primary() {
            let operation: Result<(), Failure> = Err(Failure::new(
                Phase::TcpConnect,
                io::Error::new(io::ErrorKind::ConnectionReset, "PRIVATE operation payload").into(),
            ));
            let mut metadata = Vec::new();
            record_failure(&operation, "operation_failed", &mut metadata).unwrap();
            let emitted = String::from_utf8(metadata).unwrap();
            assert!(emitted.contains("tcp_connect") && emitted.contains("ConnectionReset"));
            assert!(!emitted.contains("PRIVATE"));
            let error = finish(
                operation,
                Ok(()),
                Err(Failure::new(
                    Phase::Quiesce,
                    io::Error::other("PRIVATE cleanup payload").into(),
                )),
                false,
            )
            .unwrap_err();
            assert_eq!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<io::Error>()
                    .unwrap()
                    .kind(),
                io::ErrorKind::ConnectionReset
            );
            assert!(error.cleanup.is_some());
            let final_debug = format!("{error:?}");
            assert!(final_debug.contains("tcp_connect") && final_debug.contains("quiesce"));
            assert!(!final_debug.contains("PRIVATE"));
        }
        #[test]
        fn timeout_remains_primary_when_both_later_phases_fail() {
            let operation: Result<(), Failure> = Err(Failure::timeout(
                Phase::TlsHandshake,
                io::Error::new(io::ErrorKind::TimedOut, "original timeout").into(),
            ));
            let error = finish(
                operation,
                Err(Failure::protocol(Phase::CaptureStop, "capture refused")),
                Err(Failure::new(
                    Phase::Quiesce,
                    io::Error::other("quiesce refused").into(),
                )),
                false,
            )
            .unwrap_err();
            assert!(
                error.operation.is_some()
                    && error.capture_stop.is_some()
                    && error.cleanup.is_some()
            );
            assert_eq!(error.primary().phase.label(), "tls_handshake");
            assert_eq!(error.primary().category, "timeout");
        }
        #[test]
        fn cleanup_failure_cannot_turn_successful_operation_into_pass() {
            let error = finish(
                Ok(42),
                Ok(()),
                Err(Failure::new(
                    Phase::Quiesce,
                    io::Error::from_raw_os_error(5).into(),
                )),
                false,
            )
            .unwrap_err();
            assert!(error.operation.is_none());
            assert_eq!(error.primary().phase.label(), "quiesce");
            assert_eq!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(5)
            );
        }
        #[test]
        fn capture_failure_precedes_cleanup_if_operation_succeeded() {
            let error = finish(
                Ok(42),
                Err(Failure::protocol(Phase::CaptureStop, "capture refused")),
                Err(Failure::new(
                    Phase::Quiesce,
                    io::Error::other("cleanup failed").into(),
                )),
                false,
            )
            .unwrap_err();
            assert_eq!(error.primary().phase.label(), "capture_stop");
            assert!(error.cleanup.is_some());
        }
        #[test]
        fn diagnostic_io_failure_does_not_replace_any_attempt_failure() {
            struct Refused;
            impl io::Write for Refused {
                fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                    Err(io::Error::other("private writer detail"))
                }
                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }
            let result: Result<(), Failure> = Err(Failure::protocol(Phase::Permit, "bad permit"));
            let failed = record_failure(&result, "operation_failed", &mut Refused).is_err();
            let error = finish(result, Ok(()), Ok(()), failed).unwrap_err();
            assert!(error.diagnostic_write_failed);
            assert_eq!(error.primary().phase.label(), "permit");
            assert!(!format!("{error:?}").contains("private"));
        }
        #[test]
        fn every_fixed_phase_and_join_category_emits_only_public_metadata() {
            for phase in [
                Phase::Ready,
                Phase::Permit,
                Phase::TcpConnect,
                Phase::DropCheck,
                Phase::TlsConfiguration,
                Phase::TlsHandshake,
                Phase::TlsWrite,
                Phase::TlsRead,
                Phase::EchoCheck,
                Phase::PacketCheck,
                Phase::CaptureStop,
                Phase::Quiesce,
            ] {
                let failure =
                    Failure::task_join(phase, io::Error::other("PRIVATE join payload").into());
                let row = failure.diagnostic("operation_failed");
                assert!(row.len() < 256 && row.ends_with('\n'));
                assert!(row.contains(phase.label()) && row.contains("task_join"));
                assert!(!row.contains("PRIVATE"));
            }
        }
        #[test]
        fn all_three_successes_retain_original_row() {
            assert_eq!(
                finish(Ok(vec![1, 2, 3]), Ok(()), Ok(()), false).unwrap(),
                vec![1, 2, 3]
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(stamp) =
        option_env!("AEGIS_BUILD_SOURCE_COMMIT").or(option_env!("AEGIS_BUILD_GIT_SHA"))
    {
        aegis_core::relay_geneva::linux::install_build_source_stamp(stamp)?;
    }
    use aegis_core::relay_geneva::{
        linux::LinuxRuntime, RelayOuterGenevaSettings, RelayProtectedTcp,
    };
    use completion::{Failure, Phase};
    use rustls::pki_types::{CertificateDer, ServerName};
    use std::{io, net::SocketAddrV4, path::Path, sync::Arc, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 || !matches!(args[4].as_str(), "tls" | "tls-transfer" | "drop") {
        return Err("expected request.json endpoint ca.der tls|tls-transfer|drop".into());
    }
    let request: RelayOuterGenevaSettings = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    if request.interface != "client0"
        || request.local_address != "192.0.2.2".parse::<std::net::Ipv4Addr>()?
        || request.max_duration_secs != 24
    {
        return Err("CI-only exact isolated request refused".into());
    }
    let endpoint: SocketAddrV4 = args[2].parse()?;
    if endpoint != "192.0.2.3:24443".parse()? {
        return Err("CI-only exact relay endpoint refused".into());
    }
    let started = std::time::Instant::now();
    let runtime =
        tokio::task::spawn_blocking(move || LinuxRuntime::start(&request, vec![endpoint]))
            .await??;
    let mode = args[4].clone();
    let mut operation_phase = Phase::Ready;
    let operation = async {
        println!(
            "{}",
            serde_json::json!({"phase":"ready","source":option_env!("AEGIS_BUILD_SOURCE_COMMIT").unwrap_or("unknown"),"fallback_dials":0})
        );
        io::Write::flush(&mut io::stdout())?;
        // A blocking task must itself terminate: cancelling an unbounded stdin
        // readline can otherwise prevent Tokio shutdown. Read one ready byte
        // at a time with a separate monotonic deadline and an exact frame cap.
        operation_phase = Phase::Permit;
        let permit = tokio::task::spawn_blocking(bounded_permit).await??;
        if permit != b"continue\n" || started.elapsed() > Duration::from_secs(8) {
            return Err::<serde_json::Value, Box<dyn std::error::Error>>(
                "bounded native permit refused".into(),
            );
        }
        operation_phase = Phase::TcpConnect;
        let connection =
            tokio::time::timeout(Duration::from_secs(4), runtime.connect(endpoint)).await;
        if mode == "drop" {
            operation_phase = Phase::DropCheck;
            match connection {
                Ok(Ok((tcp, guard))) => {
                    drop(tcp);
                    drop(guard);
                    return Err::<serde_json::Value, Box<dyn std::error::Error>>(
                        "drop strategy unexpectedly connected".into(),
                    );
                }
                Ok(Err(_)) | Err(_) => {
                    let counters = runtime.packet_counters()?;
                    if runtime.is_failed()
                        || counters.outbound_empty_batches == 0
                        || counters.outbound_batches != counters.outbound_empty_batches
                        || counters.outbound_emitted_frames != 0
                        || counters.inbound_emitted_frames != 0
                    {
                        return Err(
                            "refusal without actual acknowledged empty output is not a drop proof"
                                .into(),
                        );
                    }
                    return Ok(
                        serde_json::json!({"selected_connection_refused":true,"actual_program_drop_acknowledged":true,"native_packet_counters":counters,"worker_healthy_before_quiesce":true,"fallback_dials":0}),
                    );
                }
            }
        }
        let (tcp, guard) = connection??;
        operation_phase = Phase::TlsConfiguration;
        let tcp = RelayProtectedTcp::protected(tcp, Box::new(guard))?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(std::fs::read(Path::new(&args[3]))?))?;
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        operation_phase = Phase::TlsHandshake;
        let mut tls = connector
            .connect(ServerName::try_from("relay-geneva.test")?, tcp)
            .await?;
        let marker = b"AEGIS_ENCRYPTED_TARGET_ONLY_TEST_8d38";
        let size = if mode == "tls-transfer" {
            65536
        } else {
            marker.len()
        };
        let payload: Vec<u8> = marker.iter().copied().cycle().take(size).collect();
        let transfer_started = std::time::Instant::now();
        operation_phase = Phase::TlsWrite;
        tls.write_all(&(size as u32).to_be_bytes()).await?;
        tls.write_all(&payload).await?;
        tls.flush().await?;
        let mut response = vec![0; size];
        operation_phase = Phase::TlsRead;
        tls.read_exact(&mut response).await?;
        operation_phase = Phase::EchoCheck;
        if response != payload {
            return Err("verified TLS echo content differs".into());
        }
        let elapsed = transfer_started.elapsed().as_micros();
        drop(tls);
        operation_phase = Phase::PacketCheck;
        let counters = runtime.packet_counters()?;
        if runtime.is_failed()
            || counters.outbound_emitted_frames == 0
            || counters.inbound_emitted_frames == 0
        {
            return Err("TLS echo without a healthy measured native packet path".into());
        }
        Ok(
            serde_json::json!({"strict_local_CA_name_TLS13_echo":true,"marker_bytes":marker.len(),"encrypted_echo_bytes":size,"transfer_elapsed_microseconds":elapsed,"application_transfer_not_field_throughput_acceptance":true,"native_packet_counters":counters,"worker_healthy_before_quiesce":true,"fallback_dials":0}),
        )
    };
    let result = match tokio::time::timeout(Duration::from_secs(10), operation).await {
        Ok(result) => result.map_err(|error| {
            if error.is::<tokio::time::error::Elapsed>() {
                Failure::timeout(operation_phase, error)
            } else {
                Failure::new(operation_phase, error)
            }
        }),
        Err(error) => Err(Failure::timeout(operation_phase, Box::new(error))),
    };
    // Publish primary stage/kind before cleanup can fail; never print error text.
    // A refused diagnostic write is retained without skipping checked cleanup.
    let mut diagnostic_write_failed =
        completion::record_failure(&result, "operation_failed", &mut io::stderr()).is_err();
    if result.is_err() {
        match runtime.packet_counters() {
            Ok(counters) => {
                let metadata = format!(
                    "{}\n",
                    serde_json::json!({"phase":"operation_failed_packet_snapshot","worker_failed_before_quiesce":runtime.is_failed(),"native_packet_counters":counters,"scope":"controlled attempt diagnosis only"})
                );
                diagnostic_write_failed |=
                    io::Write::write_all(&mut io::stderr(), metadata.as_bytes())
                        .and_then(|_| io::Write::flush(&mut io::stderr()))
                        .is_err();
            }
            Err(error) => {
                let snapshot: Result<(), Failure> =
                    Err(Failure::new(Phase::PacketCheck, Box::new(error)));
                diagnostic_write_failed |= completion::record_failure(
                    &snapshot,
                    "packet_snapshot_failed",
                    &mut io::stderr(),
                )
                .is_err();
            }
        }
    }
    // AF_PACKET bound to the TUN fails with ENETDOWN after device teardown.
    // Give the controller an explicit bounded capture-stop barrier while the
    // runtime still owns the live TUN. Missing/malformed permits cannot be PASS.
    let capture_barrier = if result.is_ok() {
        let phase = format!(
            "{}\n",
            serde_json::json!({"phase":"transfer_complete","tun_still_owned":true})
        );
        let published = io::Write::write_all(&mut io::stdout(), phase.as_bytes())
            .and_then(|_| io::Write::flush(&mut io::stdout()));
        let permit = tokio::task::spawn_blocking(bounded_permit).await;
        match (published, permit) {
            (Ok(()), Ok(Ok(bytes))) if bytes == b"capture_closed\n" => Ok(()),
            (Err(error), _) | (Ok(()), Ok(Err(error))) => {
                Err(Failure::new(Phase::CaptureStop, Box::new(error)))
            }
            (Ok(()), Err(error)) => Err(Failure::task_join(Phase::CaptureStop, Box::new(error))),
            (Ok(()), Ok(Ok(_))) => Err(Failure::protocol(
                Phase::CaptureStop,
                "bounded capture-stop permit refused",
            )),
        }
    } else {
        Ok(())
    };
    // All operation-local sockets have dropped, including cancelled openings.
    // Retire regardless of the primary result. Unwrap none of these failures
    // until all outcomes are retained; cleanup must never mask the first error.
    let cloned = runtime.clone();
    let cleanup = match tokio::time::timeout(
        Duration::from_secs(12),
        tokio::task::spawn_blocking(move || cloned.quiesce()),
    )
    .await
    {
        Err(error) => Err(Failure::timeout(Phase::Quiesce, Box::new(error))),
        Ok(Err(error)) => Err(Failure::task_join(Phase::Quiesce, Box::new(error))),
        Ok(Ok(result)) => result.map_err(|error| Failure::new(Phase::Quiesce, Box::new(error))),
    };
    diagnostic_write_failed |=
        completion::record_failure(&capture_barrier, "capture_stop_failed", &mut io::stderr())
            .is_err();
    diagnostic_write_failed |=
        completion::record_failure(&cleanup, "cleanup_failed", &mut io::stderr()).is_err();
    let row = completion::finish(result, capture_barrier, cleanup, diagnostic_write_failed)?;
    println!(
        "{}",
        serde_json::json!({"phase":"terminal","operation":row,"owned_runtime_quiesced":true,"runtime_seconds":started.elapsed().as_secs_f64(),"installed_client_or_target_network_acceptance":false})
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn bounded_permit() -> std::io::Result<Vec<u8>> {
    use std::{io, time::Duration};
    let until = std::time::Instant::now() + Duration::from_secs(4);
    let mut bytes = Vec::new();
    loop {
        let remaining = until.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() || bytes.len() >= 16 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native permit deadline/frame bound",
            ));
        }
        let mut descriptor = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let count = unsafe {
            libc::poll(
                &mut descriptor,
                1,
                remaining.as_millis().clamp(1, 4000) as i32,
            )
        };
        if count <= 0 || descriptor.revents & libc::POLLIN == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "native permit input unavailable",
            ));
        }
        let mut byte = 0u8;
        if unsafe { libc::read(0, (&mut byte as *mut u8).cast(), 1) } != 1 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "native permit input closed",
            ));
        }
        bytes.push(byte);
        if byte == b'\n' {
            return Ok(bytes);
        }
    }
}
