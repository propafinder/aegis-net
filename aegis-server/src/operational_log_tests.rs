use crate::operational_log::*;
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = CaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CaptureWriter(self.0.clone())
    }
}

impl io::Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn capture(policy: OperationalLogPolicy) -> String {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();
    let peer = "192.0.2.44:43123".parse().unwrap();
    let error = "synthetic request target api.private.example:9443";
    tracing::subscriber::with_default(subscriber, || {
        warn_failure(
            policy,
            FailureStage::GrpcRequest,
            FailureReason::RequestFailed,
            Some(peer),
            &error,
        );
    });
    let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    output
}

#[test]
fn default_capture_has_only_bounded_operational_fields() {
    let output = capture(OperationalLogPolicy::default());
    assert!(output.contains("server_operation_failed"));
    assert!(output.contains("failure_stage=\"grpc_request\""));
    assert!(output.contains("reason_code=\"request_failed\""));
    assert!(!output.contains("192.0.2.44"));
    assert!(!output.contains("api.private.example"));
    assert!(!output.contains("9443"));
}

#[test]
fn explicit_sensitive_context_restores_peer_and_diagnostic_detail() {
    let output = capture(OperationalLogPolicy::new(true));
    assert!(output.contains("192.0.2.44:43123"));
    assert!(output.contains("api.private.example:9443"));
}

#[test]
fn default_branch_does_not_format_error() {
    struct MustNotFormat;
    impl fmt::Display for MustNotFormat {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("default operational logging formatted an error")
        }
    }
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(capture)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        warn_failure(
            OperationalLogPolicy::default(),
            FailureStage::TcpSession,
            FailureReason::ConnectionFailed,
            None,
            &MustNotFormat,
        );
    });
}

#[test]
fn explicit_sensitive_context_formats_complete_anyhow_chain_only_in_opt_in_branch() {
    use anyhow::Context as _;

    let error = Err::<(), _>(anyhow::anyhow!("synthetic-inner-cause-marker"))
        .context("synthetic-outer-context")
        .unwrap_err();
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        warn_failure(
            OperationalLogPolicy::new(true),
            FailureStage::GrpcRequest,
            FailureReason::RequestFailed,
            None,
            &error,
        );
    });
    let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("synthetic-outer-context"));
    assert!(output.contains("synthetic-inner-cause-marker"));
}

fn capture_quic_shutdown(
    policy: OperationalLogPolicy,
    result: &Result<anyhow::Result<()>, tokio::task::JoinError>,
) -> String {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        warn_quic_shutdown_result(policy, result);
    });
    let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    output
}

#[test]
fn quic_shutdown_default_is_private_and_opt_in_retains_actual_error_chain() {
    use anyhow::Context as _;

    let failure = Err::<(), _>(anyhow::anyhow!("synthetic-quic-inner-marker"))
        .context("synthetic-quic-outer-context")
        .map(|_| ());
    let result = Ok(failure);
    let private = capture_quic_shutdown(OperationalLogPolicy::default(), &result);
    assert!(private.contains("failure_stage=\"quic_session\""));
    assert!(!private.contains("synthetic-quic-inner-marker"));
    assert!(!private.contains("synthetic-quic-outer-context"));

    let diagnostic = capture_quic_shutdown(OperationalLogPolicy::new(true), &result);
    assert!(diagnostic.contains("synthetic-quic-outer-context"));
    assert!(diagnostic.contains("synthetic-quic-inner-marker"));
}

fn capture_new_emitters(policy: OperationalLogPolicy) -> String {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(capture.clone())
        .finish();
    let peer = "192.0.2.44:43123".parse().unwrap();
    let identity = "198.51.100.77".parse().unwrap();
    let error = anyhow::anyhow!("synthetic-inner-marker").context("synthetic-outer-marker");
    tracing::subscriber::with_default(subscriber, || {
        debug_peer_event(
            policy,
            "websocket_upgrade_starting",
            peer,
            "websocket starting",
        );
        debug_peer_identity_event(
            policy,
            "websocket_banned_identity_dropped",
            peer,
            identity,
            "banned websocket identity",
        );
        debug_bundle_rejected(
            policy,
            "bundle_request_rejected",
            peer,
            403,
            "Forbidden",
            &error,
        );
        info_bundle_redeemed(
            policy,
            peer,
            std::path::Path::new("/synthetic/private/bundle-marker.tar.gz"),
            17,
        );
        info_listener_bound(policy, peer);
        info_quic_listener_bound(policy, peer);
        info_bundle_enabled(
            policy,
            std::path::Path::new("/synthetic/private/token-store-marker.json"),
            "/synthetic-private-prefix",
            3,
        );
        warn_process_alias_failure(policy, "synthetic-alias-marker", &error);
    });
    let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    output
}

#[test]
fn residual_emitters_default_to_stable_fields_without_sensitive_markers() {
    let output = capture_new_emitters(OperationalLogPolicy::default());
    for stable in [
        "websocket_upgrade_starting",
        "websocket_banned_identity_dropped",
        "bundle_request_rejected",
        "bundle_redeemed",
        "server_tcp_listener_bound",
        "server_quic_listener_bound",
        "bundle_endpoint_enabled",
        "process_alias_failed",
    ] {
        assert!(output.contains(stable), "missing stable event {stable}");
    }
    assert!(output.contains("bytes=17"));
    assert!(output.contains("tokens=3"));
    for private in [
        "192.0.2.44",
        "198.51.100.77",
        "bundle-marker",
        "token-store-marker",
        "synthetic-private-prefix",
        "synthetic-alias-marker",
        "synthetic-inner-marker",
        "synthetic-outer-marker",
    ] {
        assert!(!output.contains(private), "default log leaked {private}");
    }
}

#[test]
fn residual_emitters_restore_sensitive_context_only_for_explicit_policy() {
    let output = capture_new_emitters(OperationalLogPolicy::new(true));
    for marker in [
        "192.0.2.44:43123",
        "198.51.100.77",
        "bundle-marker.tar.gz",
        "token-store-marker.json",
        "/synthetic-private-prefix",
        "synthetic-alias-marker",
        "synthetic-inner-marker",
        "synthetic-outer-marker",
    ] {
        assert!(output.contains(marker), "explicit log omitted {marker}");
    }
}

#[test]
fn residual_default_error_emitters_do_not_format_supplied_values() {
    struct MustNotFormat;
    impl fmt::Display for MustNotFormat {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("default residual emitter formatted diagnostic detail")
        }
    }
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(capture)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        debug_bundle_rejected(
            OperationalLogPolicy::default(),
            "bundle_request_rejected",
            "192.0.2.44:43123".parse().unwrap(),
            500,
            "Internal Server Error",
            &MustNotFormat,
        );
        warn_process_alias_failure(
            OperationalLogPolicy::default(),
            "synthetic-alias-marker",
            &MustNotFormat,
        );
    });
}
