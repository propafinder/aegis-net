//! Private diagnostics accept a closed set of event/error codes. Arbitrary
//! messages, Debug values, spans and error chains never reach the formatter.
use super::RuntimeEventCode;
use serde_json::{json, Map, Value};
use std::fmt;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{format::Writer, FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

pub(super) fn known_event_code(value: &str) -> Option<&'static str> {
    RuntimeEventCode::ALL
        .iter()
        .map(|code| code.as_str())
        .find(|code| *code == value)
}

// Values come from anyhow_error_kind_code: io_error_kind_code, the typed QUIC
// classes and the closed profile command classes. Unknown prose (including
// upstream TLS errors with certificate names) is omitted even in a field
// called error_kind.
fn known_error_kind(value: &str) -> Option<&'static str> {
    const CODES: &[&str] = &[
        "not_found",
        "permission_denied",
        "connection_refused",
        "connection_reset",
        "connection_aborted",
        "not_connected",
        "addr_in_use",
        "addr_not_available",
        "network_unreachable",
        "host_unreachable",
        "broken_pipe",
        "already_exists",
        "would_block",
        "not_a_directory",
        "is_a_directory",
        "directory_not_empty",
        "invalid_input",
        "invalid_data",
        "timed_out",
        "write_zero",
        "interrupted",
        "unsupported",
        "unexpected_eof",
        "other",
        "unclassified",
        "quic_timed_out",
        "quic_connection_refused",
        "selected_relay_guard_refused",
        "profile_command_failed",
    ];
    CODES.iter().copied().find(|code| *code == value)
}

fn error_kind_field(name: &str) -> bool {
    matches!(
        name,
        "error_kind"
            | "relay_error_kind"
            | "session_error_kind"
            | "broker_source_error_kind"
            | "source_error_kind"
    )
}

/// Keep no arbitrary string, number, nested object or destination-derived ID.
/// The event code itself is supplied separately by the typed event API.
pub(super) fn private_fields(fields: &Value) -> Value {
    let mut safe = Map::new();
    safe.insert("diagnostics".into(), json!("private"));
    if let Some(fields) = fields.as_object() {
        for (name, value) in fields {
            if error_kind_field(name) {
                if let Some(code) = value.as_str().and_then(known_error_kind) {
                    safe.insert(name.clone(), json!(code));
                }
            }
        }
    }
    Value::Object(safe)
}

/// Retain detailed operator diagnostics only after the explicit opt-in.
pub fn error_message(error: &anyhow::Error) -> String {
    if super::private_logs_enabled() {
        crate::runtime_errors::anyhow_error_kind_code(error)
            .unwrap_or("unclassified")
            .to_owned()
    } else {
        format!("{error:#}")
    }
}

pub fn error_chain(error: &anyhow::Error) -> Vec<String> {
    if super::private_logs_enabled() {
        vec![error_message(error)]
    } else {
        crate::runtime_errors::anyhow_error_chain_messages(error)
    }
}

#[derive(Default)]
struct PrivateVisitor {
    fields: Map<String, Value>,
}

impl Visit for PrivateVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        let code = if field.name() == "event_code" {
            known_event_code(value)
        } else if error_kind_field(field.name()) {
            known_error_kind(value)
        } else {
            None
        };
        if let Some(code) = code {
            self.fields.insert(field.name().into(), json!(code));
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn fmt::Debug) {
        // Do not call Debug/Display on untrusted values, including `message`.
    }
}

/// All private events use this formatter, including events from dependencies.
/// It never renders parent spans or formatted prose from any callsite.
pub struct PrivateEventFormat;

impl<S, N> FormatEvent<S, N> for PrivateEventFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut visitor = PrivateVisitor::default();
        event.record(&mut visitor);
        visitor
            .fields
            .entry("event_code")
            .or_insert_with(|| json!("runtime_event"));
        visitor
            .fields
            .insert("level".into(), json!(event.metadata().level().as_str()));
        visitor
            .fields
            .insert("diagnostics".into(), json!("private"));
        writeln!(writer, "{}", Value::Object(visitor.fields))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[test]
    fn policy_ack_cause_is_visible_only_in_explicit_non_forensic_diagnostics() {
        const CHILD: &str = "AEGIS_POLICY_ACK_PRIVACY_TEST_CHILD";
        if let Some(mode) = std::env::var_os(CHILD) {
            let diagnostic = mode == "diagnostic" || mode == "forensic";
            super::super::set_private_logs(!diagnostic);
            super::super::set_forensic_redact(mode == "forensic");
            let error = anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "synthetic-private-policy-relay.example:443",
            ))
            .context("live relay policy has not confirmed this device; ingress remains blocked");
            if mode == "diagnostic" {
                assert!(error_message(&error).contains("synthetic-private-policy-relay.example"));
                assert!(error_chain(&error).len() > 1);
            } else {
                assert_eq!(error_message(&error), "connection_refused");
                assert_eq!(error_chain(&error), vec!["connection_refused"]);
            }
            return;
        }
        for mode in ["default", "diagnostic", "forensic"] {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "runtime_event_stream::privacy::tests::policy_ack_cause_is_visible_only_in_explicit_non_forensic_diagnostics", "--test-threads=1"])
                .env(CHILD, mode)
                .output().unwrap();
            assert!(
                result.status.success(),
                "policy ACK privacy child failed: {mode}"
            );
            assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
        }
    }

    #[test]
    fn private_policy_defaults_remain_independent_of_diagnostic_fixtures() {
        // Other runtime tests intentionally enable the global diagnostic
        // fixture. A fresh process proves the actual startup default without
        // racing or resetting another test's policy.
        const CHILD: &str = "AEGIS_PRIVATE_POLICY_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert!(super::super::private_logs_enabled());
            let error = anyhow::anyhow!("private-default.example");
            assert_eq!(error_message(&error), "unclassified");
            assert_eq!(error_chain(&error), vec!["unclassified"]);
            return;
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "runtime_event_stream::privacy::tests::private_policy_defaults_remain_independent_of_diagnostic_fixtures", "--test-threads=1"])
            .env(CHILD, "1")
            .output().unwrap();
        assert!(result.status.success(), "private default child failed");
        assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
    }

    #[derive(Clone)]
    pub(crate) struct Capture(pub Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn private_tracing_discards_prose_chains_spans_and_unknown_codes() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = bytes.clone();
        let subscriber = tracing_subscriber::fmt()
            .event_format(PrivateEventFormat)
            .with_writer(move || Capture(writer.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("session", host = "private-span.example");
            let _guard = span.enter();
            for reason in ["dns", "connect", "timeout", "certificate", "udp"] {
                let error = anyhow::anyhow!("{reason} failed for private-target.example:443")
                    .context("upstream private-relay.example");
                tracing::warn!(
                    event_code = RuntimeEventCode::RelayTransportFailed.as_str(),
                    error_kind = "connection_refused",
                    target = "private-target.example",
                    nested = ?json!({"arbitrary": "private-nested.example"}),
                    error_chain = ?error.chain().map(ToString::to_string).collect::<Vec<_>>(),
                    "request: {error:#}"
                );
            }
            tracing::warn!(
                event_code = "private-code.example",
                error_kind = "private-kind.example",
                "unregistered message private-message.example"
            );
        });
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(!output.contains("private-"), "{output}");
        let records: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 6);
        assert_eq!(records[0]["event_code"], "relay_transport_failed");
        assert_eq!(records[0]["error_kind"], "connection_refused");
        assert_eq!(records[5]["event_code"], "runtime_event");
        assert!(records[5].get("error_kind").is_none());
    }

    #[test]
    fn private_json_keeps_only_closed_error_codes() {
        let fields = json!({
            "relay_error_kind": "connection_refused",
            "session_error_kind": "private-kind.example",
            "target": "private-target.example",
            "error": "connect private-error.example:443 failed",
            "error_chain": ["DNS private-chain.example", "CA private-ca.example"],
            "nested": {"host": "private-nested.example"},
            "target_as_integer": 2130706433u32
        });
        let safe = private_fields(&fields);
        assert_eq!(
            safe,
            json!({"diagnostics": "private", "relay_error_kind": "connection_refused"})
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let stream = super::super::RuntimeEventStream::new(&path).unwrap();
        stream.emit(
            "warn",
            RuntimeEventCode::RelayTransportFailed,
            "relay_transport_failed",
            safe,
        );
        let persisted = std::fs::read_to_string(path).unwrap();
        assert!(!persisted.contains("private-"));
        assert!(!persisted.contains("2130706433"));
    }

    #[test]
    fn private_json_keeps_every_classifier_code() {
        use crate::runtime_errors::{anyhow_error_kind_code, ProfileCommandFailure};
        let closed = |code| {
            quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
                error_code: code,
                frame_type: None,
                reason: bytes::Bytes::from_static(b"synthetic private reason"),
            })
        };
        let classified = [
            anyhow::Error::new(quinn::ConnectionError::TimedOut),
            anyhow::Error::new(std::io::Error::other(closed(
                quinn::TransportErrorCode::CONNECTION_REFUSED,
            )))
            .context("QUIC opening private-target.example"),
            anyhow::Error::new(ProfileCommandFailure {
                kind: "selected_relay_guard_refused",
                message: "private-fixture.example".to_string(),
            }),
            anyhow::Error::new(ProfileCommandFailure {
                kind: "profile_command_failed",
                message: "private-fixture.example".to_string(),
            }),
        ]
        .iter()
        .map(|error| anyhow_error_kind_code(error).unwrap())
        .collect::<Vec<_>>();
        assert_eq!(
            classified,
            [
                "quic_timed_out",
                "quic_connection_refused",
                "selected_relay_guard_refused",
                "profile_command_failed"
            ]
        );
        for (index, code) in classified.iter().enumerate() {
            let field = [
                "error_kind",
                "relay_error_kind",
                "session_error_kind",
                "source_error_kind",
            ][index];
            let safe = private_fields(&json!({ field: code, "target": "private-target.example" }));
            assert_eq!(
                safe,
                json!({"diagnostics": "private", field: code}),
                "{code}"
            );
        }
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::NotConnected,
            ErrorKind::AddrInUse,
            ErrorKind::AddrNotAvailable,
            ErrorKind::NetworkUnreachable,
            ErrorKind::HostUnreachable,
            ErrorKind::BrokenPipe,
            ErrorKind::AlreadyExists,
            ErrorKind::WouldBlock,
            ErrorKind::NotADirectory,
            ErrorKind::IsADirectory,
            ErrorKind::DirectoryNotEmpty,
            ErrorKind::InvalidInput,
            ErrorKind::InvalidData,
            ErrorKind::TimedOut,
            ErrorKind::WriteZero,
            ErrorKind::Interrupted,
            ErrorKind::Unsupported,
            ErrorKind::UnexpectedEof,
            ErrorKind::Other,
        ] {
            let code = crate::runtime_errors::io_error_kind_code(&std::io::Error::from(kind));
            assert_eq!(known_error_kind(code), Some(code), "{code}");
        }
        assert_eq!(known_error_kind("unclassified"), Some("unclassified"));
    }

    #[test]
    fn diagnostic_formatter_preserves_explicit_operator_details() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = bytes.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || Capture(writer.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target = "explicit-diagnostic.example", "diagnostic detail");
        });
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(output.contains("explicit-diagnostic.example"));
        assert!(output.contains("diagnostic detail"));
    }
}
