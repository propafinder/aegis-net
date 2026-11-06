//! Bounded, read-only public diagnostics for the installed Linux TPROXY helper.
//! The helper invokes these through the same selected client binary it runs.

use std::io::{Read, Write};
use std::path::{Component, Path};

use serde_json::{json, Value};

#[derive(clap::Args, Clone, Debug)]
pub struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand, Clone, Debug)]
enum Action {
    StartupProbeFields {
        #[arg(long)]
        stdout: std::path::PathBuf,
        #[arg(long)]
        stderr: std::path::PathBuf,
    },
    RuntimeEventsSummary {
        #[arg(long)]
        runtime_events_jsonl: std::path::PathBuf,
        #[arg(long)]
        limit: usize,
    },
    WriteOperatorEvidence(Box<EvidenceArgs>),
}

#[derive(clap::Args, Clone, Debug)]
struct EvidenceArgs {
    #[arg(long)]
    output: std::path::PathBuf,
    #[arg(long)]
    client_config: Option<String>,
    #[arg(long)]
    runtime_events_jsonl: String,
    #[arg(long)]
    events_total: u64,
    #[arg(long)]
    backend: Option<String>,
    #[arg(long)]
    backend_runtime_id: Option<String>,
    #[arg(long)]
    startup_health: String,
    #[arg(long)]
    runtime_status: String,
    #[arg(long)]
    product_verdict: String,
    #[arg(long)]
    runtime_degradation_count: u64,
    #[arg(long)]
    failover_count: u64,
    #[arg(long)]
    terminal_failure_count: u64,
    #[arg(long)]
    latest_code: Option<String>,
    #[arg(long)]
    latest_level: Option<String>,
    #[arg(long)]
    latest_message: Option<String>,
    #[arg(long)]
    problem_code: Option<String>,
    #[arg(long)]
    problem_level: Option<String>,
    #[arg(long)]
    problem_message: Option<String>,
}

pub fn run(args: &Args) -> Result<(), String> {
    match &args.action {
        Action::StartupProbeFields { stdout, stderr } => startup_probe_fields(stdout, stderr),
        Action::RuntimeEventsSummary {
            runtime_events_jsonl,
            limit,
        } => runtime_events_summary(runtime_events_jsonl, *limit),
        Action::WriteOperatorEvidence(a) => write_operator_evidence(
            &a.output,
            a.client_config.as_deref(),
            &a.runtime_events_jsonl,
            a.events_total,
            a.backend.as_deref(),
            a.backend_runtime_id.as_deref(),
            &a.startup_health,
            &a.runtime_status,
            &a.product_verdict,
            a.runtime_degradation_count,
            a.failover_count,
            a.terminal_failure_count,
            a.latest_code.as_deref(),
            a.latest_level.as_deref(),
            a.latest_message.as_deref(),
            a.problem_code.as_deref(),
            a.problem_level.as_deref(),
            a.problem_message.as_deref(),
        ),
    }
}

fn emit(key: &str, value: Option<&Value>) {
    let text = match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(boolean)) => boolean.to_string(),
        Some(Value::Null) | None => return,
        Some(other) => other.to_string(),
    };
    println!("{key}\t{}", text.replace(['\t', '\n', '\r'], " "));
}

fn emit_str(key: &str, text: &str) {
    emit(key, Some(&Value::String(text.to_owned())));
}

fn object_from_mixed_output(text: &str) -> Option<Value> {
    let trimmed = text.trim();
    let start = trimmed.find('{')?;
    let end = trimmed.rfind('}')?;
    (end > start)
        .then(|| serde_json::from_str(&trimmed[start..=end]).ok())
        .flatten()
}

fn root_invocation() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn trusted_root_parent(path: &Path) -> Result<(), String> {
    if !root_invocation() {
        return Ok(());
    }
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("root diagnostic path must be absolute without parent traversal".into());
    }
    let parent = path.parent().ok_or("root diagnostic path has no parent")?;
    let mut checked = std::path::PathBuf::new();
    for part in parent.components() {
        checked.push(part.as_os_str());
        if !matches!(part, Component::Normal(_)) {
            continue;
        }
        let meta = std::fs::symlink_metadata(&checked)
            .map_err(|_| "root diagnostic parent unavailable")?;
        if !meta.is_dir() {
            return Err("root diagnostic parent is not a directory".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != 0 || (meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0) {
                return Err("root diagnostic parent is not trusted".into());
            }
        }
    }
    Ok(())
}

fn read_trusted_text(path: &Path, max: u64) -> Result<String, String> {
    trusted_root_parent(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| "diagnostic input unavailable")?;
    let meta = file
        .metadata()
        .map_err(|_| "diagnostic input unavailable")?;
    if !meta.is_file() || meta.len() > max {
        return Err("diagnostic input exceeds limit or is not regular".into());
    }
    #[cfg(unix)]
    if root_invocation() {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.nlink() != 1 {
            return Err("root diagnostic input is not trusted".into());
        }
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "diagnostic input unavailable")?;
    if bytes.len() as u64 > max {
        return Err("diagnostic input exceeds limit".into());
    }
    String::from_utf8(bytes).map_err(|_| "diagnostic input is not UTF-8".into())
}

pub fn startup_probe_fields(stdout: &Path, stderr: &Path) -> Result<(), String> {
    let out = read_trusted_text(stdout, 1024 * 1024)?;
    let err = read_trusted_text(stderr, 1024 * 1024)?;
    if out.len() + err.len() > 1024 * 1024 {
        return Err("probe output exceeds diagnostic limit".into());
    }
    for text in [&out, &err, &format!("{out}\n{err}")] {
        let Some(report) = object_from_mixed_output(text) else {
            continue;
        };
        let Some(startup) = report.get("startup").and_then(Value::as_object) else {
            continue;
        };
        emit("PROBE_STATUS", report.get("status"));
        for (key, field) in [
            ("PROBE_CODE", "code"),
            ("PROBE_STARTED_BACKEND", "started_backend"),
            ("PROBE_FAILURE_CODE", "failure_code"),
            ("PROBE_HINT_CODE", "hint_code"),
            ("PROBE_MESSAGE", "message"),
            ("PROBE_HINT", "hint"),
            ("PROBE_DNS_STATUS", "wide_dns_capture_preview_status"),
            ("PROBE_UDP_CAPTURE_CONTRACT", "wide_udp_capture_contract"),
            (
                "PROBE_UDP_CAPTURE_SUPPORT_TIER",
                "wide_udp_capture_support_tier",
            ),
            ("PROBE_UDP_CAPTURE_POLICY", "wide_udp_capture_policy"),
            (
                "PROBE_UDP_CAPTURE_RUNTIME_SCOPE",
                "wide_udp_capture_runtime_scope",
            ),
        ] {
            emit(key, startup.get(field));
        }
        return Ok(());
    }
    Err("missing startup probe JSON".into())
}

fn events(path: &Path) -> Result<Vec<Value>, String> {
    let text = read_trusted_text(path, 32 * 1024 * 1024)?;
    let mut parsed = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let value: Value =
            serde_json::from_str(line).map_err(|_| "malformed runtime event JSONL")?;
        if !value.is_object() {
            return Err("runtime event must be a JSON object".into());
        }
        let level = value
            .get("level")
            .and_then(Value::as_str)
            .ok_or("runtime event level unavailable or invalid")?;
        if !["trace", "debug", "info", "warn", "error"]
            .iter()
            .any(|known| level.eq_ignore_ascii_case(known))
        {
            return Err("runtime event level unavailable or invalid".into());
        }
        parsed.push(value);
    }
    Ok(parsed)
}

fn has(records: &[Value], code: &str) -> bool {
    records
        .iter()
        .any(|r| r.get("event_code").and_then(Value::as_str) == Some(code))
}

fn count(records: &[Value], codes: &[&str]) -> usize {
    records
        .iter()
        .filter(|r| {
            r.get("event_code")
                .and_then(Value::as_str)
                .is_some_and(|c| codes.contains(&c))
        })
        .count()
}

fn record_level_is(record: &Value, level: &str) -> bool {
    record
        .get("level")
        .and_then(Value::as_str)
        .is_some_and(|actual| actual.eq_ignore_ascii_case(level))
}

pub fn runtime_events_summary(path: &Path, limit: usize) -> Result<(), String> {
    if !(1..=4096).contains(&limit) {
        return Err("runtime event limit must be 1..4096".into());
    }
    let records = events(path)?;
    emit_str("EVENTS_TOTAL", &records.len().to_string());
    let Some(latest) = records.last() else {
        return Ok(());
    };
    for (key, field) in [
        ("EVENTS_LATEST_CODE", "event_code"),
        ("EVENTS_LATEST_LEVEL", "level"),
        ("EVENTS_LATEST_MESSAGE", "message"),
    ] {
        emit(key, latest.get(field));
    }
    let backend = records
        .iter()
        .rev()
        .find(|r| r.get("event_code").and_then(Value::as_str) == Some("ingress_backend_started"));
    if let Some(fields) = backend
        .and_then(|r| r.get("fields"))
        .and_then(Value::as_object)
    {
        for (key, field) in [
            ("EVENTS_BACKEND", "backend"),
            ("EVENTS_BACKEND_RUNTIME_ID", "backend_runtime_id"),
            (
                "EVENTS_BACKEND_DNS_STATUS",
                "wide_dns_capture_preview_status",
            ),
            (
                "EVENTS_BACKEND_UDP_CAPTURE_CONTRACT",
                "wide_udp_capture_contract",
            ),
            (
                "EVENTS_BACKEND_UDP_CAPTURE_SUPPORT_TIER",
                "wide_udp_capture_support_tier",
            ),
            (
                "EVENTS_BACKEND_UDP_CAPTURE_POLICY",
                "wide_udp_capture_policy",
            ),
            (
                "EVENTS_BACKEND_UDP_CAPTURE_RUNTIME_SCOPE",
                "wide_udp_capture_runtime_scope",
            ),
        ] {
            emit(key, fields.get(field));
        }
    }
    let startup = if has(&records, "ingress_startup_selection_failed") {
        "failed"
    } else if has(&records, "ingress_wide_bind_fallback") {
        "degraded_fallback"
    } else if backend.is_some() {
        "healthy"
    } else {
        "unknown"
    };
    emit_str("EVENTS_STARTUP_HEALTH", startup);
    let degradation = count(
        &records,
        &[
            "ingress_udp_datagram_dropped",
            "direct_active_stall_probe_retry_selected",
            "relay_transport_failed",
        ],
    );
    let failover = count(&records, &["direct_relay_failover_triggered"]);
    let terminal = count(
        &records,
        &["ingress_session_failed", "ingress_session_broker_failed"],
    );
    // A newly added or otherwise unclassified warn/error event must never
    // disappear from the release verdict merely because it fell outside the
    // operator's recent-detail window. The limit controls detail, not health.
    let any_warning = records.iter().any(|r| record_level_is(r, "warn"));
    let any_error = records.iter().any(|r| record_level_is(r, "error"));
    emit_str("EVENTS_RUNTIME_DEGRADATION_COUNT", &degradation.to_string());
    emit_str("EVENTS_FAILOVER_COUNT", &failover.to_string());
    emit_str("EVENTS_TERMINAL_FAILURE_COUNT", &terminal.to_string());
    let runtime = if terminal > 0 {
        "terminal_failure_seen"
    } else if failover > 0 {
        "degraded_failover_seen"
    } else if degradation > 0 || any_warning || any_error {
        "degraded_runtime_seen"
    } else {
        "healthy"
    };
    emit_str("EVENTS_RUNTIME_STATUS", runtime);
    emit_str(
        "EVENTS_PRODUCT_VERDICT",
        if terminal > 0 || any_error || matches!(startup, "failed" | "unknown") {
            "red"
        } else if failover > 0 || degradation > 0 || any_warning || startup != "healthy" {
            "degraded"
        } else {
            "green"
        },
    );
    let problems = [
        "ingress_startup_selection_failed",
        "ingress_wide_bind_fallback",
        "ingress_accept_failed",
        "ingress_session_failed",
        "ingress_session_broker_failed",
        "relay_transport_failed",
        "ingress_udp_datagram_dropped",
    ];
    let start = records.len().saturating_sub(limit);
    let problem = records[start..].iter().rev().find(|r| {
        r.get("event_code")
            .and_then(Value::as_str)
            .is_some_and(|c| problems.contains(&c))
            || record_level_is(r, "warn")
            || record_level_is(r, "error")
    });
    if let Some(problem) = problem {
        for (key, field) in [
            ("EVENTS_PROBLEM_CODE", "event_code"),
            ("EVENTS_PROBLEM_LEVEL", "level"),
            ("EVENTS_PROBLEM_MESSAGE", "message"),
        ] {
            emit(key, problem.get(field));
        }
        let fields = problem.get("fields").and_then(Value::as_object);
        for (key, field) in [
            ("EVENTS_PROBLEM_BIND_ERROR_CODE", "bind_error_code"),
            ("EVENTS_PROBLEM_BIND_HINT_CODE", "bind_hint_code"),
            (
                "EVENTS_PROBLEM_SELECTION_ERROR_CODE",
                "selection_error_code",
            ),
            ("EVENTS_PROBLEM_SELECTION_HINT_CODE", "selection_hint_code"),
            ("EVENTS_PROBLEM_DROP_REASON_CODE", "drop_reason_code"),
            (
                "EVENTS_PROBLEM_CAPTURE_DROP_STAGE",
                "wide_udp_capture_drop_stage",
            ),
            (
                "EVENTS_PROBLEM_CAPTURE_DROP_REASON_CODE",
                "wide_udp_capture_drop_reason_code",
            ),
            (
                "EVENTS_PROBLEM_UDP_CAPTURE_CONTRACT",
                "wide_udp_capture_contract",
            ),
            (
                "EVENTS_PROBLEM_UDP_CAPTURE_SUPPORT_TIER",
                "wide_udp_capture_support_tier",
            ),
            (
                "EVENTS_PROBLEM_UDP_CAPTURE_POLICY",
                "wide_udp_capture_policy",
            ),
            (
                "EVENTS_PROBLEM_UDP_CAPTURE_RUNTIME_SCOPE",
                "wide_udp_capture_runtime_scope",
            ),
            (
                "EVENTS_PROBLEM_UDP_PREVIEW_POLICY",
                "wide_udp_preview_policy",
            ),
            ("EVENTS_PROBLEM_HINT", "hint"),
            ("EVENTS_PROBLEM_TRANSPORT", "transport"),
            ("EVENTS_PROBLEM_RELAY_SERVER", "relay_server"),
            ("EVENTS_PROBLEM_RELAY_ERROR_KIND", "relay_error_kind"),
            ("EVENTS_PROBLEM_SESSION_ERROR_KIND", "session_error_kind"),
            ("EVENTS_PROBLEM_ERROR", "error"),
            ("EVENTS_PROBLEM_BACKEND", "backend"),
            (
                "EVENTS_PROBLEM_RELAY_LAST_TRANSPORT",
                "relay_last_transport",
            ),
            ("EVENTS_PROBLEM_ATTEMPT_INDEX", "attempt_index"),
            ("EVENTS_PROBLEM_ATTEMPTS_TOTAL", "attempts_total"),
            ("EVENTS_PROBLEM_EXPECTED_DNS_PORT", "expected_dns_port"),
            (
                "EVENTS_PROBLEM_EXPECTED_UDP_PREVIEW_PORTS",
                "expected_udp_preview_ports",
            ),
        ] {
            emit(key, fields.and_then(|f| f.get(field)));
        }
    }
    Ok(())
}

fn null_if_empty(value: Option<&str>) -> Value {
    value
        .filter(|s| !s.is_empty())
        .map_or(Value::Null, |s| Value::String(s.into()))
}

#[allow(clippy::too_many_arguments)]
pub fn write_operator_evidence(
    output: &Path,
    client_config: Option<&str>,
    runtime_events_jsonl: &str,
    events_total: u64,
    backend: Option<&str>,
    backend_runtime_id: Option<&str>,
    startup_health: &str,
    runtime_status: &str,
    product_verdict: &str,
    runtime_degradation_count: u64,
    failover_count: u64,
    terminal_failure_count: u64,
    latest_code: Option<&str>,
    latest_level: Option<&str>,
    latest_message: Option<&str>,
    problem_code: Option<&str>,
    problem_level: Option<&str>,
    problem_message: Option<&str>,
) -> Result<(), String> {
    let payload = json!({
        "artifact_schema": "wide_linux_operator_evidence_v1",
        "helper_action": "events",
        "client_config": null_if_empty(client_config),
        "runtime_events_jsonl": runtime_events_jsonl,
        "records_scanned": events_total,
        "backend": null_if_empty(backend),
        "backend_runtime_id": null_if_empty(backend_runtime_id),
        "startup_health": startup_health,
        "runtime_status": runtime_status,
        "product_verdict": product_verdict,
        "runtime_degradation_count": runtime_degradation_count,
        "failover_count": failover_count,
        "terminal_failure_count": terminal_failure_count,
        "latest_event": {"code": null_if_empty(latest_code), "level": null_if_empty(latest_level), "message": null_if_empty(latest_message)},
        "latest_problem_event": {"code": null_if_empty(problem_code), "level": null_if_empty(problem_level), "message": null_if_empty(problem_message)},
        "canonical_operator_loop": ["doctor", "probe", "launch_or_run", "events", "evidence"],
    });
    let parent = output.parent().ok_or("evidence output has no parent")?;
    if !root_invocation() {
        std::fs::create_dir_all(parent).map_err(|_| "evidence directory unavailable")?;
    }
    trusted_root_parent(output)?;
    let mut staged =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "evidence staging failed")?;
    staged
        .write_all(
            format!(
                "{}\n",
                serde_json::to_string_pretty(&payload)
                    .map_err(|_| "evidence serialization failed")?
            )
            .as_bytes(),
        )
        .map_err(|_| "evidence write failed")?;
    staged
        .as_file()
        .sync_all()
        .map_err(|_| "evidence sync failed")?;
    staged
        .persist(output)
        .map_err(|_| "evidence publish failed")?;
    Ok(())
}
