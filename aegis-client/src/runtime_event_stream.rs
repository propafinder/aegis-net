use crate::runtime_events::RuntimeEventCode;
use aegis_core::{ExternalCalibrationSnapshot, ExternalKnowledgePrior};
use serde::Serialize;
use serde_json::{json, Value};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static GLOBAL_STREAM: OnceLock<Option<RuntimeEventStream>> = OnceLock::new();

pub mod privacy;
pub use privacy::PrivateEventFormat;

// Detailed diagnostics require an explicit command-line opt-in. Forensic mode
// is a separate stronger policy: it also disables persistent events and state.
static PRIVATE_LOGS: AtomicBool = AtomicBool::new(true);

pub fn set_private_logs(on: bool) {
    PRIVATE_LOGS.store(on, Ordering::Relaxed);
}

pub fn private_logs_enabled() -> bool {
    PRIVATE_LOGS.load(Ordering::Relaxed) || forensic_redact_enabled()
}

// Stronger policy: private structured diagnostics plus no new persistent
// runtime events or Brain state. Does not erase existing logs or state.
static FORENSIC_REDACT: AtomicBool = AtomicBool::new(false);

pub fn set_forensic_redact(on: bool) {
    FORENSIC_REDACT.store(on, Ordering::Relaxed);
}

/// Audit F4: other subsystems (the Brain state store) consult this to also go
/// RAM-only on seizable hosts, so no persistent activity trail is left.
pub fn forensic_redact_enabled() -> bool {
    FORENSIC_REDACT.load(Ordering::Relaxed)
}

pub struct RuntimeEventStream {
    file: Mutex<File>,
}

#[derive(Debug, Serialize)]
struct JsonRuntimeEvent {
    ts_unix_ms: u128,
    level: &'static str,
    event_code: &'static str,
    message: &'static str,
    fields: Value,
}

impl RuntimeEventStream {
    // Unused in a forensic-safe build (the sink is never constructed there).
    #[cfg_attr(forensic_safe, allow(dead_code))]
    pub fn new(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let parent_existed = parent.exists();
                create_dir_all(parent)?;
                #[cfg(unix)]
                if !parent_existed {
                    use std::os::unix::fs::PermissionsExt;
                    // The supplied sink can live in an existing shared
                    // directory, including /dev. Change only a new log dir.
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
                }
                #[cfg(not(unix))]
                let _ = parent_existed;
            }
        }
        // v0.3.0: enforce 0o600 on the JSONL file so other UIDs cannot
        // read runtime events (which can contain peer addresses, target
        // hostnames, and other operationally sensitive metadata).
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path)?;
        #[cfg(unix)]
        if file.metadata()?.is_file() {
            use std::os::unix::fs::PermissionsExt;
            // OpenOptions::mode only applies on creation. Tighten existing
            // regular logs too, before the first event is written. Leave
            // special sinks such as /dev/null unchanged.
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    fn emit(
        &self,
        level: &'static str,
        code: RuntimeEventCode,
        message: &'static str,
        fields: Value,
    ) {
        self.emit_raw(level, code.as_str(), message, fields);
    }

    fn emit_raw(
        &self,
        level: &'static str,
        event_code: &'static str,
        message: &'static str,
        fields: Value,
    ) {
        let event = JsonRuntimeEvent {
            ts_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            level,
            event_code,
            message,
            fields,
        };
        let Ok(line) = serde_json::to_vec(&event) else {
            return;
        };
        let Ok(mut file) = self.file.lock() else {
            return;
        };
        let _ = file.write_all(&line);
        let _ = file.write_all(b"\n");
        let _ = file.flush();
    }

    #[allow(dead_code)]
    fn emit_external_calibration_applied(&self, snapshot: &ExternalCalibrationSnapshot) {
        self.emit(
            "info",
            RuntimeEventCode::ExternalCalibrationApplied,
            "external calibration applied",
            json!({
                "schema_version": snapshot.schema_version,
                "source": snapshot.source,
                "generated_at_unix_ms": snapshot.generated_at_unix_ms,
                "freshness_half_life_secs": snapshot.freshness_half_life_secs,
                "witness_label_count": snapshot.witness.len(),
                "adversarial_transport_count": snapshot.adversarial.len(),
                "knowledge_prior_count": snapshot.knowledge.len(),
                "verdict_status": snapshot.verdict.status,
                "acceptance_degraded": snapshot.verdict.acceptance_degraded,
                "reason_count": snapshot.verdict.reasons.len()
            }),
        );
    }

    #[allow(dead_code)]
    fn emit_knowledge_prior_applied(&self, prior: &ExternalKnowledgePrior) {
        self.emit(
            "info",
            RuntimeEventCode::KnowledgePriorApplied,
            "knowledge prior applied",
            json!({
                "target_class": prior.target_class,
                "region_id": prior.region_id,
                "score": prior.score,
                "confidence": prior.confidence,
                "hard_excluded": prior.hard_excluded,
                "fail_closed": prior.fail_closed,
                "generated_at_unix_ms": prior.generated_at_unix_ms
            }),
        );
    }
}

pub fn init(path: Option<PathBuf>) -> io::Result<()> {
    // Forensic-safe build profile: this initialization path ignores the
    // requested path and leaves the global stream None, so global emit() is a
    // no-op. The cfg does not remove all sink implementation from the binary
    // or erase previous files, OS logs, or other persisted application state.
    // The --no-runtime-events flag is the separate runtime opt-out.
    #[cfg(forensic_safe)]
    let stream: Option<RuntimeEventStream> = {
        let _ = path;
        None
    };
    #[cfg(not(forensic_safe))]
    let stream = if forensic_redact_enabled() {
        None
    } else {
        path.map(|path| RuntimeEventStream::new(&path))
            .transpose()?
    };
    let _ = GLOBAL_STREAM.set(stream);
    Ok(())
}

pub fn emit(level: &'static str, code: RuntimeEventCode, message: &'static str, mut fields: Value) {
    if forensic_redact_enabled() {
        return;
    }
    let private = private_logs_enabled();
    if private {
        fields = privacy::private_fields(&fields);
    }
    if let Some(stream) = GLOBAL_STREAM.get().and_then(Option::as_ref) {
        // Best-effort JSONL sink for machine-readable runtime automation.
        let message = if private { code.as_str() } else { message };
        stream.emit(level, code, message, fields);
    }
}

#[allow(dead_code)]
pub fn emit_external_calibration_applied(snapshot: &ExternalCalibrationSnapshot) {
    if private_logs_enabled() {
        return;
    }
    if let Some(stream) = GLOBAL_STREAM.get().and_then(Option::as_ref) {
        stream.emit_external_calibration_applied(snapshot);
    }
}

#[allow(dead_code)]
pub fn emit_knowledge_prior_applied(prior: &ExternalKnowledgePrior) {
    if private_logs_enabled() {
        return;
    }
    if let Some(stream) = GLOBAL_STREAM.get().and_then(Option::as_ref) {
        stream.emit_knowledge_prior_applied(prior);
    }
}

// Shared API: binary test cfg does not propagate into its library dependency.
// The existing forensic/private filters below apply on every target.
pub fn emit_raw(
    level: &'static str,
    event_code: &'static str,
    message: &'static str,
    fields: Value,
) {
    if forensic_redact_enabled() {
        return;
    }
    if let Some(stream) = GLOBAL_STREAM.get().and_then(Option::as_ref) {
        if private_logs_enabled() {
            // Windows-only event strings are not all members of the typed
            // registry yet. Keep the event coarse until they are registered.
            let event_code = privacy::known_event_code(event_code).unwrap_or("runtime_event");
            stream.emit_raw(
                level,
                event_code,
                event_code,
                privacy::private_fields(&fields),
            );
        } else {
            stream.emit_raw(level, event_code, message, fields);
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, forensic_safe))]
mod forensic_build_tests;
