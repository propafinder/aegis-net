//! Private native JSONL import for bounded, teacher-forced recent-route replay.
//! Source identity is declared; the verified hash binds bytes, not their origin.
use aegis_core::brain::recent_routes::offline_replay::{self, Candidate, Config, Event, EventKind};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

const MAX_INPUT: usize = 4 * 1024 * 1024;
const MAX_LINE: usize = 64 * 1024;
const MAX_METADATA: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceKind {
    RetainedNativeRuntime,
    SyntheticFixture,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    schema_version: u32,
    source_sha256: String,
    source_started_unix_ms: u64,
    source_finished_unix_ms: u64,
    source_kind: SourceKind,
    #[serde(default)]
    source_commit: Option<String>,
    window_ms: u64,
    failure_cooldown_ms: u64,
    max_observations: usize,
}

#[derive(Deserialize)]
struct NativeRow {
    ts_unix_ms: u64,
    event_code: String,
    fields: Value,
}

#[derive(Deserialize)]
struct NativeCandidate {
    strategy: String,
    estimated_reward: f64,
    belief_hard_blocked: bool,
}

#[derive(Deserialize)]
struct Planner {
    target: String,
    port: u16,
    planner_retry_attempt: u64,
    planner_ranked_candidates: Vec<NativeCandidate>,
    planner_resolved_order: Vec<String>,
}

#[derive(Deserialize)]
struct Terminal {
    target: String,
    port: u16,
    strategy: String,
    signal: String,
    bytes_sent: u64,
    #[serde(default)]
    latency_ms: Option<u64>,
    retry_attempts_used: u64,
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn context(target: &str, port: u16) -> Result<String, &'static str> {
    if target.is_empty()
        || target.len() > 1024
        || target.bytes().any(|byte| byte.is_ascii_control())
        || port == 0
    {
        return Err("native replay endpoint declaration rejected");
    }
    let mut hash = Sha256::new();
    hash.update(b"aegis-private-replay-context-v1\0");
    hash.update((target.len() as u64).to_be_bytes());
    hash.update(target.as_bytes());
    hash.update(port.to_be_bytes());
    Ok(format!("{:x}", hash.finalize()))
}

/// Strict recognized fields, additive native fields ignored. Only serial direct
/// planner/success pairs are supported. Retry/failover records cannot identify
/// all attempted arms and are refused rather than imputed as failures.
pub fn report(input: &[u8], metadata: &[u8]) -> Result<Value, &'static str> {
    if input.is_empty() || input.len() > MAX_INPUT || metadata.len() > MAX_METADATA {
        return Err("native replay input budget rejected");
    }
    let meta: Metadata =
        serde_json::from_slice(metadata).map_err(|_| "native replay metadata schema rejected")?;
    let source_sha256 = format!("{:x}", Sha256::digest(input));
    if meta.schema_version != 1
        || !lower_hex(&meta.source_sha256, 64)
        || meta.source_sha256 != source_sha256
        || meta.source_started_unix_ms > meta.source_finished_unix_ms
        || meta
            .source_finished_unix_ms
            .saturating_sub(meta.source_started_unix_ms)
            > 7 * 24 * 60 * 60 * 1000
        || meta
            .source_commit
            .as_ref()
            .is_some_and(|sha| !lower_hex(sha, 40))
    {
        return Err("native replay source hash or metadata declaration rejected");
    }
    let text = std::str::from_utf8(input).map_err(|_| "native replay UTF-8 rejected")?;
    let mut events = Vec::new();
    let mut rows = 0_usize;
    let mut first = None;
    let mut last = None;
    for line in text.lines() {
        rows += 1;
        if rows > offline_replay::MAX_EVENTS || line.is_empty() || line.len() > MAX_LINE {
            return Err("native replay row budget rejected");
        }
        let row: NativeRow =
            serde_json::from_str(line).map_err(|_| "native replay row schema rejected")?;
        if !row.fields.is_object()
            || row.event_code.is_empty()
            || row.event_code.len() > 128
            || last.is_some_and(|previous| row.ts_unix_ms < previous)
        {
            return Err("native replay row chronology or fields rejected");
        }
        first.get_or_insert(row.ts_unix_ms);
        last = Some(row.ts_unix_ms);
        match row.event_code.as_str() {
            "direct_planner_order_selected" => {
                let planner: Planner = serde_json::from_value(row.fields)
                    .map_err(|_| "native planner schema rejected")?;
                if planner.planner_retry_attempt != 0 {
                    return Err("native replay cannot associate retry attempt outcomes");
                }
                if planner.planner_ranked_candidates.len() > 16
                    || planner.planner_resolved_order.len() > 16
                {
                    return Err("native planner candidate budget rejected");
                }
                let ranked = planner
                    .planner_ranked_candidates
                    .iter()
                    .map(|candidate| candidate.strategy.as_str())
                    .collect::<BTreeSet<_>>();
                let admitted = planner
                    .planner_resolved_order
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                if admitted.len() != planner.planner_resolved_order.len()
                    || ranked.len() != planner.planner_ranked_candidates.len()
                    || !admitted.is_subset(&ranked)
                {
                    return Err("native planner order membership rejected");
                }
                let context_sha256 = context(&planner.target, planner.port)?;
                let candidates = planner
                    .planner_ranked_candidates
                    .iter()
                    .map(|candidate| Candidate {
                        strategy: candidate.strategy.clone(),
                        prior: candidate.estimated_reward,
                        runtime_admitted: admitted.contains(candidate.strategy.as_str()),
                        hard_excluded: candidate.belief_hard_blocked,
                    })
                    .collect();
                events.push(Event {
                    at_unix_ms: row.ts_unix_ms,
                    context_sha256,
                    kind: EventKind::Decision { candidates },
                });
            }
            "direct_session_succeeded" => {
                let terminal: Terminal = serde_json::from_value(row.fields)
                    .map_err(|_| "native terminal schema rejected")?;
                if !matches!(terminal.signal.as_str(), "Success" | "SuccessDegraded")
                    || terminal.retry_attempts_used != 0
                {
                    return Err("native replay requires a supported terminal without retries");
                }
                events.push(Event {
                    at_unix_ms: row.ts_unix_ms,
                    context_sha256: context(&terminal.target, terminal.port)?,
                    kind: EventKind::Outcome {
                        strategy: terminal.strategy,
                        progress_reward: f64::from(terminal.bytes_sent > 0),
                        // A success with zero progress is not a declared failure.
                        cooldown_trigger: false,
                        reported_latency_ms: terminal.latency_ms,
                        reported_outgoing_bytes: terminal.bytes_sent,
                    },
                });
            }
            "direct_relay_failover_triggered"
            | "direct_terminal_fail_closed"
            | "direct_active_stall_probe_retry_selected"
            | "direct_active_stall_probe_retry_budget_exhausted"
            | "direct_active_stall_probe_launched"
            | "direct_active_stall_probe_finished" => {
                return Err("native failure/retry tape lacks attributable per-arm outcomes");
            }
            _ => {}
        }
    }
    if first != Some(meta.source_started_unix_ms) || last != Some(meta.source_finished_unix_ms) {
        return Err("native replay complete retained file interval mismatch");
    }
    let replay = offline_replay::replay(
        Config {
            window_ms: meta.window_ms,
            failure_cooldown_ms: meta.failure_cooldown_ms,
            max_observations: meta.max_observations,
        },
        &events,
    )?;
    Ok(json!({
        "artifact_schema": "aegis_native_outcome_replay_v1",
        "source": {
            "sha256": source_sha256,
            "complete_retained_file_started_unix_ms": meta.source_started_unix_ms,
            "complete_retained_file_finished_unix_ms": meta.source_finished_unix_ms,
            "kind_declared": match meta.source_kind {
                SourceKind::RetainedNativeRuntime => "retained_native_runtime",
                SourceKind::SyntheticFixture => "synthetic_fixture",
            },
            "commit_declared": meta.source_commit,
            "content_hash_verified": true,
            "runtime_origin_independently_verified": false,
            "clock_accuracy_verified": false,
            "total_native_rows": rows,
            "imported_direct_rows": events.len(),
        },
        "scope": "serial direct planner/success tape only; other events ignored; no full runtime outcome coverage",
        "native_prior_and_admission_are_logged_declarations": true,
        "replay_initial_history": "empty; pre-file native RAM history is unknown",
        "state_from_before_retained_file_available": false,
        "opaque_context_hashes_are_not_anonymization": true,
        "complete_failed_attempt_coverage": false,
        "independent_capture_confidence_or_delivery_inferred": false,
        "current_network_reachability_verified": false,
        "observed_failure_to_progress_ms": null,
        "failure_cooldown_effect": null,
        "failure_cooldown_unknown_reason": "supported native terminal rows contain no attributable failures; fixed overlay is hypothetical",
        "replay": replay,
        "installed_acceptance": false,
        "target_network_acceptance": false,
        "beta_exit": false,
    }))
}

pub fn run(input: &Path, metadata: &Path, output: &Path) -> Result<(), &'static str> {
    let private_read = |path: &Path, max: usize| {
        aegis_core::secret_file::trusted_read_parent(path)
            .map_err(|_| "native replay private input ancestry rejected")?;
        aegis_core::secret_file::read(path, max as u64)
            .map_err(|_| "native replay private input custody or budget rejected")
    };
    let input = private_read(input, MAX_INPUT)?;
    let metadata = private_read(metadata, MAX_METADATA)?;
    let report = report(&input, &metadata)?;
    aegis_core::secret_file::trusted_parent(output)
        .map_err(|_| "native replay private output ancestry rejected")?;
    let mut bytes =
        serde_json::to_vec_pretty(&report).map_err(|_| "native replay serialization rejected")?;
    bytes.push(b'\n');
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output)
            .map_err(|_| "native replay new private output rejected")?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "native replay private output write rejected")?;
    }
    #[cfg(windows)]
    aegis_core::windows_file::write_private_new(output, &bytes, false)
        .map_err(|_| "native replay new private output rejected")?;
    #[cfg(not(any(unix, windows)))]
    return Err("native replay private output unsupported on this platform");
    Ok(())
}

#[cfg(test)]
#[path = "brain_outcome_replay_tests.rs"]
mod tests;
