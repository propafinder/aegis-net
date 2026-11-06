//! Phase 3 KPI summary generator.
//!
//! Computes the practical KPI set the AEGIS master plan tracks for release
//! readiness, from inputs that do NOT require live VPS captures (a state.json
//! snapshot, a runtime-events JSONL, and a static bootstrap script). KPIs
//! that genuinely require live captures (`witness_indistinguishability_score`,
//! `adversarial_evasion_pass_rate`, `active_probe_resistance_score`) are
//! emitted with status `DEFERRED_PHASE_4` and a pointer to the historical
//! witness-matrix artifact for the current best-known value.
//!
//! This module deliberately produces **measured numbers only when the input
//! actually supports them**, and reports `INSUFFICIENT_EVIDENCE` otherwise.
//! No fake claims, no synthesised scores, no fabricated PASS verdicts.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

/// Acceptance targets per the AEGIS master plan (Phase 3 section).
const TARGET_WITNESS_INDISTINGUISHABILITY: f64 = 0.70;
const TARGET_ADVERSARIAL_EVASION_PASS_RATE: f64 = 0.85;
const TARGET_ACTIVE_PROBE_RESISTANCE: f64 = 0.80;
const TARGET_TRANSPORT_SURVIVAL_RATE: f64 = 0.90;
const TARGET_RELAY_FAILOVER_RECOVERY_MEDIAN_MS: u64 = 30_000;
const TARGET_RELAY_FAILOVER_RECOVERY_P95_MS: u64 = 120_000;
const TARGET_BOOTSTRAP_SURVIVAL_UNDER_BLOCK: f64 = 0.95;

#[derive(Debug, Clone)]
pub struct Phase3KpiInputs<'a> {
    pub state_json: Option<&'a Path>,
    pub runtime_events_jsonl: &'a [&'a Path],
    pub bootstrap_script: &'a Path,
    /// Optional artifact from a real blocked-primary-host install run:
    /// `{ "attempts": N, "successes": M }`. Without it the bootstrap-survival
    /// KPI reports INSUFFICIENT_EVIDENCE rather than inventing a rate.
    pub bootstrap_survival_trials: Option<&'a Path>,
    pub historical_witness_matrix: Option<&'a Path>,
}

pub fn compute(inputs: Phase3KpiInputs<'_>) -> Result<Value, Box<dyn std::error::Error>> {
    let transport_survival = transport_survival_rate(inputs.state_json)?;
    let failover_recovery = relay_failover_recovery_time(inputs.runtime_events_jsonl)?;
    let bootstrap_survival =
        bootstrap_survival_audit(inputs.bootstrap_script, inputs.bootstrap_survival_trials)?;
    let witness_score = historical_witness_score(inputs.historical_witness_matrix)?;
    let adversarial = deferred_kpi(
        "adversarial_evasion_pass_rate",
        TARGET_ADVERSARIAL_EVASION_PASS_RATE,
        "requires_live_adversarial_runner_against_test_vps_phase_4",
    );
    let active_probe = deferred_kpi(
        "active_probe_resistance_score",
        TARGET_ACTIVE_PROBE_RESISTANCE,
        "requires_adversarial_event_corpus_from_live_runs_phase_4",
    );

    let kpis = json!({
        "witness_indistinguishability_score": witness_score,
        "adversarial_evasion_pass_rate": adversarial,
        "active_probe_resistance_score": active_probe,
        "transport_survival_rate": transport_survival,
        "relay_failover_recovery_time": failover_recovery,
        "bootstrap_survival_under_block": bootstrap_survival,
    });

    Ok(json!({
        "artifact": "phase3-kpi-summary",
        "artifact_schema": "phase3_kpi_summary_v1",
        "completion_claim_allowed": false,
        "full_aegis_completion_claimed": false,
        "scope": "computed_from_local_inputs_only_no_live_vps_capture",
        "targets": {
            "witness_indistinguishability_score": TARGET_WITNESS_INDISTINGUISHABILITY,
            "adversarial_evasion_pass_rate": TARGET_ADVERSARIAL_EVASION_PASS_RATE,
            "active_probe_resistance_score": TARGET_ACTIVE_PROBE_RESISTANCE,
            "transport_survival_rate": TARGET_TRANSPORT_SURVIVAL_RATE,
            "relay_failover_recovery_time_median_ms_max": TARGET_RELAY_FAILOVER_RECOVERY_MEDIAN_MS,
            "relay_failover_recovery_time_p95_ms_max": TARGET_RELAY_FAILOVER_RECOVERY_P95_MS,
            "bootstrap_survival_under_block": TARGET_BOOTSTRAP_SURVIVAL_UNDER_BLOCK,
        },
        "kpis": kpis,
    }))
}

/// `transport_survival_rate` per `StrategyStatsV2`: (successes + degraded) /
/// trials. Aggregated across all strategies in `state.json`.
fn transport_survival_rate(state_json: Option<&Path>) -> Result<Value, Box<dyn std::error::Error>> {
    let Some(path) = state_json else {
        return Ok(insufficient_evidence_kpi(
            TARGET_TRANSPORT_SURVIVAL_RATE,
            "no_state_json_supplied",
        ));
    };
    if !path.exists() {
        return Ok(insufficient_evidence_kpi(
            TARGET_TRANSPORT_SURVIVAL_RATE,
            "state_json_path_does_not_exist",
        ));
    }
    let raw = std::fs::read_to_string(path)?;
    let state: Value = serde_json::from_str(&raw)?;
    let mut per_strategy = BTreeMap::new();
    let mut total_trials: u64 = 0;
    let mut total_pass: u64 = 0;
    if let Some(strategies) = state.pointer("/strategies").and_then(Value::as_object) {
        for (key, stats) in strategies {
            let trials = stats.get("trials").and_then(Value::as_u64).unwrap_or(0);
            let successes = stats.get("successes").and_then(Value::as_u64).unwrap_or(0);
            let degraded = stats.get("degraded").and_then(Value::as_u64).unwrap_or(0);
            let pass = successes.saturating_add(degraded);
            total_trials = total_trials.saturating_add(trials);
            total_pass = total_pass.saturating_add(pass);
            let rate = if trials > 0 {
                Some(pass as f64 / trials as f64)
            } else {
                None
            };
            per_strategy.insert(
                key.clone(),
                json!({
                    "trials": trials,
                    "pass": pass,
                    "rate": rate,
                }),
            );
        }
    }
    if total_trials == 0 {
        return Ok(json!({
            "status": "INSUFFICIENT_EVIDENCE",
            "reason": "state_json_present_but_no_strategy_trials_recorded",
            "target": TARGET_TRANSPORT_SURVIVAL_RATE,
            "per_strategy": per_strategy,
        }));
    }
    let aggregate = total_pass as f64 / total_trials as f64;
    let status = if aggregate >= TARGET_TRANSPORT_SURVIVAL_RATE {
        "PASS"
    } else {
        "BELOW_TARGET"
    };
    Ok(json!({
        "status": status,
        "value": aggregate,
        "target": TARGET_TRANSPORT_SURVIVAL_RATE,
        "trials_total": total_trials,
        "pass_total": total_pass,
        "per_strategy": per_strategy,
    }))
}

/// `relay_failover_recovery_time` median + p95 from runtime events JSONL.
/// Pairs each `relay_transport_failed` (real failure scope only) with the
/// nearest subsequent `relay_session_succeeded` and reports the time delta.
fn relay_failover_recovery_time(
    jsonl_paths: &[&Path],
) -> Result<Value, Box<dyn std::error::Error>> {
    if jsonl_paths.is_empty() {
        return Ok(insufficient_evidence_recovery_kpi(
            "no_runtime_events_jsonl_supplied",
        ));
    }
    let mut deltas_ms: Vec<u64> = Vec::new();
    let mut total_recovery_pairs = 0usize;
    for path in jsonl_paths {
        if !path.exists() {
            continue;
        }
        let raw = std::fs::read_to_string(path)?;
        let mut last_real_fail_ms: Option<u64> = None;
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let record: Value = match serde_json::from_str(line) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let event_code = record
                .get("event_code")
                .and_then(Value::as_str)
                .unwrap_or("");
            let ts_ms = record
                .pointer("/ts_unix_ms")
                .and_then(Value::as_u64)
                .or_else(|| record.pointer("/timestamp_unix_ms").and_then(Value::as_u64))
                .or_else(|| record.pointer("/ts_ms").and_then(Value::as_u64));
            let Some(ts_ms) = ts_ms else {
                continue;
            };
            match event_code {
                "relay_transport_failed" => {
                    let scope = record
                        .pointer("/fields/relay_failure_scope")
                        .and_then(Value::as_str)
                        .or_else(|| {
                            record
                                .pointer("/fields/failure_scope")
                                .and_then(Value::as_str)
                        })
                        .unwrap_or("");
                    if scope == "real_transport_outage" {
                        last_real_fail_ms = Some(ts_ms);
                    }
                }
                "relay_session_succeeded" => {
                    if let Some(fail_ms) = last_real_fail_ms.take() {
                        if ts_ms >= fail_ms {
                            deltas_ms.push(ts_ms - fail_ms);
                            total_recovery_pairs += 1;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if deltas_ms.is_empty() {
        return Ok(insufficient_evidence_recovery_kpi(
            "no_real_failure_to_success_pairs_observed_in_supplied_runtime_events",
        ));
    }
    deltas_ms.sort_unstable();
    let median = percentile(&deltas_ms, 50.0);
    let p95 = percentile(&deltas_ms, 95.0);
    let status = if median <= TARGET_RELAY_FAILOVER_RECOVERY_MEDIAN_MS
        && p95 <= TARGET_RELAY_FAILOVER_RECOVERY_P95_MS
    {
        "PASS"
    } else {
        "BELOW_TARGET"
    };
    Ok(json!({
        "status": status,
        "median_ms": median,
        "p95_ms": p95,
        "target_median_ms_max": TARGET_RELAY_FAILOVER_RECOVERY_MEDIAN_MS,
        "target_p95_ms_max": TARGET_RELAY_FAILOVER_RECOVERY_P95_MS,
        "sample_count": total_recovery_pairs,
    }))
}

/// `bootstrap_survival_under_block`: the share of installs that still succeed
/// when the primary bundle host is blocked.
///
/// That is a **rate**, and a rate can only come from trials. This used to
/// grep the installer for the strings `AEGIS_INSTALL_MIRRORS` / `VOUCHER` and,
/// if either appeared anywhere in the file, emit `value: 1.0` and `PASS`
/// against a 0.95 target — a 100% survival claim derived from the presence of
/// a word in a shell script, with no install attempted and no host blocked.
/// The module header promises "no synthesised scores, no fabricated PASS
/// verdicts"; this is now enforced rather than asserted.
///
/// The static audit is still useful, but only as what it is: a **capability**
/// check that the installer *has* an automatic fallback path. It can never
/// produce a `value` or a `PASS` on its own. A measured rate requires
/// `trials`, a JSON artifact from a real blocked-host run:
///
/// ```json
/// { "attempts": 20, "successes": 19 }
/// ```
fn bootstrap_survival_audit(
    script: &Path,
    trials: Option<&Path>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let capability = bootstrap_fallback_capability(script)?;
    let measured = bootstrap_survival_measurement(trials)?;

    // Only a real trial set can produce a value or a verdict.
    let Some((attempts, successes)) = measured else {
        return Ok(json!({
            "status": "INSUFFICIENT_EVIDENCE",
            "value": Value::Null,
            "target": TARGET_BOOTSTRAP_SURVIVAL_UNDER_BLOCK,
            "reason": if trials.is_some() {
                "trials_artifact_unreadable_or_missing_attempts_successes"
            } else {
                "no_blocked_host_trial_artifact_supplied"
            },
            "measurement_required": "run installs with the primary bundle host blocked and record {\"attempts\":N,\"successes\":M}",
            "static_capability_audit": capability,
        }));
    };

    let value = if attempts == 0 {
        0.0
    } else {
        successes as f64 / attempts as f64
    };
    let status = if attempts == 0 {
        "INSUFFICIENT_EVIDENCE"
    } else if value >= TARGET_BOOTSTRAP_SURVIVAL_UNDER_BLOCK {
        "PASS"
    } else {
        "FAIL"
    };
    Ok(json!({
        "status": status,
        "value": value,
        "target": TARGET_BOOTSTRAP_SURVIVAL_UNDER_BLOCK,
        "attempts": attempts,
        "successes": successes,
        "static_capability_audit": capability,
    }))
}

/// Read `{ "attempts": N, "successes": M }` from a trial artifact.
/// Returns `None` when no usable measurement is present — never a default.
fn bootstrap_survival_measurement(
    trials: Option<&Path>,
) -> Result<Option<(u64, u64)>, Box<dyn std::error::Error>> {
    let Some(path) = trials else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let parsed: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let attempts = parsed["attempts"].as_u64();
    let successes = parsed["successes"].as_u64();
    match (attempts, successes) {
        // A trial set claiming more successes than attempts is corrupt, not a
        // 100%+ pass; refuse it rather than clamping it into a green number.
        (Some(a), Some(s)) if s <= a => Ok(Some((a, s))),
        _ => Ok(None),
    }
}

/// Does the installer have an automatic fallback at all? Capability only —
/// deliberately cannot yield a survival rate.
fn bootstrap_fallback_capability(script: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    if !script.exists() {
        return Ok(json!({
            "status": "INSUFFICIENT_EVIDENCE",
            "reason": "bootstrap_script_path_does_not_exist",
        }));
    }
    let body = std::fs::read_to_string(script)?;
    // Count distinct fallback URL sources. We recognise:
    //   * AEGIS_INSTALL_MIRRORS env var (comma-separated list)
    //   * AEGIS_INSTALL_MANIFEST_URL_FALLBACK*
    //   * VOUCHER_* env vars
    // Tor is intentionally NOT a fallback channel — it is DPI-classified on
    // sight and RU blocks exit nodes, so it fails exactly where RKN users need
    // it. Bootstrap survival credits signed mirrors and the voucher flow only.
    let mirrors_supported = body.contains("AEGIS_INSTALL_MIRRORS")
        || body.contains("MANIFEST_URL_FALLBACK")
        || body.contains("MIRROR_URLS");
    let voucher_supported = body.contains("VOUCHER")
        || body.contains("voucher_token")
        || body.contains("signed_manifest_voucher");
    // The script always supports an operator-supplied --manifest-url
    // override; that is NOT automatic survival. Mark explicitly.
    let operator_override_only = body.contains("AEGIS_INSTALL_MANIFEST_URL");
    let supported_fallback_count = [mirrors_supported, voucher_supported]
        .iter()
        .filter(|present| **present)
        .count();
    // Capability only: "the installer has an automatic fallback path" is a
    // precondition for surviving a blocked host, not evidence that it does.
    // No `value`, no PASS — those belong to the measured rate above.
    Ok(json!({
        "automatic_fallback_sources_present": supported_fallback_count,
        "mirrors_supported": mirrors_supported,
        "voucher_supported": voucher_supported,
        "operator_override_available_but_not_automatic": operator_override_only,
        "capability": if supported_fallback_count == 0 {
            "no_automatic_fallback_single_manifest_url"
        } else {
            "automatic_fallback_present"
        },
    }))
}

/// Extract historical witness scores from a prior witness-matrix
/// `result.json`. Marks the result as `HISTORICAL_BEFORE_PHASE_2_MORPHOLOGY`
/// so reviewers know the Phase 2 catalog/sampling changes have NOT been
/// re-measured. Phase 4 will refresh.
fn historical_witness_score(
    matrix_result: Option<&Path>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let Some(path) = matrix_result else {
        return Ok(deferred_kpi(
            "witness_indistinguishability_score",
            TARGET_WITNESS_INDISTINGUISHABILITY,
            "no_historical_witness_matrix_supplied_and_phase_2_morphology_changed_wire_shape_so_old_score_would_be_stale_anyway",
        ));
    };
    if !path.exists() {
        return Ok(deferred_kpi(
            "witness_indistinguishability_score",
            TARGET_WITNESS_INDISTINGUISHABILITY,
            "historical_witness_matrix_path_does_not_exist",
        ));
    }
    let raw = std::fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&raw)?;
    // The witness-matrix schema places per-cell scores under deeply nested
    // objects (one entry per transport / netem_profile). Walk the JSON tree
    // and collect every `witness_indistinguishability_score` field; report
    // count + min + mean + max so reviewers see the actual sample shape.
    let mut scores: Vec<f64> = Vec::new();
    let mut unscored_cells = 0_u64;
    collect_witness_scores(&value, &mut scores, &mut unscored_cells);
    let summary = if scores.is_empty() {
        Value::Null
    } else {
        let sum: f64 = scores.iter().copied().sum();
        let mean = sum / scores.len() as f64;
        let min = scores.iter().copied().fold(f64::INFINITY, f64::min);
        let max = scores.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        json!({
            "cell_count": scores.len(),
            // Cells whose score is null: no reference comparison was possible.
            // Reported so a matrix of unscorable cells cannot read as a small
            // clean sample.
            "unscored_cell_count": unscored_cells,
            "min": min,
            "mean": mean,
            "max": max,
        })
    };
    Ok(json!({
        "status": "HISTORICAL_BEFORE_PHASE_2_MORPHOLOGY",
        "target": TARGET_WITNESS_INDISTINGUISHABILITY,
        "historical_score_distribution": summary,
        "historical_source": path.display().to_string(),
        "reason_for_deferral": "phase_2_changed_relay_morphology_so_pre_phase_2_witness_scores_are_stale_phase_4_must_recapture",
    }))
}

fn collect_witness_scores(value: &Value, out: &mut Vec<f64>, unscored: &mut u64) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "witness_indistinguishability_score" {
                    match child.as_f64() {
                        Some(score) => out.push(score),
                        None => *unscored += 1,
                    }
                } else {
                    collect_witness_scores(child, out, unscored);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_witness_scores(item, out, unscored);
            }
        }
        _ => {}
    }
}

fn insufficient_evidence_kpi(target: f64, reason: &str) -> Value {
    json!({
        "status": "INSUFFICIENT_EVIDENCE",
        "target": target,
        "reason": reason,
    })
}

fn insufficient_evidence_recovery_kpi(reason: &str) -> Value {
    json!({
        "status": "INSUFFICIENT_EVIDENCE",
        "target_median_ms_max": TARGET_RELAY_FAILOVER_RECOVERY_MEDIAN_MS,
        "target_p95_ms_max": TARGET_RELAY_FAILOVER_RECOVERY_P95_MS,
        "reason": reason,
    })
}

fn deferred_kpi(name: &str, target: f64, reason: &str) -> Value {
    json!({
        "status": "DEFERRED_PHASE_4",
        "kpi": name,
        "target": target,
        "reason_for_deferral": reason,
    })
}

fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (pct / 100.0) * ((sorted.len() - 1) as f64);
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    if lower == upper {
        sorted[lower]
    } else {
        // Linear interpolation between sorted[lower] and sorted[upper].
        let weight = rank - lower as f64;
        let lo = sorted[lower] as f64;
        let hi = sorted[upper] as f64;
        (lo + weight * (hi - lo)).round() as u64
    }
}

pub fn render_markdown(result: &Value) -> String {
    let mut out = String::new();
    out.push_str("# Phase 3 KPI Summary\n\n");
    out.push_str("- `completion_claim_allowed`: `false`\n");
    out.push_str("- `full_aegis_completion_claimed`: `false`\n");
    out.push_str("- Scope: computed from local inputs only (no live VPS).\n\n");
    out.push_str("## KPI table\n\n");
    out.push_str("| KPI | Target | Status | Value / Note |\n");
    out.push_str("|---|---|---|---|\n");
    if let Some(kpis) = result.get("kpis").and_then(Value::as_object) {
        for (name, body) in kpis {
            let target = body
                .get("target")
                .or_else(|| body.get("target_median_ms_max"))
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());
            let status = body
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("UNKNOWN");
            let value = body
                .get("value")
                .or_else(|| body.get("median_ms"))
                .or_else(|| body.get("historical_value"))
                .or_else(|| body.pointer("/historical_score_distribution/mean"))
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!("| `{name}` | {target} | `{status}` | {value} |\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn unique_temp_path(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("aegis-phase3-kpi-{prefix}-{pid}-{nanos}"))
    }

    struct TempFile {
        path: PathBuf,
    }
    impl TempFile {
        fn write(prefix: &str, body: &str) -> Self {
            let path = unique_temp_path(prefix);
            std::fs::write(&path, body).expect("write temp file");
            TempFile { path }
        }
        fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn percentile_handles_empty_and_single() {
        assert_eq!(percentile(&[], 50.0), 0);
        assert_eq!(percentile(&[42], 50.0), 42);
    }

    #[test]
    fn percentile_handles_basic_distribution() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(percentile(&data, 50.0), 6);
        assert_eq!(percentile(&data, 95.0), 10);
    }

    #[test]
    fn bootstrap_audit_reports_no_fallback_capability() {
        let tmp = TempFile::write(
            "bootstrap-blocked",
            "MANIFEST_URL=\"${AEGIS_INSTALL_MANIFEST_URL:-https://example/release.json}\"\n",
        );
        let result = bootstrap_survival_audit(tmp.path(), None).unwrap();
        let cap = &result["static_capability_audit"];
        assert_eq!(cap["automatic_fallback_sources_present"], 0);
        assert_eq!(cap["mirrors_supported"], false);
        assert_eq!(cap["voucher_supported"], false);
        assert_eq!(cap["operator_override_available_but_not_automatic"], true);
    }

    #[test]
    fn bootstrap_audit_recognises_mirror_env_var() {
        let tmp = TempFile::write(
            "bootstrap-mirrors",
            "AEGIS_INSTALL_MIRRORS=\"mirror-a.example.org,mirror-b.example.org\"\n",
        );
        let result = bootstrap_survival_audit(tmp.path(), None).unwrap();
        assert_eq!(result["static_capability_audit"]["mirrors_supported"], true);
    }

    // REGRESSION: this KPI is a *rate* — "share of installs that still succeed
    // when the primary host is blocked". It used to grep the installer for the
    // strings AEGIS_INSTALL_MIRRORS / VOUCHER and, on a hit anywhere in the
    // file, emit value 1.0 and PASS against the 0.95 target. A 100% survival
    // claim from the presence of a word, with no install run and no host
    // blocked. Capability must never be reported as a measured rate.
    #[test]
    fn bootstrap_survival_never_passes_from_a_string_match() {
        let script = TempFile::write(
            "bootstrap-with-mirrors",
            "AEGIS_INSTALL_MIRRORS=\"a.example,b.example\"\nVOUCHER_TOKEN=x\n",
        );
        let result = bootstrap_survival_audit(script.path(), None).unwrap();
        assert_eq!(result["status"], "INSUFFICIENT_EVIDENCE");
        assert!(result["value"].is_null(), "a grep must not yield a rate");
        assert_ne!(result["status"], "PASS");
        // The capability itself is still reported — it just is not the KPI.
        assert_eq!(result["static_capability_audit"]["mirrors_supported"], true);
    }

    #[test]
    fn bootstrap_survival_uses_real_trials_when_supplied() {
        let script = TempFile::write("bootstrap", "AEGIS_INSTALL_MIRRORS=\"a.example\"\n");

        let pass = TempFile::write("trials-pass", "{\"attempts\":20,\"successes\":19}");
        let r = bootstrap_survival_audit(script.path(), Some(pass.path())).unwrap();
        assert_eq!(r["status"], "PASS");
        assert_eq!(r["attempts"], 20);
        assert!((r["value"].as_f64().unwrap() - 0.95).abs() < 1e-9);

        let fail = TempFile::write("trials-fail", "{\"attempts\":20,\"successes\":10}");
        let r = bootstrap_survival_audit(script.path(), Some(fail.path())).unwrap();
        assert_eq!(r["status"], "FAIL", "below target must not read as PASS");

        // A corrupt trial set (more successes than attempts) is refused, not
        // clamped into a green number.
        let bad = TempFile::write("trials-bad", "{\"attempts\":5,\"successes\":9}");
        let r = bootstrap_survival_audit(script.path(), Some(bad.path())).unwrap();
        assert_eq!(r["status"], "INSUFFICIENT_EVIDENCE");
        assert!(r["value"].is_null());
    }

    #[test]
    fn transport_survival_reports_insufficient_evidence_for_missing_state() {
        let result = transport_survival_rate(None).unwrap();
        assert_eq!(result["status"], "INSUFFICIENT_EVIDENCE");
        assert_eq!(result["reason"], "no_state_json_supplied");
    }

    #[test]
    fn transport_survival_computes_rate_from_state_strategies() {
        let state = serde_json::json!({
            "strategies": {
                "tls_strategy": {
                    "trials": 100, "successes": 80, "degraded": 10,
                    "freezes": 5, "timeouts": 5,
                },
                "grpc_strategy": {
                    "trials": 50, "successes": 45, "degraded": 0,
                }
            }
        });
        let tmp = TempFile::write("state-survival", &serde_json::to_string(&state).unwrap());
        let result = transport_survival_rate(Some(tmp.path())).unwrap();
        assert_eq!(result["trials_total"], 150);
        assert_eq!(result["pass_total"], 135);
        assert!((result["value"].as_f64().unwrap() - 0.9).abs() < 1e-9);
        assert_eq!(result["status"], "PASS");
    }

    #[test]
    fn relay_failover_recovery_reports_insufficient_when_no_jsonl() {
        let result = relay_failover_recovery_time(&[]).unwrap();
        assert_eq!(result["status"], "INSUFFICIENT_EVIDENCE");
    }

    #[test]
    fn a03_neutral_completion_cannot_supply_failover_recovery() {
        // `cancelled` exercises a possible neutral event, not a requirement
        // for the runtime to emit an event when the session future is dropped.
        for (scope_field, timestamp_field) in [
            ("relay_failure_scope", "ts_unix_ms"),
            ("failure_scope", "timestamp_unix_ms"),
            ("failure_scope", "ts_ms"),
        ] {
            for reason in ["no_response_observed", "no_attempt_observed", "cancelled"] {
                for prior_failure in [false, true] {
                    let mut events = Vec::new();
                    if prior_failure {
                        events.push(json!({
                            "event_code": "relay_transport_failed",
                            (timestamp_field): 1_000,
                            "fields": { (scope_field): "real_transport_outage" },
                        }));
                    }
                    events.push(json!({
                        "event_code": "relay_session_completed",
                        (timestamp_field): 2_000,
                        "fields": {
                            "relay_session_kind": "tcp_tunnel",
                            "completion_reason": reason,
                            "application_response_observed": false,
                            "transfer_result": if reason == "cancelled" { "cancelled" } else { "ok" },
                            "bytes_received_observed": 0,
                        },
                    }));
                    let body = events
                        .iter()
                        .map(Value::to_string)
                        .collect::<Vec<_>>()
                        .join("\n");
                    let tmp = TempFile::write("neutral-completion", &body);
                    let result = relay_failover_recovery_time(&[tmp.path()]).unwrap();

                    assert_eq!(result["status"], "INSUFFICIENT_EVIDENCE");
                    assert_eq!(
                        result["reason"],
                        "no_real_failure_to_success_pairs_observed_in_supplied_runtime_events"
                    );
                    assert!(result["sample_count"].is_null());
                    assert!(result["median_ms"].is_null());
                    assert!(result["p95_ms"].is_null());
                }
            }
        }
    }

    #[test]
    fn a03_failover_recovery_waits_past_neutral_completion_for_true_success() {
        let body = concat!(
            r#"{"event_code":"relay_transport_failed","ts_unix_ms":1000,"fields":{"relay_failure_scope":"real_transport_outage"}}"#,
            "\n",
            r#"{"event_code":"relay_session_completed","ts_unix_ms":2000,"fields":{"completion_reason":"no_response_observed","application_response_observed":false,"transfer_result":"ok","bytes_received_observed":0}}"#,
            "\n",
            r#"{"event_code":"relay_session_succeeded","ts_unix_ms":5500,"fields":{"application_response_observed":true,"transfer_result":"ok","bytes_received_observed":8}}"#,
            "\n",
        );
        let tmp = TempFile::write("recovery-after-neutral-completion", body);
        let result = relay_failover_recovery_time(&[tmp.path()]).unwrap();

        assert_eq!(result["status"], "PASS");
        assert_eq!(result["sample_count"], 1);
        assert_eq!(result["median_ms"], 4_500);
        assert_eq!(result["p95_ms"], 4_500);
    }

    #[test]
    fn a03_failover_recovery_prefers_producer_scope_over_legacy_scope() {
        for (producer_scope, legacy_scope, recovered) in [
            ("real_transport_outage", "benign_session_end", true),
            ("benign_session_end", "real_transport_outage", false),
        ] {
            let events = [
                json!({
                    "event_code": "relay_transport_failed",
                    "timestamp_unix_ms": 1_000,
                    "fields": {
                        "relay_failure_scope": producer_scope,
                        "failure_scope": legacy_scope,
                    },
                }),
                json!({
                    "event_code": "relay_session_succeeded",
                    "timestamp_unix_ms": 5_500,
                    "fields": { "application_response_observed": true },
                }),
            ];
            let body = events
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            let tmp = TempFile::write("recovery-scope-precedence", &body);
            let result = relay_failover_recovery_time(&[tmp.path()]).unwrap();

            if recovered {
                assert_eq!(result["status"], "PASS");
                assert_eq!(result["sample_count"], 1);
                assert_eq!(result["median_ms"], 4_500);
            } else {
                assert_eq!(result["status"], "INSUFFICIENT_EVIDENCE");
                assert!(result["sample_count"].is_null());
            }
        }
    }

    #[test]
    fn a03_failover_recovery_prefers_producer_timestamp_over_legacy_aliases() {
        let body = concat!(
            r#"{"event_code":"relay_transport_failed","ts_unix_ms":1000,"timestamp_unix_ms":4000,"ts_ms":4500,"fields":{"relay_failure_scope":"real_transport_outage"}}"#,
            "\n",
            r#"{"event_code":"relay_session_succeeded","ts_unix_ms":5500,"timestamp_unix_ms":6000,"ts_ms":7000,"fields":{"application_response_observed":true}}"#,
            "\n",
        );
        let tmp = TempFile::write("recovery-timestamp-precedence", body);
        let result = relay_failover_recovery_time(&[tmp.path()]).unwrap();

        assert_eq!(result["status"], "PASS");
        assert_eq!(result["sample_count"], 1);
        assert_eq!(result["median_ms"], 4_500);
        assert_eq!(result["p95_ms"], 4_500);
    }

    #[test]
    fn relay_failover_recovery_pairs_real_failure_with_next_success() {
        let body = concat!(
            r#"{"event_code":"relay_transport_failed","timestamp_unix_ms":1000,"fields":{"failure_scope":"real_transport_outage"}}"#,
            "\n",
            r#"{"event_code":"relay_session_succeeded","timestamp_unix_ms":5500,"fields":{}}"#,
            "\n",
            r#"{"event_code":"relay_transport_failed","timestamp_unix_ms":6000,"fields":{"failure_scope":"benign_session_end"}}"#,
            "\n",
            r#"{"event_code":"relay_session_succeeded","timestamp_unix_ms":7000,"fields":{}}"#,
            "\n",
        );
        let tmp = TempFile::write("recovery", body);
        let path: &Path = tmp.path();
        let result = relay_failover_recovery_time(&[path]).unwrap();
        assert_eq!(result["sample_count"], 1);
        assert_eq!(result["median_ms"], 4500);
        assert_eq!(result["p95_ms"], 4500);
    }
}
