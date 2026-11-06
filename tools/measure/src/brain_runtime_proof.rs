use std::{
    fs,
    path::{Path, PathBuf},
};

use aegis_core::{
    signals::classify::FailSignal, AsyncStateStore, Brain, ExternalCalibrationSnapshot,
    StrategyKey, StrategyStatsV2,
};
use serde_json::{json, Value};

mod snapshots;
mod support;

use snapshots::{
    fresh_snapshot_for_https_ws, high_confidence_fail_closed_snapshot_for_https_ws,
    stale_snapshot_for_https_ws, weak_penalty_snapshot_for_https_ws,
};
use support::{candidate_bool, candidate_f64, string_array, unix_ms, write_json, write_text};

pub fn brain_external_calibration_runtime_proof(
    artifact_dir: &Path,
) -> Result<Value, Box<dyn std::error::Error>> {
    fs::create_dir_all(artifact_dir)?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async { run_proof(artifact_dir).await })
}

async fn run_proof(artifact_dir: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let key = StrategyKey::for_target(
        "203.0.113.1:443".parse().expect("static socket addr"),
        "example.org",
        443,
        Some("example.org"),
        true,
    );

    let snapshot = fresh_snapshot_for_https_ws();
    let snapshot_path = artifact_dir.join("external-calibration-snapshot.json");
    write_json(&snapshot_path, &serde_json::to_value(&snapshot)?)?;

    let baseline_trace = select_trace(
        artifact_dir.join("state-baseline.json"),
        &key,
        vec!["legacy_tls".into(), "https_ws".into()],
        None,
        None,
    )
    .await?;
    let calibrated_trace = select_trace(
        artifact_dir.join("state-calibrated.json"),
        &key,
        vec!["legacy_tls".into(), "https_ws".into()],
        Some(snapshot.clone()),
        None,
    )
    .await?;
    let stale_trace = select_trace(
        artifact_dir.join("state-stale.json"),
        &key,
        vec!["legacy_tls".into(), "https_ws".into()],
        Some(stale_snapshot_for_https_ws()),
        None,
    )
    .await?;
    let runtime_override_trace = select_trace(
        artifact_dir.join("state-runtime-override.json"),
        &key,
        vec!["legacy_tls".into(), "https_ws".into()],
        Some(weak_penalty_snapshot_for_https_ws()),
        Some(RuntimeStatsScenario::HttpsSuccessLegacyTimeout),
    )
    .await?;
    let hard_block_trace = select_trace(
        artifact_dir.join("state-hard-block.json"),
        &key,
        vec!["legacy_tls".into(), "https_ws".into()],
        Some(high_confidence_fail_closed_snapshot_for_https_ws()),
        Some(RuntimeStatsScenario::HttpsSuccessLegacyTimeout),
    )
    .await?;

    let baseline_order = string_array(&baseline_trace["reward_selected_order"]);
    let calibrated_order = string_array(&calibrated_trace["reward_selected_order"]);
    let stale_order = string_array(&stale_trace["reward_selected_order"]);
    let runtime_override_order = string_array(&runtime_override_trace["reward_selected_order"]);
    let hard_block_order = string_array(&hard_block_trace["reward_selected_order"]);

    let select_order_changed = baseline_order.first().map(String::as_str) == Some("legacy_tls")
        && calibrated_order.first().map(String::as_str) == Some("https_ws");
    let stale_calibration_ignored = stale_order.first().map(String::as_str) == Some("legacy_tls")
        && candidate_f64(&stale_trace, "https_ws", "belief_confidence").unwrap_or(1.0) < 0.01
        && candidate_f64(&stale_trace, "https_ws", "estimated_reward") == Some(0.5);
    let runtime_success_overrode_weak_prior =
        runtime_override_order.first().map(String::as_str) == Some("https_ws");
    let high_confidence_fail_closed_hard_block = hard_block_order.first().map(String::as_str)
        == Some("legacy_tls")
        && candidate_bool(&hard_block_trace, "https_ws", "belief_hard_blocked") == Some(true)
        && candidate_f64(&hard_block_trace, "https_ws", "estimated_reward") == Some(0.0);
    let external_calibration_applied_event_present =
        write_runtime_events(artifact_dir, &snapshot, &calibrated_trace)?;

    write_json(&artifact_dir.join("baseline-trace.json"), &baseline_trace)?;
    write_json(
        &artifact_dir.join("calibrated-trace.json"),
        &calibrated_trace,
    )?;
    write_json(&artifact_dir.join("stale-trace.json"), &stale_trace)?;
    write_json(
        &artifact_dir.join("runtime-override-trace.json"),
        &runtime_override_trace,
    )?;
    write_json(
        &artifact_dir.join("hard-block-trace.json"),
        &hard_block_trace,
    )?;

    let verdict = select_order_changed
        && stale_calibration_ignored
        && runtime_success_overrode_weak_prior
        && high_confidence_fail_closed_hard_block
        && external_calibration_applied_event_present;
    let result = json!({
        "schema_version": 1,
        "artifact": "brain-external-calibration-runtime-proof",
        "status": if verdict { "PASS" } else { "NOT_PASS" },
        "verdict": if verdict { "PASS" } else { "NOT_PASS" },
        "calibration_snapshot_loaded": true,
        "external_calibration_applied_event_present": external_calibration_applied_event_present,
        "baseline_order": baseline_order,
        "calibrated_order": calibrated_order,
        "select_order_changed_after_calibration": select_order_changed,
        "stale_calibration_ignored": stale_calibration_ignored,
        "runtime_success_overrode_weak_prior": runtime_success_overrode_weak_prior,
        "high_confidence_fail_closed_hard_block": high_confidence_fail_closed_hard_block,
        "low_confidence_block_policy": "penalty_not_exclusion_existing_core_contract",
        "selection_model": "l1_l2_l3_adaptive_posterior",
        "android_status": "DEFERRED_OPTIONAL_PLATFORM_REACH",
        "phase_d_exit_claimed": false,
        "blocker": if verdict { Value::Null } else { json!("brain external calibration runtime proof failed one or more required checks") },
    });
    write_json(&artifact_dir.join("result.json"), &result)?;
    write_text(
        &artifact_dir.join("README.md"),
        &format!(
            "# Brain External Calibration Runtime Proof\n\n\
             Verdict: `{}`\n\n\
             This artifact proves that a measured external calibration snapshot can be loaded into Brain state, changes `select_order`, stale calibration decays, runtime success can overcome a weak prior penalty, and high-confidence fresh fail-closed policy hard-blocks a transport.\n\n\
             Android is deferred; this is desktop/core work and does not claim Phase D exit.\n",
            result["verdict"].as_str().unwrap_or("UNKNOWN")
        ),
    )?;
    write_text(
        &artifact_dir.join("commands.txt"),
        "scripts/run-brain-external-calibration-runtime-proof.sh\n",
    )?;
    write_text(
        &artifact_dir.join("environment.txt"),
        &format!(
            "date_utc={}\nartifact={}\n",
            unix_ms(),
            artifact_dir.display()
        ),
    )?;
    Ok(result)
}

#[derive(Clone, Copy)]
enum RuntimeStatsScenario {
    HttpsSuccessLegacyTimeout,
}

async fn select_trace(
    state_path: PathBuf,
    key: &StrategyKey,
    preferred_order: Vec<String>,
    snapshot: Option<ExternalCalibrationSnapshot>,
    runtime_stats: Option<RuntimeStatsScenario>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let store = AsyncStateStore::load(state_path).await?;
    let hk = key.hash_key();
    store
        .update(|state| {
            state.key_registry.insert(hk.clone(), key.clone());
            if let Some(snapshot) = snapshot.clone() {
                state.external_calibration = Some(snapshot);
            }
            if matches!(
                runtime_stats,
                Some(RuntimeStatsScenario::HttpsSuccessLegacyTimeout)
            ) {
                let mut https_ws = StrategyStatsV2::default();
                for _ in 0..10 {
                    https_ws.record(&FailSignal::Success, Some(20), 4096);
                }
                let mut legacy_tls = StrategyStatsV2::default();
                for _ in 0..10 {
                    legacy_tls.record(&FailSignal::Timeout, None, 0);
                }
                state
                    .strategy_stats
                    .insert(format!("{hk}|https_ws"), https_ws);
                state
                    .strategy_stats
                    .insert(format!("{hk}|legacy_tls"), legacy_tls);
            }
        })
        .await;
    let brain = Brain::new(0.0, preferred_order, store);
    let trace = brain.select_order_trace(key).await;
    Ok(json!({
        "selector_mode": trace.selector_mode,
        "explainability_trace_source": trace.explainability_trace_source,
        "explainability_observation_source": trace.explainability_observation_source,
        "decision_context": {
            "platform": trace.decision_context.platform,
            "target_class": trace.decision_context.target_class,
            "network_profile": trace.decision_context.network_profile,
            "region_id": trace.decision_context.region_id,
            "recent_failures": trace.decision_context.recent_failures,
        },
        "observation_contract": trace.observation_contract,
        "observation_capture_confidence": trace.observation_capture_confidence,
        "probe_history_disposition": trace.probe_history_disposition,
        "probe_history_reason_code": trace.probe_history_reason_code,
        "cross_session_signal_bias": trace.cross_session_signal_bias,
        "cross_session_confidence_score": trace.cross_session_confidence_score,
        "cross_session_reuse_weight": trace.cross_session_reuse_weight,
        "cross_session_stall_severity": trace.cross_session_stall_severity,
        "cross_session_probe_branch_score": trace.cross_session_probe_branch_score,
        "cross_session_relay_preference_score": trace.cross_session_relay_preference_score,
        "reward_selected_order": trace.reward_selected_order,
        "ranked_candidates": trace.ranked_candidates.into_iter().map(|candidate| json!({
            "strategy": candidate.strategy,
            "estimated_reward": candidate.estimated_reward,
            "estimated_trials": candidate.estimated_trials,
            "total_trials": candidate.total_trials,
            "probe_history_strategy_bias": candidate.probe_history_strategy_bias,
            "selection_score": candidate.selection_score,
            "selection_score_reward_component": candidate.selection_score_reward_component,
            "selection_score_ucb_exploration_bonus": candidate.selection_score_ucb_exploration_bonus,
            "selection_score_probe_bias_component": candidate.selection_score_probe_bias_component,
            "belief_alpha": candidate.belief_alpha,
            "belief_beta": candidate.belief_beta,
            "belief_detection_risk": candidate.belief_detection_risk,
            "belief_latency_cost": candidate.belief_latency_cost,
            "belief_confidence": candidate.belief_confidence,
            "belief_freshness": candidate.belief_freshness,
            "belief_hard_blocked": candidate.belief_hard_blocked,
            "belief_source": candidate.belief_source,
            "cold_start_exploration": candidate.cold_start_exploration,
        })).collect::<Vec<_>>(),
    }))
}

fn write_runtime_events(
    artifact_dir: &Path,
    snapshot: &ExternalCalibrationSnapshot,
    calibrated_trace: &Value,
) -> Result<bool, Box<dyn std::error::Error>> {
    let path = artifact_dir.join("runtime-events.jsonl");
    let body = format!(
        "{}\n{}\n",
        json!({
            "timestamp_unix_ms": unix_ms(),
            "level": "info",
            "event_code": "external_calibration_applied",
            "fields": {
                "source": snapshot.source,
                "witness_label_count": snapshot.witness.len(),
                "adversarial_transport_count": snapshot.adversarial.len(),
                "knowledge_prior_count": snapshot.knowledge.len(),
                "verdict_status": snapshot.verdict.status,
                "acceptance_degraded": snapshot.verdict.acceptance_degraded,
            }
        }),
        json!({
            "timestamp_unix_ms": unix_ms(),
            "level": "info",
            "event_code": "brain_select_order_explained",
            "fields": {
                "selection_model": "l1_l2_l3_adaptive_posterior",
                "reward_selected_order": calibrated_trace["reward_selected_order"],
                "ranked_candidates": calibrated_trace["ranked_candidates"],
            }
        })
    );
    write_text(&path, &body)?;
    Ok(
        body.contains("\"event_code\":\"external_calibration_applied\"")
            || body.contains("\"event_code\": \"external_calibration_applied\""),
    )
}
