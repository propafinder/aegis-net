use super::super::privacy_frontier_report;
use serde_json::{json, Value};

// Synthetic schema tests only; these declarations identify no actual capture.
fn unit(session: &str, trial: &str, digest: char, start: u64) -> Value {
    json!({"session_id":session,"trial_id":trial,"network_id":"network_a",
        "time_holdout_id":if start<200 {"training_holdout"} else {"evaluation_holdout"},
        "capture_sha256":digest.to_string().repeat(64),
        "capture_started_unix_ms":start,"capture_finished_unix_ms":start+10})
}

fn paired_input() -> Value {
    let rows = [
        (0, 0),
        (0, 0),
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
        (1, 1),
        (1, 1),
    ];
    let policies = [("baseline", 'b', "1"), ("cover", 'c', "2")]
        .into_iter()
        .map(|(name, digest, source)| {
            json!({"name":name,"samples":rows.iter().map(|(label,feature)|json!({
                "label":label,"feature":if name=="baseline" {*feature} else {0},
                "added_bytes":0,"added_delay_ms":0})).collect::<Vec<_>>(),
                "provenance":{"source_sha256":source.repeat(64),"sample_units":(0..rows.len())
                    .map(|n|unit(name,&format!("evaluation_{n}"),digest,300))
                    .collect::<Vec<_>>()}})
        })
        .collect::<Vec<_>>();
    json!({"alphabet":{"labels":2,"features":2},"assume_iid_fixed_alphabet":false,
        "delta":0.05,"policies":policies,"provenance":{"schema_version":1,
            "frozen_bins_sha256":"f".repeat(64),"bins_frozen_unix_ms":200,
            "training_units":[unit("training_session","training_trial",'a',100)]}})
}

#[test]
fn paired_heldout_pipeline_consumes_empirical_distances_without_population_claims() {
    let report = privacy_frontier_report(&paired_input()).unwrap();
    let diagnostics = &report["binary_hypothesis_diagnostics"];
    assert_eq!(
        diagnostics["status"],
        "declared_provenance_checked_empirical_only"
    );
    assert_eq!(
        report["provenance_validation"]["paired_units_checked"],
        true
    );
    let baseline = &diagnostics["policies"][0]["diagnostic"];
    assert_eq!(baseline["empirical_total_variation"], 0.5);
    assert!(
        (baseline["kl_h0_to_h1"]["empirical_nats"].as_f64().unwrap() - 0.5 * 3.0_f64.ln()).abs()
            < 1e-12
    );
    assert_eq!(
        diagnostics["policies"][1]["diagnostic"]["empirical_total_variation"],
        0.0
    );
    for flag in [
        "capture_contents_verified",
        "frozen_bin_contents_verified",
        "source_feature_extraction_verified",
        "statistical_independence_proven",
        "population_distance_established",
        "whole_flow_privacy_guarantee",
        "awgn_or_square_root_guarantee",
        "automatic_policy_adoption",
    ] {
        assert_eq!(diagnostics[flag], false, "{flag}");
    }
    assert_eq!(report["beta_exit"], false);
}

#[test]
fn unverified_legacy_input_does_not_emit_binary_distance_values() {
    let mut value = paired_input();
    value.as_object_mut().unwrap().remove("provenance");
    for policy in value["policies"].as_array_mut().unwrap() {
        policy.as_object_mut().unwrap().remove("provenance");
    }
    let report = privacy_frontier_report(&value).unwrap();
    assert_eq!(
        report["binary_hypothesis_diagnostics"]["status"],
        "unknown_unverified_provenance"
    );
    assert_eq!(
        report["binary_hypothesis_diagnostics"]["policies"],
        json!([])
    );
    assert_eq!(
        report["provenance_validation"]["status"],
        "unverified_legacy_input"
    );
}

#[test]
fn missing_reference_bins_leave_directional_kl_unknown_in_json() {
    let mut value = paired_input();
    for sample in value["policies"][0]["samples"].as_array_mut().unwrap() {
        sample["feature"] = sample["label"].clone();
    }
    let report = privacy_frontier_report(&value).unwrap();
    let d = &report["binary_hypothesis_diagnostics"]["policies"][0]["diagnostic"];
    assert_eq!(d["empirical_total_variation"], 1.0);
    for direction in ["kl_h0_to_h1", "kl_h1_to_h0"] {
        assert_eq!(
            d[direction]["status"],
            "unknown_zero_observed_reference_support"
        );
        assert_eq!(d[direction]["empirical_nats"], Value::Null);
    }
    assert_eq!(d["smoothing_applied"], false);
}

#[test]
fn undersampled_hypotheses_remain_unknown_after_valid_provenance() {
    let mut value = paired_input();
    for policy in value["policies"].as_array_mut().unwrap() {
        let samples = policy["samples"].as_array().unwrap();
        policy["samples"] = json!([samples[0].clone(), samples[4].clone()]);
        let units = policy["provenance"]["sample_units"].as_array().unwrap();
        policy["provenance"]["sample_units"] = json!([units[0].clone(), units[4].clone()]);
    }
    let report = privacy_frontier_report(&value).unwrap();
    let d = &report["binary_hypothesis_diagnostics"]["policies"][0]["diagnostic"];
    assert_eq!(d["status"], "unknown_insufficient_observations");
    assert_eq!(d["empirical_total_variation"], Value::Null);
    assert_eq!(d["kl_h0_to_h1"]["empirical_nats"], Value::Null);
}

#[test]
fn original_provenance_gate_refuses_unpaired_or_training_reused_inputs_first() {
    let mut changed = paired_input();
    changed["policies"][1]["provenance"]["sample_units"][0]["trial_id"] = json!("unpaired");
    assert!(privacy_frontier_report(&changed)
        .unwrap_err()
        .contains("same paired"));
    let mut reused = paired_input();
    reused["policies"][0]["provenance"]["sample_units"][0]["session_id"] =
        json!("training_session");
    assert!(privacy_frontier_report(&reused)
        .unwrap_err()
        .contains("reuses a training"));
}

#[test]
fn verified_nonbinary_frontier_is_supported_without_binary_claims() {
    let mut value = paired_input();
    value["alphabet"]["labels"] = json!(3);
    for policy in value["policies"].as_array_mut().unwrap() {
        policy["samples"][7]["label"] = json!(2);
    }
    let report = privacy_frontier_report(&value).unwrap();
    assert_eq!(
        report["binary_hypothesis_diagnostics"]["status"],
        "unknown_nonbinary_label_alphabet"
    );
    assert_eq!(
        report["binary_hypothesis_diagnostics"]["policies"],
        json!([])
    );
}
