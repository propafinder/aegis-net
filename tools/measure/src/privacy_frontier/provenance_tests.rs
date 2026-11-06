use super::super::privacy_frontier_report;
use serde_json::{json, Value};

// Synthetic schema fixtures only: these hashes identify no real captures and
// the resulting reports must retain explicit unverified-content flags.
fn unit(session: &str, trial: &str, holdout: &str, digest: char, start: u64) -> Value {
    json!({
        "session_id":session, "trial_id":trial, "network_id":"network_a",
        "time_holdout_id":holdout, "capture_sha256":digest.to_string().repeat(64),
        "capture_started_unix_ms":start, "capture_finished_unix_ms":start+10
    })
}

fn input() -> Value {
    json!({
        "alphabet":{"labels":2,"features":2},
        "assume_iid_fixed_alphabet":false, "delta":0.05,
        "qos":{"max_added_bytes":160,"max_added_delay_ms":4},
        "provenance":{
            "schema_version":1, "frozen_bins_sha256":"f".repeat(64),
            "bins_frozen_unix_ms":200,
            "training_units":[unit("training_session","training_trial","training_holdout",'a',100)]
        },
        "policies":[
            {"name":"baseline", "samples":[
                {"label":0,"feature":0,"added_bytes":0,"added_delay_ms":0},
                {"label":1,"feature":1,"added_bytes":0,"added_delay_ms":0}],
             "provenance":{"source_sha256":"1".repeat(64),"sample_units":[
                 unit("baseline_session","trial_a","evaluation_holdout",'b',300),
                 unit("baseline_session","trial_b","evaluation_holdout",'b',300)]}},
            {"name":"cover", "samples":[
                {"label":0,"feature":0,"added_bytes":128,"added_delay_ms":2},
                {"label":1,"feature":0,"added_bytes":128,"added_delay_ms":2}],
             "provenance":{"source_sha256":"2".repeat(64),"sample_units":[
                 unit("cover_session","trial_a","evaluation_holdout",'c',320),
                 unit("cover_session","trial_b","evaluation_holdout",'c',320)]}}
        ]
    })
}

#[test]
fn parses_paired_input_with_policy_specific_sessions_and_preserves_limits() {
    let report = privacy_frontier_report(&input()).unwrap();
    let provenance = &report["provenance_validation"];
    assert_eq!(provenance["status"], "declared_paired_units_consistent");
    assert_eq!(provenance["paired_units_checked"], true);
    assert_eq!(provenance["training_separation_checked"], true);
    assert_eq!(provenance["capture_contents_verified"], false);
    assert_eq!(provenance["frozen_bin_contents_verified"], false);
    assert_eq!(provenance["statistical_independence_proven"], false);
    assert_eq!(
        provenance["policies"][0]["paired_population_sha256"],
        provenance["policies"][1]["paired_population_sha256"]
    );
    assert_eq!(provenance["policies"][0]["evaluation_units"], 2);
    assert_eq!(report["qos_selected_measured_policy_index"], 1);
    assert_eq!(report["automatic_policy_adoption"], false);
    assert_eq!(report["installed_acceptance"], false);
    assert_eq!(report["target_network_acceptance"], false);
    assert_eq!(report["beta_exit"], false);
}

#[test]
fn equal_label_counts_do_not_admit_different_trials_networks_or_holdouts() {
    for field in ["trial_id", "network_id", "time_holdout_id"] {
        let mut value = input();
        value["policies"][1]["provenance"]["sample_units"][1][field] = json!("different");
        // A separate consistent capture isolates paired-population rejection.
        value["policies"][1]["provenance"]["sample_units"][1]["capture_sha256"] =
            json!("d".repeat(64));
        let error = privacy_frontier_report(&value).unwrap_err();
        assert!(error.contains("same paired"), "{field}: {error}");
    }
    let mut value = input();
    // The same marginal label counts still allow opposite trial assignments.
    value["policies"][1]["samples"][0]["label"] = json!(1);
    value["policies"][1]["samples"][1]["label"] = json!(0);
    assert!(privacy_frontier_report(&value)
        .unwrap_err()
        .contains("same paired"));
}

#[test]
fn metadata_and_sample_reordering_keeps_the_canonical_paired_population() {
    let mut value = input();
    value["policies"][1]["samples"]
        .as_array_mut()
        .unwrap()
        .reverse();
    value["policies"][1]["provenance"]["sample_units"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let report = privacy_frontier_report(&value).unwrap();
    assert_eq!(
        report["provenance_validation"]["policies"][0]["paired_population_sha256"],
        report["provenance_validation"]["policies"][1]["paired_population_sha256"]
    );
}

#[test]
fn training_units_cannot_be_reused_under_different_metadata() {
    for field in [
        "session_id",
        "trial_id",
        "capture_sha256",
        "time_holdout_id",
    ] {
        let mut value = input();
        value["policies"][0]["provenance"]["sample_units"][0][field] =
            value["provenance"]["training_units"][0][field].clone();
        assert!(
            privacy_frontier_report(&value)
                .unwrap_err()
                .contains("reuses a training"),
            "{field}"
        );
    }
}

#[test]
fn copied_captures_or_sessions_are_not_paired_policy_measurements() {
    for field in ["session_id", "capture_sha256"] {
        let mut value = input();
        value["policies"][1]["provenance"]["sample_units"][0][field] =
            value["policies"][0]["provenance"]["sample_units"][0][field].clone();
        assert!(privacy_frontier_report(&value)
            .unwrap_err()
            .contains("distinct capture and session"));
    }
}

#[test]
fn one_capture_hash_cannot_describe_conflicting_intervals_or_networks() {
    for (field, changed) in [
        ("capture_started_unix_ms", json!(301)),
        ("capture_finished_unix_ms", json!(311)),
        ("network_id", json!("network_b")),
    ] {
        let mut value = input();
        value["policies"][0]["provenance"]["sample_units"][1][field] = changed;
        assert!(privacy_frontier_report(&value)
            .unwrap_err()
            .contains("conflicting capture declarations"));
    }
    let mut training = input();
    let mut row = training["provenance"]["training_units"][0].clone();
    row["trial_id"] = json!("another_training_trial");
    row["capture_finished_unix_ms"] = json!(111);
    training["provenance"]["training_units"]
        .as_array_mut()
        .unwrap()
        .push(row);
    assert!(privacy_frontier_report(&training)
        .unwrap_err()
        .contains("conflicting capture declarations"));
}

#[test]
fn freezes_bins_before_evaluation_and_after_training_capture() {
    for (path, time) in [
        ("capture_started_unix_ms", 200),
        ("capture_finished_unix_ms", 299),
    ] {
        let mut value = input();
        value["policies"][0]["provenance"]["sample_units"][0][path] = json!(time);
        assert!(privacy_frontier_report(&value).is_err());
    }
    let mut value = input();
    value["provenance"]["training_units"][0]["capture_finished_unix_ms"] = json!(201);
    assert!(privacy_frontier_report(&value)
        .unwrap_err()
        .contains("training captures must finish"));
}

#[test]
fn rejects_incomplete_duplicate_or_unknown_provenance() {
    let mut missing_policy = input();
    missing_policy["policies"][1]
        .as_object_mut()
        .unwrap()
        .remove("provenance");
    assert!(privacy_frontier_report(&missing_policy).is_err());
    let mut missing_shared = input();
    missing_shared.as_object_mut().unwrap().remove("provenance");
    assert!(privacy_frontier_report(&missing_shared).is_err());
    let mut wrong_count = input();
    wrong_count["policies"][0]["provenance"]["sample_units"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(privacy_frontier_report(&wrong_count).is_err());
    let mut duplicate = input();
    duplicate["policies"][0]["provenance"]["sample_units"][1] =
        duplicate["policies"][0]["provenance"]["sample_units"][0].clone();
    assert!(privacy_frontier_report(&duplicate)
        .unwrap_err()
        .contains("duplicate evaluation"));
    let mut duplicate_training = input();
    let row = duplicate_training["provenance"]["training_units"][0].clone();
    duplicate_training["provenance"]["training_units"]
        .as_array_mut()
        .unwrap()
        .push(row);
    assert!(privacy_frontier_report(&duplicate_training)
        .unwrap_err()
        .contains("duplicate training"));
    let mut unknown = input();
    unknown["policies"][0]["provenance"]["sample_units"][0]["independence_proven"] = json!(true);
    assert!(privacy_frontier_report(&unknown)
        .unwrap_err()
        .contains("invalid privacy frontier schema"));
}

#[test]
fn rejects_unbounded_identifiers_invalid_hashes_and_provenance_versions() {
    for id in [
        "s".repeat(65),
        "secret/url?token".into(),
        "сеанс".into(),
        String::new(),
    ] {
        let mut value = input();
        value["policies"][0]["provenance"]["sample_units"][0]["session_id"] = json!(id);
        assert!(privacy_frontier_report(&value).is_err());
    }
    let mut malformed_hash = input();
    malformed_hash["policies"][0]["provenance"]["source_sha256"] = json!("A".repeat(64));
    assert!(privacy_frontier_report(&malformed_hash).is_err());
    for version in [0, 2] {
        let mut value = input();
        value["provenance"]["schema_version"] = json!(version);
        assert!(privacy_frontier_report(&value).is_err());
    }
}
