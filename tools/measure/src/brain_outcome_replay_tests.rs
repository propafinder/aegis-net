use super::*;

fn planner(at: u64) -> Value {
    json!({"ts_unix_ms":at,"event_code":"direct_planner_order_selected",
        "fields":{"target":"private-target.example","port":443,
        "planner_retry_attempt":0,
        "planner_ranked_candidates":[
            {"strategy":"one","estimated_reward":0.5,"belief_hard_blocked":false},
            {"strategy":"two","estimated_reward":0.25,"belief_hard_blocked":false}],
        "planner_resolved_order":["one","two"],"invitation":"private-token-marker"}})
}
fn terminal(at: u64) -> Value {
    json!({"ts_unix_ms":at,"event_code":"direct_session_succeeded",
        "fields":{"target":"private-target.example","port":443,
        "strategy":"one","signal":"Success","bytes_sent":85,"latency_ms":104,
        "retry_attempts_used":0,"observation_capture_confidence":"native_only"}})
}
fn tape(rows: &[Value]) -> Vec<u8> {
    rows.iter()
        .map(|row| serde_json::to_string(row).unwrap() + "\n")
        .collect::<String>()
        .into_bytes()
}
fn metadata(input: &[u8], start: u64, end: u64) -> Value {
    json!({"schema_version":1,"source_sha256":format!("{:x}",Sha256::digest(input)),
        "source_started_unix_ms":start,"source_finished_unix_ms":end,
        "source_kind":"synthetic_fixture","source_commit":null,
        "window_ms":100,"failure_cooldown_ms":20,"max_observations":16})
}
fn checked(rows: &[Value]) -> Result<Value, &'static str> {
    let input = tape(rows);
    report(
        &input,
        &serde_json::to_vec(&metadata(
            &input,
            rows[0]["ts_unix_ms"].as_u64().unwrap(),
            rows.last().unwrap()["ts_unix_ms"].as_u64().unwrap(),
        ))
        .unwrap(),
    )
}

#[test]
fn native_serial_schema_replays_past_only_without_raw_endpoint_or_delivery_claims() {
    let startup = json!({"ts_unix_ms":0,"event_code":"startup_plan","fields":{}});
    let out = checked(&[
        startup,
        planner(10),
        terminal(20),
        planner(30),
        terminal(40),
    ])
    .unwrap();
    assert_eq!(out["source"]["total_native_rows"], 5);
    assert_eq!(out["source"]["imported_direct_rows"], 4);
    assert_eq!(out["replay"]["observed_outcomes"], 2);
    assert_eq!(
        out["replay"]["decisions"][0]["native_recent"]["ranked"][0]["window_trials"],
        0
    );
    assert_eq!(
        out["replay"]["decisions"][1]["native_recent"]["order"][0],
        "two"
    );
    assert_eq!(out["replay"]["reported_latency_sum_ms"], 208);
    assert_eq!(out["replay"]["reported_outgoing_bytes_sum"], 170);
    for key in ["policy_cost", "policy_recovery_ms", "policy_regret"] {
        assert!(out["replay"][key].is_null());
    }
    assert!(out["failure_cooldown_effect"].is_null());
    assert!(!out["replay"]["policy_advantage_established"]
        .as_bool()
        .unwrap());
    assert!(!out["source"]["runtime_origin_independently_verified"]
        .as_bool()
        .unwrap());
    assert!(out["source"]["commit_declared"].is_null());
    let encoded = out.to_string();
    for private in [
        "private-target.example",
        "private-token-marker",
        "native_only",
    ] {
        assert!(!encoded.contains(private));
    }
}

#[test]
fn missing_or_ambiguous_attempts_and_unknown_signals_are_never_imputed() {
    assert!(checked(&[planner(10)]).is_err());
    assert!(checked(&[terminal(10)]).is_err());
    assert!(checked(&[planner(10), planner(20), terminal(30)]).is_err());
    for code in [
        "direct_relay_failover_triggered",
        "direct_active_stall_probe_retry_selected",
    ] {
        assert!(checked(&[
            planner(10),
            json!({"ts_unix_ms":20,"event_code":code,"fields":{}})
        ])
        .is_err());
    }
    let mut value = terminal(20);
    value["fields"]["signal"] = json!("Unknown-private-marker");
    assert_eq!(
        checked(&[planner(10), value]).unwrap_err(),
        "native replay requires a supported terminal without retries"
    );
    let mut value = terminal(20);
    value["fields"]["retry_attempts_used"] = json!(1);
    assert!(checked(&[planner(10), value]).is_err());
    let mut value = planner(10);
    value["fields"]["planner_retry_attempt"] = json!(1);
    assert!(checked(&[value, terminal(20)]).is_err());
}

#[test]
fn actual_native_retry_and_probe_event_names_cannot_be_skipped_between_success_pairs() {
    for code in [
        "direct_active_stall_probe_retry_selected",
        "direct_active_stall_probe_retry_budget_exhausted",
        "direct_active_stall_probe_launched",
        "direct_active_stall_probe_finished",
        "direct_terminal_fail_closed",
    ] {
        let row = json!({"ts_unix_ms":15,"event_code":code,"fields":{}});
        assert!(
            checked(&[planner(10), row, terminal(20)]).is_err(),
            "{code}"
        );
    }
}

#[test]
fn hard_and_omitted_routes_cannot_gain_imported_outcomes_and_zero_bytes_are_zero_reward() {
    let mut value = planner(10);
    value["fields"]["planner_ranked_candidates"][0]["belief_hard_blocked"] = json!(true);
    assert!(checked(&[value, terminal(20)]).is_err());
    let mut value = planner(10);
    value["fields"]["planner_resolved_order"] = json!(["two"]);
    assert!(checked(&[value, terminal(20)]).is_err());
    let mut value = planner(10);
    value["fields"]["planner_resolved_order"] = json!(["absent"]);
    assert!(checked(&[value, terminal(20)]).is_err());
    let mut value = terminal(20);
    value["fields"]["bytes_sent"] = json!(0);
    value["fields"]["signal"] = json!("SuccessDegraded");
    value["fields"]
        .as_object_mut()
        .unwrap()
        .remove("latency_ms");
    let out = checked(&[planner(10), value]).unwrap();
    assert_eq!(out["replay"]["decisions"][0]["logged_progress_reward"], 0.0);
    assert!(out["replay"]["decisions"][0]["reported_latency_ms"].is_null());
    assert_eq!(out["replay"]["reported_latency_rows"], 0);
    assert!(out["observed_failure_to_progress_ms"].is_null());
}

#[test]
fn content_hash_complete_file_interval_metadata_and_rows_are_bound_before_replay() {
    let input = tape(&[planner(10), terminal(20)]);
    let meta = metadata(&input, 10, 20);
    for mutated in [
        {
            let mut m = meta.clone();
            m["source_sha256"] = json!("0".repeat(64));
            m
        },
        {
            let mut m = meta.clone();
            m["source_started_unix_ms"] = json!(11);
            m
        },
        {
            let mut m = meta.clone();
            m["source_finished_unix_ms"] = json!(21);
            m
        },
        {
            let mut m = meta.clone();
            m["source_commit"] = json!("fake");
            m
        },
        {
            let mut m = meta.clone();
            m["unexpected"] = json!(true);
            m
        },
        {
            let mut m = meta.clone();
            m["schema_version"] = json!(2);
            m
        },
    ] {
        assert!(report(&input, &serde_json::to_vec(&mutated).unwrap()).is_err());
    }
    let malformed = b"{\"private_token\":\"do-not-echo\"}\n";
    assert_eq!(
        report(
            malformed,
            &serde_json::to_vec(&metadata(malformed, 10, 20)).unwrap()
        )
        .unwrap_err(),
        "native replay row schema rejected"
    );
    assert!(checked(&[planner(20), terminal(10)]).is_err());
    let late = json!({"ts_unix_ms":7*24*60*60*1000+21_u64,"event_code":"ignored","fields":{}});
    assert!(checked(&[planner(10), terminal(20), late]).is_err());
    let mut missing = terminal(20);
    missing["fields"]
        .as_object_mut()
        .unwrap()
        .remove("bytes_sent");
    assert!(checked(&[planner(10), missing]).is_err());
    let mut missing = planner(10);
    missing["fields"] = json!({"diagnostics":"private"});
    assert!(checked(&[missing, terminal(20)]).is_err());
    let mut missing = planner(10);
    missing["fields"]["planner_ranked_candidates"][0]
        .as_object_mut()
        .unwrap()
        .remove("belief_hard_blocked");
    assert!(checked(&[missing, terminal(20)]).is_err());
}

#[test]
fn bounded_input_line_row_and_candidate_budgets_reject_without_partial_report() {
    assert!(report(&vec![b' '; MAX_INPUT + 1], b"{}").is_err());
    let row = json!({"ts_unix_ms":1,"event_code":"ignored","fields":{}});
    assert!(checked(&vec![row; offline_replay::MAX_EVENTS + 1]).is_err());
    let huge =
        json!({"ts_unix_ms":1,"event_code":"ignored","fields":{"large":"x".repeat(MAX_LINE)}});
    assert!(checked(&[huge]).is_err());
    let mut value = planner(10);
    value["fields"]["planner_ranked_candidates"]=json!((0..17).map(|n|json!({"strategy":format!("route{n}"),"estimated_reward":0.5,"belief_hard_blocked":false})).collect::<Vec<_>>());
    assert!(checked(&[value, terminal(20)]).is_err());
    let hybrid = json!({"ts_unix_ms":1,"event_code":"hybrid_route_selected","fields":{}});
    assert!(checked(&[hybrid]).is_err());
}

#[cfg(unix)]
#[test]
fn descriptor_custody_refuses_public_or_symlink_inputs_and_never_overwrites_receipts() {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = Dir(std::env::temp_dir().join(format!(
        "aegis-private-replay-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )));
    std::fs::create_dir(&dir.0).unwrap();
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let path = dir.0.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        path
    };
    let input = tape(&[planner(10), terminal(20)]);
    let trace = write("events.jsonl", &input);
    let meta = write(
        "metadata.json",
        &serde_json::to_vec(&metadata(&input, 10, 20)).unwrap(),
    );
    let output = dir.0.join("report.json");
    run(&trace, &meta, &output).unwrap();
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let original = std::fs::read(&output).unwrap();
    assert!(run(&trace, &meta, &output).is_err());
    assert_eq!(std::fs::read(&output).unwrap(), original);
    let alias = dir.0.join("alias.jsonl");
    std::os::unix::fs::symlink(&trace, &alias).unwrap();
    let refused = dir.0.join("refused.json");
    assert!(run(&alias, &meta, &refused).is_err());
    assert!(!refused.exists());
    std::fs::set_permissions(&trace, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(run(&trace, &meta, &refused).is_err());
    assert!(!refused.exists());
}
