use std::{collections::BTreeSet, fs, path::Path};

use serde_json::Value;

pub fn adversarial_runner_contract_check(tmp: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let runner = read_jsonl(&tmp.join("runner.jsonl"))?;
    let wrapper = read_jsonl(&tmp.join("wrapper.jsonl"))?;
    let measured_pass = read_jsonl(&tmp.join("measured-pass.jsonl"))?;
    let measured_fail = read_jsonl(&tmp.join("measured-fail.jsonl"))?;
    let measured_matrix = read_jsonl(&tmp.join("measured-matrix.jsonl"))?;

    ensure(runner.len() == 1, "runner length")?;
    ensure(
        runner[0]["event"].as_str() == Some("adversarial_scenario_planned"),
        "runner event",
    )?;
    ensure(
        runner[0]["scenario"].as_str() == Some("legacy_tls"),
        "runner scenario",
    )?;
    ensure(
        runner[0]["network_profile"].as_str() == Some("clean-fiber"),
        "runner profile",
    )?;
    ensure(
        runner[0]["threshold"].as_f64() == Some(0.85),
        "runner threshold",
    )?;
    ensure(
        runner[0]["status"].as_str() == Some("PLANNED"),
        "runner status",
    )?;

    ensure(wrapper.len() == 1, "wrapper length")?;
    ensure(
        wrapper[0]["scenario"].as_str() == Some("masque_derived"),
        "wrapper scenario",
    )?;
    ensure(
        wrapper[0]["network_profile"].as_str() == Some("mobile-lossy"),
        "wrapper profile",
    )?;
    ensure(
        wrapper[0]["threshold"].as_f64() == Some(0.85),
        "wrapper threshold",
    )?;

    ensure(measured_pass.len() == 1, "measured pass length")?;
    ensure(
        measured_pass[0]["event"].as_str() == Some("adversarial_scenario_measured"),
        "measured pass event",
    )?;
    ensure(
        measured_pass[0]["status"].as_str() == Some("PASS"),
        "measured pass status",
    )?;
    ensure(
        measured_pass[0]["reason"].as_str() == Some("probe-command-succeeded"),
        "measured pass reason",
    )?;
    ensure(
        measured_pass[0]["returncode"].as_i64() == Some(0),
        "measured pass rc",
    )?;

    ensure(measured_fail.len() == 1, "measured fail length")?;
    ensure(
        measured_fail[0]["status"].as_str() == Some("FAIL"),
        "measured fail status",
    )?;
    ensure(
        measured_fail[0]["reason"].as_str() == Some("probe-command-failed"),
        "measured fail reason",
    )?;
    ensure(
        measured_fail[0]["returncode"].as_i64() == Some(7),
        "measured fail rc",
    )?;

    let scenarios = measured_matrix
        .iter()
        .filter_map(|event| event["scenario"].as_str())
        .collect::<BTreeSet<_>>();
    let profiles = measured_matrix
        .iter()
        .filter_map(|event| event["network_profile"].as_str())
        .collect::<BTreeSet<_>>();
    ensure(measured_matrix.len() == 16, "matrix length")?;
    ensure(
        scenarios == BTreeSet::from(["grpc_stream", "https_ws", "legacy_tls", "masque_derived"]),
        "matrix scenarios",
    )?;
    ensure(
        profiles
            == BTreeSet::from([
                "clean-fiber",
                "congested-wifi",
                "corporate-middlebox",
                "mobile-lossy",
            ]),
        "matrix profiles",
    )?;
    ensure(
        measured_matrix
            .iter()
            .all(|event| event["status"].as_str() == Some("PASS")),
        "matrix status",
    )?;
    Ok(())
}

fn read_jsonl(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    for (index, line) in fs::read_to_string(path)?.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        records.push(
            serde_json::from_str::<Value>(line)
                .map_err(|err| format!("{}:{} invalid JSONL: {err}", path.display(), index + 1))?,
        );
    }
    Ok(records)
}

fn ensure(condition: bool, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(format!("contract assertion failed: {message}").into())
    }
}
