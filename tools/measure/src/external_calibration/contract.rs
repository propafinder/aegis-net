use serde_json::Value;

pub fn external_calibration_contract_check(
    summary: &Value,
    markdown: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure(
        summary["event"].as_str() == Some("external_calibration_summary"),
        "unexpected calibration event",
    )?;
    ensure(
        summary["schema_version"].as_u64() == Some(1),
        "schema version",
    )?;
    ensure(
        summary["witness"]["records"].as_u64() == Some(2),
        "witness records",
    )?;
    ensure(
        summary["witness"]["labels"][0]["label"].as_str() == Some("https_ws"),
        "witness label",
    )?;
    ensure(
        summary["witness"]["labels"][0]["combined_avg"].as_f64() == Some(0.7),
        "witness combined avg",
    )?;
    let transports = summary["adversarial"]["transports"]
        .as_array()
        .ok_or("missing transports")?;
    let https_ws = transports
        .iter()
        .find(|entry| entry["transport"].as_str() == Some("https_ws"))
        .ok_or("missing https_ws")?;
    let legacy_tls = transports
        .iter()
        .find(|entry| entry["transport"].as_str() == Some("legacy_tls"))
        .ok_or("missing legacy_tls")?;
    ensure(
        https_ws["pass_rate"].as_f64() == Some(0.5),
        "https_ws pass rate",
    )?;
    ensure(
        https_ws["measured"].as_u64() == Some(2),
        "https_ws measured",
    )?;
    ensure(
        legacy_tls["planned"].as_u64() == Some(1),
        "legacy_tls planned",
    )?;
    ensure(
        summary["verdict"]["status"].as_str() == Some("MEASURED"),
        "verdict status",
    )?;
    ensure(
        markdown.contains("External Calibration Summary"),
        "markdown title",
    )?;
    Ok(())
}

fn ensure(condition: bool, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string().into())
    }
}
