use serde_json::Value;

pub fn external_calibration_markdown(summary: &Value) -> String {
    let mut lines = vec![
        "# External Calibration Summary".to_string(),
        String::new(),
        "## Witness".to_string(),
        String::new(),
        "| Label | Records | Combined | JA3 | ALPN | SNI |".to_string(),
        "|---|---:|---:|---:|---:|---:|".to_string(),
    ];
    if let Some(labels) = summary["witness"]["labels"].as_array() {
        for label in labels {
            lines.push(format!(
                "| {} | {} | {:.3} | {:.3} | {:.3} | {:.3} |",
                label["label"].as_str().unwrap_or("unknown"),
                label["records"].as_u64().unwrap_or(0),
                label["combined_avg"].as_f64().unwrap_or(0.0),
                label["ja3_present_avg"].as_f64().unwrap_or(0.0),
                label["alpn_match_avg"].as_f64().unwrap_or(0.0),
                label["sni_structure_avg"].as_f64().unwrap_or(0.0),
            ));
        }
    }
    if summary["witness"]["labels"]
        .as_array()
        .is_none_or(|labels| labels.is_empty())
    {
        lines.push("| none | 0 | n/a | n/a | n/a | n/a |".to_string());
    }
    lines.extend([
        String::new(),
        "## Adversarial".to_string(),
        String::new(),
        "| Transport | Records | Measured | Planned | Passed | Failed | Pass Rate | Threshold |"
            .to_string(),
        "|---|---:|---:|---:|---:|---:|---:|---:|".to_string(),
    ]);
    if let Some(transports) = summary["adversarial"]["transports"].as_array() {
        for transport in transports {
            lines.push(format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                transport["transport"].as_str().unwrap_or("unknown"),
                transport["records"].as_u64().unwrap_or(0),
                transport["measured"].as_u64().unwrap_or(0),
                transport["planned"].as_u64().unwrap_or(0),
                transport["passed"].as_u64().unwrap_or(0),
                transport["failed"].as_u64().unwrap_or(0),
                format_optional_f64(transport["pass_rate"].as_f64()),
                format_optional_f64(transport["threshold"].as_f64()),
            ));
        }
    }
    if summary["adversarial"]["transports"]
        .as_array()
        .is_none_or(|transports| transports.is_empty())
    {
        lines.push("| none | 0 | 0 | 0 | 0 | 0 | n/a | n/a |".to_string());
    }
    lines.extend([
        String::new(),
        "## Verdict".to_string(),
        String::new(),
        format!(
            "- Status: `{}`",
            summary["verdict"]["status"].as_str().unwrap_or("UNKNOWN")
        ),
        format!(
            "- Acceptance degraded: `{}`",
            summary["verdict"]["acceptance_degraded"]
                .as_bool()
                .unwrap_or(false)
        ),
        format!(
            "- Reasons: `{}`",
            join_strings(&summary["verdict"]["reasons"])
        ),
        String::new(),
    ]);
    lines.join("\n")
}

fn format_optional_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |value| format!("{value:.3}"))
}

fn join_strings(value: &Value) -> String {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|joined| !joined.is_empty())
        .unwrap_or_else(|| "none".to_string())
}
