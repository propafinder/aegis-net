use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

mod contract;
mod output;

pub use contract::external_calibration_contract_check;
pub use output::external_calibration_markdown;

pub fn external_calibration_summary(
    witness_events: &[Value],
    adversarial_events: &[Value],
) -> Value {
    let witness = summarize_witness_calibration(witness_events);
    let adversarial = summarize_adversarial_calibration(adversarial_events);
    let mut reasons = Vec::new();
    if witness["records"].as_u64().unwrap_or(0) == 0 {
        reasons.push("missing-witness-events");
    }
    if adversarial["records"].as_u64().unwrap_or(0) == 0 {
        reasons.push("missing-adversarial-events");
    }
    if adversarial["records"].as_u64().unwrap_or(0) > 0
        && adversarial["measured_records"].as_u64().unwrap_or(0) == 0
    {
        reasons.push("adversarial-events-are-planned-only");
    }

    json!({
        "event": "external_calibration_summary",
        "schema_version": 1,
        "generated_at_unix_ms": current_unix_ms(),
        "freshness_half_life_secs": 86400,
        "witness": witness,
        "adversarial": adversarial,
        "verdict": {
            "status": if reasons.is_empty() { "MEASURED" } else { "PARTIAL" },
            "acceptance_degraded": !reasons.is_empty(),
            "reasons": reasons,
        },
    })
}

#[derive(Default)]
struct WitnessCalibrationAccumulator {
    records: u64,
    combined_sum: f64,
    ja3_sum: f64,
    alpn_sum: f64,
    sni_sum: f64,
}

impl WitnessCalibrationAccumulator {
    fn add(&mut self, event: &Value) {
        let score = &event["score"];
        self.records += 1;
        self.combined_sum += score["combined"].as_f64().unwrap_or(0.0);
        self.ja3_sum += score["ja3_present"].as_f64().unwrap_or(0.0);
        self.alpn_sum += score["alpn_match"].as_f64().unwrap_or(0.0);
        self.sni_sum += score["sni_structure"].as_f64().unwrap_or(0.0);
    }

    fn as_json(&self, label: &str) -> Value {
        let denom = self.records.max(1) as f64;
        json!({
            "label": label,
            "records": self.records,
            "combined_avg": round3(self.combined_sum / denom),
            "ja3_present_avg": round3(self.ja3_sum / denom),
            "alpn_match_avg": round3(self.alpn_sum / denom),
            "sni_structure_avg": round3(self.sni_sum / denom),
        })
    }
}

fn summarize_witness_calibration(events: &[Value]) -> Value {
    let mut groups: BTreeMap<String, WitnessCalibrationAccumulator> = BTreeMap::new();
    let mut total = 0u64;
    for event in events {
        if event["event"].as_str() != Some("witness_tls_classification") {
            continue;
        }
        let label = event["label"].as_str().unwrap_or("unknown").to_string();
        groups.entry(label).or_default().add(event);
        total += 1;
    }
    let labels = groups
        .iter()
        .map(|(label, group)| group.as_json(label))
        .collect::<Vec<_>>();
    let min_combined = labels
        .iter()
        .filter_map(|label| label["combined_avg"].as_f64())
        .min_by(|a, b| a.total_cmp(b));
    json!({
        "records": total,
        "labels": labels,
        "min_combined_avg": min_combined,
    })
}

#[derive(Default)]
struct AdversarialCalibrationAccumulator {
    records: u64,
    measured: u64,
    planned: u64,
    passed: u64,
    failed: u64,
    thresholds: Vec<f64>,
    profiles: BTreeSet<String>,
}

impl AdversarialCalibrationAccumulator {
    fn add(&mut self, event: &Value) {
        let status = event["status"]
            .as_str()
            .unwrap_or("UNKNOWN")
            .to_ascii_uppercase();
        self.records += 1;
        if let Some(threshold) = event["threshold"].as_f64() {
            self.thresholds.push(threshold);
        }
        if let Some(profile) = event["network_profile"].as_str() {
            self.profiles.insert(profile.to_string());
        }
        match status.as_str() {
            "PLANNED" => self.planned += 1,
            "PASS" | "PASSED" | "SUCCEEDED" | "SUCCESS" => {
                self.measured += 1;
                self.passed += 1;
            }
            "FAIL" | "FAILED" | "BLOCKED" | "TIMEOUT" => {
                self.measured += 1;
                self.failed += 1;
            }
            _ => self.measured += 1,
        }
    }

    fn as_json(&self, transport: &str) -> Value {
        let pass_rate =
            (self.measured > 0).then(|| round3(self.passed as f64 / self.measured as f64));
        let threshold = self
            .thresholds
            .iter()
            .copied()
            .max_by(|a, b| a.total_cmp(b))
            .map(round3);
        // Actually evaluate the threshold.
        //
        // This used to emit `pass_rate` and `threshold` side by side and stop
        // there — the artifact printed an acceptance bar it never applied, and
        // downstream summaries read "a threshold is present" as "the threshold
        // was met". A bar nobody compares against is not an acceptance gate.
        //
        // `verdict` is explicit and three-valued: a missing threshold or zero
        // measurements is INSUFFICIENT_EVIDENCE, never a silent pass.
        let (meets_threshold, verdict) = match (pass_rate, threshold) {
            (Some(rate), Some(bar)) => {
                (Some(rate >= bar), if rate >= bar { "PASS" } else { "FAIL" })
            }
            (None, _) => (None, "INSUFFICIENT_EVIDENCE"),
            (Some(_), None) => (None, "INSUFFICIENT_EVIDENCE"),
        };
        json!({
            "transport": transport,
            "records": self.records,
            "measured": self.measured,
            "planned": self.planned,
            "passed": self.passed,
            "failed": self.failed,
            "pass_rate": pass_rate,
            "threshold": threshold,
            "meets_threshold": meets_threshold,
            "verdict": verdict,
            "verdict_reason": match (pass_rate, threshold) {
                (None, _) => Value::String("no_measured_adversarial_records".into()),
                (Some(_), None) => {
                    Value::String("no_threshold_declared_in_adversarial_events".into())
                }
                _ => Value::Null,
            },
            "network_profiles": self.profiles.iter().collect::<Vec<_>>(),
        })
    }
}

fn summarize_adversarial_calibration(events: &[Value]) -> Value {
    let mut groups: BTreeMap<String, AdversarialCalibrationAccumulator> = BTreeMap::new();
    let mut total = 0u64;
    for event in events {
        if !event["event"]
            .as_str()
            .is_some_and(|event| event.starts_with("adversarial_"))
        {
            continue;
        }
        let transport = event["transport"]
            .as_str()
            .or_else(|| event["scenario"].as_str())
            .unwrap_or("unknown")
            .to_string();
        groups.entry(transport).or_default().add(event);
        total += 1;
    }
    let transports = groups
        .iter()
        .map(|(transport, group)| group.as_json(transport))
        .collect::<Vec<_>>();
    json!({
        "records": total,
        "measured_records": transports.iter().map(|item| item["measured"].as_u64().unwrap_or(0)).sum::<u64>(),
        "planned_records": transports.iter().map(|item| item["planned"].as_u64().unwrap_or(0)).sum::<u64>(),
        "transports": transports,
    })
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod adversarial_threshold_tests {
    use super::*;

    fn accumulator(passed: u64, failed: u64, threshold: Option<f64>) -> Value {
        let mut acc = AdversarialCalibrationAccumulator::default();
        let event = |status: &str| {
            let mut e = json!({
                "event": "adversarial_scenario",
                "transport": "https_ws",
                "network_profile": "clean_fiber",
                "status": status,
            });
            if let Some(bar) = threshold {
                e["threshold"] = json!(bar);
            }
            e
        };
        for _ in 0..passed {
            acc.add(&event("PASS"));
        }
        for _ in 0..failed {
            acc.add(&event("FAIL"));
        }
        acc.as_json("https_ws")
    }

    // REGRESSION: the artifact printed `pass_rate` next to `threshold` and never
    // compared them, so an acceptance bar was published that nothing applied and
    // readers took "a threshold is present" for "the threshold was met".
    #[test]
    fn threshold_is_actually_evaluated() {
        let above = accumulator(9, 1, Some(0.85));
        assert_eq!(above["pass_rate"], 0.9);
        assert_eq!(above["meets_threshold"], true);
        assert_eq!(above["verdict"], "PASS");

        let below = accumulator(5, 5, Some(0.85));
        assert_eq!(below["pass_rate"], 0.5);
        assert_eq!(below["meets_threshold"], false);
        assert_eq!(
            below["verdict"], "FAIL",
            "a rate under the declared bar must not read as a pass"
        );
    }

    #[test]
    fn missing_threshold_or_measurements_is_not_a_pass() {
        let no_threshold = accumulator(10, 0, None);
        assert_eq!(no_threshold["verdict"], "INSUFFICIENT_EVIDENCE");
        assert!(no_threshold["meets_threshold"].is_null());
        assert_eq!(
            no_threshold["verdict_reason"],
            "no_threshold_declared_in_adversarial_events"
        );

        let nothing_measured = accumulator(0, 0, Some(0.85));
        assert_eq!(nothing_measured["verdict"], "INSUFFICIENT_EVIDENCE");
        assert_eq!(
            nothing_measured["verdict_reason"],
            "no_measured_adversarial_records"
        );
    }
}
