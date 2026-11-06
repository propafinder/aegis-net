use aegis_core::{
    signals::FailSignal, ExternalCalibrationSnapshot, StateSnapshot, StrategyStatsV2,
};
use serde_json::json;

#[test]
fn parses_external_calibration_summary_artifact() {
    let value = json!({
        "event": "external_calibration_summary",
        "schema_version": 1,
        "witness": {
            "labels": [
                {
                    "label": "https_ws",
                    "records": 2,
                    "combined_avg": 0.7,
                    "ja3_present_avg": 1.0,
                    "alpn_match_avg": 0.75,
                    "sni_structure_avg": 0.55
                }
            ]
        },
        "adversarial": {
            "transports": [
                {
                    "transport": "https_ws",
                    "records": 2,
                    "measured": 2,
                    "planned": 0,
                    "passed": 1,
                    "failed": 1,
                    "pass_rate": 0.5,
                    "threshold": 0.85
                }
            ]
        },
        "verdict": {
            "status": "MEASURED",
            "acceptance_degraded": false,
            "reasons": []
        }
    });

    let snapshot = ExternalCalibrationSnapshot::from_summary_value(&value);

    assert_eq!(snapshot.source, "external_calibration_summary");
    assert!(snapshot.has_measured_external_signal());
    assert_eq!(snapshot.witness[0].label, "https_ws");
    assert_eq!(snapshot.adversarial[0].pass_rate, Some(0.5));
    assert!(!snapshot.verdict.acceptance_degraded);
}

#[test]
fn state_snapshot_reads_without_external_calibration() {
    let snapshot: StateSnapshot = serde_json::from_value(json!({
        "schema_version": 2
    }))
    .expect("old state snapshot remains readable");

    assert!(snapshot.external_calibration.is_none());
}

#[test]
fn external_classifier_hint_can_penalize_stats_without_breaking_fallback() {
    let mut stats = StrategyStatsV2::default();
    stats.record(
        &FailSignal::ExternalClassifierHint {
            source: "witness".to_string(),
            score_milli: 250,
            confidence_milli: 900,
            hard_block: true,
        },
        None,
        0,
    );

    assert_eq!(stats.dpi_blocks, 1);
    assert!(stats.fitness_score < 0.5);
}
