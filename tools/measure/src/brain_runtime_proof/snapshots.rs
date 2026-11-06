use aegis_core::{
    ExternalAdversarialCalibration, ExternalCalibrationSnapshot, ExternalCalibrationVerdict,
    ExternalKnowledgePrior, ExternalWitnessCalibration,
};

use super::support::unix_ms;

pub(super) fn fresh_snapshot_for_https_ws() -> ExternalCalibrationSnapshot {
    ExternalCalibrationSnapshot {
        schema_version: 1,
        source: "external_calibration_snapshot".to_string(),
        generated_at_unix_ms: Some(unix_ms()),
        freshness_half_life_secs: Some(86_400),
        witness: vec![ExternalWitnessCalibration {
            label: "https_ws".to_string(),
            records: 4,
            combined_avg: 0.95,
            ja3_present_avg: 1.0,
            alpn_match_avg: 0.95,
            sni_structure_avg: 0.9,
        }],
        adversarial: vec![ExternalAdversarialCalibration {
            transport: "https_ws".to_string(),
            records: 4,
            measured: 4,
            planned: 0,
            passed: 4,
            failed: 0,
            pass_rate: Some(1.0),
            threshold: Some(0.85),
        }],
        knowledge: vec![ExternalKnowledgePrior {
            target_class: "https_ws".to_string(),
            region_id: Some("desktop_core_lab".to_string()),
            score: 0.9,
            confidence: 0.9,
            hard_excluded: false,
            fail_closed: false,
            generated_at_unix_ms: Some(unix_ms()),
        }],
        verdict: ExternalCalibrationVerdict {
            status: "MEASURED".to_string(),
            acceptance_degraded: false,
            reasons: Vec::new(),
        },
    }
}

pub(super) fn stale_snapshot_for_https_ws() -> ExternalCalibrationSnapshot {
    let mut snapshot = fresh_snapshot_for_https_ws();
    snapshot.generated_at_unix_ms = Some(1);
    snapshot.freshness_half_life_secs = Some(1);
    for prior in &mut snapshot.knowledge {
        prior.generated_at_unix_ms = Some(1);
    }
    snapshot
}

pub(super) fn weak_penalty_snapshot_for_https_ws() -> ExternalCalibrationSnapshot {
    let mut snapshot = fresh_snapshot_for_https_ws();
    snapshot.witness.clear();
    snapshot.adversarial.clear();
    snapshot.knowledge = vec![ExternalKnowledgePrior {
        target_class: "https_ws".to_string(),
        region_id: Some("desktop_core_lab".to_string()),
        score: 0.35,
        confidence: 0.25,
        hard_excluded: false,
        fail_closed: false,
        generated_at_unix_ms: Some(unix_ms()),
    }];
    snapshot
}

pub(super) fn high_confidence_fail_closed_snapshot_for_https_ws() -> ExternalCalibrationSnapshot {
    let mut snapshot = fresh_snapshot_for_https_ws();
    snapshot.witness.clear();
    snapshot.adversarial.clear();
    snapshot.knowledge = vec![ExternalKnowledgePrior {
        target_class: "https_ws".to_string(),
        region_id: Some("desktop_core_lab".to_string()),
        score: 0.0,
        confidence: 0.95,
        hard_excluded: true,
        fail_closed: true,
        generated_at_unix_ms: Some(unix_ms()),
    }];
    snapshot
}
