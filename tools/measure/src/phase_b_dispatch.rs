use crate::artifact::{read_json, read_jsonl, write_json, write_text};
use crate::cli::Command;
use crate::phase_b_baseline::{phase_b_baseline_markdown, phase_b_baseline_review};
use crate::phase_b_runtime::{
    phase_b_active_probe_markdown, phase_b_active_probe_review, phase_b_live_evidence_markdown,
    phase_b_live_evidence_review, phase_b_master_plan_status, phase_b_master_plan_status_markdown,
    phase_b_relay_shape_markdown, phase_b_relay_shape_review, phase_b_runtime_evidence_manifest,
    phase_b_runtime_evidence_manifest_check, phase_b_runtime_evidence_manifest_markdown,
    phase_b_tls_wire_markdown, phase_b_tls_wire_review, PhaseBRuntimeEvidenceManifestPaths,
};
use crate::phase_b_score::{
    phase_b_score_parity_gate, phase_b_score_parity_gate_markdown, PhaseBScoreParityGateEvidence,
    PhaseBScoreParityGateInputs,
};

pub fn is_phase_b(command: &Command) -> bool {
    matches!(
        command,
        Command::PhaseBBaselineReview { .. }
            | Command::PhaseBTlsWireReview { .. }
            | Command::PhaseBRelayShapeReview { .. }
            | Command::PhaseBActiveProbeReview { .. }
            | Command::PhaseBLiveEvidenceReview { .. }
            | Command::PhaseBRuntimeEvidenceManifest { .. }
            | Command::PhaseBRuntimeEvidenceManifestCheck { .. }
            | Command::PhaseBMasterPlanStatus { .. }
            | Command::PhaseBScoreParityGate { .. }
    )
}

pub fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::PhaseBBaselineReview {
            phase_a_exit_json,
            calibration_json,
            gate_review_json,
            classifier_json,
            output_json,
            output_markdown,
        } => {
            let review = phase_b_baseline_review(
                &read_json(&phase_a_exit_json)?,
                &read_json(&calibration_json)?,
                &read_json(&gate_review_json)?,
                &read_json(&classifier_json)?,
            );
            write_json(&output_json, &review)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_b_baseline_markdown(&review))?;
            }
        }
        Command::PhaseBTlsWireReview {
            runtime_events_jsonl,
            output_json,
            output_markdown,
        } => {
            let review = phase_b_tls_wire_review(&read_jsonl(&runtime_events_jsonl)?);
            write_json(&output_json, &review)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_b_tls_wire_markdown(&review))?;
            }
            if review["status"].as_str() != Some("PASS") {
                std::process::exit(1);
            }
        }
        Command::PhaseBRelayShapeReview {
            runtime_events_jsonl,
            output_json,
            output_markdown,
            require_diversity,
        } => {
            let review =
                phase_b_relay_shape_review(&read_jsonl(&runtime_events_jsonl)?, require_diversity);
            write_json(&output_json, &review)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_b_relay_shape_markdown(&review))?;
            }
            if review["status"].as_str() != Some("PASS") {
                std::process::exit(1);
            }
        }
        Command::PhaseBActiveProbeReview {
            runtime_events_jsonl,
            output_json,
            output_markdown,
            require_finished_probe,
        } => {
            let review = phase_b_active_probe_review(
                &read_jsonl(&runtime_events_jsonl)?,
                require_finished_probe,
            );
            write_json(&output_json, &review)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_b_active_probe_markdown(&review))?;
            }
            if review["status"].as_str() != Some("PASS") {
                std::process::exit(1);
            }
        }
        Command::PhaseBLiveEvidenceReview {
            baseline_json,
            tls_wire_json,
            relay_shape_json,
            active_probe_json,
            output_json,
            output_markdown,
        } => {
            let review = phase_b_live_evidence_review(
                &read_json(&baseline_json)?,
                &read_json(&tls_wire_json)?,
                &read_json(&relay_shape_json)?,
                &read_json(&active_probe_json)?,
            );
            write_json(&output_json, &review)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_b_live_evidence_markdown(&review))?;
            }
            if review["status"].as_str() != Some("LIVE_EVIDENCE_READY") {
                std::process::exit(1);
            }
        }
        Command::PhaseBRuntimeEvidenceManifest {
            tls_wire_json,
            relay_shape_json,
            active_probe_json,
            live_evidence_json,
            output_json,
            output_markdown,
            artifact_dir,
            runtime_events_jsonl,
            baseline_json,
        } => {
            let manifest = phase_b_runtime_evidence_manifest(
                &read_json(&tls_wire_json)?,
                &read_json(&relay_shape_json)?,
                &read_json(&active_probe_json)?,
                &read_json(&live_evidence_json)?,
                PhaseBRuntimeEvidenceManifestPaths {
                    tls_wire_json: &tls_wire_json,
                    relay_shape_json: &relay_shape_json,
                    active_probe_json: &active_probe_json,
                    live_evidence_json: &live_evidence_json,
                    artifact_dir: artifact_dir.as_deref(),
                    runtime_events_jsonl: runtime_events_jsonl.as_deref(),
                    baseline_json: baseline_json.as_deref(),
                },
            );
            write_json(&output_json, &manifest)?;
            if let Some(path) = output_markdown {
                write_text(
                    &path,
                    &phase_b_runtime_evidence_manifest_markdown(&manifest),
                )?;
            }
            if manifest["status"].as_str() != Some("BUNDLE_READY") {
                std::process::exit(1);
            }
        }
        Command::PhaseBRuntimeEvidenceManifestCheck { manifest_json } => {
            phase_b_runtime_evidence_manifest_check(&read_json(&manifest_json)?)?;
        }
        Command::PhaseBMasterPlanStatus {
            baseline_json,
            runtime_manifest_json,
            output_json,
            output_markdown,
        } => {
            let status = phase_b_master_plan_status(
                &read_json(&baseline_json)?,
                &read_json(&runtime_manifest_json)?,
            );
            write_json(&output_json, &status)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_b_master_plan_status_markdown(&status))?;
            }
            if status["status"].as_str() != Some("PHASE_B_RUNTIME_EVIDENCE_READY") {
                std::process::exit(1);
            }
        }
        Command::PhaseBScoreParityGate {
            baseline_json,
            runtime_manifest_json,
            transport_camouflage_validation_json,
            witness_wire_correlation_json,
            two_vps_parity_json,
            classifier_summary_json,
            live_manifest_json,
            output_json,
            output_markdown,
        } => {
            let gate = phase_b_score_parity_gate(
                PhaseBScoreParityGateEvidence {
                    baseline: &read_json(&baseline_json)?,
                    runtime_manifest: &read_json(&runtime_manifest_json)?,
                    transport_camouflage: &read_json(&transport_camouflage_validation_json)?,
                    witness_wire: &read_json(&witness_wire_correlation_json)?,
                    two_vps_parity: &read_json(&two_vps_parity_json)?,
                    classifier_summary: &read_json(&classifier_summary_json)?,
                    live_manifest: &read_json(&live_manifest_json)?,
                },
                PhaseBScoreParityGateInputs {
                    baseline_json: &baseline_json,
                    runtime_manifest_json: &runtime_manifest_json,
                    transport_camouflage_validation_json: &transport_camouflage_validation_json,
                    witness_wire_correlation_json: &witness_wire_correlation_json,
                    two_vps_parity_json: &two_vps_parity_json,
                    classifier_summary_json: &classifier_summary_json,
                    live_manifest_json: &live_manifest_json,
                },
            );
            write_json(&output_json, &gate)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_b_score_parity_gate_markdown(&gate))?;
            }
            if gate["status"].as_str() != Some("PHASE_B_SCORE_PARITY_READY") {
                std::process::exit(1);
            }
        }
        _ => unreachable!("phase b dispatch received non-phase-b command"),
    }
    Ok(())
}
