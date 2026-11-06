use crate::artifact::{read_json, write_json, write_text};
use crate::cli::Command;
use crate::phase_a::{
    phase_a_exit_markdown, phase_a_exit_review, phase_a_measure_gate_contract_check,
    phase_a_measure_gate_markdown, phase_a_measure_gate_review,
};

pub fn is_phase_a(command: &Command) -> bool {
    matches!(
        command,
        Command::PhaseAExitReview { .. }
            | Command::PhaseAMeasureGateReview { .. }
            | Command::PhaseAMeasureGateContractCheck { .. }
    )
}

pub fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::PhaseAExitReview {
            gate_review_json,
            calibration_json,
            classifier_json,
            threat_model,
            knowledge_architecture,
            output_json,
            output_markdown,
        } => {
            let review = phase_a_exit_review(
                &read_json(&gate_review_json)?,
                &read_json(&calibration_json)?,
                &read_json(&classifier_json)?,
                threat_model.as_deref(),
                knowledge_architecture.as_deref(),
            );
            write_json(&output_json, &review)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_a_exit_markdown(&review))?;
            }
        }
        Command::PhaseAMeasureGateReview {
            output_dir,
            skip_knowledge_check,
            applied,
        } => {
            let review = phase_a_measure_gate_review(&output_dir, skip_knowledge_check, applied)?;
            write_json(&output_dir.join("phase-a-gate-review.json"), &review)?;
            write_text(
                &output_dir.join("phase-a-gate-review.md"),
                &phase_a_measure_gate_markdown(&review),
            )?;
        }
        Command::PhaseAMeasureGateContractCheck {
            gate,
            measured_gate,
            matrix_gate,
            imported_gate,
            imported_witness_gate,
        } => {
            phase_a_measure_gate_contract_check(
                &gate,
                &measured_gate,
                &matrix_gate,
                &imported_gate,
                &imported_witness_gate,
            )?;
        }
        _ => unreachable!("phase a dispatch received non-phase-a command"),
    }
    Ok(())
}
