use std::fs;

use crate::artifact::{read_json, read_jsonl, read_optional_jsonl, write_json, write_text};
use crate::cli::Command;
use crate::external_calibration::{
    external_calibration_contract_check, external_calibration_markdown,
    external_calibration_summary,
};
use crate::hostile_classifier::{hostile_summary, hostile_summary_markdown};

pub fn is_calibration(command: &Command) -> bool {
    matches!(
        command,
        Command::HostileSummary { .. }
            | Command::ExternalCalibrationSummary { .. }
            | Command::ExternalCalibrationContractCheck { .. }
    )
}

pub fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::HostileSummary {
            adversarial_jsonl,
            classifier_jsonl,
            output_json,
            output_markdown,
        } => {
            let summary = hostile_summary(
                &read_jsonl(&adversarial_jsonl)?,
                &read_optional_jsonl(classifier_jsonl.as_deref())?,
            );
            write_json(&output_json, &summary)?;
            if let Some(path) = output_markdown {
                write_text(&path, &hostile_summary_markdown(&summary))?;
            }
        }
        Command::ExternalCalibrationSummary {
            witness_jsonl,
            adversarial_jsonl,
            output_json,
            output_markdown,
        } => {
            let summary = external_calibration_summary(
                &read_optional_jsonl(witness_jsonl.as_deref())?,
                &read_optional_jsonl(adversarial_jsonl.as_deref())?,
            );
            write_json(&output_json, &summary)?;
            if let Some(path) = output_markdown {
                write_text(&path, &external_calibration_markdown(&summary))?;
            }
        }
        Command::ExternalCalibrationContractCheck {
            summary_json,
            summary_markdown,
        } => {
            external_calibration_contract_check(
                &read_json(&summary_json)?,
                &fs::read_to_string(summary_markdown)?,
            )?;
        }
        _ => unreachable!("calibration dispatch received non-calibration command"),
    }
    Ok(())
}
