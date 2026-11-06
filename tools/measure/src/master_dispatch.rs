use crate::artifact::{read_json, read_optional_json_path, write_json, write_text};
use crate::brain_runtime_proof::brain_external_calibration_runtime_proof;
use crate::cli::Command;
use crate::master_plan::{
    master_plan_handoff, master_plan_handoff_check, master_plan_handoff_markdown,
    MasterPlanHandoffInputs,
};

pub fn is_master_control(command: &Command) -> bool {
    matches!(
        command,
        Command::MasterPlanHandoff { .. }
            | Command::MasterPlanHandoffCheck { .. }
            | Command::BrainExternalCalibrationRuntimeProof { .. }
    )
}

pub fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::MasterPlanHandoff {
            phase_c_resilience_json,
            phase_d_reach_json,
            artifact_dir,
            output_json,
            output_markdown,
        } => {
            let phase_d_reach = read_optional_json_path(phase_d_reach_json.as_deref())?;
            let handoff = master_plan_handoff(
                &read_json(&phase_c_resilience_json)?,
                phase_d_reach.as_ref(),
                MasterPlanHandoffInputs {
                    phase_c_resilience_json: &phase_c_resilience_json,
                    phase_d_reach_json: phase_d_reach_json.as_deref(),
                    artifact_dir: &artifact_dir,
                },
            );
            write_json(&output_json, &handoff)?;
            if let Some(path) = output_markdown {
                write_text(&path, &master_plan_handoff_markdown(&handoff))?;
            }
        }
        Command::MasterPlanHandoffCheck { handoff_json } => {
            master_plan_handoff_check(&read_json(&handoff_json)?)?;
        }
        Command::BrainExternalCalibrationRuntimeProof {
            artifact_dir,
            output_json,
        } => {
            let result = brain_external_calibration_runtime_proof(&artifact_dir)?;
            if let Some(path) = output_json {
                write_json(&path, &result)?;
            }
            if result["verdict"].as_str() != Some("PASS") {
                std::process::exit(1);
            }
        }
        _ => unreachable!("master dispatch received non-master command"),
    }
    Ok(())
}
