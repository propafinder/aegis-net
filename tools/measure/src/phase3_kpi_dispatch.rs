use std::path::{Path, PathBuf};

use crate::artifact::{write_json, write_text};
use crate::cli::Command;
use crate::phase3_kpi::{compute, render_markdown, Phase3KpiInputs};

pub fn is_phase3_kpi(command: &Command) -> bool {
    matches!(command, Command::Phase3KpiSummary { .. })
}

pub fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    let Command::Phase3KpiSummary {
        state_json,
        runtime_events_jsonl,
        bootstrap_script,
        bootstrap_survival_trials,
        historical_witness_matrix,
        output_json,
        output_markdown,
    } = command
    else {
        return Err("phase3-kpi-summary dispatched without matching Command variant".into());
    };
    let runtime_event_paths: Vec<&Path> =
        runtime_events_jsonl.iter().map(PathBuf::as_path).collect();
    let inputs = Phase3KpiInputs {
        state_json: state_json.as_deref(),
        runtime_events_jsonl: &runtime_event_paths,
        bootstrap_script: bootstrap_script.as_path(),
        bootstrap_survival_trials: bootstrap_survival_trials.as_deref(),
        historical_witness_matrix: historical_witness_matrix.as_deref(),
    };
    let result = compute(inputs)?;
    write_json(&output_json, &result)?;
    if let Some(md_path) = output_markdown.as_deref() {
        let md = render_markdown(&result);
        write_text(md_path, &md)?;
    }
    Ok(())
}
