use crate::artifact::{read_json, read_jsonl, read_optional_json_path, write_json, write_text};
use crate::cli::Command;
use crate::phase_c::{
    phase_c_bundle_mirrors_evidence, phase_c_bundle_mirrors_evidence_markdown,
    phase_c_multi_relay_evidence, phase_c_multi_relay_evidence_markdown, phase_c_resilience_gate,
    phase_c_resilience_gate_markdown, PhaseCResilienceGateInputs,
};
use crate::phase_c_fronted::{
    phase_c_fronted_blocked_result, phase_c_fronted_probe_attempt,
    phase_c_fronted_provider_preflight, phase_c_fronted_provider_preflight_markdown,
    phase_c_fronted_transport_evidence, phase_c_fronted_transport_evidence_markdown,
    PhaseCFrontedBlockedResult, PhaseCFrontedProbeAttempt,
};

pub fn is_phase_c(command: &Command) -> bool {
    matches!(
        command,
        Command::PhaseCResilienceGate { .. }
            | Command::PhaseCMultiRelayEvidence { .. }
            | Command::PhaseCBundleMirrorsEvidence { .. }
            | Command::PhaseCFrontedTransportEvidence { .. }
            | Command::PhaseCFrontedBlockedResult { .. }
            | Command::PhaseCFrontedProbeAttempt { .. }
            | Command::PhaseCFrontedProviderPreflight { .. }
    )
}

pub fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::PhaseCResilienceGate {
            phase_b_score_parity_json,
            multi_relay_json,
            bundle_mirrors_json,
            fronted_transport_json,
            output_json,
            output_markdown,
        } => {
            let multi_relay = read_optional_json_path(multi_relay_json.as_deref())?;
            let bundle_mirrors = read_optional_json_path(bundle_mirrors_json.as_deref())?;
            let fronted_transport = read_optional_json_path(fronted_transport_json.as_deref())?;
            let gate = phase_c_resilience_gate(
                &read_json(&phase_b_score_parity_json)?,
                multi_relay.as_ref(),
                bundle_mirrors.as_ref(),
                fronted_transport.as_ref(),
                PhaseCResilienceGateInputs {
                    phase_b_score_parity_json: &phase_b_score_parity_json,
                    multi_relay_json: multi_relay_json.as_deref(),
                    bundle_mirrors_json: bundle_mirrors_json.as_deref(),
                    fronted_transport_json: fronted_transport_json.as_deref(),
                },
            );
            write_json(&output_json, &gate)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_c_resilience_gate_markdown(&gate))?;
            }
            if gate["status"].as_str() != Some("PHASE_C_RESILIENCE_READY") {
                std::process::exit(1);
            }
        }
        Command::PhaseCMultiRelayEvidence {
            runtime_events_jsonl,
            output_json,
            output_markdown,
            single_relay_backward_compatible,
        } => {
            let evidence = phase_c_multi_relay_evidence(
                &read_jsonl(&runtime_events_jsonl)?,
                single_relay_backward_compatible,
                &runtime_events_jsonl,
            );
            write_json(&output_json, &evidence)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_c_multi_relay_evidence_markdown(&evidence))?;
            }
            if evidence["status"].as_str() != Some("PASS") {
                std::process::exit(1);
            }
        }
        Command::PhaseCBundleMirrorsEvidence {
            primary_fetch_json,
            mirror_fetch_json,
            voucher_flow_json,
            bundle_archive,
            bundle_sha256,
            operator_doc,
            output_json,
            output_markdown,
        } => {
            let evidence = phase_c_bundle_mirrors_evidence(
                &read_json(&primary_fetch_json)?,
                &read_json(&mirror_fetch_json)?,
                &read_json(&voucher_flow_json)?,
                &bundle_archive,
                &bundle_sha256,
                &operator_doc,
            );
            write_json(&output_json, &evidence)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_c_bundle_mirrors_evidence_markdown(&evidence))?;
            }
            if evidence["status"].as_str() != Some("PASS") {
                std::process::exit(1);
            }
        }
        Command::PhaseCFrontedTransportEvidence {
            attempts_jsonl,
            provider_doc,
            output_json,
            output_markdown,
        } => {
            let evidence =
                phase_c_fronted_transport_evidence(&read_jsonl(&attempts_jsonl)?, &provider_doc);
            write_json(&output_json, &evidence)?;
            if let Some(path) = output_markdown {
                write_text(
                    &path,
                    &phase_c_fronted_transport_evidence_markdown(&evidence),
                )?;
            }
            if evidence["status"].as_str() != Some("PASS") {
                std::process::exit(1);
            }
        }
        Command::PhaseCFrontedBlockedResult {
            classification,
            detail,
            front_authority,
            front_edge_server,
            front_transport_scope,
            origin_relay_address,
        } => {
            let result = phase_c_fronted_blocked_result(PhaseCFrontedBlockedResult {
                classification: &classification,
                detail: &detail,
                front_authority: &front_authority,
                front_edge_server: &front_edge_server,
                front_transport_scope: &front_transport_scope,
                origin_relay_address: &origin_relay_address,
            });
            println!("{}", serde_json::to_string(&result)?);
        }
        Command::PhaseCFrontedProbeAttempt {
            scenario,
            status,
            front_authority,
            front_edge_server,
            front_transport_scope,
            origin_relay_address,
            blocked_relay_address,
            probe_url,
            started_ms,
            finished_ms,
            detail,
        } => {
            let attempt = phase_c_fronted_probe_attempt(PhaseCFrontedProbeAttempt {
                scenario: &scenario,
                status: &status,
                front_authority: &front_authority,
                front_edge_server: &front_edge_server,
                front_transport_scope: &front_transport_scope,
                origin_relay_address: &origin_relay_address,
                blocked_relay_address: &blocked_relay_address,
                probe_url: &probe_url,
                started_ms,
                finished_ms,
                detail: &detail,
            });
            println!("{}", serde_json::to_string(&attempt)?);
        }
        Command::PhaseCFrontedProviderPreflight {
            front_authority,
            front_masque_server,
            origin_relay_address,
            provider_doc,
            output_json,
            output_markdown,
        } => {
            let preflight = phase_c_fronted_provider_preflight(
                &front_authority,
                &front_masque_server,
                &origin_relay_address,
                &provider_doc,
            );
            write_json(&output_json, &preflight)?;
            if let Some(path) = output_markdown {
                write_text(
                    &path,
                    &phase_c_fronted_provider_preflight_markdown(&preflight),
                )?;
            }
            if preflight["status"].as_str() != Some("PASS") {
                std::process::exit(1);
            }
        }
        _ => unreachable!("phase c dispatch received non-phase-c command"),
    }
    Ok(())
}
