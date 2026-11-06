use crate::artifact::{read_json, read_jsonl, read_optional_json_path, write_json, write_text};
use crate::cli::Command;
use crate::traffic_shape::{traffic_shape_score, traffic_shape_score_markdown};
use crate::transport_camouflage::{
    transport_camouflage_validation, transport_camouflage_validation_markdown,
    TransportCamouflageValidationPaths,
};
use crate::witness_score::{
    mimicry_matrix_review, mimicry_matrix_review_markdown, reference_pcap_score,
    reference_pcap_score_markdown, reference_timing_baseline, reference_timing_baseline_markdown,
    witness_score, witness_score_markdown, ReferencePcapInput, WitnessScoreInput,
};

pub fn is_transport(command: &Command) -> bool {
    matches!(
        command,
        Command::TransportCamouflageValidation { .. }
            | Command::TrafficShapeScore { .. }
            | Command::WitnessScore { .. }
            | Command::MimicryMatrixReview { .. }
            | Command::ReferenceTimingBaseline { .. }
            | Command::ReferencePcapScore { .. }
    )
}

pub fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::TransportCamouflageValidation {
            live_manifest_json,
            stealth_bundle_json,
            wire_acceptance_json,
            relay_surface_json,
            classifier_summary_json,
            witness_pcap,
            output_json,
            output_markdown,
        } => {
            let validation = transport_camouflage_validation(
                &read_json(&live_manifest_json)?,
                &read_json(&stealth_bundle_json)?,
                &read_json(&wire_acceptance_json)?,
                &read_json(&relay_surface_json)?,
                &read_json(&classifier_summary_json)?,
                &witness_pcap,
                TransportCamouflageValidationPaths {
                    live_manifest_json: &live_manifest_json,
                    stealth_bundle_json: &stealth_bundle_json,
                    wire_acceptance_json: &wire_acceptance_json,
                    relay_surface_json: &relay_surface_json,
                    classifier_summary_json: &classifier_summary_json,
                    witness_pcap: &witness_pcap,
                },
            );
            write_json(&output_json, &validation)?;
            if let Some(path) = output_markdown {
                write_text(
                    &path,
                    &transport_camouflage_validation_markdown(&validation),
                )?;
            }
            if validation["status"].as_str() != Some("READY") {
                std::process::exit(1);
            }
        }
        Command::TrafficShapeScore {
            transport,
            runtime_events_jsonl,
            classifier_summary_json,
            pcap_summary_json,
            timing_summary_json,
            pcap_path,
            netem_profile,
            output_json,
            output_markdown,
        } => {
            let pcap_summary = read_optional_json_path(pcap_summary_json.as_deref())?;
            let timing_summary = read_optional_json_path(timing_summary_json.as_deref())?;
            let score = traffic_shape_score(
                &transport,
                &read_jsonl(&runtime_events_jsonl)?,
                &read_json(&classifier_summary_json)?,
                pcap_summary.as_ref(),
                timing_summary.as_ref(),
                pcap_path.as_deref(),
                &netem_profile,
            );
            write_json(&output_json, &score)?;
            if let Some(path) = output_markdown {
                write_text(&path, &traffic_shape_score_markdown(&score))?;
            }
        }
        Command::WitnessScore {
            transport,
            netem_profile,
            relay_pcap,
            runtime_events_jsonl,
            ndpi_summary_json,
            suricata_summary_json,
            reference_profile_json,
            tshark_bin,
            output_json,
            output_markdown,
        } => {
            let reference_profile = read_optional_json_path(reference_profile_json.as_deref())?;
            let runtime_events = read_jsonl(&runtime_events_jsonl)?;
            let ndpi_summary = read_json(&ndpi_summary_json)?;
            let suricata_summary = read_json(&suricata_summary_json)?;
            let score = witness_score(WitnessScoreInput {
                transport: &transport,
                netem_profile: &netem_profile,
                pcap_path: &relay_pcap,
                runtime_events: &runtime_events,
                ndpi_summary: &ndpi_summary,
                suricata_summary: &suricata_summary,
                reference_profile: reference_profile.as_ref(),
                tshark_bin: &tshark_bin,
            });
            write_json(&output_json, &score)?;
            if let Some(path) = output_markdown {
                write_text(&path, &witness_score_markdown(&score))?;
            }
        }
        Command::MimicryMatrixReview {
            matrix_root,
            reference_status_json,
            output_json,
            output_markdown,
        } => {
            let reference_status = read_optional_json_path(reference_status_json.as_deref())?;
            let review = mimicry_matrix_review(&matrix_root, reference_status.as_ref());
            write_json(&output_json, &review)?;
            if let Some(path) = output_markdown {
                write_text(&path, &mimicry_matrix_review_markdown(&review))?;
            }
        }
        Command::ReferenceTimingBaseline {
            matrix_root,
            websocket_reference_json,
            grpc_reference_json,
            browser_reference_json,
            output_json,
            output_markdown,
        } => {
            let websocket_reference = read_optional_json_path(websocket_reference_json.as_deref())?;
            let grpc_reference = read_optional_json_path(grpc_reference_json.as_deref())?;
            let browser_reference = read_optional_json_path(browser_reference_json.as_deref())?;
            let baseline = reference_timing_baseline(
                &matrix_root,
                websocket_reference.as_ref(),
                grpc_reference.as_ref(),
                browser_reference.as_ref(),
            );
            write_json(&output_json, &baseline)?;
            if let Some(path) = output_markdown {
                write_text(&path, &reference_timing_baseline_markdown(&baseline))?;
            }
        }
        Command::ReferencePcapScore {
            artifact,
            transport,
            netem_profile,
            client_type,
            endpoint_url,
            provider,
            pcap,
            ndpi_summary_json,
            suricata_summary_json,
            expected_ja3,
            expected_ja4,
            tshark_bin,
            output_json,
            output_markdown,
        } => {
            let ndpi_summary = read_json(&ndpi_summary_json)?;
            let suricata_summary = read_json(&suricata_summary_json)?;
            let score = reference_pcap_score(ReferencePcapInput {
                artifact: &artifact,
                transport: &transport,
                netem_profile: &netem_profile,
                client_type: &client_type,
                endpoint_url: &endpoint_url,
                provider: &provider,
                pcap_path: &pcap,
                ndpi_summary: &ndpi_summary,
                suricata_summary: &suricata_summary,
                tshark_bin: &tshark_bin,
                expected_ja3: expected_ja3.as_deref(),
                expected_ja4: expected_ja4.as_deref(),
            });
            write_json(&output_json, &score)?;
            if let Some(path) = output_markdown {
                write_text(&path, &reference_pcap_score_markdown(&score))?;
            }
        }
        _ => unreachable!("transport dispatch received non-transport command"),
    }
    Ok(())
}
