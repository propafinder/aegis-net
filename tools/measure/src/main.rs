#![recursion_limit = "256"]

#[cfg(test)]
#[path = "../../../scripts/lib/research_build_target.rs"]
mod research_build_target_contract;

mod adversarial_runner;
mod artifact;
mod brain_outcome_replay;
mod brain_runtime_proof;
mod calibration_dispatch;
mod cli;
mod debian_package_host;
mod dispatch;
mod external_calibration;
mod hostile_classifier;
mod linux_live_audit_manifest;
mod linux_next_expansion_playbook;
mod linux_next_expansion_review;
mod linux_next_expansion_status;
mod linux_next_expansion_wave;
mod linux_package_acceptance_matrix;
mod linux_release_program;
mod macos_pf_helper;
mod macos_pf_operator_summary;
mod macos_utun_lab;
mod master_dispatch;
mod master_plan;
mod mimicry_wire_contract;
mod mimicry_wire_host;
mod mimicry_wire_witness;
mod pcap_tools;
mod phase3_kpi;
mod phase3_kpi_dispatch;
mod phase_a;
mod phase_a_dispatch;
mod phase_b_baseline;
mod phase_b_dispatch;
mod phase_b_runtime;
mod phase_b_score;
mod phase_c;
mod phase_c_dispatch;
mod phase_c_fronted;
mod phase_d;
mod phase_d_dispatch;
mod poisson_control;
mod poisson_insertion;
mod post_release_stealth_wave;
mod privacy_frontier;
mod privacy_pcap;
mod privacy_study;
mod private_control;
mod private_research_delivery;
mod public_client_delivery;
mod relay_surface_runtime;
mod release_artifacts;
mod release_delivery;
mod release_dispatch;
mod release_opsec;
mod release_parity;
mod research_build_info;
mod research_command;
mod research_operator_delivery;
mod rich_host;
mod rpm_package_host;
mod shipping_client_inventory;
mod stealth_anti_anomaly;
mod stealth_hostile_path;
mod stealth_live_bundle;
mod stealth_polymorphism;
mod tool_dispatch;
mod traffic_shape;
mod transport_camouflage;
mod transport_dispatch;
mod ubuntu_controlled_pilot_bundle;
mod ubuntu_controlled_pilot_playbook;
mod ubuntu_controlled_pilot_review_bundle;
mod ubuntu_field_pilot_remote_bundle;
mod ubuntu_mimicry_contour;
mod ubuntu_operator_canary;
mod ubuntu_operator_loop;
mod ubuntu_release_gate_status;
mod ubuntu_release_review;
mod ubuntu_release_wave_bundle;
mod ubuntu_release_wave_status;
mod wide_redirect_smoke;
mod wide_smoke;
mod wide_tproxy_helper;
mod windows_completion;
mod witness_score;

use clap::Parser;
use cli::Cli;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().skip(1).any(|arg| {
        arg == std::ffi::OsStr::new("--bundle-url")
            || arg
                .to_str()
                .is_some_and(|arg| arg.starts_with("--bundle-url="))
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Inline bundle URLs are no longer accepted. Use --bundle-url-file with an opaque private record path, or --bundle with an archive path.",
        ).into());
    }
    dispatch::run(Cli::parse().command)
}

#[cfg(all(test, unix))]
mod research_operator_bundle_contract_tests;
