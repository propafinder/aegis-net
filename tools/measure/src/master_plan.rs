use std::path::Path;

use serde_json::{json, Value};

mod output;
mod support;

pub use output::{master_plan_handoff_check, master_plan_handoff_markdown};

use support::{
    handoff_external_input, handoff_path_prerequisite, handoff_phase_c_prerequisites_ready_value,
    phase_c_artifact_or_placeholder, placeholder_free, release_latest_parity_gate_result,
    value_string_array, SlashPath,
};

pub struct MasterPlanHandoffInputs<'a> {
    pub phase_c_resilience_json: &'a Path,
    pub phase_d_reach_json: Option<&'a Path>,
    pub artifact_dir: &'a Path,
}

pub fn master_plan_handoff(
    phase_c_resilience: &Value,
    phase_d_reach: Option<&Value>,
    inputs: MasterPlanHandoffInputs<'_>,
) -> Value {
    let phase_c_ready = phase_c_resilience["status"].as_str() == Some("PHASE_C_RESILIENCE_READY")
        && phase_c_resilience["phase_c_exit_status"].as_str() == Some("EXIT_READY")
        && phase_c_resilience["acceptance_degraded"].as_bool() == Some(false);
    let phase_d_ready = phase_d_reach.is_some_and(|gate| {
        gate["status"].as_str() == Some("PHASE_D_EXIT_READY")
            && gate["phase_d_exit_status"].as_str() == Some("EXIT_READY")
            && gate["acceptance_degraded"].as_bool() == Some(false)
    });

    let phase_c_blockers = value_string_array(&phase_c_resilience["blockers"]);
    let phase_d_blockers = phase_d_reach
        .map(|gate| value_string_array(&gate["blockers"]))
        .unwrap_or_default();
    let release_latest_parity_ready = release_latest_parity_ready(inputs.artifact_dir);
    let live_artifact_root = inputs.artifact_dir.parent().unwrap_or(inputs.artifact_dir);
    let ubuntu_wide_latest_stable_ready = artifact_verdict_ready(
        &live_artifact_root
            .join("ubuntu-wide-tproxy-latest-stable-release-live")
            .join("result.json"),
        "PASS",
        None,
    );
    let mimicry_http_like_full_ready = artifact_verdict_ready(
        &live_artifact_root
            .join("mimicry-http-like-full-gate")
            .join("result.json"),
        "PASS",
        None,
    );
    let traffic_shape_matrix_materialized = artifact_exists(
        &live_artifact_root
            .join("mimicry-http-like-traffic-shape-matrix")
            .join("result.json"),
    );
    let witness_matrix_materialized = artifact_exists(
        &live_artifact_root
            .join("mimicry-http-like-witness-matrix")
            .join("result.json"),
    );
    let adverse_reference_observer_blocked = artifact_verdict_ready(
        &live_artifact_root
            .join("adverse-cloudflare-reference-observer-blocker")
            .join("result.json"),
        "BLOCKED",
        Some("BLOCKED_CLIENT_OBSERVER_UNAVAILABLE"),
    );
    let adverse_reference_profiles_ready = artifact_verdict_ready(
        &live_artifact_root
            .join("adverse-cloudflare-reference-profiles")
            .join("result.json"),
        "SCOPED_REFERENCE_READY",
        Some("SCOPED_ADVERSE_REFERENCE_CAPTURED"),
    );
    let adverse_reference_comparison_materialized = artifact_exists(
        &live_artifact_root
            .join("mimicry-adverse-reference-comparison")
            .join("result.json"),
    );
    let brain_operational_ready = artifact_verdict_ready(
        &live_artifact_root
            .join("brain-operational-live-calibrated-transport-proof")
            .join("result.json"),
        "PASS",
        None,
    );
    let phase_b_score_parity_arg = phase_c_artifact_or_placeholder(
        phase_c_resilience,
        "phase_b_score_parity_json",
        "<phase-b-score-parity-gate.json>",
    );
    let multi_relay_arg = phase_c_artifact_or_placeholder(
        phase_c_resilience,
        "multi_relay_json",
        "<phase-c-multi-relay-evidence.json>",
    );
    let bundle_mirrors_arg = phase_c_artifact_or_placeholder(
        phase_c_resilience,
        "bundle_mirrors_json",
        "<phase-c-bundle-mirrors-evidence.json>",
    );
    let phase_c_prerequisites = json!({
        "phase_b_score_parity_json": handoff_path_prerequisite(&phase_b_score_parity_arg),
        "multi_relay_json": handoff_path_prerequisite(&multi_relay_arg),
        "bundle_mirrors_json": handoff_path_prerequisite(&bundle_mirrors_arg),
    });
    let phase_c_fronted_external_inputs = json!({
        "relay_vps": handoff_external_input("relay VPS host reachable by SSH"),
        "client_vps": handoff_external_input("client VPS host reachable by SSH"),
        "ssh_user": handoff_external_input("SSH user for both VPS hosts"),
        "bundle_archive": handoff_external_input("current Linux bundle archive to deploy"),
        "provider_fronted_authority": handoff_external_input("non-IP provider/fronted authority"),
        "provider_edge_host": handoff_external_input("provider/fronted MASQUE edge host:443"),
        "provider_constraints_doc": handoff_external_input("provider constraints document"),
        "origin_relay_address": handoff_external_input("origin relay host:443 distinct from provider edge"),
    });

    let (
        layer,
        id,
        reason,
        command,
        expected_artifact,
        followup_command,
        expected_followup_artifact,
    ) = if !phase_c_ready
        && phase_c_blockers
            .iter()
            .any(|blocker| blocker.contains("cdn_fronted_transport"))
    {
        (
            "phase_c",
            "run_fronted_provider_preflight_then_two_vps_live",
            "Phase C is blocked only after completed multi-relay and bundle mirror/voucher evidence; CDN/fronted transport still needs a real provider-boundary live artifact.",
            format!(
                "scripts/build-phase-c-fronted-provider-preflight.sh --front-authority <provider-fronted-authority> --front-masque-server <provider-edge-host:443> --origin-relay-address <origin-relay-host:443> --provider-doc <fronted-provider-constraints.md> --output-json {}/phase-c-fronted-provider-preflight.json --output-markdown {}/phase-c-fronted-provider-preflight.md",
                inputs.artifact_dir.display(),
                inputs.artifact_dir.display()
            ),
            inputs
                .artifact_dir
                .join("phase-c-fronted-provider-preflight.json")
                .to_slash_string(),
            format!(
                "scripts/run-phase-c-fronted-transport-two-vps-live.sh --artifact-dir {} --server-host <relay-vps> --client-host <client-vps> --ssh-user <user> --bundle-archive <aegis-linux.tar.gz> --front-authority <provider-fronted-authority> --front-masque-server <provider-edge-host:443> --provider-doc <fronted-provider-constraints.md> --origin-relay-address <origin-relay-host:443> --phase-b-score-parity-json {} --multi-relay-json {} --bundle-mirrors-json {}",
                inputs.artifact_dir.display(),
                phase_b_score_parity_arg,
                multi_relay_arg,
                bundle_mirrors_arg
            ),
            inputs
                .artifact_dir
                .join("phase-c-fronted-transport-evidence.json")
                .to_slash_string(),
        )
    } else if !phase_c_ready {
        (
            "phase_c",
            "inspect_phase_c_resilience_blockers",
            "Phase C is blocked before the fronted transport slot; inspect the Phase C gate blockers first.",
            format!("cat {}", inputs.phase_c_resilience_json.display()),
            inputs.phase_c_resilience_json.display().to_string(),
            String::new(),
            String::new(),
        )
    } else if phase_d_reach.is_none() {
        (
            "phase_d",
            "materialize_phase_d_reach_gate",
            "Phase C is ready but no Phase D reach gate artifact was provided.",
            format!(
                "scripts/build-phase-d-reach-gate.sh --phase-c-resilience-json {} --windows-reach-json <windows-reach-evidence.json> --macos-reach-json <macos-reach-evidence.json> --android-reach-json <android-reach-evidence.json> --output-json {}/phase-d-reach-gate.json --output-markdown {}/phase-d-reach-gate.md",
                inputs.phase_c_resilience_json.display(),
                inputs.artifact_dir.display(),
                inputs.artifact_dir.display()
            ),
            inputs
                .artifact_dir
                .join("phase-d-reach-gate.json")
                .to_slash_string(),
            String::new(),
            String::new(),
        )
    } else if !phase_d_ready
        && phase_d_blockers
            .iter()
            .any(|blocker| blocker == "windows_reach:service_baseline_missing")
    {
        (
            "phase_d_windows",
            "run_windows_admin_service_baseline",
            "Windows reach prep is blocked by missing administrator-backed service baseline proof.",
            "Run the Windows service baseline from an elevated PowerShell session, then rebuild scripts/build-phase-d-windows-reach-evidence.sh and scripts/build-phase-d-reach-gate.sh.".to_string(),
            inputs
                .artifact_dir
                .join("windows-reach-evidence.json")
                .to_slash_string(),
            String::new(),
            String::new(),
        )
    } else if !phase_d_ready
        && phase_d_desktop_core_ready(phase_d_reach)
        && !phase_d_macos_utun_w5_ready(phase_d_reach)
    {
        (
            "desktop_core",
            "macos_utun_w5_controlled_external_relay_path",
            "Phase C is exit-ready, desktop reach is strong enough to continue core/desktop work, and Brain external-calibration runtime proof is now the completed prerequisite. Android VpnService is deferred as optional Platform Reach, and macOS NetworkExtension remains externally blocked by signing/entitlement.",
            "Run the macOS utun W5 controlled external relay path lab: keep the single controlled IPv4 route model, preserve relay IP exclusion, avoid default route/DNS/UDP/IPv6 claims, and prove the packet-to-relay path against an external AEGIS relay boundary.".to_string(),
            inputs
                .artifact_dir
                .join("macos-utun-w5-controlled-external-relay-path")
                .join("result.json")
                .to_slash_string(),
            "After W5, continue Windows DNS/UDP/reboot next-scope or release/latest parity without starting Android.".to_string(),
            inputs
                .artifact_dir
                .join("windows-dns-udp-reboot-next-scope")
                .join("result.json")
                .to_slash_string(),
        )
    } else if !phase_d_ready
        && phase_d_desktop_core_ready(phase_d_reach)
        && phase_d_macos_utun_w5_ready(phase_d_reach)
        && phase_d_windows_next_scope_blocked_on_reboot(phase_d_reach)
    {
        (
            "desktop_core",
            "windows_service_reboot_verify_after_reboot",
            "Windows DNS/UDP feasibility is now explicit and blocked on a new UDP-capable WFP layer, while service reboot persistence is waiting on the manual post-reboot verification step. Android remains deferred and macOS NetworkExtension remains externally blocked.",
            "From an elevated Windows environment after a real reboot, run scripts/windows/run-windows-wide-service-reboot-proof.ps1 -Mode VerifyAfterReboot, then rebuild scripts/build-phase-d-windows-reach-evidence.sh and scripts/build-phase-d-reach-gate.sh.".to_string(),
            inputs
                .artifact_dir
                .join("windows-wide-service-reboot-persistence-proof")
                .join("result.json")
                .to_slash_string(),
            "After reboot verification, continue release/latest parity without starting Android.".to_string(),
            release_latest_parity_gate_result(inputs.artifact_dir),
        )
    } else if !phase_d_ready
        && phase_d_desktop_core_ready(phase_d_reach)
        && phase_d_macos_utun_w5_ready(phase_d_reach)
        && phase_d_windows_current_mvp_complete(phase_d_reach)
        && release_latest_parity_ready
        && ubuntu_wide_latest_stable_ready
        && !mimicry_http_like_full_ready
        && adverse_reference_comparison_materialized
    {
        (
            "desktop_core",
            "harden_http_like_tls_fingerprint_and_shape_against_adverse_reference",
            "Adverse Cloudflare-fronted WebSocket/gRPC reference profiles are captured and compared against AEGIS witness cells. Coverage and classifier counts are clean, but full mimicry remains PARTIAL because JA3/JA4 and packet-size distribution mismatches remain.",
            "Use evidence-archive/live/2026-05-03/mimicry-adverse-reference-comparison/result.json to tune HTTP-like TLS fingerprint and packet sizing for https_ws/grpc_stream, then rerun the comparison and mimicry full gate without claiming legacy_tls or normal Cloudflare MASQUE/UDP.".to_string(),
            live_artifact_root
                .join("mimicry-adverse-reference-comparison")
                .join("result.json")
                .to_slash_string(),
            "After adverse reference mismatches are closed, rerun the mimicry full gate and keep full AEGIS completion blocked until every required proof is PASS or explicitly scoped.".to_string(),
            live_artifact_root
                .join("mimicry-http-like-full-gate")
                .join("result.json")
                .to_slash_string(),
        )
    } else if !phase_d_ready
        && phase_d_desktop_core_ready(phase_d_reach)
        && phase_d_macos_utun_w5_ready(phase_d_reach)
        && phase_d_windows_current_mvp_complete(phase_d_reach)
        && release_latest_parity_ready
        && ubuntu_wide_latest_stable_ready
        && !mimicry_http_like_full_ready
        && adverse_reference_profiles_ready
    {
        (
            "desktop_core",
            "compare_adverse_reference_profiles_against_mimicry_witness_matrix",
            "Adverse Cloudflare-fronted WebSocket/gRPC reference profiles are now captured from a separate client-side observer VPS for mobile_peak, congested_wifi, slow_mobile, and middlebox_delay. Full mimicry remains PARTIAL until these references are compared against the AEGIS witness matrix.",
            "Compare JA3/JA4/timing/size/ratio from evidence-archive/live/2026-05-03/adverse-cloudflare-reference-profiles/result.json against the existing HTTP-like witness matrix, then rerun the mimicry full gate without claiming legacy_tls or normal Cloudflare MASQUE/UDP.".to_string(),
            live_artifact_root
                .join("adverse-cloudflare-reference-profiles")
                .join("result.json")
                .to_slash_string(),
            "After adverse reference comparison is closed, rerun mimicry-http-like-full-gate and only then evaluate desktop/core completion readiness.".to_string(),
            live_artifact_root
                .join("mimicry-http-like-full-gate")
                .join("result.json")
                .to_slash_string(),
        )
    } else if !phase_d_ready
        && phase_d_desktop_core_ready(phase_d_reach)
        && phase_d_macos_utun_w5_ready(phase_d_reach)
        && phase_d_windows_current_mvp_complete(phase_d_reach)
        && release_latest_parity_ready
        && ubuntu_wide_latest_stable_ready
        && !mimicry_http_like_full_ready
        && adverse_reference_observer_blocked
    {
        (
            "desktop_core",
            "provision_client_observer_vps_for_adverse_reference",
            "HTTP-like witness matrix and clean_fiber Cloudflare reference captures exist, but adverse Cloudflare reference profiles are blocked because no separate client-side observer VPS is currently reachable. Origin-side-only substitution is explicitly rejected.",
            "Provision or restore non-interactive SSH access to an operator-selected client-side observer VPS distinct from <reference-origin-address>, then capture WebSocket and gRPC reference traffic to <reference-authority> for mobile_peak, congested_wifi, slow_mobile, and middlebox_delay with JA3/JA4, timing, size, ratio, nDPI, and Suricata metrics. Resolve these placeholders only in private operator inputs.".to_string(),
            live_artifact_root
                .join("adverse-cloudflare-reference-observer-blocker")
                .join("result.json")
                .to_slash_string(),
            "After adverse reference profiles are captured from the observer side, rerun reference timing/mimicry matrix review without changing the Brain operational PASS boundary.".to_string(),
            live_artifact_root
                .join("mimicry-reference-timing-baseline")
                .join("result.json")
                .to_slash_string(),
        )
    } else if !phase_d_ready
        && phase_d_desktop_core_ready(phase_d_reach)
        && phase_d_macos_utun_w5_ready(phase_d_reach)
        && phase_d_windows_current_mvp_complete(phase_d_reach)
        && release_latest_parity_ready
        && ubuntu_wide_latest_stable_ready
        && !mimicry_http_like_full_ready
        && witness_matrix_materialized
    {
        (
            "desktop_core",
            "expand_adverse_cloudflare_reference_profiles",
            "HTTP-like witness matrix is materialized with relay-only pcap, classifier counts, timing, netem coverage, and measured JA3/JA4; controlled Cloudflare-fronted WebSocket/gRPC clean_fiber reference pcaps now exist, but full mimicry remains PARTIAL because adverse reference profile coverage and JA3/JA4 comparison are not closed.",
            "Collect adverse Cloudflare-fronted WebSocket/gRPC reference profiles beyond the existing clean_fiber captures, compare JA3/JA4/timing/size/ratio against AEGIS cells, and rerun mimicry-matrix-review without claiming legacy_tls or normal Cloudflare MASQUE/UDP.".to_string(),
            live_artifact_root
                .join("mimicry-http-like-witness-matrix")
                .join("result.json")
                .to_slash_string(),
            "After full HTTP-like witness matrix PASS, Brain operational calibrated transport proof is available as a follow-up gate; rerun it only if transport scoring or relay selection changes.".to_string(),
            live_artifact_root
                .join("brain-operational-live-calibrated-transport-proof")
                .join("result.json")
                .to_slash_string(),
        )
    } else if !phase_d_ready
        && phase_d_desktop_core_ready(phase_d_reach)
        && phase_d_macos_utun_w5_ready(phase_d_reach)
        && phase_d_windows_current_mvp_complete(phase_d_reach)
        && release_latest_parity_ready
        && ubuntu_wide_latest_stable_ready
        && !mimicry_http_like_full_ready
        && traffic_shape_matrix_materialized
    {
        (
            "desktop_core",
            "collect_per_transport_relay_only_pcap_and_classifier_counts",
            "The Rust traffic-shape matrix is materialized, but full HTTP-like mimicry remains blocked: per-transport relay-only pcap is missing, https_ws still needs strict no-fallback isolation, and JA3/JA4 are not measured.",
            "Collect isolated relay-only pcaps for https_ws and grpc_stream, produce per-transport nDPI risk_count and Suricata alert_count, add timing/ratio summaries, and rerun the traffic-shape matrix without legacy_tls, MASQUE/UDP, direct active probe, or fallback transport mixing.".to_string(),
            live_artifact_root
                .join("mimicry-http-like-traffic-shape-matrix")
                .join("result.json")
                .to_slash_string(),
            "After the matrix reaches PASS, Brain operational calibrated transport proof is available as a follow-up gate; rerun it only if transport scoring or relay selection changes.".to_string(),
            live_artifact_root
                .join("brain-operational-live-calibrated-transport-proof")
                .join("result.json")
                .to_slash_string(),
        )
    } else if !phase_d_ready
        && phase_d_desktop_core_ready(phase_d_reach)
        && phase_d_macos_utun_w5_ready(phase_d_reach)
        && phase_d_windows_current_mvp_complete(phase_d_reach)
        && release_latest_parity_ready
        && ubuntu_wide_latest_stable_ready
        && !mimicry_http_like_full_ready
    {
        (
            "desktop_core",
            "implement_traffic_shape_scoring_and_per_transport_relay_only_pcap_matrix",
            "Ubuntu wide latest/stable is PASS, but full HTTP-like mimicry remains REQUIRED_NEXT because timing/shape, per-transport relay-only pcap, JA3/JA4, upload/download ratio, and netem scoring are not fully closed for https_ws and grpc_stream.",
            "Implement or run the per-transport HTTP-like mimicry score matrix for https_ws and grpc_stream with relay-only pcap, nDPI, Suricata, ALPN/SNI, JA3/JA4 when available, message/record size distribution, inter-arrival timing, upload/download ratio, Cloudflare boundary, and netem profile.".to_string(),
            live_artifact_root
                .join("mimicry-http-like-full-gate")
                .join("result.json")
                .to_slash_string(),
            "After mimicry PASS, reuse or rerun Brain operational calibrated transport proof before any completion-readiness artifact.".to_string(),
            live_artifact_root
                .join("brain-operational-live-calibrated-transport-proof")
                .join("result.json")
                .to_slash_string(),
        )
    } else if !phase_d_ready
        && phase_d_desktop_core_ready(phase_d_reach)
        && phase_d_macos_utun_w5_ready(phase_d_reach)
        && phase_d_windows_current_mvp_complete(phase_d_reach)
        && release_latest_parity_ready
        && ubuntu_wide_latest_stable_ready
        && mimicry_http_like_full_ready
        && !brain_operational_ready
    {
        (
            "desktop_core",
            "run_real_client_brain_operational_session_with_calibration_and_relay_success",
            "Ubuntu wide latest/stable and scoped HTTP-like clean_fiber mimicry are ready, but Brain operational runtime proof remains REQUIRED_NEXT until calibration changes a real client transport choice and the selected calibrated transport succeeds in a relay session.",
            "Run a real client with a fresh external calibration snapshot, verify external_calibration_applied and decision/strategy-score explanation events, prove the selected transport changes as expected, then require relay_session_succeeded with that selected transport plus stale-calibration and fail-closed negative cases.".to_string(),
            live_artifact_root
                .join("brain-operational-live-calibrated-transport-proof")
                .join("result.json")
                .to_slash_string(),
            "Only after Brain operational PASS, create the scoped desktop/core completion-readiness artifact.".to_string(),
            live_artifact_root
                .join("aegis-desktop-core-completion-readiness")
                .join("result.json")
                .to_slash_string(),
        )
    } else if !phase_d_ready
        && phase_d_desktop_core_ready(phase_d_reach)
        && phase_d_macos_utun_w5_ready(phase_d_reach)
        && phase_d_windows_current_mvp_complete(phase_d_reach)
        && release_latest_parity_ready
    {
        (
            "desktop_core",
            "ubuntu_wide_tproxy_latest_stable_release_proof",
            "Release/latest parity is PASS, but desktop/core completion is not ready: Ubuntu wide latest/stable, full HTTP-like mimicry, and Brain operational runtime proof remain REQUIRED_NEXT. Start with the Ubuntu wide latest/stable routed PREROUTING TPROXY release proof before any completion-readiness artifact.",
            "Run the Ubuntu wide latest/stable routed PREROUTING TPROXY release proof from current stable/latest assets; require TCP IPv4, DNS UDP/53, generic UDP, explicit IPv6 BLOCK policy, runtime relay success, firewall/routing counters, and cleanup. Do not claim desktop/core completion if this is missing or partial.".to_string(),
            inputs
                .artifact_dir
                .parent()
                .unwrap_or(inputs.artifact_dir)
                .join("ubuntu-wide-tproxy-latest-stable-release-live")
                .join("result.json")
                .to_slash_string(),
            "After Ubuntu wide latest/stable PASS, run the full HTTP-like mimicry gate for https_ws and grpc_stream, then Brain operational calibration proof. Keep macOS NetworkExtension externally blocked and Android deferred.".to_string(),
            inputs
                .artifact_dir
                .parent()
                .unwrap_or(inputs.artifact_dir)
                .join("mimicry-http-like-full-gate")
                .join("result.json")
                .to_slash_string(),
        )
    } else if !phase_d_ready
        && phase_d_desktop_core_ready(phase_d_reach)
        && phase_d_macos_utun_w5_ready(phase_d_reach)
        && phase_d_windows_current_mvp_complete(phase_d_reach)
    {
        (
            "desktop_core",
            "release_latest_parity",
            "Windows current scoped MVP is complete: service baseline, restart/reboot persistence, controlled TCP WFP, original destination recovery, process/browser capture, rollback, and explicit DNS/UDP next-layer BLOCKED evidence are all materialized. Android remains deferred and macOS NetworkExtension remains externally blocked, so continue release/latest parity without claiming broader Windows capture.",
            "Run release/latest parity against the current desktop/core artifact set; do not start Android and do not claim broad Windows wide or DNS/UDP/IPv6 capture.".to_string(),
            release_latest_parity_gate_result(inputs.artifact_dir),
            "After release/latest parity, schedule the next Windows UDP/DNS layer implementation design slice or macOS NetworkExtension prerequisites.".to_string(),
            inputs
                .artifact_dir
                .join("windows-dns-udp-next-layer-design")
                .join("result.json")
                .to_slash_string(),
        )
    } else if !phase_d_ready
        && phase_d_desktop_core_ready(phase_d_reach)
        && phase_d_macos_utun_w5_ready(phase_d_reach)
    {
        (
            "desktop_core",
            "windows_dns_udp_reboot_next_scope",
            "Phase C is exit-ready, Brain runtime calibration proof is complete, and macOS utun W5 is LAB PASS. Android remains deferred, and macOS NetworkExtension remains externally blocked, so the next desktop/core slice is Windows DNS/UDP/reboot policy and rollback scope.",
            "Run the Windows DNS, UDP, IPv6, reboot/service persistence, and rollback next-scope proofs from an elevated Windows environment, then rebuild scripts/build-phase-d-windows-reach-evidence.sh and scripts/build-phase-d-reach-gate.sh.".to_string(),
            inputs
                .artifact_dir
                .join("windows-dns-udp-reboot-next-scope")
                .join("result.json")
                .to_slash_string(),
            "After Windows next-scope, continue release/latest parity; do not start Android until desktop/core gates are stable.".to_string(),
            release_latest_parity_gate_result(inputs.artifact_dir),
        )
    } else if !phase_d_ready
        && phase_d_blockers
            .iter()
            .any(|blocker| blocker == "macos_reach:network_extension_system_wide_not_proven")
    {
        (
            "phase_d_macos",
            "run_macos_networkextension_signed_system_wide_proof",
            "macOS reach exit is blocked by NetworkExtension signing/runtime proof, not by PF apply/cleanup.",
            "Install signing/provisioning prerequisites, produce a signed NetworkExtension system-wide runtime artifact, then rebuild scripts/build-phase-d-macos-reach-evidence.sh and scripts/build-phase-d-reach-gate.sh.".to_string(),
            inputs
                .artifact_dir
                .join("macos-reach-evidence.json")
                .to_slash_string(),
            String::new(),
            String::new(),
        )
    } else if !phase_d_ready
        && phase_d_blockers
            .iter()
            .any(|blocker| blocker == "android_reach:vpnservice_basic_flow_not_proven")
    {
        (
            "phase_d_android",
            "run_android_vpnservice_basic_flow_proof",
            "Android reach exit is blocked by missing measured VpnService basic flow proof.",
            "Produce a measured VpnService flow JSON, then rebuild scripts/build-phase-d-android-reach-evidence.sh with --vpnservice-flow-json and scripts/build-phase-d-reach-gate.sh.".to_string(),
            inputs
                .artifact_dir
                .join("android-reach-evidence.json")
                .to_slash_string(),
            String::new(),
            String::new(),
        )
    } else if !phase_d_ready {
        (
            "phase_d",
            "inspect_phase_d_reach_blockers",
            "Phase D is blocked; inspect the reach gate blockers.",
            inputs
                .phase_d_reach_json
                .map(|path| format!("cat {}", path.display()))
                .unwrap_or_else(|| "inspect missing Phase D reach gate".to_string()),
            inputs
                .phase_d_reach_json
                .unwrap_or(inputs.phase_c_resilience_json)
                .display()
                .to_string(),
            String::new(),
            String::new(),
        )
    } else {
        (
            "master_plan",
            "open_next_master_plan_phase",
            "Phase C and Phase D gates are exit-ready.",
            "open next master plan phase".to_string(),
            inputs.artifact_dir.display().to_string(),
            String::new(),
            String::new(),
        )
    };
    let command_placeholder_free = placeholder_free(&command);
    let followup_command_placeholder_free =
        followup_command.trim().is_empty() || placeholder_free(&followup_command);

    json!({
        "event": "master_plan_handoff",
        "schema_version": 1,
        "status": if phase_c_ready && phase_d_ready { "READY_FOR_NEXT_PHASE" } else { "ACTION_REQUIRED" },
        "phase_c_ready": phase_c_ready,
        "phase_d_ready": phase_d_ready,
        "primary_layer": layer,
        "next_action": {
            "id": id,
            "reason": reason,
            "command": command,
            "expected_artifact": expected_artifact,
            "followup_command": followup_command,
            "expected_followup_artifact": expected_followup_artifact,
            "command_placeholder_free": command_placeholder_free,
            "followup_command_placeholder_free": followup_command_placeholder_free,
            "requires_external_inputs": !command_placeholder_free || !followup_command_placeholder_free,
        },
        "phase_c_blockers": phase_c_blockers,
        "phase_d_blockers": phase_d_blockers,
        "platform_reach_policy": {
            "android": {
                "status": if phase_d_desktop_core_ready(phase_d_reach) { "DEFERRED_OPTIONAL_PLATFORM_REACH" } else { "ACTIVE_GATE_OR_UNKNOWN" },
                "reason": "Android VpnService remains in future Platform Reach, but desktop/core gates are the operational priority until they are stable.",
            },
            "macos_networkextension": {
                "status": if phase_d_blockers.iter().any(|blocker| blocker == "macos_reach:network_extension_system_wide_not_proven") { "EXTERNALLY_BLOCKED" } else { "NOT_BLOCKING_CURRENT_HANDOFF" },
                "reason": "NetworkExtension system-wide proof requires Apple membership/signing/entitlement and must not be overclaimed.",
            }
        },
        "desktop_core_completion": {
            "allowed": false,
            "reason": "Do not mark desktop/core complete until Ubuntu wide latest/stable, full HTTP-like mimicry, and Brain operational runtime proof are all PASS.",
            "ubuntu_wide_latest_stable": if ubuntu_wide_latest_stable_ready { "PASS" } else { "REQUIRED_NEXT" },
            "full_mimicry_score_matrix": if mimicry_http_like_full_ready { "PASS" } else { "REQUIRED_NEXT" },
            "brain_operational_loop": if brain_operational_ready { "PASS" } else { "REQUIRED_NEXT" },
            "android": "DEFERRED",
            "macos_networkextension": "EXTERNALLY_BLOCKED",
        },
        "prerequisites": {
            "phase_c_fronted_followup": phase_c_prerequisites,
        },
        "external_inputs": {
            "phase_c_fronted_live": phase_c_fronted_external_inputs,
        },
        "ready_for_live_command": handoff_phase_c_prerequisites_ready_value(&phase_c_prerequisites),
        "artifacts": {
            "phase_c_resilience_json": inputs.phase_c_resilience_json,
            "phase_d_reach_json": inputs.phase_d_reach_json,
            "artifact_dir": inputs.artifact_dir,
        },
    })
}

fn phase_d_desktop_core_ready(phase_d_reach: Option<&Value>) -> bool {
    let Some(gate) = phase_d_reach else {
        return false;
    };
    gate["status"].as_str() == Some("PHASE_D_PREP_READY")
        && gate["phase_d_prep_status"].as_str() == Some("PREP_READY")
        && gate["windows_reach"]["status"].as_str() == Some("PASS")
        && gate["windows_reach"]["exit_ready"].as_bool() == Some(true)
        && gate["macos_reach"]["status"].as_str() == Some("PREP")
        && gate["macos_reach"]["utun_w4_policy_cleanup_pass"].as_bool() == Some(true)
        && gate["android_reach"]["overstated_claim_detected"].as_bool() != Some(true)
}

fn phase_d_macos_utun_w5_ready(phase_d_reach: Option<&Value>) -> bool {
    phase_d_reach.is_some_and(|gate| {
        gate["macos_reach"]["utun_w5_controlled_external_relay_path_pass"].as_bool() == Some(true)
    })
}

fn phase_d_windows_next_scope_blocked_on_reboot(phase_d_reach: Option<&Value>) -> bool {
    phase_d_reach.is_some_and(|gate| {
        gate["windows_reach"]["dns_udp_next_scope_status"].as_str()
            == Some("UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER")
            && gate["windows_reach"]["service_reboot_pass"].as_bool() == Some(false)
    })
}

fn phase_d_windows_current_mvp_complete(phase_d_reach: Option<&Value>) -> bool {
    phase_d_reach.is_some_and(|gate| {
        gate["windows_reach"]["status"].as_str() == Some("PASS")
            && gate["windows_reach"]["exit_ready"].as_bool() == Some(true)
            && gate["windows_reach"]["service_reboot_pass"].as_bool() == Some(true)
            && gate["windows_reach"]["dns_udp_next_scope_status"].as_str()
                == Some("UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER")
    })
}

fn release_latest_parity_ready(artifact_dir: &Path) -> bool {
    let path = Path::new(&release_latest_parity_gate_result(artifact_dir)).to_path_buf();
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(result) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    result["verdict"].as_str() == Some("PASS")
        && result["status"].as_str() == Some("RELEASE_LATEST_PARITY_READY")
}

fn artifact_verdict_ready(path: &Path, verdict: &str, status: Option<&str>) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(result) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    result["verdict"].as_str() == Some(verdict)
        && status.is_none_or(|expected| result["status"].as_str() == Some(expected))
}

fn artifact_exists(path: &Path) -> bool {
    path.is_file()
}
