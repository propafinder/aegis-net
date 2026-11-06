use std::path::PathBuf;

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Content-free exact-built private research tool producer snapshot.
    ResearchBuildInfo,
    /// Build-side dependency notices for the private research pair.
    ResearchToolNotices {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Paired timing control over explicitly application-owned UDP resources.
    PoissonControl {
        #[arg(long)]
        config_json: PathBuf,
        #[arg(long)]
        input_file: Option<PathBuf>,
        #[arg(long)]
        output_file: Option<PathBuf>,
    },
    /// Explicit application-owned Poisson insertion exchange, no native traffic.
    PoissonInsertion {
        #[arg(long)]
        config_json: PathBuf,
        #[arg(long)]
        application_input: Option<PathBuf>,
        #[arg(long)]
        control_input: Option<PathBuf>,
        #[arg(long)]
        application_output: Option<PathBuf>,
        #[arg(long)]
        control_output: Option<PathBuf>,
    },
    /// One authorized TLS control exchange; no installed traffic-mode activation.
    PrivateControl {
        #[arg(long)]
        config_json: PathBuf,
        #[arg(long)]
        input_file: Option<PathBuf>,
        #[arg(long)]
        output_file: Option<PathBuf>,
    },
    /// Export a strictly supported private classic PCAP trial to assembler TSV.
    PrivacyPcapExport {
        #[arg(long)]
        input_pcap: PathBuf,
        #[arg(long)]
        output_tsv: PathBuf,
    },
    /// Assemble paired finite-bin samples from private retained packet-field exports.
    PrivacyStudyAssemble {
        #[arg(long)]
        input_json: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
    },
    /// Replay private native direct outcome events without applying a route policy.
    BrainOutcomeReplay {
        #[arg(long)]
        input_jsonl: PathBuf,
        #[arg(long)]
        provenance_json: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
    },
    /// Estimate a finite-alphabet empirical privacy/cost frontier from measured input.
    PrivacyFrontier {
        #[arg(long)]
        input_json: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
    },
    HostileSummary {
        #[arg(long)]
        adversarial_jsonl: PathBuf,
        #[arg(long)]
        classifier_jsonl: Option<PathBuf>,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    ExternalCalibrationSummary {
        #[arg(long)]
        witness_jsonl: Option<PathBuf>,
        #[arg(long)]
        adversarial_jsonl: Option<PathBuf>,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    ExternalCalibrationContractCheck {
        #[arg(long)]
        summary_json: PathBuf,
        #[arg(long)]
        summary_markdown: PathBuf,
    },
    PhaseAExitReview {
        #[arg(long)]
        gate_review_json: PathBuf,
        #[arg(long)]
        calibration_json: PathBuf,
        #[arg(long)]
        classifier_json: PathBuf,
        #[arg(long)]
        threat_model: Option<PathBuf>,
        #[arg(long)]
        knowledge_architecture: Option<PathBuf>,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    PhaseBBaselineReview {
        #[arg(long)]
        phase_a_exit_json: PathBuf,
        #[arg(long)]
        calibration_json: PathBuf,
        #[arg(long)]
        gate_review_json: PathBuf,
        #[arg(long)]
        classifier_json: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    PhaseBTlsWireReview {
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    PhaseBRelayShapeReview {
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        require_diversity: bool,
    },
    PhaseBActiveProbeReview {
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        require_finished_probe: bool,
    },
    PhaseBLiveEvidenceReview {
        #[arg(long)]
        baseline_json: PathBuf,
        #[arg(long)]
        tls_wire_json: PathBuf,
        #[arg(long)]
        relay_shape_json: PathBuf,
        #[arg(long)]
        active_probe_json: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    PhaseBRuntimeEvidenceManifest {
        #[arg(long)]
        tls_wire_json: PathBuf,
        #[arg(long)]
        relay_shape_json: PathBuf,
        #[arg(long)]
        active_probe_json: PathBuf,
        #[arg(long)]
        live_evidence_json: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
        #[arg(long)]
        artifact_dir: Option<PathBuf>,
        #[arg(long)]
        runtime_events_jsonl: Option<PathBuf>,
        #[arg(long)]
        baseline_json: Option<PathBuf>,
    },
    PhaseBRuntimeEvidenceManifestCheck {
        #[arg(long)]
        manifest_json: PathBuf,
    },
    PhaseBMasterPlanStatus {
        #[arg(long)]
        baseline_json: PathBuf,
        #[arg(long)]
        runtime_manifest_json: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    PhaseBScoreParityGate {
        #[arg(long)]
        baseline_json: PathBuf,
        #[arg(long)]
        runtime_manifest_json: PathBuf,
        #[arg(long)]
        transport_camouflage_validation_json: PathBuf,
        #[arg(long)]
        witness_wire_correlation_json: PathBuf,
        #[arg(long)]
        two_vps_parity_json: PathBuf,
        #[arg(long)]
        classifier_summary_json: PathBuf,
        #[arg(long)]
        live_manifest_json: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    PhaseCResilienceGate {
        #[arg(long)]
        phase_b_score_parity_json: PathBuf,
        #[arg(long)]
        multi_relay_json: Option<PathBuf>,
        #[arg(long)]
        bundle_mirrors_json: Option<PathBuf>,
        #[arg(long)]
        fronted_transport_json: Option<PathBuf>,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    PhaseCMultiRelayEvidence {
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        single_relay_backward_compatible: bool,
    },
    PhaseCBundleMirrorsEvidence {
        #[arg(long)]
        primary_fetch_json: PathBuf,
        #[arg(long)]
        mirror_fetch_json: PathBuf,
        #[arg(long)]
        voucher_flow_json: PathBuf,
        #[arg(long)]
        bundle_archive: PathBuf,
        #[arg(long)]
        bundle_sha256: PathBuf,
        #[arg(long)]
        operator_doc: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    PhaseCFrontedTransportEvidence {
        #[arg(long)]
        attempts_jsonl: PathBuf,
        #[arg(long)]
        provider_doc: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    PhaseCFrontedBlockedResult {
        #[arg(long)]
        classification: String,
        #[arg(long)]
        detail: String,
        #[arg(long)]
        front_authority: String,
        #[arg(long)]
        front_edge_server: String,
        #[arg(long)]
        front_transport_scope: String,
        #[arg(long)]
        origin_relay_address: String,
    },
    PhaseCFrontedProbeAttempt {
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        status: String,
        #[arg(long)]
        front_authority: String,
        #[arg(long)]
        front_edge_server: String,
        #[arg(long)]
        front_transport_scope: String,
        #[arg(long)]
        origin_relay_address: String,
        #[arg(long)]
        blocked_relay_address: String,
        #[arg(long)]
        probe_url: String,
        #[arg(long)]
        started_ms: u64,
        #[arg(long)]
        finished_ms: u64,
        #[arg(long)]
        detail: String,
    },
    PhaseCFrontedProviderPreflight {
        #[arg(long)]
        front_authority: String,
        #[arg(long)]
        front_masque_server: String,
        #[arg(long)]
        origin_relay_address: String,
        #[arg(long)]
        provider_doc: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    PhaseDReachGate {
        #[arg(long)]
        phase_c_resilience_json: PathBuf,
        #[arg(long)]
        windows_reach_json: Option<PathBuf>,
        #[arg(long)]
        macos_reach_json: Option<PathBuf>,
        #[arg(long)]
        android_reach_json: Option<PathBuf>,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    PhaseDWindowsReachEvidence {
        #[arg(long)]
        socks_client_artifact: PathBuf,
        #[arg(long)]
        service_artifact: PathBuf,
        #[arg(long)]
        controlled_wfp_artifact: PathBuf,
        #[arg(long)]
        dynamic_original_dst_artifact: PathBuf,
        #[arg(long)]
        controlled_process_artifact: Option<PathBuf>,
        #[arg(long)]
        controlled_browser_artifact: Option<PathBuf>,
        #[arg(long)]
        dns_policy_json: Option<PathBuf>,
        #[arg(long)]
        udp_policy_json: Option<PathBuf>,
        #[arg(long)]
        ipv6_policy_json: Option<PathBuf>,
        #[arg(long)]
        service_persistence_json: Option<PathBuf>,
        #[arg(long)]
        service_reboot_json: Option<PathBuf>,
        #[arg(long)]
        dns_udp_next_scope_json: Option<PathBuf>,
        #[arg(long)]
        rollback_matrix_json: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        broad_capture_claimed: bool,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    WindowsMvpCompletionReview {
        #[arg(long)]
        windows_reach_json: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    WindowsDnsUdpNextLayerDesign {
        #[arg(long)]
        output_dir: PathBuf,
    },
    PhaseDMacosReachEvidence {
        #[arg(long)]
        pf_artifact: PathBuf,
        #[arg(long)]
        foreground_socks_artifact: PathBuf,
        #[arg(long)]
        launchdaemon_socks_artifact: PathBuf,
        #[arg(long)]
        utun_lab_artifact: Option<PathBuf>,
        #[arg(long)]
        utun_w1_artifact: Option<PathBuf>,
        #[arg(long)]
        utun_w2_artifact: Option<PathBuf>,
        #[arg(long)]
        utun_w3_artifact: Option<PathBuf>,
        #[arg(long)]
        utun_w4_artifact: Option<PathBuf>,
        #[arg(long)]
        utun_w5_artifact: Option<PathBuf>,
        #[arg(long)]
        network_extension_artifact: PathBuf,
        #[arg(long, default_value_t = false)]
        pf_system_wide_capture_claimed: bool,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    PhaseDAndroidReachEvidence {
        #[arg(long)]
        vpnservice_flow_json: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        production_claim: bool,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    MasterPlanHandoff {
        #[arg(long)]
        phase_c_resilience_json: PathBuf,
        #[arg(long)]
        phase_d_reach_json: Option<PathBuf>,
        #[arg(long)]
        artifact_dir: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    MasterPlanHandoffCheck {
        #[arg(long)]
        handoff_json: PathBuf,
    },
    BrainExternalCalibrationRuntimeProof {
        #[arg(long)]
        artifact_dir: PathBuf,
        #[arg(long)]
        output_json: Option<PathBuf>,
    },
    ReleaseLatestParity {
        #[arg(long)]
        server_result_json: PathBuf,
        #[arg(long)]
        client_result_json: PathBuf,
        #[arg(long)]
        negative_result_json: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    ReleaseOpsecGate {
        #[arg(long, required = true)]
        input: Vec<PathBuf>,
        #[arg(long)]
        pattern: Vec<String>,
        #[arg(long, default_value_t = false)]
        include_nm: bool,
        #[arg(long)]
        output_json: Option<PathBuf>,
    },
    /// Print the architecture name this binary uses when naming release
    /// artifacts. Packaging scripts compare their own name against it so the
    /// two can never drift apart again.
    HostArch,
    BuildReleaseDeliveryManifest {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        channel: String,
        #[arg(long)]
        prerelease: String,
        #[arg(long)]
        rpm_status: String,
        #[arg(long, default_value = "")]
        rpm_reason: String,
        #[arg(long)]
        git_sha: String,
        #[arg(long)]
        build_timestamp: String,
        #[arg(long)]
        debian_revision: Option<String>,
    },
    ReleasePackageMetadata {
        #[arg(long)]
        root: PathBuf,
    },
    MacosClientPackageMetadata {
        #[arg(long)]
        root: PathBuf,
    },
    PrintCargoPackageVersion {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        package_name: String,
    },
    BuildPackageRootManifest {
        #[arg(long)]
        package_dir: PathBuf,
        #[arg(long)]
        rootfs_dir: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        arch: String,
        #[arg(long)]
        target_triple: String,
        #[arg(long)]
        git_sha: String,
        #[arg(long)]
        build_timestamp: String,
    },
    BuildPublicClientDelivery {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        operator_bundle: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        channel: String,
        #[arg(long, action = clap::ArgAction::Set)]
        prerelease: bool,
    },
    StagePublicClientMirror {
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        expected_source: String,
    },
    BuildPrivateResearchManifest {
        #[arg(long)]
        bundle_dir: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        arch: String,
        #[arg(long)]
        target_triple: String,
        #[arg(long)]
        git_sha: String,
        #[arg(long)]
        cargo_lock_sha256: String,
    },
    BuildReleaseBundleManifest {
        #[arg(long)]
        bundle_dir: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        arch: String,
        #[arg(long)]
        target_triple: String,
        #[arg(long)]
        git_sha: String,
        #[arg(long)]
        build_timestamp: String,
        /// Exact just-built full administrative producer hash; absence retains legacy admission.
        #[arg(long)]
        administrative_measure_sha256: Option<String>,
        /// Exact JSON output of the fixed native client Cargo build.
        #[arg(long)]
        client_build_messages: Option<PathBuf>,
    },
    BuildMacosClientTarballManifest {
        #[arg(long)]
        bundle_dir: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        arch: String,
        #[arg(long)]
        target_triple: String,
        #[arg(long)]
        git_sha: String,
        #[arg(long)]
        build_timestamp: String,
    },
    WriteArchiveSha256 {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        sha256_path: PathBuf,
    },
    WriteDebMd5Sums {
        #[arg(long)]
        stage_dir: PathBuf,
        #[arg(long)]
        debian_dir: PathBuf,
    },
    BuildSplitDebManifest {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        deb_arch: String,
    },
    BuildDebPackageManifest {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        deb_name: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        deb_arch: String,
        #[arg(long)]
        rootfs_dir: PathBuf,
    },
    CheckDebPackageContractArtifacts {
        #[arg(long)]
        deb_path: PathBuf,
        #[arg(long)]
        deb_sha256_path: PathBuf,
        #[arg(long)]
        manifest_path: PathBuf,
        #[arg(long)]
        extract_dir: PathBuf,
        #[arg(long)]
        control_dir: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        deb_arch: String,
    },
    CheckSplitDebPackageContractArtifacts {
        #[arg(long)]
        server_deb: PathBuf,
        #[arg(long)]
        client_deb: PathBuf,
        #[arg(long)]
        server_sha256_path: PathBuf,
        #[arg(long)]
        client_sha256_path: PathBuf,
        #[arg(long)]
        manifest_path: PathBuf,
        #[arg(long)]
        server_extract_dir: PathBuf,
        #[arg(long)]
        server_control_dir: PathBuf,
        #[arg(long)]
        client_extract_dir: PathBuf,
        #[arg(long)]
        client_control_dir: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        deb_arch: String,
    },
    BuildRpmPackagesManifest {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        arch: String,
    },
    BuildLinuxWideLiveAuditManifest {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        output_dir: String,
        #[arg(long)]
        server_host: String,
        #[arg(long)]
        client_host: String,
        #[arg(long)]
        relay_address: String,
        #[arg(long)]
        runtime_events: String,
        #[arg(long)]
        preflight: String,
        #[arg(long)]
        startup_probe: String,
        #[arg(long)]
        wire_helper_stdout: String,
        #[arg(long, default_value = "")]
        witness_summary: String,
        #[arg(long, default_value = "")]
        witness_pcap: String,
        #[arg(long)]
        transient_runtime_events: String,
        #[arg(long)]
        wire_helper_runtime_events: String,
        #[arg(long)]
        wire_acceptance_summary: PathBuf,
        #[arg(long)]
        stealth_live_acceptance_bundle: PathBuf,
        #[arg(long)]
        stealth_live_acceptance_manifest: String,
        #[arg(long)]
        rerun_command: String,
        #[arg(long)]
        review_summary_command: String,
        #[arg(long)]
        review_manifest_command: String,
        #[arg(long, default_value = "")]
        handoff_status_json: String,
    },
    BuildLinuxWideLiveAuditHandoffStatus {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    LinuxWideLiveAuditManifestContractCheck {
        #[arg(long, required = true)]
        manifest: Vec<PathBuf>,
        #[arg(long, default_value_t = false)]
        expect_fail: bool,
    },
    LinuxWideLiveAuditHandoffStatusContractCheck {
        #[arg(long)]
        expected_topology_file: PathBuf,
        #[arg(long, required = true)]
        status_json: Vec<PathBuf>,
        #[arg(long, default_value_t = false)]
        expect_fail: bool,
    },
    LinuxWideLiveAuditHandoffStatusFixtureContractCheck {
        #[arg(long)]
        expected_topology_file: PathBuf,
        #[arg(long)]
        stealth_manifest: PathBuf,
        #[arg(long)]
        wire_manifest: PathBuf,
        #[arg(long)]
        green_manifest: PathBuf,
        #[arg(long)]
        stealth_status: PathBuf,
        #[arg(long)]
        wire_status: PathBuf,
        #[arg(long)]
        green_status: PathBuf,
    },
    LinuxWideLiveAuditMaterializedContractCheck {
        #[arg(long)]
        expected_topology_file: PathBuf,
        #[arg(long)]
        dry_run_output: PathBuf,
        #[arg(long)]
        stealth_manifest: PathBuf,
        #[arg(long)]
        wire_manifest: PathBuf,
        #[arg(long)]
        green_manifest: PathBuf,
        #[arg(long)]
        dry_run_manifest: PathBuf,
    },
    TransportCamouflageValidation {
        #[arg(long)]
        live_manifest_json: PathBuf,
        #[arg(long)]
        stealth_bundle_json: PathBuf,
        #[arg(long)]
        wire_acceptance_json: PathBuf,
        #[arg(long)]
        relay_surface_json: PathBuf,
        #[arg(long)]
        classifier_summary_json: PathBuf,
        #[arg(long)]
        witness_pcap: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    TrafficShapeScore {
        #[arg(long)]
        transport: String,
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        classifier_summary_json: PathBuf,
        #[arg(long)]
        pcap_summary_json: Option<PathBuf>,
        #[arg(long)]
        timing_summary_json: Option<PathBuf>,
        #[arg(long)]
        pcap_path: Option<PathBuf>,
        #[arg(long, default_value = "clean_fiber")]
        netem_profile: String,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    WitnessScore {
        #[arg(long)]
        transport: String,
        #[arg(long)]
        netem_profile: String,
        #[arg(long)]
        relay_pcap: PathBuf,
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        ndpi_summary_json: PathBuf,
        #[arg(long)]
        suricata_summary_json: PathBuf,
        #[arg(long)]
        reference_profile_json: Option<PathBuf>,
        #[arg(long, default_value = "tshark")]
        tshark_bin: String,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    MimicryMatrixReview {
        #[arg(long)]
        matrix_root: PathBuf,
        #[arg(long)]
        reference_status_json: Option<PathBuf>,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    ReferenceTimingBaseline {
        #[arg(long)]
        matrix_root: PathBuf,
        #[arg(long)]
        websocket_reference_json: Option<PathBuf>,
        #[arg(long)]
        grpc_reference_json: Option<PathBuf>,
        /// A real browser capture (JA3/JA4). The websocket/grpc references are
        /// curl and python-websockets; matching those is not the goal.
        #[arg(long)]
        browser_reference_json: Option<PathBuf>,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    ReferencePcapScore {
        #[arg(long)]
        artifact: String,
        #[arg(long)]
        transport: String,
        #[arg(long)]
        netem_profile: String,
        #[arg(long)]
        client_type: String,
        #[arg(long)]
        endpoint_url: String,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        pcap: PathBuf,
        #[arg(long)]
        ndpi_summary_json: PathBuf,
        #[arg(long)]
        suricata_summary_json: PathBuf,
        /// JA3/JA4 this reference is expected to carry, from the recorded
        /// live-browser capture. Without them the profile can only report that
        /// its fingerprints parsed, never that they are the browser's.
        #[arg(long)]
        expected_ja3: Option<String>,
        #[arg(long)]
        expected_ja4: Option<String>,
        #[arg(long, default_value = "tshark")]
        tshark_bin: String,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
    Sll2ToRawIp {
        #[arg(long)]
        input_pcap: PathBuf,
        #[arg(long)]
        output_pcap: PathBuf,
    },
    SuricataAlertCount {
        #[arg(long)]
        eve_json: PathBuf,
    },
    NdpiRiskCount {
        #[arg(long)]
        ndpi_output: PathBuf,
    },
    ClassifierVerdict {
        #[arg(long)]
        classifier: String,
        #[arg(long)]
        status: String,
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        transport: String,
        #[arg(long)]
        pcap: PathBuf,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        alert_count: Option<u64>,
        #[arg(long)]
        risk_count: Option<u64>,
        #[arg(long)]
        json_output: Option<PathBuf>,
        #[arg(long)]
        ndpi_input_pcap: Option<PathBuf>,
    },
    PrettyJson {
        #[arg(long)]
        input: PathBuf,
    },
    BuildDebianPackageHostRunSummary {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        operator_loop_summary: Option<PathBuf>,
        #[arg(long)]
        validation_root: String,
        #[arg(long)]
        upgrade_reapply_mode: String,
        #[arg(long)]
        phase: Vec<String>,
    },
    BuildDebianPackageHostValidationReport {
        #[arg(long)]
        mode: String,
        #[arg(long)]
        os_pretty_name: String,
        #[arg(long)]
        os_id: String,
        #[arg(long)]
        os_version_id: Option<String>,
        #[arg(long)]
        package_manager: Option<String>,
        #[arg(long)]
        supported_product_contour: String,
        #[arg(long)]
        supported_operator_scope: String,
        #[arg(long)]
        release_gate_name: String,
        #[arg(long)]
        release_gate_scope: String,
        #[arg(long)]
        host_family_id: String,
        #[arg(long)]
        host_family_validation_tier: String,
        #[arg(long)]
        ready: String,
        #[arg(long)]
        release_gate_required_phase: Vec<String>,
        #[arg(long)]
        command: Vec<String>,
        #[arg(long)]
        missing_command: Vec<String>,
        #[arg(long)]
        remediation_command: String,
        #[arg(long)]
        run_command: String,
        #[arg(long)]
        artifact_dir: Option<String>,
        #[arg(long)]
        release_handoff_artifact: Option<String>,
        #[arg(long)]
        release_summary_artifact: Option<String>,
        #[arg(long)]
        operator_loop_summary_artifact: Option<String>,
        #[arg(long)]
        pilot_inputs_artifact: Option<String>,
        #[arg(long)]
        validation_root: String,
        #[arg(long)]
        helper_exit_code: Option<i32>,
        #[arg(long)]
        error_code: Option<String>,
    },
    BuildDebianPackageHostOperatorLoopSummary {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        client_config: PathBuf,
        #[arg(long)]
        runtime_events: String,
        #[arg(long)]
        preflight_json: PathBuf,
        #[arg(long)]
        startup_probe_json: PathBuf,
        #[arg(long)]
        events_summary_json: PathBuf,
        #[arg(long)]
        operator_evidence_json: PathBuf,
        #[arg(long)]
        operator_evidence_txt: String,
    },
    BuildDebianPackageHostReleaseGateHandoff {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        host_summary: PathBuf,
    },
    BuildDebianPackageHostReleaseSummary {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        host_summary: PathBuf,
        #[arg(long)]
        release_handoff: PathBuf,
        #[arg(long)]
        operator_loop_summary: PathBuf,
    },
    BuildDebianPackageHostPilotInputs {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        validation_summary: PathBuf,
        #[arg(long)]
        runtime_artifacts_dir: PathBuf,
        #[arg(long)]
        release_handoff: PathBuf,
        #[arg(long)]
        release_summary: PathBuf,
        #[arg(long)]
        operator_loop_summary: PathBuf,
    },
    VerifyDebianPackageHostInstallState {
        #[arg(long)]
        dpkg_query: PathBuf,
        #[arg(long)]
        validation_root: PathBuf,
    },
    VerifyDebianPackageHostRemoveState {
        #[arg(long)]
        dpkg_query: PathBuf,
        #[arg(long)]
        validation_root: PathBuf,
    },
    VerifyDebianPackageHostPurgeState {
        #[arg(long)]
        dpkg_query: PathBuf,
        #[arg(long)]
        validation_root: PathBuf,
    },
    CheckDpkgLifecycleSmokeState {
        #[arg(long)]
        phase: String,
        #[arg(long)]
        rootdir: PathBuf,
        #[arg(long)]
        status_path: PathBuf,
        #[arg(long)]
        hook_log: PathBuf,
    },
    VerifyDebianPackageHostClientJsonArtifact {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        exit_status: i32,
    },
    BuildDebianPackageHostRuntimeEventsSummary {
        #[arg(long)]
        runtime_events: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    CheckDebianPackageHostContractJsonCase {
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        exit_status: i32,
    },
    CheckDebianPackageHostContractRunMode {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        validation_summary: PathBuf,
        #[arg(long)]
        release_handoff: PathBuf,
        #[arg(long)]
        release_summary: PathBuf,
        #[arg(long)]
        pilot_inputs: PathBuf,
        #[arg(long)]
        operator_loop: PathBuf,
        #[arg(long)]
        dpkg_log: PathBuf,
        #[arg(long)]
        helper_log: PathBuf,
        #[arg(long)]
        exit_status: i32,
        #[arg(long)]
        validation_root: PathBuf,
    },
    CheckDebianPackageHostContractScript {
        #[arg(long)]
        script: PathBuf,
    },
    BuildRpmPackageHostValidationReport {
        #[arg(long)]
        mode: String,
        #[arg(long)]
        os_pretty_name: String,
        #[arg(long)]
        os_id: String,
        #[arg(long)]
        os_version_id: Option<String>,
        #[arg(long)]
        package_manager: Option<String>,
        #[arg(long)]
        supported_product_contour: String,
        #[arg(long)]
        supported_operator_scope: String,
        #[arg(long)]
        host_family_id: String,
        #[arg(long)]
        host_family_validation_tier: String,
        #[arg(long)]
        ready: String,
        #[arg(long)]
        command: Vec<String>,
        #[arg(long)]
        missing_command: Vec<String>,
        #[arg(long)]
        remediation_command: String,
        #[arg(long)]
        run_command: String,
        #[arg(long)]
        validation_root: String,
        #[arg(long)]
        helper_exit_code: Option<i32>,
        #[arg(long)]
        error_code: Option<String>,
    },
    BuildRpmPackageHostRunSummary {
        #[arg(long)]
        validation_root: String,
    },
    WideSmokeAdversarialEvent {
        #[arg(long)]
        contract_json: PathBuf,
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        output_jsonl: PathBuf,
        #[arg(long, default_value = "masque_derived")]
        scenario: String,
        #[arg(long, default_value = "masque_derived")]
        transport: String,
        #[arg(long, default_value = "two-vps-linux-tproxy-generic-udp")]
        network_profile: String,
        #[arg(long, default_value = "")]
        artifact_dir: String,
        #[arg(long)]
        packet_capture: Option<PathBuf>,
        #[arg(long)]
        tcpdump_log: Option<PathBuf>,
    },
    ReserveTcpPort,
    WaitTcpPort {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long)]
        timeout_secs: f64,
    },
    RunWithTimeout {
        #[arg(long)]
        timeout_secs: f64,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    ValidateRelayTransportPriority {
        #[arg(long)]
        priority: String,
    },
    ConcatTextFiles {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        input: Vec<PathBuf>,
    },
    WarnRuntimeEventPresence {
        #[arg(long)]
        runtime_events: PathBuf,
        #[arg(long)]
        event_code: String,
        #[arg(long)]
        field_bool: Option<String>,
        #[arg(long)]
        empty_warning: String,
        #[arg(long)]
        missing_warning: String,
    },
    SocksHttpProbe {
        #[arg(long)]
        socks_port: u16,
        #[arg(long)]
        target_host: String,
        #[arg(long)]
        target_port: u16,
    },
    UdpEchoServer {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value_t = false)]
        reuse_addr: bool,
    },
    UdpEchoClient {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "wide-dns-smoke")]
        payload: String,
        #[arg(long, default_value_t = 15.0)]
        timeout_secs: f64,
    },
    TproxyClientContract {
        #[arg(long)]
        config: PathBuf,
    },
    TproxyStartupProbeFields {
        #[arg(long)]
        stdout: PathBuf,
        #[arg(long)]
        stderr: PathBuf,
    },
    TproxyRuntimeEventsSummary {
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        limit: usize,
    },
    WriteTproxyOperatorEvidence {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        client_config: Option<String>,
        #[arg(long)]
        runtime_events_jsonl: String,
        #[arg(long)]
        events_total: u64,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long)]
        backend_runtime_id: Option<String>,
        #[arg(long)]
        startup_health: String,
        #[arg(long)]
        runtime_status: String,
        #[arg(long)]
        product_verdict: String,
        #[arg(long)]
        runtime_degradation_count: u64,
        #[arg(long)]
        failover_count: u64,
        #[arg(long)]
        terminal_failure_count: u64,
        #[arg(long)]
        latest_code: Option<String>,
        #[arg(long)]
        latest_level: Option<String>,
        #[arg(long)]
        latest_message: Option<String>,
        #[arg(long)]
        problem_code: Option<String>,
        #[arg(long)]
        problem_level: Option<String>,
        #[arg(long)]
        problem_message: Option<String>,
    },
    WriteTproxySmokeContractArtifact {
        #[arg(long)]
        helper_apply_log: PathBuf,
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        smoke_protocol: String,
        #[arg(long)]
        ip_family: String,
        #[arg(long)]
        host_shape: String,
        #[arg(long)]
        firewall_backend: String,
        #[arg(long)]
        udp_capture_contract: String,
    },
    TproxyRuntimeDeliveryHint {
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
    },
    VerifyTproxyGenericUdpRuntimeContract {
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        target_port: u16,
        #[arg(long)]
        ip_family: String,
    },
    VerifyTproxyUdpPreviewDropRuntimeContract {
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        target_port: u16,
        #[arg(long)]
        dns_port: u16,
        #[arg(long)]
        udp_preview_ports: String,
        #[arg(long)]
        ip_family: String,
    },
    TproxyPreflightExit {
        #[arg(long)]
        preflight_json: PathBuf,
        #[arg(long)]
        preflight_log: PathBuf,
        #[arg(long)]
        status: i32,
        #[arg(long)]
        exit_needs_cap_net_admin: i32,
        #[arg(long)]
        exit_listener_conflict: i32,
        #[arg(long)]
        exit_listener_busy: i32,
        #[arg(long)]
        exit_unsupported_adapter: i32,
        #[arg(long)]
        exit_socks_bind_failed: i32,
        #[arg(long)]
        exit_rollout_prerequisites: i32,
        #[arg(long)]
        expected_interface: String,
    },
    WriteTproxyContractSelfTestEvents {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        smoke_protocol: String,
        #[arg(long)]
        target_host: String,
        #[arg(long)]
        target_port: u16,
        #[arg(long)]
        dns_port: u16,
        #[arg(long)]
        udp_preview_ports: String,
        #[arg(long)]
        support_tier: String,
        #[arg(long)]
        capture_policy: String,
        #[arg(long)]
        runtime_scope: String,
        #[arg(long)]
        preview_policy: Option<String>,
        #[arg(long)]
        variant: Option<String>,
    },
    VerifyTproxySmokeContractSelfTest {
        #[arg(long)]
        contract_artifact: PathBuf,
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        smoke_protocol: String,
        #[arg(long)]
        ip_family: String,
        #[arg(long)]
        firewall_backend_requested: String,
        #[arg(long)]
        expected_effective: String,
        #[arg(long)]
        expected_tier: String,
        #[arg(long)]
        expected_policy: String,
        #[arg(long)]
        expected_scope: String,
        #[arg(long, default_value_t = 0)]
        target_port: u16,
    },
    VerifyTproxyTransportFailureSelfTest {
        #[arg(long)]
        contract_artifact: PathBuf,
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
    },
    VerifyTproxyTransportRecoveredSelfTest {
        #[arg(long)]
        contract_artifact: PathBuf,
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
    },
    VerifyTproxyLoopbackIdempotentLog {
        #[arg(long)]
        ip_log: PathBuf,
    },
    ValidateRichHostBootstrap {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        bootstrap_status: i32,
    },
    BuildWideLinuxValidationHostBootstrapReport {
        #[arg(long)]
        mode: String,
        #[arg(long)]
        os_pretty_name: String,
        #[arg(long)]
        os_id: String,
        #[arg(long)]
        os_version_id: Option<String>,
        #[arg(long)]
        package_manager: Option<String>,
        #[arg(long)]
        supported_product_contour: String,
        #[arg(long)]
        supported_operator_scope: String,
        #[arg(long)]
        host_family_id: String,
        #[arg(long)]
        host_family_validation_tier: String,
        #[arg(long)]
        install_rustup: String,
        #[arg(long)]
        ready: String,
        #[arg(long)]
        command: Vec<String>,
        #[arg(long)]
        missing_command: Vec<String>,
        #[arg(long)]
        sudo_status: String,
        #[arg(long)]
        sudo_detail: String,
        #[arg(long)]
        remediation_command: String,
        #[arg(long)]
        bootstrap_check_command: String,
        #[arg(long)]
        bootstrap_install_command: String,
        #[arg(long)]
        validation_command: String,
        #[arg(long)]
        upgrade_reapply_command: String,
        #[arg(long)]
        helper_exit_code: Option<i32>,
        #[arg(long)]
        error_code: Option<String>,
    },
    CheckWideLinuxValidationHostBootstrapContractCase {
        #[arg(long)]
        case_id: String,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        status: i32,
        #[arg(long)]
        command_log: Option<PathBuf>,
        #[arg(long)]
        expected_cargo: Option<String>,
        #[arg(long)]
        package_manager: Option<String>,
        #[arg(long)]
        command_snippet: Option<String>,
    },
    CheckWideLinuxValidationHostBootstrapCoverage {
        #[arg(long)]
        repo_root: PathBuf,
    },
    WriteRichHostMatrixTargets {
        #[arg(long)]
        output: PathBuf,
    },
    BuildRichHostMetadata {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        host_bootstrap: PathBuf,
    },
    BuildRichHostMatrixSummary {
        #[arg(long)]
        status_dir: PathBuf,
        #[arg(long)]
        artifact_dir: PathBuf,
        #[arg(long)]
        matrix_targets: PathBuf,
        #[arg(long)]
        matrix_results: PathBuf,
        #[arg(long)]
        matrix_summary: PathBuf,
        #[arg(long)]
        host_metadata: PathBuf,
        #[arg(long)]
        host_bootstrap: PathBuf,
    },
    BuildRichHostValidationBundle {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        artifact_dir: PathBuf,
        #[arg(long)]
        matrix_targets: PathBuf,
        #[arg(long)]
        matrix_results: PathBuf,
        #[arg(long)]
        matrix_summary: PathBuf,
        #[arg(long)]
        host_metadata: PathBuf,
        #[arg(long)]
        host_bootstrap: PathBuf,
        #[arg(long)]
        rerun_env: PathBuf,
        #[arg(long)]
        rerun_script: PathBuf,
        #[arg(long)]
        bootstrap_helper: PathBuf,
        #[arg(long)]
        validation_script: PathBuf,
        #[arg(long)]
        cargo_target_dir: String,
        #[arg(long)]
        startup_wait_secs: u64,
        #[arg(long)]
        request_timeout_secs: u64,
        #[arg(long)]
        case_timeout_secs: u64,
    },
    CheckRichHostValidationContractArtifacts {
        #[arg(long)]
        artifact_dir: PathBuf,
        #[arg(long)]
        repo_root: PathBuf,
        #[arg(long)]
        failed_artifact_dir: PathBuf,
        #[arg(long)]
        bootstrap_fail_artifact_dir: PathBuf,
        #[arg(long)]
        bootstrap_fail_output: PathBuf,
        #[arg(long)]
        bootstrap_broken_artifact_dir: PathBuf,
        #[arg(long)]
        bootstrap_broken_output: PathBuf,
    },
    WideRedirectPreflightExit {
        #[arg(long)]
        preflight_json: PathBuf,
        #[arg(long)]
        preflight_log: PathBuf,
        #[arg(long)]
        status: i32,
        #[arg(long)]
        exit_listener_conflict: i32,
        #[arg(long)]
        exit_listener_busy: i32,
        #[arg(long)]
        exit_unsupported_adapter: i32,
        #[arg(long)]
        exit_socks_bind_failed: i32,
        #[arg(long)]
        exit_rollout_prerequisites: i32,
        #[arg(long, default_value = "")]
        expected_interface: String,
    },
    BuildRelaySurfaceRuntimeSummary {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        runtime_events: PathBuf,
    },
    BuildStealthHostilePathAcceptanceSummary {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        wire_acceptance_summary: PathBuf,
        #[arg(long)]
        polymorphism_acceptance_summary: PathBuf,
        #[arg(long)]
        relay_surface_runtime_summary: Option<PathBuf>,
    },
    BuildStealthAntiAnomalyAcceptanceSummary {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = ".")]
        repo_root: PathBuf,
    },
    BuildStealthPolymorphismAcceptanceSummary {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        repo_root: PathBuf,
        #[arg(long)]
        now_secs: u64,
    },
    BuildMimicryWireWitnessSummary {
        #[arg(long)]
        pcap: PathBuf,
        #[arg(long)]
        runtime_events: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "tshark")]
        tshark_bin: String,
        #[arg(long, default_value_t = 2000)]
        window_ms: i64,
    },
    BuildMimicryWireValidationContract {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = ".")]
        repo_root: PathBuf,
    },
    BuildMimicryWireHostAcceptance {
        #[arg(long)]
        runtime_events_jsonl: PathBuf,
        #[arg(long)]
        contract_json: PathBuf,
        #[arg(long)]
        capture_summary_json: PathBuf,
        #[arg(long)]
        host_summary_json: PathBuf,
        #[arg(long)]
        witness_summary_json: Option<PathBuf>,
    },
    BuildMimicryWireHostHelperReport {
        #[arg(long)]
        mode: String,
        #[arg(long)]
        supported_operator_scope: String,
        #[arg(long)]
        supported_product_contour: String,
        #[arg(long)]
        ready: String,
        #[arg(long)]
        runtime_events_jsonl: Option<String>,
        #[arg(long)]
        witness_summary_json: Option<String>,
        #[arg(long)]
        artifact_dir: Option<String>,
        #[arg(long)]
        requirement: Vec<String>,
        #[arg(long)]
        missing_requirement: Vec<String>,
        #[arg(long)]
        helper_exit_code: i32,
        #[arg(long)]
        error_code: Option<String>,
    },
    CheckMimicryWireHostHelperReportContract {
        #[arg(long)]
        report_json: PathBuf,
    },
    CheckMimicryWireHostAcceptanceContract {
        #[arg(long)]
        host_summary_json: PathBuf,
        #[arg(long)]
        capture_summary_json: Option<PathBuf>,
        #[arg(long)]
        stdout_json: Option<PathBuf>,
        #[arg(long)]
        expected_product_verdict: String,
        #[arg(long)]
        expected_acceptance_status: String,
        #[arg(long)]
        expected_verdict_reason: String,
        #[arg(long)]
        expected_witness_status: Option<String>,
        #[arg(long)]
        expected_hostile_path_ready: Option<bool>,
        #[arg(long)]
        expected_hostile_path_tier: Option<String>,
        #[arg(long)]
        expected_witness_matched: Option<u64>,
        #[arg(long)]
        expected_witness_mismatched: Option<u64>,
        #[arg(long)]
        expected_mismatch_field: Option<String>,
        #[arg(long)]
        expected_records_scanned: Option<u64>,
        #[arg(long)]
        expected_complete_records: Option<u64>,
        #[arg(long)]
        expected_active_ready_count: Option<u64>,
        #[arg(long)]
        expected_active_missing_count: Option<u64>,
    },
    BuildStealthLiveAcceptanceBundle {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        wire_acceptance_summary: PathBuf,
        #[arg(long)]
        runtime_events: PathBuf,
        #[arg(long)]
        relay_runtime_events: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        polymorphism_summary: PathBuf,
        #[arg(long)]
        relay_surface_runtime_summary: PathBuf,
        #[arg(long)]
        hostile_path_summary: PathBuf,
    },
    BuildPostReleaseStealthWaveSummary {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        ubuntu_release_wave_status: Option<PathBuf>,
        #[arg(long)]
        wire_acceptance_summary: Option<PathBuf>,
    },
    BuildLinuxNextExpansionStatus {
        #[arg(long)]
        matrix_manifest: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        review_json: Option<PathBuf>,
    },
    BuildLinuxNextExpansionPlaybook {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        matrix_manifest: PathBuf,
        #[arg(long)]
        target_family: Option<String>,
        #[arg(long, default_value = "next-linux-validation-host")]
        host_label: String,
    },
    BuildLinuxNextExpansionWaveManifest {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        mode: String,
        #[arg(long)]
        source_json: PathBuf,
        #[arg(long)]
        status_json: PathBuf,
    },
    LinuxNextExpansionReviewInputs {
        #[arg(long)]
        matrix_manifest: PathBuf,
        #[arg(long)]
        target_evidence: PathBuf,
        #[arg(long)]
        target_family: Option<String>,
    },
    BuildLinuxNextExpansionReviewBundleArtifacts {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        previous_matrix_manifest: PathBuf,
        #[arg(long)]
        target_evidence: PathBuf,
        #[arg(long)]
        playbook_json: PathBuf,
        #[arg(long)]
        refreshed_matrix_manifest: PathBuf,
        #[arg(long)]
        host_label: String,
    },
    BuildLinuxReleaseProgramBundle {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        ubuntu_wave_manifest: PathBuf,
        #[arg(long)]
        next_expansion_status: Option<PathBuf>,
        #[arg(long)]
        stealth_summary: Option<PathBuf>,
        #[arg(long)]
        mimicry_next_contour: Option<PathBuf>,
    },
    BuildLinuxPackageAcceptanceMatrix {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, required = true)]
        evidence: Vec<PathBuf>,
    },
    BuildMacosPfOperatorAcceptanceSummary {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        rooted_live_dir: PathBuf,
        #[arg(long)]
        phase4_dir: Option<PathBuf>,
    },
    MacosPfStateBasename {
        #[arg(long)]
        state_base_dir: String,
        #[arg(long)]
        home: Option<String>,
        #[arg(long)]
        user: Option<String>,
    },
    MacosPfReadStateJson {
        #[arg(long)]
        state_path: PathBuf,
    },
    MacosPfReadStateField {
        #[arg(long)]
        state_path: PathBuf,
        #[arg(long)]
        field: String,
    },
    BuildMacosUtunBlockedResult {
        #[arg(long)]
        artifact: String,
        #[arg(long)]
        status: String,
        #[arg(long)]
        blocker: String,
        #[arg(long)]
        output_json: PathBuf,
    },
    BuildMacosUtunW0BlockedResult {
        #[arg(long)]
        status: String,
        #[arg(long)]
        blocker: String,
        #[arg(long)]
        output_json: PathBuf,
    },
    BuildMacosUtunW0TimeoutResult {
        #[arg(long)]
        helper_exit: String,
        #[arg(long)]
        main_exit: String,
        #[arg(long)]
        output_json: PathBuf,
    },
    BuildMacosUtunW1Result {
        #[arg(long)]
        status: String,
        #[arg(long)]
        verdict: String,
        #[arg(long)]
        helper_exit: String,
        #[arg(long)]
        main_exit: String,
        #[arg(long)]
        packet_loop_pass: String,
        #[arg(long)]
        route_proof_pass: String,
        #[arg(long)]
        controlled_peer: String,
        #[arg(long)]
        relay_ip: String,
        #[arg(long)]
        output_json: PathBuf,
    },
    BuildMacosUtunW2Result {
        #[arg(long)]
        artifact: String,
        #[arg(long)]
        status: String,
        #[arg(long)]
        verdict: String,
        #[arg(long)]
        helper_exit: String,
        #[arg(long)]
        main_exit: String,
        #[arg(long)]
        packet_loop_pass: String,
        #[arg(long)]
        route_proof_pass: String,
        #[arg(long)]
        tcp_flow_observed: String,
        #[arg(long)]
        tcp_destination_port_match: String,
        #[arg(long)]
        tcp_synack_lab_pass: Option<String>,
        #[arg(long)]
        tcp_ack_observed: Option<String>,
        #[arg(long)]
        controlled_peer: String,
        #[arg(long)]
        controlled_tcp_port: u16,
        #[arg(long)]
        packet_to_flow_adapter: String,
        #[arg(long)]
        output_json: PathBuf,
    },
    BuildUbuntuReleaseGateStatus {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        host_summary: Option<PathBuf>,
    },
    BuildUbuntuOperatorReapplyCanary {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        pilot_inputs: PathBuf,
    },
    BuildUbuntuProductOperatorLoopSummary {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        client_config: String,
        #[arg(long)]
        runtime_events_jsonl: String,
        #[arg(long)]
        operator_evidence_json: PathBuf,
        #[arg(long)]
        doctor_log: String,
        #[arg(long)]
        probe_log: String,
        #[arg(long)]
        events_log: String,
        #[arg(long)]
        doctor_status: i64,
        #[arg(long)]
        probe_status: i64,
        #[arg(long)]
        events_status: i64,
    },
    BuildUbuntuProductOperatorLoopCheckReport {
        #[arg(long)]
        mode: String,
        #[arg(long)]
        supported_product_contour: String,
        #[arg(long)]
        supported_operator_scope: String,
        #[arg(long)]
        helper_script: String,
        #[arg(long)]
        client_config: Option<String>,
        #[arg(long)]
        runtime_events_jsonl: Option<String>,
        #[arg(long)]
        operator_evidence_json: Option<String>,
        #[arg(long)]
        artifact_dir: Option<String>,
        #[arg(long)]
        ready: String,
        #[arg(long)]
        requirement: Vec<String>,
        #[arg(long)]
        missing_requirement: Vec<String>,
        #[arg(long)]
        helper_exit_code: i32,
        #[arg(long)]
        error_code: Option<String>,
    },
    CheckRpmPackageHostContractJsonCase {
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        exit_status: i32,
    },
    CheckRpmPackageHostContractRunMode {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        validation_summary: PathBuf,
        #[arg(long)]
        rpm_log: PathBuf,
        #[arg(long)]
        exit_status: i32,
        #[arg(long)]
        validation_root: PathBuf,
    },
    CheckRpmPackageHostContractScript {
        #[arg(long)]
        script: PathBuf,
    },
    BuildUbuntuControlledPilotPlaybook {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "ubuntu-relay-host")]
        relay_host: String,
        #[arg(long, default_value = "ubuntu-client-host")]
        client_host: String,
        #[arg(long, default_value = "hostile_or_blocked_network_shape")]
        blocked_shape: String,
        /// Existing archive pathname; default is the bundle handoff path.
        #[arg(long, conflicts_with = "bundle_url_file")]
        bundle: Option<PathBuf>,
        /// Opaque private record path on the target client; never read here.
        #[arg(long, conflicts_with = "bundle")]
        bundle_url_file: Option<PathBuf>,
    },
    BuildUbuntuMimicryNextContour {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        stealth_summary: Option<PathBuf>,
        #[arg(long)]
        wire_contract: PathBuf,
    },
    BuildUbuntuReleaseWaveStatus {
        #[arg(long)]
        pilot_inputs: PathBuf,
        #[arg(long)]
        pilot_review_manifest: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    BuildUbuntuReleaseReview {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        release_summary: PathBuf,
        #[arg(long)]
        pilot_bundle: PathBuf,
        #[arg(long)]
        matrix_manifest: Option<PathBuf>,
        #[arg(long)]
        wire_acceptance_summary: Option<PathBuf>,
    },
    BuildUbuntuReleaseWaveBundleManifest {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        pilot_review_manifest: PathBuf,
        #[arg(long)]
        wave_status: PathBuf,
    },
    BuildUbuntuFieldPilotRemoteBundleManifest {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        pilot_inputs: PathBuf,
        #[arg(long)]
        pilot_review_manifest: PathBuf,
        #[arg(long)]
        release_wave_status: PathBuf,
        #[arg(long)]
        release_wave_manifest: PathBuf,
    },
    UbuntuPilotInputsReleaseSummary {
        #[arg(long)]
        pilot_inputs: PathBuf,
    },
    BuildUbuntuControlledPilotReviewBundleManifest {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        pilot_inputs: PathBuf,
        #[arg(long)]
        playbook_json: PathBuf,
        #[arg(long)]
        operator_canary_json: PathBuf,
        #[arg(long)]
        pilot_summary_json: PathBuf,
        #[arg(long)]
        release_review_json: PathBuf,
        #[arg(long)]
        matrix_manifest: Option<PathBuf>,
        #[arg(long)]
        wire_witness_summary: Option<PathBuf>,
        #[arg(long)]
        wire_acceptance_summary: Option<PathBuf>,
    },
    UbuntuControlledPilotInputFields {
        #[arg(long)]
        pilot_inputs: PathBuf,
    },
    BuildUbuntuControlledPilotBundle {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        server_status: PathBuf,
        #[arg(long)]
        server_journal: PathBuf,
        #[arg(long)]
        client_preflight: PathBuf,
        #[arg(long)]
        client_startup_probe: PathBuf,
        #[arg(long)]
        client_runtime_events_summary: PathBuf,
        #[arg(long)]
        client_operator_evidence: PathBuf,
        #[arg(long)]
        validation_summary: Option<PathBuf>,
        #[arg(long)]
        release_summary: Option<PathBuf>,
        #[arg(long)]
        operator_loop_summary: Option<PathBuf>,
        #[arg(long)]
        release_handoff: Option<PathBuf>,
        #[arg(long)]
        pilot_inputs: Option<PathBuf>,
        #[arg(long)]
        wire_witness_summary: Option<PathBuf>,
        #[arg(long)]
        wire_acceptance_summary: Option<PathBuf>,
        #[arg(long)]
        server_host: String,
        #[arg(long)]
        client_host: String,
        #[arg(long)]
        blocked_shape: String,
    },
    PhaseAMeasureGateReview {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = false)]
        skip_knowledge_check: bool,
        #[arg(long, default_value_t = false)]
        applied: bool,
    },
    PhaseAMeasureGateContractCheck {
        #[arg(long)]
        gate: PathBuf,
        #[arg(long)]
        measured_gate: PathBuf,
        #[arg(long)]
        matrix_gate: PathBuf,
        #[arg(long)]
        imported_gate: PathBuf,
        #[arg(long)]
        imported_witness_gate: PathBuf,
    },
    AdversarialRunner {
        #[arg(long)]
        scenario: Option<String>,
        #[arg(long)]
        network_profile: Option<String>,
        #[arg(long)]
        output_jsonl: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        #[arg(long)]
        live_command: Option<String>,
        #[arg(long, default_value_t = false)]
        live_matrix: bool,
        #[arg(long, default_value_t = 30.0)]
        timeout_seconds: f64,
    },
    AdversarialRunnerContractCheck {
        #[arg(long)]
        tmp_dir: PathBuf,
    },
    /// Phase 3 KPI summary. Computes the master-plan release-readiness KPI
    /// set from local inputs (state.json, runtime-events JSONL, the
    /// bootstrap installer script, and an optional historical
    /// witness-matrix result). Marks Phase-4-dependent KPIs as
    /// `DEFERRED_PHASE_4` rather than fabricating values.
    Phase3KpiSummary {
        /// Optional path to `state.json` for `transport_survival_rate`.
        #[arg(long)]
        state_json: Option<PathBuf>,
        /// Zero or more runtime-events JSONL files used to extract
        /// `relay_failover_recovery_time` from `relay_transport_failed`
        /// → `relay_session_succeeded` pairs.
        #[arg(long)]
        runtime_events_jsonl: Vec<PathBuf>,
        /// Bootstrap installer script (default `bootstrap-install.sh`).
        #[arg(long, default_value = "bootstrap-install.sh")]
        bootstrap_script: PathBuf,
        /// Optional JSON artifact from a real blocked-primary-host install run,
        /// shaped `{ "attempts": N, "successes": M }`. `bootstrap_survival_under_block`
        /// is a rate, so without trials it reports INSUFFICIENT_EVIDENCE — the static
        /// script audit alone can only report whether a fallback path exists.
        #[arg(long)]
        bootstrap_survival_trials: Option<PathBuf>,
        /// Optional path to a prior `mimicry-http-like-witness-matrix`
        /// `result.json` to surface historical witness-score values
        /// alongside the DEFERRED_PHASE_4 status.
        #[arg(long)]
        historical_witness_matrix: Option<PathBuf>,
        #[arg(long)]
        output_json: PathBuf,
        #[arg(long)]
        output_markdown: Option<PathBuf>,
    },
}
