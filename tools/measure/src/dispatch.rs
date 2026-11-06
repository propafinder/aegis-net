use crate::calibration_dispatch;
use crate::cli::Command;
use crate::master_dispatch;
use crate::phase3_kpi_dispatch;
use crate::phase_a_dispatch;
use crate::phase_b_dispatch;
use crate::phase_c_dispatch;
use crate::phase_d_dispatch;
use crate::release_dispatch;
use crate::tool_dispatch;
use crate::transport_dispatch;

pub fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    if calibration_dispatch::is_calibration(&command) {
        return calibration_dispatch::run(command);
    }
    if phase3_kpi_dispatch::is_phase3_kpi(&command) {
        return phase3_kpi_dispatch::run(command);
    }
    if phase_a_dispatch::is_phase_a(&command) {
        return phase_a_dispatch::run(command);
    }
    if phase_b_dispatch::is_phase_b(&command) {
        return phase_b_dispatch::run(command);
    }
    if phase_c_dispatch::is_phase_c(&command) {
        return phase_c_dispatch::run(command);
    }
    if phase_d_dispatch::is_phase_d(&command) {
        return phase_d_dispatch::run(command);
    }
    if tool_dispatch::is_tooling(&command) {
        return tool_dispatch::run(command);
    }
    if master_dispatch::is_master_control(&command) {
        return master_dispatch::run(command);
    }
    if transport_dispatch::is_transport(&command) {
        return transport_dispatch::run(command);
    }
    if release_dispatch::is_release(&command) {
        return release_dispatch::run(command);
    }

    match command {
        Command::ResearchToolNotices {
            root,
            target,
            output,
        } => {
            use std::io::Write;
            if ![
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
                "x86_64-pc-windows-msvc",
            ]
            .contains(&target.as_str())
            {
                return Err("research notices target refused".into());
            }
            let bytes = crate::public_client_delivery::research_notices(&root, &target)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok(())
        }
        // A full build-side tool must not self-report the restricted delivery role.
        Command::ResearchBuildInfo => {
            Err("full build-side tool is not a delivered research producer".into())
        }
        Command::PoissonControl {
            config_json,
            input_file,
            output_file,
        } => {
            crate::research_command::run(crate::research_command::ResearchCommand::PoissonControl {
                config_json,
                input_file,
                output_file,
            })
        }
        Command::PoissonInsertion {
            config_json,
            application_input,
            control_input,
            application_output,
            control_output,
        } => crate::research_command::run(
            crate::research_command::ResearchCommand::PoissonInsertion {
                config_json,
                application_input,
                control_input,
                application_output,
                control_output,
            },
        ),
        Command::PrivateControl {
            config_json,
            input_file,
            output_file,
        } => {
            crate::research_command::run(crate::research_command::ResearchCommand::PrivateControl {
                config_json,
                input_file,
                output_file,
            })
        }
        Command::PrivacyPcapExport {
            input_pcap,
            output_tsv,
        } => crate::research_command::run(
            crate::research_command::ResearchCommand::PrivacyPcapExport {
                input_pcap,
                output_tsv,
            },
        ),
        Command::PrivacyStudyAssemble {
            input_json,
            output_json,
        } => crate::research_command::run(
            crate::research_command::ResearchCommand::PrivacyStudyAssemble {
                input_json,
                output_json,
            },
        ),
        Command::BrainOutcomeReplay {
            input_jsonl,
            provenance_json,
            output_json,
        } => crate::research_command::run(
            crate::research_command::ResearchCommand::BrainOutcomeReplay {
                input_jsonl,
                provenance_json,
                output_json,
            },
        ),
        Command::PrivacyFrontier {
            input_json,
            output_json,
        } => crate::research_command::run(
            crate::research_command::ResearchCommand::PrivacyFrontier {
                input_json,
                output_json,
            },
        ),
        Command::HostileSummary { .. }
        | Command::ExternalCalibrationSummary { .. }
        | Command::ExternalCalibrationContractCheck { .. } => {
            unreachable!("calibration commands are delegated before generic dispatch")
        }
        Command::Phase3KpiSummary { .. } => {
            unreachable!("phase3-kpi-summary is delegated before generic dispatch")
        }
        Command::PhaseAExitReview { .. }
        | Command::PhaseAMeasureGateReview { .. }
        | Command::PhaseAMeasureGateContractCheck { .. } => {
            unreachable!("phase a commands are delegated before generic dispatch")
        }
        Command::PhaseBBaselineReview { .. }
        | Command::PhaseBTlsWireReview { .. }
        | Command::PhaseBRelayShapeReview { .. }
        | Command::PhaseBActiveProbeReview { .. }
        | Command::PhaseBLiveEvidenceReview { .. }
        | Command::PhaseBRuntimeEvidenceManifest { .. }
        | Command::PhaseBRuntimeEvidenceManifestCheck { .. }
        | Command::PhaseBMasterPlanStatus { .. }
        | Command::PhaseBScoreParityGate { .. } => {
            unreachable!("phase b commands are delegated before generic dispatch")
        }
        Command::PhaseCResilienceGate { .. }
        | Command::PhaseCMultiRelayEvidence { .. }
        | Command::PhaseCBundleMirrorsEvidence { .. }
        | Command::PhaseCFrontedTransportEvidence { .. }
        | Command::PhaseCFrontedBlockedResult { .. }
        | Command::PhaseCFrontedProbeAttempt { .. }
        | Command::PhaseCFrontedProviderPreflight { .. } => {
            unreachable!("phase c commands are delegated before generic dispatch")
        }
        Command::PhaseDReachGate { .. }
        | Command::PhaseDWindowsReachEvidence { .. }
        | Command::WindowsMvpCompletionReview { .. }
        | Command::WindowsDnsUdpNextLayerDesign { .. }
        | Command::PhaseDMacosReachEvidence { .. }
        | Command::PhaseDAndroidReachEvidence { .. } => {
            unreachable!("phase d commands are delegated before generic dispatch")
        }
        Command::MasterPlanHandoff { .. }
        | Command::MasterPlanHandoffCheck { .. }
        | Command::BrainExternalCalibrationRuntimeProof { .. } => {
            unreachable!("master commands are delegated before generic dispatch")
        }
        Command::TransportCamouflageValidation { .. }
        | Command::TrafficShapeScore { .. }
        | Command::WitnessScore { .. }
        | Command::MimicryMatrixReview { .. }
        | Command::ReferenceTimingBaseline { .. }
        | Command::ReferencePcapScore { .. } => {
            unreachable!("transport commands are delegated before generic dispatch")
        }
        Command::ReleaseLatestParity { .. }
        | Command::ReleaseOpsecGate { .. }
        | Command::HostArch
        | Command::BuildReleaseDeliveryManifest { .. }
        | Command::BuildPublicClientDelivery { .. }
        | Command::StagePublicClientMirror { .. }
        | Command::ReleasePackageMetadata { .. }
        | Command::MacosClientPackageMetadata { .. }
        | Command::PrintCargoPackageVersion { .. }
        | Command::BuildPackageRootManifest { .. }
        | Command::BuildPrivateResearchManifest { .. }
        | Command::BuildReleaseBundleManifest { .. }
        | Command::BuildMacosClientTarballManifest { .. }
        | Command::WriteArchiveSha256 { .. }
        | Command::WriteDebMd5Sums { .. }
        | Command::BuildSplitDebManifest { .. }
        | Command::BuildDebPackageManifest { .. }
        | Command::CheckDebPackageContractArtifacts { .. }
        | Command::CheckSplitDebPackageContractArtifacts { .. }
        | Command::BuildRpmPackagesManifest { .. }
        | Command::BuildLinuxWideLiveAuditManifest { .. }
        | Command::BuildLinuxWideLiveAuditHandoffStatus { .. }
        | Command::LinuxWideLiveAuditManifestContractCheck { .. }
        | Command::LinuxWideLiveAuditHandoffStatusContractCheck { .. }
        | Command::LinuxWideLiveAuditHandoffStatusFixtureContractCheck { .. }
        | Command::LinuxWideLiveAuditMaterializedContractCheck { .. } => {
            unreachable!("release commands are delegated before generic dispatch")
        }
        Command::Sll2ToRawIp { .. }
        | Command::SuricataAlertCount { .. }
        | Command::NdpiRiskCount { .. }
        | Command::ClassifierVerdict { .. }
        | Command::PrettyJson { .. }
        | Command::BuildDebianPackageHostRunSummary { .. }
        | Command::BuildDebianPackageHostValidationReport { .. }
        | Command::BuildDebianPackageHostOperatorLoopSummary { .. }
        | Command::BuildDebianPackageHostReleaseGateHandoff { .. }
        | Command::BuildDebianPackageHostReleaseSummary { .. }
        | Command::BuildDebianPackageHostPilotInputs { .. }
        | Command::VerifyDebianPackageHostInstallState { .. }
        | Command::VerifyDebianPackageHostRemoveState { .. }
        | Command::VerifyDebianPackageHostPurgeState { .. }
        | Command::CheckDpkgLifecycleSmokeState { .. }
        | Command::VerifyDebianPackageHostClientJsonArtifact { .. }
        | Command::BuildDebianPackageHostRuntimeEventsSummary { .. }
        | Command::CheckDebianPackageHostContractJsonCase { .. }
        | Command::CheckDebianPackageHostContractRunMode { .. }
        | Command::CheckDebianPackageHostContractScript { .. }
        | Command::BuildRpmPackageHostValidationReport { .. }
        | Command::BuildRpmPackageHostRunSummary { .. }
        | Command::CheckRpmPackageHostContractJsonCase { .. }
        | Command::CheckRpmPackageHostContractRunMode { .. }
        | Command::CheckRpmPackageHostContractScript { .. }
        | Command::WideSmokeAdversarialEvent { .. }
        | Command::ReserveTcpPort
        | Command::WaitTcpPort { .. }
        | Command::RunWithTimeout { .. }
        | Command::ValidateRelayTransportPriority { .. }
        | Command::ConcatTextFiles { .. }
        | Command::WarnRuntimeEventPresence { .. }
        | Command::SocksHttpProbe { .. }
        | Command::UdpEchoServer { .. }
        | Command::UdpEchoClient { .. }
        | Command::TproxyClientContract { .. }
        | Command::TproxyStartupProbeFields { .. }
        | Command::TproxyRuntimeEventsSummary { .. }
        | Command::WriteTproxyOperatorEvidence { .. }
        | Command::WriteTproxySmokeContractArtifact { .. }
        | Command::TproxyRuntimeDeliveryHint { .. }
        | Command::VerifyTproxyGenericUdpRuntimeContract { .. }
        | Command::VerifyTproxyUdpPreviewDropRuntimeContract { .. }
        | Command::TproxyPreflightExit { .. }
        | Command::WriteTproxyContractSelfTestEvents { .. }
        | Command::VerifyTproxySmokeContractSelfTest { .. }
        | Command::VerifyTproxyTransportFailureSelfTest { .. }
        | Command::VerifyTproxyTransportRecoveredSelfTest { .. }
        | Command::VerifyTproxyLoopbackIdempotentLog { .. }
        | Command::ValidateRichHostBootstrap { .. }
        | Command::BuildWideLinuxValidationHostBootstrapReport { .. }
        | Command::CheckWideLinuxValidationHostBootstrapContractCase { .. }
        | Command::CheckWideLinuxValidationHostBootstrapCoverage { .. }
        | Command::WriteRichHostMatrixTargets { .. }
        | Command::BuildRichHostMetadata { .. }
        | Command::BuildRichHostMatrixSummary { .. }
        | Command::BuildRichHostValidationBundle { .. }
        | Command::CheckRichHostValidationContractArtifacts { .. }
        | Command::WideRedirectPreflightExit { .. } => {
            unreachable!("tooling commands are delegated before generic dispatch")
        }
        Command::BuildRelaySurfaceRuntimeSummary { .. }
        | Command::BuildStealthHostilePathAcceptanceSummary { .. }
        | Command::BuildStealthAntiAnomalyAcceptanceSummary { .. }
        | Command::BuildStealthPolymorphismAcceptanceSummary { .. }
        | Command::BuildMimicryWireWitnessSummary { .. }
        | Command::BuildMimicryWireValidationContract { .. }
        | Command::BuildMimicryWireHostAcceptance { .. }
        | Command::BuildMimicryWireHostHelperReport { .. }
        | Command::CheckMimicryWireHostHelperReportContract { .. }
        | Command::CheckMimicryWireHostAcceptanceContract { .. }
        | Command::BuildStealthLiveAcceptanceBundle { .. }
        | Command::BuildPostReleaseStealthWaveSummary { .. }
        | Command::BuildLinuxNextExpansionStatus { .. }
        | Command::BuildLinuxNextExpansionPlaybook { .. }
        | Command::BuildLinuxNextExpansionWaveManifest { .. }
        | Command::LinuxNextExpansionReviewInputs { .. }
        | Command::BuildLinuxNextExpansionReviewBundleArtifacts { .. }
        | Command::BuildLinuxReleaseProgramBundle { .. }
        | Command::BuildLinuxPackageAcceptanceMatrix { .. }
        | Command::BuildMacosPfOperatorAcceptanceSummary { .. }
        | Command::MacosPfStateBasename { .. }
        | Command::MacosPfReadStateJson { .. }
        | Command::MacosPfReadStateField { .. }
        | Command::BuildMacosUtunBlockedResult { .. }
        | Command::BuildMacosUtunW0BlockedResult { .. }
        | Command::BuildMacosUtunW0TimeoutResult { .. }
        | Command::BuildMacosUtunW1Result { .. }
        | Command::BuildMacosUtunW2Result { .. }
        | Command::BuildUbuntuReleaseGateStatus { .. }
        | Command::BuildUbuntuOperatorReapplyCanary { .. }
        | Command::BuildUbuntuProductOperatorLoopSummary { .. }
        | Command::BuildUbuntuProductOperatorLoopCheckReport { .. }
        | Command::BuildUbuntuControlledPilotPlaybook { .. }
        | Command::BuildUbuntuMimicryNextContour { .. }
        | Command::BuildUbuntuReleaseWaveStatus { .. }
        | Command::BuildUbuntuReleaseReview { .. }
        | Command::BuildUbuntuReleaseWaveBundleManifest { .. }
        | Command::BuildUbuntuFieldPilotRemoteBundleManifest { .. }
        | Command::UbuntuPilotInputsReleaseSummary { .. }
        | Command::BuildUbuntuControlledPilotReviewBundleManifest { .. }
        | Command::UbuntuControlledPilotInputFields { .. }
        | Command::BuildUbuntuControlledPilotBundle { .. }
        | Command::AdversarialRunner { .. }
        | Command::AdversarialRunnerContractCheck { .. } => {
            unreachable!("tooling commands are delegated before generic dispatch")
        }
    }
}
