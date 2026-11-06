use super::RuntimeEventCode;
use super::RuntimeEventSurface;
use std::collections::BTreeSet;

#[test]
fn runtime_event_codes_are_stable_and_unique() {
    let codes = [
        RuntimeEventCode::IngressStartupPlanEvaluated,
        RuntimeEventCode::IngressPreflightHint,
        RuntimeEventCode::IngressStartupFallbackSelected,
        RuntimeEventCode::IngressStartupSelectionFailed,
        RuntimeEventCode::IngressWideBindFallback,
        RuntimeEventCode::IngressBackendStarted,
        RuntimeEventCode::IngressAcceptFailed,
        RuntimeEventCode::IngressTcpConnectRejectResponseFailed,
        RuntimeEventCode::IngressTcpConnectRejected,
        RuntimeEventCode::IngressUdpAssociateRejectResponseFailed,
        RuntimeEventCode::IngressUdpAssociateRejected,
        RuntimeEventCode::IngressUdpDatagramObserved,
        RuntimeEventCode::IngressUdpDatagramDropped,
        RuntimeEventCode::IngressUdpDatagramCompleted,
        RuntimeEventCode::IngressUdpDatagramResponseStage,
        RuntimeEventCode::IngressSessionFailed,
        RuntimeEventCode::IngressSessionBrokerFailed,
        RuntimeEventCode::RelaySessionStarted,
        RuntimeEventCode::RelayTransportSelected,
        RuntimeEventCode::RelaySessionSucceeded,
        RuntimeEventCode::RelaySessionCompleted,
        RuntimeEventCode::RelayUdpDatagramStage,
        RuntimeEventCode::DirectPlannerOrderSelected,
        RuntimeEventCode::DirectRelayPreferredFromProbeHistory,
        RuntimeEventCode::DirectActiveProbeBranchSelected,
        RuntimeEventCode::DirectSessionSucceeded,
        RuntimeEventCode::DirectRelayFailoverTriggered,
        RuntimeEventCode::DirectTerminalFailClosed,
        RuntimeEventCode::HybridRouteSelected,
        RuntimeEventCode::GenevaDirectAttemptStarted,
        RuntimeEventCode::GenevaDirectAttemptSucceeded,
        RuntimeEventCode::GenevaDirectAttemptFailed,
        RuntimeEventCode::DirectRelayHandoffStarted,
        RuntimeEventCode::DirectRelayHandoffSucceeded,
        RuntimeEventCode::HybridFlowBlockedFailClosed,
        RuntimeEventCode::DirectActiveStallProbeLaunched,
        RuntimeEventCode::DirectActiveStallProbeFinished,
        RuntimeEventCode::DirectActiveStallProbeRetrySelected,
        RuntimeEventCode::DirectActiveStallProbeRetryBudgetExhausted,
        RuntimeEventCode::DirectActiveStallProbeRetrySkipped,
        RuntimeEventCode::ExternalCalibrationApplied,
        RuntimeEventCode::KnowledgePriorApplied,
        RuntimeEventCode::BrainSelectOrderExplained,
        RuntimeEventCode::MacosUtunHelperStarted,
        RuntimeEventCode::MacosUtunFdReceived,
        RuntimeEventCode::MacosUtunPacketObserved,
        RuntimeEventCode::MacosUtunCleanupCompleted,
        RuntimeEventCode::RelayTransportFailed,
        RuntimeEventCode::StealthProfileRotated,
        RuntimeEventCode::SurfaceProfileIdPinnedWarning,
        RuntimeEventCode::MorphologyProfileSampled,
    ];
    let labels: BTreeSet<_> = codes.into_iter().map(RuntimeEventCode::as_str).collect();
    assert_eq!(labels.len(), 51);
    assert!(labels.contains("ingress_backend_started"));
    assert!(labels.contains("ingress_accept_failed"));
    assert!(labels.contains("ingress_tcp_connect_rejected"));
    assert!(labels.contains("ingress_udp_datagram_observed"));
    assert!(labels.contains("ingress_udp_datagram_dropped"));
    assert!(labels.contains("ingress_udp_datagram_completed"));
    assert!(labels.contains("ingress_udp_datagram_response_stage"));
    assert!(labels.contains("relay_session_started"));
    assert!(labels.contains("relay_transport_selected"));
    assert!(labels.contains("relay_session_succeeded"));
    assert!(labels.contains("relay_session_completed"));
    assert!(labels.contains("relay_udp_datagram_stage"));
    assert!(labels.contains("direct_planner_order_selected"));
    assert!(labels.contains("direct_active_probe_branch_selected"));
    assert!(labels.contains("direct_session_succeeded"));
    assert!(labels.contains("direct_relay_failover_triggered"));
    assert!(labels.contains("direct_terminal_fail_closed"));
    assert!(labels.contains("hybrid_route_selected"));
    assert!(labels.contains("geneva_direct_attempt_started"));
    assert!(labels.contains("geneva_direct_attempt_succeeded"));
    assert!(labels.contains("geneva_direct_attempt_failed"));
    assert!(labels.contains("direct_relay_handoff_started"));
    assert!(labels.contains("direct_relay_handoff_succeeded"));
    assert!(labels.contains("hybrid_flow_blocked_fail_closed"));
    assert!(labels.contains("direct_active_stall_probe_launched"));
    assert!(labels.contains("direct_active_stall_probe_retry_selected"));
    assert!(labels.contains("direct_active_stall_probe_retry_budget_exhausted"));
    assert!(labels.contains("direct_active_stall_probe_retry_skipped"));
    assert!(labels.contains("external_calibration_applied"));
    assert!(labels.contains("knowledge_prior_applied"));
    assert!(labels.contains("brain_select_order_explained"));
    assert!(labels.contains("macos_utun_helper_started"));
    assert!(labels.contains("macos_utun_fd_received"));
    assert!(labels.contains("macos_utun_packet_observed"));
    assert!(labels.contains("macos_utun_cleanup_completed"));
    assert!(labels.contains("relay_transport_failed"));
    assert!(labels.contains("stealth_profile_rotated"));
    assert!(labels.contains("surface_profile_id_pinned_warning"));
    assert!(labels.contains("morphology_profile_sampled"));
}

#[test]
fn morphology_profile_sampled_code_is_stable_and_stealth_surface() {
    assert_eq!(
        RuntimeEventCode::MorphologyProfileSampled.as_str(),
        "morphology_profile_sampled"
    );
    assert_eq!(
        RuntimeEventCode::MorphologyProfileSampled.surface(),
        RuntimeEventSurface::Stealth
    );
}

#[test]
fn surface_profile_id_pinned_warning_code_is_stable_and_stealth_surface() {
    assert_eq!(
        RuntimeEventCode::SurfaceProfileIdPinnedWarning.as_str(),
        "surface_profile_id_pinned_warning"
    );
    assert_eq!(
        RuntimeEventCode::SurfaceProfileIdPinnedWarning.surface(),
        RuntimeEventSurface::Stealth
    );
}

#[test]
fn runtime_event_codes_are_grouped_by_surface() {
    assert_eq!(
        RuntimeEventCode::RelaySessionCompleted.surface(),
        RuntimeEventSurface::Relay
    );
    assert_eq!(
        RuntimeEventCode::WideCaptureFlowCompleted.surface(),
        RuntimeEventSurface::Ingress
    );
    assert_eq!(
        RuntimeEventCode::WideCaptureFlowCompleted.as_str(),
        "wide_capture_flow_completed"
    );
    assert_eq!(
        RuntimeEventCode::ExternalCalibrationApplied.surface(),
        RuntimeEventSurface::BrainCalibration
    );
    assert_eq!(
        RuntimeEventCode::KnowledgePriorApplied.surface().as_str(),
        "brain_calibration"
    );
    assert_eq!(
        RuntimeEventCode::MacosUtunPacketObserved.surface(),
        RuntimeEventSurface::MacosUtun
    );
    assert_eq!(
        RuntimeEventCode::RelayTransportSelected.surface(),
        RuntimeEventSurface::Relay
    );
    assert_eq!(
        RuntimeEventCode::DirectPlannerOrderSelected.surface(),
        RuntimeEventSurface::Direct
    );
    assert_eq!(
        RuntimeEventCode::HybridFlowBlockedFailClosed.surface(),
        RuntimeEventSurface::Direct
    );
}

#[test]
fn proof_event_groups_remain_stable() {
    let brain: Vec<_> = RuntimeEventCode::BRAIN_CALIBRATION_EVENTS
        .iter()
        .map(|code| code.as_str())
        .collect();
    assert_eq!(
        brain,
        vec![
            "external_calibration_applied",
            "knowledge_prior_applied",
            "brain_select_order_explained",
            "brain_morphology_choice_explained"
        ]
    );

    let macos_utun: Vec<_> = RuntimeEventCode::MACOS_UTUN_EVENTS
        .iter()
        .map(|code| code.as_str())
        .collect();
    assert_eq!(
        macos_utun,
        vec![
            "macos_utun_helper_started",
            "macos_utun_fd_received",
            "macos_utun_packet_observed",
            "macos_utun_cleanup_completed"
        ]
    );

    let phase_b_relay: Vec<_> = RuntimeEventCode::PHASE_B_RELAY_CAMOUFLAGE_EVENTS
        .iter()
        .map(|code| code.as_str())
        .collect();
    assert_eq!(
        phase_b_relay,
        vec![
            "relay_session_started",
            "relay_transport_selected",
            "relay_transport_failed",
            "relay_session_succeeded"
        ]
    );
}
