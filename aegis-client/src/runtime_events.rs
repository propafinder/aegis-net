#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RuntimeEventSurface {
    Ingress,
    Relay,
    Direct,
    BrainCalibration,
    MacosUtun,
    Stealth,
}

impl RuntimeEventSurface {
    #[allow(dead_code)]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Relay => "relay",
            Self::Direct => "direct",
            Self::BrainCalibration => "brain_calibration",
            Self::MacosUtun => "macos_utun",
            Self::Stealth => "stealth",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEventCode {
    IngressStartupPlanEvaluated,
    IngressPreflightHint,
    IngressStartupFallbackSelected,
    IngressStartupSelectionFailed,
    IngressWideBindFallback,
    IngressBackendStarted,
    IngressAcceptFailed,
    IngressTcpConnectRejectResponseFailed,
    IngressTcpConnectRejected,
    IngressUdpAssociateRejectResponseFailed,
    IngressUdpAssociateRejected,
    IngressUdpDatagramObserved,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    IngressUdpDatagramDropped,
    IngressUdpDatagramCompleted,
    IngressUdpDatagramResponseStage,
    IngressSessionFailed,
    IngressSessionBrokerFailed,
    RelaySessionStarted,
    RelayTransportSelected,
    RelaySoftWireApplied,
    RelayEndpointShortCircuitFastFail,
    RelayFailoverRecoveryObserved,
    RelayCarrierStateChanged,
    RelaySessionSucceeded,
    /// TCP returned normally without terminal response evidence. Neutral:
    /// neither an application-success receipt nor a transport failure.
    RelaySessionCompleted,
    RelayUdpDatagramStage,
    DirectPlannerOrderSelected,
    DirectRelayPreferredFromProbeHistory,
    DirectActiveProbeBranchSelected,
    DirectSessionSucceeded,
    DirectRelayFailoverTriggered,
    DirectTerminalFailClosed,
    HybridRouteSelected,
    GenevaDirectAttemptStarted,
    GenevaDirectAttemptSucceeded,
    GenevaDirectAttemptFailed,
    DirectRelayHandoffStarted,
    DirectRelayHandoffSucceeded,
    HybridFlowBlockedFailClosed,
    DirectActiveStallProbeLaunched,
    DirectActiveStallProbeFinished,
    DirectActiveStallProbeRetrySelected,
    DirectActiveStallProbeRetryBudgetExhausted,
    DirectActiveStallProbeRetrySkipped,
    #[allow(dead_code)]
    ExternalCalibrationApplied,
    #[allow(dead_code)]
    KnowledgePriorApplied,
    #[allow(dead_code)]
    BrainSelectOrderExplained,
    /// Phase 5 Phase 3: closed-loop morphology selection — emitted at
    /// session open when Brain inputs (probe history disposition,
    /// cross-session signal metrics, observation contract) produced a
    /// non-neutral `SurfaceBias`. The event carries every input signal
    /// plus the computed bias axes so reviewers can audit which signal
    /// drove which axis.
    #[allow(dead_code)]
    BrainMorphologyChoiceExplained,
    #[allow(dead_code)]
    MacosUtunHelperStarted,
    #[allow(dead_code)]
    MacosUtunFdReceived,
    #[allow(dead_code)]
    MacosUtunPacketObserved,
    #[allow(dead_code)]
    MacosUtunCleanupCompleted,
    RelayTransportFailed,
    /// C3 (Track C anti-anomaly): fired during a live session when the
    /// timer-driven intra-session drift check would pick a different
    /// catalog profile than the one the session opened with. Emits the
    /// old and new profile ids so downstream telemetry can measure drift
    /// frequency without needing to reconstruct catalog selection.
    StealthProfileRotated,
    /// Emitted once at startup when the operator has explicitly pinned
    /// `relay.policy.surface_profile_id` in config. A pinned surface
    /// profile removes the per-epoch morphology drift; if the same pin is
    /// also unique per user/install it can become a stable per-user
    /// wire-correlatable marker. Advisory only — does not change transport
    /// selection, Brain behavior, or fail startup.
    SurfaceProfileIdPinnedWarning,
    /// Emitted once per relay session open when the adaptive morphology
    /// profile is sampled — records the sampled family + instance dynamics
    /// (chunk/delay/jitter ranges, padding policy, direction summary) so
    /// per-session morphology sampling is a first-class observable event,
    /// not only relay_transport_selected surface fields.
    MorphologyProfileSampled,
    /// DNS-preview fake-IP listener lifecycle: started/stopped.
    /// Started side is emitted by `spawn_dns_preview` after a successful
    /// listener bind. The stopped side (`DnsPreviewDisabled`) is reserved
    /// for a future explicit teardown emission path — currently the
    /// listener is implicitly torn down by the process exit + restart that
    /// `aegis-wide-disable.sh` triggers via `systemctl restart`. The
    /// always-on allow keeps the workspace clippy gate green until that
    /// emission lands.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    DnsPreviewEnabled,
    #[allow(dead_code)]
    DnsPreviewDisabled,
    /// DNS-preview: a hostname was just assigned a fresh fake IP.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    DnsFakeIpAssigned,
    /// DNS-preview: a query hit an existing mapping (no allocation).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    DnsFakeIpMappingHit,
    /// Wide ingress: incoming TCP target IP fell in the fake-IP pool;
    /// hostname substituted for relay tunnel target.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    WideFakeIpHostnameRecovered,
    /// Wide ingress: incoming TCP to fake-IP pool had no mapping; rejected.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    WideFakeIpHostnameMissing,
    /// Wide ingress NFQUEUE observer: a diverted TCP flow (IPv4 or IPv6) was
    /// decoded from the netfilter queue, witnessed, and ACCEPTed back to the
    /// kernel. Observer-only — does not terminate the connection. Becomes live
    /// once the NFQUEUE backend is selected by ingress dispatch (next batch);
    /// allow dead_code until then.
    #[allow(dead_code)]
    WideNfqueueFlowObserved,
    /// NFQUEUE lifecycle: the operator opted into the (observer-only) NFQUEUE
    /// backend. Default Linux wide backend stays TPROXY; this is opt-in.
    #[allow(dead_code)]
    WideNfqueueBackendSelected,
    /// NFQUEUE lifecycle: preflight finished, reporting kernel/tooling/privilege
    /// capability and IPv4/IPv6 support classification.
    #[allow(dead_code)]
    WideNfqueuePreflightCompleted,
    /// NFQUEUE lifecycle: scoped divert rules (IPv4 and/or IPv6) were installed.
    #[allow(dead_code)]
    WideNfqueueRulesInstalled,
    /// NFQUEUE lifecycle: the observer socket loop started.
    #[allow(dead_code)]
    WideNfqueueObserverStarted,
    /// NFQUEUE backend (full-wide policy mode): the netfilter-queue runtime
    /// started, reporting the active per-class policy (udp/dns/ipv6).
    #[allow(dead_code)]
    WideNfqueueBackendStarted,
    /// NFQUEUE backend: a generic (non-DNS) UDP datagram was decoded from the
    /// queue. `verdict` records ACCEPT/DROP per the resolved UDP policy.
    #[allow(dead_code)]
    WideNfqueueUdpObserved,
    /// NFQUEUE backend: a DNS (UDP/53) datagram was decoded from the queue.
    #[allow(dead_code)]
    WideNfqueueDnsObserved,
    /// NFQUEUE backend: an IPv6 packet (TCP or UDP) was decoded from the queue.
    #[allow(dead_code)]
    WideNfqueueIpv6Observed,
    /// NFQUEUE backend: a per-packet verdict (ACCEPT/DROP) was emitted to the
    /// kernel, with the packet class and the policy reason.
    #[allow(dead_code)]
    WideNfqueueVerdictEmitted,
    /// NFQUEUE backend: a runtime error occurred (socket/parse). In a fail-closed
    /// full-wide mode the queue without a consumer drops, so an error never
    /// silently opens a leak.
    #[allow(dead_code)]
    WideNfqueueBackendError,
    /// wide-udp-direct: the MASQUE direct CONNECT-UDP health check succeeded
    /// (endpoint reachable + UDP associate + controlled target egress echoed).
    /// Generic UDP may be carried via MASQUE direct.
    #[allow(dead_code)]
    MasqueUdpHealthSucceeded,
    /// wide-udp-direct: the MASQUE direct CONNECT-UDP health check FAILED.
    /// Generic UDP stays blocked/fail-closed — never a native fallback.
    #[allow(dead_code)]
    MasqueUdpHealthFailed,
    /// full-wide-nfqueue (udp_policy=masque_direct): a generic UDP flow was
    /// observed at the NFQUEUE verdict layer and handed to the MASQUE direct
    /// send bridge. The original packet is still DROPped (no native leak).
    #[allow(dead_code)]
    WideUdpFlowObserved,
    /// masque_direct: a new MASQUE direct CONNECT-UDP send session was opened
    /// for a UDP flow tuple (first datagram for that tuple).
    #[allow(dead_code)]
    WideUdpMasqueSessionStarted,
    /// masque_direct: a datagram was sent over MASQUE direct CONNECT-UDP.
    #[allow(dead_code)]
    WideUdpMasqueDatagramSent,
    /// masque_direct: a response datagram was received at the relay over MASQUE
    /// direct (round-trip proven at the relay; NOT injected back to the local
    /// app — NFQUEUE is verdict-only, so the bridge is send-only by design).
    #[allow(dead_code)]
    WideUdpMasqueDatagramReceived,
    /// masque_direct: the MASQUE direct send leg for a UDP flow failed.
    /// The flow stays fail-closed (DROP) — never a native fallback.
    #[allow(dead_code)]
    WideUdpFlowFailed,
    /// masque_direct: a generic UDP flow was held fail-closed because the
    /// MASQUE direct send bridge was unavailable/saturated (no native leak).
    #[allow(dead_code)]
    WideUdpFailClosed,
    /// udp-redirect-proxy (bidirectional): a new captured generic-UDP flow
    /// (peer + original destination) was admitted by the REDIRECT transparent
    /// proxy and a carry session created.
    #[allow(dead_code)]
    WideUdpSessionCreated,
    /// udp-redirect-proxy (bidirectional): the MASQUE direct response datagram
    /// was delivered back to the local application from the original destination
    /// tuple (transparent reply). This is the bidirectional leg the send-only
    /// NFQUEUE bridge could not do.
    #[allow(dead_code)]
    WideUdpResponseDelivered,
    /// udp-redirect-proxy (bidirectional): a captured generic-UDP flow was
    /// closed (idle timeout / proxy shutdown). Sessions are reaped, no leak.
    #[allow(dead_code)]
    WideUdpFlowClosed,
    /// Wide capture: a captured (no-proxy) local TCP flow began its relay leg.
    #[allow(dead_code)]
    WideCaptureFlowStarted,
    /// Wide capture: a captured TCP flow returned normally and its terminal
    /// relay attempt observed application response bytes (not a delivery receipt).
    #[allow(dead_code)]
    WideCaptureFlowSucceeded,
    /// TCP flow returned normally without confirmed terminal response evidence.
    WideCaptureFlowCompleted,
    /// Wide capture: a captured TCP flow's relay leg failed (closed/fail-closed,
    /// not a native fallback).
    #[allow(dead_code)]
    WideCaptureFlowFailed,
    /// NFQUEUE lifecycle: the fail-safe watchdog was armed (guarantees rule
    /// teardown if the observer dies/hangs).
    #[allow(dead_code)]
    WideNfqueueWatchdogArmed,
    /// NFQUEUE lifecycle: normal cleanup completed (rules removed, baseline
    /// connectivity restored).
    #[allow(dead_code)]
    WideNfqueueCleanupCompleted,
    /// NFQUEUE lifecycle: the watchdog performed cleanup after an abnormal
    /// observer exit, restoring the network without a hung host.
    #[allow(dead_code)]
    WideNfqueueWatchdogCleanupCompleted,
    /// TUN+smoltcp IPv6 relay lab (controlled, opt-in; NOT a production default
    /// and NOT a default route). Operator selected the lab path.
    #[allow(dead_code)]
    WideTunSmoltcpBackendSelected,
    /// TUN+smoltcp lab: preflight (TUN device support, root/CAP, ip route tool).
    #[allow(dead_code)]
    WideTunSmoltcpPreflightCompleted,
    /// TUN+smoltcp lab: the AEGIS-owned TUN device was created.
    #[allow(dead_code)]
    WideTunSmoltcpDeviceCreated,
    /// TUN+smoltcp lab: a controlled IPv6 /128 route was installed (relay IP
    /// excluded; no default route touched).
    #[allow(dead_code)]
    WideTunSmoltcpRouteInstalled,
    /// TUN+smoltcp lab: a controlled IPv6 packet was read from the TUN device.
    #[allow(dead_code)]
    WideTunSmoltcpIpv6PacketObserved,
    /// TUN+smoltcp lab: smoltcp established the controlled TCP flow.
    #[allow(dead_code)]
    WideTunSmoltcpTcpFlowEstablished,
    /// TUN+smoltcp lab: the bridged relay session succeeded.
    #[allow(dead_code)]
    WideTunSmoltcpRelaySessionSucceeded,
    /// TUN+smoltcp lab: cleanup removed only AEGIS-owned route/interface state.
    #[allow(dead_code)]
    WideTunSmoltcpCleanupCompleted,
    /// TUN+smoltcp IPv6 UDP: a generic IPv6 UDP flow was observed at the smoltcp
    /// socket (src endpoint + payload captured from the TUN).
    #[allow(dead_code)]
    Ipv6UdpFlowObserved,
    /// TUN+smoltcp IPv6 UDP: a new IPv6 UDP carry session was created for a flow.
    #[allow(dead_code)]
    Ipv6UdpSessionCreated,
    /// TUN+smoltcp IPv6 UDP: a datagram was sent over the relay (MASQUE direct).
    #[allow(dead_code)]
    Ipv6UdpDatagramSent,
    /// TUN+smoltcp IPv6 UDP: a response datagram was received from the relay.
    #[allow(dead_code)]
    Ipv6UdpDatagramReceived,
    /// TUN+smoltcp IPv6 UDP: the response was injected back through the TUN and
    /// delivered to the originating app (bidirectional).
    #[allow(dead_code)]
    Ipv6UdpResponseDelivered,
    /// TUN+smoltcp IPv6 UDP: a carry session was closed (idle/shutdown).
    #[allow(dead_code)]
    Ipv6UdpFlowClosed,
    /// TUN+smoltcp IPv6 UDP: a flow was held fail-closed (relay unavailable /
    /// send error). No native IPv6 UDP fallback, ever.
    #[allow(dead_code)]
    Ipv6UdpFailClosed,
}

impl RuntimeEventCode {
    /// Closed registry for private diagnostics; unrecognized strings are not logged.
    pub const ALL: &'static [Self] = &[
        Self::IngressStartupPlanEvaluated,
        Self::IngressPreflightHint,
        Self::IngressStartupFallbackSelected,
        Self::IngressStartupSelectionFailed,
        Self::IngressWideBindFallback,
        Self::IngressBackendStarted,
        Self::IngressAcceptFailed,
        Self::IngressTcpConnectRejectResponseFailed,
        Self::IngressTcpConnectRejected,
        Self::IngressUdpAssociateRejectResponseFailed,
        Self::IngressUdpAssociateRejected,
        Self::IngressUdpDatagramObserved,
        Self::IngressUdpDatagramDropped,
        Self::IngressUdpDatagramCompleted,
        Self::IngressUdpDatagramResponseStage,
        Self::IngressSessionFailed,
        Self::IngressSessionBrokerFailed,
        Self::RelaySessionStarted,
        Self::RelayTransportSelected,
        Self::RelaySoftWireApplied,
        Self::RelayEndpointShortCircuitFastFail,
        Self::RelayFailoverRecoveryObserved,
        Self::RelayCarrierStateChanged,
        Self::RelaySessionSucceeded,
        Self::RelaySessionCompleted,
        Self::RelayUdpDatagramStage,
        Self::DirectPlannerOrderSelected,
        Self::DirectRelayPreferredFromProbeHistory,
        Self::DirectActiveProbeBranchSelected,
        Self::DirectSessionSucceeded,
        Self::DirectRelayFailoverTriggered,
        Self::DirectTerminalFailClosed,
        Self::HybridRouteSelected,
        Self::GenevaDirectAttemptStarted,
        Self::GenevaDirectAttemptSucceeded,
        Self::GenevaDirectAttemptFailed,
        Self::DirectRelayHandoffStarted,
        Self::DirectRelayHandoffSucceeded,
        Self::HybridFlowBlockedFailClosed,
        Self::DirectActiveStallProbeLaunched,
        Self::DirectActiveStallProbeFinished,
        Self::DirectActiveStallProbeRetrySelected,
        Self::DirectActiveStallProbeRetryBudgetExhausted,
        Self::DirectActiveStallProbeRetrySkipped,
        Self::ExternalCalibrationApplied,
        Self::KnowledgePriorApplied,
        Self::BrainSelectOrderExplained,
        Self::BrainMorphologyChoiceExplained,
        Self::MacosUtunHelperStarted,
        Self::MacosUtunFdReceived,
        Self::MacosUtunPacketObserved,
        Self::MacosUtunCleanupCompleted,
        Self::RelayTransportFailed,
        Self::StealthProfileRotated,
        Self::SurfaceProfileIdPinnedWarning,
        Self::MorphologyProfileSampled,
        Self::DnsPreviewEnabled,
        Self::DnsPreviewDisabled,
        Self::DnsFakeIpAssigned,
        Self::DnsFakeIpMappingHit,
        Self::WideFakeIpHostnameRecovered,
        Self::WideFakeIpHostnameMissing,
        Self::WideNfqueueFlowObserved,
        Self::WideNfqueueBackendSelected,
        Self::WideNfqueuePreflightCompleted,
        Self::WideNfqueueRulesInstalled,
        Self::WideNfqueueObserverStarted,
        Self::WideNfqueueBackendStarted,
        Self::WideNfqueueUdpObserved,
        Self::WideNfqueueDnsObserved,
        Self::WideNfqueueIpv6Observed,
        Self::WideNfqueueVerdictEmitted,
        Self::WideNfqueueBackendError,
        Self::MasqueUdpHealthSucceeded,
        Self::MasqueUdpHealthFailed,
        Self::WideUdpFlowObserved,
        Self::WideUdpMasqueSessionStarted,
        Self::WideUdpMasqueDatagramSent,
        Self::WideUdpMasqueDatagramReceived,
        Self::WideUdpFlowFailed,
        Self::WideUdpFailClosed,
        Self::WideUdpSessionCreated,
        Self::WideUdpResponseDelivered,
        Self::WideUdpFlowClosed,
        Self::WideCaptureFlowStarted,
        Self::WideCaptureFlowSucceeded,
        Self::WideCaptureFlowCompleted,
        Self::WideCaptureFlowFailed,
        Self::WideNfqueueWatchdogArmed,
        Self::WideNfqueueCleanupCompleted,
        Self::WideNfqueueWatchdogCleanupCompleted,
        Self::WideTunSmoltcpBackendSelected,
        Self::WideTunSmoltcpPreflightCompleted,
        Self::WideTunSmoltcpDeviceCreated,
        Self::WideTunSmoltcpRouteInstalled,
        Self::WideTunSmoltcpIpv6PacketObserved,
        Self::WideTunSmoltcpTcpFlowEstablished,
        Self::WideTunSmoltcpRelaySessionSucceeded,
        Self::WideTunSmoltcpCleanupCompleted,
        Self::Ipv6UdpFlowObserved,
        Self::Ipv6UdpSessionCreated,
        Self::Ipv6UdpDatagramSent,
        Self::Ipv6UdpDatagramReceived,
        Self::Ipv6UdpResponseDelivered,
        Self::Ipv6UdpFlowClosed,
        Self::Ipv6UdpFailClosed,
    ];

    #[allow(dead_code)]
    pub const BRAIN_CALIBRATION_EVENTS: &'static [RuntimeEventCode] = &[
        Self::ExternalCalibrationApplied,
        Self::KnowledgePriorApplied,
        Self::BrainSelectOrderExplained,
        Self::BrainMorphologyChoiceExplained,
    ];

    #[allow(dead_code)]
    pub const MACOS_UTUN_EVENTS: &'static [RuntimeEventCode] = &[
        Self::MacosUtunHelperStarted,
        Self::MacosUtunFdReceived,
        Self::MacosUtunPacketObserved,
        Self::MacosUtunCleanupCompleted,
    ];

    #[allow(dead_code)]
    pub const RELAY_SURFACE_EVENTS: &'static [RuntimeEventCode] = &[
        Self::RelaySessionStarted,
        Self::RelayTransportSelected,
        Self::RelaySoftWireApplied,
        Self::RelayEndpointShortCircuitFastFail,
        Self::RelayFailoverRecoveryObserved,
        Self::RelayCarrierStateChanged,
        Self::RelaySessionSucceeded,
        Self::RelaySessionCompleted,
        Self::RelayUdpDatagramStage,
        Self::RelayTransportFailed,
    ];

    #[allow(dead_code)]
    pub const PHASE_B_RELAY_CAMOUFLAGE_EVENTS: &'static [RuntimeEventCode] = &[
        Self::RelaySessionStarted,
        Self::RelayTransportSelected,
        Self::RelayTransportFailed,
        Self::RelaySessionSucceeded,
    ];

    #[allow(dead_code)]
    pub const fn surface(self) -> RuntimeEventSurface {
        match self {
            Self::IngressStartupPlanEvaluated
            | Self::IngressPreflightHint
            | Self::IngressStartupFallbackSelected
            | Self::IngressStartupSelectionFailed
            | Self::IngressWideBindFallback
            | Self::IngressBackendStarted
            | Self::IngressAcceptFailed
            | Self::IngressTcpConnectRejectResponseFailed
            | Self::IngressTcpConnectRejected
            | Self::IngressUdpAssociateRejectResponseFailed
            | Self::IngressUdpAssociateRejected
            | Self::IngressUdpDatagramObserved
            | Self::IngressUdpDatagramDropped
            | Self::IngressUdpDatagramCompleted
            | Self::IngressUdpDatagramResponseStage
            | Self::IngressSessionFailed
            | Self::IngressSessionBrokerFailed
            | Self::DnsPreviewEnabled
            | Self::DnsPreviewDisabled
            | Self::DnsFakeIpAssigned
            | Self::DnsFakeIpMappingHit
            | Self::WideFakeIpHostnameRecovered
            | Self::WideFakeIpHostnameMissing
            | Self::WideNfqueueFlowObserved
            | Self::WideNfqueueBackendSelected
            | Self::WideNfqueuePreflightCompleted
            | Self::WideNfqueueRulesInstalled
            | Self::WideNfqueueObserverStarted
            | Self::WideNfqueueBackendStarted
            | Self::WideNfqueueUdpObserved
            | Self::WideNfqueueDnsObserved
            | Self::WideNfqueueIpv6Observed
            | Self::WideNfqueueVerdictEmitted
            | Self::WideNfqueueBackendError
            | Self::MasqueUdpHealthSucceeded
            | Self::MasqueUdpHealthFailed
            | Self::WideUdpFlowObserved
            | Self::WideUdpMasqueSessionStarted
            | Self::WideUdpMasqueDatagramSent
            | Self::WideUdpMasqueDatagramReceived
            | Self::WideUdpFlowFailed
            | Self::WideUdpFailClosed
            | Self::WideUdpSessionCreated
            | Self::WideUdpResponseDelivered
            | Self::WideUdpFlowClosed
            | Self::WideCaptureFlowStarted
            | Self::WideCaptureFlowSucceeded
            | Self::WideCaptureFlowCompleted
            | Self::WideCaptureFlowFailed
            | Self::WideNfqueueWatchdogArmed
            | Self::WideNfqueueCleanupCompleted
            | Self::WideNfqueueWatchdogCleanupCompleted
            | Self::WideTunSmoltcpBackendSelected
            | Self::WideTunSmoltcpPreflightCompleted
            | Self::WideTunSmoltcpDeviceCreated
            | Self::WideTunSmoltcpRouteInstalled
            | Self::WideTunSmoltcpIpv6PacketObserved
            | Self::WideTunSmoltcpTcpFlowEstablished
            | Self::WideTunSmoltcpRelaySessionSucceeded
            | Self::WideTunSmoltcpCleanupCompleted
            | Self::Ipv6UdpFlowObserved
            | Self::Ipv6UdpSessionCreated
            | Self::Ipv6UdpDatagramSent
            | Self::Ipv6UdpDatagramReceived
            | Self::Ipv6UdpResponseDelivered
            | Self::Ipv6UdpFlowClosed
            | Self::Ipv6UdpFailClosed => RuntimeEventSurface::Ingress,
            Self::RelaySessionStarted
            | Self::RelayTransportSelected
            | Self::RelaySoftWireApplied
            | Self::RelayEndpointShortCircuitFastFail
            | Self::RelayFailoverRecoveryObserved
            | Self::RelayCarrierStateChanged
            | Self::RelaySessionSucceeded
            | Self::RelaySessionCompleted
            | Self::RelayUdpDatagramStage
            | Self::RelayTransportFailed => RuntimeEventSurface::Relay,
            Self::DirectPlannerOrderSelected
            | Self::DirectRelayPreferredFromProbeHistory
            | Self::DirectActiveProbeBranchSelected
            | Self::DirectSessionSucceeded
            | Self::DirectRelayFailoverTriggered
            | Self::DirectTerminalFailClosed
            | Self::HybridRouteSelected
            | Self::GenevaDirectAttemptStarted
            | Self::GenevaDirectAttemptSucceeded
            | Self::GenevaDirectAttemptFailed
            | Self::DirectRelayHandoffStarted
            | Self::DirectRelayHandoffSucceeded
            | Self::HybridFlowBlockedFailClosed
            | Self::DirectActiveStallProbeLaunched
            | Self::DirectActiveStallProbeFinished
            | Self::DirectActiveStallProbeRetrySelected
            | Self::DirectActiveStallProbeRetryBudgetExhausted
            | Self::DirectActiveStallProbeRetrySkipped => RuntimeEventSurface::Direct,
            Self::ExternalCalibrationApplied
            | Self::KnowledgePriorApplied
            | Self::BrainSelectOrderExplained
            | Self::BrainMorphologyChoiceExplained => RuntimeEventSurface::BrainCalibration,
            Self::MacosUtunHelperStarted
            | Self::MacosUtunFdReceived
            | Self::MacosUtunPacketObserved
            | Self::MacosUtunCleanupCompleted => RuntimeEventSurface::MacosUtun,
            Self::StealthProfileRotated => RuntimeEventSurface::Stealth,
            Self::SurfaceProfileIdPinnedWarning => RuntimeEventSurface::Stealth,
            Self::MorphologyProfileSampled => RuntimeEventSurface::Stealth,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IngressStartupPlanEvaluated => "ingress_startup_plan_evaluated",
            Self::IngressPreflightHint => "ingress_preflight_hint",
            Self::IngressStartupFallbackSelected => "ingress_startup_fallback_selected",
            Self::IngressStartupSelectionFailed => "ingress_startup_selection_failed",
            Self::IngressWideBindFallback => "ingress_wide_bind_fallback",
            Self::IngressBackendStarted => "ingress_backend_started",
            Self::IngressAcceptFailed => "ingress_accept_failed",
            Self::IngressTcpConnectRejectResponseFailed => {
                "ingress_tcp_connect_reject_response_failed"
            }
            Self::IngressTcpConnectRejected => "ingress_tcp_connect_rejected",
            Self::IngressUdpAssociateRejectResponseFailed => {
                "ingress_udp_associate_reject_response_failed"
            }
            Self::IngressUdpAssociateRejected => "ingress_udp_associate_rejected",
            Self::IngressUdpDatagramObserved => "ingress_udp_datagram_observed",
            Self::IngressUdpDatagramDropped => "ingress_udp_datagram_dropped",
            Self::IngressUdpDatagramCompleted => "ingress_udp_datagram_completed",
            Self::IngressUdpDatagramResponseStage => "ingress_udp_datagram_response_stage",
            Self::IngressSessionFailed => "ingress_session_failed",
            Self::IngressSessionBrokerFailed => "ingress_session_broker_failed",
            Self::RelaySessionStarted => "relay_session_started",
            Self::RelayTransportSelected => "relay_transport_selected",
            Self::RelaySoftWireApplied => "relay_soft_wire_applied",
            Self::RelayEndpointShortCircuitFastFail => "relay_endpoint_short_circuit_fast_fail",
            Self::RelayFailoverRecoveryObserved => "relay_failover_recovery_observed",
            Self::RelayCarrierStateChanged => "relay_carrier_state_changed",
            Self::RelaySessionSucceeded => "relay_session_succeeded",
            Self::RelaySessionCompleted => "relay_session_completed",
            Self::RelayUdpDatagramStage => "relay_udp_datagram_stage",
            Self::DirectPlannerOrderSelected => "direct_planner_order_selected",
            Self::DirectRelayPreferredFromProbeHistory => {
                "direct_relay_preferred_from_probe_history"
            }
            Self::DirectActiveProbeBranchSelected => "direct_active_probe_branch_selected",
            Self::DirectSessionSucceeded => "direct_session_succeeded",
            Self::DirectRelayFailoverTriggered => "direct_relay_failover_triggered",
            Self::DirectTerminalFailClosed => "direct_terminal_fail_closed",
            Self::HybridRouteSelected => "hybrid_route_selected",
            Self::GenevaDirectAttemptStarted => "geneva_direct_attempt_started",
            Self::GenevaDirectAttemptSucceeded => "geneva_direct_attempt_succeeded",
            Self::GenevaDirectAttemptFailed => "geneva_direct_attempt_failed",
            Self::DirectRelayHandoffStarted => "direct_relay_handoff_started",
            Self::DirectRelayHandoffSucceeded => "direct_relay_handoff_succeeded",
            Self::HybridFlowBlockedFailClosed => "hybrid_flow_blocked_fail_closed",
            Self::DirectActiveStallProbeLaunched => "direct_active_stall_probe_launched",
            Self::DirectActiveStallProbeFinished => "direct_active_stall_probe_finished",
            Self::DirectActiveStallProbeRetrySelected => "direct_active_stall_probe_retry_selected",
            Self::DirectActiveStallProbeRetryBudgetExhausted => {
                "direct_active_stall_probe_retry_budget_exhausted"
            }
            Self::DirectActiveStallProbeRetrySkipped => "direct_active_stall_probe_retry_skipped",
            Self::ExternalCalibrationApplied => "external_calibration_applied",
            Self::KnowledgePriorApplied => "knowledge_prior_applied",
            Self::BrainSelectOrderExplained => "brain_select_order_explained",
            Self::BrainMorphologyChoiceExplained => "brain_morphology_choice_explained",
            Self::MacosUtunHelperStarted => "macos_utun_helper_started",
            Self::MacosUtunFdReceived => "macos_utun_fd_received",
            Self::MacosUtunPacketObserved => "macos_utun_packet_observed",
            Self::MacosUtunCleanupCompleted => "macos_utun_cleanup_completed",
            Self::RelayTransportFailed => "relay_transport_failed",
            Self::StealthProfileRotated => "stealth_profile_rotated",
            Self::SurfaceProfileIdPinnedWarning => "surface_profile_id_pinned_warning",
            Self::MorphologyProfileSampled => "morphology_profile_sampled",
            Self::DnsPreviewEnabled => "dns_preview_enabled",
            Self::DnsPreviewDisabled => "dns_preview_disabled",
            Self::DnsFakeIpAssigned => "dns_fake_ip_assigned",
            Self::DnsFakeIpMappingHit => "dns_fake_ip_mapping_hit",
            Self::WideFakeIpHostnameRecovered => "wide_fake_ip_hostname_recovered",
            Self::WideFakeIpHostnameMissing => "wide_fake_ip_hostname_missing",
            Self::WideNfqueueFlowObserved => "wide_nfqueue_flow_observed",
            Self::WideNfqueueBackendSelected => "wide_nfqueue_backend_selected",
            Self::WideNfqueuePreflightCompleted => "wide_nfqueue_preflight_completed",
            Self::WideNfqueueRulesInstalled => "wide_nfqueue_rules_installed",
            Self::WideNfqueueObserverStarted => "wide_nfqueue_observer_started",
            Self::WideNfqueueBackendStarted => "wide_nfqueue_backend_started",
            Self::WideNfqueueUdpObserved => "wide_nfqueue_udp_observed",
            Self::WideNfqueueDnsObserved => "wide_nfqueue_dns_observed",
            Self::WideNfqueueIpv6Observed => "wide_nfqueue_ipv6_observed",
            Self::WideNfqueueVerdictEmitted => "wide_nfqueue_verdict_emitted",
            Self::WideNfqueueBackendError => "wide_nfqueue_backend_error",
            Self::MasqueUdpHealthSucceeded => "masque_udp_health_succeeded",
            Self::MasqueUdpHealthFailed => "masque_udp_health_failed",
            Self::WideUdpFlowObserved => "wide_udp_flow_observed",
            Self::WideUdpMasqueSessionStarted => "wide_udp_masque_session_started",
            Self::WideUdpMasqueDatagramSent => "wide_udp_masque_datagram_sent",
            Self::WideUdpMasqueDatagramReceived => "wide_udp_masque_datagram_received",
            Self::WideUdpFlowFailed => "wide_udp_flow_failed",
            Self::WideUdpFailClosed => "wide_udp_fail_closed",
            Self::WideUdpSessionCreated => "wide_udp_session_created",
            Self::WideUdpResponseDelivered => "wide_udp_response_delivered",
            Self::WideUdpFlowClosed => "wide_udp_flow_closed",
            Self::WideCaptureFlowStarted => "wide_capture_flow_started",
            Self::WideCaptureFlowSucceeded => "wide_capture_flow_succeeded",
            Self::WideCaptureFlowCompleted => "wide_capture_flow_completed",
            Self::WideCaptureFlowFailed => "wide_capture_flow_failed",
            Self::WideNfqueueWatchdogArmed => "wide_nfqueue_watchdog_armed",
            Self::WideNfqueueCleanupCompleted => "wide_nfqueue_cleanup_completed",
            Self::WideNfqueueWatchdogCleanupCompleted => "wide_nfqueue_watchdog_cleanup_completed",
            Self::WideTunSmoltcpBackendSelected => "wide_tun_smoltcp_backend_selected",
            Self::WideTunSmoltcpPreflightCompleted => "wide_tun_smoltcp_preflight_completed",
            Self::WideTunSmoltcpDeviceCreated => "wide_tun_smoltcp_device_created",
            Self::WideTunSmoltcpRouteInstalled => "wide_tun_smoltcp_route_installed",
            Self::WideTunSmoltcpIpv6PacketObserved => "wide_tun_smoltcp_ipv6_packet_observed",
            Self::WideTunSmoltcpTcpFlowEstablished => "wide_tun_smoltcp_tcp_flow_established",
            Self::WideTunSmoltcpRelaySessionSucceeded => "wide_tun_smoltcp_relay_session_succeeded",
            Self::WideTunSmoltcpCleanupCompleted => "wide_tun_smoltcp_cleanup_completed",
            Self::Ipv6UdpFlowObserved => "ipv6_udp_flow_observed",
            Self::Ipv6UdpSessionCreated => "ipv6_udp_session_created",
            Self::Ipv6UdpDatagramSent => "ipv6_udp_datagram_sent",
            Self::Ipv6UdpDatagramReceived => "ipv6_udp_datagram_received",
            Self::Ipv6UdpResponseDelivered => "ipv6_udp_response_delivered",
            Self::Ipv6UdpFlowClosed => "ipv6_udp_flow_closed",
            Self::Ipv6UdpFailClosed => "ipv6_udp_fail_closed",
        }
    }
}

#[cfg(test)]
mod tests;
