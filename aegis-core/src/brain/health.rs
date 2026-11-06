use crate::signals::classify::FailSignal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveStallProbeOutcomeClass {
    Success,
    SuccessDegraded,
    Timeout,
    ThroughputCollapse,
    SessionFreeze,
    OtherFailure,
}

impl ActiveStallProbeOutcomeClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::SuccessDegraded => "success_degraded",
            Self::Timeout => "timeout",
            Self::ThroughputCollapse => "throughput_collapse",
            Self::SessionFreeze => "session_freeze",
            Self::OtherFailure => "other_failure",
        }
    }

    pub const fn from_signal(signal: &FailSignal) -> Self {
        match signal {
            FailSignal::Success => Self::Success,
            FailSignal::SuccessDegraded => Self::SuccessDegraded,
            FailSignal::Timeout => Self::Timeout,
            FailSignal::ThroughputCollapse => Self::ThroughputCollapse,
            FailSignal::SessionFreeze { .. } => Self::SessionFreeze,
            _ => Self::OtherFailure,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectPathHealthTier {
    Healthy,
    Degraded,
    Unstable,
}

impl DirectPathHealthTier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unstable => "unstable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DirectPathHealthReasonCode {
    SuccessfulDirectPath,
    SuccessLatencyDegraded,
    ActiveProbeInFlight,
    ActiveProbeRecoveredPath,
    ActiveProbeRecoveredButLatencyDegraded,
    ActiveProbeSignalNotSuccessful,
    DirectRelayFailoverTriggered,
    ProbeRetryBudgetExhausted,
    ProbeRetrySuppressed,
}

impl DirectPathHealthReasonCode {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::SuccessfulDirectPath => "successful_direct_path",
            Self::SuccessLatencyDegraded => "success_latency_degraded",
            Self::ActiveProbeInFlight => "active_probe_in_flight",
            Self::ActiveProbeRecoveredPath => "active_probe_recovered_path",
            Self::ActiveProbeRecoveredButLatencyDegraded => {
                "active_probe_recovered_but_latency_degraded"
            }
            Self::ActiveProbeSignalNotSuccessful => "active_probe_signal_not_successful",
            Self::DirectRelayFailoverTriggered => "direct_relay_failover_triggered",
            Self::ProbeRetryBudgetExhausted => "probe_retry_budget_exhausted",
            Self::ProbeRetrySuppressed => "probe_retry_suppressed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DirectPathHealthDecision {
    pub(super) tier: DirectPathHealthTier,
    pub(super) reason_code: DirectPathHealthReasonCode,
}

impl DirectPathHealthDecision {
    const fn new(tier: DirectPathHealthTier, reason_code: DirectPathHealthReasonCode) -> Self {
        Self { tier, reason_code }
    }
}

pub(super) fn direct_session_health_decision(signal: &FailSignal) -> DirectPathHealthDecision {
    match signal {
        FailSignal::Success => DirectPathHealthDecision::new(
            DirectPathHealthTier::Healthy,
            DirectPathHealthReasonCode::SuccessfulDirectPath,
        ),
        FailSignal::SuccessDegraded => DirectPathHealthDecision::new(
            DirectPathHealthTier::Degraded,
            DirectPathHealthReasonCode::SuccessLatencyDegraded,
        ),
        _ => DirectPathHealthDecision::new(
            DirectPathHealthTier::Unstable,
            DirectPathHealthReasonCode::ActiveProbeSignalNotSuccessful,
        ),
    }
}

pub(super) fn active_probe_launch_health_decision() -> DirectPathHealthDecision {
    DirectPathHealthDecision::new(
        DirectPathHealthTier::Unstable,
        DirectPathHealthReasonCode::ActiveProbeInFlight,
    )
}

pub(super) fn active_probe_result_health_decision(signal: &FailSignal) -> DirectPathHealthDecision {
    match signal {
        FailSignal::Success => DirectPathHealthDecision::new(
            DirectPathHealthTier::Degraded,
            DirectPathHealthReasonCode::ActiveProbeRecoveredPath,
        ),
        FailSignal::SuccessDegraded => DirectPathHealthDecision::new(
            DirectPathHealthTier::Degraded,
            DirectPathHealthReasonCode::ActiveProbeRecoveredButLatencyDegraded,
        ),
        _ => DirectPathHealthDecision::new(
            DirectPathHealthTier::Unstable,
            DirectPathHealthReasonCode::ActiveProbeSignalNotSuccessful,
        ),
    }
}

pub(super) fn direct_failover_health_decision() -> DirectPathHealthDecision {
    DirectPathHealthDecision::new(
        DirectPathHealthTier::Unstable,
        DirectPathHealthReasonCode::DirectRelayFailoverTriggered,
    )
}

pub(super) fn retry_budget_exhausted_health_decision() -> DirectPathHealthDecision {
    DirectPathHealthDecision::new(
        DirectPathHealthTier::Unstable,
        DirectPathHealthReasonCode::ProbeRetryBudgetExhausted,
    )
}

pub(super) fn retry_skipped_health_decision() -> DirectPathHealthDecision {
    DirectPathHealthDecision::new(
        DirectPathHealthTier::Unstable,
        DirectPathHealthReasonCode::ProbeRetrySuppressed,
    )
}
