#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeHistoryDisposition {
    None,
    BiasProbeBranch,
    PreferRelay,
}

impl ProbeHistoryDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BiasProbeBranch => "bias_probe_branch",
            Self::PreferRelay => "prefer_relay",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeHistoryReasonCode {
    NoRecentProbeHistory,
    ProbeSignalNotStallLike,
    ProbeObservationMissing,
    ProbeObservationNotProbeCapable,
    SingleStallBiasProbeBranch,
    RepeatedStallPreferRelay,
}

impl ProbeHistoryReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoRecentProbeHistory => "no_recent_probe_history",
            Self::ProbeSignalNotStallLike => "probe_signal_not_stall_like",
            Self::ProbeObservationMissing => "probe_observation_missing",
            Self::ProbeObservationNotProbeCapable => "probe_observation_not_probe_capable",
            Self::SingleStallBiasProbeBranch => "single_stall_bias_probe_branch",
            Self::RepeatedStallPreferRelay => "repeated_stall_prefer_relay",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveStallProbeRetrySuppressedReasonCode {
    AdvisoryPreferRelay,
    ProbeSignalNotSuccessful,
    ProbeObservationNotCaptureBacked,
}

impl ActiveStallProbeRetrySuppressedReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdvisoryPreferRelay => "advisory_prefer_relay",
            Self::ProbeSignalNotSuccessful => "probe_signal_not_successful",
            Self::ProbeObservationNotCaptureBacked => "probe_observation_not_capture_backed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectRelayFailoverReasonCode {
    NoExecutableStrategy,
    UnsupportedAddressFamily,
    MissingRawCapability,
    StrategiesExhausted,
    NoInlineProbeAttempt,
    ProbeRetryBudgetExhausted,
    AdvisoryPreferRelayAfterProbe,
    ProbeSignalNotSuccessfulAfterProbe,
    ProbeObservationNotCaptureBackedAfterProbe,
}

impl DirectRelayFailoverReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoExecutableStrategy => "no_executable_strategy",
            Self::UnsupportedAddressFamily => "unsupported_address_family",
            Self::MissingRawCapability => "missing_raw_capability",
            Self::StrategiesExhausted => "strategies_exhausted",
            Self::NoInlineProbeAttempt => "no_inline_probe_attempt",
            Self::ProbeRetryBudgetExhausted => "probe_retry_budget_exhausted",
            Self::AdvisoryPreferRelayAfterProbe => "advisory_prefer_relay_after_probe",
            Self::ProbeSignalNotSuccessfulAfterProbe => "probe_signal_not_successful_after_probe",
            Self::ProbeObservationNotCaptureBackedAfterProbe => {
                "probe_observation_not_capture_backed_after_probe"
            }
        }
    }

    pub const fn from_retry_suppressed_reason(
        reason_code: ActiveStallProbeRetrySuppressedReasonCode,
    ) -> Self {
        match reason_code {
            ActiveStallProbeRetrySuppressedReasonCode::AdvisoryPreferRelay => {
                Self::AdvisoryPreferRelayAfterProbe
            }
            ActiveStallProbeRetrySuppressedReasonCode::ProbeSignalNotSuccessful => {
                Self::ProbeSignalNotSuccessfulAfterProbe
            }
            ActiveStallProbeRetrySuppressedReasonCode::ProbeObservationNotCaptureBacked => {
                Self::ProbeObservationNotCaptureBackedAfterProbe
            }
        }
    }
}
