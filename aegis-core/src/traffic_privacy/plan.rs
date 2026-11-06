//! Pure installed-client admission. Diagnostic declarations do not execute a
//! measurement or alter traffic. A library primitive is not a runtime emitter.
use crate::{Mode, Settings};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Diagnostic {
    LeakageAnalysis,
    MeasuredFrontier,
    NetworkCalculus,
    BinaryScheduleAccountant,
    MinimumEntropyCoupling,
    NonstationaryBandit,
    FleetFailureDomains,
}

/// A requested installed packet schedule, never a feature activation switch.
/// Actual authenticated framing owns either constant cadence or bounded
/// exponential proposals. Separate one-shot schedule/MEC APIs are not full-flow owners.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketModifier {
    ConstantCadence,
    RandomizedSchedule,
    PoissonSchedule,
    MecControl,
    NetShaperEpoch,
    AdaptiveChannel,
    CoverStream,
    BitTrapsService,
    LiuChannel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedGuarantee {
    #[default]
    None,
    WholeFlowDifferentialPrivacy,
}

/// Upper bounds on the actual authenticated framing profile. These are local
/// framing bounds, excluding TLS/H2/network overhead; no Internet service bound.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FramingBudget {
    pub max_payload_bytes: usize,
    pub max_buffer_bytes: usize,
    pub max_wire_bytes_per_direction: u64,
    pub max_session_ms: u64,
    pub max_queue_delay_ms: u64,
}
impl FramingBudget {
    fn accepts(&self, s: &crate::carrier_runtime::PrivacySettings) -> bool {
        (1..=4096).contains(&self.max_payload_bytes)
            && (1..=1_048_576).contains(&self.max_buffer_bytes)
            && self.max_wire_bytes_per_direction > 0
            && (1..=3_600_000).contains(&self.max_session_ms)
            && self.max_queue_delay_ms > 0
            && s.payload_bytes <= self.max_payload_bytes
            && s.buffer_bytes <= self.max_buffer_bytes
            && s.max_wire_bytes <= self.max_wire_bytes_per_direction
            && s.session_timeout_ms <= self.max_session_ms
            && s.max_queue_delay_ms <= self.max_queue_delay_ms
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyPlan {
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
    #[serde(default)]
    pub packet_modifiers: Vec<PacketModifier>,
    #[serde(default)]
    pub requested_guarantee: RequestedGuarantee,
    #[serde(default)]
    pub framing_budget: Option<FramingBudget>,
}

/// Admission reports source-supported local behavior, never proof of deployment,
/// packet indistinguishability, complete-flow DP, or an independently run audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    pub authenticated_constant_cadence: bool,
    pub authenticated_exponential_proposals: bool,
    pub authenticated_netshaper_epoch: bool,
    pub authenticated_adaptive_channel: bool,
    pub authenticated_cover_stream: bool,
    pub authenticated_bittraps_service: bool,
    pub authenticated_liu_channel: bool,
    pub whole_flow_differential_privacy: bool,
}

pub fn admit(settings: &Settings) -> Result<Admission, String> {
    let shaping = settings.relay.authenticated_shaping.as_ref();
    // Infer from the actual paired runtime profile, never a declaration toggle.
    let owner = shaping.map(|s| {
        if s.liu_channel.is_some() {
            PacketModifier::LiuChannel
        } else if s.cover_stream.is_some() {
            PacketModifier::CoverStream
        } else if s.bit_traps.is_some() {
            PacketModifier::BitTrapsService
        } else if s.adaptive_channel.is_some() {
            PacketModifier::AdaptiveChannel
        } else if s.net_shaper.is_some() {
            PacketModifier::NetShaperEpoch
        } else if s.poisson_pacing.is_some() {
            PacketModifier::PoissonSchedule
        } else {
            PacketModifier::ConstantCadence
        }
    });
    if let Some(plan) = &settings.privacy_plan {
        if plan.requested_guarantee != RequestedGuarantee::None {
            return Err("privacy_plan: whole-flow differential privacy is unsupported".into());
        }
        if plan.diagnostics.len() > 7
            || plan
                .diagnostics
                .iter()
                .enumerate()
                .any(|(i, d)| plan.diagnostics[..i].contains(d))
        {
            return Err("privacy_plan: duplicate or oversized diagnostics".into());
        }
        // One schedule owner: neither nesting nor order-dependent precedence.
        if plan.packet_modifiers.len() > 1 {
            return Err("privacy_plan: incompatible packet schedule owners".into());
        }
        if plan.packet_modifiers.iter().any(|m| {
            matches!(
                m,
                PacketModifier::RandomizedSchedule | PacketModifier::MecControl
            )
        }) {
            return Err("privacy_plan: requested modifier has no installed runtime emitter".into());
        }
        if plan.packet_modifiers.first().copied() != owner {
            return Err("privacy_plan: declared schedule differs from actual relay framing".into());
        }
        match (shaping, &plan.framing_budget) {
            (Some(s), Some(b)) if b.accepts(s) => {}
            (None, None) => {}
            _ => return Err("privacy_plan: missing, unused or exceeded framing budget".into()),
        }
    }
    if shaping.is_some() {
        if !matches!(settings.mode, Mode::Relay) {
            return Err("privacy_plan: authenticated framing requires relay mode".into());
        }
        // Existing real runtime constraints (transport, device TLS, budgets),
        // with no credential reads or socket construction in this pure method.
        settings.relay.validate_inner_tls_transport().map_err(|_| {
            "privacy_plan: authenticated framing runtime profile rejected".to_owned()
        })?;
    }
    Ok(Admission {
        authenticated_constant_cadence: owner == Some(PacketModifier::ConstantCadence),
        authenticated_exponential_proposals: owner == Some(PacketModifier::PoissonSchedule),
        authenticated_netshaper_epoch: owner == Some(PacketModifier::NetShaperEpoch),
        authenticated_adaptive_channel: owner == Some(PacketModifier::AdaptiveChannel),
        authenticated_cover_stream: owner == Some(PacketModifier::CoverStream),
        authenticated_bittraps_service: owner == Some(PacketModifier::BitTrapsService),
        authenticated_liu_channel: owner == Some(PacketModifier::LiuChannel),
        whole_flow_differential_privacy: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn shaped() -> Settings {
        let mut s = Settings {
            mode: Mode::Relay,
            ..Default::default()
        };
        s.relay.authenticated_shaping = Some(crate::carrier_runtime::PrivacySettings {
            payload_bytes: 256,
            cadence_ms: 5,
            buffer_bytes: 1024,
            max_wire_bytes: 8192,
            io_timeout_ms: 100,
            session_timeout_ms: 1000,
            max_queue_delay_ms: 525,
            poisson_pacing: None,
            net_shaper: None,
            adaptive_channel: None,
            arrival_envelope: None,
            cover_stream: None,
            bit_traps: None,
            liu_channel: None,
        });
        s.relay.inner_tls = Some(crate::secure_channel::ClientSettings {
            cert: "absent.pem".into(),
            key: "absent.key".into(),
            server_ca: "absent.ca".into(),
            server_name: "relay.test".into(),
        });
        s.relay.tls_backend = crate::RelayTlsBackend::Rustls;
        s.relay.connect_timeout_ms = 1000;
        s.relay.ca_cert = Some("absent-outer.ca".into());
        s.relay.transport_priority = vec![crate::TunnelTransportFamily::GrpcStream];
        s.relay.udp_transport_priority = Some(vec![crate::TunnelTransportFamily::GrpcDatagram]);
        s
    }
    fn planned() -> Settings {
        let mut s = shaped();
        s.privacy_plan = Some(PrivacyPlan {
            diagnostics: vec![
                Diagnostic::LeakageAnalysis,
                Diagnostic::MeasuredFrontier,
                Diagnostic::NetworkCalculus,
                Diagnostic::BinaryScheduleAccountant,
                Diagnostic::MinimumEntropyCoupling,
                Diagnostic::NonstationaryBandit,
                Diagnostic::FleetFailureDomains,
            ],
            packet_modifiers: vec![PacketModifier::ConstantCadence],
            framing_budget: Some(FramingBudget {
                max_payload_bytes: 256,
                max_buffer_bytes: 1024,
                max_wire_bytes_per_direction: 8192,
                max_session_ms: 1000,
                max_queue_delay_ms: 525,
            }),
            ..Default::default()
        });
        s
    }
    fn planned_poisson() -> Settings {
        let mut s = planned();
        let shaping = s.relay.authenticated_shaping.as_mut().unwrap();
        shaping.cadence_ms = 1000;
        shaping.max_queue_delay_ms = 5500;
        shaping.session_timeout_ms = 10_000;
        shaping.poisson_pacing = Some(crate::traffic_privacy::poisson::PoissonPacing {
            mean_interval_us: 1000,
            max_gap_us: 1_000_000,
        });
        let plan = s.privacy_plan.as_mut().unwrap();
        plan.packet_modifiers = vec![PacketModifier::PoissonSchedule];
        let budget = plan.framing_budget.as_mut().unwrap();
        budget.max_queue_delay_ms = 5500;
        budget.max_session_ms = 10_000;
        s
    }
    #[test]
    fn actual_exponential_runtime_is_the_only_admitted_poisson_owner() {
        let mut s = planned_poisson();
        let a = admit(&s).unwrap();
        assert!(a.authenticated_exponential_proposals);
        assert!(!a.authenticated_constant_cadence);
        assert!(!a.whole_flow_differential_privacy);
        s.privacy_plan = None;
        assert_eq!(admit(&s).unwrap(), a);
        s.relay.authenticated_shaping = None;
        let a = admit(&s).unwrap();
        assert!(!a.authenticated_exponential_proposals && !a.authenticated_constant_cadence);
    }
    #[test]
    fn actual_and_declared_schedule_mismatches_or_stacks_refuse() {
        for (mut s, declaration) in [
            (planned(), PacketModifier::PoissonSchedule),
            (planned_poisson(), PacketModifier::ConstantCadence),
        ] {
            s.privacy_plan.as_mut().unwrap().packet_modifiers = vec![declaration];
            assert!(admit(&s).unwrap_err().contains("differs"));
        }
        let mut s = planned_poisson();
        s.privacy_plan
            .as_mut()
            .unwrap()
            .packet_modifiers
            .push(PacketModifier::ConstantCadence);
        assert!(admit(&s).unwrap_err().contains("incompatible"));
    }
    #[test]
    fn actual_exponential_gap_service_and_explicit_budgets_are_not_bypassed() {
        let mut s = planned_poisson();
        s.relay
            .authenticated_shaping
            .as_mut()
            .unwrap()
            .max_queue_delay_ms = 5499;
        assert!(admit(&s).unwrap_err().contains("runtime profile"));
        let mut s = planned_poisson();
        s.privacy_plan
            .as_mut()
            .unwrap()
            .framing_budget
            .as_mut()
            .unwrap()
            .max_queue_delay_ms = 5499;
        assert!(admit(&s).unwrap_err().contains("budget"));
        let mut s = planned_poisson();
        s.relay.authenticated_shaping.as_mut().unwrap().cadence_ms = 999;
        assert!(admit(&s).unwrap_err().contains("runtime profile"));
        let mut s = planned_poisson();
        s.relay
            .authenticated_shaping
            .as_mut()
            .unwrap()
            .poisson_pacing
            .as_mut()
            .unwrap()
            .max_gap_us = 1_000_001;
        assert!(admit(&s).unwrap_err().contains("runtime profile"));
    }
    #[test]
    fn compatible_diagnostics_and_existing_profiles_do_not_claim_dp() {
        for s in [Settings::default(), shaped(), planned()] {
            let a = admit(&s).unwrap();
            assert!(!a.whole_flow_differential_privacy);
            assert!(!a.authenticated_exponential_proposals);
            assert_eq!(
                a.authenticated_constant_cadence,
                s.relay.authenticated_shaping.is_some()
            );
        }
    }
    #[test]
    fn unimplemented_schedules_and_composition_fail_without_identity_reads() {
        for m in [
            PacketModifier::RandomizedSchedule,
            PacketModifier::MecControl,
        ] {
            let mut s = planned();
            s.privacy_plan.as_mut().unwrap().packet_modifiers = vec![m];
            assert!(admit(&s)
                .unwrap_err()
                .contains("no installed runtime emitter"));
            s.privacy_plan
                .as_mut()
                .unwrap()
                .packet_modifiers
                .push(PacketModifier::ConstantCadence);
            assert!(admit(&s).unwrap_err().contains("incompatible"));
        }
    }
    #[test]
    fn budget_and_service_limits_are_checked_before_admission() {
        for i in 0..5 {
            let mut s = planned();
            let b = s
                .privacy_plan
                .as_mut()
                .unwrap()
                .framing_budget
                .as_mut()
                .unwrap();
            match i {
                0 => b.max_payload_bytes -= 1,
                1 => b.max_buffer_bytes -= 1,
                2 => b.max_wire_bytes_per_direction -= 1,
                3 => b.max_session_ms -= 1,
                _ => b.max_queue_delay_ms -= 1,
            }
            assert!(admit(&s).unwrap_err().contains("budget"));
        }
        let mut s = shaped();
        s.relay
            .authenticated_shaping
            .as_mut()
            .unwrap()
            .max_queue_delay_ms = 524;
        assert!(admit(&s).unwrap_err().contains("runtime profile"));
    }
    #[test]
    fn missing_owner_unused_budget_duplicate_diagnostic_and_dp_are_rejected() {
        let mut s = planned();
        s.privacy_plan.as_mut().unwrap().packet_modifiers.clear();
        assert!(admit(&s).unwrap_err().contains("differs"));
        let mut s = planned();
        s.privacy_plan
            .as_mut()
            .unwrap()
            .diagnostics
            .push(Diagnostic::NetworkCalculus);
        assert!(admit(&s).unwrap_err().contains("diagnostics"));
        let mut s = planned();
        s.privacy_plan.as_mut().unwrap().requested_guarantee =
            RequestedGuarantee::WholeFlowDifferentialPrivacy;
        assert!(admit(&s).unwrap_err().contains("whole-flow"));
        let mut s = planned();
        s.relay.authenticated_shaping = None;
        s.privacy_plan.as_mut().unwrap().packet_modifiers.clear();
        assert!(admit(&s).unwrap_err().contains("unused"));
    }
}
