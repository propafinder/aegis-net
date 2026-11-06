//! Actual shared mimicry runtime surface; binary direct and relay use one owner.
//! No transport, credential, clock or authenticated-readiness policy is supplied.
use aegis_core::mimicry::{
    negotiated_wire_options_preface, observed_wire_ipv4_header_shaping_preface,
    resolve_wire_mimicry_runtime, suggested_ttl_from_observed_ttl, tuning_for,
    wire_fragment_choreography_plan, wire_mimicry_plan, wire_options_preface_profile,
    StackProfileId,
};
use aegis_core::{
    KeyObservation, ObservationContract, ObservedWireChoreographyHint,
    ObservedWireIpv4HeaderShaping, ObservedWireNegotiatedOptions, WireMimicryMode,
};
use serde_json::Value;
use std::net::SocketAddr;

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimicryCapabilityPlan {
    pub stage: &'static str,
    pub readiness: &'static str,
    pub observation_capture_confidence: &'static str,
    pub wire_stage: &'static str,
    pub wire_scope: &'static str,
    pub wire_validation_strategy: &'static str,
    pub wire_linux_only: bool,
    pub wire_requires_raw_capabilities: bool,
    pub wire_window_preface_ready: bool,
    pub wire_window_preface: Option<u16>,
    pub wire_negotiated_options_ready: bool,
    pub wire_fragment_choreography_ready: bool,
    pub wire_ipv4_header_shaping_ready: bool,
    pub wire_observed_negotiated_options_ready: bool,
    pub wire_observed_fragment_choreography_ready: bool,
    pub wire_observed_ipv4_header_shaping_ready: bool,
    pub wire_observed_negotiated_options: Option<ObservedWireNegotiatedOptions>,
    pub wire_observed_fragment_choreography: Option<ObservedWireChoreographyHint>,
    pub wire_observed_ipv4_header_shaping: Option<ObservedWireIpv4HeaderShaping>,
    pub userspace_ttl_hint_ready: bool,
    pub userspace_ttl_hint: Option<u32>,
    pub server_hint_ready: bool,
    pub window_profile_ready: bool,
    pub reference_path_ready: bool,
    pub rst_path_ready: bool,
    pub server_hint: Option<&'static str>,
    pub window_profile: Option<&'static str>,
    pub reference_path_hops: Option<u8>,
    pub rst_path_hops: Option<u8>,
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn build_mimicry_capability_plan(
    observation: Option<&KeyObservation>,
) -> MimicryCapabilityPlan {
    let wire_plan = wire_mimicry_plan();
    let Some(observation) = observation else {
        return MimicryCapabilityPlan {
            stage: "pre_wire_input_surface",
            readiness: "runtime_only_baseline",
            observation_capture_confidence: "runtime_only",
            wire_stage: wire_plan.stage,
            wire_scope: wire_plan.scope,
            wire_validation_strategy: wire_plan.validation_strategy,
            wire_linux_only: wire_plan.linux_only,
            wire_requires_raw_capabilities: wire_plan.requires_raw_capabilities,
            wire_window_preface_ready: false,
            wire_window_preface: None,
            wire_negotiated_options_ready: false,
            wire_fragment_choreography_ready: false,
            wire_ipv4_header_shaping_ready: false,
            wire_observed_negotiated_options_ready: false,
            wire_observed_fragment_choreography_ready: false,
            wire_observed_ipv4_header_shaping_ready: false,
            wire_observed_negotiated_options: None,
            wire_observed_fragment_choreography: None,
            wire_observed_ipv4_header_shaping: None,
            userspace_ttl_hint_ready: false,
            userspace_ttl_hint: None,
            server_hint_ready: false,
            window_profile_ready: false,
            reference_path_ready: false,
            rst_path_ready: false,
            server_hint: None,
            window_profile: None,
            reference_path_hops: None,
            rst_path_hops: None,
        };
    };
    if matches!(
        observation.observation_contract(),
        ObservationContract::ExplicitAbsence
    ) {
        // Explicit absence must stay an honest "no capture-backed confidence"
        // surface even if legacy handshake TTL metadata is present nearby.
        return MimicryCapabilityPlan {
            stage: "early_pre_wire_capability_layer",
            readiness: "runtime_only_baseline",
            observation_capture_confidence: observation.observation_capture_confidence(),
            wire_stage: wire_plan.stage,
            wire_scope: wire_plan.scope,
            wire_validation_strategy: wire_plan.validation_strategy,
            wire_linux_only: wire_plan.linux_only,
            wire_requires_raw_capabilities: wire_plan.requires_raw_capabilities,
            wire_window_preface_ready: false,
            wire_window_preface: None,
            wire_negotiated_options_ready: false,
            wire_fragment_choreography_ready: false,
            wire_ipv4_header_shaping_ready: false,
            wire_observed_negotiated_options_ready: false,
            wire_observed_fragment_choreography_ready: false,
            wire_observed_ipv4_header_shaping_ready: false,
            wire_observed_negotiated_options: None,
            wire_observed_fragment_choreography: None,
            wire_observed_ipv4_header_shaping: None,
            userspace_ttl_hint_ready: false,
            userspace_ttl_hint: None,
            server_hint_ready: false,
            window_profile_ready: false,
            reference_path_ready: false,
            rst_path_ready: false,
            server_hint: None,
            window_profile: None,
            reference_path_hops: None,
            rst_path_hops: None,
        };
    }
    let server_hint = observation.runtime_server_hint().map(|hint| hint.as_str());
    let window_profile = observation
        .runtime_window_profile_hint()
        .map(|profile| profile.as_str());
    let reference_path_hops = observation.reference_path_hops();
    let rst_path_hops = observation.rst_path_hops();
    let wire_observed_negotiated_options = observation.observed_wire_negotiated_options_hint();
    let wire_observed_fragment_choreography = observation.observed_wire_choreography_hint();
    let wire_observed_ipv4_header_shaping = observation.observed_wire_ipv4_header_shaping_hint();
    let userspace_ttl_hint = if supports_adaptive_ttl_planning(observation) {
        suggested_ttl_from_observed_ttl(
            observation
                .first_data_ttl
                .or(observation.syn_ack_ttl)
                .or(observation.first_packet_ttl),
        )
    } else {
        None
    };
    let wire_window_preface = if supports_adaptive_ttl_planning(observation) {
        observation.runtime_window_hint()
    } else {
        None
    };
    let server_hint_ready = server_hint.is_some();
    let window_profile_ready = window_profile.is_some();
    let wire_window_preface_ready = wire_window_preface.is_some();
    let wire_observed_negotiated_options_ready = wire_observed_negotiated_options.is_some();
    let wire_observed_fragment_choreography_ready = wire_observed_fragment_choreography.is_some();
    let wire_observed_ipv4_header_shaping_ready = wire_observed_ipv4_header_shaping.is_some();
    let deep_observed = observation.observation_capture_confidence() == "deep_observed";
    let wire_negotiated_options_ready =
        deep_observed && (wire_observed_negotiated_options_ready || window_profile_ready);
    let wire_fragment_choreography_ready =
        deep_observed && (wire_observed_fragment_choreography_ready || window_profile_ready);
    let wire_ipv4_header_shaping_ready = wire_observed_ipv4_header_shaping_ready;
    let userspace_ttl_hint_ready = userspace_ttl_hint.is_some();
    let reference_path_ready = reference_path_hops.is_some();
    let rst_path_ready = rst_path_hops.is_some();
    let readiness = if (server_hint_ready || window_profile_ready)
        && (reference_path_ready || rst_path_ready)
    {
        "composite_signal_ready"
    } else if server_hint_ready || window_profile_ready {
        "fingerprint_signal_ready"
    } else if reference_path_ready || rst_path_ready {
        "path_signal_ready"
    } else {
        "runtime_only_baseline"
    };
    // This is intentionally just a planning surface for the next mimicry epic:
    // it names the stable inputs we can trust before any wire-level impersonation
    // and now also exposes the first explicit pre-wire capability-layer stage.
    MimicryCapabilityPlan {
        stage: "early_pre_wire_capability_layer",
        readiness,
        observation_capture_confidence: observation.observation_capture_confidence(),
        wire_stage: wire_plan.stage,
        wire_scope: wire_plan.scope,
        wire_validation_strategy: wire_plan.validation_strategy,
        wire_linux_only: wire_plan.linux_only,
        wire_requires_raw_capabilities: wire_plan.requires_raw_capabilities,
        wire_window_preface_ready,
        wire_window_preface,
        wire_negotiated_options_ready,
        wire_fragment_choreography_ready,
        wire_ipv4_header_shaping_ready,
        wire_observed_negotiated_options_ready,
        wire_observed_fragment_choreography_ready,
        wire_observed_ipv4_header_shaping_ready,
        wire_observed_negotiated_options,
        wire_observed_fragment_choreography,
        wire_observed_ipv4_header_shaping,
        userspace_ttl_hint_ready,
        userspace_ttl_hint,
        server_hint_ready,
        window_profile_ready,
        reference_path_ready,
        rst_path_ready,
        server_hint,
        window_profile,
        reference_path_hops,
        rst_path_hops,
    }
}

pub fn supports_adaptive_ttl_planning(observation: &KeyObservation) -> bool {
    matches!(
        observation.observation_contract(),
        ObservationContract::TrustedShallow | ObservationContract::DeepObserved
    )
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MimicryCapabilitySignalOrigin {
    AdvisoryLatestObservation,
    LiveRuntimeObservation,
    LiveActiveProbeObservation,
}

impl MimicryCapabilitySignalOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdvisoryLatestObservation => "advisory_latest_observation",
            Self::LiveRuntimeObservation => "live_runtime_observation",
            Self::LiveActiveProbeObservation => "live_active_probe_observation",
        }
    }
}

pub fn mimicry_userspace_wiring_mode(
    stack_profile: Option<StackProfileId>,
    capability: &MimicryCapabilityPlan,
) -> &'static str {
    match (stack_profile, capability.userspace_ttl_hint_ready) {
        (Some(_), true) => "profile_plus_capture_backed_ttl",
        (Some(_), false) => "profile_only",
        (None, true) => "capture_backed_ttl_only",
        (None, false) => "telemetry_only_no_stack_profile",
    }
}

pub fn mimicry_userspace_nodelay_hint(stack_profile: Option<StackProfileId>) -> Option<bool> {
    // Keep the next socket-level hint profile-derived only, so the userspace
    // contract stays separate from capture-backed TTL and raw ladder semantics.
    stack_profile.map(|profile| tuning_for(profile).nodelay)
}

pub fn mimicry_userspace_reuseaddr_hint(stack_profile: Option<StackProfileId>) -> Option<bool> {
    // `reuseaddr` stays in the same profile-derived/socket-only lane as
    // `nodelay`: no capture input, no packet-level mimicry claims.
    stack_profile.map(|profile| tuning_for(profile).reuseaddr)
}

pub fn mimicry_userspace_send_buffer_hint(stack_profile: Option<StackProfileId>) -> Option<usize> {
    // Buffer shaping is still profile-scoped userspace tuning, not packet-level
    // impersonation, so keep it tied strictly to explicit stack profiles.
    stack_profile.and_then(|profile| tuning_for(profile).send_buffer_size)
}

pub fn mimicry_userspace_recv_buffer_hint(stack_profile: Option<StackProfileId>) -> Option<usize> {
    stack_profile.and_then(|profile| tuning_for(profile).recv_buffer_size)
}

pub fn mimicry_wire_runtime_plan(
    wire_mode: WireMimicryMode,
    dst: SocketAddr,
    capability: &MimicryCapabilityPlan,
    stack_profile: Option<StackProfileId>,
) -> aegis_core::WireMimicryRuntimePlan {
    resolve_wire_mimicry_runtime(
        wire_mode,
        dst,
        aegis_core::default_raw_engine().capabilities(),
        capability.userspace_ttl_hint,
        capability.wire_window_preface,
        wire_options_preface_profile(stack_profile),
        observed_wire_ipv4_header_shaping_preface(capability.wire_observed_ipv4_header_shaping),
        negotiated_wire_options_preface(
            stack_profile,
            capability.observation_capture_confidence,
            capability.window_profile,
            capability.wire_observed_negotiated_options,
        ),
        wire_fragment_choreography_plan(
            capability.observation_capture_confidence,
            capability.window_profile,
            capability.wire_observed_fragment_choreography,
        ),
    )
}

pub fn add_runtime_baseline_mimicry_fields_compact(
    fields: &mut Value,
    stack_profile: Option<StackProfileId>,
    wire_mode: WireMimicryMode,
    dst: SocketAddr,
) {
    let capability = build_mimicry_capability_plan(None);
    let wire_runtime = mimicry_wire_runtime_plan(wire_mode, dst, &capability, stack_profile);
    let Some(map) = fields.as_object_mut() else {
        return;
    };
    map.insert(
        "mimicry_capability_signal_origin".into(),
        Value::String(
            MimicryCapabilitySignalOrigin::LiveRuntimeObservation
                .as_str()
                .to_string(),
        ),
    );
    map.insert(
        "mimicry_capability_stage".into(),
        Value::String(capability.stage.to_string()),
    );
    map.insert(
        "mimicry_capability_readiness".into(),
        Value::String(capability.readiness.to_string()),
    );
    map.insert(
        "mimicry_capability_observation_capture_confidence".into(),
        Value::String(capability.observation_capture_confidence.to_string()),
    );
    map.insert(
        "mimicry_capability_wire_config_mode".into(),
        Value::String(wire_mode.as_str().to_string()),
    );
    map.insert(
        "mimicry_capability_wire_requested".into(),
        Value::Bool(wire_runtime.requested),
    );
    map.insert(
        "mimicry_capability_wire_active".into(),
        Value::Bool(wire_runtime.active),
    );
    map.insert(
        "mimicry_capability_wire_activation_reason".into(),
        Value::String(wire_runtime.activation_reason.to_string()),
    );
    map.insert(
        "mimicry_capability_userspace_wiring_mode".into(),
        Value::String(mimicry_userspace_wiring_mode(stack_profile, &capability).to_string()),
    );
    map.insert(
        "mimicry_capability_userspace_stack_profile".into(),
        stack_profile
            .map(|value| Value::String(value.as_str().to_string()))
            .unwrap_or(Value::Null),
    );
}
