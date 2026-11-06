//! Test-only bounded, content-free projection of already parsed failure JSON.
//! Does not execute an operator or alter admission/success.
use serde_json::{json, Value};

const PHASES: &[&str] = &[
    "windows_highres_timer_create",
    "windows_highres_timer_arm",
    "windows_highres_timer_timeout",
    "windows_highres_timer_wait",
    "application_ready_callback_late",
    "application_resource_profile",
    "application_write_partial",
    "arrival_before_phase_origin",
    "arrival_clock",
    "arrival_decode_ambiguous",
    "arrival_decode_impossible",
    "arrival_order",
    "block_range",
    "buffering_clock",
    "buffering_reference",
    "checkpoint_capacity",
    "checkpoint_count",
    "clock_before_origin",
    "clock_overflow",
    "clock_sync_late",
    "clock_sync_order",
    "clock_sync_overflow",
    "clock_sync_uncertainty",
    "codeword_capacity",
    "codeword_clock",
    "collector_already_joined",
    "collector_extra_or_failed",
    "collector_lock",
    "collector_terminal",
    "darwin_absolute_wait_interrupted",
    "darwin_anchor_order",
    "darwin_critical_timer_count",
    "darwin_critical_timer_event",
    "darwin_critical_timer_registration",
    "darwin_critical_timer_request",
    "darwin_critical_timer_wait",
    "darwin_kevent64_critical_absolute",
    "darwin_timebase",
    "darwin_timebase_overflow",
    "darwin_timer_create",
    "darwin_wait_clock",
    "declared_service_reference_capacity",
    "decoded_record_authentication",
    "decoded_record_length",
    "decoded_word_range",
    "diagnostic_publish_signal",
    "draw_capacity",
    "duplicate_or_reordered_owned_event",
    "exclusive_owner_or_clock",
    "exporter",
    "external_io",
    "final_public_slot_late",
    "input_capacity",
    "material",
    "metadata_capacity",
    "metadata_count",
    "metadata_digest",
    "metadata_entropy",
    "metadata_frame",
    "metadata_public_slot_late",
    "metadata_total",
    "missed_original_public_window",
    "original_clock_runway",
    "original_packet_identity",
    "original_point_outside_public_window",
    "owned_checkpoint_slot",
    "owned_drain_original_clock",
    "owned_preparation_budget",
    "owned_qos_class",
    "owned_qos_prior_invalid",
    "owned_qos_query",
    "owned_qos_readback_mismatch",
    "owned_qos_set",
    "owned_ready_abandoned",
    "owned_ready_clock",
    "owned_ready_consumed",
    "owned_ready_terminal",
    "owned_release_cancelled",
    "owned_release_capacity",
    "owned_release_original_clock",
    "owned_release_panicked",
    "owned_result_clock",
    "owned_result_consumed",
    "owned_schedule_clock",
    "owned_schedule_runway",
    "owned_schedule_size",
    "owned_service_fifo_sequence",
    "owned_service_missing",
    "owned_thread_missing",
    "owned_windows_priority_base",
    "owned_windows_priority_class",
    "owned_windows_priority_class_changed",
    "owned_windows_priority_query_class",
    "owned_windows_priority_query_relative",
    "owned_windows_priority_readback",
    "owned_windows_priority_relative",
    "owned_windows_priority_set",
    "owned_word_range",
    "owned_work_budget",
    "packet_write_delivery_cutoff",
    "packet_write_partial",
    "paired_admission",
    "paired_codebook",
    "peer_decoded_record",
    "precision_work_budget",
    "preparation_work_budget",
    "profile_serialize",
    "public_point_clock",
    "public_point_delivery_cutoff",
    "public_point_prior_write_overlap",
    "public_profile",
    "public_schedule_capacity_or_order",
    "receiver_not_armed",
    "receiver_packet_capacity",
    "record_encrypt",
    "record_material_already_used",
    "release_late",
    "service_arrival_original_cutoff",
    "service_completed_after_original_cutoff",
    "service_original_delivery_cutoff",
    "service_queue_capacity",
    "source_clock",
    "source_fifo_capacity",
    "source_origin_missing",
    "source_origin_order",
    "source_packet_capacity",
    "source_starvation",
    "source_unavailable_at_original_point",
    "source_unavailable_at_public_point",
    "strict_command_checkpoint_missing",
    "strict_command_panicked",
    "strict_command_result_clock",
    "strict_command_terminal",
    "strict_command_thread_missing",
    "strict_command_worker_missing",
    "strict_packet_write",
    "strict_sender_consumed",
    "tls_version",
    "unexpected_peer_during_owned_release",
    "windows_timer_clock_overflow",
    "windows_timer_due_overflow",
    "windows_timer_original_cutoff",
    "windows_timer_initial_cutoff",
    "windows_timer_before_arm_cutoff",
    "windows_timer_after_arm_cutoff",
    "windows_timer_before_wait_cutoff",
    "windows_timer_diagnostic_entry_cutoff",
    "windows_timer_after_wait_cutoff",
    "windows_timer_wait_overflow",
];
fn label(value: &Value, allowed: &'static [&'static str]) -> &'static str {
    // Return static storage, not even a matching slice owned by the child.
    allowed
        .iter()
        .copied()
        .find(|&s| value.as_str() == Some(s))
        .unwrap_or("unknown_or_unreported")
}

// Closed numeric tuple only; unknown/absent input remains omitted.
fn service_cutoff(value: &Value) -> Option<Value> {
    if value["phase"].as_str() != Some("service_completed_after_original_cutoff") {
        return None;
    }
    let input = &value["confirmed_prefix"]["service_cutoff"];
    let event_ordinal = input["event_ordinal"].as_u64()?;
    let admission_lateness_ns = input["admission_lateness_ns"].as_u64()?;
    let pending_wait_ns = input["pending_wait_ns"].as_u64()?;
    let write_observation_bracket_ns = input["write_observation_bracket_ns"].as_u64()?;
    let completion_lateness_ns = input["completion_lateness_ns"].as_u64()?;
    let original_allowance_ns = input["original_allowance_ns"].as_u64()?;
    let sum = admission_lateness_ns
        .checked_add(pending_wait_ns)?
        .checked_add(write_observation_bracket_ns)?;
    // Existing operator caps only; these do not change core admission.
    if event_ordinal >= 8192
        || completion_lateness_ns > 60_000_000_000
        || !(1..=20_000_000).contains(&original_allowance_ns)
        || completion_lateness_ns <= original_allowance_ns
        || sum != completion_lateness_ns
    {
        return None;
    }
    Some(json!({
        "event_ordinal": event_ordinal,
        "admission_lateness_ns": admission_lateness_ns,
        "pending_wait_ns": pending_wait_ns,
        "write_observation_bracket_ns": write_observation_bracket_ns,
        "completion_lateness_ns": completion_lateness_ns,
        "original_allowance_ns": original_allowance_ns
    }))
}

// A real macOS CLI failure receipt carries one typed first miss. Project
// only bounded scalars, never arbitrary child strings or absolute clock data.
fn darwin_admission_miss(value: &Value) -> Option<Value> {
    if !matches!(
        value["phase"].as_str(),
        Some("service_arrival_original_cutoff" | "missed_original_public_window")
    ) {
        return None;
    }
    let input = &value["confirmed_prefix"]["darwin_admission_miss"];
    let bounded = |field: &str| input[field].as_u64().filter(|&n| n <= 60_000_000_000);
    let optional = |field: &str| -> Option<Option<u64>> {
        let field_value = input.get(field)?;
        if field_value.is_null() {
            Some(None)
        } else {
            field_value
                .as_u64()
                .filter(|&n| n <= 60_000_000_000)
                .map(Some)
        }
    };
    let event = bounded("event_ordinal")?;
    let block = bounded("block_ordinal")?;
    let allowance = bounded("original_allowance_ns")?;
    let late = bounded("observed_lateness_ns")?;
    let excess = bounded("cutoff_excess_ns")?;
    if event >= 8192
        || block > u64::from(u16::MAX)
        || !(1..=20_000_000).contains(&allowance)
        || late <= allowance
        || late.checked_sub(allowance)? != excess
    {
        return None;
    }
    let qos_class = optional("qos_requested_class")?;
    if qos_class.is_some_and(|class| !matches!(class, 0x19 | 0x21)) {
        return None;
    }
    let qos_readback = input["qos_readback_matched"].as_bool()?;
    let mach_readback = input["mach_policy_readback_matched"].as_bool()?;
    let wait_present = input["last_wait_present"].as_bool()?;
    let point_matches = input["last_wait_point_matches_admission"].as_bool()?;
    let same_io = input["no_intervening_io_attempt"].as_bool()?;
    let gather_matches = input["gather_point_matches_admission"].as_bool()?;
    let coarse_value = input.get("last_wait_coarse")?;
    let coarse = if coarse_value.is_null() {
        None
    } else {
        Some(coarse_value.as_bool()?)
    };
    let call = optional("last_wait_call_interval_ns")?;
    let overshoot = optional("last_wait_wake_overshoot_ns")?;
    let wait_to_gather = optional("last_wait_return_to_gather_ns")?;
    let gather_to_admit = optional("gather_to_admission_ns")?;
    let wait_to_admit = optional("last_wait_return_to_admission_ns")?;
    if !wait_present
        && (point_matches
            || coarse.is_some()
            || call.is_some()
            || overshoot.is_some()
            || wait_to_gather.is_some()
            || wait_to_admit.is_some())
    {
        return None;
    }
    if point_matches
        && same_io
        && gather_matches
        && matches!(
            (wait_to_gather, gather_to_admit, wait_to_admit),
            (Some(a), Some(b), Some(total)) if a.checked_add(b) != Some(total)
        )
    {
        return None;
    }
    Some(json!({
        "event_ordinal": event,
        "block_ordinal": block,
        "original_allowance_ns": allowance,
        "observed_lateness_ns": late,
        "cutoff_excess_ns": excess,
        "qos_requested_class": qos_class,
        "qos_readback_matched": qos_readback,
        "mach_policy_readback_matched": mach_readback,
        "last_wait_present": wait_present,
        "last_wait_point_matches_admission": point_matches,
        "no_intervening_io_attempt": same_io,
        "gather_point_matches_admission": gather_matches,
        "last_wait_coarse": coarse,
        "last_wait_call_interval_ns": call,
        "last_wait_wake_overshoot_ns": overshoot,
        "last_wait_return_to_gather_ns": wait_to_gather,
        "gather_to_admission_ns": gather_to_admit,
        "last_wait_return_to_admission_ns": wait_to_admit,
    }))
}

pub fn content_free_refusal(value: &Value) -> Value {
    let prefix = &value["confirmed_prefix"];
    let mut counts = serde_json::Map::new();
    for field in [
        "accepted_packets",
        "sent_packets",
        "received_packets",
        "delivered_packets",
        "retained_packets",
        "native_work_steps",
        "preparation_work_steps",
        "pending_service_packets",
    ] {
        counts.insert(field.into(), json!(prefix[field].as_u64()));
    }
    let mut custody = serde_json::Map::new();
    for field in [
        "release_thread_started",
        "release_thread_terminal",
        "release_thread_joined",
        "release_cancel_requested",
        "collector_started",
        "collector_joined",
        "collector_abort_requested",
    ] {
        custody.insert(field.into(), json!(prefix[field].as_bool()));
    }
    let mut output = json!({
        "phase": label(&value["phase"], PHASES),
        "error_kind": label(&value["error_kind"], &["NotFound", "PermissionDenied", "ConnectionRefused", "ConnectionReset", "HostUnreachable", "NetworkUnreachable", "ConnectionAborted", "NotConnected", "AddrInUse", "AddrNotAvailable", "NetworkDown", "BrokenPipe", "AlreadyExists", "WouldBlock", "InvalidInput", "InvalidData", "TimedOut", "WriteZero", "Interrupted", "UnexpectedEof", "OutOfMemory", "Unsupported", "Other"]),
        "accepted_delivery_complete": value["accepted_delivery_complete"].as_bool(),
        "packet_io_outcome_may_be_unknown": value["packet_io_outcome_may_be_unknown"].as_bool(),
        "owned_pending_disposition": label(&value["owned_pending_disposition"], &["cancellation_requested_terminal_unobserved", "collector_abort_requested_terminal_unobserved", "owned_terminal_drop_zeroizes_pending_bytes"]),
        "counts": counts, "custody": custody
    });
    if let Some(witness) = service_cutoff(value) {
        output
            .as_object_mut()
            .unwrap()
            .insert("service_cutoff".into(), witness);
    }
    if let Some(witness) = darwin_admission_miss(value) {
        output
            .as_object_mut()
            .unwrap()
            .insert("darwin_admission_miss".into(), witness);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn darwin_first_miss_projects_only_bounded_arithmetic_and_no_child_text() {
        let tuple = json!({
            "event_ordinal": 502,
            "block_ordinal": 4,
            "original_allowance_ns": 10_000_000,
            "observed_lateness_ns": 25_940_083,
            "cutoff_excess_ns": 15_940_083,
            "qos_requested_class": 0x19,
            "qos_readback_matched": true,
            "mach_policy_readback_matched": true,
            "last_wait_present": true,
            "last_wait_point_matches_admission": true,
            "no_intervening_io_attempt": true,
            "gather_point_matches_admission": true,
            "last_wait_coarse": true,
            "last_wait_call_interval_ns": 23_000_000,
            "last_wait_wake_overshoot_ns": 22_000_000,
            "last_wait_return_to_gather_ns": 1_000_000,
            "gather_to_admission_ns": 940_083,
            "last_wait_return_to_admission_ns": 1_940_083
        });
        let mut input = json!({"phase":"service_arrival_original_cutoff", "confirmed_prefix":{"darwin_admission_miss":tuple.clone()}});
        assert_eq!(content_free_refusal(&input)["darwin_admission_miss"], tuple);
        let mut window_miss = input.clone();
        window_miss["phase"] = json!("missed_original_public_window");
        assert_eq!(
            content_free_refusal(&window_miss)["darwin_admission_miss"],
            tuple
        );
        let secret = "SYNTHETIC_PRIVATE_CLOCK_OR_ADDRESS_CANARY";
        input["confirmed_prefix"]["darwin_admission_miss"]["raw_point"] = json!(secret);
        assert_eq!(content_free_refusal(&input)["darwin_admission_miss"], tuple);
        assert!(!content_free_refusal(&input).to_string().contains(secret));
        for field in [
            "observed_lateness_ns",
            "cutoff_excess_ns",
            "last_wait_return_to_admission_ns",
        ] {
            let mut bad = input.clone();
            bad["confirmed_prefix"]["darwin_admission_miss"][field] = json!(u64::MAX);
            assert!(content_free_refusal(&bad)
                .get("darwin_admission_miss")
                .is_none());
        }
        let mut bad = input.clone();
        bad["confirmed_prefix"]["darwin_admission_miss"]["cutoff_excess_ns"] = json!(15_940_084);
        assert!(content_free_refusal(&bad)
            .get("darwin_admission_miss")
            .is_none());
        let mut bad = input.clone();
        bad["confirmed_prefix"]["darwin_admission_miss"]["last_wait_return_to_admission_ns"] =
            json!(1_940_084);
        assert!(content_free_refusal(&bad)
            .get("darwin_admission_miss")
            .is_none());
        let mut bad = input;
        bad["phase"] = json!("external_io");
        assert!(content_free_refusal(&bad)
            .get("darwin_admission_miss")
            .is_none());
    }
    #[test]
    fn one_service_numeric_tuple_is_exact_and_malformed_input_never_escapes() {
        let tuple = json!({
            "event_ordinal": 7,
            "admission_lateness_ns": 1_000_000,
            "pending_wait_ns": 2_000_000,
            "write_observation_bracket_ns": 12_000_000,
            "completion_lateness_ns": 15_000_000,
            "original_allowance_ns": 10_000_000
        });
        let mut value = json!({
            "phase": "service_completed_after_original_cutoff",
            "confirmed_prefix": {"service_cutoff": tuple.clone()}
        });
        assert_eq!(content_free_refusal(&value)["service_cutoff"], tuple);
        let secret = "SYNTHETIC_PRIVATE_VALUE_CANARY";
        for mutation in 0..8 {
            let mut malformed = value.clone();
            let witness = &mut malformed["confirmed_prefix"]["service_cutoff"];
            match mutation {
                0 => witness["write_observation_bracket_ns"] = json!(secret),
                1 => witness["event_ordinal"] = json!(8192),
                2 => witness["pending_wait_ns"] = json!(-1),
                3 => witness["completion_lateness_ns"] = json!(15_000_001),
                4 => witness["original_allowance_ns"] = json!(20_000_001),
                5 => witness["completion_lateness_ns"] = json!(u64::MAX),
                6 => witness["admission_lateness_ns"] = json!(u64::MAX),
                _ => malformed["phase"] = json!(secret),
            }
            let output = content_free_refusal(&malformed);
            assert!(output.get("service_cutoff").is_none());
            assert!(!output.to_string().contains(secret));
        }
        value["confirmed_prefix"]["service_cutoff"]["payload"] = json!(secret);
        let output = content_free_refusal(&value);
        assert_eq!(output["service_cutoff"], tuple);
        assert!(!output.to_string().contains(secret));
        value["phase"] = json!("windows_timer_after_wait_cutoff");
        assert!(content_free_refusal(&value).get("service_cutoff").is_none());
        value["confirmed_prefix"]["service_cutoff"] = Value::Null;
        assert!(content_free_refusal(&value).get("service_cutoff").is_none());
    }

    #[test]
    fn known_refusal_keeps_custody_unknown_distinct_from_false() {
        let actual = content_free_refusal(
            &json!({"phase":"windows_timer_original_cutoff", "error_kind":"TimedOut", "accepted_delivery_complete":false, "packet_io_outcome_may_be_unknown":true, "owned_pending_disposition":"collector_abort_requested_terminal_unobserved", "confirmed_prefix":{"accepted_packets":81,"sent_packets":73,"retained_packets":8,"release_thread_joined":true,"collector_joined":false,"collector_abort_requested":true}}),
        );
        assert_eq!(actual["phase"], "windows_timer_original_cutoff");
        assert_eq!(actual["error_kind"], "TimedOut");
        assert_eq!(actual["counts"]["accepted_packets"], 81);
        assert_eq!(actual["counts"]["sent_packets"], 73);
        assert_eq!(actual["counts"]["retained_packets"], 8);
        assert_eq!(actual["custody"]["collector_joined"], false);
        assert_eq!(actual["custody"]["collector_abort_requested"], true);
        assert!(actual["custody"]["collector_started"].is_null());
        assert_eq!(actual["accepted_delivery_complete"], false);
        assert_eq!(actual["packet_io_outcome_may_be_unknown"], true);
    }
    #[test]
    fn static_native_cutoff_stages_survive_content_free_projection() {
        for phase in [
            "windows_timer_initial_cutoff",
            "windows_timer_before_arm_cutoff",
            "windows_timer_after_arm_cutoff",
            "windows_timer_before_wait_cutoff",
            "windows_timer_diagnostic_entry_cutoff",
            "windows_timer_after_wait_cutoff",
        ] {
            let actual = content_free_refusal(
                &json!({"phase": phase, "error_kind": "TimedOut", "accepted_delivery_complete": false}),
            );
            assert_eq!(actual["phase"], phase);
            assert_eq!(actual["accepted_delivery_complete"], false);
        }
    }
    #[test]
    fn arbitrary_text_nested_fields_and_wrong_types_never_escape() {
        let secret = "synthetic_payload_private_key_address_CANARY";
        let actual = content_free_refusal(
            &json!({"phase":secret,"error_kind":secret,"owned_pending_disposition":secret,"payload":secret,"stderr":secret,"confirmed_prefix":{"accepted_packets":secret,"sent_packets":-1,"received_packets":1.5,"release_thread_joined":secret,"collector_started":[secret],"unknown":secret},"accepted_delivery_complete":secret,"packet_io_outcome_may_be_unknown":secret}),
        );
        let text = actual.to_string();
        assert!(!text.contains(secret));
        assert_eq!(actual["phase"], "unknown_or_unreported");
        assert_eq!(actual["error_kind"], "unknown_or_unreported");
        assert!(actual["counts"]
            .as_object()
            .unwrap()
            .values()
            .all(Value::is_null));
        assert!(actual["custody"]
            .as_object()
            .unwrap()
            .values()
            .all(Value::is_null));
        assert!(actual["accepted_delivery_complete"].is_null());
        assert!(actual["packet_io_outcome_may_be_unknown"].is_null());
        assert!(actual.get("payload").is_none());
        assert!(actual.get("stderr").is_none());
        assert!(text.len() < 2048);
    }
    #[test]
    fn missing_success_receipt_and_nonobject_are_explicitly_unreported() {
        for value in [
            Value::Null,
            json!([]),
            json!({"observations":{"delivered_packets":1500},"timing_control_authenticated":true}),
        ] {
            let actual = content_free_refusal(&value);
            assert_eq!(actual["phase"], "unknown_or_unreported");
            assert!(actual["counts"]["delivered_packets"].is_null());
            assert!(actual["accepted_delivery_complete"].is_null());
        }
    }
    #[test]
    fn current_native_api_phase_labels_keep_typed_refusal_without_error_text() {
        for phase in [
            "windows_highres_timer_create",
            "windows_highres_timer_arm",
            "windows_highres_timer_timeout",
            "windows_highres_timer_wait",
        ] {
            let actual = content_free_refusal(
                &json!({"phase":phase,"error_kind":"Other","stderr":"synthetic_private_error_CANARY"}),
            );
            assert_eq!(actual["phase"], phase);
            assert_eq!(actual["error_kind"], "Other");
            assert!(!actual.to_string().contains("CANARY"));
        }
    }
}
