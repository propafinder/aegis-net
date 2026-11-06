#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

OUT="${TMP_DIR}/mimicry-wire-validation.json"

bash "${ROOT}/scripts/mimicry-wire-validation-contract.sh" --output "${OUT}"

jq -e '
  .artifact_schema == "wire_mimicry_validation_contract_v1"
  and .scope == "future_packet_wire_linux_only"
  and .stable_userspace_boundary == "pre_connect_socket_only"
  and .first_runtime_slice == "linux_experimental_ipv4_ttl_preface"
  and .expanded_runtime_slice == "linux_experimental_ipv4_ttl_window_preface"
  and .options_runtime_slice == "linux_experimental_ipv4_ttl_window_options_preface"
  and .negotiated_options_runtime_slice == "linux_experimental_ipv4_ttl_window_negotiated_options_preface"
  and .fragment_choreography_runtime_slice == "linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface"
  and .config_path == "direct.wire_mimicry_mode=linux_experimental_ttl_preface"
  and .validation_strategy == "capture_replay_plus_privileged_host_acceptance"
  and .separate_from_release_gate == true
  and .release_gate_dependency == "none"
  and .host_helper_script == "scripts/validate-mimicry-wire-host.sh"
  and .required_runtime_capability_fields == [
    "mimicry_capability_wire_stage",
    "mimicry_capability_wire_scope",
    "mimicry_capability_wire_requested",
    "mimicry_capability_wire_active",
    "mimicry_capability_wire_activation_reason",
    "mimicry_capability_wire_runtime_slice",
    "mimicry_capability_wire_ttl_preface",
    "mimicry_capability_wire_window_preface_ready",
    "mimicry_capability_wire_window_preface",
    "mimicry_capability_wire_options_preface_ready",
    "mimicry_capability_wire_options_preface_profile",
    "mimicry_capability_wire_options_preface_size",
    "mimicry_capability_wire_ipv4_header_shaping_ready",
    "mimicry_capability_wire_ipv4_header_shaping_observed_ready",
    "mimicry_capability_wire_ipv4_header_shaping_profile",
    "mimicry_capability_wire_ipv4_header_shaping_tos",
    "mimicry_capability_wire_ipv4_header_shaping_ip_id",
    "mimicry_capability_wire_ipv4_header_shaping_dont_fragment",
    "mimicry_capability_wire_ipv4_header_shaping_source",
    "mimicry_capability_wire_negotiated_options_ready",
    "mimicry_capability_wire_negotiated_options_observed_ready",
    "mimicry_capability_wire_negotiated_options_profile",
    "mimicry_capability_wire_negotiated_options_size",
    "mimicry_capability_wire_negotiated_options_mss",
    "mimicry_capability_wire_negotiated_options_window_scale",
    "mimicry_capability_wire_negotiated_options_sack_permitted",
    "mimicry_capability_wire_negotiated_options_timestamp_mode",
    "mimicry_capability_wire_negotiated_options_source",
    "mimicry_capability_wire_raw_ipv4_send_ready",
    "mimicry_capability_wire_tcp_repair_ready",
    "mimicry_capability_wire_ipv4_header_control_ready",
    "mimicry_capability_wire_ipv4_fragmentation_ready",
    "mimicry_capability_wire_fragment_choreography_ready",
    "mimicry_capability_wire_fragment_choreography_observed_ready",
    "mimicry_capability_wire_fragment_choreography_profile",
    "mimicry_capability_wire_fragment_choreography_steps",
    "mimicry_capability_wire_fragment_choreography_first_payload_len",
    "mimicry_capability_wire_fragment_choreography_disorder_split_at",
    "mimicry_capability_wire_fragment_choreography_overlap",
    "mimicry_capability_wire_fragment_choreography_source"
  ]
  and .required_runtime_state_matrix == [
    "requested_false",
    "requested_true_inactive",
    "requested_true_active"
  ]
  and .required_replay_artifacts == [
    "runtime-events-jsonl",
    "capture-replay-summary.json"
  ]
  and .required_host_acceptance_artifacts == [
    "wire-host-acceptance-summary.json"
  ]
  and .optional_witness_artifacts == [
    "wire-witness-summary.json"
  ]
  and .required_capabilities == ["CAP_NET_RAW", "CAP_NET_ADMIN"]
  and .required_active_runtime_ready_fields == [
    "mimicry_capability_wire_raw_ipv4_send_ready",
    "mimicry_capability_wire_tcp_repair_ready",
    "mimicry_capability_wire_ipv4_header_control_ready"
  ]
  and .witness_summary_schema == "wire_mimicry_independent_witness_summary_v1"
  and .witness_correlation_strategy == "target_port_runtime_slice_plus_capture_backed_field_match"
  and .witness_correlation_fields == [
    "ttl_preface",
    "window_preface",
    "ipv4_header_shaping.tos",
    "ipv4_header_shaping.ip_id",
    "ipv4_header_shaping.dont_fragment",
    "negotiated_options.mss",
    "negotiated_options.window_scale",
    "negotiated_options.sack_permitted",
    "negotiated_options.timestamp_mode",
    "fragment_choreography.first_payload_len",
    "fragment_choreography.disorder_split_at",
    "fragment_choreography.overlap"
  ]
  and .verdict_vocabulary == ["green", "degraded", "red"]
' "${OUT}" >/dev/null

echo "mimicry-wire-validation contract: ok"
