#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/validate-mimicry-wire-host.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-wire-host-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cargo build -q -p aegis-measure
export AEGIS_MEASURE_BIN="${ROOT}/target/debug/aegis-measure"
IS_LINUX=0
if [[ "$(uname -s)" == "Linux" ]]; then
  IS_LINUX=1
fi

run_check_case() {
  local output_json="${TMP_DIR}/check.json"
  AEGIS_MIMICRY_WIRE_FORCE_CAP_NET_RAW=1 \
  AEGIS_MIMICRY_WIRE_FORCE_CAP_NET_ADMIN=1 \
    bash "${SCRIPT}" --check --json > "${output_json}"

  cargo run -q -p aegis-measure -- check-mimicry-wire-host-helper-report-contract \
    --report-json "${output_json}"
}

write_runtime_events_case() {
  local events_path="$1"
  cat > "${events_path}" <<'EOF'
{"event_code":"direct_session_succeeded","fields":{"mimicry_capability_signal_origin":"live_runtime_observation","mimicry_capability_wire_stage":"architecture_scaffold_only","mimicry_capability_wire_scope":"future_packet_wire_linux_only","mimicry_capability_wire_requested":false,"mimicry_capability_wire_active":false,"mimicry_capability_wire_activation_reason":"config_disabled","mimicry_capability_wire_runtime_slice":null,"mimicry_capability_wire_ttl_preface":null,"mimicry_capability_wire_window_preface_ready":false,"mimicry_capability_wire_window_preface":null,"mimicry_capability_wire_options_preface_ready":false,"mimicry_capability_wire_options_preface_profile":null,"mimicry_capability_wire_options_preface_size":null,"mimicry_capability_wire_ipv4_header_shaping_ready":false,"mimicry_capability_wire_ipv4_header_shaping_observed_ready":false,"mimicry_capability_wire_ipv4_header_shaping_profile":null,"mimicry_capability_wire_ipv4_header_shaping_tos":null,"mimicry_capability_wire_ipv4_header_shaping_ip_id":null,"mimicry_capability_wire_ipv4_header_shaping_dont_fragment":null,"mimicry_capability_wire_ipv4_header_shaping_source":null,"mimicry_capability_wire_negotiated_options_ready":false,"mimicry_capability_wire_negotiated_options_observed_ready":false,"mimicry_capability_wire_negotiated_options_profile":null,"mimicry_capability_wire_negotiated_options_size":null,"mimicry_capability_wire_negotiated_options_mss":null,"mimicry_capability_wire_negotiated_options_window_scale":null,"mimicry_capability_wire_negotiated_options_sack_permitted":null,"mimicry_capability_wire_negotiated_options_timestamp_mode":null,"mimicry_capability_wire_negotiated_options_source":null,"mimicry_capability_wire_raw_ipv4_send_ready":false,"mimicry_capability_wire_tcp_repair_ready":false,"mimicry_capability_wire_ipv4_header_control_ready":false,"mimicry_capability_wire_ipv4_fragmentation_ready":true,"mimicry_capability_wire_fragment_choreography_ready":false,"mimicry_capability_wire_fragment_choreography_observed_ready":false,"mimicry_capability_wire_fragment_choreography_profile":null,"mimicry_capability_wire_fragment_choreography_steps":null,"mimicry_capability_wire_fragment_choreography_first_payload_len":null,"mimicry_capability_wire_fragment_choreography_disorder_split_at":null,"mimicry_capability_wire_fragment_choreography_overlap":null,"mimicry_capability_wire_fragment_choreography_source":null}}
{"event_code":"direct_planner_order_selected","fields":{"mimicry_capability_signal_origin":"advisory_latest_observation","mimicry_capability_wire_stage":"architecture_scaffold_only","mimicry_capability_wire_scope":"future_packet_wire_linux_only","mimicry_capability_wire_requested":true,"mimicry_capability_wire_active":false,"mimicry_capability_wire_activation_reason":"raw_capabilities_missing","mimicry_capability_wire_runtime_slice":null,"mimicry_capability_wire_ttl_preface":60,"mimicry_capability_wire_window_preface_ready":true,"mimicry_capability_wire_window_preface":64240,"mimicry_capability_wire_options_preface_ready":true,"mimicry_capability_wire_options_preface_profile":"ack_timestamp_pad12","mimicry_capability_wire_options_preface_size":12,"mimicry_capability_wire_ipv4_header_shaping_ready":true,"mimicry_capability_wire_ipv4_header_shaping_observed_ready":true,"mimicry_capability_wire_ipv4_header_shaping_profile":"observed_capture_backed_ipv4_header_shaping_v1","mimicry_capability_wire_ipv4_header_shaping_tos":16,"mimicry_capability_wire_ipv4_header_shaping_ip_id":4660,"mimicry_capability_wire_ipv4_header_shaping_dont_fragment":true,"mimicry_capability_wire_ipv4_header_shaping_source":"observed_capture_backed","mimicry_capability_wire_negotiated_options_ready":true,"mimicry_capability_wire_negotiated_options_observed_ready":true,"mimicry_capability_wire_negotiated_options_profile":"observed_capture_backed_negotiated_options_v1","mimicry_capability_wire_negotiated_options_size":20,"mimicry_capability_wire_negotiated_options_mss":1460,"mimicry_capability_wire_negotiated_options_window_scale":8,"mimicry_capability_wire_negotiated_options_sack_permitted":true,"mimicry_capability_wire_negotiated_options_timestamp_mode":"syn_timestamp_offer_layout20","mimicry_capability_wire_negotiated_options_source":"observed_capture_backed","mimicry_capability_wire_raw_ipv4_send_ready":false,"mimicry_capability_wire_tcp_repair_ready":false,"mimicry_capability_wire_ipv4_header_control_ready":false,"mimicry_capability_wire_ipv4_fragmentation_ready":true,"mimicry_capability_wire_fragment_choreography_ready":true,"mimicry_capability_wire_fragment_choreography_observed_ready":true,"mimicry_capability_wire_fragment_choreography_profile":"observed_capture_backed_fragment_ordered_decoy_v1","mimicry_capability_wire_fragment_choreography_steps":"fragment_then_disorder_then_overlap","mimicry_capability_wire_fragment_choreography_first_payload_len":40,"mimicry_capability_wire_fragment_choreography_disorder_split_at":40,"mimicry_capability_wire_fragment_choreography_overlap":8,"mimicry_capability_wire_fragment_choreography_source":"observed_capture_backed"}}
{"event_code":"direct_planner_order_selected","fields":{"mimicry_capability_signal_origin":"advisory_latest_observation","mimicry_capability_wire_stage":"architecture_scaffold_only","mimicry_capability_wire_scope":"future_packet_wire_linux_only","mimicry_capability_wire_requested":true,"mimicry_capability_wire_active":true,"mimicry_capability_wire_activation_reason":"linux_experimental_ttl_preface_active","mimicry_capability_wire_runtime_slice":"linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface","mimicry_capability_wire_ttl_preface":60,"mimicry_capability_wire_window_preface_ready":true,"mimicry_capability_wire_window_preface":64240,"mimicry_capability_wire_options_preface_ready":true,"mimicry_capability_wire_options_preface_profile":"ack_timestamp_pad12","mimicry_capability_wire_options_preface_size":12,"mimicry_capability_wire_ipv4_header_shaping_ready":true,"mimicry_capability_wire_ipv4_header_shaping_observed_ready":true,"mimicry_capability_wire_ipv4_header_shaping_profile":"observed_capture_backed_ipv4_header_shaping_v1","mimicry_capability_wire_ipv4_header_shaping_tos":16,"mimicry_capability_wire_ipv4_header_shaping_ip_id":4660,"mimicry_capability_wire_ipv4_header_shaping_dont_fragment":true,"mimicry_capability_wire_ipv4_header_shaping_source":"observed_capture_backed","mimicry_capability_wire_negotiated_options_ready":true,"mimicry_capability_wire_negotiated_options_observed_ready":true,"mimicry_capability_wire_negotiated_options_profile":"observed_capture_backed_negotiated_options_v1","mimicry_capability_wire_negotiated_options_size":20,"mimicry_capability_wire_negotiated_options_mss":1460,"mimicry_capability_wire_negotiated_options_window_scale":8,"mimicry_capability_wire_negotiated_options_sack_permitted":true,"mimicry_capability_wire_negotiated_options_timestamp_mode":"syn_timestamp_offer_layout20","mimicry_capability_wire_negotiated_options_source":"observed_capture_backed","mimicry_capability_wire_raw_ipv4_send_ready":true,"mimicry_capability_wire_tcp_repair_ready":true,"mimicry_capability_wire_ipv4_header_control_ready":true,"mimicry_capability_wire_ipv4_fragmentation_ready":true,"mimicry_capability_wire_fragment_choreography_ready":true,"mimicry_capability_wire_fragment_choreography_observed_ready":true,"mimicry_capability_wire_fragment_choreography_profile":"observed_capture_backed_fragment_ordered_decoy_v1","mimicry_capability_wire_fragment_choreography_steps":"fragment_then_disorder_then_overlap","mimicry_capability_wire_fragment_choreography_first_payload_len":40,"mimicry_capability_wire_fragment_choreography_disorder_split_at":40,"mimicry_capability_wire_fragment_choreography_overlap":8,"mimicry_capability_wire_fragment_choreography_source":"observed_capture_backed"}}
EOF
}

write_witness_runtime_events_case() {
  local events_path="$1"
  cat > "${events_path}" <<'EOF'
{"ts_unix_ms":1709999998000,"event_code":"direct_session_succeeded","fields":{"target":"planner.example","port":443,"mimicry_capability_signal_origin":"live_runtime_observation","mimicry_capability_wire_stage":"architecture_scaffold_only","mimicry_capability_wire_scope":"future_packet_wire_linux_only","mimicry_capability_wire_requested":false,"mimicry_capability_wire_active":false,"mimicry_capability_wire_activation_reason":"config_disabled","mimicry_capability_wire_runtime_slice":null,"mimicry_capability_wire_ttl_preface":null,"mimicry_capability_wire_window_preface_ready":false,"mimicry_capability_wire_window_preface":null,"mimicry_capability_wire_options_preface_ready":false,"mimicry_capability_wire_options_preface_profile":null,"mimicry_capability_wire_options_preface_size":null,"mimicry_capability_wire_ipv4_header_shaping_ready":false,"mimicry_capability_wire_ipv4_header_shaping_observed_ready":false,"mimicry_capability_wire_ipv4_header_shaping_profile":null,"mimicry_capability_wire_ipv4_header_shaping_tos":null,"mimicry_capability_wire_ipv4_header_shaping_ip_id":null,"mimicry_capability_wire_ipv4_header_shaping_dont_fragment":null,"mimicry_capability_wire_ipv4_header_shaping_source":null,"mimicry_capability_wire_negotiated_options_ready":false,"mimicry_capability_wire_negotiated_options_observed_ready":false,"mimicry_capability_wire_negotiated_options_profile":null,"mimicry_capability_wire_negotiated_options_size":null,"mimicry_capability_wire_negotiated_options_mss":null,"mimicry_capability_wire_negotiated_options_window_scale":null,"mimicry_capability_wire_negotiated_options_sack_permitted":null,"mimicry_capability_wire_negotiated_options_timestamp_mode":null,"mimicry_capability_wire_negotiated_options_source":null,"mimicry_capability_wire_raw_ipv4_send_ready":false,"mimicry_capability_wire_tcp_repair_ready":false,"mimicry_capability_wire_ipv4_header_control_ready":false,"mimicry_capability_wire_ipv4_fragmentation_ready":true,"mimicry_capability_wire_fragment_choreography_ready":false,"mimicry_capability_wire_fragment_choreography_observed_ready":false,"mimicry_capability_wire_fragment_choreography_profile":null,"mimicry_capability_wire_fragment_choreography_steps":null,"mimicry_capability_wire_fragment_choreography_first_payload_len":null,"mimicry_capability_wire_fragment_choreography_disorder_split_at":null,"mimicry_capability_wire_fragment_choreography_overlap":null,"mimicry_capability_wire_fragment_choreography_source":null}}
{"ts_unix_ms":1709999999000,"event_code":"direct_planner_order_selected","fields":{"target":"planner.example","port":443,"mimicry_capability_signal_origin":"advisory_latest_observation","mimicry_capability_wire_stage":"architecture_scaffold_only","mimicry_capability_wire_scope":"future_packet_wire_linux_only","mimicry_capability_wire_requested":true,"mimicry_capability_wire_active":false,"mimicry_capability_wire_activation_reason":"raw_capabilities_missing","mimicry_capability_wire_runtime_slice":null,"mimicry_capability_wire_ttl_preface":60,"mimicry_capability_wire_window_preface_ready":true,"mimicry_capability_wire_window_preface":64240,"mimicry_capability_wire_options_preface_ready":true,"mimicry_capability_wire_options_preface_profile":"ack_timestamp_pad12","mimicry_capability_wire_options_preface_size":12,"mimicry_capability_wire_ipv4_header_shaping_ready":true,"mimicry_capability_wire_ipv4_header_shaping_observed_ready":true,"mimicry_capability_wire_ipv4_header_shaping_profile":"observed_capture_backed_ipv4_header_shaping_v1","mimicry_capability_wire_ipv4_header_shaping_tos":16,"mimicry_capability_wire_ipv4_header_shaping_ip_id":4660,"mimicry_capability_wire_ipv4_header_shaping_dont_fragment":true,"mimicry_capability_wire_ipv4_header_shaping_source":"observed_capture_backed","mimicry_capability_wire_negotiated_options_ready":true,"mimicry_capability_wire_negotiated_options_observed_ready":true,"mimicry_capability_wire_negotiated_options_profile":"observed_capture_backed_negotiated_options_v1","mimicry_capability_wire_negotiated_options_size":20,"mimicry_capability_wire_negotiated_options_mss":1460,"mimicry_capability_wire_negotiated_options_window_scale":8,"mimicry_capability_wire_negotiated_options_sack_permitted":true,"mimicry_capability_wire_negotiated_options_timestamp_mode":"syn_timestamp_offer_layout20","mimicry_capability_wire_negotiated_options_source":"observed_capture_backed","mimicry_capability_wire_raw_ipv4_send_ready":false,"mimicry_capability_wire_tcp_repair_ready":false,"mimicry_capability_wire_ipv4_header_control_ready":false,"mimicry_capability_wire_ipv4_fragmentation_ready":true,"mimicry_capability_wire_fragment_choreography_ready":true,"mimicry_capability_wire_fragment_choreography_observed_ready":true,"mimicry_capability_wire_fragment_choreography_profile":"observed_capture_backed_fragment_ordered_decoy_v1","mimicry_capability_wire_fragment_choreography_steps":"fragment_then_disorder_then_overlap","mimicry_capability_wire_fragment_choreography_first_payload_len":40,"mimicry_capability_wire_fragment_choreography_disorder_split_at":40,"mimicry_capability_wire_fragment_choreography_overlap":8,"mimicry_capability_wire_fragment_choreography_source":"observed_capture_backed"}}
{"ts_unix_ms":1710000000000,"event_code":"direct_planner_order_selected","fields":{"target":"planner.example","port":443,"mimicry_capability_signal_origin":"advisory_latest_observation","mimicry_capability_wire_stage":"architecture_scaffold_only","mimicry_capability_wire_scope":"future_packet_wire_linux_only","mimicry_capability_wire_requested":true,"mimicry_capability_wire_active":true,"mimicry_capability_wire_activation_reason":"linux_experimental_ttl_preface_active","mimicry_capability_wire_runtime_slice":"linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface","mimicry_capability_wire_ttl_preface":60,"mimicry_capability_wire_window_preface_ready":true,"mimicry_capability_wire_window_preface":64240,"mimicry_capability_wire_options_preface_ready":true,"mimicry_capability_wire_options_preface_profile":"ack_timestamp_pad12","mimicry_capability_wire_options_preface_size":12,"mimicry_capability_wire_ipv4_header_shaping_ready":true,"mimicry_capability_wire_ipv4_header_shaping_observed_ready":true,"mimicry_capability_wire_ipv4_header_shaping_profile":"observed_capture_backed_ipv4_header_shaping_v1","mimicry_capability_wire_ipv4_header_shaping_tos":16,"mimicry_capability_wire_ipv4_header_shaping_ip_id":4660,"mimicry_capability_wire_ipv4_header_shaping_dont_fragment":true,"mimicry_capability_wire_ipv4_header_shaping_source":"observed_capture_backed","mimicry_capability_wire_negotiated_options_ready":true,"mimicry_capability_wire_negotiated_options_observed_ready":true,"mimicry_capability_wire_negotiated_options_profile":"observed_capture_backed_negotiated_options_v1","mimicry_capability_wire_negotiated_options_size":20,"mimicry_capability_wire_negotiated_options_mss":1460,"mimicry_capability_wire_negotiated_options_window_scale":8,"mimicry_capability_wire_negotiated_options_sack_permitted":true,"mimicry_capability_wire_negotiated_options_timestamp_mode":"syn_timestamp_offer_layout20","mimicry_capability_wire_negotiated_options_source":"observed_capture_backed","mimicry_capability_wire_raw_ipv4_send_ready":true,"mimicry_capability_wire_tcp_repair_ready":true,"mimicry_capability_wire_ipv4_header_control_ready":true,"mimicry_capability_wire_ipv4_fragmentation_ready":true,"mimicry_capability_wire_fragment_choreography_ready":true,"mimicry_capability_wire_fragment_choreography_observed_ready":true,"mimicry_capability_wire_fragment_choreography_profile":"observed_capture_backed_fragment_ordered_decoy_v1","mimicry_capability_wire_fragment_choreography_steps":"fragment_then_disorder_then_overlap","mimicry_capability_wire_fragment_choreography_first_payload_len":40,"mimicry_capability_wire_fragment_choreography_disorder_split_at":40,"mimicry_capability_wire_fragment_choreography_overlap":8,"mimicry_capability_wire_fragment_choreography_source":"observed_capture_backed"}}
EOF
}

write_witness_summary_match_case() {
  local witness_path="$1"
  cat > "${witness_path}" <<'EOF'
{"artifact_schema":"wire_mimicry_independent_witness_summary_v1","generated_by":"test-fixture","records":[{"target":"planner.example","port":443,"runtime_slice":"linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface","capture_window":{"start_unix_ms":1709999999000,"end_unix_ms":1710000001000},"ttl_preface":60,"window_preface":64240,"ipv4_header_shaping":{"tos":16,"ip_id":4660,"dont_fragment":true},"negotiated_options":{"mss":1460,"window_scale":8,"sack_permitted":true,"timestamp_mode":"syn_timestamp_offer_layout20"},"fragment_choreography":{"first_payload_len":40,"disorder_split_at":40,"overlap":8}}]}
EOF
}

write_witness_summary_mismatch_case() {
  local witness_path="$1"
  cat > "${witness_path}" <<'EOF'
{"artifact_schema":"wire_mimicry_independent_witness_summary_v1","generated_by":"test-fixture","records":[{"target":"planner.example","port":443,"runtime_slice":"linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface","capture_window":{"start_unix_ms":1709999999000,"end_unix_ms":1710000001000},"ttl_preface":61,"window_preface":64240,"ipv4_header_shaping":{"tos":16,"ip_id":4660,"dont_fragment":true}}]}
EOF
}

run_green_case() {
  local case_dir="${TMP_DIR}/green"
  local events_path="${case_dir}/runtime-events.jsonl"
  local artifact_dir="${case_dir}/artifacts"
  local stdout_json="${case_dir}/stdout.json"
  mkdir -p "${case_dir}" "${artifact_dir}"
  write_runtime_events_case "${events_path}"

  bash "${SCRIPT}" \
    --run \
    --runtime-events "${events_path}" \
    --artifact-dir "${artifact_dir}" \
    --json > "${stdout_json}"

  cargo run -q -p aegis-measure -- check-mimicry-wire-host-acceptance-contract \
    --stdout-json "${stdout_json}" \
    --capture-summary-json "${artifact_dir}/capture-replay-summary.json" \
    --host-summary-json "${artifact_dir}/wire-host-acceptance-summary.json" \
    --expected-product-verdict green \
    --expected-acceptance-status passed \
    --expected-verdict-reason full_wire_state_matrix_with_privileged_active_runtime \
    --expected-witness-status not_provided \
    --expected-hostile-path-ready false \
    --expected-hostile-path-tier not_proven \
    --expected-records-scanned 3 \
    --expected-complete-records 3 \
    --expected-active-ready-count 1 \
    --expected-active-missing-count 0
}

run_witness_match_case() {
  local case_dir="${TMP_DIR}/witness-match"
  local events_path="${case_dir}/runtime-events.jsonl"
  local witness_path="${case_dir}/wire-witness-summary.json"
  local artifact_dir="${case_dir}/artifacts"
  mkdir -p "${case_dir}" "${artifact_dir}"

  write_witness_runtime_events_case "${events_path}"
  write_witness_summary_match_case "${witness_path}"

  bash "${SCRIPT}" \
    --run \
    --runtime-events "${events_path}" \
    --artifact-dir "${artifact_dir}" \
    --witness-summary "${witness_path}" >/dev/null

  cargo run -q -p aegis-measure -- check-mimicry-wire-host-acceptance-contract \
    --capture-summary-json "${artifact_dir}/capture-replay-summary.json" \
    --host-summary-json "${artifact_dir}/wire-host-acceptance-summary.json" \
    --expected-product-verdict green \
    --expected-acceptance-status passed \
    --expected-verdict-reason full_wire_state_matrix_with_privileged_active_runtime_and_witness_match \
    --expected-witness-status matched \
    --expected-hostile-path-ready true \
    --expected-hostile-path-tier wire_level_supported_hostile_path \
    --expected-witness-matched 1 \
    --expected-witness-mismatched 0
}

run_witness_mismatch_case() {
  local case_dir="${TMP_DIR}/witness-mismatch"
  local events_path="${case_dir}/runtime-events.jsonl"
  local witness_path="${case_dir}/wire-witness-summary.json"
  local artifact_dir="${case_dir}/artifacts"
  mkdir -p "${case_dir}" "${artifact_dir}"

  write_witness_runtime_events_case "${events_path}"
  write_witness_summary_mismatch_case "${witness_path}"

  bash "${SCRIPT}" \
    --run \
    --runtime-events "${events_path}" \
    --artifact-dir "${artifact_dir}" \
    --witness-summary "${witness_path}" >/dev/null

  cargo run -q -p aegis-measure -- check-mimicry-wire-host-acceptance-contract \
    --capture-summary-json "${artifact_dir}/capture-replay-summary.json" \
    --host-summary-json "${artifact_dir}/wire-host-acceptance-summary.json" \
    --expected-product-verdict degraded \
    --expected-acceptance-status degraded \
    --expected-verdict-reason independent_witness_not_correlated_with_runtime \
    --expected-witness-status mismatched \
    --expected-hostile-path-ready false \
    --expected-witness-mismatched 1 \
    --expected-mismatch-field ttl_preface
}

run_degraded_case() {
  local case_dir="${TMP_DIR}/degraded"
  local events_path="${case_dir}/runtime-events.jsonl"
  local artifact_dir="${case_dir}/artifacts"
  mkdir -p "${case_dir}" "${artifact_dir}"
  cat > "${events_path}" <<'EOF'
{"event_code":"direct_session_succeeded","fields":{"mimicry_capability_signal_origin":"live_runtime_observation","mimicry_capability_wire_stage":"architecture_scaffold_only","mimicry_capability_wire_scope":"future_packet_wire_linux_only","mimicry_capability_wire_requested":false,"mimicry_capability_wire_active":false,"mimicry_capability_wire_activation_reason":"config_disabled","mimicry_capability_wire_runtime_slice":null,"mimicry_capability_wire_ttl_preface":null,"mimicry_capability_wire_window_preface_ready":false,"mimicry_capability_wire_window_preface":null,"mimicry_capability_wire_options_preface_ready":false,"mimicry_capability_wire_options_preface_profile":null,"mimicry_capability_wire_options_preface_size":null,"mimicry_capability_wire_ipv4_header_shaping_ready":false,"mimicry_capability_wire_ipv4_header_shaping_observed_ready":false,"mimicry_capability_wire_ipv4_header_shaping_profile":null,"mimicry_capability_wire_ipv4_header_shaping_tos":null,"mimicry_capability_wire_ipv4_header_shaping_ip_id":null,"mimicry_capability_wire_ipv4_header_shaping_dont_fragment":null,"mimicry_capability_wire_ipv4_header_shaping_source":null,"mimicry_capability_wire_negotiated_options_ready":false,"mimicry_capability_wire_negotiated_options_observed_ready":false,"mimicry_capability_wire_negotiated_options_profile":null,"mimicry_capability_wire_negotiated_options_size":null,"mimicry_capability_wire_negotiated_options_mss":null,"mimicry_capability_wire_negotiated_options_window_scale":null,"mimicry_capability_wire_negotiated_options_sack_permitted":null,"mimicry_capability_wire_negotiated_options_timestamp_mode":null,"mimicry_capability_wire_negotiated_options_source":null,"mimicry_capability_wire_raw_ipv4_send_ready":false,"mimicry_capability_wire_tcp_repair_ready":false,"mimicry_capability_wire_ipv4_header_control_ready":false,"mimicry_capability_wire_ipv4_fragmentation_ready":true,"mimicry_capability_wire_fragment_choreography_ready":false,"mimicry_capability_wire_fragment_choreography_observed_ready":false,"mimicry_capability_wire_fragment_choreography_profile":null,"mimicry_capability_wire_fragment_choreography_steps":null,"mimicry_capability_wire_fragment_choreography_first_payload_len":null,"mimicry_capability_wire_fragment_choreography_disorder_split_at":null,"mimicry_capability_wire_fragment_choreography_overlap":null,"mimicry_capability_wire_fragment_choreography_source":null}}
{"event_code":"direct_planner_order_selected","fields":{"mimicry_capability_signal_origin":"advisory_latest_observation","mimicry_capability_wire_stage":"architecture_scaffold_only","mimicry_capability_wire_scope":"future_packet_wire_linux_only","mimicry_capability_wire_requested":true,"mimicry_capability_wire_active":false,"mimicry_capability_wire_activation_reason":"raw_capabilities_missing","mimicry_capability_wire_runtime_slice":null,"mimicry_capability_wire_ttl_preface":60,"mimicry_capability_wire_window_preface_ready":true,"mimicry_capability_wire_window_preface":64240,"mimicry_capability_wire_options_preface_ready":true,"mimicry_capability_wire_options_preface_profile":"ack_timestamp_pad12","mimicry_capability_wire_options_preface_size":12,"mimicry_capability_wire_ipv4_header_shaping_ready":true,"mimicry_capability_wire_ipv4_header_shaping_observed_ready":true,"mimicry_capability_wire_ipv4_header_shaping_profile":"observed_capture_backed_ipv4_header_shaping_v1","mimicry_capability_wire_ipv4_header_shaping_tos":16,"mimicry_capability_wire_ipv4_header_shaping_ip_id":4660,"mimicry_capability_wire_ipv4_header_shaping_dont_fragment":true,"mimicry_capability_wire_ipv4_header_shaping_source":"observed_capture_backed","mimicry_capability_wire_negotiated_options_ready":true,"mimicry_capability_wire_negotiated_options_observed_ready":true,"mimicry_capability_wire_negotiated_options_profile":"observed_capture_backed_negotiated_options_v1","mimicry_capability_wire_negotiated_options_size":20,"mimicry_capability_wire_negotiated_options_mss":1460,"mimicry_capability_wire_negotiated_options_window_scale":8,"mimicry_capability_wire_negotiated_options_sack_permitted":true,"mimicry_capability_wire_negotiated_options_timestamp_mode":"syn_timestamp_offer_layout20","mimicry_capability_wire_negotiated_options_source":"observed_capture_backed","mimicry_capability_wire_raw_ipv4_send_ready":false,"mimicry_capability_wire_tcp_repair_ready":false,"mimicry_capability_wire_ipv4_header_control_ready":false,"mimicry_capability_wire_ipv4_fragmentation_ready":true,"mimicry_capability_wire_fragment_choreography_ready":true,"mimicry_capability_wire_fragment_choreography_observed_ready":true,"mimicry_capability_wire_fragment_choreography_profile":"observed_capture_backed_fragment_ordered_decoy_v1","mimicry_capability_wire_fragment_choreography_steps":"fragment_then_disorder_then_overlap","mimicry_capability_wire_fragment_choreography_first_payload_len":40,"mimicry_capability_wire_fragment_choreography_disorder_split_at":40,"mimicry_capability_wire_fragment_choreography_overlap":8,"mimicry_capability_wire_fragment_choreography_source":"observed_capture_backed"}}
EOF

  bash "${SCRIPT}" \
    --run \
    --runtime-events "${events_path}" \
    --artifact-dir "${artifact_dir}" >/dev/null

  cargo run -q -p aegis-measure -- check-mimicry-wire-host-acceptance-contract \
    --host-summary-json "${artifact_dir}/wire-host-acceptance-summary.json" \
    --expected-product-verdict degraded \
    --expected-acceptance-status degraded \
    --expected-verdict-reason partial_wire_state_matrix_only
}

if [[ "${IS_LINUX}" -eq 1 ]]; then
  run_check_case
fi
run_green_case
run_degraded_case
run_witness_match_case
run_witness_mismatch_case

echo "validate-mimicry-wire-host contract: ok"
