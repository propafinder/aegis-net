#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-d-reach.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/phase-c-blocked.json" <<'JSON'
{
  "status": "PHASE_C_RESILIENCE_BLOCKED",
  "phase_c_exit_status": "EXIT_NOT_READY",
  "acceptance_degraded": true
}
JSON

cat >"${TMP_DIR}/phase-c-ready.json" <<'JSON'
{
  "status": "PHASE_C_RESILIENCE_READY",
  "phase_c_exit_status": "EXIT_READY",
  "acceptance_degraded": false
}
JSON

cat >"${TMP_DIR}/windows-prep.json" <<'JSON'
{
  "socks_client_baseline_pass": true,
  "service_baseline_pass": true,
  "controlled_wfp_tcp_path_pass": true,
  "dynamic_original_destination_pass": true,
  "controlled_process_capture_pass": false,
  "controlled_browser_capture_pass": false,
  "broad_capture_claimed": false,
  "dns_policy_proven": false,
  "udp_policy_proven": false,
  "ipv6_policy_proven": false,
  "service_persistence_proven": false,
  "service_reboot_pass": false,
  "service_reboot_status": "NOT_PROVIDED",
  "dns_udp_next_scope_status": "NOT_PROVIDED",
  "dns_capture_claimed": false,
  "udp_capture_claimed": false,
  "ipv6_capture_claimed": false,
  "rollback_matrix_proven": false
}
JSON

cat >"${TMP_DIR}/macos-prep.json" <<'JSON'
{
  "pf_apply_cleanup_evidence": true,
  "foreground_socks_supported": true,
  "launchdaemon_socks_supported": true,
  "utun_w0_lab_pass": true,
  "utun_w4_policy_cleanup_pass": true,
  "utun_w5_controlled_external_relay_path_pass": true,
  "network_extension_system_wide_proven": false,
  "pf_system_wide_capture_claimed": false
}
JSON

cat >"${TMP_DIR}/android-prep.json" <<'JSON'
{
  "rust_jni_core_compiles": true,
  "vpnservice_basic_flow_proven": false,
  "production_android_claimed": false
}
JSON

if bash "${ROOT}/scripts/build-phase-d-reach-gate.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c-blocked.json" \
  --windows-reach-json "${TMP_DIR}/windows-prep.json" \
  --macos-reach-json "${TMP_DIR}/macos-prep.json" \
  --android-reach-json "${TMP_DIR}/android-prep.json" \
  --output-json "${TMP_DIR}/prep-blocked.json" \
  --output-markdown "${TMP_DIR}/prep-blocked.md"; then
  echo "expected Phase C blocked to prevent Phase D exit" >&2
  exit 1
fi
grep -q '"status": "PHASE_D_PREP_READY"' "${TMP_DIR}/prep-blocked.json"
grep -q '"utun_w4_policy_cleanup_pass": true' "${TMP_DIR}/prep-blocked.json"
grep -q '"utun_w5_controlled_external_relay_path_pass": true' "${TMP_DIR}/prep-blocked.json"
grep -q 'phase_c_resilience_not_ready' "${TMP_DIR}/prep-blocked.json"
grep -q 'Phase D Reach Gate' "${TMP_DIR}/prep-blocked.md"

cat >"${TMP_DIR}/windows-overclaim.json" <<'JSON'
{
  "socks_client_baseline_pass": true,
  "service_baseline_pass": true,
  "controlled_wfp_tcp_path_pass": true,
  "dynamic_original_destination_pass": true,
  "broad_capture_claimed": true
}
JSON

if bash "${ROOT}/scripts/build-phase-d-reach-gate.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c-ready.json" \
  --windows-reach-json "${TMP_DIR}/windows-overclaim.json" \
  --macos-reach-json "${TMP_DIR}/macos-prep.json" \
  --android-reach-json "${TMP_DIR}/android-prep.json" \
  --output-json "${TMP_DIR}/overclaim.json"; then
  echo "expected Windows broad capture overclaim to block" >&2
  exit 1
fi
grep -q 'windows_reach:broad_capture_overclaim_detected' "${TMP_DIR}/overclaim.json"

cat >"${TMP_DIR}/windows-pass.json" <<'JSON'
{
  "socks_client_baseline_pass": true,
  "service_baseline_pass": true,
  "controlled_wfp_tcp_path_pass": true,
  "dynamic_original_destination_pass": true,
  "controlled_process_capture_pass": true,
  "controlled_browser_capture_pass": true,
  "broad_capture_claimed": false,
  "dns_policy_proven": true,
  "udp_policy_proven": true,
  "ipv6_policy_proven": true,
  "service_persistence_proven": true,
  "service_reboot_pass": false,
  "service_reboot_status": "BLOCKED_BY_MANUAL_REBOOT_REQUIRED",
  "dns_udp_next_scope_status": "UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER",
  "dns_capture_claimed": false,
  "udp_capture_claimed": false,
  "ipv6_capture_claimed": false,
  "rollback_matrix_proven": true
}
JSON

cat >"${TMP_DIR}/macos-pass.json" <<'JSON'
{
  "pf_apply_cleanup_evidence": true,
  "foreground_socks_supported": true,
  "launchdaemon_socks_supported": true,
  "utun_w0_lab_pass": true,
  "utun_w4_policy_cleanup_pass": true,
  "utun_w5_controlled_external_relay_path_pass": true,
  "network_extension_system_wide_proven": true,
  "pf_system_wide_capture_claimed": false
}
JSON

cat >"${TMP_DIR}/android-pass.json" <<'JSON'
{
  "rust_jni_core_compiles": true,
  "vpnservice_basic_flow_proven": true,
  "production_android_claimed": false
}
JSON

bash "${ROOT}/scripts/build-phase-d-reach-gate.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c-ready.json" \
  --windows-reach-json "${TMP_DIR}/windows-pass.json" \
  --macos-reach-json "${TMP_DIR}/macos-pass.json" \
  --android-reach-json "${TMP_DIR}/android-pass.json" \
  --output-json "${TMP_DIR}/ready.json"

grep -q '"status": "PHASE_D_EXIT_READY"' "${TMP_DIR}/ready.json"
grep -q '"phase_d_exit_status": "EXIT_READY"' "${TMP_DIR}/ready.json"
grep -q '"dns_udp_next_scope_status": "UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER"' "${TMP_DIR}/ready.json"
grep -q '"service_reboot_pass": false' "${TMP_DIR}/ready.json"

echo "ok"
