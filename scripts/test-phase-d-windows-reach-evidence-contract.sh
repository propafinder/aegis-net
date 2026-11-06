#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-d-windows.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/socks" "${TMP_DIR}/service" "${TMP_DIR}/wfp" "${TMP_DIR}/dynamic" \
  "${TMP_DIR}/process" "${TMP_DIR}/browser" "${TMP_DIR}/persistence" "${TMP_DIR}/reboot" \
  "${TMP_DIR}/dns-udp" "${TMP_DIR}/rollback"
cat >"${TMP_DIR}/socks/result.json" <<'JSON'
{
  "verdict": "PASS",
  "socks_listener_verified": true,
  "socks_egress_verified": true,
  "wide_claim": "not_tested"
}
JSON
cat >"${TMP_DIR}/service/result.json" <<'JSON'
{
  "verdict": "BLOCKED",
  "install_script_whatif": "PASS",
  "uninstall_script_whatif": "PASS",
  "service_started": false,
  "socks_egress_verified": false
}
JSON
cat >"${TMP_DIR}/wfp/result.json" <<'JSON'
{
  "status": "PASS",
  "scope": "controlled_tcp_ipv4",
  "flow_redirected_to_aegis": true,
  "relay_session_succeeded": true,
  "broad_capture_claim": "not_claimed"
}
JSON
cat >"${TMP_DIR}/dynamic/result.json" <<'JSON'
{
  "status": "PASS",
  "original_dst_method": "wfp_redirect_context",
  "configured_original_dst_fallback": false,
  "relay_session_succeeded": true
}
JSON
cat >"${TMP_DIR}/process/result.json" <<'JSON'
{
  "status": "PASS",
  "feature": "windows_wfp_controlled_process_capture",
  "scope": "controlled_process_tcp_ipv4",
  "process_match_method": "driver_classify_process_id",
  "original_dst_method": "wfp_redirect_context",
  "non_selected_process_direct": true,
  "relay_session_succeeded": true,
  "cleanup": "PASS",
  "broad_capture_claim": "not_claimed"
}
JSON
cat >"${TMP_DIR}/browser/result.json" <<'JSON'
{
  "status": "PASS",
  "feature": "windows_wfp_controlled_browser_capture",
  "scope": "controlled_browser_tcp_ipv4",
  "process_match_method": "wfp_ale_app_id",
  "original_dst_method": "wfp_redirect_context",
  "non_selected_process_direct": true,
  "relay_session_succeeded": true,
  "cleanup": "PASS",
  "broad_capture_claim": "not_claimed"
}
JSON

if bash "${ROOT}/scripts/build-phase-d-windows-reach-evidence.sh" \
  --socks-client-artifact "${TMP_DIR}/socks" \
  --service-artifact "${TMP_DIR}/service" \
  --controlled-wfp-artifact "${TMP_DIR}/wfp" \
  --dynamic-original-dst-artifact "${TMP_DIR}/dynamic" \
  --controlled-process-artifact "${TMP_DIR}/process" \
  --controlled-browser-artifact "${TMP_DIR}/browser" \
  --output-json "${TMP_DIR}/windows.json" \
  --output-markdown "${TMP_DIR}/windows.md"; then
  echo "expected blocked service baseline to keep evidence command non-zero" >&2
  exit 1
fi
grep -q '"socks_client_baseline_pass": true' "${TMP_DIR}/windows.json"
grep -q '"service_baseline_pass": false' "${TMP_DIR}/windows.json"
grep -q '"service_admin_ready": false' "${TMP_DIR}/windows.json"
grep -q '"service_whatif_pass": true' "${TMP_DIR}/windows.json"
grep -q '"controlled_wfp_tcp_path_pass": true' "${TMP_DIR}/windows.json"
grep -q '"dynamic_original_destination_pass": true' "${TMP_DIR}/windows.json"
grep -q '"controlled_process_capture_pass": true' "${TMP_DIR}/windows.json"
grep -q '"controlled_browser_capture_pass": true' "${TMP_DIR}/windows.json"
grep -q 'Phase D Windows Reach Evidence' "${TMP_DIR}/windows.md"

cat >"${TMP_DIR}/service/result.json" <<'JSON'
{
  "verdict": "PASS",
  "install_script_whatif": "PASS",
  "uninstall_script_whatif": "PASS",
  "administrator_shell": true,
  "service_installed": true,
  "service_started": true,
  "socks_listener_verified": true,
  "socks_egress_verified": true
}
JSON
cat >"${TMP_DIR}/dns.json" <<'JSON'
{
  "status": "PASS",
  "feature": "windows_dns_policy_proof",
  "dns_policy": "explicit_out_of_scope_no_capture",
  "capture_dns": false,
  "wfp_dns_or_udp_filter_installed": false,
  "dns_resolve_succeeded": true,
  "runtime_dns_events_seen": false,
  "cleanup": "PASS",
  "broad_capture_claim": "not_claimed"
}
JSON
cat >"${TMP_DIR}/weak-dns.json" <<'JSON'
{"status":"PASS"}
JSON
cat >"${TMP_DIR}/udp.json" <<'JSON'
{
  "status": "PASS",
  "feature": "windows_udp_policy_proof",
  "udp_policy": "explicit_out_of_scope_no_capture",
  "udp_capture": false,
  "wfp_udp_filter_installed": false,
  "udp_probe_succeeded": true,
  "runtime_udp_events_seen": false,
  "cleanup": "PASS",
  "broad_capture_claim": "not_claimed"
}
JSON
cat >"${TMP_DIR}/ipv6.json" <<'JSON'
{
  "status": "PASS",
  "feature": "windows_ipv6_policy_proof",
  "ipv6_policy": "explicit_not_supported_no_capture",
  "ipv6_capture": false,
  "wfp_ipv6_filter_installed": false,
  "ipv6_probe_succeeded": true,
  "runtime_ipv6_events_seen": false,
  "cleanup": "PASS",
  "broad_capture_claim": "not_claimed"
}
JSON
cat >"${TMP_DIR}/persistence/result.json" <<'JSON'
{
  "status": "PASS",
  "feature": "windows_wide_service_persistence_proof",
  "scope": "controlled_wfp_service_restart",
  "service_installed": true,
  "service_started": true,
  "service_restarted": true,
  "service_pid_changed": true,
  "wfp_reconfigured_after_restart": true,
  "cleanup": "PASS",
  "reboot_claim": "not_claimed",
  "broad_capture_claim": "not_claimed"
}
JSON
cat >"${TMP_DIR}/reboot/result.json" <<'JSON'
{
  "status": "BLOCKED_BY_MANUAL_REBOOT_REQUIRED",
  "feature": "windows_wide_service_reboot_persistence_proof",
  "scope": "controlled_wfp_service_reboot",
  "service_started_after_reboot": false,
  "runtime_events_restarted": false,
  "wfp_reconfigured_after_reboot": false,
  "controlled_tcp_wfp_proof_after_reboot": false,
  "relay_egress_after_reboot": false,
  "reboot_verified": false,
  "cleanup": "NOT_RUN",
  "broad_capture_claim": "not_claimed"
}
JSON
cat >"${TMP_DIR}/dns-udp/result.json" <<'JSON'
{
  "status": "UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER",
  "feature": "windows_wfp_controlled_dns_udp_next_scope",
  "scope": "controlled_dns_udp_only",
  "dns_udp_next_scope_status": "UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER",
  "controlled_target_only": true,
  "controlled_udp_or_dns_captured": false,
  "cleanup": "PASS",
  "dns_capture_claimed": false,
  "udp_capture_claimed": false,
  "broad_capture_claim": "not_claimed"
}
JSON
cat >"${TMP_DIR}/rollback/result.json" <<'JSON'
{
  "status": "PASS",
  "feature": "windows_wide_rollback_matrix",
  "normal_cleanup": true,
  "idempotent_cleanup": true,
  "aegis_client_crash_cleanup": true,
  "driver_service_removed": true,
  "broad_capture_claim": "not_claimed"
}
JSON

bash "${ROOT}/scripts/build-phase-d-windows-reach-evidence.sh" \
  --socks-client-artifact "${TMP_DIR}/socks" \
  --service-artifact "${TMP_DIR}/service" \
  --controlled-wfp-artifact "${TMP_DIR}/wfp" \
  --dynamic-original-dst-artifact "${TMP_DIR}/dynamic" \
  --controlled-process-artifact "${TMP_DIR}/process" \
  --controlled-browser-artifact "${TMP_DIR}/browser" \
  --dns-policy-json "${TMP_DIR}/dns.json" \
  --udp-policy-json "${TMP_DIR}/udp.json" \
  --ipv6-policy-json "${TMP_DIR}/ipv6.json" \
  --service-persistence-json "${TMP_DIR}/persistence" \
  --service-reboot-json "${TMP_DIR}/reboot" \
  --dns-udp-next-scope-json "${TMP_DIR}/dns-udp/result.json" \
  --rollback-matrix-json "${TMP_DIR}/rollback" \
  --output-json "${TMP_DIR}/windows-pass.json"

grep -q '"service_baseline_pass": true' "${TMP_DIR}/windows-pass.json"
grep -q '"service_admin_ready": true' "${TMP_DIR}/windows-pass.json"
grep -q '"dns_policy_proven": true' "${TMP_DIR}/windows-pass.json"
grep -q '"udp_policy_proven": true' "${TMP_DIR}/windows-pass.json"
grep -q '"ipv6_policy_proven": true' "${TMP_DIR}/windows-pass.json"
grep -q '"service_persistence_proven": true' "${TMP_DIR}/windows-pass.json"
grep -q '"service_reboot_pass": false' "${TMP_DIR}/windows-pass.json"
grep -q '"service_reboot_status": "BLOCKED_BY_MANUAL_REBOOT_REQUIRED"' "${TMP_DIR}/windows-pass.json"
grep -q '"dns_udp_next_scope_status": "UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER"' "${TMP_DIR}/windows-pass.json"
grep -q '"dns_capture_claimed": false' "${TMP_DIR}/windows-pass.json"
grep -q '"udp_capture_claimed": false' "${TMP_DIR}/windows-pass.json"
grep -q '"rollback_matrix_proven": true' "${TMP_DIR}/windows-pass.json"

bash "${ROOT}/scripts/build-phase-d-windows-reach-evidence.sh" \
  --socks-client-artifact "${TMP_DIR}/socks" \
  --service-artifact "${TMP_DIR}/service" \
  --controlled-wfp-artifact "${TMP_DIR}/wfp" \
  --dynamic-original-dst-artifact "${TMP_DIR}/dynamic" \
  --controlled-process-artifact "${TMP_DIR}/process" \
  --controlled-browser-artifact "${TMP_DIR}/browser" \
  --dns-policy-json "${TMP_DIR}/weak-dns.json" \
  --output-json "${TMP_DIR}/windows-weak-dns.json" || true
grep -q '"dns_policy_proven": false' "${TMP_DIR}/windows-weak-dns.json"

cat >"${TMP_DIR}/service/result.json" <<'JSON'
{
  "verdict": "PASS",
  "install_script_whatif": "PASS",
  "uninstall_script_whatif": "PASS",
  "service_started": true,
  "socks_egress_verified": true
}
JSON

if bash "${ROOT}/scripts/build-phase-d-windows-reach-evidence.sh" \
  --socks-client-artifact "${TMP_DIR}/socks" \
  --service-artifact "${TMP_DIR}/service" \
  --controlled-wfp-artifact "${TMP_DIR}/wfp" \
  --dynamic-original-dst-artifact "${TMP_DIR}/dynamic" \
  --controlled-process-artifact "${TMP_DIR}/process" \
  --controlled-browser-artifact "${TMP_DIR}/browser" \
  --output-json "${TMP_DIR}/weak-service.json"; then
  echo "expected weak service baseline without install/listener proof to fail" >&2
  exit 1
fi
grep -q '"service_baseline_pass": false' "${TMP_DIR}/weak-service.json"

cat >"${TMP_DIR}/service/result.json" <<'JSON'
{
  "verdict": "PASS",
  "install_script_whatif": "PASS",
  "uninstall_script_whatif": "PASS",
  "administrator_shell": true,
  "service_installed": true,
  "service_started": true,
  "socks_listener_verified": true,
  "socks_egress_verified": true
}
JSON

if bash "${ROOT}/scripts/build-phase-d-windows-reach-evidence.sh" \
  --socks-client-artifact "${TMP_DIR}/socks" \
  --service-artifact "${TMP_DIR}/service" \
  --controlled-wfp-artifact "${TMP_DIR}/wfp" \
  --dynamic-original-dst-artifact "${TMP_DIR}/dynamic" \
  --controlled-process-artifact "${TMP_DIR}/process" \
  --controlled-browser-artifact "${TMP_DIR}/browser" \
  --broad-capture-claimed \
  --output-json "${TMP_DIR}/overclaim.json"; then
  echo "expected broad capture claim to fail" >&2
  exit 1
fi
grep -q '"broad_capture_claimed": true' "${TMP_DIR}/overclaim.json"

echo "ok"
