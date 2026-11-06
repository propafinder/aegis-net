#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-d-macos.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/pf" "${TMP_DIR}/foreground" "${TMP_DIR}/launchdaemon" "${TMP_DIR}/w4" "${TMP_DIR}/w5" "${TMP_DIR}/ne"
cat >"${TMP_DIR}/pf/result.json" <<'JSON'
{
  "verdict": "PASS",
  "live_claim": "PF_RULE_APPLY_AND_CLEANUP_ONLY",
  "runtime_traffic_proof": false,
  "apply": {
    "command_result": "PASS",
    "system_wide_enabled": true
  },
  "cleanup": {
    "result": "PASS",
    "aegis_rules_gone": true
  }
}
JSON
cat >"${TMP_DIR}/foreground/result.json" <<'JSON'
{
  "verdict": "PASS",
  "socks_public_ipv4": "198.51.100.22",
  "socks_expected_ipv4": "198.51.100.22",
  "runtime_events_jsonl_valid": true
}
JSON
cat >"${TMP_DIR}/launchdaemon/result.json" <<'JSON'
{
  "verdict": "PASS",
  "socks_public_ipv4": "198.51.100.22",
  "socks_expected_ipv4": "198.51.100.22",
  "runtime_events_jsonl_valid": true
}
JSON
cat >"${TMP_DIR}/w4/result.json" <<'JSON'
{
  "artifact": "macos-utun-w4-policy-cleanup-matrix-lab",
  "verdict": "PASS",
  "tcp_ipv4_controlled_route_relay_bridge_pass": true,
  "dns_policy": "OUT_OF_SCOPE",
  "udp_policy": "OUT_OF_SCOPE",
  "ipv6_policy": "OUT_OF_SCOPE",
  "policy_matrix_explicit": true,
  "relay_ip_exclusion_verified": true,
  "default_route_changed": false,
  "cleanup_only_aegis_owned_state": true,
  "cleanup_restores_baseline_route_state": true,
  "cleanup_after_simulated_helper_client_stop_verified": true,
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "dns_claimed": false,
  "udp_claimed": false,
  "ipv6_claimed": false,
  "network_extension_claimed": false,
  "product_ready_claim": false
}
JSON
cat >"${TMP_DIR}/w5/result.json" <<'JSON'
{
  "artifact": "macos-utun-w5-controlled-external-relay-path-lab",
  "verdict": "PASS",
  "scope": "LAB_CONTROLLED_EXTERNAL_IPV4_32_ROUTE_PLUS_HTTPS_WS_RELAY_PATH",
  "controlled_route_prefix": "/32",
  "baseline_direct_route_recorded": true,
  "relay_ip_exclusion_recorded": true,
  "aegis_owned_32_route_added": true,
  "packet_loop_observed": true,
  "relay_session_succeeded": true,
  "selected_transport": "HttpsWs",
  "external_egress_proof_collected": true,
  "phase_c_provider_boundary_recorded": true,
  "macos_utun_external_relay_path_succeeded_event": true,
  "cleanup_only_aegis_owned_state": true,
  "w4_cleanup_policy_pass": true,
  "baseline_route_restored": true,
  "default_route_untouched": true,
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "dns_claimed": false,
  "udp_claimed": false,
  "ipv6_claimed": false,
  "network_extension_claimed": false,
  "product_ready_claim": false
}
JSON
cat >"${TMP_DIR}/ne/result.json" <<'JSON'
{
  "verdict": "BLOCKED_BY_SIGNING",
  "feasible_now": false,
  "networkextension_sdk": {
    "framework_in_xcode_sdk": true,
    "packet_tunnel_provider_typecheck": "PASS"
  }
}
JSON

if bash "${ROOT}/scripts/build-phase-d-macos-reach-evidence.sh" \
  --pf-artifact "${TMP_DIR}/pf" \
  --foreground-socks-artifact "${TMP_DIR}/foreground" \
  --launchdaemon-socks-artifact "${TMP_DIR}/launchdaemon" \
  --utun-w4-artifact "${TMP_DIR}/w4" \
  --utun-w5-artifact "${TMP_DIR}/w5" \
  --network-extension-artifact "${TMP_DIR}/ne" \
  --output-json "${TMP_DIR}/macos.json" \
  --output-markdown "${TMP_DIR}/macos.md"; then
  echo "expected NetworkExtension signing blocker to keep evidence command non-zero" >&2
  exit 1
fi
grep -q '"pf_apply_cleanup_evidence": true' "${TMP_DIR}/macos.json"
grep -q '"foreground_socks_supported": true' "${TMP_DIR}/macos.json"
grep -q '"launchdaemon_socks_supported": true' "${TMP_DIR}/macos.json"
grep -q '"utun_w4_policy_cleanup_pass": true' "${TMP_DIR}/macos.json"
grep -q '"utun_w5_controlled_external_relay_path_pass": true' "${TMP_DIR}/macos.json"
grep -q '"network_extension_sdk_ready": true' "${TMP_DIR}/macos.json"
grep -q '"network_extension_system_wide_proven": false' "${TMP_DIR}/macos.json"
grep -q 'Phase D macOS Reach Evidence' "${TMP_DIR}/macos.md"

cat >"${TMP_DIR}/ne/result.json" <<'JSON'
{
  "verdict": "PASS",
  "network_extension_system_wide_proven": true,
  "packet_tunnel_runtime_proven": true,
  "networkextension_sdk": {
    "framework_in_xcode_sdk": true,
    "packet_tunnel_provider_typecheck": "PASS"
  }
}
JSON

if bash "${ROOT}/scripts/build-phase-d-macos-reach-evidence.sh" \
  --pf-artifact "${TMP_DIR}/pf" \
  --foreground-socks-artifact "${TMP_DIR}/foreground" \
  --launchdaemon-socks-artifact "${TMP_DIR}/launchdaemon" \
  --utun-w4-artifact "${TMP_DIR}/w4" \
  --utun-w5-artifact "${TMP_DIR}/w5" \
  --network-extension-artifact "${TMP_DIR}/ne" \
  --output-json "${TMP_DIR}/macos-weak-ne.json"; then
  echo "expected weak NetworkExtension PASS flags to fail without signed runtime proof fields" >&2
  exit 1
fi
grep -q '"network_extension_system_wide_proven": false' "${TMP_DIR}/macos-weak-ne.json"

cat >"${TMP_DIR}/ne/result.json" <<'JSON'
{
  "verdict": "PASS",
  "feature": "macos_networkextension_system_wide_proof",
  "platform": "macOS",
  "scope": "networkextension_packet_tunnel_ipv4_tcp",
  "network_extension_system_wide_proven": true,
  "packet_tunnel_runtime_proven": true,
  "signed_app_and_extension": true,
  "network_extension_entitlement_present": true,
  "vpn_configuration_approved": true,
  "no_manual_proxy_used": true,
  "relay_session_succeeded": true,
  "cleanup_restored_direct_path": true,
  "pf_system_wide_capture_claimed": false,
  "networkextension_sdk": {
    "framework_in_xcode_sdk": true,
    "packet_tunnel_provider_typecheck": "PASS"
  }
}
JSON

bash "${ROOT}/scripts/build-phase-d-macos-reach-evidence.sh" \
  --pf-artifact "${TMP_DIR}/pf" \
  --foreground-socks-artifact "${TMP_DIR}/foreground" \
  --launchdaemon-socks-artifact "${TMP_DIR}/launchdaemon" \
  --utun-w4-artifact "${TMP_DIR}/w4" \
  --utun-w5-artifact "${TMP_DIR}/w5" \
  --network-extension-artifact "${TMP_DIR}/ne" \
  --output-json "${TMP_DIR}/macos-pass.json"

grep -q '"network_extension_system_wide_proven": true' "${TMP_DIR}/macos-pass.json"

if bash "${ROOT}/scripts/build-phase-d-macos-reach-evidence.sh" \
  --pf-artifact "${TMP_DIR}/pf" \
  --foreground-socks-artifact "${TMP_DIR}/foreground" \
  --launchdaemon-socks-artifact "${TMP_DIR}/launchdaemon" \
  --utun-w4-artifact "${TMP_DIR}/w4" \
  --utun-w5-artifact "${TMP_DIR}/w5" \
  --network-extension-artifact "${TMP_DIR}/ne" \
  --pf-system-wide-capture-claimed \
  --output-json "${TMP_DIR}/overclaim.json"; then
  echo "expected PF system-wide capture claim to fail" >&2
  exit 1
fi
grep -q '"pf_system_wide_capture_claimed": true' "${TMP_DIR}/overclaim.json"

echo "ok"
