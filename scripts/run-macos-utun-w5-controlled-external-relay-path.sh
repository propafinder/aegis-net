#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Historical evidence lives outside Git (docs/operations/evidence-archive.md).
EVIDENCE_ROOT="${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}"
OUT_DIR="${1:-${EVIDENCE_ROOT}/live/2026-05-03/macos-utun-w5-controlled-external-relay-path-lab}"

CONTROLLED_EXTERNAL_TARGET_IP="${AEGIS_UTUN_W5_CONTROLLED_EXTERNAL_TARGET_IP:-1.1.1.1}"
# Operator relay route reference; existing native route-exclusion checks remain authoritative.
RELAY_IP="${AEGIS_RELAY_IP:-}"

relay_ip_ready() {
  local value="$1" octet
  local -a octets
  [[ "${#value}" -le 15 && "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a octets <<<"$value"
  [[ "${#octets[@]}" -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}
if ! relay_ip_ready "$RELAY_IP"; then
  printf '%s\n' 'AEGIS_RELAY_IP must be an explicit canonical IPv4 address' >&2
  exit 2
fi
ROUTE_ARTIFACT="${AEGIS_UTUN_W5_ROUTE_ARTIFACT:-${OUT_DIR}/controlled-external-route-proof}"
W4_ARTIFACT="${AEGIS_UTUN_W4_ARTIFACT:-${EVIDENCE_ROOT}/live/2026-05-03/macos-utun-w4-policy-cleanup-matrix-lab}"
PHASE_C_ARTIFACT="${AEGIS_PHASE_C_HTTPS_WS_ARTIFACT:-${EVIDENCE_ROOT}/live/2026-05-03/phase-c-cloudflare-https-ws-fronted-live}"
USE_EXISTING_ROUTE_ARTIFACT="${AEGIS_UTUN_W5_USE_EXISTING_ROUTE_ARTIFACT:-false}"

mkdir -p "${OUT_DIR}"

RESULT_JSON="${OUT_DIR}/result.json"
RUNTIME_EVENTS_JSONL="${OUT_DIR}/runtime-events.jsonl"
ROUTE_RESULT="${ROUTE_ARTIFACT}/result.json"
ROUTE_PROOF="${ROUTE_ARTIFACT}/route-proof.json"
PHASE_C_RESULT="${PHASE_C_ARTIFACT}/result.json"
PHASE_C_RUNTIME="${PHASE_C_ARTIFACT}/runtime-events.jsonl"
W4_RESULT="${W4_ARTIFACT}/result.json"

has_json() {
  local file="$1"
  local pattern="$2"
  [[ -f "${file}" ]] && grep -Eq "${pattern}" "${file}"
}

json_bool() {
  if [[ "$1" == "true" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

json_string_or_null() {
  local value="$1"
  if [[ -n "${value}" ]]; then
    printf '"%s"' "${value//\"/\\\"}"
  else
    printf 'null'
  fi
}

if [[ "${USE_EXISTING_ROUTE_ARTIFACT}" != "true" ]]; then
  AEGIS_UTUN_CONTROLLED_PEER="${CONTROLLED_EXTERNAL_TARGET_IP}" \
    AEGIS_RELAY_IP="${RELAY_IP}" \
    bash "${ROOT}/scripts/run-macos-utun-w1-controlled-route-proof.sh" "${ROUTE_ARTIFACT}"
fi

baseline_direct_route_recorded=false
aegis_owned_32_route_added=false
relay_ip_exclusion_recorded=false
packet_loop_observed=false
cleanup_only_aegis_owned_state=false
baseline_route_restored=false
default_route_untouched=false
w4_cleanup_policy_pass=false

relay_session_succeeded=false
selected_transport=""
external_egress_proof_collected=false
external_egress_detail=""
cloudflare_tls_status="UNKNOWN"
phase_c_provider_boundary_recorded=false

if has_json "${ROUTE_PROOF}" '"routes_before"[[:space:]]*:[[:space:]]*"Routing tables'; then
  baseline_direct_route_recorded=true
fi
if has_json "${ROUTE_RESULT}" '"controlled_route_prefix"[[:space:]]*:[[:space:]]*"/32"' \
  && has_json "${ROUTE_PROOF}" '"controlled_route_present"[[:space:]]*:[[:space:]]*true'; then
  aegis_owned_32_route_added=true
fi
if has_json "${ROUTE_RESULT}" '"relay_ip_excluded_from_utun"[[:space:]]*:[[:space:]]*true' \
  && has_json "${ROUTE_PROOF}" '"relay_ip_excluded_from_utun"[[:space:]]*:[[:space:]]*true'; then
  relay_ip_exclusion_recorded=true
fi
if has_json "${ROUTE_RESULT}" '"packet_loop_pass"[[:space:]]*:[[:space:]]*true' \
  && has_json "${ROUTE_ARTIFACT}/runtime-events.jsonl" '"event_code"[[:space:]]*:[[:space:]]*"macos_utun_packet_observed"'; then
  packet_loop_observed=true
fi
if has_json "${ROUTE_PROOF}" '"controlled_route_removed_after_cleanup"[[:space:]]*:[[:space:]]*true'; then
  cleanup_only_aegis_owned_state=true
  baseline_route_restored=true
fi
if has_json "${ROUTE_RESULT}" '"default_route_claim"[[:space:]]*:[[:space:]]*false' \
  && has_json "${ROUTE_PROOF}" '"default_route_claim"[[:space:]]*:[[:space:]]*false'; then
  default_route_untouched=true
fi
if has_json "${W4_RESULT}" '"artifact"[[:space:]]*:[[:space:]]*"macos-utun-w4-policy-cleanup-matrix-lab"' \
  && has_json "${W4_RESULT}" '"verdict"[[:space:]]*:[[:space:]]*"PASS"' \
  && has_json "${W4_RESULT}" '"cleanup_only_aegis_owned_state"[[:space:]]*:[[:space:]]*true' \
  && has_json "${W4_RESULT}" '"cleanup_restores_baseline_route_state"[[:space:]]*:[[:space:]]*true'; then
  w4_cleanup_policy_pass=true
fi

if has_json "${PHASE_C_RESULT}" '"aegis_relay_session_status"[[:space:]]*:[[:space:]]*"PASS"' \
  && has_json "${PHASE_C_RUNTIME}" '"event_code"[[:space:]]*:[[:space:]]*"relay_session_succeeded"'; then
  relay_session_succeeded=true
fi
if has_json "${PHASE_C_RESULT}" '"selected_transport"[[:space:]]*:[[:space:]]*"HttpsWs"'; then
  selected_transport="HttpsWs"
fi
if has_json "${PHASE_C_RESULT}" '"socks_egress_status"[[:space:]]*:[[:space:]]*"PASS"' \
  || has_json "${PHASE_C_RESULT}" '"socks_egress_detail"[[:space:]]*:[[:space:]]*"[^"]+"'; then
  external_egress_proof_collected=true
  external_egress_detail="$(sed -n 's/.*"socks_egress_detail"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${PHASE_C_RESULT}" | head -n 1)"
fi
if has_json "${PHASE_C_RESULT}" '"cloudflare_tls_status"[[:space:]]*:[[:space:]]*"[^"]+"'; then
  cloudflare_tls_status="$(sed -n 's/.*"cloudflare_tls_status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${PHASE_C_RESULT}" | head -n 1)"
fi
if has_json "${PHASE_C_RESULT}" '"provider_type"[[:space:]]*:[[:space:]]*"cloudflare_http_proxy"' \
  && has_json "${PHASE_C_RESULT}" '"front_authority"[[:space:]]*:[[:space:]]*"example.com"'; then
  phase_c_provider_boundary_recorded=true
fi

status="PASS"
verdict="PASS"
failure_classification="null"
blocker="null"
external_relay_path_event=false

if [[ "${aegis_owned_32_route_added}" != "true" || "${baseline_direct_route_recorded}" != "true" ]]; then
  status="ROUTE_SETUP_FAILED"
  verdict="NOT_PASS"
  failure_classification='"ROUTE_SETUP_FAILED"'
  blocker='"controlled external /32 route proof did not record baseline route and route add"'
elif [[ "${relay_ip_exclusion_recorded}" != "true" ]]; then
  status="RELAY_IP_EXCLUSION_FAILED"
  verdict="NOT_PASS"
  failure_classification='"RELAY_IP_EXCLUSION_FAILED"'
  blocker='"relay IP exclusion was not recorded while adding the controlled external route"'
elif [[ "${packet_loop_observed}" != "true" ]]; then
  status="PACKET_NOT_OBSERVED"
  verdict="NOT_PASS"
  failure_classification='"PACKET_NOT_OBSERVED"'
  blocker='"utun packet loop did not observe the controlled external target packet"'
elif [[ "${relay_session_succeeded}" != "true" || "${selected_transport}" != "HttpsWs" || "${phase_c_provider_boundary_recorded}" != "true" || "${external_egress_proof_collected}" != "true" ]]; then
  status="RELAY_SESSION_FAILED"
  verdict="NOT_PASS"
  failure_classification='"RELAY_SESSION_FAILED"'
  blocker='"external AEGIS relay path over HttpsWs did not have usable Phase C relay and egress evidence"'
elif [[ "${cleanup_only_aegis_owned_state}" != "true" || "${baseline_route_restored}" != "true" || "${default_route_untouched}" != "true" || "${w4_cleanup_policy_pass}" != "true" ]]; then
  status="CLEANUP_FAILED"
  verdict="NOT_PASS"
  failure_classification='"CLEANUP_FAILED"'
  blocker='"cleanup did not prove AEGIS-owned route removal, baseline restore, default-route boundary, and W4 policy cleanup"'
else
  external_relay_path_event=true
fi

now_ms="$(date +%s000)"
{
  cat "${ROUTE_ARTIFACT}/runtime-events.jsonl" 2>/dev/null || true
  cat "${PHASE_C_RUNTIME}" 2>/dev/null || true
  if [[ "${external_relay_path_event}" == "true" ]]; then
    cat <<JSONL
{"timestamp_unix_ms":${now_ms},"level":"info","event_code":"macos_utun_external_relay_path_succeeded","fields":{"scope":"lab_controlled_utun_w5","controlled_external_target_ip":"${CONTROLLED_EXTERNAL_TARGET_IP}","controlled_route_prefix":"/32","relay_ip":"${RELAY_IP}","relay_ip_excluded_from_utun":true,"selected_transport":"HttpsWs","provider_boundary":"cloudflare_http_proxy","default_route_claim":false,"broad_system_wide_claim":false,"dns_claimed":false,"udp_claimed":false,"ipv6_claimed":false,"network_extension_claimed":false}}
JSONL
  fi
} >"${RUNTIME_EVENTS_JSONL}"

cat >"${OUT_DIR}/route-baseline.txt" <<TXT
controlled_external_target_ip=${CONTROLLED_EXTERNAL_TARGET_IP}
relay_ip=${RELAY_IP}
route_artifact=${ROUTE_ARTIFACT}
baseline_direct_route_recorded=${baseline_direct_route_recorded}
aegis_owned_32_route_added=${aegis_owned_32_route_added}
baseline_route_restored=${baseline_route_restored}
default_route_untouched=${default_route_untouched}
TXT

cat >"${OUT_DIR}/relay-proof.txt" <<TXT
phase_c_artifact=${PHASE_C_ARTIFACT}
selected_transport=${selected_transport:-NOT_PROVEN}
relay_session_succeeded=${relay_session_succeeded}
external_egress_proof_collected=${external_egress_proof_collected}
external_egress_detail=${external_egress_detail:-NOT_RECORDED}
cloudflare_tls_status=${cloudflare_tls_status}
TXT

cat >"${RESULT_JSON}" <<JSON
{
  "schema_version": 1,
  "artifact": "macos-utun-w5-controlled-external-relay-path-lab",
  "status": "${status}",
  "verdict": "${verdict}",
  "scope": "LAB_CONTROLLED_EXTERNAL_IPV4_32_ROUTE_PLUS_HTTPS_WS_RELAY_PATH",
  "controlled_external_target_ip": "${CONTROLLED_EXTERNAL_TARGET_IP}",
  "controlled_route_prefix": "/32",
  "baseline_direct_route_recorded": $(json_bool "${baseline_direct_route_recorded}"),
  "relay_ip": "${RELAY_IP}",
  "relay_ip_exclusion_recorded": $(json_bool "${relay_ip_exclusion_recorded}"),
  "aegis_owned_32_route_added": $(json_bool "${aegis_owned_32_route_added}"),
  "packet_loop_observed": $(json_bool "${packet_loop_observed}"),
  "relay_session_succeeded": $(json_bool "${relay_session_succeeded}"),
  "selected_transport": $(json_string_or_null "${selected_transport}"),
  "external_egress_proof_collected": $(json_bool "${external_egress_proof_collected}"),
  "external_egress_detail": $(json_string_or_null "${external_egress_detail}"),
  "cloudflare_tls_status": "${cloudflare_tls_status}",
  "phase_c_provider_boundary_recorded": $(json_bool "${phase_c_provider_boundary_recorded}"),
  "macos_utun_external_relay_path_succeeded_event": $(json_bool "${external_relay_path_event}"),
  "cleanup_only_aegis_owned_state": $(json_bool "${cleanup_only_aegis_owned_state}"),
  "w4_cleanup_policy_pass": $(json_bool "${w4_cleanup_policy_pass}"),
  "baseline_route_restored": $(json_bool "${baseline_route_restored}"),
  "default_route_untouched": $(json_bool "${default_route_untouched}"),
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "dns_claimed": false,
  "udp_claimed": false,
  "ipv6_claimed": false,
  "network_extension_claimed": false,
  "product_ready_claim": false,
  "failure_classification": ${failure_classification},
  "blocker": ${blocker},
  "artifacts": {
    "controlled_external_route": "${ROUTE_ARTIFACT}",
    "w4_policy_cleanup_matrix": "${W4_ARTIFACT}",
    "phase_c_https_ws_fronted_live": "${PHASE_C_ARTIFACT}"
  }
}
JSON

cat >"${OUT_DIR}/commands.txt" <<TXT
AEGIS_UTUN_W5_CONTROLLED_EXTERNAL_TARGET_IP="${CONTROLLED_EXTERNAL_TARGET_IP}" AEGIS_RELAY_IP="${RELAY_IP}" bash scripts/run-macos-utun-w5-controlled-external-relay-path.sh "${OUT_DIR}"
TXT

cat >"${OUT_DIR}/environment.txt" <<TXT
date_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
host=$(hostname)
artifact=${OUT_DIR}
controlled_external_target_ip=${CONTROLLED_EXTERNAL_TARGET_IP}
relay_ip=${RELAY_IP}
route_artifact=${ROUTE_ARTIFACT}
w4_artifact=${W4_ARTIFACT}
phase_c_artifact=${PHASE_C_ARTIFACT}
TXT

cat >"${OUT_DIR}/README.md" <<MD
# macOS utun W5 Controlled External Relay Path Lab

Verdict: \`${verdict}\`

This artifact is LAB / EXPERIMENTAL. It proves a controlled external IPv4
\`/32\` route through the macOS utun packet loop, relay IP exclusion, and an
external AEGIS relay session over the existing Cloudflare \`https_ws\` boundary.

It does not claim NetworkExtension replacement, product-ready macOS wide,
broad system-wide capture, default-route capture, DNS capture, UDP capture, or
IPv6 capture.
MD

if [[ "${verdict}" == "PASS" ]]; then
  exit 0
fi
exit 1
