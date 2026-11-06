#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Historical evidence lives outside Git (docs/operations/evidence-archive.md).
EVIDENCE_ROOT="${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}"
OUT_DIR="${1:-${EVIDENCE_ROOT}/live/2026-05-03/macos-utun-w2-tcp-flow-adapter-proof-lab}"
AEGIS_USER="${AEGIS_USER:-aegis}"
source "${ROOT}/scripts/macos-utun-main-launch.sh"
aegis_utun_require_main_user "${AEGIS_USER}"
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
CONTROLLED_PEER="${AEGIS_UTUN_CONTROLLED_PEER:-198.18.0.2}"
CONTROLLED_LOCAL="${AEGIS_UTUN_CONTROLLED_LOCAL:-198.18.0.1}"
CONTROLLED_PORT="${AEGIS_UTUN_CONTROLLED_TCP_PORT:-443}"
USER_TMP="${AEGIS_UTUN_USER_TMP:-/tmp/aegis-macos-utun-w2/${AEGIS_USER}/tmp}"
USER_STATE="${AEGIS_UTUN_USER_STATE:-/tmp/aegis-macos-utun-w2/${AEGIS_USER}/state}"
SOCKET_PATH="${USER_TMP}/aegis-utun-w2.sock"
USER_EVENTS_MAIN="${USER_STATE}/runtime-events-main.jsonl"
USER_EVENTS_HELPER="${USER_STATE}/runtime-events-helper.jsonl"
USER_PACKET_RESULT="${USER_STATE}/packet-flow-result.json"
USER_ROUTE_PROOF="${USER_STATE}/route-proof.json"
RUN_BINARY="${AEGIS_MACOS_UTUN_HELPER:-/usr/local/sbin/aegis-macos-utun-lab-w0}"

run_aegis_measure() {
  if [[ -x "${AEGIS_MEASURE_BIN:-}" ]]; then
    "${AEGIS_MEASURE_BIN}" "$@"
  elif [[ -x "${ROOT}/target/debug/aegis-measure" ]] &&
    "${ROOT}/target/debug/aegis-measure" build-macos-utun-w2-result --help >/dev/null 2>&1
  then
    "${ROOT}/target/debug/aegis-measure" "$@"
  else
    cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- "$@"
  fi
}

write_blocked_result() {
  local status="$1"
  local blocker="$2"
  run_aegis_measure build-macos-utun-blocked-result \
    --artifact macos-utun-w2-tcp-flow-adapter-proof-lab \
    --status "${status}" \
    --blocker "${blocker}" \
    --output-json "${OUT_DIR}/result.json"
}

mkdir -p "${OUT_DIR}"

{
  printf 'artifact=%s\n' "${OUT_DIR}"
  printf 'aegis_user=%s\n' "${AEGIS_USER}"
  printf 'relay_ip=%s\n' "${RELAY_IP}"
  printf 'controlled_local=%s\n' "${CONTROLLED_LOCAL}"
  printf 'controlled_peer=%s\n' "${CONTROLLED_PEER}"
  printf 'controlled_tcp_port=%s\n' "${CONTROLLED_PORT}"
  printf 'socket_path=%s\n' "${SOCKET_PATH}"
} >"${OUT_DIR}/environment.txt"

if [[ ! -x "${RUN_BINARY}" ]]; then
  write_blocked_result "BLOCKED_BY_HELPER_BINARY_MISSING" "helper binary is not executable"
  exit 0
fi

(
  cd /
  sudo -n -H -u "${AEGIS_USER}" /bin/bash -lc \
    "mkdir -p '${USER_TMP}' '${USER_STATE}' && rm -f '${SOCKET_PATH}' '${USER_EVENTS_MAIN}' '${USER_EVENTS_HELPER}' '${USER_PACKET_RESULT}' '${USER_ROUTE_PROOF}'"
)

aegis_utun_start_main "${RUN_BINARY}" main \
    --socket "${SOCKET_PATH}" \
    --runtime-events-jsonl "${USER_EVENTS_MAIN}" \
    --result-json "${USER_PACKET_RESULT}" \
    --expected-protocol tcp \
    --expected-dst-port "${CONTROLLED_PORT}" \
    --packet-timeout-ms 7000 \
  >"${OUT_DIR}/main.stdout.log" \
  2>"${OUT_DIR}/main.stderr.log"
MAIN_PID="${AEGIS_UTUN_MAIN_PID}"

sleep 1

set +e
sudo -n "${RUN_BINARY}" helper \
  --main-uid "${AEGIS_UTUN_MAIN_UID}" --main-pid "${MAIN_PID}" \
  --socket "${SOCKET_PATH}" \
  --runtime-events-jsonl "${USER_EVENTS_HELPER}" \
  --route-proof-json "${USER_ROUTE_PROOF}" \
  --probe tcp \
  --controlled-peer "${CONTROLLED_PEER}" \
  --controlled-local "${CONTROLLED_LOCAL}" \
  --relay-ip "${RELAY_IP}" \
  >"${OUT_DIR}/helper.stdout.log" \
  2>"${OUT_DIR}/helper.stderr.log"
HELPER_STATUS="$?"
wait "${MAIN_PID}"
MAIN_STATUS="$?"
set -e

{
  printf '%s\n' 'Selected launch arguments; not a complete replay script. Main runs as the preflight-checked non-root caller.'
  printf '%s\n' "exec ${RUN_BINARY} main --socket ${SOCKET_PATH} --runtime-events-jsonl ${USER_EVENTS_MAIN} --result-json ${USER_PACKET_RESULT} --expected-protocol tcp --expected-dst-port ${CONTROLLED_PORT}"
  printf '%s\n' "sudo -n ${RUN_BINARY} helper --main-uid ${AEGIS_UTUN_MAIN_UID} --main-pid ${MAIN_PID} --socket ${SOCKET_PATH} --runtime-events-jsonl ${USER_EVENTS_HELPER} --route-proof-json ${USER_ROUTE_PROOF} --probe tcp --controlled-peer ${CONTROLLED_PEER} --controlled-local ${CONTROLLED_LOCAL} --relay-ip ${RELAY_IP}"
} >"${OUT_DIR}/commands.txt"

{
  cat "${USER_EVENTS_HELPER}" 2>/dev/null || true
  cat "${USER_EVENTS_MAIN}" 2>/dev/null || true
} >"${OUT_DIR}/runtime-events.jsonl"
cat "${USER_PACKET_RESULT}" >"${OUT_DIR}/packet-flow-result.json" 2>"${OUT_DIR}/packet-flow-result.copy.stderr.log" || true
cat "${USER_ROUTE_PROOF}" >"${OUT_DIR}/route-proof.json" 2>"${OUT_DIR}/route-proof.copy.stderr.log" || true

PACKET_PASS=false
ROUTE_PASS=false
TCP_FLOW_OBSERVED=false
TCP_DST_PORT_MATCH=false
grep -q '"verdict": "PASS"' "${OUT_DIR}/packet-flow-result.json" 2>/dev/null && PACKET_PASS=true
grep -q '"verdict": "PASS"' "${OUT_DIR}/route-proof.json" 2>/dev/null && ROUTE_PASS=true
grep -Eq '"protocol"[[:space:]]*:[[:space:]]*6' "${OUT_DIR}/packet-flow-result.json" 2>/dev/null && TCP_FLOW_OBSERVED=true
grep -Eq "\"destination_port\"[[:space:]]*:[[:space:]]*${CONTROLLED_PORT}" "${OUT_DIR}/packet-flow-result.json" 2>/dev/null && TCP_DST_PORT_MATCH=true

if [[ "${HELPER_STATUS}" == "0" && "${MAIN_STATUS}" == "0" && "${PACKET_PASS}" == "true" && "${ROUTE_PASS}" == "true" && "${TCP_FLOW_OBSERVED}" == "true" && "${TCP_DST_PORT_MATCH}" == "true" ]]; then
  STATUS="PASS"
  VERDICT="PASS"
else
  STATUS="NOT_PASS"
  VERDICT="NOT_PASS"
fi

run_aegis_measure build-macos-utun-w2-result \
  --artifact macos-utun-w2-tcp-flow-adapter-proof-lab \
  --status "${STATUS}" \
  --verdict "${VERDICT}" \
  --helper-exit "${HELPER_STATUS}" \
  --main-exit "${MAIN_STATUS}" \
  --packet-loop-pass "${PACKET_PASS}" \
  --route-proof-pass "${ROUTE_PASS}" \
  --tcp-flow-observed "${TCP_FLOW_OBSERVED}" \
  --tcp-destination-port-match "${TCP_DST_PORT_MATCH}" \
  --controlled-peer "${CONTROLLED_PEER}" \
  --controlled-tcp-port "${CONTROLLED_PORT}" \
  --packet-to-flow-adapter LAB_TCP_IPV4_HEADER_PARSE_ONLY \
  --output-json "${OUT_DIR}/result.json"

{
  printf '# macOS utun W2 TCP Flow Adapter Proof Lab\n\n'
  printf 'Verdict: `%s`.\n\n' "${VERDICT}"
  printf -- '- TCP flow observed: `%s`\n' "${TCP_FLOW_OBSERVED}"
  printf -- '- TCP destination port match: `%s`\n' "${TCP_DST_PORT_MATCH}"
  printf -- '- packet-to-flow adapter: `LAB_TCP_IPV4_HEADER_PARSE_ONLY`\n'
  printf -- '- relay session claim: `false`\n'
  printf -- '- broad system-wide claim: `false`\n'
} >"${OUT_DIR}/README.md"
