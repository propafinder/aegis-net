#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Historical evidence lives outside Git (docs/operations/evidence-archive.md).
EVIDENCE_ROOT="${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}"
OUT_DIR="${1:-${EVIDENCE_ROOT}/live/2026-05-03/macos-utun-helper-fd-loop-lab}"
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
# This point-in-time selection is not immutable executable or ancestry custody.
INSTALLED_BINARY="${AEGIS_MACOS_UTUN_HELPER:-/usr/local/sbin/aegis-macos-utun-lab-w0}"
if [[ "${INSTALLED_BINARY}" != /* || ! -f "${INSTALLED_BINARY}" ||
      -L "${INSTALLED_BINARY}" || ! -x "${INSTALLED_BINARY}" ]]; then
  printf '%s\n' 'AEGIS_MACOS_UTUN_HELPER must select an absolute regular non-symlink executable' >&2
  exit 2
fi
RUN_BINARY="${INSTALLED_BINARY}"

CONTROLLED_PEER="${AEGIS_UTUN_CONTROLLED_PEER:-198.18.0.2}"
CONTROLLED_LOCAL="${AEGIS_UTUN_CONTROLLED_LOCAL:-198.18.0.1}"
USER_TMP="${AEGIS_UTUN_USER_TMP:-/tmp/aegis-macos-utun-w0/${AEGIS_USER}/tmp}"
USER_STATE="${AEGIS_UTUN_USER_STATE:-/tmp/aegis-macos-utun-w0/${AEGIS_USER}/state}"
SOCKET_PATH="${USER_TMP}/aegis-utun-w0.sock"
USER_EVENTS="${USER_STATE}/runtime-events.jsonl"
USER_EVENTS_MAIN="${USER_STATE}/runtime-events-main.jsonl"
USER_EVENTS_HELPER="${USER_STATE}/runtime-events-helper.jsonl"
USER_RESULT="${USER_STATE}/result.json"
BUILD_PROFILE="${AEGIS_MACOS_UTUN_PROFILE:-release}"
if [[ "${BUILD_PROFILE}" == "release" ]]; then
  CARGO_BUILD_ARGS=(build -p macos-utun-lab --release)
  BINARY="${ROOT}/target/release/aegis-macos-utun-lab"
else
  CARGO_BUILD_ARGS=(build -p macos-utun-lab)
  BINARY="${ROOT}/target/debug/aegis-macos-utun-lab"
fi

run_with_timeout() {
  local seconds="$1"
  shift
  "$@" &
  local pid="$!"
  (
    sleep "${seconds}"
    kill "${pid}" >/dev/null 2>&1 || true
  ) &
  local killer="$!"
  wait "${pid}"
  local status="$?"
  kill "${killer}" >/dev/null 2>&1 || true
  wait "${killer}" >/dev/null 2>&1 || true
  return "${status}"
}

run_aegis_measure() {
  if [[ -x "${AEGIS_MEASURE_BIN:-}" ]]; then
    "${AEGIS_MEASURE_BIN}" "$@"
  elif [[ -x "${ROOT}/target/debug/aegis-measure" ]] &&
    "${ROOT}/target/debug/aegis-measure" build-macos-utun-w0-blocked-result --help >/dev/null 2>&1
  then
    "${ROOT}/target/debug/aegis-measure" "$@"
  else
    cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- "$@"
  fi
}

write_blocked_result() {
  local status="$1"
  local blocker="$2"
  run_aegis_measure build-macos-utun-w0-blocked-result \
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
  printf 'socket_path=%s\n' "${SOCKET_PATH}"
  printf 'runtime_events_main=%s\n' "${USER_EVENTS_MAIN}"
  printf 'runtime_events_helper=%s\n' "${USER_EVENTS_HELPER}"
  printf 'build_profile=%s\n' "${BUILD_PROFILE}"
} >"${OUT_DIR}/environment.txt"

cargo "${CARGO_BUILD_ARGS[@]}"
if [[ "${RUN_BINARY}" == "${INSTALLED_BINARY}" ]]; then
  BUILT_HASH="$(shasum -a 256 "${BINARY}" | awk '{print $1}')"
  INSTALLED_HASH="$(shasum -a 256 "${RUN_BINARY}" | awk '{print $1}')"
  if [[ "${BUILT_HASH}" != "${INSTALLED_HASH}" ]]; then
    {
      printf 'built_sha256=%s\n' "${BUILT_HASH}"
      printf 'installed_sha256=%s\n' "${INSTALLED_HASH}"
      printf 'note=%s\n' "signed installed binaries may differ from freshly built unsigned workspace binaries"
    } >"${OUT_DIR}/installed-binary-hash-warning.txt"
  fi
fi
security find-identity -v -p codesigning >"${OUT_DIR}/codesigning-identities.txt" 2>&1 || true
set +e
spctl --assess --type execute -vv "${RUN_BINARY}" >"${OUT_DIR}/spctl-assess.txt" 2>&1
SPCTL_STATUS="$?"
set -e
if grep -q "0 valid identities found" "${OUT_DIR}/codesigning-identities.txt" && [[ "${SPCTL_STATUS}" != "0" ]]; then
  write_blocked_result "BLOCKED_BY_MACOS_CODESIGN_IDENTITY_MISSING" "macOS rejects the helper executable and no valid local code signing identity is available"
  : >"${OUT_DIR}/runtime-events.jsonl"
  : >"${OUT_DIR}/main.stderr.log"
  : >"${OUT_DIR}/helper.stderr.log"
  cat >"${OUT_DIR}/README.md" <<'MD'
# macOS utun Helper FD Loop Lab

Verdict: `NOT_PASS`.

Blocker: `BLOCKED_BY_MACOS_CODESIGN_IDENTITY_MISSING`.

macOS rejects the helper executable and this machine has no valid code signing
identity. No utun, FD passing, route, packet-loop, or broad system-wide claim is
made.
MD
  exit 0
fi

(
  cd /
  sudo -n -H -u "${AEGIS_USER}" /bin/bash -lc \
    "mkdir -p '${USER_TMP}' '${USER_STATE}' && rm -f '${SOCKET_PATH}' '${USER_EVENTS}' '${USER_EVENTS_MAIN}' '${USER_EVENTS_HELPER}' '${USER_RESULT}'"
)

if ! run_with_timeout 5 "${RUN_BINARY}" --self-check >/dev/null 2>"${OUT_DIR}/binary-self-check.stderr.log"; then
  write_blocked_result "LOCAL_BINARY_SELF_CHECK_FAILED" "installed lab binary did not complete --self-check within timeout or failed to execute"
  cp "${OUT_DIR}/binary-self-check.stderr.log" "${OUT_DIR}/helper.stderr.log"
  : >"${OUT_DIR}/main.stderr.log"
  : >"${OUT_DIR}/runtime-events.jsonl"
  cat >"${OUT_DIR}/README.md" <<'MD'
# macOS utun Helper FD Loop Lab

Verdict: `NOT_PASS`.

Blocker: `LOCAL_BINARY_SELF_CHECK_FAILED`.

The installed lab binary did not complete `--self-check` within timeout or failed to
execute. No utun, FD passing, route, packet-loop, or broad system-wide claim is
made.
MD
  exit 0
fi

if ! run_with_timeout 5 sudo -n -H -u "${AEGIS_USER}" "${RUN_BINARY}" --self-check >/dev/null 2>"${OUT_DIR}/binary-self-check-aegis.stderr.log"; then
  write_blocked_result "AEGIS_USER_BINARY_SELF_CHECK_FAILED" "aegis user could not complete lab binary --self-check within timeout or failed to execute"
  cp "${OUT_DIR}/binary-self-check-aegis.stderr.log" "${OUT_DIR}/main.stderr.log"
  : >"${OUT_DIR}/helper.stderr.log"
  : >"${OUT_DIR}/runtime-events.jsonl"
  cat >"${OUT_DIR}/README.md" <<'MD'
# macOS utun Helper FD Loop Lab

Verdict: `NOT_PASS`.

Blocker: `AEGIS_USER_BINARY_SELF_CHECK_FAILED`.

The non-root `aegis` user could not complete lab binary `--self-check` within timeout
or failed to execute it. No utun, FD passing, route, packet-loop, or broad
system-wide claim is made.
MD
  exit 0
fi

if ! sudo -n -l "${RUN_BINARY}" >/dev/null 2>"${OUT_DIR}/sudo-root-preflight.stderr.log"; then
  cat >"${OUT_DIR}/commands.txt" <<CMDS
cargo ${CARGO_BUILD_ARGS[*]}
sudo -n -l "${RUN_BINARY}"
Planned only; not executed: exec "${RUN_BINARY}" main --socket "${SOCKET_PATH}" --runtime-events-jsonl "${USER_EVENTS_MAIN}" --result-json "${USER_RESULT}"
Planned only; not executed: sudo -n "${RUN_BINARY}" helper --main-uid "${AEGIS_UTUN_MAIN_UID}" --main-pid <ACTUAL_MAIN_PID_FROM_DIRECT_EXEC> --socket "${SOCKET_PATH}" --runtime-events-jsonl "${USER_EVENTS_HELPER}" --controlled-peer "${CONTROLLED_PEER}" --controlled-local "${CONTROLLED_LOCAL}" --relay-ip "${RELAY_IP}"
CMDS
  cat >"${OUT_DIR}/runtime-events.jsonl" <<JSONL
{"event_code":"macos_utun_helper_started","status":"blocked","blocker":"BLOCKED_BY_ROOT_HELPER_SUDO","scope":"lab_controlled_utun_w0"}
{"event_code":"macos_utun_fd_received","status":"not_observed","scope":"lab_controlled_utun_w0"}
{"event_code":"macos_utun_packet_observed","status":"not_observed","scope":"lab_controlled_utun_w0"}
{"event_code":"macos_utun_cleanup_completed","status":"not_observed","scope":"lab_controlled_utun_w0"}
JSONL
  write_blocked_result "BLOCKED_BY_ROOT_HELPER_SUDO" "sudo -n root helper execution requires password or explicit NOPASSWD command allowance"
  cat >"${OUT_DIR}/README.md" <<'MD'
# macOS utun Helper FD Loop Lab

Verdict: `NOT_PASS`.

Blocker: `BLOCKED_BY_ROOT_HELPER_SUDO`.

The non-root `aegis` user is ready, but this runner also needs non-interactive
root helper permission for the lab binary. No utun, route, or packet-loop PASS
is claimed.
MD
  exit 0
fi

aegis_utun_start_main "${RUN_BINARY}" main \
    --socket "${SOCKET_PATH}" \
    --runtime-events-jsonl "${USER_EVENTS_MAIN}" \
    --result-json "${USER_RESULT}" \
  >"${OUT_DIR}/main.stdout.log" \
  2>"${OUT_DIR}/main.stderr.log"
MAIN_PID="${AEGIS_UTUN_MAIN_PID}"

sleep 1

set +e
sudo -n "${RUN_BINARY}" helper \
  --main-uid "${AEGIS_UTUN_MAIN_UID}" --main-pid "${MAIN_PID}" \
  --socket "${SOCKET_PATH}" \
  --runtime-events-jsonl "${USER_EVENTS_HELPER}" \
  --controlled-peer "${CONTROLLED_PEER}" \
  --controlled-local "${CONTROLLED_LOCAL}" \
  --relay-ip "${RELAY_IP}" \
  >"${OUT_DIR}/helper.stdout.log" \
  2>"${OUT_DIR}/helper.stderr.log" &
HELPER_PID="$!"
HELPER_STATUS=""
for _ in $(seq 1 15); do
  if ! kill -0 "${HELPER_PID}" >/dev/null 2>&1; then
    wait "${HELPER_PID}"
    HELPER_STATUS="$?"
    break
  fi
  sleep 1
done
if [[ -z "${HELPER_STATUS}" ]]; then
  kill "${HELPER_PID}" >/dev/null 2>&1 || true
  wait "${HELPER_PID}" >/dev/null 2>&1 || true
  HELPER_STATUS="124"
fi

MAIN_STATUS=""
for _ in $(seq 1 10); do
  if ! kill -0 "${MAIN_PID}" >/dev/null 2>&1; then
    wait "${MAIN_PID}"
    MAIN_STATUS="$?"
    break
  fi
  sleep 1
done
if [[ -z "${MAIN_STATUS}" ]]; then
  kill "${MAIN_PID}" >/dev/null 2>&1 || true
  wait "${MAIN_PID}" >/dev/null 2>&1 || true
  MAIN_STATUS="124"
fi
set -e

{
  printf '%s\n' 'Selected launch arguments; not a complete replay script. Main runs as the preflight-checked non-root caller.'
  printf 'cargo %s\n' "${CARGO_BUILD_ARGS[*]}"
  printf 'exec %s main --socket %s --runtime-events-jsonl %s --result-json %s\n' \
    "${RUN_BINARY}" "${SOCKET_PATH}" "${USER_EVENTS_MAIN}" "${USER_RESULT}"
  printf 'sudo -n %s helper --main-uid %s --main-pid %s --socket %s --runtime-events-jsonl %s --controlled-peer %s --controlled-local %s --relay-ip %s\n' \
    "${RUN_BINARY}" "${AEGIS_UTUN_MAIN_UID}" "${MAIN_PID}" "${SOCKET_PATH}" "${USER_EVENTS_HELPER}" "${CONTROLLED_PEER}" "${CONTROLLED_LOCAL}" "${RELAY_IP}"
} >"${OUT_DIR}/commands.txt"

{
  cat "${USER_EVENTS_HELPER}" 2>/dev/null || true
  cat "${USER_EVENTS_MAIN}" 2>/dev/null || true
} >"${OUT_DIR}/runtime-events.jsonl"
cat "${USER_RESULT}" >"${OUT_DIR}/result.json" 2>"${OUT_DIR}/result.copy.stderr.log" || true

if [[ ! -s "${OUT_DIR}/result.json" ]]; then
  run_aegis_measure build-macos-utun-w0-timeout-result \
    --helper-exit "${HELPER_STATUS}" \
    --main-exit "${MAIN_STATUS}" \
    --output-json "${OUT_DIR}/result.json"
fi

if [[ "${HELPER_STATUS}" == "0" && "${MAIN_STATUS}" == "0" ]] && grep -q '"verdict": "PASS"' "${OUT_DIR}/result.json"; then
  STATUS="PASS"
else
  STATUS="NOT_PASS"
fi

{
  printf '# macOS utun Helper FD Loop Lab\n\n'
  printf 'Verdict: `%s`.\n\n' "${STATUS}"
  printf -- '- helper exit: `%s`\n' "${HELPER_STATUS}"
  printf -- '- main exit: `%s`\n' "${MAIN_STATUS}"
  printf -- '- controlled peer: `%s`\n' "${CONTROLLED_PEER}"
  printf -- '- relay IP excluded from default-route claims: `%s`\n\n' "${RELAY_IP}"
  printf 'No broad system-wide, DNS, UDP, IPv6, or NetworkExtension replacement claim is made.\n'
} >"${OUT_DIR}/README.md"

exit 0
