#!/usr/bin/env bash
# Stage a tunnel-credential rotation without disconnecting installed clients.
#
# Server phase: new primary + old primary as a hard-expiring legacy key.
# Client phase: update every inventoried client only after every relay accepts
# both credentials. A partial run therefore keeps old clients working.
#
# Usage:
#   scripts/rotate-relay-auth-token.sh \
#     --relays "ip1 ip2" --clients "ip3 ip4" \
#     --legacy-id legacy-2026-08 --legacy-not-after 1787875199 \
#     --confirm-staged-rotation
#
# Requires SSH keys, or sshpass with AEGIS_SSH_PASSWORD in the environment.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELAYS=""
CLIENTS=""
LEGACY_ID=""
LEGACY_NOT_AFTER=""
CONFIRM=0
DRY=0
SERVER_CFG="/etc/aegis/server/aegis-server.toml"
CLIENT_CFG="/etc/aegis/client/aegis.toml"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --relays) RELAYS="$2"; shift 2 ;;
    --clients|--client) CLIENTS="$2"; shift 2 ;;
    --legacy-id) LEGACY_ID="$2"; shift 2 ;;
    --legacy-not-after) LEGACY_NOT_AFTER="$2"; shift 2 ;;
    --server-config) SERVER_CFG="$2"; shift 2 ;;
    --client-config) CLIENT_CFG="$2"; shift 2 ;;
    --confirm-staged-rotation) CONFIRM=1; shift ;;
    --dry-run) DRY=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -n "${RELAYS}" ]] || { echo "--relays is required" >&2; exit 2; }
[[ -n "${CLIENTS}" ]] || { echo "--clients is required; an empty client inventory is unsafe" >&2; exit 2; }
[[ "${LEGACY_ID}" =~ ^[A-Za-z0-9_-]{1,32}$ && "${LEGACY_ID}" != current ]] || {
  echo "--legacy-id must be 1-32 safe characters and not 'current'" >&2; exit 2;
}
[[ "${LEGACY_NOT_AFTER}" =~ ^[0-9]+$ ]] || { echo "--legacy-not-after must be a unix timestamp" >&2; exit 2; }
NOW="$(date +%s)"
if (( LEGACY_NOT_AFTER < NOW + 300 || LEGACY_NOT_AFTER > NOW + 90 * 24 * 60 * 60 )); then
  echo "--legacy-not-after must be 5 minutes to 90 days in the future" >&2
  exit 2
fi
if [[ "${DRY}" -eq 0 && "${CONFIRM}" -ne 1 ]]; then
  echo "refusing mutation without --confirm-staged-rotation" >&2
  exit 2
fi

sshx() {
  local host="$1"
  if [[ -n "${AEGIS_SSH_PASSWORD:-}" ]]; then
    SSHPASS="${AEGIS_SSH_PASSWORD}" sshpass -e ssh -o StrictHostKeyChecking=accept-new \
      -o ConnectTimeout=20 "root@${host}" 'bash -s'
  else
    ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 "root@${host}" 'bash -s'
  fi
}

copy_tool() {
  local host="$1" tool="$2" destination="$3"
  if [[ -n "${AEGIS_SSH_PASSWORD:-}" ]]; then
    SSHPASS="${AEGIS_SSH_PASSWORD}" sshpass -e scp -q -o StrictHostKeyChecking=accept-new \
      "${tool}" "root@${host}:${destination}"
  else
    scp -q -o StrictHostKeyChecking=accept-new "${tool}" "root@${host}:${destination}"
  fi
}

server_fingerprint() {
  local host="$1"
  printf 'sed -n '\''s/^[[:space:]]*auth_token[[:space:]]*=[[:space:]]*"\\([^" ]*\\)".*/\\1/p'\'' %q | head -1 | sha256sum | cut -c1-12\n' \
    "${SERVER_CFG}" | sshx "${host}"
}

client_fingerprint() {
  local host="$1"
  printf 'awk '\''BEGIN{s=0} /^\\[relay\\]/{s=1;next} /^\\[/{s=0} s && /^[[:space:]]*auth_token[[:space:]]*=/{x=$0;sub(/^[^=]*=[[:space:]]*"/,"",x);sub(/".*$/,"",x);print x;exit}'\'' %q | sha256sum | cut -c1-12\n' \
    "${CLIENT_CFG}" | sshx "${host}"
}

echo "== preflight =="
expected=""
for host in ${RELAYS}; do
  status="$(printf 'aegis-server --config %q config-check && systemctl is-active aegis-server\n' "${SERVER_CFG}" | sshx "${host}")"
  fp="$(server_fingerprint "${host}" | tail -1)"
  expected="${expected:-${fp}}"
  [[ "${fp}" == "${expected}" ]] || { echo "relay primary fingerprint mismatch on ${host}" >&2; exit 1; }
  echo "  relay ${host}: ${status//$'\n'/; } primary=${fp}"
done
for host in ${CLIENTS}; do
  fp="$(client_fingerprint "${host}" | tail -1)"
  [[ "${fp}" == "${expected}" ]] || { echo "client primary fingerprint mismatch on ${host}" >&2; exit 1; }
  echo "  client ${host}: reachable primary=${fp}"
done

if [[ "${DRY}" -eq 1 ]]; then
  echo "dry run: staged rotation preflight passed; no credential generated or changed"
  exit 0
fi

TOKEN="$(openssl rand -hex 32)"
REMOTE_TOOL="${ROOT}/scripts/lib/rotate-auth-token-remote.py"
[[ -f "${REMOTE_TOOL}" ]] || { echo "missing ${REMOTE_TOOL}" >&2; exit 1; }
RUN_ID="$(date +%s)-$$"
ROLLBACK_DIR="/root/.aegis-auth-rollback"
SERVER_ROLLBACK="${ROLLBACK_DIR}/server-${RUN_ID}.toml"
CLIENT_ROLLBACK="${ROLLBACK_DIR}/client-${RUN_ID}.toml"
REMOTE_TOOL_DIR="/root/.aegis-auth-tools"
REMOTE_TOOL_COPY="${REMOTE_TOOL_DIR}/rotate-${RUN_ID}.py"
TOUCHED_RELAYS=()
TOUCHED_CLIENTS=()
ROLLBACK_ARMED=0

rollback_host() {
  local host="$1" cfg="$2" snapshot="$3" service="$4"
  if printf 'set -e\ntest -f %q\ncp -a -- %q %q\nsystemctl restart %q\nsystemctl is-active %q\nrm -f -- %q\n' \
    "${snapshot}" "${snapshot}" "${cfg}" "${service}" "${service}" "${REMOTE_TOOL_COPY}" | \
    sshx "${host}" >/dev/null; then
    echo "  ${host}: restored ${service} snapshot and service is active" >&2
    return 0
  fi
  echo "  ${host}: CRITICAL: automatic ${service} rollback failed" >&2
  return 1
}

rollback_all() {
  local failed=0 host
  set +e
  for host in "${TOUCHED_CLIENTS[@]}"; do
    rollback_host "${host}" "${CLIENT_CFG}" "${CLIENT_ROLLBACK}" aegis-client || failed=1
  done
  for host in "${TOUCHED_RELAYS[@]}"; do
    rollback_host "${host}" "${SERVER_CFG}" "${SERVER_ROLLBACK}" aegis-server || failed=1
  done
  set -e
  return "${failed}"
}

on_exit() {
  local rc=$?
  trap - EXIT
  if [[ ${rc} -ne 0 && ${ROLLBACK_ARMED} -eq 1 ]]; then
    echo "rotation aborted; restoring every touched host" >&2
    rollback_all || true
  fi
  exit "${rc}"
}
trap on_exit EXIT

apply_to() {
  local host="$1" cfg="$2" role="$3"
  printf 'install -d -m 700 %q\n' "${REMOTE_TOOL_DIR}" | sshx "${host}"
  copy_tool "${host}" "${REMOTE_TOOL}" "${REMOTE_TOOL_COPY}"
  local remote_args
  if [[ "${role}" == server ]]; then
    printf -v remote_args "python3 %q %q server %q %q" \
      "${REMOTE_TOOL_COPY}" "${cfg}" "${LEGACY_ID}" "${LEGACY_NOT_AFTER}"
  else
    printf -v remote_args "python3 %q %q client" "${REMOTE_TOOL_COPY}" "${cfg}"
  fi
  local output
  set +e
  output="$({
    printf 'set -e\n'
    printf 'token=%q\n' "${TOKEN}"
    printf 'printf '\''%%s'\'' "$token" | %s\n' "${remote_args}"
    printf 'rm -f -- %q\n' "${REMOTE_TOOL_COPY}"
  } | sshx "${host}")"
  local rc=$?
  set -e
  if [[ ${rc} -ne 0 ]]; then
    echo "  ${host} (${role}): FAILED" >&2
    return "${rc}"
  fi
  echo "  ${host} (${role}): ${output}"
}

echo "== relay overlap phase =="
for host in ${RELAYS}; do
  printf 'set -e\ninstall -d -m 700 %q\ncp -a -- %q %q\n' \
    "${ROLLBACK_DIR}" "${SERVER_CFG}" "${SERVER_ROLLBACK}" | sshx "${host}"
  TOUCHED_RELAYS+=("${host}")
  ROLLBACK_ARMED=1
  if ! apply_to "${host}" "${SERVER_CFG}" server; then
    echo "  ${host}: staging failed" >&2
    exit 1
  fi
  if ! printf 'aegis-server --config %q config-check && systemctl restart aegis-server && systemctl is-active aegis-server\n' \
    "${SERVER_CFG}" | \
    sshx "${host}" | sed "s/^/  ${host}: /"; then
    echo "  ${host}: validation/start failed" >&2
    exit 1
  fi
done

echo "== inventoried client phase =="
for host in ${CLIENTS}; do
  printf 'set -e\ninstall -d -m 700 %q\ncp -a -- %q %q\n' \
    "${ROLLBACK_DIR}" "${CLIENT_CFG}" "${CLIENT_ROLLBACK}" | sshx "${host}"
  TOUCHED_CLIENTS+=("${host}")
  if ! apply_to "${host}" "${CLIENT_CFG}" client; then
    echo "  ${host}: staging failed" >&2
    exit 1
  fi
  if ! printf 'systemctl restart aegis-client && systemctl is-active aegis-client\n' | \
    sshx "${host}" | sed "s/^/  ${host}: /"; then
    echo "  ${host}: validation/start failed" >&2
    exit 1
  fi
done

# Every host is on the new primary and every service is active. Disarm first:
# cleanup failure must leave a root-only recovery snapshot, not undo a healthy
# completed rotation after another host's snapshot was already removed.
ROLLBACK_ARMED=0
trap - EXIT
for host in "${TOUCHED_CLIENTS[@]}"; do
  if ! printf 'rm -f -- %q %q\n' "${CLIENT_ROLLBACK}" "${REMOTE_TOOL_COPY}" | sshx "${host}"; then
    echo "  ${host}: warning: client recovery snapshot cleanup failed" >&2
  fi
done
for host in "${TOUCHED_RELAYS[@]}"; do
  if ! printf 'rm -f -- %q %q\n' "${SERVER_ROLLBACK}" "${REMOTE_TOOL_COPY}" | sshx "${host}"; then
    echo "  ${host}: warning: server recovery snapshot cleanup failed" >&2
  fi
done

cat <<NOTE

Rotation is staged, not complete. Relays accept the previous credential only
until unix time ${LEGACY_NOT_AFTER}. Verify traffic from every inventoried
client, monitor auth_key_legacy telemetry, and remove the legacy table after
the migration window. The hard runtime expiry applies even if cleanup is late.
NOTE
