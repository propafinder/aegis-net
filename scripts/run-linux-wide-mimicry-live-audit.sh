#!/usr/bin/env bash
# Orchestrate a repeatable two-VPS Linux wide+mimicry live audit with archived artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REDEPLOY_SCRIPT="${ROOT}/scripts/redeploy-two-vps-release.sh"
WIRE_HELPER_SCRIPT="${ROOT}/scripts/validate-mimicry-wire-host.sh"
WITNESS_SCRIPT="${ROOT}/scripts/build-mimicry-wire-witness-summary.sh"
STEALTH_BUNDLE_SCRIPT="${ROOT}/scripts/build-stealth-live-acceptance-bundle.sh"
MANIFEST_HELPER_SCRIPT="${ROOT}/scripts/build-linux-wide-live-audit-manifest.sh"
HANDOFF_STATUS_SCRIPT="${ROOT}/scripts/linux-wide-live-audit-handoff-status.sh"
PHASE_B_RUNTIME_EVIDENCE_SCRIPT="${ROOT}/scripts/build-phase-b-runtime-evidence-bundle.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/run-linux-wide-mimicry-live-audit.sh \
    --server-host <host> \
    --client-host <host> \
    --ssh-user <user> \
    --output-dir <dir> \
    [--server-port <port>] \
    [--client-port <port>] \
    [--server-private-key-path <path>] \
    [--client-private-key-path <path>] \
    [--server-name <tls-name>] \
    [--relay-address <host:port>] \
    [--manifest-url <url>] \
    [--bootstrap-url <url>] \
    [--client-audit-script <path>] \
    [--server-audit-script <path>] \
    [--remote-client-pcap <path>] \
    [--remote-client-pcap-interface <iface>] \
    [--remote-runtime-events <path>] \
    [--relay-transport-priority <comma-list>] \
    [--phase-b-baseline-json <path>] \
    [--phase-b-runtime-evidence-strict] \
    [--skip-redeploy] \
    [--dry-run]
EOF
}

SERVER_HOST=""
CLIENT_HOST=""
SSH_USER=""
SERVER_PORT=22
CLIENT_PORT=22
SERVER_PRIVATE_KEY_PATH=""
CLIENT_PRIVATE_KEY_PATH=""
SERVER_NAME=""
RELAY_ADDRESS=""
MANIFEST_URL=""
BOOTSTRAP_URL="${AEGIS_REDEPLOY_BOOTSTRAP_URL:-https://github.com/propafinder/aegis-release/releases/latest/download/bootstrap-install.sh}"
OUTPUT_DIR=""
CLIENT_AUDIT_SCRIPT=""
SERVER_AUDIT_SCRIPT=""
REMOTE_CLIENT_PCAP=""
REMOTE_CLIENT_PCAP_INTERFACE=""
REMOTE_RUNTIME_EVENTS="${AEGIS_LINUX_WIDE_MIMICRY_REMOTE_RUNTIME_EVENTS:-/var/log/aegis-client/runtime-events.jsonl}"
REMOTE_CLIENT_CONFIG="${AEGIS_LINUX_WIDE_MIMICRY_REMOTE_CLIENT_CONFIG:-/etc/aegis/client/aegis.toml}"
REMOTE_SERVER_CONFIG="${AEGIS_LINUX_WIDE_MIMICRY_REMOTE_SERVER_CONFIG:-/etc/aegis/server/aegis-server.toml}"
REMOTE_TRANSIENT_RELAY_WIRE_RUNTIME="${AEGIS_LINUX_WIDE_MIMICRY_REMOTE_TRANSIENT_RELAY_WIRE_RUNTIME:-/tmp/aegis-live-audit-transient-relay-wire.jsonl}"
REMOTE_TRANSIENT_RELAY_WIRE_CONFIG="${AEGIS_LINUX_WIDE_MIMICRY_REMOTE_TRANSIENT_RELAY_WIRE_CONFIG:-/tmp/aegis-live-audit-transient-relay-wire.toml}"
REMOTE_TRANSIENT_DIRECT_WIRE_ACTIVE_RUNTIME="${AEGIS_LINUX_WIDE_MIMICRY_REMOTE_TRANSIENT_DIRECT_WIRE_ACTIVE_RUNTIME:-/tmp/aegis-live-audit-transient-direct-wire-active.jsonl}"
REMOTE_TRANSIENT_DIRECT_WIRE_ACTIVE_CONFIG="${AEGIS_LINUX_WIDE_MIMICRY_REMOTE_TRANSIENT_DIRECT_WIRE_ACTIVE_CONFIG:-/tmp/aegis-live-audit-transient-direct-wire-active.toml}"
RELAY_TRANSPORT_PRIORITY="${AEGIS_LINUX_WIDE_MIMICRY_RELAY_TRANSPORT_PRIORITY:-https_ws,grpc_stream,legacy_tls,masque_derived}"
PHASE_B_BASELINE_JSON=""
PHASE_B_RUNTIME_EVIDENCE_STRICT=0
SKIP_REDEPLOY=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-host)
      SERVER_HOST="$2"
      shift 2
      ;;
    --client-host)
      CLIENT_HOST="$2"
      shift 2
      ;;
    --ssh-user)
      SSH_USER="$2"
      shift 2
      ;;
    --server-port)
      SERVER_PORT="$2"
      shift 2
      ;;
    --client-port)
      CLIENT_PORT="$2"
      shift 2
      ;;
    --server-private-key-path)
      SERVER_PRIVATE_KEY_PATH="$2"
      shift 2
      ;;
    --client-private-key-path)
      CLIENT_PRIVATE_KEY_PATH="$2"
      shift 2
      ;;
    --server-name)
      SERVER_NAME="$2"
      shift 2
      ;;
    --relay-address)
      RELAY_ADDRESS="$2"
      shift 2
      ;;
    --manifest-url)
      MANIFEST_URL="$2"
      shift 2
      ;;
    --bootstrap-url)
      BOOTSTRAP_URL="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --client-audit-script)
      CLIENT_AUDIT_SCRIPT="$2"
      shift 2
      ;;
    --server-audit-script)
      SERVER_AUDIT_SCRIPT="$2"
      shift 2
      ;;
    --remote-client-pcap)
      REMOTE_CLIENT_PCAP="$2"
      shift 2
      ;;
    --remote-client-pcap-interface)
      REMOTE_CLIENT_PCAP_INTERFACE="$2"
      shift 2
      ;;
    --remote-runtime-events)
      REMOTE_RUNTIME_EVENTS="$2"
      shift 2
      ;;
    --relay-transport-priority)
      RELAY_TRANSPORT_PRIORITY="$2"
      shift 2
      ;;
    --phase-b-baseline-json)
      PHASE_B_BASELINE_JSON="$2"
      shift 2
      ;;
    --phase-b-runtime-evidence-strict)
      PHASE_B_RUNTIME_EVIDENCE_STRICT=1
      shift
      ;;
    --skip-redeploy)
      SKIP_REDEPLOY=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${SERVER_HOST}" || -z "${CLIENT_HOST}" || -z "${SSH_USER}" || -z "${OUTPUT_DIR}" ]]; then
  usage >&2
  exit 1
fi

if [[ ! "${SERVER_PORT}" =~ ^[0-9]+$ || ! "${CLIENT_PORT}" =~ ^[0-9]+$ ]]; then
  echo "SSH ports must be numeric" >&2
  exit 1
fi
if [[ -n "${SERVER_PRIVATE_KEY_PATH}" && ! -f "${SERVER_PRIVATE_KEY_PATH}" ]]; then
  echo "Server private key not found: ${SERVER_PRIVATE_KEY_PATH}" >&2
  exit 1
fi
if [[ -n "${CLIENT_PRIVATE_KEY_PATH}" && ! -f "${CLIENT_PRIVATE_KEY_PATH}" ]]; then
  echo "Client private key not found: ${CLIENT_PRIVATE_KEY_PATH}" >&2
  exit 1
fi
if [[ -n "${PHASE_B_BASELINE_JSON}" && ! -f "${PHASE_B_BASELINE_JSON}" ]]; then
  echo "Phase B baseline json not found: ${PHASE_B_BASELINE_JSON}" >&2
  exit 1
fi

if [[ -z "${SERVER_NAME}" ]]; then
  SERVER_NAME="${SERVER_HOST}"
fi
if [[ -z "${RELAY_ADDRESS}" ]]; then
  RELAY_ADDRESS="${SERVER_HOST}:8443"
fi
if [[ -z "${RELAY_TRANSPORT_PRIORITY}" ]]; then
  echo "--relay-transport-priority must not be empty" >&2
  exit 2
fi
cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- validate-relay-transport-priority \
  --priority "${RELAY_TRANSPORT_PRIORITY}"

for required_path in "${REDEPLOY_SCRIPT}" "${WIRE_HELPER_SCRIPT}" "${WITNESS_SCRIPT}" "${STEALTH_BUNDLE_SCRIPT}" "${MANIFEST_HELPER_SCRIPT}" "${HANDOFF_STATUS_SCRIPT}" "${PHASE_B_RUNTIME_EVIDENCE_SCRIPT}"; do
  if [[ ! -f "${required_path}" ]]; then
    echo "Required local helper not found: ${required_path}" >&2
    exit 1
  fi
done
if [[ -n "${CLIENT_AUDIT_SCRIPT}" && ! -f "${CLIENT_AUDIT_SCRIPT}" ]]; then
  echo "Client audit script not found: ${CLIENT_AUDIT_SCRIPT}" >&2
  exit 1
fi
if [[ -n "${SERVER_AUDIT_SCRIPT}" && ! -f "${SERVER_AUDIT_SCRIPT}" ]]; then
  echo "Server audit script not found: ${SERVER_AUDIT_SCRIPT}" >&2
  exit 1
fi

SSH_BIN="${AEGIS_REDEPLOY_SSH_BIN:-ssh}"
SCP_BIN="${AEGIS_REDEPLOY_SCP_BIN:-scp}"
SSHPASS_BIN="${AEGIS_REDEPLOY_SSHPASS_BIN:-sshpass}"
SSH_PASSWORD="${AEGIS_SSH_PASSWORD:-}"

SSH_PREFIX=()
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ConnectTimeout=15)
SCP_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
if [[ -n "${SSH_PASSWORD}" && -z "${SERVER_PRIVATE_KEY_PATH}" && -z "${CLIENT_PRIVATE_KEY_PATH}" ]]; then
  if ! command -v "${SSHPASS_BIN}" >/dev/null 2>&1; then
    echo "AEGIS_SSH_PASSWORD is set but sshpass is unavailable (${SSHPASS_BIN})" >&2
    exit 1
  fi
  export SSHPASS="${SSH_PASSWORD}"
  SSH_PREFIX=("${SSHPASS_BIN}" -e)
  SSH_OPTS+=(-o PreferredAuthentications=password -o PubkeyAuthentication=no)
  SCP_OPTS+=(-o PreferredAuthentications=password -o PubkeyAuthentication=no)
else
  SSH_OPTS+=(-o BatchMode=yes)
  SCP_OPTS+=(-o BatchMode=yes)
fi

mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR_ABS="$(cd "${OUTPUT_DIR}" 2>/dev/null && pwd -P)"
CLIENT_ARTIFACT_DIR="${OUTPUT_DIR_ABS}/client"
SERVER_ARTIFACT_DIR="${OUTPUT_DIR_ABS}/server"
LOCAL_RUNTIME_EVENTS="${CLIENT_ARTIFACT_DIR}/runtime-events.jsonl"
LOCAL_TRANSIENT_RELAY_WIRE_RUNTIME="${CLIENT_ARTIFACT_DIR}/transient-relay-wire-runtime-events.jsonl"
LOCAL_TRANSIENT_DIRECT_WIRE_ACTIVE_RUNTIME="${CLIENT_ARTIFACT_DIR}/transient-direct-wire-active-runtime-events.jsonl"
LOCAL_WIRE_HELPER_RUNTIME_EVENTS="${CLIENT_ARTIFACT_DIR}/wire-helper-runtime-events.jsonl"
LOCAL_CLIENT_CONFIG="${CLIENT_ARTIFACT_DIR}/aegis.toml"
LOCAL_SERVER_CONFIG="${SERVER_ARTIFACT_DIR}/aegis-server.toml"
LOCAL_CLIENT_STATUS="${CLIENT_ARTIFACT_DIR}/systemctl-status.txt"
LOCAL_CLIENT_JOURNAL="${CLIENT_ARTIFACT_DIR}/journalctl.txt"
LOCAL_CLIENT_PREFLIGHT="${CLIENT_ARTIFACT_DIR}/preflight.json"
LOCAL_CLIENT_STARTUP_PROBE="${CLIENT_ARTIFACT_DIR}/startup-probe.json"
LOCAL_SERVER_STATUS="${SERVER_ARTIFACT_DIR}/systemctl-status.txt"
LOCAL_SERVER_JOURNAL="${SERVER_ARTIFACT_DIR}/journalctl.txt"
LOCAL_WITNESS_PCAP=""
LOCAL_WITNESS_SUMMARY=""
LOCAL_WIRE_HELPER_STDOUT="${CLIENT_ARTIFACT_DIR}/wire-host-helper.stdout.json"
LOCAL_WIRE_ACCEPTANCE_SUMMARY="${CLIENT_ARTIFACT_DIR}/wire-host-acceptance-summary.json"
LOCAL_STEALTH_BUNDLE_DIR="${OUTPUT_DIR_ABS}/stealth-live-acceptance"
LOCAL_PHASE_B_RUNTIME_EVIDENCE_DIR="${OUTPUT_DIR_ABS}/phase-b-runtime-evidence"
LOCAL_MANIFEST="${OUTPUT_DIR_ABS}/live-audit.manifest.json"
LOCAL_SUMMARY_MD="${OUTPUT_DIR_ABS}/live-audit-summary.md"
LOCAL_HANDOFF_STATUS_JSON="${OUTPUT_DIR_ABS}/live-audit-handoff-status.json"

if [[ -n "${REMOTE_CLIENT_PCAP}" ]]; then
  LOCAL_WITNESS_PCAP="${CLIENT_ARTIFACT_DIR}/wire-witness-capture.pcapng"
  LOCAL_WITNESS_SUMMARY="${CLIENT_ARTIFACT_DIR}/wire-witness-summary.json"
fi
if [[ -n "${REMOTE_CLIENT_PCAP_INTERFACE}" && -z "${REMOTE_CLIENT_PCAP}" ]]; then
  echo "--remote-client-pcap-interface requires --remote-client-pcap" >&2
  exit 1
fi

step() {
  printf '\n==> %s\n' "$*"
}

quote_args() {
  local quoted=""
  local arg=""
  for arg in "$@"; do
    if [[ -n "${quoted}" ]]; then
      quoted+=" "
    fi
    quoted+="$(printf '%q' "${arg}")"
  done
  printf '%s\n' "${quoted}"
}

remote_spec() {
  local host="$1"
  printf '%s@%s\n' "${SSH_USER}" "${host}"
}

private_key_for_host() {
  local host="$1"
  if [[ "${host}" == "${SERVER_HOST}" && -n "${SERVER_PRIVATE_KEY_PATH}" ]]; then
    printf '%s\n' "${SERVER_PRIVATE_KEY_PATH}"
    return 0
  fi
  if [[ "${host}" == "${CLIENT_HOST}" && -n "${CLIENT_PRIVATE_KEY_PATH}" ]]; then
    printf '%s\n' "${CLIENT_PRIVATE_KEY_PATH}"
    return 0
  fi
  printf '%s\n' ""
}

run_ssh() {
  local host="$1"
  local port="$2"
  shift 2
  local private_key=""
  local host_ssh_opts=("${SSH_OPTS[@]}")
  private_key="$(private_key_for_host "${host}")"
  if [[ -n "${private_key}" ]]; then
    host_ssh_opts+=(-i "${private_key}")
  fi
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    if [[ -n "${private_key}" ]]; then
      printf '[dry-run] ssh -i %s -p %s %s %s\n' "${private_key}" "${port}" "$(remote_spec "${host}")" "$(quote_args "$@")"
    else
      printf '[dry-run] ssh -p %s %s %s\n' "${port}" "$(remote_spec "${host}")" "$(quote_args "$@")"
    fi
    return 0
  fi
  if (( ${#SSH_PREFIX[@]} != 0 )); then
    "${SSH_PREFIX[@]}" "${SSH_BIN}" "${host_ssh_opts[@]}" -p "${port}" "$(remote_spec "${host}")" "$@"
  else
    "${SSH_BIN}" "${host_ssh_opts[@]}" -p "${port}" "$(remote_spec "${host}")" "$@"
  fi
}

run_ssh_file() {
  local host="$1"
  local port="$2"
  local script_path="$3"
  shift 3
  local remote_args=""
  local private_key=""
  local host_ssh_opts=("${SSH_OPTS[@]}")
  remote_args="$(quote_args "$@")"
  private_key="$(private_key_for_host "${host}")"
  if [[ -n "${private_key}" ]]; then
    host_ssh_opts+=(-i "${private_key}")
  fi
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    if [[ -n "${private_key}" ]]; then
      printf '[dry-run] ssh -i %s -p %s %s bash -s -- %s < %s\n' "${private_key}" "${port}" "$(remote_spec "${host}")" "${remote_args}" "${script_path}"
    else
      printf '[dry-run] ssh -p %s %s bash -s -- %s < %s\n' "${port}" "$(remote_spec "${host}")" "${remote_args}" "${script_path}"
    fi
    return 0
  fi
  if (( ${#SSH_PREFIX[@]} != 0 )); then
    "${SSH_PREFIX[@]}" "${SSH_BIN}" "${host_ssh_opts[@]}" -p "${port}" "$(remote_spec "${host}")" "bash -s -- ${remote_args}" < "${script_path}"
  else
    "${SSH_BIN}" "${host_ssh_opts[@]}" -p "${port}" "$(remote_spec "${host}")" "bash -s -- ${remote_args}" < "${script_path}"
  fi
}

run_scp_from_remote() {
  local host="$1"
  local port="$2"
  local remote_path="$3"
  local local_path="$4"
  local private_key=""
  local host_scp_opts=("${SCP_OPTS[@]}")
  private_key="$(private_key_for_host "${host}")"
  if [[ -n "${private_key}" ]]; then
    host_scp_opts+=(-i "${private_key}")
  fi
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    if [[ -n "${private_key}" ]]; then
      printf '[dry-run] scp -i %s -P %s %s:%s %s\n' "${private_key}" "${port}" "$(remote_spec "${host}")" "${remote_path}" "${local_path}"
    else
      printf '[dry-run] scp -P %s %s:%s %s\n' "${port}" "$(remote_spec "${host}")" "${remote_path}" "${local_path}"
    fi
    return 0
  fi
  mkdir -p "$(dirname "${local_path}")"
  if (( ${#SSH_PREFIX[@]} != 0 )); then
    "${SSH_PREFIX[@]}" "${SCP_BIN}" "${host_scp_opts[@]}" -P "${port}" "$(remote_spec "${host}"):${remote_path}" "${local_path}"
  else
    "${SCP_BIN}" "${host_scp_opts[@]}" -P "${port}" "$(remote_spec "${host}"):${remote_path}" "${local_path}"
  fi
}

write_remote_capture() {
  local host="$1"
  local port="$2"
  local remote_cmd="$3"
  local local_path="$4"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] ssh -p %s %s %s > %s\n' "${port}" "$(remote_spec "${host}")" "$(printf '%q' "${remote_cmd}")" "${local_path}"
    return 0
  fi
  mkdir -p "$(dirname "${local_path}")"
  run_ssh "${host}" "${port}" "${remote_cmd}" > "${local_path}"
}

require_local_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "Required local tool is missing: ${tool}" >&2
    exit 1
  fi
}

build_rerun_command() {
  local cmd=("bash" "scripts/run-linux-wide-mimicry-live-audit.sh"
    "--server-host" "${SERVER_HOST}"
    "--client-host" "${CLIENT_HOST}"
    "--ssh-user" "${SSH_USER}"
    "--server-name" "${SERVER_NAME}"
    "--relay-address" "${RELAY_ADDRESS}"
    "--output-dir" "${OUTPUT_DIR}"
  )
  if [[ "${SERVER_PORT}" != "22" ]]; then
    cmd+=("--server-port" "${SERVER_PORT}")
  fi
  if [[ "${CLIENT_PORT}" != "22" ]]; then
    cmd+=("--client-port" "${CLIENT_PORT}")
  fi
  if [[ -n "${SERVER_PRIVATE_KEY_PATH}" ]]; then
    cmd+=("--server-private-key-path" "${SERVER_PRIVATE_KEY_PATH}")
  fi
  if [[ -n "${CLIENT_PRIVATE_KEY_PATH}" ]]; then
    cmd+=("--client-private-key-path" "${CLIENT_PRIVATE_KEY_PATH}")
  fi
  if [[ -n "${MANIFEST_URL}" ]]; then
    cmd+=("--manifest-url" "${MANIFEST_URL}")
  fi
  if [[ -n "${BOOTSTRAP_URL}" ]]; then
    cmd+=("--bootstrap-url" "${BOOTSTRAP_URL}")
  fi
  if [[ -n "${CLIENT_AUDIT_SCRIPT}" ]]; then
    cmd+=("--client-audit-script" "${CLIENT_AUDIT_SCRIPT}")
  fi
  if [[ -n "${SERVER_AUDIT_SCRIPT}" ]]; then
    cmd+=("--server-audit-script" "${SERVER_AUDIT_SCRIPT}")
  fi
  if [[ -n "${REMOTE_CLIENT_PCAP}" ]]; then
    cmd+=("--remote-client-pcap" "${REMOTE_CLIENT_PCAP}")
  fi
  if [[ -n "${REMOTE_CLIENT_PCAP_INTERFACE}" ]]; then
    cmd+=("--remote-client-pcap-interface" "${REMOTE_CLIENT_PCAP_INTERFACE}")
  fi
  if [[ -n "${REMOTE_RUNTIME_EVENTS}" ]]; then
    cmd+=("--remote-runtime-events" "${REMOTE_RUNTIME_EVENTS}")
  fi
  if [[ -n "${RELAY_TRANSPORT_PRIORITY}" ]]; then
    cmd+=("--relay-transport-priority" "${RELAY_TRANSPORT_PRIORITY}")
  fi
  if [[ -n "${PHASE_B_BASELINE_JSON}" ]]; then
    cmd+=("--phase-b-baseline-json" "${PHASE_B_BASELINE_JSON}")
  fi
  if [[ "${PHASE_B_RUNTIME_EVIDENCE_STRICT}" -eq 1 ]]; then
    cmd+=("--phase-b-runtime-evidence-strict")
  fi
  if [[ "${SKIP_REDEPLOY}" -eq 1 ]]; then
    cmd+=("--skip-redeploy")
  fi
  quote_args "${cmd[@]}"
}

harvest_transient_relay_wire_runtime() {
  local host="$1"
  local port="$2"
  local remote_client_config="$3"
  local remote_output_jsonl="$4"
  local remote_temp_config="$5"
  local local_output_jsonl="$6"
  local target_host="$7"
  local target_port="$8"
  local relay_transport_priority="$9"
  local temp_script=""
  temp_script="$(mktemp "${TMPDIR:-/tmp}/aegis-transient-relay-wire.XXXXXX")"
  cat > "${temp_script}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

REMOTE_CLIENT_CONFIG="$1"
REMOTE_OUTPUT_JSONL="$2"
REMOTE_TEMP_CONFIG="$3"
REMOTE_SOCKS_PORT="${4:-1180}"
TARGET_HOST="${5:-1.1.1.1}"
TARGET_PORT="${6:-443}"
RELAY_TRANSPORT_PRIORITY="${7:-https_ws,grpc_stream,legacy_tls,masque_derived}"
REMOTE_LOG_PATH="${REMOTE_OUTPUT_JSONL%.jsonl}.log"

client_bin="$(command -v aegis-client || true)"
if [[ -z "${client_bin}" ]]; then
  echo "remote aegis-client binary is missing" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "remote python3 is required for transient relay config generation" >&2
  exit 1
fi

write_relay_temp_config() {
  local dest_config="$1"
  local socks_port="$2"
  local chunk_size="$3"
python3 - "${REMOTE_CLIENT_CONFIG}" "${dest_config}" "${socks_port}" "${chunk_size}" "${RELAY_TRANSPORT_PRIORITY}" <<'PY'
import sys
import tomllib
import json
from pathlib import Path

source = Path(sys.argv[1])
dest = Path(sys.argv[2])
socks_port = int(sys.argv[3])
chunk_size = int(sys.argv[4])
relay_transport_priority = [item.strip() for item in sys.argv[5].split(",") if item.strip()]
cfg = tomllib.loads(source.read_text(encoding="utf-8"))
relay = cfg["relay"]
policy = relay.get("policy", {})
direct = cfg.get("direct", {})

def toml_bool(value):
    return "true" if value else "false"

dest.write_text(
    f"""mode = "relay"

[ingress]
primary = "socks5"
allow_fallback = true

[ingress.wide]
enabled = false
platform_backend = "auto"
rollout_profile = "output_only_safe"
listen = "127.0.0.1:15081"
capture_dns = false
udp_capture_contract = "preview_allowlist_only"
dns_port = 53
udp_preview_ports = []
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = {direct.get("state_path", "~/.cache/aegis/state.json")!r}
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
stack_profile = "linux"
wire_mimicry_mode = "linux_experimental_ttl_preface"

[relay]
server = {relay["server"]!r}
server_name = {relay["server_name"]!r}
auth_token = {relay["auth_token"]!r}
transport_priority = {json.dumps(relay_transport_priority)}
websocket_path = {relay.get("websocket_path", "/aegis/ws")!r}
grpc_path = {relay.get("grpc_path", "/aegis.tunnel.v1.TunnelService/Open")!r}
masque_path = {relay.get("masque_path", "/.well-known/masque/udp")!r}
ca_cert = {relay["ca_cert"]!r}
connect_timeout_ms = {relay.get("connect_timeout_ms", 5000)!r}

[relay.policy]
rotate_transports_per_session = {toml_bool(policy.get("rotate_transports_per_session", True))}
max_transport_attempts = {policy.get("max_transport_attempts", 4)!r}
write_chunk_size = {chunk_size!r}
inter_chunk_delay_ms = {policy.get("inter_chunk_delay_ms", 0)!r}
drift_epoch_secs = 1
""",
    encoding="utf-8",
)
PY
}

run_relay_socks_probe() {
  local socks_port="$1"
  local target_host="$2"
  local target_port="$3"
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- socks-http-probe \
    --socks-port "${socks_port}" \
    --target-host "${target_host}" \
    --target-port "${target_port}"
}

rm -f "${REMOTE_OUTPUT_JSONL}" "${REMOTE_LOG_PATH}"
touch "${REMOTE_OUTPUT_JSONL}" "${REMOTE_LOG_PATH}"
scenario_index=0
for chunk_size in 16384 12288 8192 6144 32768 10240; do
  scenario_socks_port="$((REMOTE_SOCKS_PORT + scenario_index))"
  scenario_target_port="$((TARGET_PORT + scenario_index))"
  scenario_config="${REMOTE_TEMP_CONFIG}.${scenario_index}.toml"
  scenario_jsonl="${REMOTE_OUTPUT_JSONL}.${scenario_index}.jsonl"
  scenario_log="${REMOTE_OUTPUT_JSONL%.jsonl}.${scenario_index}.log"
  write_relay_temp_config "${scenario_config}" "${scenario_socks_port}" "${chunk_size}"

  rm -f "${scenario_jsonl}" "${scenario_log}"
  (timeout 20s "${client_bin}" --config "${scenario_config}" --runtime-events-jsonl "${scenario_jsonl}" >"${scenario_log}" 2>&1) &
  pid=$!

  for _ in $(seq 1 20); do
    if ss -ltn | awk -v port=":${scenario_socks_port}$" '$4 ~ port { found=1 } END { exit found ? 0 : 1 }'; then
      break
    fi
    sleep 1
  done

  run_relay_socks_probe "${scenario_socks_port}" "${TARGET_HOST}" "${scenario_target_port}"

  sleep 2
  wait "${pid}" || true
  if [[ -s "${scenario_jsonl}" ]]; then
    cat "${scenario_jsonl}" >> "${REMOTE_OUTPUT_JSONL}"
  fi
  if [[ -s "${scenario_log}" ]]; then
    {
      printf '\n===== relay scenario %s chunk=%s target=%s:%s =====\n' \
        "${scenario_index}" "${chunk_size}" "${TARGET_HOST}" "${scenario_target_port}"
      cat "${scenario_log}"
    } >> "${REMOTE_LOG_PATH}"
  fi
  scenario_index="$((scenario_index + 1))"
done
EOF
  chmod +x "${temp_script}"
  trap 'rm -f "${temp_script}"' RETURN
  # Same resilience pattern as harvest_transient_direct_wire_active_runtime:
  # remote workload may fail (transient relay handshake reset, stale binary,
  # network blip), but we still want to scp whatever partial artifact exists
  # so the downstream wire acceptance helper surfaces the gap via its normal
  # machinery instead of being eaten by `set -e`.
  local workload_rc=0
  run_ssh_file "${host}" "${port}" "${temp_script}" \
    "${remote_client_config}" \
    "${remote_output_jsonl}" \
    "${remote_temp_config}" \
    1180 \
    "${target_host}" \
    "${target_port}" \
    "${relay_transport_priority}" || workload_rc=$?
  run_scp_from_remote "${host}" "${port}" "${remote_output_jsonl}" "${local_output_jsonl}" || true
  if [[ ! -s "${local_output_jsonl}" ]]; then
    : > "${local_output_jsonl}"
  fi
  if [[ "${workload_rc}" -ne 0 ]]; then
    printf '[warn] transient relay wire workload exited with rc=%s; harvesting partial artifact so wire acceptance surfaces the gap instead of crashing the audit\n' "${workload_rc}" >&2
  fi
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- warn-runtime-event-presence \
    --runtime-events "${local_output_jsonl}" \
    --event-code "relay_session_started" \
    --empty-warning "[warn] transient relay wire runtime artifact ${local_output_jsonl} is empty: letting wire acceptance surface the gap downstream" \
    --missing-warning "[warn] transient relay runtime missing relay_session_started: letting wire acceptance surface the gap downstream"
  rm -f "${temp_script}"
  trap - RETURN
}

start_remote_http_target() {
  local host="$1"
  local port="$2"
  local listen_port="$3"
  local pid_path="$4"
  local log_path="$5"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] ssh -p %s %s %s\n' "${port}" "$(remote_spec "${host}")" \
      "$(printf '%q' "nohup python3 -m http.server ${listen_port} --bind 0.0.0.0 > ${log_path} 2>&1 < /dev/null & echo \$! > ${pid_path}")"
    return 0
  fi
  run_ssh "${host}" "${port}" "rm -f '${pid_path}' '${log_path}'; nohup python3 -m http.server ${listen_port} --bind 0.0.0.0 > '${log_path}' 2>&1 < /dev/null & echo \$! > '${pid_path}'"
  run_ssh "${host}" "${port}" "python3 - '${listen_port}' <<'PY'
import socket
import sys
import time

listen_port = int(sys.argv[1])
for _ in range(30):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect(('127.0.0.1', listen_port))
            raise SystemExit(0)
        except OSError:
            time.sleep(0.5)
raise SystemExit('temporary HTTP target did not start')
PY"
}

stop_remote_http_target() {
  local host="$1"
  local port="$2"
  local pid_path="$3"
  local log_path="$4"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] ssh -p %s %s %s\n' "${port}" "$(remote_spec "${host}")" \
      "$(printf '%q' "if [ -f '${pid_path}' ]; then kill \$(cat '${pid_path}') >/dev/null 2>&1 || true; fi; rm -f '${pid_path}' '${log_path}'")"
    return 0
  fi
  run_ssh "${host}" "${port}" "if [ -f '${pid_path}' ]; then kill \$(cat '${pid_path}') >/dev/null 2>&1 || true; fi; rm -f '${pid_path}' '${log_path}'"
}

start_remote_client_pcap_capture() {
  if [[ -z "${REMOTE_CLIENT_PCAP}" || -z "${REMOTE_CLIENT_PCAP_INTERFACE}" ]]; then
    return 0
  fi
  local remote_stdout="${REMOTE_CLIENT_PCAP}.stdout.log"
  local remote_stderr="${REMOTE_CLIENT_PCAP}.stderr.log"
  local remote_pid="${REMOTE_CLIENT_PCAP}.pid"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] ssh -p %s %s %s\n' "${CLIENT_PORT}" "$(remote_spec "${CLIENT_HOST}")" \
      "$(printf '%q' "tcpdump -i '${REMOTE_CLIENT_PCAP_INTERFACE}' -s 0 -w '${REMOTE_CLIENT_PCAP}' 'tcp and host ${SERVER_HOST}'")"
    return 0
  fi
  run_ssh "${CLIENT_HOST}" "${CLIENT_PORT}" "set -euo pipefail; command -v tcpdump >/dev/null; rm -f '${REMOTE_CLIENT_PCAP}' '${remote_stdout}' '${remote_stderr}' '${remote_pid}'; nohup tcpdump -i '${REMOTE_CLIENT_PCAP_INTERFACE}' -s 0 -w '${REMOTE_CLIENT_PCAP}' 'tcp and host ${SERVER_HOST}' >'${remote_stdout}' 2>'${remote_stderr}' & echo \$! > '${remote_pid}'; sleep 1; kill -0 \$(cat '${remote_pid}')"
}

stop_remote_client_pcap_capture() {
  if [[ -z "${REMOTE_CLIENT_PCAP}" || -z "${REMOTE_CLIENT_PCAP_INTERFACE}" ]]; then
    return 0
  fi
  local remote_pid="${REMOTE_CLIENT_PCAP}.pid"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] ssh -p %s %s %s\n' "${CLIENT_PORT}" "$(remote_spec "${CLIENT_HOST}")" \
      "$(printf '%q' "kill -INT \$(cat '${remote_pid}') && test -s '${REMOTE_CLIENT_PCAP}'")"
    return 0
  fi
  run_ssh "${CLIENT_HOST}" "${CLIENT_PORT}" "set -euo pipefail; if [[ -f '${remote_pid}' ]]; then pid=\$(cat '${remote_pid}'); kill -INT \"\${pid}\" >/dev/null 2>&1 || true; for _ in \$(seq 1 20); do kill -0 \"\${pid}\" >/dev/null 2>&1 || break; sleep 0.5; done; rm -f '${remote_pid}'; fi; test -s '${REMOTE_CLIENT_PCAP}'"
}

start_remote_active_probe_target() {
  local host="$1"
  local port="$2"
  local listen_port="$3"
  local pid_path="$4"
  local log_path="$5"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] ssh -p %s %s %s\n' "${port}" "$(remote_spec "${host}")" \
      "$(printf '%q' "rm -f '${pid_path}' '${log_path}'; python3 active-probe-target ${listen_port} > '${log_path}' 2>&1 < /dev/null & echo \$! > '${pid_path}'")"
    return 0
  fi
  run_ssh "${host}" "${port}" "rm -f '${pid_path}' '${log_path}'; python3 - '${listen_port}' > '${log_path}' 2>&1 < /dev/null <<'PY' &
import socket
import sys
import threading
import time

listen_port = int(sys.argv[1])
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(('0.0.0.0', listen_port))
listener.listen(8)
listener.settimeout(8)
attempt = 0
idle = 0

def handle(conn, attempt_index):
    with conn:
        conn.settimeout(2)
        try:
            data = conn.recv(4096)
        except OSError:
            data = b''
        if not data:
            return
        if attempt_index == 0:
            time.sleep(5)
            return
        try:
            conn.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\nprobe!')
        except OSError:
            pass

while attempt < 6 and idle < 2:
    try:
        conn, _ = listener.accept()
    except socket.timeout:
        idle += 1
        continue
    idle = 0
    threading.Thread(target=handle, args=(conn, attempt), daemon=True).start()
    attempt += 1
listener.close()
PY
echo \$! > '${pid_path}'"
  run_ssh "${host}" "${port}" "for _ in \$(seq 1 30); do ss -ltn | awk -v port=':${listen_port}\$' '\$4 ~ port { found=1 } END { exit found ? 0 : 1 }' && exit 0; sleep 0.5; done; echo 'temporary active probe target did not start' >&2; exit 1"
}

harvest_transient_direct_wire_active_runtime() {
  local server_host="$1"
  local server_port="$2"
  local client_host="$3"
  local client_port="$4"
  local remote_client_config="$5"
  local remote_output_jsonl="$6"
  local remote_temp_config="$7"
  local local_output_jsonl="$8"
  local target_host="$9"
  local target_port="${10}"
  local remote_server_pid_path="/tmp/aegis-live-audit-direct-target.pid"
  local remote_server_log_path="/tmp/aegis-live-audit-direct-target.log"
  local temp_script=""
  temp_script="$(mktemp "${TMPDIR:-/tmp}/aegis-transient-direct-wire.XXXXXX")"
  cat > "${temp_script}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

REMOTE_CLIENT_CONFIG="$1"
REMOTE_OUTPUT_JSONL="$2"
REMOTE_TEMP_CONFIG="$3"
REMOTE_SOCKS_PORT="${4:-1181}"
TARGET_HOST="${5:-127.0.0.1}"
TARGET_PORT="${6:-18080}"
REMOTE_LOG_PATH="${REMOTE_OUTPUT_JSONL%.jsonl}.log"
REMOTE_DISABLED_CONFIG="${REMOTE_TEMP_CONFIG}.disabled"

client_bin="$(command -v aegis-client || true)"
if [[ -z "${client_bin}" ]]; then
  echo "remote aegis-client binary is missing" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "remote python3 is required for transient direct config generation" >&2
  exit 1
fi

python3 - "${REMOTE_CLIENT_CONFIG}" "${REMOTE_TEMP_CONFIG}" "${REMOTE_SOCKS_PORT}" "linux_experimental_ttl_preface" <<'PY'
import sys
import tomllib
from pathlib import Path

source = Path(sys.argv[1])
dest = Path(sys.argv[2])
socks_port = int(sys.argv[3])
wire_mode = sys.argv[4]
cfg = tomllib.loads(source.read_text(encoding="utf-8"))
direct = cfg.get("direct", {})

dest.write_text(
    f"""mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[ingress.wide]
enabled = false
platform_backend = "auto"
rollout_profile = "output_only_safe"
listen = "127.0.0.1:15081"
capture_dns = false
udp_capture_contract = "preview_allowlist_only"
dns_port = 53
udp_preview_ports = []
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = {direct.get("state_path", "~/.cache/aegis/state.json")!r}
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 300
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
stack_profile = "linux"
wire_mimicry_mode = {wire_mode!r}
""",
    encoding="utf-8",
)
PY
python3 - "${REMOTE_CLIENT_CONFIG}" "${REMOTE_DISABLED_CONFIG}" "${REMOTE_SOCKS_PORT}" "disabled" <<'PY'
import sys
import tomllib
from pathlib import Path

source = Path(sys.argv[1])
dest = Path(sys.argv[2])
socks_port = int(sys.argv[3])
wire_mode = sys.argv[4]
cfg = tomllib.loads(source.read_text(encoding="utf-8"))
direct = cfg.get("direct", {})

dest.write_text(
    f"""mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[ingress.wide]
enabled = false
platform_backend = "auto"
rollout_profile = "output_only_safe"
listen = "127.0.0.1:15081"
capture_dns = false
udp_capture_contract = "preview_allowlist_only"
dns_port = 53
udp_preview_ports = []
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = {direct.get("state_path", "~/.cache/aegis/state.json")!r}
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 300
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
stack_profile = "linux"
wire_mimicry_mode = {wire_mode!r}
""",
    encoding="utf-8",
)
PY

rm -f "${REMOTE_OUTPUT_JSONL}" "${REMOTE_LOG_PATH}"
timeout 20s "${client_bin}" \
  --config "${REMOTE_DISABLED_CONFIG}" \
  --runtime-events-jsonl "${REMOTE_OUTPUT_JSONL}" \
  --direct-active-probe-evidence "${TARGET_HOST}:${TARGET_PORT}" \
  --json >"${REMOTE_LOG_PATH}" 2>&1 || true
timeout 20s "${client_bin}" \
  --config "${REMOTE_TEMP_CONFIG}" \
  --runtime-events-jsonl "${REMOTE_OUTPUT_JSONL}" \
  --direct-active-probe-evidence "${TARGET_HOST}:${TARGET_PORT}" \
  --json >>"${REMOTE_LOG_PATH}" 2>&1 || true
EOF
  chmod +x "${temp_script}"
  start_remote_http_target "${server_host}" "${server_port}" "${target_port}" "${remote_server_pid_path}" "${remote_server_log_path}"
  trap 'stop_remote_http_target "'"${server_host}"'" "'"${server_port}"'" "'"${remote_server_pid_path}"'" "'"${remote_server_log_path}"'"; rm -f "'"${temp_script}"'"' RETURN
  # Run the remote workload. The ssh wrapper is allowed to fail here (stale
  # deployed binary may not reach direct_session_succeeded yet); we keep going
  # so the downstream scp + diagnostic check still run and so the partial
  # artifact is preserved for wire acceptance triage instead of being eaten by
  # `set -e`.
  local workload_rc=0
  run_ssh_file "${client_host}" "${client_port}" "${temp_script}" \
    "${remote_client_config}" \
    "${remote_output_jsonl}" \
    "${remote_temp_config}" \
    1181 \
    "${target_host}" \
    "${target_port}" || workload_rc=$?
  # The remote log path mirrors the jsonl path with .log suffix (see inner
  # script). Best-effort harvest keeps it for operator triage even when the
  # workload itself failed on the remote.
  local remote_log_path="${remote_output_jsonl%.jsonl}.log"
  local local_log_path="${local_output_jsonl%.jsonl}.log"
  run_scp_from_remote "${client_host}" "${client_port}" "${remote_output_jsonl}" "${local_output_jsonl}" || true
  run_scp_from_remote "${client_host}" "${client_port}" "${remote_log_path}" "${local_log_path}" || true
  if [[ ! -s "${local_output_jsonl}" ]]; then
    # Ensure a placeholder exists so compose_wire_helper_runtime_events does
    # not FileNotFoundError and so wire acceptance can surface the gap via its
    # normal machinery instead of hiding the run failure behind a bash trap.
    : > "${local_output_jsonl}"
  fi
  if [[ "${workload_rc}" -ne 0 ]]; then
    printf '[warn] transient direct wire active workload exited with rc=%s; harvesting partial artifact so wire acceptance surfaces the gap instead of crashing the audit\n' "${workload_rc}" >&2
  fi
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- warn-runtime-event-presence \
    --runtime-events "${local_output_jsonl}" \
    --event-code "direct_session_succeeded" \
    --field-bool "mimicry_capability_wire_active" \
    --empty-warning "[warn] transient direct wire active runtime artifact ${local_output_jsonl} is empty: letting wire acceptance surface the gap downstream" \
    --missing-warning "[warn] transient direct runtime missing active direct_session_succeeded; wire acceptance will stay red until the deployed aegis-client emits this event"
  stop_remote_http_target "${server_host}" "${server_port}" "${remote_server_pid_path}" "${remote_server_log_path}"
  rm -f "${temp_script}"
  trap - RETURN
}

compose_wire_helper_runtime_events() {
  local baseline_runtime="$1"
  local transient_runtime="$2"
  local active_runtime="$3"
  local helper_runtime="$4"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] aegis-measure concat-text-files %s %s %s > %s\n' \
      "${baseline_runtime}" "${transient_runtime}" "${active_runtime}" "${helper_runtime}"
    return 0
  fi
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- concat-text-files \
    --output "${helper_runtime}" \
    --input "${baseline_runtime}" \
    --input "${transient_runtime}" \
    --input "${active_runtime}"
}

if [[ "${DRY_RUN}" -eq 0 ]]; then
  require_local_tool "${SSH_BIN}"
  require_local_tool "${SCP_BIN}"
fi

mkdir -p "${CLIENT_ARTIFACT_DIR}" "${SERVER_ARTIFACT_DIR}"

RERUN_COMMAND="$(build_rerun_command)"
REVIEW_SUMMARY_COMMAND="$(quote_args sed -n '1,160p' "${LOCAL_SUMMARY_MD}")"
REVIEW_MANIFEST_COMMAND="$(quote_args cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- pretty-json --input "${LOCAL_MANIFEST}")"
REVIEW_HANDOFF_STATUS_COMMAND="$(quote_args cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- pretty-json --input "${LOCAL_HANDOFF_STATUS_JSON}")"
if [[ "${SKIP_REDEPLOY}" -eq 1 ]]; then
  step "Skip redeploy and reuse current remote install state"
else
  step "Redeploy server and client from a clean purge"
  redeploy_args=(
    --server-host "${SERVER_HOST}"
    --client-host "${CLIENT_HOST}"
    --ssh-user "${SSH_USER}"
    --server-port "${SERVER_PORT}"
    --client-port "${CLIENT_PORT}"
    --server-name "${SERVER_NAME}"
    --relay-address "${RELAY_ADDRESS}"
    --bootstrap-url "${BOOTSTRAP_URL}"
  )
  if [[ -n "${SERVER_PRIVATE_KEY_PATH}" ]]; then
    redeploy_args+=(--server-private-key-path "${SERVER_PRIVATE_KEY_PATH}")
  fi
  if [[ -n "${CLIENT_PRIVATE_KEY_PATH}" ]]; then
    redeploy_args+=(--client-private-key-path "${CLIENT_PRIVATE_KEY_PATH}")
  fi
  if [[ -n "${MANIFEST_URL}" ]]; then
    redeploy_args+=(--manifest-url "${MANIFEST_URL}")
  fi
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    redeploy_args+=(--dry-run)
  fi
  bash "${REDEPLOY_SCRIPT}" "${redeploy_args[@]}"
fi

if [[ -n "${SERVER_AUDIT_SCRIPT}" ]]; then
  step "Run server live audit script"
  run_ssh_file "${SERVER_HOST}" "${SERVER_PORT}" "${SERVER_AUDIT_SCRIPT}" "${OUTPUT_DIR_ABS}" "${RELAY_ADDRESS}"
fi

if [[ -n "${CLIENT_AUDIT_SCRIPT}" ]]; then
  step "Run client live audit script"
  run_ssh_file "${CLIENT_HOST}" "${CLIENT_PORT}" "${CLIENT_AUDIT_SCRIPT}" "${OUTPUT_DIR_ABS}" "${RELAY_ADDRESS}"
fi

step "Collect server service artifacts"
write_remote_capture "${SERVER_HOST}" "${SERVER_PORT}" "systemctl status aegis-server.service --no-pager || true" "${LOCAL_SERVER_STATUS}"
write_remote_capture "${SERVER_HOST}" "${SERVER_PORT}" "journalctl -u aegis-server.service -n 200 --no-pager || true" "${LOCAL_SERVER_JOURNAL}"
run_scp_from_remote "${SERVER_HOST}" "${SERVER_PORT}" "${REMOTE_SERVER_CONFIG}" "${LOCAL_SERVER_CONFIG}"

step "Collect client runtime and service artifacts"
write_remote_capture "${CLIENT_HOST}" "${CLIENT_PORT}" "systemctl status aegis-client.service --no-pager || true" "${LOCAL_CLIENT_STATUS}"
write_remote_capture "${CLIENT_HOST}" "${CLIENT_PORT}" "journalctl -u aegis-client.service -n 200 --no-pager || true" "${LOCAL_CLIENT_JOURNAL}"
write_remote_capture "${CLIENT_HOST}" "${CLIENT_PORT}" "if command -v aegis-client >/dev/null 2>&1; then aegis-client --config ${REMOTE_CLIENT_CONFIG} --ingress-preflight --json || true; fi | sed -n '/^{/,\$p'" "${LOCAL_CLIENT_PREFLIGHT}"
write_remote_capture "${CLIENT_HOST}" "${CLIENT_PORT}" "if command -v aegis-client >/dev/null 2>&1; then aegis-client --config ${REMOTE_CLIENT_CONFIG} --ingress-startup-probe --json || true; fi | sed -n '/^{/,\$p'" "${LOCAL_CLIENT_STARTUP_PROBE}"
run_scp_from_remote "${CLIENT_HOST}" "${CLIENT_PORT}" "${REMOTE_CLIENT_CONFIG}" "${LOCAL_CLIENT_CONFIG}"
run_scp_from_remote "${CLIENT_HOST}" "${CLIENT_PORT}" "${REMOTE_RUNTIME_EVENTS}" "${LOCAL_RUNTIME_EVENTS}"

if [[ -n "${REMOTE_CLIENT_PCAP_INTERFACE}" ]]; then
  step "Start remote witness capture"
  start_remote_client_pcap_capture
fi

step "Harvest transient relay wire runtime"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  printf '[dry-run] transient relay runtime via %s -> %s (target %s:%s)\n' \
    "${REMOTE_TRANSIENT_RELAY_WIRE_CONFIG}" "${REMOTE_TRANSIENT_RELAY_WIRE_RUNTIME}" "${SERVER_HOST}" "18081"
else
  for relay_target_index in 0 1 2 3 4 5; do
    relay_target_port="$((18081 + relay_target_index))"
    start_remote_http_target \
      "${SERVER_HOST}" \
      "${SERVER_PORT}" \
      "${relay_target_port}" \
      "/tmp/aegis-live-audit-relay-target-${relay_target_index}.pid" \
      "/tmp/aegis-live-audit-relay-target-${relay_target_index}.log"
  done
  trap 'for relay_target_index in 0 1 2 3 4 5; do stop_remote_http_target "'"${SERVER_HOST}"'" "'"${SERVER_PORT}"'" "/tmp/aegis-live-audit-relay-target-${relay_target_index}.pid" "/tmp/aegis-live-audit-relay-target-${relay_target_index}.log"; done' RETURN
  harvest_transient_relay_wire_runtime \
    "${CLIENT_HOST}" \
    "${CLIENT_PORT}" \
    "${REMOTE_CLIENT_CONFIG}" \
    "${REMOTE_TRANSIENT_RELAY_WIRE_RUNTIME}" \
    "${REMOTE_TRANSIENT_RELAY_WIRE_CONFIG}" \
    "${LOCAL_TRANSIENT_RELAY_WIRE_RUNTIME}" \
    "${SERVER_HOST}" \
    "18081" \
    "${RELAY_TRANSPORT_PRIORITY}"
  for relay_target_index in 0 1 2 3 4 5; do
    stop_remote_http_target \
      "${SERVER_HOST}" \
      "${SERVER_PORT}" \
      "/tmp/aegis-live-audit-relay-target-${relay_target_index}.pid" \
      "/tmp/aegis-live-audit-relay-target-${relay_target_index}.log"
  done
  trap - RETURN
fi

step "Harvest transient direct wire active runtime"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  printf '[dry-run] transient direct active runtime via %s -> %s (target %s:%s)\n' \
    "${REMOTE_TRANSIENT_DIRECT_WIRE_ACTIVE_CONFIG}" "${REMOTE_TRANSIENT_DIRECT_WIRE_ACTIVE_RUNTIME}" "${SERVER_HOST}" "18080"
else
  harvest_transient_direct_wire_active_runtime \
    "${SERVER_HOST}" \
    "${SERVER_PORT}" \
    "${CLIENT_HOST}" \
    "${CLIENT_PORT}" \
    "${REMOTE_CLIENT_CONFIG}" \
    "${REMOTE_TRANSIENT_DIRECT_WIRE_ACTIVE_RUNTIME}" \
    "${REMOTE_TRANSIENT_DIRECT_WIRE_ACTIVE_CONFIG}" \
    "${LOCAL_TRANSIENT_DIRECT_WIRE_ACTIVE_RUNTIME}" \
    "${SERVER_HOST}" \
    "18080"
fi

if [[ -n "${REMOTE_CLIENT_PCAP_INTERFACE}" ]]; then
  step "Stop remote witness capture"
  stop_remote_client_pcap_capture
fi

if [[ -n "${REMOTE_CLIENT_PCAP}" ]]; then
  step "Download remote witness capture"
  run_scp_from_remote "${CLIENT_HOST}" "${CLIENT_PORT}" "${REMOTE_CLIENT_PCAP}" "${LOCAL_WITNESS_PCAP}"
fi

step "Compose wire helper runtime matrix input"
compose_wire_helper_runtime_events \
  "${LOCAL_RUNTIME_EVENTS}" \
  "${LOCAL_TRANSIENT_RELAY_WIRE_RUNTIME}" \
  "${LOCAL_TRANSIENT_DIRECT_WIRE_ACTIVE_RUNTIME}" \
  "${LOCAL_WIRE_HELPER_RUNTIME_EVENTS}"

if [[ -n "${LOCAL_WITNESS_PCAP}" ]]; then
  step "Build local witness summary from downloaded pcap"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] bash %s --pcap %s --runtime-events %s --output %s\n' \
      "${WITNESS_SCRIPT}" "${LOCAL_WITNESS_PCAP}" "${LOCAL_WIRE_HELPER_RUNTIME_EVENTS}" "${LOCAL_WITNESS_SUMMARY}"
  else
    bash "${WITNESS_SCRIPT}" \
      --pcap "${LOCAL_WITNESS_PCAP}" \
      --runtime-events "${LOCAL_WIRE_HELPER_RUNTIME_EVENTS}" \
      --output "${LOCAL_WITNESS_SUMMARY}"
  fi
fi

step "Materialize local wire acceptance summary"
wire_helper_args=(
  --run
  --runtime-events "${LOCAL_WIRE_HELPER_RUNTIME_EVENTS}"
  --artifact-dir "${CLIENT_ARTIFACT_DIR}"
  --json
)
if [[ -n "${LOCAL_WITNESS_SUMMARY}" ]]; then
  wire_helper_args+=(--witness-summary "${LOCAL_WITNESS_SUMMARY}")
fi
if [[ "${DRY_RUN}" -eq 1 ]]; then
  printf '[dry-run] bash %s %s > %s\n' \
    "${WIRE_HELPER_SCRIPT}" "$(quote_args "${wire_helper_args[@]}")" "${LOCAL_WIRE_HELPER_STDOUT}"
else
  bash "${WIRE_HELPER_SCRIPT}" "${wire_helper_args[@]}" > "${LOCAL_WIRE_HELPER_STDOUT}"
fi

step "Materialize local stealth live acceptance bundle"
stealth_bundle_args=(
  "${LOCAL_STEALTH_BUNDLE_DIR}"
  --wire-acceptance-summary "${CLIENT_ARTIFACT_DIR}/wire-host-acceptance-summary.json"
  --runtime-events "${LOCAL_RUNTIME_EVENTS}"
  --relay-runtime-events "${LOCAL_WIRE_HELPER_RUNTIME_EVENTS}"
  --config "${LOCAL_CLIENT_CONFIG}"
)
if [[ "${DRY_RUN}" -eq 1 ]]; then
  printf '[dry-run] bash %s %s\n' \
    "${STEALTH_BUNDLE_SCRIPT}" "$(quote_args "${stealth_bundle_args[@]}")"
  printf '[dry-run] stealth bundle outputs: %s %s\n' \
    "${LOCAL_STEALTH_BUNDLE_DIR}/stealth-live-acceptance-bundle.json" \
    "${LOCAL_STEALTH_BUNDLE_DIR}/stealth-live-acceptance.manifest.json"
else
  bash "${STEALTH_BUNDLE_SCRIPT}" "${stealth_bundle_args[@]}"
fi

if [[ -n "${PHASE_B_BASELINE_JSON}" ]]; then
  step "Materialize Phase B runtime evidence bundle"
  phase_b_runtime_evidence_args=(
    --baseline-json "${PHASE_B_BASELINE_JSON}"
    --runtime-events-jsonl "${LOCAL_WIRE_HELPER_RUNTIME_EVENTS}"
    --output-dir "${LOCAL_PHASE_B_RUNTIME_EVIDENCE_DIR}"
    --allow-review-failures
  )
  if [[ "${PHASE_B_RUNTIME_EVIDENCE_STRICT}" -eq 1 ]]; then
    phase_b_runtime_evidence_args+=(--require-relay-shape-diversity --require-finished-probe)
  fi
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] bash %s %s\n' \
      "${PHASE_B_RUNTIME_EVIDENCE_SCRIPT}" "$(quote_args "${phase_b_runtime_evidence_args[@]}")"
    printf '[dry-run] phase-b runtime evidence outputs: %s %s\n' \
      "${LOCAL_PHASE_B_RUNTIME_EVIDENCE_DIR}/phase-b-runtime-evidence.manifest.json" \
      "${LOCAL_PHASE_B_RUNTIME_EVIDENCE_DIR}/phase-b-master-plan-status.json"
  else
    bash "${PHASE_B_RUNTIME_EVIDENCE_SCRIPT}" "${phase_b_runtime_evidence_args[@]}"
  fi
fi

step "Write local audit manifest"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  printf '[dry-run] write manifest to %s\n' "${LOCAL_MANIFEST}"
  printf '[dry-run] write summary to %s\n' "${LOCAL_SUMMARY_MD}"
  printf '[dry-run] write handoff status to %s\n' "${LOCAL_HANDOFF_STATUS_JSON}"
  printf '[dry-run] manifest will link markdown summary %s\n' "${LOCAL_SUMMARY_MD}"
  printf '[dry-run] rerun command: %s\n' "${RERUN_COMMAND}"
  printf '[dry-run] review summary command: %s\n' "${REVIEW_SUMMARY_COMMAND}"
  printf '[dry-run] review manifest command: %s\n' "${REVIEW_MANIFEST_COMMAND}"
  printf '[dry-run] review handoff status command: %s\n' "${REVIEW_HANDOFF_STATUS_COMMAND}"
  printf '[dry-run] manifest will publish blocker-aware next action commands\n'
  printf '[dry-run] manifest will publish next action artifact paths\n'
  printf '[dry-run] manifest will publish unified next_action object\n'
  printf '[dry-run] manifest will publish compact next_action context\n'
  printf '[dry-run] manifest will publish canonical operator handoff object\n'
  printf '[dry-run] manifest will summarize wire acceptance from %s\n' \
    "${LOCAL_WIRE_ACCEPTANCE_SUMMARY}"
  printf '[dry-run] manifest will summarize stealth bundle from %s\n' \
    "${LOCAL_STEALTH_BUNDLE_DIR}/stealth-live-acceptance-bundle.json"
  if [[ -n "${PHASE_B_BASELINE_JSON}" ]]; then
    printf '[dry-run] phase-b master plan status will be written to %s\n' \
      "${LOCAL_PHASE_B_RUNTIME_EVIDENCE_DIR}/phase-b-master-plan-status.json"
  fi
else
  bash "${MANIFEST_HELPER_SCRIPT}" \
    --manifest "${LOCAL_MANIFEST}" \
    --output-dir "${OUTPUT_DIR_ABS}" \
    --server-host "${SERVER_HOST}" \
    --client-host "${CLIENT_HOST}" \
    --relay-address "${RELAY_ADDRESS}" \
    --runtime-events "${LOCAL_RUNTIME_EVENTS}" \
    --preflight "${LOCAL_CLIENT_PREFLIGHT}" \
    --startup-probe "${LOCAL_CLIENT_STARTUP_PROBE}" \
    --wire-helper-stdout "${LOCAL_WIRE_HELPER_STDOUT}" \
    --witness-summary "${LOCAL_WITNESS_SUMMARY}" \
    --witness-pcap "${LOCAL_WITNESS_PCAP}" \
    --transient-runtime-events "${LOCAL_TRANSIENT_RELAY_WIRE_RUNTIME}" \
    --wire-helper-runtime-events "${LOCAL_WIRE_HELPER_RUNTIME_EVENTS}" \
    --wire-acceptance-summary "${LOCAL_WIRE_ACCEPTANCE_SUMMARY}" \
    --stealth-live-acceptance-bundle "${LOCAL_STEALTH_BUNDLE_DIR}/stealth-live-acceptance-bundle.json" \
    --stealth-live-acceptance-manifest "${LOCAL_STEALTH_BUNDLE_DIR}/stealth-live-acceptance.manifest.json" \
    --rerun-command "${RERUN_COMMAND}" \
    --review-summary-command "${REVIEW_SUMMARY_COMMAND}" \
    --review-manifest-command "${REVIEW_MANIFEST_COMMAND}" \
    --handoff-status-json "${LOCAL_HANDOFF_STATUS_JSON}"
  bash "${HANDOFF_STATUS_SCRIPT}" \
    --manifest "${LOCAL_MANIFEST}" \
    --output "${LOCAL_HANDOFF_STATUS_JSON}"
fi

step "Linux wide mimicry live audit flow completed"
