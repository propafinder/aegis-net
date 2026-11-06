#!/usr/bin/env bash
# Exact-binary live proof for the non-direct rows of the Geneva hybrid route.
#
# The runner derives a temporary strict hybrid config from an existing
# root-owned client config without printing or copying its auth token into the
# artifact. It exercises real authenticated gRPC traffic and one fail-closed
# relay outage. Direct hostile-path wire behavior is covered separately by
# run-geneva-hostile-netns-live.sh.
set -euo pipefail
umask 077

CLIENT_BIN=""
SOURCE_CONFIG=""
AUTH_TOKEN_CONFIG=""
CA_CERT=""
RELAY_SERVER=""
RELAY_SERVER_NAME=""
MASQUE_SERVER=""
MASQUE_SERVER_NAME=""
MASQUE_CA=""
OUT_DIR=""

usage() {
  cat >&2 <<'EOF'
usage: run-geneva-hybrid-relay-live.sh \
  --client-bin PATH --source-config PATH --ca-cert PATH \
  [--auth-token-config ROOT_ONLY_SERVER_CONFIG] \
  [--relay-server HOST:PORT --relay-server-name NAME] \
  --masque-server HOST:PORT --masque-server-name NAME --masque-ca PATH \
  --out-dir DIR
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --client-bin) CLIENT_BIN="$2"; shift 2 ;;
    --source-config) SOURCE_CONFIG="$2"; shift 2 ;;
    --auth-token-config) AUTH_TOKEN_CONFIG="$2"; shift 2 ;;
    --ca-cert) CA_CERT="$2"; shift 2 ;;
    --relay-server) RELAY_SERVER="$2"; shift 2 ;;
    --relay-server-name) RELAY_SERVER_NAME="$2"; shift 2 ;;
    --masque-server) MASQUE_SERVER="$2"; shift 2 ;;
    --masque-server-name) MASQUE_SERVER_NAME="$2"; shift 2 ;;
    --masque-ca) MASQUE_CA="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: one case deliberately drops Linux capabilities" >&2
  exit 2
fi
for required in "${CLIENT_BIN}" "${SOURCE_CONFIG}" "${CA_CERT}" "${MASQUE_CA}"; do
  [[ -f "${required}" ]] || { echo "missing input: ${required}" >&2; exit 2; }
done
[[ -x "${CLIENT_BIN}" && -n "${MASQUE_SERVER}" && -n "${MASQUE_SERVER_NAME}" && -n "${OUT_DIR}" ]] || {
  usage
  exit 2
}
for tool in curl python3 sha256sum ss setpriv stat; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "missing tool: ${tool}" >&2; exit 2; }
done

CLIENT_BIN="$(readlink -f "${CLIENT_BIN}")"
SOURCE_CONFIG="$(readlink -f "${SOURCE_CONFIG}")"
if [[ -n "${AUTH_TOKEN_CONFIG}" ]]; then
  AUTH_TOKEN_CONFIG="$(readlink -f "${AUTH_TOKEN_CONFIG}")"
  [[ -f "${AUTH_TOKEN_CONFIG}" ]] || { echo "missing auth token config" >&2; exit 2; }
fi
CA_CERT="$(readlink -f "${CA_CERT}")"
MASQUE_CA="$(readlink -f "${MASQUE_CA}")"
mkdir -p "${OUT_DIR}"
OUT_DIR="$(readlink -f "${OUT_DIR}")"
chmod 0700 "${OUT_DIR}"
work_dir="$(mktemp -d /tmp/aegis-hybrid-relay-live.XXXXXX)"
# The capability-drop case keeps UID 0 but loses the complete capability set.
# Each child remains mode 0700, so configs/tokens are not listable or readable
# by unrelated users.
chmod 0711 "${work_dir}"
client_pid=""

cleanup() {
  set +e
  if [[ -n "${client_pid}" ]]; then
    kill "${client_pid}" 2>/dev/null || true
    wait "${client_pid}" 2>/dev/null || true
    client_pid=""
  fi
  if [[ -n "${work_dir}" && "${work_dir}" == /tmp/aegis-hybrid-relay-live.* ]]; then
    rm -rf -- "${work_dir}"
  fi
}
trap cleanup EXIT INT TERM

date -u +'%Y-%m-%dT%H:%M:%SZ' >"${OUT_DIR}/started-at-utc.txt"
uname -a >"${OUT_DIR}/host-uname.txt"
if [[ -r /etc/os-release ]]; then
  cp /etc/os-release "${OUT_DIR}/host-os-release.txt"
fi
"${CLIENT_BIN}" --version >"${OUT_DIR}/client-version.txt"
sha256sum "${CLIENT_BIN}" >"${OUT_DIR}/client-binary.sha256"
stat -c '%a %U:%G' "${SOURCE_CONFIG}" >"${OUT_DIR}/source-config-mode.txt"

next_port=$((22000 + ($$ % 10000)))
suite_failed=0

make_case_config() {
  local case_dir="$1" port="$2" state_path="$3" relay_override="$4" server_name_override="$5"
  cp "${CA_CERT}" "${case_dir}/ca.pem"
  cp "${MASQUE_CA}" "${case_dir}/masque-ca.pem"
  chmod 0600 "${case_dir}/ca.pem" "${case_dir}/masque-ca.pem"
  python3 - "${SOURCE_CONFIG}" "${AUTH_TOKEN_CONFIG}" "${case_dir}/client.toml" "${state_path}" "${port}" \
    "${case_dir}/ca.pem" "${MASQUE_SERVER}" "${MASQUE_SERVER_NAME}" \
    "${case_dir}/masque-ca.pem" "${relay_override}" "${server_name_override}" <<'PY'
from pathlib import Path
import re
import sys

(source_path, auth_token_path, output_path, state_path, port, ca_cert, masque_server,
 masque_server_name, masque_ca, relay_override, server_name_override) = sys.argv[1:]
text = Path(source_path).read_text(encoding="utf-8")
auth_text = Path(auth_token_path).read_text(encoding="utf-8") if auth_token_path else text

def auth_token_for_section(config_text, wanted_section):
    section = None
    for line in config_text.splitlines():
        section_match = re.match(r'^\s*\[([^]]+)\]\s*(?:#.*)?$', line)
        if section_match:
            section = section_match.group(1).strip()
            continue
        auth_match = re.match(r'^\s*auth_token\s*=\s*"([^"]+)"', line)
        if auth_match and section == wanted_section:
            return auth_match.group(1)
    return None

# A server config carries the tunnel credential at TOML top level. A client
# config also contains a local SOCKS password before [relay], so a global
# first-match regex would silently select the wrong secret and rate-limit the
# live client's source IP at every relay.
wanted_section = None if auth_token_path else "relay"
auth_token = auth_token_for_section(auth_text, wanted_section)
if not auth_token:
    location = "top level" if auth_token_path else "[relay]"
    raise SystemExit(f"auth token source has no {location} auth_token")
lines = text.splitlines()
try:
    relay_start = next(i for i, line in enumerate(lines) if line.strip() == "[relay]")
except StopIteration as exc:
    raise SystemExit("source config has no [relay] section") from exc

relay = []
skip_array = False
array_depth = 0
inserted = False
override_keys = {
    "server", "server_name", "transport_priority", "udp_transport_priority",
    "auth_token", "ca_cert", "masque_server", "masque_server_name", "masque_ca_cert", "endpoints",
}

def insert_overrides():
    nonlocal_insert = [
        f'transport_priority = ["grpc_stream"]',
        f'udp_transport_priority = ["masque_derived", "grpc_datagram"]',
        f'ca_cert = {ca_cert!r}',
        f'masque_server = {masque_server!r}',
        f'masque_server_name = {masque_server_name!r}',
        f'masque_ca_cert = {masque_ca!r}',
    ]
    return nonlocal_insert

for line in lines[relay_start:]:
    stripped = line.strip()
    if skip_array:
        array_depth += line.count("[") - line.count("]")
        if array_depth <= 0:
            skip_array = False
        continue
    if stripped == "[relay.policy]" and not inserted:
        relay.extend(insert_overrides())
        inserted = True
    match = re.match(r"^([A-Za-z0-9_]+)\s*=", stripped)
    if match and match.group(1) in override_keys:
        if match.group(1) == "endpoints" and "[" in line and "]" not in line:
            skip_array = True
            array_depth = line.count("[") - line.count("]")
        continue
    relay.append(line)
if not inserted:
    relay.extend(insert_overrides())

# Reinsert the selected relay authority after removing the source keys. The
# auth_token line is carried from the source section and never printed.
server = relay_override
server_name = server_name_override
if not server or not server_name:
    for line in lines[relay_start:]:
        match = re.match(r'^\s*(server|server_name)\s*=\s*"([^"]+)"', line)
        if not match:
            continue
        if match.group(1) == "server" and not server:
            server = match.group(2)
        if match.group(1) == "server_name" and not server_name:
            server_name = match.group(2)
if not server or not server_name:
    raise SystemExit("relay server/server_name missing")
relay.insert(1, f'server_name = {server_name!r}')
relay.insert(1, f'server = {server!r}')
relay.insert(1, f'auth_token = {auth_token!r}')

header = f'''mode = "auto"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{port}"

[direct]
state_path = {state_path!r}
strategies = ["geneva"]
geneva_strategy = '[TCP:flags:PA]-duplicate(,)-| \\/'
hybrid_geneva = true
epsilon = 0.0
first_chunk_timeout_ms = 1200
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

'''
Path(output_path).write_text(header + "\n".join(relay) + "\n", encoding="utf-8")
PY
  chmod 0600 "${case_dir}/client.toml"
}

seed_hard_classifier() {
  local state_path="$1"
  python3 - "${state_path}" <<'PY'
import json
from pathlib import Path
import sys
import time

now = int(time.time() * 1000)
state = {
    "schema_version": 2,
    "key_registry": {},
    "key_observations": {},
    "strategy_stats": {},
    "stall_probe_stats": {},
    "transport_stats": {},
    "hybrid_route_stats": {},
    "external_calibration": {
        "schema_version": 1,
        "source": "controlled-live-hard-block",
        "generated_at_unix_ms": now,
        "freshness_half_life_secs": 3600,
        "witness": [],
        "adversarial": [],
        "knowledge": [{
            "target_class": "direct_geneva",
            "region_id": "controlled-live",
            "score": 0.0,
            "confidence": 1.0,
            "hard_excluded": True,
            "fail_closed": True,
            "generated_at_unix_ms": now,
        }],
        "verdict": {"status": "controlled", "acceptance_degraded": False, "reasons": []},
    },
}
Path(sys.argv[1]).write_text(json.dumps(state), encoding="utf-8")
PY
  chmod 0600 "${state_path}"
}

wait_for_listener() {
  local port="$1"
  for _ in $(seq 1 120); do
    if ss -H -ltn | grep -q "127.0.0.1:${port}"; then
      return 0
    fi
    if ! kill -0 "${client_pid}" 2>/dev/null; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

start_client() {
  local case_dir="$1" port="$2" drop_privileges="$3"
  if [[ "${drop_privileges}" == "true" ]]; then
    # Keep UID 0 for the root-owned artifact contour but clear the capability
    # bounding set before exec. The resulting client cannot acquire
    # CAP_NET_RAW/CAP_NET_ADMIN, while SELinux does not misclassify this as an
    # sshd-domain nobody process that cannot write its own event file.
    setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
      env RUST_LOG=info "${CLIENT_BIN}" --config "${case_dir}/client.toml" \
      --runtime-events-jsonl "${case_dir}/events.jsonl" >"${case_dir}/client.log" 2>&1 &
  else
    env RUST_LOG=info "${CLIENT_BIN}" --config "${case_dir}/client.toml" \
      --runtime-events-jsonl "${case_dir}/events.jsonl" >"${case_dir}/client.log" 2>&1 &
  fi
  client_pid=$!
  wait_for_listener "${port}"
}

stop_client() {
  if [[ -n "${client_pid}" ]]; then
    kill "${client_pid}" 2>/dev/null || true
    wait "${client_pid}" 2>/dev/null || true
    client_pid=""
  fi
}

wait_for_event() {
  local events="$1" event_code="$2"
  for _ in $(seq 1 100); do
    if grep -q "\"event_code\":\"${event_code}\"" "${events}" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "${client_pid}" 2>/dev/null; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

assert_case() {
  local case_name="$1" events="$2" expected_reason="$3" expected_success="$4" curl_rc="$5" http_code="$6"
  python3 - "${events}" "${OUT_DIR}/${case_name}-result.json" "${case_name}" \
    "${expected_reason}" "${expected_success}" "${curl_rc}" "${http_code}" <<'PY'
import json
from pathlib import Path
import sys

events_path, result_path, case_name, expected_reason, expected_success, curl_rc, http_code = sys.argv[1:]
records = [json.loads(line) for line in Path(events_path).read_text(encoding="utf-8").splitlines() if line.strip()]
selected = next((r for r in records if r.get("event_code") == "hybrid_route_selected"), None)
codes = [r.get("event_code") for r in records]
success_expected = expected_success == "true"
checks = {
    "route_selected": selected is not None,
    "route_is_grpc": selected is not None and selected.get("fields", {}).get("route_family") == "relay_grpc",
    "reason_matches": selected is not None and selected.get("fields", {}).get("reason_code") == expected_reason,
    "fingerprint_present": selected is not None and len(selected.get("fields", {}).get("strategy_fingerprint", "")) == 24,
    "direct_not_attempted": "geneva_direct_attempt_started" not in codes,
    "handoff_started": "direct_relay_handoff_started" in codes,
    "curl_outcome_matches": (int(curl_rc) == 0 and http_code != "000") == success_expected,
}
if success_expected:
    checks["handoff_succeeded"] = "direct_relay_handoff_succeeded" in codes
    checks["relay_succeeded"] = "relay_session_succeeded" in codes
else:
    checks["handoff_not_succeeded"] = "direct_relay_handoff_succeeded" not in codes
    checks["session_failed"] = "ingress_session_failed" in codes
result = {
    "artifact_schema": "geneva_hybrid_relay_case_v1",
    "case": case_name,
    "status": "PASS" if all(checks.values()) else "FAIL",
    "expected_reason": expected_reason,
    "curl_rc": int(curl_rc),
    "http_code": http_code,
    "checks": checks,
    "event_codes": codes,
}
Path(result_path).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, ensure_ascii=False))
raise SystemExit(0 if result["status"] == "PASS" else 1)
PY
}

copy_safe_case_artifacts() {
  local case_name="$1" case_dir="$2"
  chown -R 0:0 "${case_dir}"
  python3 - "${SOURCE_CONFIG}" "${AUTH_TOKEN_CONFIG}" "${case_dir}" <<'PY'
from pathlib import Path
import re
import sys

source_path, auth_path, case_path = sys.argv[1:]
sources = [Path(source_path).read_text(encoding="utf-8")]
if auth_path:
    sources.append(Path(auth_path).read_text(encoding="utf-8"))
tokens = {
    match.group(1).encode()
    for source in sources
    for match in re.finditer(r'^\s*auth_token\s*=\s*"([^"]+)"', source, re.MULTILINE)
    if match.group(1)
}
if not tokens:
    raise SystemExit("source auth token missing")
case_dir = Path(case_path)
for name in ("events.jsonl", "client.log", "curl.stderr"):
    path = case_dir / name
    data = path.read_bytes() if path.exists() else b""
    if any(token in data for token in tokens):
        raise SystemExit(f"auth token leaked into {name}")
PY
  for name in events.jsonl client.log curl.stderr udp-probe.json; do
    if [[ -f "${case_dir}/${name}" ]]; then
      cp "${case_dir}/${name}" "${OUT_DIR}/${case_name}-${name}"
    fi
  done
}

assert_udp_case() {
  local case_name="$1" events="$2" probe_result="$3" target_family="$4"
  python3 - "${events}" "${probe_result}" "${OUT_DIR}/${case_name}-result.json" \
    "${case_name}" "${target_family}" <<'PY'
import json
from pathlib import Path
import sys

events_path, probe_path, result_path, case_name, target_family = sys.argv[1:]
records = [json.loads(line) for line in Path(events_path).read_text(encoding="utf-8").splitlines() if line.strip()]
probe = json.loads(Path(probe_path).read_text(encoding="utf-8"))
codes = [record.get("event_code") for record in records]
selected = next((record for record in records if record.get("event_code") == "relay_transport_selected" and record.get("fields", {}).get("relay_session_kind") == "udp_associate"), None)
succeeded = next((record for record in records if record.get("event_code") == "relay_session_succeeded" and record.get("fields", {}).get("relay_session_kind") == "udp_associate"), None)
checks = {
    "udp_probe_succeeded": probe.get("status") == "PASS",
    "target_family_matches": probe.get("target_family") == target_family,
    "dns_response_verified": probe.get("dns_response_verified") is True,
    "masque_selected": selected is not None and selected.get("fields", {}).get("transport") == "MasqueDerived",
    "relay_succeeded": succeeded is not None and succeeded.get("fields", {}).get("chosen_transport") == "MasqueDerived",
    "direct_not_attempted": "geneva_direct_attempt_started" not in codes,
    "session_not_failed": "ingress_session_failed" not in codes,
}
result = {
    "artifact_schema": "geneva_hybrid_relay_udp_case_v1",
    "case": case_name,
    "status": "PASS" if all(checks.values()) else "FAIL",
    "target_family": target_family,
    "checks": checks,
    "probe": probe,
    "event_codes": codes,
}
Path(result_path).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, ensure_ascii=False))
raise SystemExit(0 if result["status"] == "PASS" else 1)
PY
}

run_udp_probe() {
  local port="$1" target_host="$2" target_family="$3" output_path="$4"
  python3 - "${port}" "${target_host}" "${target_family}" "${output_path}" <<'PY'
import ipaddress
import json
from pathlib import Path
import socket
import struct
import sys

socks_port, target_host, target_family, output_path = sys.argv[1:]
socks_port = int(socks_port)

def recv_exact(sock, size):
    chunks = []
    left = size
    while left:
        part = sock.recv(left)
        if not part:
            raise RuntimeError("unexpected EOF from SOCKS control socket")
        chunks.append(part)
        left -= len(part)
    return b"".join(chunks)

def recv_address(sock, atyp):
    if atyp == 1:
        return str(ipaddress.ip_address(recv_exact(sock, 4)))
    if atyp == 4:
        return str(ipaddress.ip_address(recv_exact(sock, 16)))
    if atyp == 3:
        return recv_exact(sock, recv_exact(sock, 1)[0]).decode("ascii")
    raise RuntimeError(f"unsupported SOCKS address type {atyp}")

control = socket.create_connection(("127.0.0.1", socks_port), timeout=10)
control.settimeout(25)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("127.0.0.1", 0))
udp.settimeout(25)
try:
    control.sendall(b"\x05\x01\x00")
    if recv_exact(control, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS no-auth negotiation failed")
    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    head = recv_exact(control, 4)
    if head[:3] != b"\x05\x00\x00":
        raise RuntimeError(f"UDP ASSOCIATE rejected with reply {head[1]}")
    bind_host = recv_address(control, head[3])
    bind_port = struct.unpack("!H", recv_exact(control, 2))[0]
    if bind_host in ("0.0.0.0", "::"):
        bind_host = "127.0.0.1"

    query_id = 0xA3D4
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question
    target_ip = ipaddress.ip_address(target_host)
    atyp = 1 if target_ip.version == 4 else 4
    envelope = b"\x00\x00\x00" + bytes([atyp]) + target_ip.packed + struct.pack("!H", 53) + query
    udp.sendto(envelope, (bind_host, bind_port))
    response, _ = udp.recvfrom(65535)
    if len(response) < 10 or response[:3] != b"\x00\x00\x00":
        raise RuntimeError("invalid SOCKS UDP response envelope")
    offset = 4
    response_atyp = response[3]
    if response_atyp == 1:
        offset += 4
    elif response_atyp == 4:
        offset += 16
    elif response_atyp == 3:
        offset += 1 + response[4]
    else:
        raise RuntimeError(f"invalid response address type {response_atyp}")
    offset += 2
    dns = response[offset:]
    verified = len(dns) >= 12 and struct.unpack("!H", dns[:2])[0] == query_id and bool(struct.unpack("!H", dns[2:4])[0] & 0x8000)
    if not verified:
        raise RuntimeError("DNS transaction id or response bit did not verify")
    result = {
        "status": "PASS",
        "target_family": target_family,
        "target_port": 53,
        "dns_response_verified": True,
        "response_bytes": len(dns),
    }
    Path(output_path).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
finally:
    udp.close()
    control.close()
PY
}

run_udp_case() {
  local case_name="$1" target_host="$2" target_family="$3"
  local case_dir="${work_dir}/${case_name}" port="${next_port}"
  next_port=$((next_port + 1))
  mkdir -p "${case_dir}"
  chmod 0700 "${case_dir}"
  make_case_config "${case_dir}" "${port}" "${case_dir}/state" "${RELAY_SERVER}" "${RELAY_SERVER_NAME}"
  if ! start_client "${case_dir}" "${port}" false; then
    stop_client
    copy_safe_case_artifacts "${case_name}" "${case_dir}"
    record_start_failure "${case_name}" "masque_udp_${target_family}"
    suite_failed=1
    return 0
  fi
  set +e
  run_udp_probe "${port}" "${target_host}" "${target_family}" "${case_dir}/udp-probe.json" \
    >"${case_dir}/udp-probe.stdout" 2>"${case_dir}/curl.stderr"
  probe_rc=$?
  set -e
  if [[ "${probe_rc}" -eq 0 ]]; then
    wait_for_event "${case_dir}/events.jsonl" relay_session_succeeded || true
  fi
  stop_client
  copy_safe_case_artifacts "${case_name}" "${case_dir}"
  if [[ "${probe_rc}" -ne 0 || ! -f "${case_dir}/udp-probe.json" ]]; then
    record_udp_probe_failure "${case_name}" "${target_family}" "${probe_rc}"
    suite_failed=1
    return 0
  fi
  if ! assert_udp_case "${case_name}" "${case_dir}/events.jsonl" \
    "${case_dir}/udp-probe.json" "${target_family}"; then
    suite_failed=1
  fi
}

record_start_failure() {
  local case_name="$1" expected_reason="$2"
  python3 - "${OUT_DIR}/${case_name}-result.json" "${case_name}" "${expected_reason}" <<'PY'
import json
from pathlib import Path
import sys

result = {
    "artifact_schema": "geneva_hybrid_relay_case_v1",
    "case": sys.argv[2],
    "status": "FAIL",
    "expected_reason": sys.argv[3],
    "checks": {"client_started": False},
    "event_codes": [],
}
Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, ensure_ascii=False))
PY
}

record_udp_probe_failure() {
  local case_name="$1" target_family="$2" probe_rc="$3"
  python3 - "${OUT_DIR}/${case_name}-result.json" "${case_name}" "${target_family}" "${probe_rc}" <<'PY'
import json
from pathlib import Path
import sys

result = {
    "artifact_schema": "geneva_hybrid_relay_udp_case_v1",
    "case": sys.argv[2],
    "status": "FAIL",
    "target_family": sys.argv[3],
    "checks": {
        "client_started": True,
        "udp_probe_succeeded": False,
    },
    "udp_probe_rc": int(sys.argv[4]),
    "event_codes": [],
}
Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, ensure_ascii=False))
PY
}

run_tcp_case() {
  local case_name="$1" expected_reason="$2" seed_classifier="$3" drop_privileges="$4"
  local relay_override="$5" server_name_override="$6" expect_success="$7" target_url="$8"
  local case_dir="${work_dir}/${case_name}" port="${next_port}"
  next_port=$((next_port + 1))
  mkdir -p "${case_dir}"
  chmod 0700 "${case_dir}"
  make_case_config "${case_dir}" "${port}" "${case_dir}/state" "${relay_override}" "${server_name_override}"
  if [[ "${seed_classifier}" == "true" ]]; then
    seed_hard_classifier "${case_dir}/state"
  fi
  if ! start_client "${case_dir}" "${port}" "${drop_privileges}"; then
    stop_client
    copy_safe_case_artifacts "${case_name}" "${case_dir}"
    record_start_failure "${case_name}" "${expected_reason}"
    suite_failed=1
    return 0
  fi
  set +e
  # The public witness may otherwise keep the HTTP/1.1 connection alive after
  # curl has received a redirect.  The relay then has no terminal outcome to
  # classify, and the harness kills a healthy tunnel before the handoff-success
  # event can be emitted.  Require an explicitly completed witness session.
  # Keep the application witness on plain HTTP: the AlmaLinux 9 curl 7.76 TLS
  # path resets the local SOCKS socket after receiving a complete 200 response,
  # so the generic tunnel correctly reports a peer reset instead of a clean
  # terminal.  The relay leg itself remains authenticated TLS/gRPC; this target
  # exists only to provide portable, unambiguous stream-completion semantics.
  http_code="$(curl -sS --http1.1 --header 'Connection: close' --max-time 25 \
    --socks5-hostname "127.0.0.1:${port}" \
    -o /dev/null -w '%{http_code}' "${target_url}" 2>"${case_dir}/curl.stderr")"
  curl_rc=$?
  set -e
  if [[ "${expect_success}" == "true" ]]; then
    wait_for_event "${case_dir}/events.jsonl" direct_relay_handoff_succeeded || true
  else
    wait_for_event "${case_dir}/events.jsonl" ingress_session_failed || true
  fi
  stop_client
  copy_safe_case_artifacts "${case_name}" "${case_dir}"
  if ! assert_case "${case_name}" "${case_dir}/events.jsonl" "${expected_reason}" \
    "${expect_success}" "${curl_rc}" "${http_code}"; then
    suite_failed=1
  fi
}

ipv4_target='http://1.1.1.1/cdn-cgi/trace'
run_tcp_case external_classifier_hard_block external_classifier_hard_block true false \
  "${RELAY_SERVER}" "${RELAY_SERVER_NAME}" true "${ipv4_target}"
run_tcp_case raw_capability_missing direct_capability_unavailable false true \
  "${RELAY_SERVER}" "${RELAY_SERVER_NAME}" true "${ipv4_target}"
run_tcp_case ipv6_relay_policy ipv6_relay_policy false false \
  "${RELAY_SERVER}" "${RELAY_SERVER_NAME}" true 'http://[2606:4700:4700::1111]/'
run_tcp_case relay_unavailable_fail_closed external_classifier_hard_block true false \
  '127.0.0.1:9' 'localhost' false "${ipv4_target}"
run_udp_case masque_udp_ipv4 '1.1.1.1' ipv4
run_udp_case masque_udp_ipv6 '2606:4700:4700::1111' ipv6

final_status=0
python3 - "${OUT_DIR}" <<'PY' || final_status=$?
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
cases = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(root.glob("*-result.json"))]
result = {
    "artifact_schema": "geneva_hybrid_relay_live_v1",
    "status": "PASS" if len(cases) == 6 and all(case["status"] == "PASS" for case in cases) else "FAIL",
    "boundary": "real authenticated relay paths plus controlled local relay outage; direct hostile path is a separate artifact",
    "provenance": {
        "client_version": (root / "client-version.txt").read_text(encoding="utf-8").strip(),
        "client_sha256": (root / "client-binary.sha256").read_text(encoding="utf-8").split()[0],
        "host_uname": (root / "host-uname.txt").read_text(encoding="utf-8").strip(),
    },
    "cases": cases,
}
(root / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, ensure_ascii=False))
raise SystemExit(0 if result["status"] == "PASS" else 1)
PY

(
  cd "${OUT_DIR}"
  sha256sum *-events.jsonl *-result.json result.json >sha256sums.txt
)
[[ "${suite_failed}" -eq 0 && "${final_status}" -eq 0 ]]
echo "PASS: hybrid relay live artifact written to ${OUT_DIR}"
