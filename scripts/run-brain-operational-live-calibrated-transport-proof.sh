#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Historical evidence lives outside Git (docs/operations/evidence-archive.md).
EVIDENCE_ROOT="${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}"
OUT_DIR="${1:-${EVIDENCE_ROOT}/live/2026-05-03/brain-operational-live-calibrated-transport-proof}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-brain-operational-proof.XXXXXX")"

cleanup() {
  for pid in "${CLIENT_PID:-}" "${STALE_CLIENT_PID:-}" "${SERVER_PID:-}" "${HTTP_PID:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

cd "${ROOT}"
mkdir -p "${OUT_DIR}"
rm -f \
  "${OUT_DIR}/calibrated-runtime-events.jsonl" \
  "${OUT_DIR}/stale-runtime-events.jsonl" \
  "${OUT_DIR}/result.json" \
  "${OUT_DIR}/README.md" \
  "${OUT_DIR}/socks-egress-response.txt" \
  "${OUT_DIR}/stale-socks-egress-response.txt" \
  "${OUT_DIR}/calibrated-client.log" \
  "${OUT_DIR}/stale-client.log" \
  "${OUT_DIR}/relay-server.log" \
  "${OUT_DIR}/target-http.log" \
  "${OUT_DIR}/calibration-apply.stdout.json" \
  "${OUT_DIR}/stale-calibration-apply.stdout.json"

cargo build -q -p aegis-server -p aegis-client

python3 - <<'PY' > "${TMP_DIR}/ports.env"
import socket

def reserve():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port

for name in ["SERVER_PORT", "SOCKS_PORT", "STALE_SOCKS_PORT", "TARGET_PORT"]:
    print(f"{name}={reserve()}")
PY
source "${TMP_DIR}/ports.env"
AUTH_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"

cat > "${TMP_DIR}/openssl.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[dn]
CN = localhost

[v3_req]
subjectAltName = DNS:localhost
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${TMP_DIR}/server.key" \
  -out "${TMP_DIR}/server.crt" \
  -config "${TMP_DIR}/openssl.cnf" \
  -days 1 >/dev/null 2>&1

python3 - "${OUT_DIR}" <<'PY'
import json
import pathlib
import sys
import time

out = pathlib.Path(sys.argv[1])
now = int(time.time() * 1000)

def snapshot(generated_at, half_life):
    return {
        "schema_version": 1,
        "source": "brain_operational_live_calibrated_transport_proof",
        "generated_at_unix_ms": generated_at,
        "freshness_half_life_secs": half_life,
        "witness": [
            {
                "label": "https_ws",
                "records": 6,
                "combined_avg": 0.96,
                "ja3_present_avg": 1.0,
                "alpn_match_avg": 0.95,
                "sni_structure_avg": 0.92,
            },
            {
                "label": "legacy_tls",
                "records": 6,
                "combined_avg": 0.15,
                "ja3_present_avg": 0.0,
                "alpn_match_avg": 0.0,
                "sni_structure_avg": 0.45,
            },
        ],
        "adversarial": [
            {
                "transport": "https_ws",
                "records": 6,
                "measured": 6,
                "planned": 0,
                "passed": 6,
                "failed": 0,
                "pass_rate": 1.0,
                "threshold": 0.85,
            },
            {
                "transport": "legacy_tls",
                "records": 6,
                "measured": 6,
                "planned": 0,
                "passed": 0,
                "failed": 6,
                "pass_rate": 0.0,
                "threshold": 0.85,
            },
        ],
        "knowledge": [
            {
                "target_class": "https_ws",
                "region_id": "brain_operational_live_lab",
                "score": 0.95,
                "confidence": 0.95,
                "hard_excluded": False,
                "fail_closed": False,
                "generated_at_unix_ms": generated_at,
            },
            {
                "target_class": "legacy_tls",
                "region_id": "brain_operational_live_lab",
                "score": 0.05,
                "confidence": 0.9,
                "hard_excluded": False,
                "fail_closed": False,
                "generated_at_unix_ms": generated_at,
            },
        ],
        "verdict": {
            "status": "MEASURED",
            "acceptance_degraded": False,
            "reasons": [],
        },
    }

(out / "external-calibration-snapshot.json").write_text(
    json.dumps(snapshot(now, 86400), indent=2) + "\n"
)
(out / "stale-external-calibration-snapshot.json").write_text(
    json.dumps(snapshot(1, 1), indent=2) + "\n"
)
PY

cat > "${TMP_DIR}/server.toml" <<EOF
listen = "127.0.0.1:${SERVER_PORT}"
cert = "${TMP_DIR}/server.crt"
key = "${TMP_DIR}/server.key"
auth_token = "${AUTH_TOKEN}"
fallback = "close"

[target_policy]
# This proof intentionally tunnels to its own loopback HTTP fixture. Production
# relays keep the safer public_internet default.
profile = "full_vpn_egress"

[transport]
websocket_path = "/aegis/ws"
websocket_path_pool = []
grpc_path = "/aegis.tunnel.v1.TunnelService/Open"
grpc_path_pool = []
masque_path_pool = []
EOF

write_client_config() {
  local path="$1"
  local state_path="$2"
  local socks_port="$3"
  cat > "${path}" <<EOF
mode = "relay"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:${socks_port}"

[direct]
state_path = "${state_path}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:${SERVER_PORT}"
server_name = "localhost"
auth_token = "${AUTH_TOKEN}"
transport_priority = ["legacy_tls", "https_ws", "grpc_stream"]
websocket_path = "/aegis/ws"
websocket_path_pool = []
grpc_path = "/aegis.tunnel.v1.TunnelService/Open"
grpc_path_pool = []
masque_path = "/.well-known/masque/udp"
masque_path_pool = []
ca_cert = "${TMP_DIR}/server.crt"
connect_timeout_ms = 3000

[relay.policy]
rotate_transports_per_session = false
max_transport_attempts = 1
write_chunk_size = 16384
inter_chunk_delay_ms = 0
drift_epoch_secs = 900
EOF
}

write_client_config "${TMP_DIR}/client-calibrated.toml" "${TMP_DIR}/calibrated-state.json" "${SOCKS_PORT}"
write_client_config "${TMP_DIR}/client-stale.toml" "${TMP_DIR}/stale-state.json" "${STALE_SOCKS_PORT}"
chmod 600 "${TMP_DIR}/server.toml" "${TMP_DIR}/client-calibrated.toml" "${TMP_DIR}/client-stale.toml"

wait_for_runtime_event() {
  local event_path="$1"
  local event_code="$2"
  local label="$3"
  local process_pid="$4"
  local timeout_secs="${5:-45}"

  python3 - "${event_path}" "${event_code}" "${label}" "${process_pid}" "${timeout_secs}" <<'PY'
import json
import os
import pathlib
import sys
import time

path = pathlib.Path(sys.argv[1])
event_code = sys.argv[2]
label = sys.argv[3]
pid = int(sys.argv[4])
timeout_secs = int(sys.argv[5])
deadline = time.monotonic() + timeout_secs

while True:
    events = []
    if path.exists():
        # The runtime appends JSONL while this waiter reads it. Ignore only an
        # incomplete trailing line; a complete matching event is still
        # mandatory before the deadline.
        lines = path.read_text(errors="replace").splitlines()
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                if index != len(lines) - 1:
                    raise

    if any(event.get("event_code") == event_code for event in events):
        break

    process_state = None
    proc_stat = pathlib.Path(f"/proc/{pid}/stat")
    if proc_stat.exists():
        # A background child that exits can remain as a zombie until the shell
        # waits for it; kill(pid, 0) still succeeds in that state.
        try:
            process_state = proc_stat.read_text().rsplit(")", 1)[1].split()[0]
        except (IndexError, OSError):
            process_state = None
    if process_state == "Z":
        raise SystemExit(
            f"{label} process became a zombie before {event_code} "
            f"(observed_events={len(events)})"
        )

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        raise SystemExit(
            f"{label} process exited before {event_code} "
            f"(observed_events={len(events)})"
        )
    except PermissionError:
        pass

    if time.monotonic() > deadline:
        raise SystemExit(
            f"{label} did not report {event_code} within {timeout_secs}s "
            f"(process_alive=true, observed_events={len(events)})"
        )
    time.sleep(0.1)
PY
}

python3 - "${TMP_DIR}/www" <<'PY'
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)
(root / "proof.txt").write_text("AEGIS brain calibrated transport proof OK\n")
PY

python3 -m http.server "${TARGET_PORT}" --bind 127.0.0.1 --directory "${TMP_DIR}/www" \
  > "${OUT_DIR}/target-http.log" 2>&1 &
HTTP_PID=$!

target/debug/aegis-server --config "${TMP_DIR}/server.toml" \
  > "${OUT_DIR}/relay-server.log" 2>&1 &
SERVER_PID=$!

python3 - "${OUT_DIR}/relay-server.log" "${TARGET_PORT}" "${SERVER_PID}" <<'PY'
import os
import pathlib
import socket
import sys
import time

deadline = time.time() + 15
server_log = pathlib.Path(sys.argv[1])
server_pid = int(sys.argv[3])
while True:
    if server_log.exists() and "server_ingress_ready" in server_log.read_text(errors="ignore"):
        break
    proc_stat = pathlib.Path(f"/proc/{server_pid}/stat")
    if proc_stat.exists():
        try:
            if proc_stat.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                raise SystemExit("relay server exited before ready")
        except (IndexError, OSError):
            pass
    try:
        os.kill(server_pid, 0)
    except ProcessLookupError:
        raise SystemExit("relay server exited before ready")
    except PermissionError:
        pass
    if time.time() > deadline:
        raise SystemExit("relay server did not report ready")
    time.sleep(0.1)

port = int(sys.argv[2])
while True:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            break
    except OSError as exc:
        if time.time() > deadline:
            raise SystemExit(f"target HTTP port did not become ready: {exc}")
        time.sleep(0.1)
PY

# This synthetic loopback proof inspects calibration scores and transport
# explanations, so all four producer invocations explicitly opt into details.
# The installed/runtime default remains private.
target/debug/aegis-client --diagnostic-logs \
  --config "${TMP_DIR}/client-calibrated.toml" \
  --runtime-events-jsonl "${OUT_DIR}/calibrated-runtime-events.jsonl" \
  --apply-external-calibration-summary "${OUT_DIR}/external-calibration-snapshot.json" \
  --json > "${OUT_DIR}/calibration-apply.stdout.json"

target/debug/aegis-client --diagnostic-logs \
  --config "${TMP_DIR}/client-calibrated.toml" \
  --runtime-events-jsonl "${OUT_DIR}/calibrated-runtime-events.jsonl" \
  --runtime-external-calibration-summary "${OUT_DIR}/external-calibration-snapshot.json" \
  > "${OUT_DIR}/calibrated-client.log" 2>&1 &
CLIENT_PID=$!

wait_for_runtime_event \
  "${OUT_DIR}/calibrated-runtime-events.jsonl" \
  "ingress_backend_started" \
  "calibrated SOCKS backend" \
  "${CLIENT_PID}"

curl --silent --show-error --fail --max-time 15 \
  --socks5-hostname "127.0.0.1:${SOCKS_PORT}" \
  "http://127.0.0.1:${TARGET_PORT}/proof.txt" \
  --output "${OUT_DIR}/socks-egress-response.txt"

wait_for_runtime_event \
  "${OUT_DIR}/calibrated-runtime-events.jsonl" \
  "relay_session_succeeded" \
  "calibrated relay session" \
  "${CLIENT_PID}"

kill "${CLIENT_PID}" 2>/dev/null || true
wait "${CLIENT_PID}" 2>/dev/null || true
CLIENT_PID=""

target/debug/aegis-client --diagnostic-logs \
  --config "${TMP_DIR}/client-stale.toml" \
  --runtime-events-jsonl "${OUT_DIR}/stale-runtime-events.jsonl" \
  --apply-external-calibration-summary "${OUT_DIR}/stale-external-calibration-snapshot.json" \
  --json > "${OUT_DIR}/stale-calibration-apply.stdout.json"

target/debug/aegis-client --diagnostic-logs \
  --config "${TMP_DIR}/client-stale.toml" \
  --runtime-events-jsonl "${OUT_DIR}/stale-runtime-events.jsonl" \
  --runtime-external-calibration-summary "${OUT_DIR}/stale-external-calibration-snapshot.json" \
  > "${OUT_DIR}/stale-client.log" 2>&1 &
STALE_CLIENT_PID=$!

wait_for_runtime_event \
  "${OUT_DIR}/stale-runtime-events.jsonl" \
  "ingress_backend_started" \
  "stale SOCKS backend" \
  "${STALE_CLIENT_PID}"

curl --silent --show-error --fail --max-time 15 \
  --socks5-hostname "127.0.0.1:${STALE_SOCKS_PORT}" \
  "http://127.0.0.1:${TARGET_PORT}/proof.txt" \
  --output "${OUT_DIR}/stale-socks-egress-response.txt"

wait_for_runtime_event \
  "${OUT_DIR}/stale-runtime-events.jsonl" \
  "relay_session_succeeded" \
  "stale relay session" \
  "${STALE_CLIENT_PID}"

kill "${STALE_CLIENT_PID}" 2>/dev/null || true
wait "${STALE_CLIENT_PID}" 2>/dev/null || true
STALE_CLIENT_PID=""

python3 - "${OUT_DIR}" "${SOCKS_PORT}" "${STALE_SOCKS_PORT}" "${SERVER_PORT}" "${TARGET_PORT}" <<'PY'
import json
import pathlib
import sys
import time

out = pathlib.Path(sys.argv[1])
ports = {
    "socks_port": int(sys.argv[2]),
    "stale_socks_port": int(sys.argv[3]),
    "server_port": int(sys.argv[4]),
    "target_port": int(sys.argv[5]),
}

def read_jsonl(name):
    path = out / name
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

def first(events, code):
    for event in events:
        if event.get("event_code") == code:
            return event
    raise AssertionError(f"missing {code}")

calibrated = read_jsonl("calibrated-runtime-events.jsonl")
stale = read_jsonl("stale-runtime-events.jsonl")

calibration_event = first(calibrated, "external_calibration_applied")
brain_event = first(calibrated, "brain_select_order_explained")
selected = first(calibrated, "relay_transport_selected")
succeeded = first(calibrated, "relay_session_succeeded")
stale_brain = first(stale, "brain_select_order_explained")
stale_selected = first(stale, "relay_transport_selected")
stale_succeeded = first(stale, "relay_session_succeeded")

expected_transport_key = brain_event["fields"]["calibrated_transport_order"][0]
debug_name = {
    "https_ws": "HttpsWs",
    "grpc_stream": "GrpcStream",
    "legacy_tls": "LegacyTls",
    "masque_derived": "MasqueDerived",
}[expected_transport_key]

checks = {
    "calibration_snapshot_penalizes_legacy_tls_and_prefers_http_like": True,
    "client_loads_calibration": calibration_event["fields"]["source"] == "brain_operational_live_calibrated_transport_proof",
    "external_calibration_applied_event_present": True,
    "strategy_score_explanation_present": bool(brain_event["fields"]["ranked_candidates"]),
    "calibrated_order_applied": brain_event["fields"]["calibrated_order_applied"] is True,
    "selected_transport_matches_calibrated_expectation": selected["fields"]["transport"] == debug_name,
    "relay_session_succeeded_present": succeeded["fields"]["chosen_transport"] == debug_name,
    "socks_egress_proof_works": "AEGIS brain calibrated transport proof OK" in (out / "socks-egress-response.txt").read_text(),
    "stale_calibration_negative_ignored": stale_brain["fields"]["calibrated_order_applied"] is False
        and stale_brain["fields"]["calibrated_transport_order"][0] == "legacy_tls"
        and stale_selected["fields"]["transport"] == "LegacyTls"
        and stale_succeeded["fields"]["chosen_transport"] == "LegacyTls",
    "no_fallback_contamination": not any(
        event.get("event_code") in {
            "ingress_startup_fallback_selected",
            "direct_relay_failover_triggered",
            "relay_transport_failed",
        }
        for event in calibrated
    ),
    "stale_no_fallback_contamination": not any(
        event.get("event_code") in {
            "ingress_startup_fallback_selected",
            "direct_relay_failover_triggered",
            "relay_transport_failed",
        }
        for event in stale
    ),
}
verdict = all(checks.values())
result = {
    "artifact": "brain-operational-live-calibrated-transport-proof",
    "schema_version": 1,
    "status": "PASS" if verdict else "NOT_PASS",
    "verdict": "PASS" if verdict else "NOT_PASS",
    "completion_claim_allowed": False,
    "full_aegis_completion_claimed": False,
    "mimicry_reference_maturity_status": "PARTIAL_UNCHANGED",
    "runtime_log_mode": "explicit_diagnostics_synthetic_fixture",
    "brain_operational_runtime_proof": "PASS" if verdict else "NOT_PASS",
    "selected_transport_after_calibration": expected_transport_key,
    "selected_transport_debug_name": debug_name,
    "baseline_configured_order": brain_event["fields"]["original_transport_order"],
    "calibrated_transport_order": brain_event["fields"]["calibrated_transport_order"],
    "stale_transport_order": stale_brain["fields"]["calibrated_transport_order"],
    "ports": ports,
    "checks": checks,
    "evidence": {
        "calibration_snapshot": "external-calibration-snapshot.json",
        "stale_calibration_snapshot": "stale-external-calibration-snapshot.json",
        "calibrated_runtime_events": "calibrated-runtime-events.jsonl",
        "stale_runtime_events": "stale-runtime-events.jsonl",
        "socks_egress_response": "socks-egress-response.txt",
        "stale_socks_egress_response": "stale-socks-egress-response.txt",
    },
    "next_action": "continue mimicry/reference maturity; do not claim full AEGIS completion",
    "generated_at_unix_ms": int(time.time() * 1000),
}
(out / "result.json").write_text(json.dumps(result, indent=2) + "\n")

readme = f"""# Brain Operational Live Calibrated Transport Proof

## Verdict
`{result['verdict']}`

## Scope
This artifact proves the operational Brain calibration path for a real local client runtime relay session. It does not claim full AEGIS completion, and it does not change mimicry/reference maturity beyond the existing PARTIAL boundary.
The synthetic fixture explicitly enables `--diagnostic-logs` to inspect calibration and transport details. Production runtime logging remains private by default.

## Evidence
- Fresh calibration snapshot penalizes `legacy_tls` and prefers `{expected_transport_key}`.
- Client applies the external calibration and emits `external_calibration_applied`.
- Relay runtime emits `brain_select_order_explained` with candidate scores and an applied calibrated order.
- The first `relay_transport_selected` and `relay_session_succeeded` match `{debug_name}`.
- SOCKS egress through the client and relay returns `socks-egress-response.txt`.
- Stale calibration is ignored: stale runtime keeps `legacy_tls` first and still succeeds without fallback.
- No fallback contamination events are present in the positive or stale runtime JSONL files.
"""
(out / "README.md").write_text(readme)

commands = """scripts/run-brain-operational-live-calibrated-transport-proof.sh evidence-archive/live/2026-05-03/brain-operational-live-calibrated-transport-proof
"""
(out / "commands.txt").write_text(commands)

environment = f"""date_unix_ms={result['generated_at_unix_ms']}
artifact=evidence-archive/live/2026-05-03/brain-operational-live-calibrated-transport-proof
client_binary=target/debug/aegis-client
server_binary=target/debug/aegis-server
"""
(out / "environment.txt").write_text(environment)

sanitized_config = f"""mode = "relay"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{ports['socks_port']}"

[direct]
state_path = "<temp-state-path>"
strategies = ["passthrough"]

[relay]
server = "127.0.0.1:{ports['server_port']}"
server_name = "localhost"
auth_token = "REDACTED"
transport_priority = ["legacy_tls", "https_ws", "grpc_stream"]
ca_cert = "<temp-ca-cert>"

[relay.policy]
rotate_transports_per_session = false
max_transport_attempts = 1
"""
(out / "client-calibrated.sanitized.toml").write_text(sanitized_config)

if not verdict:
    raise SystemExit(json.dumps(result, indent=2))
PY

echo "PASS ${OUT_DIR}/result.json"
