#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-c-multi-relay.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/pass-runtime.jsonl" <<'JSONL'
{"event_code":"relay_session_started","ts_unix_ms":100000,"fields":{"relay_server":"relay-a.example.org:443","relay_server_name":"relay-a.example.org","attempts_total":2}}
{"event_code":"relay_transport_selected","ts_unix_ms":100100,"fields":{"relay_server":"relay-a.example.org:443","relay_server_name":"relay-a.example.org","attempt_index":1,"attempts_total":2}}
{"event_code":"relay_transport_failed","ts_unix_ms":101000,"fields":{"relay_server":"relay-a.example.org:443","relay_server_name":"relay-a.example.org","attempt_index":1,"attempts_total":2,"relay_error_kind":"timed_out"}}
{"event_code":"relay_transport_selected","ts_unix_ms":103000,"fields":{"relay_server":"relay-b.example.org:443","relay_server_name":"relay-b.example.org","attempt_index":2,"attempts_total":2}}
{"event_code":"relay_session_succeeded","ts_unix_ms":104000,"fields":{"relay_server":"relay-b.example.org:443","relay_server_name":"relay-b.example.org","attempt_index":2,"attempts_total":2}}
JSONL

bash "${ROOT}/scripts/build-phase-c-multi-relay-evidence.sh" \
  --runtime-events-jsonl "${TMP_DIR}/pass-runtime.jsonl" \
  --single-relay-backward-compatible \
  --output-json "${TMP_DIR}/pass.json" \
  --output-markdown "${TMP_DIR}/pass.md"

grep -q '"status": "PASS"' "${TMP_DIR}/pass.json"
grep -q '"primary_block_recovery_median_secs": 3.0' "${TMP_DIR}/pass.json"
grep -q 'Phase C Multi-Relay Evidence' "${TMP_DIR}/pass.md"

cat >"${TMP_DIR}/single-runtime.jsonl" <<'JSONL'
{"event_code":"relay_session_started","ts_unix_ms":100000,"fields":{"relay_server":"relay-a.example.org:443","relay_server_name":"relay-a.example.org","attempts_total":1}}
{"event_code":"relay_session_succeeded","ts_unix_ms":101000,"fields":{"relay_server":"relay-a.example.org:443","relay_server_name":"relay-a.example.org","attempt_index":1,"attempts_total":1}}
JSONL

if bash "${ROOT}/scripts/build-phase-c-multi-relay-evidence.sh" \
  --runtime-events-jsonl "${TMP_DIR}/single-runtime.jsonl" \
  --single-relay-backward-compatible \
  --output-json "${TMP_DIR}/single.json"; then
  echo "expected single relay runtime to block" >&2
  exit 1
fi
grep -q 'fewer_than_two_relay_endpoints_observed' "${TMP_DIR}/single.json"
grep -q 'mid_session_primary_block_survival_missing' "${TMP_DIR}/single.json"

cat >"${TMP_DIR}/slow-runtime.jsonl" <<'JSONL'
{"event_code":"relay_transport_failed","ts_unix_ms":100000,"fields":{"relay_server":"relay-a.example.org:443","relay_server_name":"relay-a.example.org","attempt_index":1,"attempts_total":2}}
{"event_code":"relay_session_succeeded","ts_unix_ms":131000,"fields":{"relay_server":"relay-b.example.org:443","relay_server_name":"relay-b.example.org","attempt_index":2,"attempts_total":2}}
JSONL

if bash "${ROOT}/scripts/build-phase-c-multi-relay-evidence.sh" \
  --runtime-events-jsonl "${TMP_DIR}/slow-runtime.jsonl" \
  --single-relay-backward-compatible \
  --output-json "${TMP_DIR}/slow.json"; then
  echo "expected slow recovery to block" >&2
  exit 1
fi
grep -q 'primary_block_recovery_median_not_below_30s' "${TMP_DIR}/slow.json"

if bash "${ROOT}/scripts/build-phase-c-multi-relay-evidence.sh" \
  --runtime-events-jsonl "${TMP_DIR}/pass-runtime.jsonl" \
  --output-json "${TMP_DIR}/no-compat.json"; then
  echo "expected missing backward-compat evidence to block" >&2
  exit 1
fi
grep -q 'single_relay_backward_compatibility_missing' "${TMP_DIR}/no-compat.json"

echo "ok"
