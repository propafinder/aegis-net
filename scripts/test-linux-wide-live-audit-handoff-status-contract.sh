#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATUS_SCRIPT="${ROOT}/scripts/linux-wide-live-audit-handoff-status.sh"
MANIFEST_HELPER="${ROOT}/scripts/build-linux-wide-live-audit-manifest.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-live-audit-handoff-status.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

# Independent fixture expectation is selected before reported artifacts.
cat > "${TMP_DIR}/expected-topology.json" <<'TOPOLOGY'
{"schema":"aegis_linux_live_expected_topology_v1","server_host":"192.0.2.10","client_host":"192.0.2.20","relay_address":"192.0.2.10:8443"}
TOPOLOGY
chmod 600 "${TMP_DIR}/expected-topology.json"

cat > "${TMP_DIR}/wire-green.json" <<'EOF'
{
  "artifact_schema": "wire_mimicry_host_acceptance_v1",
  "product_verdict": "green",
  "acceptance_status": "passed",
  "hostile_path_support_ready": true,
  "independent_witness_correlation_status": "matched"
}
EOF

cat > "${TMP_DIR}/wire-blocked.json" <<'EOF'
{
  "artifact_schema": "wire_mimicry_host_acceptance_v1",
  "product_verdict": "yellow",
  "acceptance_status": "needs_witness",
  "hostile_path_support_ready": false,
  "independent_witness_correlation_status": "missing"
}
EOF

cat > "${TMP_DIR}/stealth-green.json" <<'EOF'
{
  "artifact_schema": "stealth_live_acceptance_bundle_v1",
  "bundle_verdict": "green",
  "bundle_status": "acceptance_green",
  "next_action": "collect_next_live_validation_slice",
  "primary_blocker": null,
  "active_blockers": []
}
EOF

cat > "${TMP_DIR}/stealth-blocked.json" <<'EOF'
{
  "artifact_schema": "stealth_live_acceptance_bundle_v1",
  "bundle_verdict": "yellow",
  "bundle_status": "blocked_on_runtime_relay_surface_evidence",
  "next_action": "inspect_runtime_relay_surface_evidence",
  "primary_blocker": {
    "id": "runtime_relay_surface_evidence"
  },
  "active_blockers": [
    {
      "id": "runtime_relay_surface_evidence"
    }
  ]
}
EOF

touch "${TMP_DIR}/runtime-events.jsonl" "${TMP_DIR}/preflight.json" "${TMP_DIR}/startup.json" \
  "${TMP_DIR}/wire-helper.stdout.json" "${TMP_DIR}/transient-runtime-events.jsonl" \
  "${TMP_DIR}/wire-helper-runtime-events.jsonl" "${TMP_DIR}/wire-witness-summary.json" \
  "${TMP_DIR}/wire.pcapng"

bash "${MANIFEST_HELPER}" \
  --manifest "${TMP_DIR}/stealth/live-audit.manifest.json" \
  --output-dir "${TMP_DIR}/stealth" \
  --server-host 192.0.2.10 \
  --client-host 192.0.2.20 \
  --relay-address 192.0.2.10:8443 \
  --runtime-events "${TMP_DIR}/runtime-events.jsonl" \
  --preflight "${TMP_DIR}/preflight.json" \
  --startup-probe "${TMP_DIR}/startup.json" \
  --wire-helper-stdout "${TMP_DIR}/wire-helper.stdout.json" \
  --witness-summary "${TMP_DIR}/wire-witness-summary.json" \
  --witness-pcap "${TMP_DIR}/wire.pcapng" \
  --transient-runtime-events "${TMP_DIR}/transient-runtime-events.jsonl" \
  --wire-helper-runtime-events "${TMP_DIR}/wire-helper-runtime-events.jsonl" \
  --wire-acceptance-summary "${TMP_DIR}/wire-green.json" \
  --stealth-live-acceptance-bundle "${TMP_DIR}/stealth-blocked.json" \
  --stealth-live-acceptance-manifest "${TMP_DIR}/stealth-live-acceptance.manifest.json" \
  --rerun-command "bash scripts/run-linux-wide-mimicry-live-audit.sh --server-host 192.0.2.10 --client-host 192.0.2.20" \
  --review-summary-command "sed -n '1,160p' ${TMP_DIR}/stealth/live-audit-summary.md" \
  --review-manifest-command "cargo run -q -p aegis-measure -- pretty-json --input ${TMP_DIR}/stealth/live-audit.manifest.json"

bash "${MANIFEST_HELPER}" \
  --manifest "${TMP_DIR}/wire/live-audit.manifest.json" \
  --output-dir "${TMP_DIR}/wire" \
  --server-host 192.0.2.10 \
  --client-host 192.0.2.20 \
  --relay-address 192.0.2.10:8443 \
  --runtime-events "${TMP_DIR}/runtime-events.jsonl" \
  --preflight "${TMP_DIR}/preflight.json" \
  --startup-probe "${TMP_DIR}/startup.json" \
  --wire-helper-stdout "${TMP_DIR}/wire-helper.stdout.json" \
  --witness-summary "" \
  --witness-pcap "" \
  --transient-runtime-events "${TMP_DIR}/transient-runtime-events.jsonl" \
  --wire-helper-runtime-events "${TMP_DIR}/wire-helper-runtime-events.jsonl" \
  --wire-acceptance-summary "${TMP_DIR}/wire-blocked.json" \
  --stealth-live-acceptance-bundle "${TMP_DIR}/stealth-green.json" \
  --stealth-live-acceptance-manifest "${TMP_DIR}/stealth-live-acceptance.manifest.json" \
  --rerun-command "bash scripts/run-linux-wide-mimicry-live-audit.sh --server-host 192.0.2.10 --client-host 192.0.2.20" \
  --review-summary-command "sed -n '1,160p' ${TMP_DIR}/wire/live-audit-summary.md" \
  --review-manifest-command "cargo run -q -p aegis-measure -- pretty-json --input ${TMP_DIR}/wire/live-audit.manifest.json"

bash "${MANIFEST_HELPER}" \
  --manifest "${TMP_DIR}/green/live-audit.manifest.json" \
  --output-dir "${TMP_DIR}/green" \
  --server-host 192.0.2.10 \
  --client-host 192.0.2.20 \
  --relay-address 192.0.2.10:8443 \
  --runtime-events "${TMP_DIR}/runtime-events.jsonl" \
  --preflight "${TMP_DIR}/preflight.json" \
  --startup-probe "${TMP_DIR}/startup.json" \
  --wire-helper-stdout "${TMP_DIR}/wire-helper.stdout.json" \
  --witness-summary "" \
  --witness-pcap "" \
  --transient-runtime-events "${TMP_DIR}/transient-runtime-events.jsonl" \
  --wire-helper-runtime-events "${TMP_DIR}/wire-helper-runtime-events.jsonl" \
  --wire-acceptance-summary "${TMP_DIR}/wire-green.json" \
  --stealth-live-acceptance-bundle "${TMP_DIR}/stealth-green.json" \
  --stealth-live-acceptance-manifest "${TMP_DIR}/stealth-live-acceptance.manifest.json" \
  --rerun-command "bash scripts/run-linux-wide-mimicry-live-audit.sh --server-host 192.0.2.10 --client-host 192.0.2.20" \
  --review-summary-command "sed -n '1,160p' ${TMP_DIR}/green/live-audit-summary.md" \
  --review-manifest-command "cargo run -q -p aegis-measure -- pretty-json --input ${TMP_DIR}/green/live-audit.manifest.json"

bash "${STATUS_SCRIPT}" \
  --manifest "${TMP_DIR}/stealth/live-audit.manifest.json" \
  --output "${TMP_DIR}/stealth/status.json"

bash "${STATUS_SCRIPT}" \
  --manifest "${TMP_DIR}/wire/live-audit.manifest.json" \
  --output "${TMP_DIR}/wire/status.json"

bash "${STATUS_SCRIPT}" \
  --manifest "${TMP_DIR}/green/live-audit.manifest.json" \
  --output "${TMP_DIR}/green/status.json"

cargo run -q -p aegis-measure -- linux-wide-live-audit-manifest-contract-check \
  --manifest "${TMP_DIR}/stealth/live-audit.manifest.json" \
  --manifest "${TMP_DIR}/wire/live-audit.manifest.json" \
  --manifest "${TMP_DIR}/green/live-audit.manifest.json"

cargo run -q -p aegis-measure -- linux-wide-live-audit-handoff-status-contract-check \
  --expected-topology-file "${TMP_DIR}/expected-topology.json" \
  --status-json "${TMP_DIR}/stealth/status.json" \
  --status-json "${TMP_DIR}/wire/status.json" \
  --status-json "${TMP_DIR}/green/status.json"

cargo run -q -p aegis-measure -- linux-wide-live-audit-handoff-status-fixture-contract-check \
  --expected-topology-file "${TMP_DIR}/expected-topology.json" \
  --stealth-manifest "${TMP_DIR}/stealth/live-audit.manifest.json" \
  --wire-manifest "${TMP_DIR}/wire/live-audit.manifest.json" \
  --green-manifest "${TMP_DIR}/green/live-audit.manifest.json" \
  --stealth-status "${TMP_DIR}/stealth/status.json" \
  --wire-status "${TMP_DIR}/wire/status.json" \
  --green-status "${TMP_DIR}/green/status.json"

echo "linux-wide-live-audit-handoff-status contract: ok"
