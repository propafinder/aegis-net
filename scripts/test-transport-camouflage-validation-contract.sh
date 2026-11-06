#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-transport-camouflage-validation.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-transport-camouflage.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/live.manifest.json" <<'JSON'
{"acceptance_overview":{"overall_status":"acceptance_green","wire_layer_verdict":"green","wire_layer_status":"passed","stealth_layer_verdict":"green","stealth_layer_status":"ready_for_runtime_surface_hostile_path_validation"}}
JSON
cat >"${TMP_DIR}/stealth.json" <<'JSON'
{"active_blockers":[],"blocking_requirements":{"live_wire_green":true,"independent_witness_matched":true,"runtime_relay_surface_green":true,"wire_hostile_path_ready":true}}
JSON
cat >"${TMP_DIR}/wire.json" <<'JSON'
{"product_verdict":"green","acceptance_status":"passed","hostile_path_support_ready":true,"independent_witness_correlation_status":"matched"}
JSON
cat >"${TMP_DIR}/relay.json" <<'JSON'
{"verdict":"green","status":"runtime_surface_green","relay_events_scanned":5,"relay_events_missing_surface":0,"checks":{"surface_fields_complete_on_all_relay_events":true}}
JSON
cat >"${TMP_DIR}/classifier-pass.json" <<'JSON'
{"status":"PASS","acceptance_degraded":false,"classifier_records":2,"classifiers":["suricata","ndpi"],"verdict_counts":{"pass":2,"fail":0,"unknown":0},"reasons":[]}
JSON
cat >"${TMP_DIR}/classifier-blocked.json" <<'JSON'
{"status":"FAIL","acceptance_degraded":true,"classifier_records":2,"classifiers":["suricata","ndpi"],"verdict_counts":{"pass":0,"fail":0,"unknown":2},"reasons":["hostile-classifier-verdict-unknown"]}
JSON
cat >"${TMP_DIR}/classifier-detected.json" <<'JSON'
{"status":"FAIL","acceptance_degraded":true,"classifier_records":2,"classifiers":["suricata","ndpi"],"verdict_counts":{"pass":1,"fail":1,"unknown":0},"reasons":["hostile-classifier-detected-or-blocked"]}
JSON
printf 'pcap-with-packet-backed-bytes-beyond-header\n' >"${TMP_DIR}/wire.pcapng"

bash "${SCRIPT}" \
  --live-manifest-json "${TMP_DIR}/live.manifest.json" \
  --stealth-bundle-json "${TMP_DIR}/stealth.json" \
  --wire-acceptance-json "${TMP_DIR}/wire.json" \
  --relay-surface-json "${TMP_DIR}/relay.json" \
  --classifier-summary-json "${TMP_DIR}/classifier-pass.json" \
  --witness-pcap "${TMP_DIR}/wire.pcapng" \
  --output-json "${TMP_DIR}/ready.json" \
  --output-markdown "${TMP_DIR}/ready.md"

jq -e '
  .artifact_schema == "transport_camouflage_validation_v1"
  and .status == "READY"
  and .next_action == "open_next_phase_b_score_and_parity_gate"
  and .blockers == []
  and .checks.hostile_classifier_pass == true
  and .checks.relay_surface_runtime_green == true
' "${TMP_DIR}/ready.json" >/dev/null

grep -Fq -- "Transport Camouflage Validation" "${TMP_DIR}/ready.md"
grep -Fq -- "- Status: \`READY\`" "${TMP_DIR}/ready.md"

if bash "${SCRIPT}" \
  --live-manifest-json "${TMP_DIR}/live.manifest.json" \
  --stealth-bundle-json "${TMP_DIR}/stealth.json" \
  --wire-acceptance-json "${TMP_DIR}/wire.json" \
  --relay-surface-json "${TMP_DIR}/relay.json" \
  --classifier-summary-json "${TMP_DIR}/classifier-blocked.json" \
  --witness-pcap "${TMP_DIR}/wire.pcapng" \
  --output-json "${TMP_DIR}/blocked.json" \
  --output-markdown "${TMP_DIR}/blocked.md" >/dev/null 2>&1; then
  echo "expected blocked classifier validation to exit non-zero" >&2
  exit 1
fi

jq -e '
  .status == "BLOCKED"
  and (.blockers | index("hostile_classifier_not_pass") != null)
  and .next_action == "run_or_install_hostile_classifiers_for_witness_pcap"
' "${TMP_DIR}/blocked.json" >/dev/null

if bash "${SCRIPT}" \
  --live-manifest-json "${TMP_DIR}/live.manifest.json" \
  --stealth-bundle-json "${TMP_DIR}/stealth.json" \
  --wire-acceptance-json "${TMP_DIR}/wire.json" \
  --relay-surface-json "${TMP_DIR}/relay.json" \
  --classifier-summary-json "${TMP_DIR}/classifier-detected.json" \
  --witness-pcap "${TMP_DIR}/wire.pcapng" \
  --output-json "${TMP_DIR}/detected.json" \
  --output-markdown "${TMP_DIR}/detected.md" >/dev/null 2>&1; then
  echo "expected detected classifier validation to exit non-zero" >&2
  exit 1
fi

jq -e '
  .status == "BLOCKED"
  and (.blockers | index("hostile_classifier_not_pass") != null)
  and .next_action == "tune_transport_camouflage_until_hostile_classifiers_pass"
' "${TMP_DIR}/detected.json" >/dev/null

echo "PASS: transport camouflage validation contract"
