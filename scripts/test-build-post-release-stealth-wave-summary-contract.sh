#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-post-release-stealth-wave-summary.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-stealth-wave.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/ubuntu-release-wave-status.json" <<'EOF'
{"artifact_schema":"ubuntu_release_wave_status_v1","ship_ready":true,"bypass_ready":true,"bypass_support_tier":"wire_level_supported_hostile_path","fully_proven":true}
EOF

cat > "${TMP_DIR}/wire-acceptance-summary.json" <<'EOF'
{"artifact_schema":"wire_host_acceptance_summary_v1","verdict":"green"}
EOF

bash "${SCRIPT}" "${TMP_DIR}/out" \
  --ubuntu-release-wave-status "${TMP_DIR}/ubuntu-release-wave-status.json" \
  --wire-acceptance-summary "${TMP_DIR}/wire-acceptance-summary.json" >/dev/null

OUTPUT_JSON="${TMP_DIR}/out/stealth-wave-summary.json"
OUTPUT_MD="${TMP_DIR}/out/stealth-wave-summary.md"

jq -e '
  .artifact_schema == "post_release_stealth_wave_v1"
  and .release_prerequisite == "ubuntu_live_bypass_proven_with_working_wire_support"
  and .prerequisite_state == "satisfied"
  and .status == "ready_after_proven_ubuntu_bypass_and_wire"
  and .current_milestone == "witness_maturity_and_correlation_discipline"
  and .current_milestone_state == "witness_evidence_green"
  and .current_milestone_next_action == "open_linux_wire_mimicry_execution_contour"
  and (.current_entrypoints | index("scripts/validate-mimicry-wire-host.sh") != null)
  and (.current_entrypoints | index("scripts/build-relay-surface-runtime-summary.sh") != null)
  and (.current_entrypoints | index("scripts/build-stealth-polymorphism-acceptance-summary.sh") != null)
  and (.current_entrypoints | index("scripts/build-stealth-hostile-path-acceptance-summary.sh") != null)
  and (.current_entrypoints | index("scripts/build-stealth-live-acceptance-bundle.sh") != null)
  and (.next_tracks | index("transport_camouflage_and_stronger_anti_dpi_behaviors") != null)
' "${OUTPUT_JSON}" >/dev/null

grep -Fq -- "Post-Release Stealth Wave" "${OUTPUT_MD}"
grep -Fq -- "\`scripts/build-mimicry-wire-witness-summary.sh\`" "${OUTPUT_MD}"
grep -Fq -- "\`scripts/build-relay-surface-runtime-summary.sh\`" "${OUTPUT_MD}"
grep -Fq -- "\`scripts/build-stealth-polymorphism-acceptance-summary.sh\`" "${OUTPUT_MD}"
grep -Fq -- "\`scripts/build-stealth-hostile-path-acceptance-summary.sh\`" "${OUTPUT_MD}"
grep -Fq -- "\`scripts/build-stealth-live-acceptance-bundle.sh\`" "${OUTPUT_MD}"
grep -Fq -- "- Prerequisite state: \`satisfied\`" "${OUTPUT_MD}"
grep -Fq -- "- Current milestone: \`witness_maturity_and_correlation_discipline\`" "${OUTPUT_MD}"

echo "post-release stealth wave summary contract: ok"
