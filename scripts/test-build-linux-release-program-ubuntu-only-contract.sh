#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-linux-release-program-bundle.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-linux-release-program-ubuntu-only.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/ubuntu-wave-status.json" <<'EOF'
{
  "artifact_schema": "ubuntu_release_wave_status_v1",
  "ship_ready": true,
  "ship_decision": "ship",
  "wave_status": "fully_proven_hostile_path",
  "next_required_action": "none"
}
EOF

cat > "${TMP_DIR}/ubuntu-wave.manifest.json" <<EOF
{
  "artifact_schema": "ubuntu_release_wave_bundle_v1",
  "wave_status_json": "${TMP_DIR}/ubuntu-wave-status.json"
}
EOF

cat > "${TMP_DIR}/stealth-wave-summary.json" <<'EOF'
{
  "artifact_schema": "post_release_stealth_wave_v1",
  "status": "ready_after_proven_ubuntu_bypass_and_wire",
  "current_milestone": "witness_maturity_and_correlation_discipline",
  "current_milestone_state": "witness_evidence_green",
  "current_milestone_next_action": "open_linux_wire_mimicry_execution_contour"
}
EOF

cat > "${TMP_DIR}/mimicry-next-contour.json" <<'EOF'
{
  "artifact_schema": "ubuntu_mimicry_next_contour_v1",
  "contour_status": "ready_for_linux_wire_execution_contour",
  "next_required_action": "implement_linux_wire_execution_contour_in_runtime"
}
EOF

bash "${SCRIPT}" "${TMP_DIR}/out" \
  --ubuntu-wave-manifest "${TMP_DIR}/ubuntu-wave.manifest.json" \
  --stealth-summary "${TMP_DIR}/stealth-wave-summary.json" \
  --mimicry-next-contour "${TMP_DIR}/mimicry-next-contour.json" >/dev/null

STATUS_JSON="${TMP_DIR}/out/linux-release-program-status.json"
MANIFEST_JSON="${TMP_DIR}/out/linux-release-program.manifest.json"
OUTPUT_MD="${TMP_DIR}/out/linux-release-program.md"

jq -e '
  .artifact_schema == "linux_release_program_bundle_v1"
  and .next_expansion_status == null
  and .stealth_status == "ready_after_proven_ubuntu_bypass_and_wire"
  and .stealth_current_milestone == "witness_maturity_and_correlation_discipline"
  and .mimicry_contour_status == "ready_for_linux_wire_execution_contour"
  and .program_status == "ubuntu_post_release_tracks_visible"
  and .next_required_action == "open_linux_wire_mimicry_execution_contour"
' "${STATUS_JSON}" >/dev/null

jq -e '
  .artifact_schema == "linux_release_program_manifest_v1"
  and .program_status == "ubuntu_post_release_tracks_visible"
' "${MANIFEST_JSON}" >/dev/null

grep -Fq -- "Linux Release Program" "${OUTPUT_MD}"
grep -Fq -- "- Program status: \`ubuntu_post_release_tracks_visible\`" "${OUTPUT_MD}"

echo "build-linux-release-program ubuntu-only contract: ok"
