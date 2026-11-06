#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-ubuntu-mimicry-next-contour.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-mimicry-next.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/stealth-wave-summary.json" <<'EOF'
{
  "artifact_schema": "post_release_stealth_wave_v1",
  "status": "ready_after_proven_ubuntu_bypass_and_wire",
  "current_milestone": "witness_maturity_and_correlation_discipline",
  "current_milestone_state": "witness_evidence_green",
  "current_milestone_next_action": "open_linux_wire_mimicry_execution_contour"
}
EOF

bash "${SCRIPT}" "${TMP_DIR}/out" \
  --stealth-summary "${TMP_DIR}/stealth-wave-summary.json" >/dev/null

OUTPUT_JSON="${TMP_DIR}/out/ubuntu-mimicry-next-contour.json"
OUTPUT_MD="${TMP_DIR}/out/ubuntu-mimicry-next-contour.md"

jq -e '
  .artifact_schema == "ubuntu_mimicry_next_contour_v1"
  and .current_focus == "linux_wire_mimicry_execution_contour"
  and .contour_status == "ready_for_linux_wire_execution_contour"
  and .next_required_action == "implement_linux_wire_execution_contour_in_runtime"
  and .primary_code_paths == ["aegis-core/src/mimicry.rs", "aegis-client/src/direct.rs"]
  and .execution_ladder[0] == "linux_experimental_ipv4_ttl_preface"
  and .execution_ladder[-1] == "linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface"
' "${OUTPUT_JSON}" >/dev/null

grep -Fq -- "Ubuntu Mimicry Next Contour" "${OUTPUT_MD}"
grep -Fq -- "- Contour status: \`ready_for_linux_wire_execution_contour\`" "${OUTPUT_MD}"

echo "build-ubuntu-mimicry-next-contour contract: ok"
