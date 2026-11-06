#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/linux-next-expansion-status.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-next-expansion-status.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

PENDING_RESULTS="${TMP_DIR}/pending-results.json"
PENDING_MANIFEST="${TMP_DIR}/pending-manifest.json"
READY_RESULTS="${TMP_DIR}/ready-results.json"
READY_MANIFEST="${TMP_DIR}/ready-manifest.json"
READY_REVIEW="${TMP_DIR}/ready-review.json"

cat > "${PENDING_RESULTS}" <<'EOF'
[
  {"host_family_id":"debian-apt","status":"passed"},
  {"host_family_id":"rhel-dnf","status":"pending_live_evidence"},
  {"host_family_id":"suse-zypper","status":"pending_live_evidence"}
]
EOF

cat > "${PENDING_MANIFEST}" <<'EOF'
{
  "artifact_schema": "linux_package_acceptance_matrix_bundle_v1",
  "matrix_results_artifact": "REPLACE_PENDING_RESULTS",
  "release_claim_boundary": "ubuntu_first_only",
  "canonical_release_family": "debian-apt",
  "passed_families": ["debian-apt"],
  "failed_families": [],
  "pending_families": ["rhel-dnf", "suse-zypper"],
  "next_expansion_candidate": "rhel-dnf"
}
EOF

cat > "${READY_RESULTS}" <<'EOF'
[
  {"host_family_id":"debian-apt","status":"passed"},
  {"host_family_id":"rhel-dnf","status":"passed"},
  {"host_family_id":"suse-zypper","status":"pending_live_evidence"}
]
EOF

cat > "${READY_MANIFEST}" <<'EOF'
{
  "artifact_schema": "linux_package_acceptance_matrix_bundle_v1",
  "matrix_results_artifact": "REPLACE_READY_RESULTS",
  "release_claim_boundary": "ubuntu_first_only",
  "canonical_release_family": "debian-apt",
  "passed_families": ["debian-apt", "rhel-dnf"],
  "failed_families": [],
  "pending_families": ["suse-zypper"],
  "next_expansion_candidate": "suse-zypper"
}
EOF

cat > "${READY_REVIEW}" <<'EOF'
{
  "artifact_schema": "linux_next_expansion_review_v1",
  "target_family_id": "rhel-dnf",
  "target_result_status": "passed",
  "review_verdict": "ready",
  "next_required_action": "none"
}
EOF

jq --arg matrix_results "${PENDING_RESULTS}" \
  '.matrix_results_artifact = $matrix_results' \
  "${PENDING_MANIFEST}" >"${PENDING_MANIFEST}.tmp"
mv "${PENDING_MANIFEST}.tmp" "${PENDING_MANIFEST}"

jq --arg matrix_results "${READY_RESULTS}" \
  '.matrix_results_artifact = $matrix_results' \
  "${READY_MANIFEST}" >"${READY_MANIFEST}.tmp"
mv "${READY_MANIFEST}.tmp" "${READY_MANIFEST}"

bash "${SCRIPT}" \
  --matrix-manifest "${PENDING_MANIFEST}" \
  --output "${TMP_DIR}/pending-status.json"

bash "${SCRIPT}" \
  --matrix-manifest "${READY_MANIFEST}" \
  --review-json "${READY_REVIEW}" \
  --output "${TMP_DIR}/ready-status.json"

jq -e '
  .artifact_schema == "linux_next_expansion_status_v1"
  and .expansion_status == "pending_next_family"
  and .next_expansion_candidate == "rhel-dnf"
  and .latest_review_json == null
  and (.next_required_action | contains("build-linux-next-expansion-playbook.sh"))
' "${TMP_DIR}/pending-status.json" >/dev/null

READY_MANIFEST_CANONICAL="$(cd "$(dirname "${READY_MANIFEST}")" && pwd)/$(basename "${READY_MANIFEST}")"

jq -e --arg ready_manifest "${READY_MANIFEST_CANONICAL}" '
  .artifact_schema == "linux_next_expansion_status_v1"
  and .expansion_status == "target_validated_next_candidate_pending"
  and .next_expansion_candidate == "suse-zypper"
  and .latest_review_applied == true
  and .latest_review_family == "rhel-dnf"
  and .latest_review_verdict == "ready"
  and (.next_required_action | contains($ready_manifest))
' "${TMP_DIR}/ready-status.json" >/dev/null

echo "linux-next-expansion-status contract: ok"
