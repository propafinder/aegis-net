#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-package-acceptance-matrix.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/debian.json" <<'EOF'
{
  "artifact_schema": "debian_package_host_validation_v1",
  "mode": "run",
  "os_pretty_name": "Debian 12",
  "package_manager": "apt-get",
  "supported_product_contour": "linux_first_split_deb_package_validation",
  "supported_operator_scope": "debian_host_package_lifecycle_validation",
  "host_family_id": "debian-apt",
  "host_family_validation_tier": "packaging_validation_target",
  "ready": true,
  "helper_exit_code": 0
}
EOF

cat > "${TMP_DIR}/rhel.json" <<'EOF'
{
  "artifact_schema": "rpm_package_host_validation_v1",
  "mode": "run",
  "os_pretty_name": "Rocky Linux 9",
  "package_manager": "dnf",
  "supported_product_contour": "linux_first_split_rpm_package_validation",
  "supported_operator_scope": "rpm_host_package_lifecycle_validation",
  "host_family_id": "rhel-dnf",
  "host_family_validation_tier": "packaging_validation_target",
  "ready": true,
  "helper_exit_code": 0
}
EOF

bash "${ROOT}/scripts/build-linux-package-acceptance-matrix.sh" "${TMP_DIR}/out" \
  --evidence "${TMP_DIR}/debian.json" \
  --evidence "${TMP_DIR}/rhel.json" >/dev/null

bash "${ROOT}/scripts/build-linux-package-acceptance-matrix.sh" "${TMP_DIR}/out-debian-first" \
  --evidence "${TMP_DIR}/rhel.json" >/dev/null

TARGETS_JSON="${TMP_DIR}/out/matrix.targets.json"
RESULTS_JSON="${TMP_DIR}/out/matrix.results.json"
SUMMARY_MD="${TMP_DIR}/out/matrix-summary.md"
MANIFEST_JSON="${TMP_DIR}/out/bundle.manifest.json"
DEBIAN_FIRST_RESULTS_JSON="${TMP_DIR}/out-debian-first/matrix.results.json"
DEBIAN_FIRST_SUMMARY_MD="${TMP_DIR}/out-debian-first/matrix-summary.md"
DEBIAN_FIRST_MANIFEST_JSON="${TMP_DIR}/out-debian-first/bundle.manifest.json"

jq -e '
  length == 3
  and ([.[].host_family_id] | sort) == ["debian-apt", "rhel-dnf", "suse-zypper"]
  and (map(select(.host_family_id == "debian-apt"))[0].status == "canonical_release_family")
  and (map(select(.host_family_id == "rhel-dnf"))[0].status == "next_expansion_candidate")
  and (map(select(.host_family_id == "suse-zypper"))[0].status == "later_expansion_candidate")
  and (map(select(.host_family_id == "debian-apt"))[0].helper_run_json_command | contains("--artifact-dir ./dist/linux-family-evidence/debian-apt/artifacts --json"))
  and (map(select(.host_family_id == "rhel-dnf"))[0].helper_run_json_command | contains("--artifact-dir ./dist/linux-family-evidence/rhel-dnf/artifacts --json"))
' "${TARGETS_JSON}" >/dev/null

jq -e '
  (map(select(.host_family_id == "debian-apt"))[0].status == "passed")
  and (map(select(.host_family_id == "debian-apt"))[0].package_manager == "apt-get")
  and (map(select(.host_family_id == "rhel-dnf"))[0].status == "passed")
  and (map(select(.host_family_id == "rhel-dnf"))[0].package_manager == "dnf")
  and (map(select(.host_family_id == "suse-zypper"))[0].status == "pending_live_evidence")
  and (map(select(.host_family_id == "suse-zypper"))[0].evidence_path == null)
' "${RESULTS_JSON}" >/dev/null

jq -e '
  .artifact_schema == "linux_package_acceptance_matrix_bundle_v1"
  and .case_count == 3
  and .passed_case_count == 2
  and .failed_case_count == 0
  and .pending_case_count == 1
  and .passed_families == ["debian-apt", "rhel-dnf"]
  and .pending_families == ["suse-zypper"]
  and .release_claim_boundary == "ubuntu_first_only"
  and .canonical_release_family == "debian-apt"
  and .next_expansion_strategy == "first_unvalidated_family_in_documented_order"
  and .next_expansion_candidate == "suse-zypper"
  and (.next_expansion_helper_run_command | endswith("validate-rpm-package-host.sh --run"))
  and (.next_expansion_helper_run_json_command | endswith("host-validation.json"))
  and (.next_expansion_playbook_command | contains("build-linux-next-expansion-playbook.sh"))
  and (.next_expansion_review_bundle_command | contains("build-linux-next-expansion-review-bundle.sh"))
  and (.next_expansion_status_command | contains("linux-next-expansion-status.sh"))
  and (.next_expansion_wave_bundle_command | contains("build-linux-next-expansion-wave-bundle.sh"))
' "${MANIFEST_JSON}" >/dev/null

grep -Fq -- "- Passed families: \`2\`" "${SUMMARY_MD}"
grep -Fq -- "- Pending: \`suse-zypper\`" "${SUMMARY_MD}"
grep -Fq -- "- Canonical release family: \`debian-apt\`" "${SUMMARY_MD}"
grep -Fq -- "- Release claim boundary: \`ubuntu_first_only\`" "${SUMMARY_MD}"
grep -Fq -- "- Next expansion strategy: \`first_unvalidated_family_in_documented_order\`" "${SUMMARY_MD}"
grep -Fq -- "- Next expansion candidate: \`suse-zypper\`" "${SUMMARY_MD}"
grep -Fq -- "| \`debian-apt\` | \`deb\` | \`passed\` | \`apt-get\` |" "${SUMMARY_MD}"
grep -Fq -- "| \`rhel-dnf\` | \`rpm\` | \`passed\` | \`dnf\` |" "${SUMMARY_MD}"
grep -Fq -- "| \`suse-zypper\` | \`rpm\` | \`pending_live_evidence\` | \`unknown\` | \`none\` |" "${SUMMARY_MD}"

jq -e '
  (map(select(.host_family_id == "debian-apt"))[0].status == "pending_live_evidence")
  and (map(select(.host_family_id == "rhel-dnf"))[0].status == "passed")
  and (map(select(.host_family_id == "suse-zypper"))[0].status == "pending_live_evidence")
' "${DEBIAN_FIRST_RESULTS_JSON}" >/dev/null

jq -e '
  .passed_families == ["rhel-dnf"]
  and .pending_families == ["debian-apt", "suse-zypper"]
  and .next_expansion_strategy == "first_unvalidated_family_in_documented_order"
  and .next_expansion_candidate == "debian-apt"
  and (.next_expansion_helper_run_command | endswith("validate-debian-package-host.sh --run"))
' "${DEBIAN_FIRST_MANIFEST_JSON}" >/dev/null

grep -Fq -- "debian-apt\`" "${DEBIAN_FIRST_SUMMARY_MD}"
grep -Fq -- "- Pending: \`debian-apt, suse-zypper\`" "${DEBIAN_FIRST_SUMMARY_MD}"
grep -Fq -- "- Next expansion candidate: \`debian-apt\`" "${DEBIAN_FIRST_SUMMARY_MD}"

echo "Linux package acceptance matrix contract ok"
