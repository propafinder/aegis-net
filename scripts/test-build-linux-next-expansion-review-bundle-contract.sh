#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-linux-next-expansion-review-bundle.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-next-expansion-review.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

replace_in_file() {
  local path="$1"
  local needle="$2"
  local replacement="$3"
  local tmp_path="${path}.tmp"
  awk -v needle="${needle}" -v replacement="${replacement}" '{ gsub(needle, replacement); print }' "${path}" > "${tmp_path}"
  mv "${tmp_path}" "${path}"
}

require_file_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -Fq -- "${expected}" "${file}"; then
    echo "expected ${file} to contain: ${expected}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

FIRST_RESULTS_JSON="${TMP_DIR}/first-matrix.results.json"
FIRST_MANIFEST_JSON="${TMP_DIR}/first-bundle.manifest.json"
FIRST_TARGET_EVIDENCE="${TMP_DIR}/first-debian-host-validation.json"
RESULTS_JSON="${TMP_DIR}/matrix.results.json"
MANIFEST_JSON="${TMP_DIR}/bundle.manifest.json"
TARGET_EVIDENCE="${TMP_DIR}/rhel-host-validation.json"
DEBIAN_EVIDENCE="${TMP_DIR}/debian-host-validation.json"

cat > "${DEBIAN_EVIDENCE}" <<'EOF'
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

cat > "${FIRST_RESULTS_JSON}" <<'EOF'
[
  {
    "host_family_id": "debian-apt",
    "package_family": "deb",
    "validation_tier": "packaging_validation_target",
    "status": "pending_live_evidence",
    "evidence_path": null,
    "artifact_schema": null,
    "os_pretty_name": null,
    "package_manager": null,
    "supported_product_contour": null,
    "supported_operator_scope": null,
    "helper_exit_code": null,
    "mode": null,
    "notes": "No run-mode host evidence collected yet for this family."
  },
  {
    "host_family_id": "rhel-dnf",
    "package_family": "rpm",
    "validation_tier": "packaging_validation_target",
    "status": "pending_live_evidence",
    "evidence_path": null,
    "artifact_schema": null,
    "os_pretty_name": null,
    "package_manager": null,
    "supported_product_contour": null,
    "supported_operator_scope": null,
    "helper_exit_code": null,
    "mode": null,
    "notes": "No run-mode host evidence collected yet for this family."
  },
  {
    "host_family_id": "suse-zypper",
    "package_family": "rpm",
    "validation_tier": "packaging_validation_target",
    "status": "pending_live_evidence",
    "evidence_path": null,
    "artifact_schema": null,
    "os_pretty_name": null,
    "package_manager": null,
    "supported_product_contour": null,
    "supported_operator_scope": null,
    "helper_exit_code": null,
    "mode": null,
    "notes": "No run-mode host evidence collected yet for this family."
  }
]
EOF

cat > "${FIRST_MANIFEST_JSON}" <<'EOF'
{
  "artifact_schema": "linux_package_acceptance_matrix_bundle_v1",
  "matrix_results_artifact": "REPLACE_FIRST_RESULTS",
  "matrix_summary_artifact": "/tmp/matrix-summary.md",
  "release_claim_boundary": "ubuntu_first_only",
  "canonical_release_family": "debian-apt",
  "next_expansion_strategy": "first_unvalidated_family_in_documented_order",
  "next_expansion_candidate": "debian-apt",
  "documented_host_family_matrix": [
    {
      "host_family_id": "debian-apt",
      "package_family": "deb",
      "validation_tier": "packaging_validation_target",
      "status": "canonical_release_family",
      "helper_script": "scripts/validate-debian-package-host.sh",
      "helper_check_command": "bash scripts/validate-debian-package-host.sh --check",
      "helper_run_command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-debian-package-host.sh --run",
      "helper_run_json_command": "mkdir -p ./dist/linux-family-evidence/debian-apt && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-debian-package-host.sh --run --artifact-dir ./dist/linux-family-evidence/debian-apt/artifacts --json > ./dist/linux-family-evidence/debian-apt/host-validation.json"
    },
    {
      "host_family_id": "rhel-dnf",
      "package_family": "rpm",
      "validation_tier": "packaging_validation_target",
      "status": "next_expansion_candidate",
      "helper_script": "scripts/validate-rpm-package-host.sh",
      "helper_check_command": "bash scripts/validate-rpm-package-host.sh --check",
      "helper_run_command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-rpm-package-host.sh --run",
      "helper_run_json_command": "mkdir -p ./dist/linux-family-evidence/rhel-dnf && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-rpm-package-host.sh --run --artifact-dir ./dist/linux-family-evidence/rhel-dnf/artifacts --json > ./dist/linux-family-evidence/rhel-dnf/host-validation.json"
    },
    {
      "host_family_id": "suse-zypper",
      "package_family": "rpm",
      "validation_tier": "packaging_validation_target",
      "status": "later_expansion_candidate",
      "helper_script": "scripts/validate-rpm-package-host.sh",
      "helper_check_command": "bash scripts/validate-rpm-package-host.sh --check",
      "helper_run_command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-rpm-package-host.sh --run",
      "helper_run_json_command": "mkdir -p ./dist/linux-family-evidence/suse-zypper && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-rpm-package-host.sh --run --artifact-dir ./dist/linux-family-evidence/suse-zypper/artifacts --json > ./dist/linux-family-evidence/suse-zypper/host-validation.json"
    }
  ]
}
EOF

replace_in_file "${FIRST_MANIFEST_JSON}" "REPLACE_FIRST_RESULTS" "${FIRST_RESULTS_JSON}"

cp "${DEBIAN_EVIDENCE}" "${FIRST_TARGET_EVIDENCE}"

cat > "${RESULTS_JSON}" <<'EOF'
[
  {
    "host_family_id": "debian-apt",
    "package_family": "deb",
    "validation_tier": "packaging_validation_target",
    "status": "passed",
    "evidence_path": "REPLACE_DEBIAN_EVIDENCE",
    "artifact_schema": "debian_package_host_validation_v1",
    "os_pretty_name": "Debian 12",
    "package_manager": "apt-get",
    "supported_product_contour": "linux_first_split_deb_package_validation",
    "supported_operator_scope": "debian_host_package_lifecycle_validation",
    "helper_exit_code": 0,
    "mode": "run",
    "notes": "run-mode validation helper passed on a live host"
  },
  {
    "host_family_id": "rhel-dnf",
    "package_family": "rpm",
    "validation_tier": "packaging_validation_target",
    "status": "pending_live_evidence",
    "evidence_path": null,
    "artifact_schema": null,
    "os_pretty_name": null,
    "package_manager": null,
    "supported_product_contour": null,
    "supported_operator_scope": null,
    "helper_exit_code": null,
    "mode": null,
    "notes": "No run-mode host evidence collected yet for this family."
  },
  {
    "host_family_id": "suse-zypper",
    "package_family": "rpm",
    "validation_tier": "packaging_validation_target",
    "status": "pending_live_evidence",
    "evidence_path": null,
    "artifact_schema": null,
    "os_pretty_name": null,
    "package_manager": null,
    "supported_product_contour": null,
    "supported_operator_scope": null,
    "helper_exit_code": null,
    "mode": null,
    "notes": "No run-mode host evidence collected yet for this family."
  }
]
EOF

cat > "${MANIFEST_JSON}" <<'EOF'
{
  "artifact_schema": "linux_package_acceptance_matrix_bundle_v1",
  "matrix_results_artifact": "REPLACE_RESULTS",
  "matrix_summary_artifact": "/tmp/matrix-summary.md",
  "release_claim_boundary": "ubuntu_first_only",
  "canonical_release_family": "debian-apt",
  "next_expansion_candidate": "rhel-dnf",
  "documented_host_family_matrix": [
    {
      "host_family_id": "debian-apt",
      "package_family": "deb",
      "validation_tier": "packaging_validation_target",
      "status": "canonical_release_family",
      "helper_script": "scripts/validate-debian-package-host.sh",
      "helper_check_command": "bash scripts/validate-debian-package-host.sh --check",
      "helper_run_command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-debian-package-host.sh --run",
      "helper_run_json_command": "mkdir -p ./dist/linux-family-evidence/debian-apt && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-debian-package-host.sh --run --artifact-dir ./dist/linux-family-evidence/debian-apt/artifacts --json > ./dist/linux-family-evidence/debian-apt/host-validation.json"
    },
    {
      "host_family_id": "rhel-dnf",
      "package_family": "rpm",
      "validation_tier": "packaging_validation_target",
      "status": "next_expansion_candidate",
      "helper_script": "scripts/validate-rpm-package-host.sh",
      "helper_check_command": "bash scripts/validate-rpm-package-host.sh --check",
      "helper_run_command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-rpm-package-host.sh --run",
      "helper_run_json_command": "mkdir -p ./dist/linux-family-evidence/rhel-dnf && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-rpm-package-host.sh --run --artifact-dir ./dist/linux-family-evidence/rhel-dnf/artifacts --json > ./dist/linux-family-evidence/rhel-dnf/host-validation.json"
    },
    {
      "host_family_id": "suse-zypper",
      "package_family": "rpm",
      "validation_tier": "packaging_validation_target",
      "status": "later_expansion_candidate",
      "helper_script": "scripts/validate-rpm-package-host.sh",
      "helper_check_command": "bash scripts/validate-rpm-package-host.sh --check",
      "helper_run_command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-rpm-package-host.sh --run",
      "helper_run_json_command": "mkdir -p ./dist/linux-family-evidence/suse-zypper && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-rpm-package-host.sh --run --artifact-dir ./dist/linux-family-evidence/suse-zypper/artifacts --json > ./dist/linux-family-evidence/suse-zypper/host-validation.json"
    }
  ]
}
EOF

replace_in_file "${MANIFEST_JSON}" "REPLACE_RESULTS" "${RESULTS_JSON}"
replace_in_file "${RESULTS_JSON}" "REPLACE_DEBIAN_EVIDENCE" "${DEBIAN_EVIDENCE}"

cat > "${TARGET_EVIDENCE}" <<'EOF'
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

bash "${SCRIPT}" "${TMP_DIR}/first-out" \
  --matrix-manifest "${FIRST_MANIFEST_JSON}" \
  --target-evidence "${FIRST_TARGET_EVIDENCE}" \
  --host-label "debian-canary-host" >/dev/null

bash "${SCRIPT}" "${TMP_DIR}/out" \
  --matrix-manifest "${MANIFEST_JSON}" \
  --target-evidence "${TARGET_EVIDENCE}" \
  --host-label "rocky-canary-host" >/dev/null

FIRST_REVIEW_JSON="${TMP_DIR}/first-out/next-expansion-review.json"
FIRST_BUNDLE_JSON="${TMP_DIR}/first-out/next-expansion-review.manifest.json"
FIRST_REFRESHED_JSON="${TMP_DIR}/first-out/refreshed-matrix/bundle.manifest.json"
REVIEW_JSON="${TMP_DIR}/out/next-expansion-review.json"
BUNDLE_JSON="${TMP_DIR}/out/next-expansion-review.manifest.json"
REFRESHED_JSON="${TMP_DIR}/out/refreshed-matrix/bundle.manifest.json"

require_file_contains "${FIRST_REVIEW_JSON}" '"artifact_schema": "linux_next_expansion_review_v1"'
require_file_contains "${FIRST_REVIEW_JSON}" '"target_family_id": "debian-apt"'
require_file_contains "${FIRST_REVIEW_JSON}" '"target_wave_role": "canonical_first_non_ubuntu_family"'
require_file_contains "${FIRST_REVIEW_JSON}" '"target_host_label": "debian-canary-host"'
require_file_contains "${FIRST_REVIEW_JSON}" '"target_result_status": "passed"'
require_file_contains "${FIRST_REVIEW_JSON}" '"review_verdict": "ready"'
require_file_contains "${FIRST_REVIEW_JSON}" '"next_expansion_candidate_before_refresh": "debian-apt"'
require_file_contains "${FIRST_REVIEW_JSON}" '"next_expansion_candidate_after_refresh": "rhel-dnf"'
require_file_contains "${FIRST_REVIEW_JSON}" '"release_claim_boundary": "ubuntu_first_only"'
require_file_contains "${FIRST_BUNDLE_JSON}" '"artifact_schema": "linux_next_expansion_review_bundle_v1"'
require_file_contains "${FIRST_BUNDLE_JSON}" '"target_family_id": "debian-apt"'
require_file_contains "${FIRST_BUNDLE_JSON}" '"target_wave_role": "canonical_first_non_ubuntu_family"'
require_file_contains "${FIRST_BUNDLE_JSON}" '"review_verdict": "ready"'
require_file_contains "${FIRST_REFRESHED_JSON}" '"next_expansion_candidate": "rhel-dnf"'
require_file_contains "${FIRST_REFRESHED_JSON}" '"passed_case_count": 1'
require_file_contains "${FIRST_REFRESHED_JSON}" '"debian-apt"'

require_file_contains "${REVIEW_JSON}" '"artifact_schema": "linux_next_expansion_review_v1"'
require_file_contains "${REVIEW_JSON}" '"target_family_id": "rhel-dnf"'
require_file_contains "${REVIEW_JSON}" '"target_wave_role": "subsequent_non_ubuntu_family"'
require_file_contains "${REVIEW_JSON}" '"target_host_label": "rocky-canary-host"'
require_file_contains "${REVIEW_JSON}" '"target_result_status": "passed"'
require_file_contains "${REVIEW_JSON}" '"review_verdict": "ready"'
require_file_contains "${REVIEW_JSON}" '"next_expansion_candidate_before_refresh": "rhel-dnf"'
require_file_contains "${REVIEW_JSON}" '"next_expansion_candidate_after_refresh": "suse-zypper"'
require_file_contains "${REVIEW_JSON}" '"release_claim_boundary": "ubuntu_first_only"'
require_file_contains "${BUNDLE_JSON}" '"artifact_schema": "linux_next_expansion_review_bundle_v1"'
require_file_contains "${BUNDLE_JSON}" '"target_family_id": "rhel-dnf"'
require_file_contains "${BUNDLE_JSON}" '"target_wave_role": "subsequent_non_ubuntu_family"'
require_file_contains "${BUNDLE_JSON}" '"review_verdict": "ready"'
require_file_contains "${REFRESHED_JSON}" '"next_expansion_candidate": "suse-zypper"'
require_file_contains "${REFRESHED_JSON}" '"passed_case_count": 2'
require_file_contains "${REFRESHED_JSON}" '"debian-apt"'
require_file_contains "${REFRESHED_JSON}" '"rhel-dnf"'

echo "build-linux-next-expansion-review-bundle contract: ok"
