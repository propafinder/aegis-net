#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-linux-next-expansion-wave-bundle.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-next-expansion-wave.XXXXXX")"
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

reject_file_contains() {
  local file="$1"
  local unexpected="$2"
  if grep -Fq -- "${unexpected}" "${file}"; then
    echo "expected ${file} not to contain: ${unexpected}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

PENDING_RESULTS="${TMP_DIR}/pending-results.json"
PENDING_MANIFEST="${TMP_DIR}/pending-manifest.json"
READY_RESULTS="${TMP_DIR}/ready-results.json"
READY_MANIFEST="${TMP_DIR}/ready-manifest.json"
TARGET_EVIDENCE="${TMP_DIR}/rhel-host-validation.json"

cat > "${PENDING_RESULTS}" <<'EOF'
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

cat > "${PENDING_MANIFEST}" <<'EOF'
{
  "artifact_schema": "linux_package_acceptance_matrix_bundle_v1",
  "matrix_results_artifact": "REPLACE_PENDING_RESULTS",
  "matrix_summary_artifact": "/tmp/matrix-summary.md",
  "release_claim_boundary": "ubuntu_first_only",
  "canonical_release_family": "debian-apt",
  "passed_families": [],
  "failed_families": [],
  "pending_families": ["debian-apt", "rhel-dnf", "suse-zypper"],
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

cat > "${READY_RESULTS}" <<'EOF'
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

replace_in_file "${PENDING_MANIFEST}" "REPLACE_PENDING_RESULTS" "${PENDING_RESULTS}"

cat > "${TMP_DIR}/debian-host-validation.json" <<'EOF'
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

cat > "${READY_MANIFEST}" <<'EOF'
{
  "artifact_schema": "linux_package_acceptance_matrix_bundle_v1",
  "matrix_results_artifact": "REPLACE_READY_RESULTS",
  "matrix_summary_artifact": "/tmp/matrix-summary.md",
  "release_claim_boundary": "ubuntu_first_only",
  "canonical_release_family": "debian-apt",
  "passed_families": ["debian-apt"],
  "failed_families": [],
  "pending_families": ["rhel-dnf", "suse-zypper"],
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

replace_in_file "${READY_MANIFEST}" "REPLACE_READY_RESULTS" "${READY_RESULTS}"
replace_in_file "${READY_RESULTS}" "REPLACE_DEBIAN_EVIDENCE" "${TMP_DIR}/debian-host-validation.json"

bash "${SCRIPT}" "${TMP_DIR}/plan-out" \
  --matrix-manifest "${PENDING_MANIFEST}" \
  --host-label "rocky-canary-host" >/dev/null

bash "${SCRIPT}" "${TMP_DIR}/review-out" \
  --matrix-manifest "${READY_MANIFEST}" \
  --target-evidence "${TARGET_EVIDENCE}" \
  --host-label "rocky-canary-host" >/dev/null

PLAN_WAVE_MANIFEST="${TMP_DIR}/plan-out/next-expansion-wave.manifest.json"
REVIEW_WAVE_MANIFEST="${TMP_DIR}/review-out/next-expansion-wave.manifest.json"
require_file_contains "${PLAN_WAVE_MANIFEST}" '"artifact_schema": "linux_next_expansion_wave_bundle_v1"'
require_file_contains "${PLAN_WAVE_MANIFEST}" '"mode": "plan_only"'
require_file_contains "${PLAN_WAVE_MANIFEST}" '"target_family_id": "debian-apt"'
require_file_contains "${PLAN_WAVE_MANIFEST}" '"target_wave_role": "canonical_first_non_ubuntu_family"'
require_file_contains "${PLAN_WAVE_MANIFEST}" '"review_bundle_manifest_json": null'
require_file_contains "${PLAN_WAVE_MANIFEST}" '"expansion_status": "pending_next_family"'
require_file_contains "${PLAN_WAVE_MANIFEST}" "build-linux-next-expansion-playbook.sh"
require_file_contains "${REVIEW_WAVE_MANIFEST}" '"artifact_schema": "linux_next_expansion_wave_bundle_v1"'
require_file_contains "${REVIEW_WAVE_MANIFEST}" '"mode": "review_with_evidence"'
require_file_contains "${REVIEW_WAVE_MANIFEST}" '"target_family_id": "rhel-dnf"'
require_file_contains "${REVIEW_WAVE_MANIFEST}" '"target_wave_role": "subsequent_non_ubuntu_family"'
require_file_contains "${REVIEW_WAVE_MANIFEST}" "next-expansion-review.manifest.json"
require_file_contains "${REVIEW_WAVE_MANIFEST}" '"expansion_status": "target_validated_next_candidate_pending"'
require_file_contains "${REVIEW_WAVE_MANIFEST}" "build-linux-next-expansion-playbook.sh"
reject_file_contains "${PENDING_MANIFEST}" "REPLACE_PENDING_RESULTS"
reject_file_contains "${READY_MANIFEST}" "REPLACE_READY_RESULTS"
reject_file_contains "${READY_RESULTS}" "REPLACE_DEBIAN_EVIDENCE"

echo "build-linux-next-expansion-wave-bundle contract: ok"
