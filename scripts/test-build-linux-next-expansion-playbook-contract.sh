#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-linux-next-expansion-playbook.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-next-expansion-playbook.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

RESULTS_JSON="${TMP_DIR}/matrix.results.json"
MANIFEST_JSON="${TMP_DIR}/bundle.manifest.json"

cat > "${RESULTS_JSON}" <<'EOF'
[
  {
    "host_family_id": "debian-apt",
    "status": "pending_live_evidence",
    "evidence_path": null
  },
  {
    "host_family_id": "rhel-dnf",
    "status": "passed",
    "evidence_path": "/tmp/rhel-run.json"
  },
  {
    "host_family_id": "suse-zypper",
    "status": "pending_live_evidence",
    "evidence_path": null
  }
]
EOF

cat > "${MANIFEST_JSON}" <<'EOF'
{
  "artifact_schema": "linux_package_acceptance_matrix_bundle_v1",
  "matrix_results_artifact": "REPLACE_RESULTS",
  "release_claim_boundary": "ubuntu_first_only",
  "canonical_release_family": "debian-apt",
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

jq --arg matrix_results "${RESULTS_JSON}" \
  '.matrix_results_artifact = $matrix_results' \
  "${MANIFEST_JSON}" >"${MANIFEST_JSON}.tmp"
mv "${MANIFEST_JSON}.tmp" "${MANIFEST_JSON}"

bash "${SCRIPT}" "${TMP_DIR}/out" \
  --matrix-manifest "${MANIFEST_JSON}" \
  --host-label "rocky-canary-host" >/dev/null

OUTPUT_JSON="${TMP_DIR}/out/next-expansion-playbook.json"
OUTPUT_MD="${TMP_DIR}/out/next-expansion-playbook.md"

jq -e '
  .artifact_schema == "linux_next_expansion_playbook_v1"
  and .target_family_id == "debian-apt"
  and .target_wave_role == "canonical_first_non_ubuntu_family"
  and .target_package_family == "deb"
  and .target_host_label == "rocky-canary-host"
  and .target_helper_script == "scripts/validate-debian-package-host.sh"
  and .target_evidence_json == "dist/linux-family-evidence/debian-apt/host-validation.json"
  and .target_artifact_dir == "dist/linux-family-evidence/debian-apt/artifacts"
  and .existing_evidence_paths == ["/tmp/rhel-run.json"]
  and .steps[0].command == "bash scripts/validate-debian-package-host.sh --check"
  and (.steps[1].command | contains("--artifact-dir ./dist/linux-family-evidence/debian-apt/artifacts --json"))
  and (.steps[2].command | contains("--evidence /tmp/rhel-run.json"))
  and (.steps[2].command | contains("--evidence dist/linux-family-evidence/debian-apt/host-validation.json"))
' "${OUTPUT_JSON}" >/dev/null

grep -Fq -- "Linux Next Expansion Playbook" "${OUTPUT_MD}"
grep -Fq -- "- Target family: \`debian-apt\`" "${OUTPUT_MD}"
grep -Fq -- "- Target wave role: \`canonical_first_non_ubuntu_family\`" "${OUTPUT_MD}"

echo "build-linux-next-expansion-playbook contract: ok"
