#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-ubuntu-controlled-pilot-playbook.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-ubuntu-pilot-playbook.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

bash "${SCRIPT}" "${TMP_DIR}/out" \
  --relay-host "relay-a" \
  --client-host "client-b" \
  --blocked-shape "dpi-lab-shape" \
  --bundle "/tmp/client-bundle.tar.gz" >/dev/null

OUTPUT_JSON="${TMP_DIR}/out/pilot-playbook.json"
OUTPUT_MD="${TMP_DIR}/out/pilot-playbook.md"

jq -e '
  .artifact_schema == "ubuntu_controlled_pilot_playbook_v1"
  and .relay_host_label == "relay-a"
  and .client_host_label == "client-b"
  and .blocked_shape_label == "dpi-lab-shape"
  and .bundle_url_example == null
  and .bundle_input == {"kind":"bundle","path":"/tmp/client-bundle.tar.gz"}
  and .rollout_acceptance.must_pass_checks[0].id == "server_service_active"
  and .rollout_acceptance.advisory_checks[0].id == "dns_runtime_ready_when_requested"
  and (.required_release_artifacts | index("ubuntu-operator-reapply-canary.json") != null)
  and (.required_release_artifacts | index("field-pilot-remote-bundle.json") != null)
  and .required_release_artifacts[0] == "validation-summary.json"
  and any(.steps[]; .phase == "operator_canary")
  and any(.steps[]; .phase == "release_wave_bundle")
  and any(.steps[]; .phase == "field_pilot_remote_bundle")
  and any(.steps[]; .phase == "release_review")
' "${OUTPUT_JSON}" >/dev/null

grep -Fq -- "Ubuntu Controlled Pilot Playbook" "${OUTPUT_MD}"
grep -Fq -- "## Must-Pass Checks" "${OUTPUT_MD}"
grep -Fq -- "## Advisory Checks" "${OUTPUT_MD}"
grep -Fq -- "\`release_review\` on \`client-b\`" "${OUTPUT_MD}"


# The remote private pathname above need not exist on this planning host.
# Deprecated values must be refused before any new output directory is made.
for form in split equals; do
  refused_dir="${TMP_DIR}/rejected-${form}"
  if [[ "$form" == split ]]; then
    deprecated=(--bundle-url 'https://fixture.invalid/?token=INLINE_PRIVATE_SENTINEL')
  else
    deprecated=('--bundle-url=https://fixture.invalid/?token=INLINE_PRIVATE_SENTINEL')
  fi
  if bash "${SCRIPT}" "$refused_dir" "${deprecated[@]}" >"${TMP_DIR}/refusal-${form}.log" 2>&1; then
    echo "deprecated inline bundle form accepted" >&2
    exit 1
  fi
  [[ ! -e "$refused_dir" ]] || { echo "deprecated form created outputs" >&2; exit 1; }
  if grep -q 'INLINE_PRIVATE_SENTINEL' "${TMP_DIR}/refusal-${form}.log"; then
    echo "deprecated form reflected private material" >&2
    exit 1
  fi
  grep -q 'Use --bundle-url-file' "${TMP_DIR}/refusal-${form}.log"
done

echo "ubuntu controlled pilot playbook contract: ok"
