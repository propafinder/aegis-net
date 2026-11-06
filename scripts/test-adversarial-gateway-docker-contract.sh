#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-gateway-docker-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

FAKE_DOCKER="${TMP_DIR}/docker"
DOCKER_LOG="${TMP_DIR}/docker.log"

cat >"${FAKE_DOCKER}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${AEGIS_TEST_DOCKER_LOG:?}"

if [[ "$1" == "build" ]]; then
  exit 0
fi

if [[ "$1" == "run" ]]; then
  out_dir=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -v)
        out_dir="${2%%:/out}"
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done
  mkdir -p "${out_dir}"
  cat >"${out_dir}/events.jsonl" <<'JSONL'
{"event":"adversarial_scenario_measured","schema_version":1,"mode":"live_command","scenario":"legacy_tls","transport":"legacy_tls","network_profile":"clean-fiber","threshold":0.85,"status":"PASS","reason":"probe-command-succeeded","returncode":0}
JSONL
  exit 0
fi

echo "unexpected docker command: $*" >&2
exit 2
EOF
chmod +x "${FAKE_DOCKER}"

AEGIS_DOCKER_BIN="${FAKE_DOCKER}" \
AEGIS_TEST_DOCKER_LOG="${DOCKER_LOG}" \
bash "${ROOT}/scripts/run-adversarial-gateway-docker.sh" \
  --output-dir "${TMP_DIR}/out" \
  --scenario legacy_tls \
  --network-profile clean-fiber \
  --live-command "true" >/dev/null

OUT="${TMP_DIR}/out"
LOG="$(cat "${DOCKER_LOG}")"
EVENTS="$(cat "${OUT}/events.jsonl")"

[[ "${LOG}" == *"build"* ]]
[[ "${LOG}" == *"Dockerfile.dpi-gateway"* ]]
[[ "${LOG}" == *"run"* ]]
[[ "${LOG}" == *"--scenario legacy_tls"* ]]
[[ "${LOG}" == *"--network-profile clean-fiber"* ]]
[[ "${LOG}" == *"-v ${OUT}:/out"* ]]
[[ "${EVENTS}" == *'"event":"adversarial_scenario_measured"'* ]]
[[ "${EVENTS}" == *'"status":"PASS"'* ]]
[[ -f "${OUT}/commands.txt" ]]
[[ -f "${OUT}/docker-build.stdout.log" ]]
[[ -f "${OUT}/docker-run.stderr.log" ]]

if AEGIS_DOCKER_BIN="${FAKE_DOCKER}" bash "${ROOT}/scripts/run-adversarial-gateway-docker.sh" --output-dir "${TMP_DIR}/bad" >/dev/null 2>&1; then
  echo "expected missing required arguments failure" >&2
  exit 1
fi

echo "PASS: adversarial gateway docker contract"
