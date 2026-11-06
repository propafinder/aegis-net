#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-witness-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

FAKE_BIN="${TMP_DIR}/aegis-witness"
FAKE_TCPDUMP="${TMP_DIR}/tcpdump"
ARG_LOG="${TMP_DIR}/args.txt"
TCPDUMP_ARG_LOG="${TMP_DIR}/tcpdump-args.txt"
mkdir -p "${TMP_DIR}/bin"

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

require_regular_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "expected file to exist: ${path}" >&2
    exit 1
  fi
}

cat >"${FAKE_BIN}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >"${AEGIS_TEST_WITNESS_ARG_LOG:?}"

events=""
summary_json=""
summary_markdown=""
label="unlabeled"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-jsonl)
      events="$2"
      shift 2
      ;;
    --summary-json)
      summary_json="$2"
      shift 2
      ;;
    --summary-markdown)
      summary_markdown="$2"
      shift 2
      ;;
    --label)
      label="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

mkdir -p "$(dirname "${events}")"
printf '{"event":"witness_tls_classification","label":"%s"}\n' "${label}" >"${events}"
printf '{"schema_version":1,"groups":[{"label":"%s","total_records":1}]}\n' "${label}" >"${summary_json}"
printf '| Label | Records |\n|---|---:|\n| %s | 1 |\n' "${label}" >"${summary_markdown}"
EOF
chmod +x "${FAKE_BIN}"

cat >"${FAKE_TCPDUMP}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >"${AEGIS_TEST_TCPDUMP_ARG_LOG:?}"
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -w)
      out="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "${out}")"
printf 'fake pcap\n' >"${out}"
EOF
chmod +x "${FAKE_TCPDUMP}"

touch "${TMP_DIR}/capture.pcap"

AEGIS_WITNESS_BIN="${FAKE_BIN}" \
AEGIS_TEST_WITNESS_ARG_LOG="${ARG_LOG}" \
bash "${ROOT}/scripts/run-hostile-witness-audit.sh" \
  --output-dir "${TMP_DIR}/out" \
  --label legacy_tls \
  --input-pcap "${TMP_DIR}/capture.pcap" >/dev/null

require_file_contains "${ARG_LOG}" "--input-pcap"
require_file_contains "${ARG_LOG}" "--label legacy_tls"
require_file_contains "${ARG_LOG}" "--output-jsonl"
require_file_contains "${ARG_LOG}" "--summary-json"
require_file_contains "${ARG_LOG}" "--summary-markdown"
require_regular_file "${TMP_DIR}/out/events.jsonl"
require_regular_file "${TMP_DIR}/out/summary.json"
require_regular_file "${TMP_DIR}/out/summary.md"
require_regular_file "${TMP_DIR}/out/stdout.log"
require_regular_file "${TMP_DIR}/out/stderr.log"
require_regular_file "${TMP_DIR}/out/commands.txt"
require_file_contains "${TMP_DIR}/out/summary.md" "legacy_tls"

AEGIS_WITNESS_BIN="${FAKE_BIN}" \
AEGIS_TCPDUMP_BIN="${FAKE_TCPDUMP}" \
AEGIS_TEST_WITNESS_ARG_LOG="${ARG_LOG}" \
AEGIS_TEST_TCPDUMP_ARG_LOG="${TCPDUMP_ARG_LOG}" \
bash "${ROOT}/scripts/run-hostile-witness-audit.sh" \
  --output-dir "${TMP_DIR}/out-interface" \
  --label interface_tls \
  --interface lo0 \
  --duration 0 >/dev/null

require_file_contains "${TCPDUMP_ARG_LOG}" "-i lo0"
require_file_contains "${TCPDUMP_ARG_LOG}" "-w"
require_file_contains "${ARG_LOG}" "--input-pcap"
require_file_contains "${ARG_LOG}" "out-interface/capture.pcap"
require_regular_file "${TMP_DIR}/out-interface/capture.pcap"
require_regular_file "${TMP_DIR}/out-interface/tcpdump.stdout.log"
require_regular_file "${TMP_DIR}/out-interface/tcpdump.stderr.log"
require_regular_file "${TMP_DIR}/out-interface/events.jsonl"
require_regular_file "${TMP_DIR}/out-interface/summary.json"
require_regular_file "${TMP_DIR}/out-interface/summary.md"

if bash "${ROOT}/scripts/run-hostile-witness-audit.sh" --output-dir "${TMP_DIR}/bad" >/dev/null 2>&1; then
  echo "expected missing input failure" >&2
  exit 1
fi

echo "PASS: hostile witness audit wrapper contract"
