#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-b-ja3.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

bash "${ROOT}/scripts/build-phase-b-ja3-targets.sh" \
  --output "${TMP_DIR}/ja3-targets.json"

cargo run -q -p aegis-knowledge -- validate-ja3-targets \
  --input "${TMP_DIR}/ja3-targets.json"

grep -q '"event": "phase_b_ja3_profile_targets"' "${TMP_DIR}/ja3-targets.json"
grep -q '"target_class": "https_ws"' "${TMP_DIR}/ja3-targets.json"
grep -q '"target_class": "masque_derived"' "${TMP_DIR}/ja3-targets.json"

cat >"${TMP_DIR}/bad-ja3-targets.json" <<'JSON'
{
  "event": "phase_b_ja3_profile_targets",
  "schema_version": 1,
  "corpus_version": "fixture",
  "targets": [
    {
      "id": "bad",
      "browser_family": "bad",
      "target_class": "https_ws",
      "ja3_hash": "bad",
      "alpn": ["h3"],
      "weight": 1.0,
      "source_label": "fixture"
    }
  ]
}
JSON

if cargo run -q -p aegis-knowledge -- validate-ja3-targets --input "${TMP_DIR}/bad-ja3-targets.json" >/dev/null 2>&1; then
  echo "expected JA3 target/runtime ALPN mismatch failure" >&2
  exit 1
fi

echo "PASS: Phase B JA3 targets contract"
