#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-adversarial-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cd "${ROOT}"

cargo run -q -p aegis-measure -- adversarial-runner \
  --dry-run \
  --scenario legacy_tls \
  --network-profile clean-fiber \
  --output-jsonl "${TMP_DIR}/runner.jsonl"

bash "${ROOT}/scripts/run-adversarial-evasion-test.sh" \
  --dry-run \
  --scenario masque_derived \
  --network-profile mobile-lossy \
  --output-jsonl "${TMP_DIR}/wrapper.jsonl"

cargo run -q -p aegis-measure -- adversarial-runner \
  --scenario legacy_tls \
  --network-profile clean-fiber \
  --live-command "true" \
  --output-jsonl "${TMP_DIR}/measured-pass.jsonl"

bash "${ROOT}/scripts/run-adversarial-evasion-test.sh" \
  --scenario https_ws \
  --network-profile clean-fiber \
  --live-command "sh -c 'exit 7'" \
  --output-jsonl "${TMP_DIR}/measured-fail.jsonl"

bash "${ROOT}/scripts/run-adversarial-evasion-test.sh" \
  --live-matrix \
  --live-command "true" \
  --output-jsonl "${TMP_DIR}/measured-matrix.jsonl"

cargo run -q -p aegis-measure -- adversarial-runner-contract-check --tmp-dir "${TMP_DIR}"

if cargo run -q -p aegis-measure -- adversarial-runner --scenario legacy_tls >/dev/null 2>&1; then
  echo "expected runner without --dry-run to fail" >&2
  exit 1
fi

if bash "${ROOT}/scripts/run-adversarial-evasion-test.sh" --dry-run --live-command "true" --output-jsonl "${TMP_DIR}/bad.jsonl" >/dev/null 2>&1; then
  echo "expected conflicting dry-run/live-command failure" >&2
  exit 1
fi

if cargo run -q -p aegis-measure -- adversarial-runner --live-matrix --output-jsonl "${TMP_DIR}/bad-matrix.jsonl" >/dev/null 2>&1; then
  echo "expected live matrix without command failure" >&2
  exit 1
fi

echo "PASS: adversarial runner contract"
