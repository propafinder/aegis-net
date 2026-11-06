#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-knowledge-check.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cargo run -q -p aegis-knowledge -- refresh-dry-run >"${TMP_DIR}/refresh.json"

cargo run -q -p aegis-knowledge -- validate-refresh-dry-run --input "${TMP_DIR}/refresh.json"

cargo test -p aegis-knowledge

echo "PASS: knowledge corpus check"
