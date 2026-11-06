#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-witness-fixture.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cargo run -p aegis-witness -- \
  --fixture-clienthello-hostname relay.example \
  --fixture-clienthello-alpn h2 \
  --label legacy_tls \
  --output-jsonl "${TMP_DIR}/events.jsonl" \
  --summary-json "${TMP_DIR}/summary.json" \
  --summary-markdown "${TMP_DIR}/summary.md" >/dev/null 2>&1

jq -e '
  .groups[0].label == "legacy_tls" and
  .groups[0].tls_client_hello_records == 1 and
  .groups[0].combined_avg == 1.0
' "${TMP_DIR}/summary.json" >/dev/null

echo "PASS: witness clienthello fixture contract"
