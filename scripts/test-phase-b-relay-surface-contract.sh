#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-b-relay-shape.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cargo test -p aegis-client relay_profile_sample_covers_catalog_and_path_pools
cargo test -p aegis-client relay_profile_distribution_stays_bounded
cargo test -p aegis-client relay_surface_fields_include_request_shape_variants

cat >"${TMP_DIR}/runtime-events-shape-pass.jsonl" <<'JSONL'
{"event_code":"relay_session_started","relay_surface_profile_id":"browser_like_balanced","relay_surface_write_chunk_size":16384,"relay_surface_inter_chunk_delay_ms":0}
{"event_code":"relay_transport_selected","relay_surface_profile_id":"mobile_safari_tight","relay_surface_write_chunk_size":6144,"relay_surface_inter_chunk_delay_ms":3}
JSONL

cargo run -q -p aegis-measure -- phase-b-relay-shape-review \
  --runtime-events-jsonl "${TMP_DIR}/runtime-events-shape-pass.jsonl" \
  --output-json "${TMP_DIR}/relay-shape-review-pass.json" \
  --output-markdown "${TMP_DIR}/relay-shape-review-pass.md" \
  --require-diversity
grep -q '"status": "PASS"' "${TMP_DIR}/relay-shape-review-pass.json"
grep -q 'Phase B Relay Shape Review' "${TMP_DIR}/relay-shape-review-pass.md"

cat >"${TMP_DIR}/runtime-events-shape-fail.jsonl" <<'JSONL'
{"event_code":"relay_transport_selected","relay_surface_profile_id":"bad_shape","relay_surface_write_chunk_size":16,"relay_surface_inter_chunk_delay_ms":500}
JSONL

if cargo run -q -p aegis-measure -- phase-b-relay-shape-review \
  --runtime-events-jsonl "${TMP_DIR}/runtime-events-shape-fail.jsonl" \
  --output-json "${TMP_DIR}/relay-shape-review-fail.json" >/dev/null 2>&1; then
  echo "expected Phase B relay shape range failure" >&2
  exit 1
fi
grep -q '"status": "FAIL"' "${TMP_DIR}/relay-shape-review-fail.json"

echo "PASS: Phase B relay surface contract"
