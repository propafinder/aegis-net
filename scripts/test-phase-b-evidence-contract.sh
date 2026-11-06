#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

bash scripts/test-phase-b-baseline-review-contract.sh
bash scripts/test-phase-b-ja3-targets-contract.sh
bash scripts/test-phase-b-relay-surface-contract.sh
bash scripts/test-phase-b-tls-profile-target-contract.sh
bash scripts/test-phase-b-active-probe-contract.sh
bash scripts/test-phase-b-live-evidence-review-contract.sh
bash scripts/test-phase-b-runtime-evidence-bundle-contract.sh

echo "PASS: Phase B evidence contract"
