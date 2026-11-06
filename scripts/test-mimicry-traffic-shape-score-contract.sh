#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

bash scripts/test-traffic-shape-score-contract.sh

echo "mimicry traffic-shape-score contract: ok"
