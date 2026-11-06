#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

cargo run -q -p aegis-measure -- external-calibration-summary "$@"
