#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cargo run -q -p aegis-measure -- build-linux-wide-live-audit-manifest "$@"
