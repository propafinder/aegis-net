#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

exec bash "${ROOT}/scripts/lib/aegis-measure-run.sh" phase-c-fronted-provider-preflight "$@"
