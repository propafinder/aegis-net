#!/usr/bin/env bash
# Literal CI invocation with fake sudo/python; never run the native driver.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 -I "${ROOT}/scripts/test-deviceguard-ci-privilege-inert.py" "$@"
