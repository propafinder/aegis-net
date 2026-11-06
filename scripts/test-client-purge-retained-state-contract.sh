#!/usr/bin/env bash
# Offline selected-removal/report contract; no real host purge or network.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v python3 >/dev/null 2>&1 || { echo 'INVALID: Python 3 is required' >&2; exit 2; }
[[ -f "${BASH}" && -x "${BASH}" ]] || { echo 'INVALID: actual Bash is required' >&2; exit 2; }
umask 077
evidence="$(mktemp -d "${TMPDIR:-/tmp}/aegis-retained-state-contract.XXXXXX")"
completed=0
trap 'if [[ "${completed}" == 1 ]]; then rm -rf -- "${evidence}"; else printf "Retained private QA evidence: %s\n" "${evidence}" >&2; fi' EXIT
python3 -I "${ROOT}/scripts/test-client-purge-retained-state-contract.py" \
  --source-root "${ROOT}" --output "${evidence}/actual" --bash "${BASH}"
completed=1
