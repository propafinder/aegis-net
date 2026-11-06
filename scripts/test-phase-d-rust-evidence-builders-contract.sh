#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

builders=(
  scripts/build-phase-d-android-reach-evidence.sh
  scripts/build-phase-d-macos-reach-evidence.sh
  scripts/build-phase-d-windows-reach-evidence.sh
  scripts/build-phase-d-reach-gate.sh
)
forbidden_interpreters=(py"thon" py"thon3" node ruby perl)
forbidden_pattern="$(IFS='|'; printf '%s' "${forbidden_interpreters[*]}")"

for builder in "${builders[@]}"; do
  test -x "${builder}"
  grep -q 'cargo run -q -p aegis-measure -- phase-d-' "${builder}"
  if grep -Eq "${forbidden_pattern}" "${builder}"; then
    echo "Phase D evidence builder must stay Rust-owned: ${builder}" >&2
    exit 1
  fi
done

echo "ok"
