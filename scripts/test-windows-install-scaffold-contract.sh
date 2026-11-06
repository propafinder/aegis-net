#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/windows/install-windows-client.ps1"

grep -q "aegis-winctl.exe" "${SCRIPT}"
grep -q "service install" "${SCRIPT}"
grep -q "env:ProgramFiles" "${SCRIPT}"
grep -q "env:ProgramData" "${SCRIPT}"
grep -q "env:LOCALAPPDATA" "${SCRIPT}"
grep -q "env:APPDATA" "${SCRIPT}"
grep -q "install-manifest.json" "${SCRIPT}"
grep -q 'broad_wfp_filters_installed = $false' "${SCRIPT}"
if grep -Eq "install-controlled-tcp|FWPM_LAYER" "${SCRIPT}"; then
  echo "installer must not install WFP filters by default" >&2
  exit 1
fi
if grep -Eq "verdict|result\\.json" "${SCRIPT}"; then
  echo "installer must not contain proof verdict/result logic" >&2
  exit 1
fi

echo "ok"
