#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/windows/uninstall-windows-client.ps1"

grep -q "aegis-winctl.exe" "${SCRIPT}"
grep -q "service stop" "${SCRIPT}"
grep -q "service uninstall" "${SCRIPT}"
grep -q "wfp cleanup" "${SCRIPT}"
grep -q "CleanupWfpProofState" "${SCRIPT}"
grep -q "Config/state preserved unless -Purge was used" "${SCRIPT}"
if grep -Eq "install-controlled-tcp|FWPM_LAYER|broad.*filter" "${SCRIPT}"; then
  echo "uninstaller must not install WFP filters" >&2
  exit 1
fi
if grep -Eq "verdict|result\\.json" "${SCRIPT}"; then
  echo "uninstaller must not contain proof verdict/result logic" >&2
  exit 1
fi

echo "ok"
