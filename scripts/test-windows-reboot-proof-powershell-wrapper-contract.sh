#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/windows/run-windows-wide-service-reboot-proof.ps1"

grep -q "aegis-winctl" "${SCRIPT}"
grep -q "proof service-reboot" "${SCRIPT}"

if grep -Eq "ConvertTo-Json|Set-Content.*result\\.json|BLOCKED_BY_|verdict|Write-Result|Get-CimInstance|Win32_Service" "${SCRIPT}"; then
  echo "PowerShell wrapper must not contain JSON/verdict/service proof logic" >&2
  exit 1
fi

echo "ok"
