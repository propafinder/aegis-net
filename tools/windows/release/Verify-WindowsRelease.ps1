[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Package,
  [Parameter(Mandatory)][string]$ManifestSignature,
  [string]$Policy = (Join-Path $PSScriptRoot 'authenticode-policy.json')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PrivateSnapshot.ps1')
$snapshot = New-PrivateReleaseSnapshot -Package $Package -ManifestSignature $ManifestSignature -Policy $Policy
$locks = Open-PrivateSnapshotLocks $snapshot
try {
$root = $snapshot.Package
$ManifestSignature = $snapshot.Signature
$Policy = $snapshot.Policy
# This is the pre-execution boundary: authenticate the verifier executable with
# Windows trust, the committed certificate pin and RFC3161 before launching it.
try {
  & (Join-Path $PSScriptRoot 'Test-AuthenticodePolicy.ps1') -Package $root -Policy $Policy -BootstrapOnly | Out-Host
  if (-not $?) { throw 'validator returned failure' }
} catch { throw "Bootstrap Authenticode verification failed: $($_.Exception.Message)" }
$winctl = Join-Path $root 'aegis-winctl.exe'
$result = & $winctl package verify-signature --package $root --signature $ManifestSignature --authenticode-policy $Policy
if ($LASTEXITCODE -ne 0) { throw 'Detached Ed25519 manifest verification failed' }
$verified = $result | ConvertFrom-Json
if ($verified.ok -ne $true -or $verified.publisher_signature_verified -ne $true -or
    $verified.signed_release -ne $true -or $verified.authenticode_verified -ne $true) {
  throw 'Verifier did not establish the complete signed-release contract'
}
# Re-run the OS trust checks over every executable and the pinned Wintun after
# Ed25519 authenticated the exact final manifest and hashes.
try {
  & (Join-Path $PSScriptRoot 'Test-AuthenticodePolicy.ps1') -Package $root -Policy $Policy | Out-Host
  if (-not $?) { throw 'validator returned failure' }
} catch { throw "Final Authenticode verification failed: $($_.Exception.Message)" }
$verified | ConvertTo-Json -Compress
} finally {
  foreach ($lock in $locks) { $lock.Dispose() }
  if (Test-Path -LiteralPath $snapshot.Root) { Remove-Item -LiteralPath $snapshot.Root -Recurse -Force }
}
