param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$ArtifactRoot = (Join-Path $RepoRoot 'artifacts\live\2026-05-01\windows-wfp-aegis-original-dst-dynamic'),
  [string]$BaseConfig = 'C:\ProgramData\AEGIS\client\aegis.toml',
  [string]$TargetHost = 'v4.ident.me',
  [int]$TargetPort = 80,
  [string]$RedirectAddress = '127.0.0.1',
  [int]$RedirectPort = 18080
)

$script = Join-Path $PSScriptRoot 'run-wfp-aegis-controlled-proof.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script `
  -RepoRoot $RepoRoot `
  -ArtifactRoot $ArtifactRoot `
  -BaseConfig $BaseConfig `
  -TargetHost $TargetHost `
  -TargetPort $TargetPort `
  -RedirectAddress $RedirectAddress `
  -RedirectPort $RedirectPort `
  -DynamicOriginalDst
exit $LASTEXITCODE
