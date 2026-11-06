param(
  [Parameter(Mandatory=$true)][string]$PackagePath,
  [Parameter(Mandatory=$true)][string]$ManifestSha256,
  [Parameter(Mandatory=$true)][string]$ConfigPath,
  [Parameter(Mandatory=$true)][string]$Root,
  [string]$WinctlExePath = 'target\release\aegis-winctl.exe',
  [switch]$Service,
  [switch]$StartService
)
$ErrorActionPreference = 'Stop'
$cliArgs = @('client', 'install', '--package', $PackagePath, '--manifest-sha256', $ManifestSha256, '--config', $ConfigPath, '--root', $Root)
if ($Service) { $cliArgs += '--service' }
if ($StartService) { $cliArgs += '--start' }
& $WinctlExePath @cliArgs
exit $LASTEXITCODE
