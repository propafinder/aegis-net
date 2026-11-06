param(
  [Parameter(Mandatory=$true)][string]$OutputDir,
  [Parameter(Mandatory=$true)][string]$SourceCommit,
  [string]$ClientExePath = 'target\release\aegis-client.exe',
  [string]$WinctlExePath = 'target\release\aegis-winctl.exe'
)
$ErrorActionPreference = 'Stop'
& $WinctlExePath package build --client $ClientExePath --winctl $WinctlExePath --output $OutputDir --source-commit $SourceCommit
exit $LASTEXITCODE
