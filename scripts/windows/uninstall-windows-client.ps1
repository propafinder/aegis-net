param(
  [Parameter(Mandatory=$true)][string]$Root,
  [string]$WinctlExePath = 'target\release\aegis-winctl.exe'
)
$ErrorActionPreference = 'Stop'
# Run the controller from the original kit, outside the installed bin folder.
& $WinctlExePath client uninstall --root $Root
exit $LASTEXITCODE
