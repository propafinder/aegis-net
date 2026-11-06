param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$ArtifactRoot = (Join-Path $RepoRoot 'artifacts\live\2026-05-01\windows-wide-service-reboot-persistence-proof'),
  [ValidateSet('Prepare', 'VerifyAfterReboot')]
  [string]$Mode = 'Prepare',
  [string]$ServiceName = 'AegisClient',
  [string]$TargetHost = 'api.ipify.org',
  [int]$TargetPort = 443,
  [string]$ExpectedRelayEgressIp = ''
)

$ErrorActionPreference = 'Stop'
$parsedExpectedRelayEgressIp = $null
if ([string]::IsNullOrWhiteSpace($ExpectedRelayEgressIp) -or
    $ExpectedRelayEgressIp -cne $ExpectedRelayEgressIp.Trim() -or
    -not [System.Net.IPAddress]::TryParse($ExpectedRelayEgressIp, [ref]$parsedExpectedRelayEgressIp) -or
    $ExpectedRelayEgressIp.Contains('%') -or
    ($parsedExpectedRelayEgressIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
     $ExpectedRelayEgressIp -cne $parsedExpectedRelayEgressIp.ToString())) {
  throw 'ExpectedRelayEgressIp must be an explicit IP address'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ArtifactRoot = [IO.Path]::GetFullPath($ArtifactRoot)
$winctl = Join-Path $RepoRoot 'target\debug\aegis-winctl.exe'

if (!(Test-Path $winctl)) {
  Push-Location $RepoRoot
  try {
    cargo +stable build -p aegis-winctl
  }
  finally {
    Pop-Location
  }
}

$subcommand = if ($Mode -eq 'Prepare') { 'prepare' } else { 'verify-after-reboot' }

& $winctl proof service-reboot $subcommand `
  --artifact-dir $ArtifactRoot `
  --service-name $ServiceName `
  --target-host $TargetHost `
  --target-port $TargetPort `
  --expected-relay-egress-ip $ExpectedRelayEgressIp

exit $LASTEXITCODE
