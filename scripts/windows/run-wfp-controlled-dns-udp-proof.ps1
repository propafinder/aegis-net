param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$ArtifactRoot = (Join-Path $RepoRoot 'artifacts\live\2026-05-01\windows-wfp-controlled-dns-udp-proof'),
  [string]$ControlledDnsServer = '1.1.1.1',
  [int]$ControlledDnsPort = 53,
  [int]$ControlledUdpPort = 19053,
  [switch]$AllowExperimentalUdpLayer
)

$ErrorActionPreference = 'Continue'
$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ArtifactRoot = [IO.Path]::GetFullPath($ArtifactRoot)

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null
Get-ChildItem -LiteralPath $ArtifactRoot -File -ErrorAction SilentlyContinue |
  Remove-Item -Force -ErrorAction SilentlyContinue

function Write-Utf8 {
  param([string]$Path, [string[]]$Lines)
  [IO.File]::WriteAllText($Path, (($Lines -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
}

function Test-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$status = 'UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER'
$verdict = 'BLOCKED'
$blocker = 'current AEGIS WFP proof path installs ALE_CONNECT_REDIRECT_V4 with IPPROTO_TCP only; controlled DNS/UDP needs a UDP-capable WFP layer and driver callout changes'
$cleanup = 'PASS'

Write-Utf8 -Path (Join-Path $ArtifactRoot 'commands.txt') -Lines @(
  'powershell -File scripts/windows/run-wfp-controlled-dns-udp-proof.ps1',
  'aegis-winctl wfp udp-feasibility',
  'audit tools/windows/aegis-wfpctl/aegis_wfpctl.c for FWPM_LAYER_ALE_CONNECT_REDIRECT_V4 and IPPROTO_TCP',
  'do not install broad UDP/DNS filters',
  'cleanup AEGIS-owned WFP state if a future experimental path is enabled'
)

Write-Utf8 -Path (Join-Path $ArtifactRoot 'environment.txt') -Lines @(
  "date=$(Get-Date -Format o)",
  "computer=$env:COMPUTERNAME",
  "user=$env:USERNAME",
  "repo=$RepoRoot",
  "artifact=$ArtifactRoot",
  "controlled_dns_server=$ControlledDnsServer",
  "controlled_dns_port=$ControlledDnsPort",
  "controlled_udp_port=$ControlledUdpPort",
  "administrator_shell=$(Test-Admin)",
  'scope=controlled_dns_udp_only'
)

Write-Utf8 -Path (Join-Path $ArtifactRoot 'feasibility.txt') -Lines @(
  'Rust-first feasibility command: aegis-winctl wfp udp-feasibility',
  'WFP layer currently used: FWPM_LAYER_ALE_CONNECT_REDIRECT_V4',
  'Protocol currently installed: IPPROTO_TCP',
  'Current userspace listener: TCP only',
  'Controlled DNS/UDP with current path: not supported',
  'Broad DNS/UDP capture claim: false',
  'Required next implementation: separate UDP-capable WFP layer/callout design, then controlled target-only proof'
)

if (!(Test-Admin)) {
  $status = 'BLOCKED_BY_ADMIN_REQUIRED'
  $blocker = 'administrator shell is required before any WFP DNS/UDP experiment can install or cleanup filters'
}
elseif ($AllowExperimentalUdpLayer) {
  $status = 'UDP_CAPTURE_REQUIRES_CALLOUT_DRIVER'
  $blocker = 'experimental UDP path was requested, but no AEGIS UDP callout/listener implementation exists yet'
}

try {
  $controller = Join-Path $RepoRoot 'target\debug\aegis-wfpctl.exe'
  if (Test-Path $controller) {
    & $controller cleanup *> (Join-Path $ArtifactRoot 'wfp-cleanup.log')
  }
}
catch {
  $cleanup = 'WARN'
  Add-Content -Path (Join-Path $ArtifactRoot 'wfp-cleanup.log') -Value $_.Exception.Message
}

$result = [ordered]@{
  schema_version = 1
  feature = 'windows_wfp_controlled_dns_udp_next_scope'
  platform = 'Windows'
  scope = 'controlled_dns_udp_only'
  status = $status
  verdict = $verdict
  dns_udp_next_scope_status = $status
  feasibility_status = $status
  wfp_layer_current = 'ALE_CONNECT_REDIRECT_V4'
  wfp_protocol_current = 'IPPROTO_TCP'
  udp_redirect_supported_by_current_code = $false
  dns_udp_53_redirect_supported_by_current_layer = $false
  new_wfp_layer_needed = $true
  callout_driver_needed = $true
  controlled_target_only = $true
  controlled_dns_server = $ControlledDnsServer
  controlled_dns_port = $ControlledDnsPort
  controlled_udp_port = $ControlledUdpPort
  controlled_udp_or_dns_captured = $false
  original_destination_recorded = $false
  original_destination_unavailable_reason = 'current proof path is TCP ALE redirect only'
  relay_session_claimed = $false
  relay_session_succeeded = $false
  cleanup = $cleanup
  blocker = $blocker
  dns_capture_claimed = $false
  udp_capture_claimed = $false
  ipv6_capture_claimed = $false
  broad_capture_claim = 'not_claimed'
  production_driver_claim = 'not_claimed'
}
$winctl = Join-Path $RepoRoot 'target\debug\aegis-winctl.exe'
if (Test-Path $winctl) {
  try {
    $feasibilityJson = & $winctl wfp udp-feasibility
    [IO.File]::WriteAllText(
      (Join-Path $ArtifactRoot 'udp-feasibility.json'),
      (($feasibilityJson -join "`n") + "`n"),
      [Text.UTF8Encoding]::new($false)
    )
  }
  catch {
    Write-Utf8 -Path (Join-Path $ArtifactRoot 'udp-feasibility-error.txt') -Lines @($_.Exception.Message)
  }
}
[IO.File]::WriteAllText(
  (Join-Path $ArtifactRoot 'result.json'),
  ((($result | ConvertTo-Json -Depth 6) -replace "`r`n", "`n") + "`n"),
  [Text.UTF8Encoding]::new($false)
)

Write-Utf8 -Path (Join-Path $ArtifactRoot 'README.md') -Lines @(
  '# Windows WFP Controlled DNS/UDP Proof',
  '',
  "Verdict: $verdict",
  "Status: $status",
  '',
  'This scaffold is controlled-target only. It does not claim broad Windows',
  'wide capture, DNS capture, UDP capture, IPv6 capture, relay success, or',
  'production driver support.'
)

Write-Host "$verdict artifact=$ArtifactRoot status=$status"
exit 0
