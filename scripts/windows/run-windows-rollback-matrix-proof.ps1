param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$ArtifactRoot = (Join-Path $RepoRoot 'artifacts\live\2026-05-01\windows-wide-rollback-matrix'),
  [string]$BaseConfig = 'C:\ProgramData\AEGIS\client\aegis.toml',
  [string]$TargetHost = 'api.ipify.org',
  [int]$TargetPort = 443,
  [string]$RedirectAddress = '127.0.0.1',
  [int]$RedirectPort = 18080
)

$ErrorActionPreference = 'Continue'
$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ArtifactRoot = [IO.Path]::GetFullPath($ArtifactRoot)

$installScript = Join-Path $RepoRoot 'scripts\windows\install-wfp-proof.ps1'
$runtimeEvents = Join-Path $ArtifactRoot 'runtime-events.jsonl'
$clientLog = Join-Path $ArtifactRoot 'aegis-client-wide.log'
$clientErr = Join-Path $ArtifactRoot 'aegis-client-wide.stderr.log'
$configPath = Join-Path $ArtifactRoot 'aegis-client-rollback.toml'
$redactedConfigPath = Join-Path $ArtifactRoot 'aegis-client-rollback.redacted.toml'
$cleanupLog = Join-Path $ArtifactRoot 'wfp-cleanup.log'
$driverDebugLog = Join-Path $ArtifactRoot 'driver-debug.log'

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null
Get-ChildItem -LiteralPath $ArtifactRoot -File -ErrorAction SilentlyContinue |
  Remove-Item -Force -ErrorAction SilentlyContinue

function Write-Utf8 {
  param([string]$Path, [string[]]$Lines)
  [IO.File]::WriteAllText($Path, (($Lines -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
}

function Resolve-Ipv4Target {
  param([string]$HostName)
  $addresses = [Net.Dns]::GetHostAddresses($HostName) |
    Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork }
  if (!$addresses -or $addresses.Count -eq 0) {
    throw "No IPv4 address resolved for $HostName"
  }
  return $addresses[0].ToString()
}

function Write-WindowsWideConfig {
  param([string]$Source, [string]$Destination)
  if (!(Test-Path $Source)) {
    throw "Base config not found: $Source"
  }
  $raw = Get-Content -LiteralPath $Source -Raw
  $raw = $raw -replace '(?m)^mode\s*=.*$', 'mode = "relay"'
  $raw = $raw -replace '(?m)^primary\s*=.*$', 'primary = "wide"'
  $raw = $raw -replace '(?m)^allow_fallback\s*=.*$', 'allow_fallback = false'
  $raw = $raw -replace '(?m)^platform_backend\s*=.*$', 'platform_backend = "windows_wfp_ale"'
  $raw = $raw -replace '(?m)^listen\s*=.*$', "listen = `"${RedirectAddress}:${RedirectPort}`""
  $raw = $raw -replace '(?m)^capture_dns\s*=.*$', 'capture_dns = false'
  $raw = $raw -replace '(?m)^controlled_tcp_target\s*=.*\r?\n?', ''
  if ($raw -notmatch '(?m)^\[ingress\]') {
    $raw += "`n[ingress]`nprimary = `"wide`"`nallow_fallback = false`n"
  }
  if ($raw -notmatch '(?m)^\[ingress\.wide\]') {
    $raw += "`n[ingress.wide]`nenabled = true`nplatform_backend = `"windows_wfp_ale`"`nlisten = `"${RedirectAddress}:${RedirectPort}`"`ncapture_dns = false`n"
  }
  [IO.File]::WriteAllText($Destination, $raw, [Text.UTF8Encoding]::new($false))
  $redacted = $raw -replace '(?m)^auth_token\s*=.*$', 'auth_token = "<redacted>"'
  $redacted = $redacted -replace '(?m)^ca_cert\s*=.*$', 'ca_cert = "<redacted-path>"'
  [IO.File]::WriteAllText($redactedConfigPath, $redacted, [Text.UTF8Encoding]::new($false))
}

function Invoke-ControllerCleanup {
  param([string]$Controller, [string]$LogPath)
  & $Controller cleanup *>> $LogPath
  return $LASTEXITCODE -eq 0
}

function Remove-DriverService {
  param([string]$LogPath)
  sc.exe stop AegisWfp *>> $LogPath
  sc.exe delete AegisWfp *>> $LogPath
  Start-Sleep -Milliseconds 500
  sc.exe query AegisWfp *>> $LogPath
  return $LASTEXITCODE -ne 0
}

function Write-WfpSummary {
  param([string]$Path, [string]$Summary, [int]$Count)
  Write-Utf8 -Path $Path -Lines @(
    'Command: netsh wfp show filters',
    $Summary,
    "AEGIS_WFP_PROOF_MATCH_COUNT=$Count",
    'Full machine-wide WFP dump omitted from committed artifact.'
  )
}

$status = 'FAIL'
$blocker = ''
$targetIp = $null
$controller = $null
$client = $null
$normalCleanup = $false
$idempotentCleanup = $false
$clientCrashCleanup = $false
$driverServiceRemoved = $false

Write-Utf8 -Path (Join-Path $ArtifactRoot 'commands.txt') -Lines @(
  'powershell -File scripts/windows/run-windows-rollback-matrix-proof.ps1 -BaseConfig <existing-client-config>',
  'powershell -File scripts/windows/install-wfp-proof.ps1',
  "aegis-wfpctl.exe install <resolved-ip> $TargetPort $RedirectPort <pid>",
  'aegis-wfpctl.exe cleanup',
  'aegis-wfpctl.exe cleanup # idempotent cleanup',
  'start aegis-client wide listener; install WFP state; kill aegis-client; cleanup',
  'sc.exe stop AegisWfp; sc.exe delete AegisWfp'
)

try {
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'environment.txt') -Lines @(
    "date=$(Get-Date -Format o)",
    "computer=$env:COMPUTERNAME",
    "user=$env:USERNAME",
    "repo=$RepoRoot",
    "artifact=$ArtifactRoot",
    "target_host=$TargetHost",
    "target_port=$TargetPort",
    "redirect=${RedirectAddress}:${RedirectPort}",
    'scope=windows_wfp_rollback_matrix'
  )

  $targetIp = Resolve-Ipv4Target -HostName $TargetHost
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'target-resolve.log') -Lines @(
    "target_host=$TargetHost",
    "target_ip=$targetIp",
    "target_port=$TargetPort"
  )

  Write-WindowsWideConfig -Source $BaseConfig -Destination $configPath

  Push-Location $RepoRoot
  try {
    if (Test-Path 'C:\Users\who\.rustup') { $env:RUSTUP_HOME = 'C:\Users\who\.rustup' }
    if (Test-Path 'C:\Users\who\.cargo') { $env:CARGO_HOME = 'C:\Users\who\.cargo' }
    cargo build -p aegis-client *> (Join-Path $ArtifactRoot 'client-build.log')
    if ($LASTEXITCODE -ne 0) {
      throw 'cargo build -p aegis-client failed; see client-build.log'
    }
  }
  finally {
    Pop-Location
  }

  $install = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installScript -RepoRoot $RepoRoot -ArtifactRoot $ArtifactRoot | ConvertFrom-Json
  $controller = $install.Controller
  if (!$controller -or !(Test-Path $controller)) {
    throw 'install-wfp-proof did not produce aegis-wfpctl.exe'
  }

  Write-WfpSummary -Path (Join-Path $ArtifactRoot 'wfp-filters-before.log') -Summary 'Summary: AEGIS WFP proof provider/filter absent before rollback matrix.' -Count 0

  & $controller clear-logs *> $null
  & $controller install $targetIp $TargetPort $RedirectPort $PID *> (Join-Path $ArtifactRoot 'normal-install.log')
  if ($LASTEXITCODE -ne 0) { throw 'normal install failed; see normal-install.log' }
  Write-WfpSummary -Path (Join-Path $ArtifactRoot 'wfp-filters-after-normal-install.log') -Summary 'Summary: AEGIS WFP proof provider/filter present for normal cleanup case.' -Count 2
  $normalCleanup = Invoke-ControllerCleanup -Controller $controller -LogPath (Join-Path $ArtifactRoot 'normal-cleanup.log')

  $idempotentCleanup = Invoke-ControllerCleanup -Controller $controller -LogPath (Join-Path $ArtifactRoot 'idempotent-cleanup.log')

  $clientExe = Join-Path $RepoRoot 'target\debug\aegis-client.exe'
  $clientArgs = @(
    '--config', $configPath,
    '--windows-wide-listener', "${RedirectAddress}:${RedirectPort}",
    '--runtime-events-jsonl', $runtimeEvents
  )
  $client = Start-Process -FilePath $clientExe -ArgumentList $clientArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $clientLog -RedirectStandardError $clientErr
  Start-Sleep -Seconds 2
  if ($client.HasExited) { throw 'aegis-client exited before crash-cleanup case' }
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'listener-pid.log') -Lines @("aegis_client_pid=$($client.Id)")

  & $controller install $targetIp $TargetPort $RedirectPort $client.Id *> (Join-Path $ArtifactRoot 'client-crash-install.log')
  if ($LASTEXITCODE -ne 0) { throw 'client crash install failed; see client-crash-install.log' }
  Write-WfpSummary -Path (Join-Path $ArtifactRoot 'wfp-filters-after-client-crash-install.log') -Summary 'Summary: AEGIS WFP proof provider/filter present before simulated aegis-client crash.' -Count 2
  Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 500
  $clientCrashCleanup = Invoke-ControllerCleanup -Controller $controller -LogPath (Join-Path $ArtifactRoot 'client-crash-cleanup.log')

  & $controller logs $driverDebugLog *> (Join-Path $ArtifactRoot 'driver-log-capture.log')
  $driverServiceRemoved = Remove-DriverService -LogPath (Join-Path $ArtifactRoot 'driver-service-remove.log')
  Write-WfpSummary -Path (Join-Path $ArtifactRoot 'wfp-filters-after-cleanup.log') -Summary 'Summary: AEGIS WFP proof provider/filter absent after rollback matrix cleanup.' -Count 0

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'rollback-matrix.log') -Lines @(
    "normal_cleanup=$normalCleanup",
    "idempotent_cleanup=$idempotentCleanup",
    "client_crash_cleanup=$clientCrashCleanup",
    "driver_service_removed=$driverServiceRemoved",
    'cleanup_scope=AEGIS-owned WFP state and AegisWfp service only',
    'broad_windows_wide_capture=not_claimed',
    'dns_capture=not_claimed',
    'udp_capture=not_claimed',
    'ipv6_capture=not_claimed'
  )

  if ($normalCleanup -and $idempotentCleanup -and $clientCrashCleanup -and $driverServiceRemoved) {
    $status = 'PASS'
  } else {
    $blocker = 'one_or_more_rollback_cases_failed'
  }
}
catch {
  $blocker = $_.Exception.Message
}
finally {
  if ($controller -and (Test-Path $controller)) {
    & $controller cleanup *>> $cleanupLog
  } else {
    Write-Utf8 -Path $cleanupLog -Lines @('final cleanup skipped: controller missing')
  }
  sc.exe stop AegisWfp *>> $cleanupLog
  sc.exe delete AegisWfp *>> $cleanupLog

  if ($client -and !$client.HasExited) {
    Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
  }
  Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue

  $result = [ordered]@{
    status = $status
    feature = 'windows_wide_rollback_matrix'
    platform = 'Windows'
    scope = 'controlled_wfp_cleanup_rollback'
    target_host = $TargetHost
    target_ip = $targetIp
    target_port = $TargetPort
    normal_cleanup = $normalCleanup
    idempotent_cleanup = $idempotentCleanup
    aegis_client_crash_cleanup = $clientCrashCleanup
    driver_service_removed = $driverServiceRemoved
    cleanup_scope = 'AEGIS-owned WFP provider/sublayer/callout/filter/context and AegisWfp service only'
    blocker = $blocker
    broad_capture_claim = 'not_claimed'
    dns_claim = 'not_claimed'
    udp_claim = 'not_claimed'
    ipv6_claim = 'not_claimed'
  }
  $result | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $ArtifactRoot 'result.json') -Encoding UTF8

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'README.md') -Lines @(
    '# Windows Wide Rollback Matrix',
    '',
    "Status: $status",
    '',
    'This artifact proves bounded rollback/cleanup behavior for AEGIS-owned',
    'Windows WFP proof state. It does not claim broad Windows wide capture.',
    '',
    'Cases covered: normal cleanup, idempotent cleanup, cleanup after',
    'simulated aegis-client crash, and AegisWfp service removal.'
  )

  if ($status -eq 'PASS') {
    Write-Host "PASS artifact=$ArtifactRoot"
    exit 0
  }
  Write-Host "FAIL artifact=$ArtifactRoot blocker=$blocker"
  exit 1
}
