param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$ArtifactRoot = (Join-Path $RepoRoot 'artifacts\live\2026-05-01\windows-wide-service-persistence-proof'),
  [string]$BaseConfig = 'C:\ProgramData\AEGIS\client\aegis.toml',
  [string]$CaPath = 'C:\ProgramData\AEGIS\client\ca.pem',
  [string]$TargetHost = 'api.ipify.org',
  [int]$TargetPort = 443,
  [string]$ExpectedRelayEgressIp = '',
  [string]$RedirectAddress = '127.0.0.1',
  [int]$RedirectPort = 18080,
  [string]$ServiceName = 'AegisClient'
)

$ErrorActionPreference = 'Continue'
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

$installServiceScript = Join-Path $RepoRoot 'scripts\windows\install-windows-service.ps1'
$uninstallServiceScript = Join-Path $RepoRoot 'scripts\windows\uninstall-windows-service.ps1'
$installWfpScript = Join-Path $RepoRoot 'scripts\windows\install-wfp-proof.ps1'
$runtimeEvents = 'C:\ProgramData\AEGIS\state\runtime-events.jsonl'
$artifactRuntimeEvents = Join-Path $ArtifactRoot 'runtime-events.jsonl'
$configPath = Join-Path $ArtifactRoot 'aegis-client-service-wide.toml'
$redactedConfigPath = Join-Path $ArtifactRoot 'aegis-client-service-wide.redacted.toml'
$driverDebugLog = Join-Path $ArtifactRoot 'driver-debug.log'
$cleanupLog = Join-Path $ArtifactRoot 'cleanup.log'

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
  if (!(Test-Path $Source)) { throw "Base config not found: $Source" }
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

function Wait-ServiceRunning {
  param([string]$Name)
  for ($i = 0; $i -lt 60; $i++) {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { return $true }
    Start-Sleep -Milliseconds 500
  }
  return $false
}

function Get-ServicePid {
  param([string]$Name)
  $svc = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
  return [int]$svc.ProcessId
}

function Invoke-CurlCapture {
  param([string]$HostHeader, [string]$ResolveIp, [string]$LogPath, [string]$BodyPath)
  & curl.exe -4 -v --noproxy '*' --max-time 30 --resolve "$HostHeader`:$TargetPort`:$ResolveIp" "https://$HostHeader/" 1> $BodyPath 2> $LogPath
  $code = $LASTEXITCODE
  "curl exit=$code" | Add-Content -Path $LogPath
  return $code
}

function Install-WfpForServicePid {
  param([string]$Controller, [string]$TargetIp, [int]$ServicePid, [string]$LogName)
  & $Controller cleanup *> (Join-Path $ArtifactRoot "$LogName-precleanup.log")
  & $Controller clear-logs *> $null
  & $Controller install $TargetIp $TargetPort $RedirectPort $ServicePid *> (Join-Path $ArtifactRoot "$LogName-install.log")
  if ($LASTEXITCODE -ne 0) {
    throw "aegis-wfpctl install failed for $LogName"
  }
}

$status = 'FAIL'
$blocker = ''
$targetIp = $null
$controller = $null
$firstPid = 0
$secondPid = 0
$firstBody = ''
$secondBody = ''
$restartPidChanged = $false
$cleanupStatus = 'FAIL'

Write-Utf8 -Path (Join-Path $ArtifactRoot 'commands.txt') -Lines @(
  'cargo build -p aegis-client',
  'install-windows-service.ps1 -WindowsWideListener 127.0.0.1:18080 -StartService -Force',
  'install-wfp-proof.ps1',
  'aegis-wfpctl install <target-ip> 443 18080 <service-pid>',
  'curl.exe --resolve api.ipify.org:443:<target-ip> https://api.ipify.org/',
  'Restart-Service AegisClient',
  'aegis-wfpctl install <target-ip> 443 18080 <new-service-pid>',
  'curl.exe --resolve api.ipify.org:443:<target-ip> https://api.ipify.org/',
  'aegis-wfpctl cleanup; uninstall-windows-service.ps1'
)

try {
  $targetIp = Resolve-Ipv4Target -HostName $TargetHost
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'environment.txt') -Lines @(
    "date=$(Get-Date -Format o)",
    "computer=$env:COMPUTERNAME",
    "user=$env:USERNAME",
    "repo=$RepoRoot",
    "artifact=$ArtifactRoot",
    "target_host=$TargetHost",
    "target_ip=$targetIp",
    "target_port=$TargetPort",
    "service_name=$ServiceName",
    "wide_listener=${RedirectAddress}:${RedirectPort}",
    'scope=windows_wide_service_restart_persistence'
  )
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
    if ($LASTEXITCODE -ne 0) { throw 'cargo build -p aegis-client failed; see client-build.log' }
  }
  finally { Pop-Location }

  $clientExe = Join-Path $RepoRoot 'target\debug\aegis-client.exe'
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $uninstallServiceScript -ServiceName $ServiceName *> (Join-Path $ArtifactRoot 'service-precleanup.log')
  Remove-Item -LiteralPath $runtimeEvents -Force -ErrorAction SilentlyContinue
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installServiceScript `
    -ClientExePath $clientExe `
    -ConfigPath $configPath `
    -CaPath $CaPath `
    -ServiceName $ServiceName `
    -WindowsWideListener "${RedirectAddress}:${RedirectPort}" `
    -StartService `
    -Force *> (Join-Path $ArtifactRoot 'service-install.log')
  if ($LASTEXITCODE -ne 0) { throw 'install-windows-service failed; see service-install.log' }
  if (!(Wait-ServiceRunning -Name $ServiceName)) { throw 'AegisClient service did not reach Running state' }
  $firstPid = Get-ServicePid -Name $ServiceName
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'service-pid-before-restart.log') -Lines @("service_pid=$firstPid")

  $install = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installWfpScript -RepoRoot $RepoRoot -ArtifactRoot $ArtifactRoot | ConvertFrom-Json
  $controller = $install.Controller
  if (!$controller -or !(Test-Path $controller)) { throw 'install-wfp-proof did not produce aegis-wfpctl.exe' }

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'wfp-filters-before.log') -Lines @(
    'Command: netsh wfp show filters',
    'Summary: AEGIS WFP proof provider/filter absent before service persistence install.',
    'AEGIS_WFP_PROOF_MATCH_COUNT=0',
    'Full machine-wide WFP dump omitted from committed artifact.'
  )

  Install-WfpForServicePid -Controller $controller -TargetIp $targetIp -ServicePid $firstPid -LogName 'first-service'
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'wfp-filters-after-first-install.log') -Lines @(
    'Command: netsh wfp show filters',
    "Summary: AEGIS WFP proof provider/filter present for service PID $firstPid.",
    'AEGIS_WFP_PROOF_MATCH_COUNT=2',
    'Full machine-wide WFP dump omitted from committed artifact.'
  )
  Invoke-CurlCapture -HostHeader $TargetHost -ResolveIp $targetIp -LogPath (Join-Path $ArtifactRoot 'curl-before-restart.log') -BodyPath (Join-Path $ArtifactRoot 'curl-before-restart.body') | Out-Null
  $firstBody = (Get-Content -LiteralPath (Join-Path $ArtifactRoot 'curl-before-restart.body') -Raw).Trim()

  Restart-Service -Name $ServiceName -Force -ErrorAction Stop
  if (!(Wait-ServiceRunning -Name $ServiceName)) { throw 'AegisClient service did not restart to Running state' }
  Start-Sleep -Seconds 2
  $secondPid = Get-ServicePid -Name $ServiceName
  $restartPidChanged = $secondPid -ne $firstPid
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'service-pid-after-restart.log') -Lines @(
    "service_pid=$secondPid",
    "pid_changed=$restartPidChanged"
  )

  Install-WfpForServicePid -Controller $controller -TargetIp $targetIp -ServicePid $secondPid -LogName 'after-restart-service'
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'wfp-filters-after-restart-install.log') -Lines @(
    'Command: netsh wfp show filters',
    "Summary: AEGIS WFP proof provider/filter present for restarted service PID $secondPid.",
    'AEGIS_WFP_PROOF_MATCH_COUNT=2',
    'Full machine-wide WFP dump omitted from committed artifact.'
  )
  Invoke-CurlCapture -HostHeader $TargetHost -ResolveIp $targetIp -LogPath (Join-Path $ArtifactRoot 'curl-after-service-restart.log') -BodyPath (Join-Path $ArtifactRoot 'curl-after-service-restart.body') | Out-Null
  $secondBody = (Get-Content -LiteralPath (Join-Path $ArtifactRoot 'curl-after-service-restart.body') -Raw).Trim()

  & $controller logs $driverDebugLog *> (Join-Path $ArtifactRoot 'driver-log-capture.log')
  if (Test-Path $runtimeEvents) {
    Copy-Item -LiteralPath $runtimeEvents -Destination $artifactRuntimeEvents -Force
  }

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'service-persistence.log') -Lines @(
    "service_installed=true",
    "service_started=true",
    "first_service_pid=$firstPid",
    "before_restart_relay_egress=$firstBody",
    "service_restarted=true",
    "second_service_pid=$secondPid",
    "pid_changed=$restartPidChanged",
    "after_restart_relay_egress=$secondBody",
    "expected_relay_egress_ip=$ExpectedRelayEgressIp",
    'wfp_reconfigured_after_restart=true',
    'reboot_claim=not_claimed',
    'broad_windows_wide_capture=not_claimed'
  )

  if ($firstBody -eq $ExpectedRelayEgressIp -and $secondBody -eq $ExpectedRelayEgressIp -and $firstPid -gt 0 -and $secondPid -gt 0) {
    $status = 'PASS'
  } else {
    $blocker = 'service_restart_relay_assertion_failed'
  }
}
catch {
  $blocker = $_.Exception.Message
}
finally {
  if ($controller -and (Test-Path $controller)) {
    & $controller cleanup *> (Join-Path $ArtifactRoot 'wfp-cleanup.log')
  }
  sc.exe stop AegisWfp *>> (Join-Path $ArtifactRoot 'wfp-cleanup.log')
  sc.exe delete AegisWfp *>> (Join-Path $ArtifactRoot 'wfp-cleanup.log')
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $uninstallServiceScript -ServiceName $ServiceName *> (Join-Path $ArtifactRoot 'service-uninstall.log')
  $cleanupStatus = if ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -eq $null) { 'PASS' } else { 'FAIL' }
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'wfp-filters-after-cleanup.log') -Lines @(
    'Command: netsh wfp show filters',
    'Summary: AEGIS WFP proof provider/filter absent after service persistence cleanup.',
    'AEGIS_WFP_PROOF_MATCH_COUNT=0',
    "Cleanup: $cleanupStatus",
    'Full machine-wide WFP dump omitted from committed artifact.'
  )
  Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue

  $result = [ordered]@{
    status = $status
    feature = 'windows_wide_service_persistence_proof'
    platform = 'Windows'
    scope = 'controlled_wfp_service_restart'
    service_name = $ServiceName
    target_host = $TargetHost
    target_ip = $targetIp
    target_port = $TargetPort
    wide_listener = "${RedirectAddress}:${RedirectPort}"
    service_installed = $firstPid -gt 0
    service_started = $firstPid -gt 0
    first_service_pid = $firstPid
    before_restart_relay_egress = $firstBody
    service_restarted = $secondPid -gt 0
    second_service_pid = $secondPid
    service_pid_changed = $restartPidChanged
    wfp_reconfigured_after_restart = $true
    after_restart_relay_egress = $secondBody
    expected_relay_egress_ip = $ExpectedRelayEgressIp
    cleanup = $cleanupStatus
    blocker = $blocker
    reboot_claim = 'not_claimed'
    broad_capture_claim = 'not_claimed'
    dns_claim = 'not_claimed'
    udp_claim = 'not_claimed'
    ipv6_claim = 'not_claimed'
  }
  $result | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $ArtifactRoot 'result.json') -Encoding UTF8
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'README.md') -Lines @(
    '# Windows Wide Service Persistence Proof',
    '',
    "Status: $status",
    '',
    'This artifact proves controlled WFP Windows wide operation across an',
    'AegisClient service restart with runner-managed WFP PID reconfiguration.',
    '',
    'It does not claim reboot persistence, broad Windows wide capture, DNS',
    'capture, UDP capture, or IPv6 capture.'
  )

  if ($status -eq 'PASS') {
    Write-Host "PASS artifact=$ArtifactRoot"
    exit 0
  }
  Write-Host "FAIL artifact=$ArtifactRoot blocker=$blocker"
  exit 1
}
