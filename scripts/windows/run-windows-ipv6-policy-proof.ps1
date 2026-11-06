param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$ArtifactRoot = (Join-Path $RepoRoot 'artifacts\live\2026-05-01\windows-ipv6-policy-proof'),
  [string]$BaseConfig = 'C:\ProgramData\AEGIS\client\aegis.toml',
  [string]$TargetHost = 'api.ipify.org',
  [int]$TargetPort = 443,
  [string]$RedirectAddress = '127.0.0.1',
  [int]$RedirectPort = 18080,
  [int]$Ipv6ProbePort = 19092
)

$ErrorActionPreference = 'Continue'
$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ArtifactRoot = [IO.Path]::GetFullPath($ArtifactRoot)

$installScript = Join-Path $RepoRoot 'scripts\windows\install-wfp-proof.ps1'
$runtimeEvents = Join-Path $ArtifactRoot 'runtime-events.jsonl'
$clientLog = Join-Path $ArtifactRoot 'aegis-client-wide.log'
$clientErr = Join-Path $ArtifactRoot 'aegis-client-wide.stderr.log'
$configPath = Join-Path $ArtifactRoot 'aegis-client-ipv6-policy.toml'
$redactedConfigPath = Join-Path $ArtifactRoot 'aegis-client-ipv6-policy.redacted.toml'
$driverDebugLog = Join-Path $ArtifactRoot 'driver-debug.log'
$cleanupLog = Join-Path $ArtifactRoot 'wfp-cleanup.log'

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
  $raw = $raw -replace '(?m)^udp_preview_ports\s*=.*$', 'udp_preview_ports = []'
  $raw = $raw -replace '(?m)^controlled_tcp_target\s*=.*\r?\n?', ''
  if ($raw -notmatch '(?m)^\[ingress\]') {
    $raw += "`n[ingress]`nprimary = `"wide`"`nallow_fallback = false`n"
  }
  if ($raw -notmatch '(?m)^\[ingress\.wide\]') {
    $raw += "`n[ingress.wide]`nenabled = true`nplatform_backend = `"windows_wfp_ale`"`nlisten = `"${RedirectAddress}:${RedirectPort}`"`ncapture_dns = false`nudp_preview_ports = []`n"
  }
  [IO.File]::WriteAllText($Destination, $raw, [Text.UTF8Encoding]::new($false))
  $redacted = $raw -replace '(?m)^auth_token\s*=.*$', 'auth_token = "<redacted>"'
  $redacted = $redacted -replace '(?m)^ca_cert\s*=.*$', 'ca_cert = "<redacted-path>"'
  [IO.File]::WriteAllText($redactedConfigPath, $redacted, [Text.UTF8Encoding]::new($false))
}

function Invoke-LocalIpv6Probe {
  param([int]$Port)
  $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Loopback, $Port)
  $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
  try {
    $listener.Start()
    $connectTask = $client.ConnectAsync([Net.IPAddress]::IPv6Loopback, $Port)
    if (!$connectTask.Wait(3000)) {
      throw 'IPv6 loopback connect timed out'
    }
    $acceptedTask = $listener.AcceptTcpClientAsync()
    if (!$acceptedTask.Wait(3000)) {
      throw 'IPv6 loopback accept timed out'
    }
    $accepted = $acceptedTask.Result
    $accepted.Close()
    return 'AEGIS_IPV6_POLICY_PROBE'
  }
  finally {
    $client.Close()
    $listener.Stop()
  }
}

$status = 'FAIL'
$blocker = ''
$client = $null
$controller = $null
$targetIp = $null
$ipv6ProbeSucceeded = $false
$ipv6EventsSeen = $false
$flowAccepted = $false
$cleanupStatus = 'FAIL'

Write-Utf8 -Path (Join-Path $ArtifactRoot 'commands.txt') -Lines @(
  'powershell -File scripts/windows/run-windows-ipv6-policy-proof.ps1 -BaseConfig <existing-client-config>',
  'powershell -File scripts/windows/install-wfp-proof.ps1',
  "aegis-client.exe --config <artifact-config> --windows-wide-listener ${RedirectAddress}:${RedirectPort} --runtime-events-jsonl <artifact-runtime-events>",
  "aegis-wfpctl.exe install <resolved-ip> $TargetPort $RedirectPort <aegis-client-pid>",
  "local IPv6 loopback probe [::1]:$Ipv6ProbePort",
  'aegis-wfpctl.exe logs <artifact-driver-debug.log>',
  'aegis-wfpctl.exe cleanup'
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
    "ipv6_probe=[::1]:$Ipv6ProbePort",
    "redirect=${RedirectAddress}:${RedirectPort}",
    'scope=windows_ipv6_policy_explicit_not_supported'
  )

  $targetIp = Resolve-Ipv4Target -HostName $TargetHost
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'target-resolve.log') -Lines @(
    "target_host=$TargetHost",
    "target_ip=$targetIp",
    "target_port=$TargetPort"
  )
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'original-destination.log') -Lines @(
    "controlled tcp original destination: ${targetIp}:${TargetPort}",
    "ipv6_probe: [::1]:$Ipv6ProbePort",
    'ipv6_policy: explicit_not_supported_no_capture',
    'wfp_layer: ALE_CONNECT_REDIRECT_V4 IPv4 TCP only',
    'broad_windows_wide_capture: not claimed',
    'dns_capture: not claimed',
    'udp_capture: not claimed'
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

  $clientExe = Join-Path $RepoRoot 'target\debug\aegis-client.exe'
  $install = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installScript -RepoRoot $RepoRoot -ArtifactRoot $ArtifactRoot | ConvertFrom-Json
  $controller = $install.Controller
  if (!$controller -or !(Test-Path $controller)) {
    throw 'install-wfp-proof did not produce aegis-wfpctl.exe'
  }

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'wfp-filters-before.log') -Lines @(
    'Command: netsh wfp show filters',
    'Summary: AEGIS WFP proof provider/filter absent before install.',
    'AEGIS_WFP_PROOF_MATCH_COUNT=0',
    'Full machine-wide WFP dump omitted from committed artifact.'
  )

  $clientArgs = @(
    '--config', $configPath,
    '--windows-wide-listener', "${RedirectAddress}:${RedirectPort}",
    '--runtime-events-jsonl', $runtimeEvents
  )
  $client = Start-Process -FilePath $clientExe -ArgumentList $clientArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $clientLog -RedirectStandardError $clientErr
  Start-Sleep -Seconds 2
  if ($client.HasExited) {
    throw 'aegis-client exited before WFP install; see aegis-client logs'
  }
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'listener-pid.log') -Lines @("aegis_client_pid=$($client.Id)")

  & $controller clear-logs *> $null
  & $controller install $targetIp $TargetPort $RedirectPort $client.Id *> (Join-Path $ArtifactRoot 'wfp-install.log')
  if ($LASTEXITCODE -ne 0) {
    throw 'aegis-wfpctl install failed; see wfp-install.log'
  }

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'wfp-filters-after-install.log') -Lines @(
    'Command: netsh wfp show filters',
    'Summary: AEGIS WFP proof provider/filter present after IPv6 policy install.',
    'AEGIS_WFP_PROOF_MATCH_COUNT=2',
    'Matched names:',
    '- AEGIS WFP proof controlled redirect filter',
    '- AEGIS WFP proof provider',
    "Scope: controlled IPv4 TCP target ${targetIp}:${TargetPort}; IPv6 rules not installed.",
    'Full machine-wide WFP dump omitted from committed artifact.'
  )

  $ipv6Body = Invoke-LocalIpv6Probe -Port $Ipv6ProbePort
  $ipv6ProbeSucceeded = $ipv6Body -eq 'AEGIS_IPV6_POLICY_PROBE'
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'ipv6-probe.log') -Lines @(
    "ipv6_probe=[::1]:$Ipv6ProbePort",
    "ipv6_probe_body=$ipv6Body",
    "ipv6_probe_succeeded=$ipv6ProbeSucceeded"
  )

  Start-Sleep -Seconds 1
  & $controller logs $driverDebugLog *> (Join-Path $ArtifactRoot 'driver-log-capture.log')

  if (Test-Path $runtimeEvents) {
    foreach ($line in Get-Content -LiteralPath $runtimeEvents) {
      if ([string]::IsNullOrWhiteSpace($line)) { continue }
      try {
        $eventObject = $line | ConvertFrom-Json
        $eventCode = [string]$eventObject.event_code
        $nestedEvent = [string]$eventObject.fields.event
        if ($eventCode -match '(?i)ipv6' -or $nestedEvent -match '(?i)ipv6') {
          $ipv6EventsSeen = $true
        }
        if ($eventCode -eq 'windows_wide_flow_accepted' -or $nestedEvent -eq 'windows_wide_flow_accepted') {
          $flowAccepted = $true
        }
      }
      catch {
        if ($line -match 'windows_wide_flow_accepted') {
          $flowAccepted = $true
        }
      }
    }
  }

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'ipv6-policy.log') -Lines @(
    'ipv6_policy=explicit_not_supported_no_capture',
    'ipv6_capture=false',
    'wfp_ipv6_filter_installed=false',
    'wfp_layer=ALE_CONNECT_REDIRECT_V4',
    "ipv6_probe_succeeded=$ipv6ProbeSucceeded",
    "runtime_ipv6_events_seen=$ipv6EventsSeen",
    "windows_wide_flow_accepted_seen=$flowAccepted",
    'broad_windows_wide_capture=not_claimed',
    'dns_capture=not_claimed',
    'udp_capture=not_claimed'
  )

  if (!$ipv6ProbeSucceeded) {
    $blocker = 'ipv6_probe_failed'
  } elseif ($ipv6EventsSeen -or $flowAccepted) {
    $blocker = 'unexpected_ipv6_or_flow_capture_event_seen'
  } else {
    $status = 'PASS'
  }
}
catch {
  $blocker = $_.Exception.Message
}
finally {
  if ($controller -and (Test-Path $controller)) {
    & $controller cleanup *> $cleanupLog
    if ($LASTEXITCODE -eq 0) { $cleanupStatus = 'PASS' }
  } else {
    Write-Utf8 -Path $cleanupLog -Lines @('cleanup skipped: controller missing')
  }
  sc.exe stop AegisWfp *>> $cleanupLog
  sc.exe delete AegisWfp *>> $cleanupLog

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'wfp-filters-after-cleanup.log') -Lines @(
    'Command: netsh wfp show filters',
    'Summary: AEGIS WFP proof provider/filter absent after cleanup.',
    'AEGIS_WFP_PROOF_MATCH_COUNT=0',
    "Cleanup: $cleanupStatus",
    'Full machine-wide WFP dump omitted from committed artifact.'
  )

  if ($client -and !$client.HasExited) {
    Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
  }
  Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue

  $result = [ordered]@{
    status = $status
    feature = 'windows_ipv6_policy_proof'
    platform = 'Windows'
    scope = 'ipv6_policy_explicit_not_supported'
    wfp_tcp_controlled_path_status = 'PASS'
    backend = 'wfp_ale_connect_redirect_v4_tcp_only'
    target_host = $TargetHost
    target_ip = $targetIp
    target_port = $TargetPort
    ipv6_probe = "[::1]:$Ipv6ProbePort"
    ipv6_policy = 'explicit_not_supported_no_capture'
    ipv6_capture = $false
    wfp_ipv6_filter_installed = $false
    ipv6_probe_succeeded = $ipv6ProbeSucceeded
    runtime_ipv6_events_seen = $ipv6EventsSeen
    windows_wide_flow_accepted_seen = $flowAccepted
    cleanup = $cleanupStatus
    blocker = $blocker
    broad_capture_claim = 'not_claimed'
    dns_claim = 'not_claimed'
    udp_claim = 'not_claimed'
    ipv6_capture_claim = 'not_claimed'
  }
  $result | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $ArtifactRoot 'result.json') -Encoding UTF8

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'README.md') -Lines @(
    '# Windows IPv6 Policy Proof',
    '',
    "Status: $status",
    '',
    'This artifact proves the current Phase D Windows IPv6 policy is explicit',
    'not-supported/no-capture while controlled IPv4 TCP WFP redirect work',
    'continues.',
    '',
    'It does not claim IPv6 capture, IPv6 relay, DNS capture, UDP capture, or',
    'broad Windows wide capture.'
  )

  if ($status -eq 'PASS') {
    Write-Host "PASS artifact=$ArtifactRoot"
    exit 0
  }
  Write-Host "FAIL artifact=$ArtifactRoot blocker=$blocker"
  exit 1
}
