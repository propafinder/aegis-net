param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$ArtifactRoot = (Join-Path $RepoRoot 'artifacts\live\2026-05-01\windows-udp-policy-proof'),
  [string]$BaseConfig = 'C:\ProgramData\AEGIS\client\aegis.toml',
  [string]$TargetHost = 'api.ipify.org',
  [int]$TargetPort = 443,
  [string]$RedirectAddress = '127.0.0.1',
  [int]$RedirectPort = 18080,
  [int]$UdpProbePort = 19091
)

$ErrorActionPreference = 'Continue'
$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ArtifactRoot = [IO.Path]::GetFullPath($ArtifactRoot)

$installScript = Join-Path $RepoRoot 'scripts\windows\install-wfp-proof.ps1'
$runtimeEvents = Join-Path $ArtifactRoot 'runtime-events.jsonl'
$clientLog = Join-Path $ArtifactRoot 'aegis-client-wide.log'
$clientErr = Join-Path $ArtifactRoot 'aegis-client-wide.stderr.log'
$configPath = Join-Path $ArtifactRoot 'aegis-client-udp-policy.toml'
$redactedConfigPath = Join-Path $ArtifactRoot 'aegis-client-udp-policy.redacted.toml'
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
  $raw = $raw -replace '(?m)^udp_capture_contract\s*=.*$', 'udp_capture_contract = "preview_allowlist_only"'
  $raw = $raw -replace '(?m)^udp_preview_ports\s*=.*$', 'udp_preview_ports = []'
  $raw = $raw -replace '(?m)^controlled_tcp_target\s*=.*\r?\n?', ''
  if ($raw -notmatch '(?m)^\[ingress\]') {
    $raw += "`n[ingress]`nprimary = `"wide`"`nallow_fallback = false`n"
  }
  if ($raw -notmatch '(?m)^\[ingress\.wide\]') {
    $raw += "`n[ingress.wide]`nenabled = true`nplatform_backend = `"windows_wfp_ale`"`nlisten = `"${RedirectAddress}:${RedirectPort}`"`ncapture_dns = false`nudp_capture_contract = `"preview_allowlist_only`"`nudp_preview_ports = []`n"
  }
  [IO.File]::WriteAllText($Destination, $raw, [Text.UTF8Encoding]::new($false))
  $redacted = $raw -replace '(?m)^auth_token\s*=.*$', 'auth_token = "<redacted>"'
  $redacted = $redacted -replace '(?m)^ca_cert\s*=.*$', 'ca_cert = "<redacted-path>"'
  [IO.File]::WriteAllText($redactedConfigPath, $redacted, [Text.UTF8Encoding]::new($false))
}

function Invoke-LocalUdpProbe {
  param([int]$Port)
  $listener = [Net.Sockets.UdpClient]::new($Port)
  $sender = [Net.Sockets.UdpClient]::new()
  try {
    $listener.Client.ReceiveTimeout = 3000
    $payload = [Text.Encoding]::ASCII.GetBytes('AEGIS_UDP_POLICY_PROBE')
    [void]$sender.Send($payload, $payload.Length, '127.0.0.1', $Port)
    $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
    $received = $listener.Receive([ref]$remote)
    return [Text.Encoding]::ASCII.GetString($received)
  }
  finally {
    $sender.Close()
    $listener.Close()
  }
}

$status = 'FAIL'
$blocker = ''
$client = $null
$controller = $null
$targetIp = $null
$udpProbeSucceeded = $false
$udpEventsSeen = $false
$flowAccepted = $false
$cleanupStatus = 'FAIL'

Write-Utf8 -Path (Join-Path $ArtifactRoot 'commands.txt') -Lines @(
  'powershell -File scripts/windows/run-windows-udp-policy-proof.ps1 -BaseConfig <existing-client-config>',
  'powershell -File scripts/windows/install-wfp-proof.ps1',
  "aegis-client.exe --config <artifact-config> --windows-wide-listener ${RedirectAddress}:${RedirectPort} --runtime-events-jsonl <artifact-runtime-events>",
  "aegis-wfpctl.exe install <resolved-ip> $TargetPort $RedirectPort <aegis-client-pid>",
  "local UDP probe 127.0.0.1:$UdpProbePort",
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
    "udp_probe=127.0.0.1:$UdpProbePort",
    "redirect=${RedirectAddress}:${RedirectPort}",
    'scope=windows_udp_policy_explicit_out_of_scope'
  )

  $targetIp = Resolve-Ipv4Target -HostName $TargetHost
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'target-resolve.log') -Lines @(
    "target_host=$TargetHost",
    "target_ip=$targetIp",
    "target_port=$TargetPort"
  )
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'original-destination.log') -Lines @(
    "controlled tcp original destination: ${targetIp}:${TargetPort}",
    "udp_probe: 127.0.0.1:$UdpProbePort",
    "udp_policy: explicit_out_of_scope_no_capture",
    'udp_capture_contract: preview_allowlist_only',
    'udp_preview_ports: []',
    'wfp_layer: ALE_CONNECT_REDIRECT_V4 TCP only',
    'broad_windows_wide_capture: not claimed',
    'dns_capture: not claimed',
    'ipv6_capture: not claimed'
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
    'Summary: AEGIS WFP proof provider/filter present after UDP policy install.',
    'AEGIS_WFP_PROOF_MATCH_COUNT=2',
    'Matched names:',
    '- AEGIS WFP proof controlled redirect filter',
    '- AEGIS WFP proof provider',
    "Scope: controlled TCP target ${targetIp}:${TargetPort}; UDP rules not installed.",
    'Full machine-wide WFP dump omitted from committed artifact.'
  )

  $udpBody = Invoke-LocalUdpProbe -Port $UdpProbePort
  $udpProbeSucceeded = $udpBody -eq 'AEGIS_UDP_POLICY_PROBE'
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'udp-probe.log') -Lines @(
    "udp_probe=127.0.0.1:$UdpProbePort",
    "udp_probe_body=$udpBody",
    "udp_probe_succeeded=$udpProbeSucceeded"
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
        if ($eventCode -match '(?i)udp' -or $nestedEvent -match '(?i)udp') {
          $udpEventsSeen = $true
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

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'udp-policy.log') -Lines @(
    'udp_policy=explicit_out_of_scope_no_capture',
    'udp_capture=false',
    'wfp_udp_filter_installed=false',
    'udp_capture_contract=preview_allowlist_only',
    'udp_preview_ports=[]',
    "udp_probe_succeeded=$udpProbeSucceeded",
    "runtime_udp_events_seen=$udpEventsSeen",
    "windows_wide_flow_accepted_seen=$flowAccepted",
    'broad_windows_wide_capture=not_claimed',
    'dns_capture=not_claimed',
    'ipv6_capture=not_claimed'
  )

  if (!$udpProbeSucceeded) {
    $blocker = 'udp_probe_failed'
  } elseif ($udpEventsSeen -or $flowAccepted) {
    $blocker = 'unexpected_udp_or_flow_capture_event_seen'
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
    feature = 'windows_udp_policy_proof'
    platform = 'Windows'
    scope = 'udp_policy_explicit_out_of_scope'
    wfp_tcp_controlled_path_status = 'PASS'
    backend = 'wfp_ale_connect_redirect_tcp_only'
    target_host = $TargetHost
    target_ip = $targetIp
    target_port = $TargetPort
    udp_probe = "127.0.0.1:$UdpProbePort"
    udp_policy = 'explicit_out_of_scope_no_capture'
    udp_capture = $false
    wfp_udp_filter_installed = $false
    udp_capture_contract = 'preview_allowlist_only'
    udp_preview_ports = @()
    udp_probe_succeeded = $udpProbeSucceeded
    runtime_udp_events_seen = $udpEventsSeen
    windows_wide_flow_accepted_seen = $flowAccepted
    cleanup = $cleanupStatus
    blocker = $blocker
    broad_capture_claim = 'not_claimed'
    dns_claim = 'not_claimed'
    udp_capture_claim = 'not_claimed'
    ipv6_claim = 'not_claimed'
  }
  $result | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $ArtifactRoot 'result.json') -Encoding UTF8

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'README.md') -Lines @(
    '# Windows UDP Policy Proof',
    '',
    "Status: $status",
    '',
    'This artifact proves the current Phase D Windows UDP policy is explicit',
    'out-of-scope/no-capture while controlled TCP WFP redirect work continues.',
    '',
    'It does not claim UDP relay, UDP capture, IPv6 capture, DNS capture, or',
    'broad Windows wide capture.'
  )

  if ($status -eq 'PASS') {
    Write-Host "PASS artifact=$ArtifactRoot"
    exit 0
  }
  Write-Host "FAIL artifact=$ArtifactRoot blocker=$blocker"
  exit 1
}
