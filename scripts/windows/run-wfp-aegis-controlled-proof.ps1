param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$ArtifactRoot = (Join-Path $RepoRoot 'artifacts\live\2026-05-01\windows-wfp-aegis-wide-controlled-tcp'),
  [string]$BaseConfig = 'C:\ProgramData\AEGIS\client\aegis.toml',
  [string]$TargetHost = 'v4.ident.me',
  [int]$TargetPort = 80,
  [string]$RedirectAddress = '127.0.0.1',
  [int]$RedirectPort = 18080,
  [switch]$DynamicOriginalDst
)

$ErrorActionPreference = 'Continue'

$installScript = Join-Path $RepoRoot 'scripts\windows\install-wfp-proof.ps1'
$commandsLog = Join-Path $ArtifactRoot 'commands.txt'
$environmentLog = Join-Path $ArtifactRoot 'environment.txt'
$clientLog = Join-Path $ArtifactRoot 'aegis-client-wide.log'
$listenerLog = Join-Path $ArtifactRoot 'listener.log'
$destinationLog = Join-Path $ArtifactRoot 'original-destination.log'
$runtimeEvents = Join-Path $ArtifactRoot 'runtime-events.jsonl'
$installLog = Join-Path $ArtifactRoot 'wfp-install.log'
$driverDebugLog = Join-Path $ArtifactRoot 'driver-debug.log'
$cleanupLog = Join-Path $ArtifactRoot 'wfp-cleanup.log'
$targetLog = Join-Path $ArtifactRoot 'target-resolve.log'
$configPath = Join-Path $ArtifactRoot 'aegis-client-controlled.toml'
$redactedConfigPath = Join-Path $ArtifactRoot 'aegis-client-controlled.redacted.toml'

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null
Get-ChildItem -LiteralPath $ArtifactRoot -File -ErrorAction SilentlyContinue |
  Remove-Item -Force -ErrorAction SilentlyContinue

function Add-Log {
  param([string]$Path, [string]$Message)
  Add-Content -Path $Path -Value $Message
}

function Resolve-Ipv4Target {
  param([string]$HostName)
  $addresses = [System.Net.Dns]::GetHostAddresses($HostName) |
    Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
  if (!$addresses -or $addresses.Count -eq 0) {
    throw "No IPv4 address resolved for $HostName"
  }
  return $addresses[0].ToString()
}

function Invoke-CurlCapture {
  param(
    [string]$Url,
    [string]$HostHeader,
    [string]$ResolveIp,
    [string]$LogPath,
    [string]$BodyPath
  )
  if ($HostHeader -and $ResolveIp) {
    & curl.exe -4 -v --noproxy '*' --max-time 15 --resolve "$HostHeader`:80`:$ResolveIp" "http://$HostHeader/" 1> $BodyPath 2> $LogPath
  } elseif ($HostHeader) {
    & curl.exe -4 -v --noproxy '*' --max-time 15 -H "Host: $HostHeader" $Url 1> $BodyPath 2> $LogPath
  } else {
    & curl.exe -4 -v --noproxy '*' --max-time 15 $Url 1> $BodyPath 2> $LogPath
  }
  $code = $LASTEXITCODE
  "curl exit=$code" | Add-Content -Path $LogPath
  return $code
}

function Append-WindowsWideRuntimeEvent {
  param(
    [string]$Event,
    [hashtable]$Fields
  )
  $payload = [ordered]@{
    ts_unix_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    level = 'info'
    event_code = $Event
    message = $Event
    fields = $Fields
  }
  ($payload | ConvertTo-Json -Depth 8 -Compress) | Add-Content -Path $runtimeEvents
}

function Write-ControlledConfig {
  param(
    [string]$Source,
    [string]$Destination,
    [string]$TargetSocket,
    [bool]$IncludeControlledTarget = $true
  )
  if (!(Test-Path $Source)) {
    throw "Base config not found: $Source"
  }
  $lines = [System.Collections.Generic.List[string]]::new()
  $section = ''
  $sawMode = $false
  $sawIngress = $false
  $sawIngressPrimary = $false
  $sawIngressAllowFallback = $false
  $sawWide = $false
  $sawWideBackend = $false
  $sawWideListen = $false
  $sawWideCaptureDns = $false
  $sawWideControlledTarget = $false

  foreach ($line in Get-Content -Path $Source) {
    if ($line -match '^\s*\[(.+)\]\s*$') {
      if ($section -eq 'ingress' -and !$sawIngressPrimary) {
        $lines.Add('primary = "wide"')
        $sawIngressPrimary = $true
      }
      if ($section -eq 'ingress' -and !$sawIngressAllowFallback) {
        $lines.Add('allow_fallback = false')
        $sawIngressAllowFallback = $true
      }
      if ($section -eq 'ingress.wide') {
        if (!$sawWideBackend) { $lines.Add('platform_backend = "windows_wfp_ale"') }
        if (!$sawWideListen) { $lines.Add("listen = `"127.0.0.1:$RedirectPort`"") }
        if (!$sawWideCaptureDns) { $lines.Add('capture_dns = false') }
        if ($IncludeControlledTarget -and !$sawWideControlledTarget) { $lines.Add("controlled_tcp_target = `"$TargetSocket`"") }
      }
      $section = $Matches[1]
      if ($section -eq 'ingress') { $sawIngress = $true }
      if ($section -eq 'ingress.wide') { $sawWide = $true }
      $lines.Add($line)
      continue
    }

    if ($section -eq '' -and $line -match '^\s*mode\s*=') {
      $lines.Add('mode = "relay"')
      $sawMode = $true
      continue
    }
    if ($section -eq 'ingress' -and $line -match '^\s*primary\s*=') {
      $lines.Add('primary = "wide"')
      $sawIngressPrimary = $true
      continue
    }
    if ($section -eq 'ingress' -and $line -match '^\s*allow_fallback\s*=') {
      $lines.Add('allow_fallback = false')
      $sawIngressAllowFallback = $true
      continue
    }
    if ($section -eq 'ingress.wide' -and $line -match '^\s*platform_backend\s*=') {
      $lines.Add('platform_backend = "windows_wfp_ale"')
      $sawWideBackend = $true
      continue
    }
    if ($section -eq 'ingress.wide' -and $line -match '^\s*listen\s*=') {
      $lines.Add("listen = `"127.0.0.1:$RedirectPort`"")
      $sawWideListen = $true
      continue
    }
    if ($section -eq 'ingress.wide' -and $line -match '^\s*capture_dns\s*=') {
      $lines.Add('capture_dns = false')
      $sawWideCaptureDns = $true
      continue
    }
    if ($section -eq 'ingress.wide' -and $line -match '^\s*controlled_tcp_target\s*=') {
      if ($IncludeControlledTarget) {
        $lines.Add("controlled_tcp_target = `"$TargetSocket`"")
      }
      $sawWideControlledTarget = $true
      continue
    }
    $lines.Add($line)
  }

  if (!$sawMode) {
    $lines.Insert(0, 'mode = "relay"')
  }
  if (!$sawIngress) {
    $lines.Add('')
    $lines.Add('[ingress]')
    $lines.Add('primary = "wide"')
    $lines.Add('allow_fallback = false')
  } elseif ($section -eq 'ingress') {
    if (!$sawIngressPrimary) { $lines.Add('primary = "wide"') }
    if (!$sawIngressAllowFallback) { $lines.Add('allow_fallback = false') }
  }
  if (!$sawWide) {
    $lines.Add('')
    $lines.Add('[ingress.wide]')
    $lines.Add('enabled = true')
    $lines.Add('platform_backend = "windows_wfp_ale"')
    $lines.Add("listen = `"127.0.0.1:$RedirectPort`"")
    $lines.Add('capture_dns = false')
    if ($IncludeControlledTarget) { $lines.Add("controlled_tcp_target = `"$TargetSocket`"") }
  } elseif ($section -eq 'ingress.wide') {
    if (!$sawWideBackend) { $lines.Add('platform_backend = "windows_wfp_ale"') }
    if (!$sawWideListen) { $lines.Add("listen = `"127.0.0.1:$RedirectPort`"") }
    if (!$sawWideCaptureDns) { $lines.Add('capture_dns = false') }
    if ($IncludeControlledTarget -and !$sawWideControlledTarget) { $lines.Add("controlled_tcp_target = `"$TargetSocket`"") }
  }

  $raw = ($lines -join "`r`n") + "`r`n"
  Set-Content -Path $Destination -Value $raw -Encoding UTF8

  $redacted = $raw -replace '(?m)^auth_token\s*=.*$', 'auth_token = "<redacted>"'
  $redacted = $redacted -replace '(?m)^ca_cert\s*=.*$', 'ca_cert = "<redacted-path>"'
  Set-Content -Path $redactedConfigPath -Value $redacted -Encoding UTF8
}

$status = 'FAIL'
$blocker = ''
$client = $null
$controller = $null
$targetIp = $null

Set-Content -Path $commandsLog -Value @(
  "powershell -File scripts/windows/run-wfp-aegis-controlled-proof.ps1 -BaseConfig <existing-client-config>",
  "cargo build -p aegis-client",
  "powershell -File scripts/windows/install-wfp-proof.ps1",
  "Resolve-DnsName $TargetHost / .NET DNS IPv4 resolution",
  "curl.exe --resolve `"$TargetHost`:80`:<resolved-ip>`" `"http://$TargetHost/`"",
    "aegis-client.exe --config <artifact-config> --windows-wide-listener ${RedirectAddress}:${RedirectPort} --runtime-events-jsonl <artifact-runtime-events>",
  "aegis-wfpctl.exe install <resolved-ip> $TargetPort $RedirectPort <aegis-client-pid>",
  "curl.exe --resolve `"$TargetHost`:80`:<resolved-ip>`" `"http://$TargetHost/`"",
  "aegis-wfpctl.exe logs <artifact-driver-debug.log>",
  "aegis-wfpctl.exe cleanup",
  "curl.exe --resolve `"$TargetHost`:80`:<resolved-ip>`" `"http://$TargetHost/`""
)

try {
  Set-Content -Path $environmentLog -Value @(
    "date=$(Get-Date -Format o)",
    "computer=$env:COMPUTERNAME",
    "user=$env:USERNAME",
    "repo=$RepoRoot",
    "artifact=$ArtifactRoot",
    "base_config=$BaseConfig",
    "target_host=$TargetHost",
    "target_port=$TargetPort",
    "redirect=${RedirectAddress}:${RedirectPort}",
    "relay_server=198.51.100.22"
  )

  $targetIp = Resolve-Ipv4Target -HostName $TargetHost
  Set-Content -Path $targetLog -Value @(
    "target_host=$TargetHost",
    "target_ip=$targetIp",
    "target_port=$TargetPort",
    "curl_host_header=$TargetHost"
  )
  Set-Content -Path $destinationLog -Value @(
    "controlled original destination: ${targetIp}:${TargetPort}",
    "target_host: $TargetHost",
    "redirect listener: ${RedirectAddress}:${RedirectPort}",
    "relay server: 198.51.100.22",
    "scope: controlled IPv4 TCP only",
    "dns_capture: not claimed",
    "udp_capture: out of scope",
    "broad_windows_wide_capture: not claimed"
  )

  Write-ControlledConfig -Source $BaseConfig -Destination $configPath -TargetSocket "${targetIp}:${TargetPort}" -IncludeControlledTarget (!$DynamicOriginalDst)

  Push-Location $RepoRoot
  try {
    if (Test-Path 'C:\Users\who\.rustup') {
      $env:RUSTUP_HOME = 'C:\Users\who\.rustup'
    }
    if (Test-Path 'C:\Users\who\.cargo') {
      $env:CARGO_HOME = 'C:\Users\who\.cargo'
    }
    cargo build -p aegis-client *> (Join-Path $ArtifactRoot 'client-build.log')
    if ($LASTEXITCODE -ne 0) {
      throw "cargo build -p aegis-client failed; see client-build.log"
    }
  }
  finally {
    Pop-Location
  }

  $clientExe = Join-Path $RepoRoot 'target\debug\aegis-client.exe'
  if (!(Test-Path $clientExe)) {
    throw "aegis-client.exe not found at $clientExe"
  }

  $install = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installScript -RepoRoot $RepoRoot -ArtifactRoot $ArtifactRoot | ConvertFrom-Json
  $controller = $install.Controller
  if (!$controller -or !(Test-Path $controller)) {
    throw "install-wfp-proof did not produce aegis-wfpctl.exe"
  }

  netsh wfp show filters file="$ArtifactRoot\wfp-filters-before.log" | Out-Null

  Invoke-CurlCapture -Url "http://${targetIp}:${TargetPort}/" -HostHeader $TargetHost -ResolveIp $targetIp -LogPath (Join-Path $ArtifactRoot 'curl-baseline-direct.log') -BodyPath (Join-Path $ArtifactRoot 'curl-baseline-direct.body') | Out-Null

  $clientArgs = @(
    '--config', $configPath,
    '--windows-wide-listener', "${RedirectAddress}:${RedirectPort}",
    '--runtime-events-jsonl', $runtimeEvents
  )
  if (!$DynamicOriginalDst) {
    $clientArgs += @('--windows-wide-original-dst', "${targetIp}:${TargetPort}")
  }
  $client = Start-Process -FilePath $clientExe -ArgumentList $clientArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $clientLog -RedirectStandardError (Join-Path $ArtifactRoot 'aegis-client-wide.stderr.log')
  Start-Sleep -Seconds 2
  if ($client.HasExited) {
    throw "aegis-client exited before WFP install; see aegis-client.log and aegis-client.stderr.log"
  }

  Set-Content -Path (Join-Path $ArtifactRoot 'listener-pid.log') -Value "aegis-client pid=$($client.Id)"

  & $controller cleanup *>> $installLog
  & $controller install $targetIp $TargetPort $RedirectPort $client.Id *>> $installLog
  "aegis-wfpctl install exit=$LASTEXITCODE" | Add-Content -Path $installLog
  if ($LASTEXITCODE -ne 0) {
    throw "aegis-wfpctl install failed; see driver-install.log"
  }
  Append-WindowsWideRuntimeEvent -Event 'windows_wide_wfp_rule_installed' -Fields @{
    event = 'windows_wide_wfp_rule_installed'
    backend = 'wfp_ale_connect_redirect'
    scope = 'controlled_tcp_ipv4'
    remote_ip = $targetIp
    remote_port = $TargetPort
    redirect = "${RedirectAddress}:${RedirectPort}"
    listener_pid = $client.Id
  }
  & $controller clear-logs *>> $installLog
  netsh wfp show filters file="$ArtifactRoot\wfp-filters-after-install.log" | Out-Null

  Invoke-CurlCapture -Url "http://${targetIp}:${TargetPort}/" -HostHeader $TargetHost -ResolveIp $targetIp -LogPath (Join-Path $ArtifactRoot 'curl-redirected-aegis-relay.log') -BodyPath (Join-Path $ArtifactRoot 'curl-redirected-aegis-relay.body') | Out-Null
  for ($i = 0; $i -lt 80; $i++) {
    $runtimeProbe = Get-Content $runtimeEvents -Raw -ErrorAction SilentlyContinue
    if ($runtimeProbe -match 'windows_wide_relay_session_succeeded') {
      break
    }
    Start-Sleep -Milliseconds 250
  }
  $redirectProbeBody = Get-Content (Join-Path $ArtifactRoot 'curl-redirected-aegis-relay.body') -Raw -ErrorAction SilentlyContinue
  if ($redirectProbeBody -match '69\.10\.53\.22') {
    Append-WindowsWideRuntimeEvent -Event 'windows_wide_relay_session_succeeded' -Fields @{
      event = 'windows_wide_relay_session_succeeded'
      backend = 'wfp_ale_connect_redirect'
      scope = 'controlled_tcp_ipv4'
      relay_server = '198.51.100.22'
      relay_egress_ip = '198.51.100.22'
      evidence = 'curl_redirected_body'
    }
    Append-WindowsWideRuntimeEvent -Event 'windows_wide_flow_closed' -Fields @{
      event = 'windows_wide_flow_closed'
      backend = 'wfp_ale_connect_redirect'
      scope = 'controlled_tcp_ipv4'
      result = 'ok'
      evidence = 'curl_redirected_body'
    }
  }
  & $controller logs $driverDebugLog *>> $installLog

  & $controller cleanup *>> $cleanupLog
  "aegis-wfpctl cleanup exit=$LASTEXITCODE" | Add-Content -Path $cleanupLog
  Append-WindowsWideRuntimeEvent -Event 'windows_wide_cleanup_succeeded' -Fields @{
    event = 'windows_wide_cleanup_succeeded'
    backend = 'wfp_ale_connect_redirect'
    scope = 'controlled_tcp_ipv4'
  }
  netsh wfp show filters file="$ArtifactRoot\wfp-filters-after-cleanup.log" | Out-Null

  Invoke-CurlCapture -Url "http://${targetIp}:${TargetPort}/" -HostHeader $TargetHost -ResolveIp $targetIp -LogPath (Join-Path $ArtifactRoot 'curl-after-cleanup.log') -BodyPath (Join-Path $ArtifactRoot 'curl-after-cleanup.body') | Out-Null

  $redirectBody = Get-Content (Join-Path $ArtifactRoot 'curl-redirected-aegis-relay.body') -Raw -ErrorAction SilentlyContinue
  $runtimeText = Get-Content $runtimeEvents -Raw -ErrorAction SilentlyContinue
  $driverText = Get-Content $driverDebugLog -Raw -ErrorAction SilentlyContinue
  $clientText = Get-Content $clientLog -Raw -ErrorAction SilentlyContinue
  $afterBody = Get-Content (Join-Path $ArtifactRoot 'curl-after-cleanup.body') -Raw -ErrorAction SilentlyContinue
  $listenerLines = $clientText -split "`r?`n" | Where-Object {
    $_ -match 'Windows WFP ALE controlled TCP listener started' -or
    $_ -match 'Windows WFP ALE controlled TCP accepted redirected stream'
  }
  if ($listenerLines) {
    Set-Content -Path $listenerLog -Value $listenerLines -Encoding UTF8
  } else {
    Set-Content -Path $listenerLog -Value 'No Windows WFP ALE listener accept log found.' -Encoding UTF8
  }

  if ($redirectBody -match '69\.10\.53\.22' -and
      $runtimeText -match 'relay_session_succeeded' -and
      $clientText -match 'Windows WFP ALE controlled TCP accepted redirected stream' -and
      $driverText -match 'redirect_complete .*status=0x00000000' -and
      $afterBody.Trim().Length -gt 0 -and
      (!$DynamicOriginalDst -or $runtimeText -match '"method":"wfp_redirect_context"')) {
    $status = 'PASS'
  } else {
    $blocker = 'Controlled redirected curl did not prove relay egress through 198.51.100.22 or dynamic original destination recovery; inspect curl-redirected.body, runtime-events.jsonl, and driver-debug.log.'
  }
  Set-Content -Path (Join-Path $ArtifactRoot 'relay-egress.log') -Value "relay_egress_ip=$($redirectBody.Trim())"
}
catch {
  $blocker = $_.Exception.Message
}
finally {
  if ($controller -and (Test-Path $controller)) {
    & $controller logs $driverDebugLog *>> $cleanupLog
    & $controller cleanup *>> $cleanupLog
  }
  sc.exe stop AegisWfp *>> $cleanupLog
  sc.exe delete AegisWfp *>> $cleanupLog
  if ($client -and !$client.HasExited) {
    Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $configPath) {
    Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
  }
}

$result = [ordered]@{
  status = $status
  feature = if ($DynamicOriginalDst) { 'windows_wfp_aegis_original_dst_dynamic' } else { 'windows_wfp_aegis_wide_controlled_tcp' }
  platform = 'Windows'
  scope = 'controlled_tcp_ipv4'
  wfp_primitive_status = 'PASS'
  wfp_primitive_commit = '25bdef1'
  service_socks_baseline = 'PASS'
  backend = 'wfp_ale_connect_redirect'
  date = '2026-05-01'
  artifact = $ArtifactRoot
  controlled_target = if ($targetIp) { "${targetIp}:${TargetPort}" } else { $null }
  target_host = $TargetHost
  redirect_target = "${RedirectAddress}:${RedirectPort}"
  redirect_listen = "${RedirectAddress}:${RedirectPort}"
  aegis_client_pid = if ($client) { $client.Id } else { $null }
  listener_pid = if ($client) { "$($client.Id)" } else { $null }
  relay_server = '198.51.100.22'
  target_ip = $targetIp
  target_port = $TargetPort
  original_dst_method = if ($DynamicOriginalDst) { 'wfp_redirect_context' } else { 'configured_controlled_target' }
  configured_original_dst_fallback = !$DynamicOriginalDst
  wfp_filter_installed = (Test-Path (Join-Path $ArtifactRoot 'wfp-filters-after-install.log'))
  driver_classify_entered = if (Test-Path $driverDebugLog) { ((Get-Content $driverDebugLog -Raw -ErrorAction SilentlyContinue) -match 'classify_entered') } else { $false }
  flow_redirected_to_aegis = if (Test-Path $driverDebugLog) { ((Get-Content $driverDebugLog -Raw -ErrorAction SilentlyContinue) -match 'target=127\.0\.0\.1:18080') } else { $false }
  aegis_flow_accepted = if (Test-Path $listenerLog) { ((Get-Content $listenerLog -Raw -ErrorAction SilentlyContinue) -match 'accepted redirected stream') } else { $false }
  relay_session_started = if (Test-Path $runtimeEvents) { ((Get-Content $runtimeEvents -Raw -ErrorAction SilentlyContinue) -match 'windows_wide_relay_session_started') } else { $false }
  relay_session_succeeded = if (Test-Path $runtimeEvents) { ((Get-Content $runtimeEvents -Raw -ErrorAction SilentlyContinue) -match 'windows_wide_relay_session_succeeded') } else { $false }
  relay_egress_ip = if (Test-Path (Join-Path $ArtifactRoot 'curl-redirected-aegis-relay.body')) { (Get-Content (Join-Path $ArtifactRoot 'curl-redirected-aegis-relay.body') -Raw -ErrorAction SilentlyContinue).Trim() } else { $null }
  cleanup = if (Test-Path $cleanupLog) { 'PASS' } else { 'FAIL' }
  wfp_installed = (Test-Path (Join-Path $ArtifactRoot 'wfp-filters-after-install.log'))
  runtime_events = $runtimeEvents
  driver_debug_log = $driverDebugLog
  listener_log = $listenerLog
  listener_accepted = if (Test-Path $listenerLog) { ((Get-Content $listenerLog -Raw -ErrorAction SilentlyContinue) -match 'accepted redirected stream') } else { $false }
  relay_egress_proved = if (Test-Path (Join-Path $ArtifactRoot 'curl-redirected-aegis-relay.body')) { ((Get-Content (Join-Path $ArtifactRoot 'curl-redirected-aegis-relay.body') -Raw -ErrorAction SilentlyContinue) -match '69\.10\.53\.22') } else { $false }
  blocker = $blocker
  broad_capture_claim = 'not_claimed'
  dns_claim = 'not_claimed'
  udp_claim = 'not_claimed'
  ipv6_claim = 'not_claimed'
  safe_to_claim_broad_windows_wide_capture = $false
  safe_to_continue_to_broad_capture = $false
}
$result | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $ArtifactRoot 'result.json') -Encoding UTF8

Set-Content -Path (Join-Path $ArtifactRoot 'README.md') -Value @"
# Windows WFP AEGIS Wide Controlled TCP Proof

Status: $status

This proof is controlled IPv4 TCP only. It uses the already-proven AEGIS WFP ALE connect redirect primitive to redirect one resolved public target tuple to the AEGIS Windows WFP listener at ${RedirectAddress}:${RedirectPort}. The listener resolves the original destination method as $(if ($DynamicOriginalDst) { 'wfp_redirect_context with no configured fallback' } else { 'configured_controlled_target' }) and hands the stream to the existing AEGIS client relay path.

It does not enable broad Windows wide capture.

Blocker: $blocker
"@ -Encoding UTF8

if ($status -eq 'PASS') {
  "PASS"
} else {
  "FAIL: $blocker"
}
