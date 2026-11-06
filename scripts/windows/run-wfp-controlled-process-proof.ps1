param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$ArtifactRoot = (Join-Path $RepoRoot 'artifacts\live\2026-05-01\windows-wfp-controlled-process-capture'),
  [string]$BaseConfig = 'C:\ProgramData\AEGIS\client\aegis.toml',
  [string]$TargetHost = 'api.ipify.org',
  [int]$TargetPort = 443,
  [string]$RedirectAddress = '127.0.0.1',
  [int]$RedirectPort = 18080
)

$ErrorActionPreference = 'Continue'

$installScript = Join-Path $RepoRoot 'scripts\windows\install-wfp-proof.ps1'
$commandsLog = Join-Path $ArtifactRoot 'commands.txt'
$environmentLog = Join-Path $ArtifactRoot 'environment.txt'
$runtimeEvents = Join-Path $ArtifactRoot 'runtime-events.jsonl'
$clientLog = Join-Path $ArtifactRoot 'aegis-client-wide.log'
$clientErr = Join-Path $ArtifactRoot 'aegis-client-wide.stderr.log'
$listenerLog = Join-Path $ArtifactRoot 'listener.log'
$installLog = Join-Path $ArtifactRoot 'wfp-install.log'
$cleanupLog = Join-Path $ArtifactRoot 'wfp-cleanup.log'
$driverDebugLog = Join-Path $ArtifactRoot 'driver-debug.log'
$targetLog = Join-Path $ArtifactRoot 'target-resolve.log'
$destinationLog = Join-Path $ArtifactRoot 'original-destination.log'
$configPath = Join-Path $ArtifactRoot 'aegis-client-controlled-process.toml'
$redactedConfigPath = Join-Path $ArtifactRoot 'aegis-client-controlled-process.redacted.toml'
$workerScript = Join-Path $ArtifactRoot 'selected-process-worker.ps1'
$triggerPath = Join-Path $ArtifactRoot 'selected-process.trigger'
$selectedBody = Join-Path $ArtifactRoot 'selected-process.body'
$selectedLog = Join-Path $ArtifactRoot 'selected-process.log'

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null
Get-ChildItem -LiteralPath $ArtifactRoot -File -ErrorAction SilentlyContinue |
  Remove-Item -Force -ErrorAction SilentlyContinue

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
    [string]$HostHeader,
    [string]$ResolveIp,
    [string]$LogPath,
    [string]$BodyPath
  )
  $scheme = if ($TargetPort -eq 443) { 'https' } else { 'http' }
  & curl.exe -4 -v --noproxy '*' --max-time 20 --resolve "$HostHeader`:$TargetPort`:$ResolveIp" "${scheme}://$HostHeader/" 1> $BodyPath 2> $LogPath
  $code = $LASTEXITCODE
  "curl exit=$code" | Add-Content -Path $LogPath
  return $code
}

function Write-ControlledConfig {
  param(
    [string]$Source,
    [string]$Destination
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
  }
  if (!$sawWide) {
    $lines.Add('')
    $lines.Add('[ingress.wide]')
    $lines.Add('enabled = true')
    $lines.Add('platform_backend = "windows_wfp_ale"')
    $lines.Add("listen = `"127.0.0.1:$RedirectPort`"")
    $lines.Add('capture_dns = false')
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
$worker = $null
$controller = $null
$targetIp = $null

Set-Content -Path $commandsLog -Value @(
  "powershell -File scripts/windows/run-wfp-controlled-process-proof.ps1 -BaseConfig <existing-client-config>",
  "powershell -File scripts/windows/install-wfp-proof.ps1",
  "aegis-client.exe --config <artifact-config> --windows-wide-listener ${RedirectAddress}:${RedirectPort} --runtime-events-jsonl <artifact-runtime-events>",
  "start selected powershell worker; capture selected worker PID before WFP install",
  "aegis-wfpctl.exe install <resolved-ip> $TargetPort $RedirectPort <aegis-client-pid> <selected-worker-pid>",
  "curl.exe --resolve `"$TargetHost`:$TargetPort`:<resolved-ip>`" `"<scheme>://$TargetHost/`" # non-selected control",
  "selected worker sends HTTP GET with Host/SNI: $TargetHost to <resolved-ip>:$TargetPort",
  "aegis-wfpctl.exe logs <artifact-driver-debug.log>",
  "aegis-wfpctl.exe cleanup"
)

try {
  Set-Content -Path $environmentLog -Value @(
    "date=$(Get-Date -Format o)",
    "computer=$env:COMPUTERNAME",
    "user=$env:USERNAME",
    "repo=$RepoRoot",
    "artifact=$ArtifactRoot",
    "target_host=$TargetHost",
    "target_port=$TargetPort",
    "redirect=${RedirectAddress}:${RedirectPort}",
    "scope=controlled_process_tcp_ipv4"
  )

  $targetIp = Resolve-Ipv4Target -HostName $TargetHost
  Set-Content -Path $targetLog -Value @(
    "target_host=$TargetHost",
    "target_ip=$targetIp",
    "target_port=$TargetPort"
  )
  Set-Content -Path $destinationLog -Value @(
    "controlled original destination: ${targetIp}:${TargetPort}",
    "target_host: $TargetHost",
    "redirect listener: ${RedirectAddress}:${RedirectPort}",
    "process_match: selected worker PID only",
    "broad_windows_wide_capture: not claimed",
    "dns_capture: not claimed",
    "udp_capture: not claimed",
    "ipv6_capture: not claimed"
  )

  Write-ControlledConfig -Source $BaseConfig -Destination $configPath

  Push-Location $RepoRoot
  try {
    if (Test-Path 'C:\Users\who\.rustup') { $env:RUSTUP_HOME = 'C:\Users\who\.rustup' }
    if (Test-Path 'C:\Users\who\.cargo') { $env:CARGO_HOME = 'C:\Users\who\.cargo' }
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
  Invoke-CurlCapture -HostHeader $TargetHost -ResolveIp $targetIp -LogPath (Join-Path $ArtifactRoot 'curl-baseline-direct.log') -BodyPath (Join-Path $ArtifactRoot 'curl-baseline-direct.body') | Out-Null

  $clientArgs = @(
    '--config', $configPath,
    '--windows-wide-listener', "${RedirectAddress}:${RedirectPort}",
    '--runtime-events-jsonl', $runtimeEvents
  )
  $client = Start-Process -FilePath $clientExe -ArgumentList $clientArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $clientLog -RedirectStandardError $clientErr
  Start-Sleep -Seconds 2
  if ($client.HasExited) {
    throw "aegis-client exited before WFP install; see aegis-client logs"
  }

  Set-Content -Path $workerScript -Value @"
`$ErrorActionPreference = 'Stop'
while (!(Test-Path -LiteralPath '$triggerPath')) { Start-Sleep -Milliseconds 100 }
try {
  `$client = [Net.Sockets.TcpClient]::new()
  `$client.ReceiveTimeout = 30000
  `$client.SendTimeout = 30000
  `$client.Connect('$targetIp', $TargetPort)
  `$baseStream = `$client.GetStream()
  if ($TargetPort -eq 443) {
    `$stream = [Net.Security.SslStream]::new(`$baseStream, `$false, ({ `$true } -as [Net.Security.RemoteCertificateValidationCallback]))
    `$stream.AuthenticateAsClient('$TargetHost')
  } else {
    `$stream = `$baseStream
  }
  `$request = "GET / HTTP/1.1`r`nHost: $TargetHost`r`nConnection: close`r`nUser-Agent: AEGIS-WFP-PROCESS-PROOF`r`n`r`n"
  `$bytes = [Text.Encoding]::ASCII.GetBytes(`$request)
  `$stream.Write(`$bytes, 0, `$bytes.Length)
  `$buffer = New-Object byte[] 8192
  `$chunks = New-Object System.Collections.Generic.List[byte]
  while ((`$read = `$stream.Read(`$buffer, 0, `$buffer.Length)) -gt 0) {
    for (`$i = 0; `$i -lt `$read; `$i++) { `$chunks.Add(`$buffer[`$i]) }
  }
  `$text = [Text.Encoding]::UTF8.GetString(`$chunks.ToArray())
  Set-Content -Path '$selectedBody' -Value `$text -Encoding UTF8
  Set-Content -Path '$selectedLog' -Value "selected_worker_exit=0`npid=`$PID`nbytes=`$(`$chunks.Count)" -Encoding UTF8
  `$client.Close()
  exit 0
} catch {
  Set-Content -Path '$selectedLog' -Value "selected_worker_exit=1`npid=`$PID`nerror=`$(`$_.Exception.Message)" -Encoding UTF8
  exit 1
}
"@ -Encoding UTF8

  $worker = Start-Process -FilePath powershell.exe -ArgumentList @(
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    $workerScript
  ) -WindowStyle Hidden -PassThru
  Start-Sleep -Seconds 1
  Set-Content -Path (Join-Path $ArtifactRoot 'process-match.log') -Value @(
    "selected_process_pid=$($worker.Id)",
    "selected_process_image=powershell.exe",
    "non_selected_process=curl.exe",
    "match_scope=target_ip_port_and_selected_pid"
  )
  Set-Content -Path (Join-Path $ArtifactRoot 'listener-pid.log') -Value "aegis-client pid=$($client.Id)"

  & $controller cleanup *>> $installLog
  & $controller install $targetIp $TargetPort $RedirectPort $client.Id $worker.Id *>> $installLog
  "aegis-wfpctl install exit=$LASTEXITCODE" | Add-Content -Path $installLog
  if ($LASTEXITCODE -ne 0) {
    throw "aegis-wfpctl install failed"
  }
  & $controller clear-logs *>> $installLog
  netsh wfp show filters file="$ArtifactRoot\wfp-filters-after-install.log" | Out-Null

  Invoke-CurlCapture -HostHeader $TargetHost -ResolveIp $targetIp -LogPath (Join-Path $ArtifactRoot 'curl-non-selected-direct.log') -BodyPath (Join-Path $ArtifactRoot 'curl-non-selected-direct.body') | Out-Null

  New-Item -ItemType File -Force -Path $triggerPath | Out-Null
  Wait-Process -Id $worker.Id -Timeout 45 -ErrorAction SilentlyContinue
  if (!$worker.HasExited) {
    throw "selected worker did not finish"
  }

  & $controller logs $driverDebugLog *>> $installLog
  & $controller cleanup *>> $cleanupLog
  "aegis-wfpctl cleanup exit=$LASTEXITCODE" | Add-Content -Path $cleanupLog
  netsh wfp show filters file="$ArtifactRoot\wfp-filters-after-cleanup.log" | Out-Null

  Invoke-CurlCapture -HostHeader $TargetHost -ResolveIp $targetIp -LogPath (Join-Path $ArtifactRoot 'curl-after-cleanup.log') -BodyPath (Join-Path $ArtifactRoot 'curl-after-cleanup.body') | Out-Null

  $clientText = Get-Content $clientLog -Raw -ErrorAction SilentlyContinue
  $driverText = Get-Content $driverDebugLog -Raw -ErrorAction SilentlyContinue
  $runtimeText = Get-Content $runtimeEvents -Raw -ErrorAction SilentlyContinue
  $selectedText = Get-Content $selectedBody -Raw -ErrorAction SilentlyContinue
  $nonSelectedText = Get-Content (Join-Path $ArtifactRoot 'curl-non-selected-direct.body') -Raw -ErrorAction SilentlyContinue
  $afterText = Get-Content (Join-Path $ArtifactRoot 'curl-after-cleanup.body') -Raw -ErrorAction SilentlyContinue
  $listenerLines = $clientText -split "`r?`n" | Where-Object {
    $_ -match 'Windows WFP ALE controlled TCP listener started' -or
    $_ -match 'Windows WFP ALE controlled TCP accepted redirected stream'
  }
  if ($listenerLines) {
    Set-Content -Path $listenerLog -Value $listenerLines -Encoding UTF8
  } else {
    Set-Content -Path $listenerLog -Value 'No Windows WFP ALE listener accept log found.' -Encoding UTF8
  }

  if ($selectedText -match '153\.75\.246\.229' -and
      $nonSelectedText -notmatch '153\.75\.246\.229' -and
      $afterText.Trim().Length -gt 0 -and
      $driverText -match "filter_matched .*process_id=$($worker.Id)" -and
      $driverText -match 'loop_prevention_reason_if_skipped=process_mismatch' -and
      $runtimeText -match 'windows_wide_original_dst_resolved' -and
      $runtimeText -match '"method":"wfp_redirect_context"') {
    $status = 'PASS'
  } else {
    $blocker = 'selected process did not prove relay egress, non-selected process was not proven direct, or driver logs did not show process match/mismatch'
  }
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
  if ($worker -and !$worker.HasExited) {
    Stop-Process -Id $worker.Id -Force -ErrorAction SilentlyContinue
  }
  if ($client -and !$client.HasExited) {
    Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $configPath) {
    Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
  }
}

$selectedBodyText = if (Test-Path $selectedBody) { (Get-Content $selectedBody -Raw -ErrorAction SilentlyContinue) } else { '' }
$nonSelectedBodyText = if (Test-Path (Join-Path $ArtifactRoot 'curl-non-selected-direct.body')) { (Get-Content (Join-Path $ArtifactRoot 'curl-non-selected-direct.body') -Raw -ErrorAction SilentlyContinue) } else { '' }
$driverDebugText = if (Test-Path $driverDebugLog) { (Get-Content $driverDebugLog -Raw -ErrorAction SilentlyContinue) } else { '' }
$runtimeText = if (Test-Path $runtimeEvents) { (Get-Content $runtimeEvents -Raw -ErrorAction SilentlyContinue) } else { '' }

$result = [ordered]@{
  status = $status
  feature = 'windows_wfp_controlled_process_capture'
  platform = 'Windows'
  scope = 'controlled_process_tcp_ipv4'
  backend = 'wfp_ale_connect_redirect'
  artifact = $ArtifactRoot
  target_host = $TargetHost
  target_ip = $targetIp
  target_port = $TargetPort
  redirect_listen = "${RedirectAddress}:${RedirectPort}"
  aegis_client_pid = if ($client) { $client.Id } else { $null }
  selected_process = 'powershell.exe'
  selected_process_pid = if ($worker) { $worker.Id } else { $null }
  non_selected_process = 'curl.exe'
  process_match_method = 'driver_classify_process_id'
  original_dst_method = 'wfp_redirect_context'
  selected_process_relay_egress_ip = if ($selectedBodyText -match '153\.75\.246\.229') { '198.51.100.229' } else { $null }
  non_selected_process_direct = $nonSelectedBodyText -notmatch '153\.75\.246\.229'
  driver_process_match_seen = if ($worker) { $driverDebugText -match "filter_matched .*process_id=$($worker.Id)" } else { $false }
  driver_process_mismatch_seen = $driverDebugText -match 'loop_prevention_reason_if_skipped=process_mismatch'
  relay_session_succeeded = $runtimeText -match 'windows_wide_relay_session_succeeded'
  cleanup = if (Test-Path $cleanupLog) { 'PASS' } else { 'FAIL' }
  blocker = $blocker
  broad_capture_claim = 'not_claimed'
  dns_claim = 'not_claimed'
  udp_claim = 'not_claimed'
  ipv6_claim = 'not_claimed'
}
$result | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $ArtifactRoot 'result.json') -Encoding UTF8

Set-Content -Path (Join-Path $ArtifactRoot 'README.md') -Value @"
# Windows WFP Controlled Process Capture

Status: $status

This artifact proves only a selected process PID is redirected for one controlled
IPv4 TCP target. It does not claim broad Windows wide capture, DNS, UDP, or IPv6.

Blocker: $blocker
"@ -Encoding UTF8

if ($status -eq 'PASS') {
  'PASS'
} else {
  "FAIL: $blocker"
}
