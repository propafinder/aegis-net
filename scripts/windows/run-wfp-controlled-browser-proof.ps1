param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$ArtifactRoot = (Join-Path $RepoRoot 'artifacts\live\2026-05-01\windows-wfp-controlled-browser-capture'),
  [string]$BaseConfig = 'C:\ProgramData\AEGIS\client\aegis.toml',
  [string]$BrowserPath = '',
  [string]$TargetHost = 'api.ipify.org',
  [int]$TargetPort = 443,
  [string]$ExpectedRelayEgressIp = '',
  [string]$RedirectAddress = '127.0.0.1',
  [int]$RedirectPort = 18080,
  [int]$DevToolsPort = 9223
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

$installScript = Join-Path $RepoRoot 'scripts\windows\install-wfp-proof.ps1'
$runtimeEvents = Join-Path $ArtifactRoot 'runtime-events.jsonl'
$clientLog = Join-Path $ArtifactRoot 'aegis-client-wide.log'
$clientErr = Join-Path $ArtifactRoot 'aegis-client-wide.stderr.log'
$browserStdout = Join-Path $ArtifactRoot 'browser.stdout.log'
$browserStderr = Join-Path $ArtifactRoot 'browser.stderr.log'
$configPath = Join-Path $ArtifactRoot 'aegis-client-browser.toml'
$redactedConfigPath = Join-Path $ArtifactRoot 'aegis-client-browser.redacted.toml'
$driverDebugLog = Join-Path $ArtifactRoot 'driver-debug.log'
$cleanupLog = Join-Path $ArtifactRoot 'wfp-cleanup.log'
$browserProfile = Join-Path $ArtifactRoot 'browser-profile'

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null
Get-ChildItem -LiteralPath $ArtifactRoot -File -ErrorAction SilentlyContinue |
  Remove-Item -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $browserProfile -Recurse -Force -ErrorAction SilentlyContinue

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

function Find-Browser {
  $candidates = @(
    'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
    'C:\Program Files\Google\Chrome\Application\chrome.exe',
    'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
  )
  foreach ($candidate in $candidates) {
    if (Test-Path $candidate) { return $candidate }
  }
  throw 'No supported Edge/Chrome browser found'
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

function Invoke-CurlCapture {
  param([string]$HostHeader, [string]$ResolveIp, [string]$LogPath, [string]$BodyPath)
  $scheme = if ($TargetPort -eq 443) { 'https' } else { 'http' }
  & curl.exe -4 -v --noproxy '*' --max-time 20 --resolve "$HostHeader`:$TargetPort`:$ResolveIp" "${scheme}://$HostHeader/" 1> $BodyPath 2> $LogPath
  $code = $LASTEXITCODE
  "curl exit=$code" | Add-Content -Path $LogPath
  return $code
}

function Wait-DevTools {
  param([int]$Port)
  for ($i = 0; $i -lt 80; $i++) {
    try {
      $version = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/json/version" -TimeoutSec 1
      if ($version.webSocketDebuggerUrl) { return $true }
    }
    catch {}
    Start-Sleep -Milliseconds 250
  }
  return $false
}

function Invoke-DevToolsCommand {
  param(
    [string]$WebSocketUrl,
    [int]$Id,
    [string]$Method,
    [hashtable]$Params = @{}
  )
  $ws = [Net.WebSockets.ClientWebSocket]::new()
  $ct = [Threading.CancellationToken]::None
  try {
    $ws.ConnectAsync([Uri]$WebSocketUrl, $ct).Wait(5000) | Out-Null
    $payload = @{ id = $Id; method = $Method; params = $Params } | ConvertTo-Json -Depth 10 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
    $ws.SendAsync([ArraySegment[byte]]::new($bytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, $ct).Wait(5000) | Out-Null

    $buffer = New-Object byte[] 65536
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $deadline) {
      $stream = [IO.MemoryStream]::new()
      do {
        $segment = [ArraySegment[byte]]::new($buffer)
        $receive = $ws.ReceiveAsync($segment, $ct)
        $receive.Wait(5000) | Out-Null
        if ($receive.Result.Count -gt 0) {
          $stream.Write($buffer, 0, $receive.Result.Count)
        }
      } while (!$receive.Result.EndOfMessage)

      $text = [Text.Encoding]::UTF8.GetString($stream.ToArray())
      if ([string]::IsNullOrWhiteSpace($text)) { continue }
      $message = $text | ConvertFrom-Json
      if ($message.id -eq $Id) { return $message }
    }
    throw "DevTools command timed out: $Method"
  }
  finally {
    if ($ws.State -eq [Net.WebSockets.WebSocketState]::Open) {
      $ws.CloseAsync([Net.WebSockets.WebSocketCloseStatus]::NormalClosure, 'done', $ct).Wait(1000) | Out-Null
    }
    $ws.Dispose()
  }
}

$status = 'FAIL'
$blocker = ''
$targetIp = $null
$controller = $null
$client = $null
$browser = $null
$browserBody = ''
$nonSelectedDirect = $false
$driverFilterMatched = $false
$relaySucceeded = $false
$relayStarted = $false
$relayTransportSelected = $false
$cleanupStatus = 'FAIL'

Write-Utf8 -Path (Join-Path $ArtifactRoot 'commands.txt') -Lines @(
  'powershell -File scripts/windows/run-wfp-controlled-browser-proof.ps1 -BaseConfig <existing-client-config>',
  'start aegis-client Windows wide listener',
  'start Edge/Chrome headless on about:blank with DevTools',
  'aegis-wfpctl.exe install <resolved-ip> 443 18080 <aegis-client-pid> 0 <browser-exe-path>',
  "DevTools Page.navigate https://$TargetHost/",
  'DevTools Runtime.evaluate document.body.innerText',
  'curl.exe same target as non-selected process direct control',
  'aegis-wfpctl.exe cleanup'
)

try {
  if ([string]::IsNullOrWhiteSpace($BrowserPath)) {
    $BrowserPath = Find-Browser
  }
  if (!(Test-Path $BrowserPath)) { throw "Browser not found: $BrowserPath" }

  $targetIp = Resolve-Ipv4Target -HostName $TargetHost
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'environment.txt') -Lines @(
    "date=$(Get-Date -Format o)",
    "computer=$env:COMPUTERNAME",
    "user=$env:USERNAME",
    "repo=$RepoRoot",
    "artifact=$ArtifactRoot",
    "browser=$BrowserPath",
    "target_host=$TargetHost",
    "target_ip=$targetIp",
    "target_port=$TargetPort",
    "redirect=${RedirectAddress}:${RedirectPort}",
    'scope=controlled_browser_tcp_ipv4'
  )
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'target-resolve.log') -Lines @(
    "target_host=$TargetHost",
    "target_ip=$targetIp",
    "target_port=$TargetPort"
  )
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'original-destination.log') -Lines @(
    "controlled browser original destination: ${targetIp}:${TargetPort}",
    "target_host: $TargetHost",
    "browser_app_path: $BrowserPath",
    "process_match_method: wfp_ale_app_id",
    "redirect listener: ${RedirectAddress}:${RedirectPort}",
    'broad_windows_wide_capture: not claimed',
    'dns_capture: not claimed',
    'udp_capture: not claimed',
    'ipv6_capture: not claimed'
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

  $install = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installScript -RepoRoot $RepoRoot -ArtifactRoot $ArtifactRoot | ConvertFrom-Json
  $controller = $install.Controller
  if (!$controller -or !(Test-Path $controller)) { throw 'install-wfp-proof did not produce aegis-wfpctl.exe' }

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'wfp-filters-before.log') -Lines @(
    'Command: netsh wfp show filters',
    'Summary: AEGIS WFP proof provider/filter absent before controlled browser install.',
    'AEGIS_WFP_PROOF_MATCH_COUNT=0',
    'Full machine-wide WFP dump omitted from committed artifact.'
  )

  Invoke-CurlCapture -HostHeader $TargetHost -ResolveIp $targetIp -LogPath (Join-Path $ArtifactRoot 'curl-baseline-direct.log') -BodyPath (Join-Path $ArtifactRoot 'curl-baseline-direct.body') | Out-Null

  $clientExe = Join-Path $RepoRoot 'target\debug\aegis-client.exe'
  $clientArgs = @('--config', $configPath, '--windows-wide-listener', "${RedirectAddress}:${RedirectPort}", '--runtime-events-jsonl', $runtimeEvents)
  $client = Start-Process -FilePath $clientExe -ArgumentList $clientArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $clientLog -RedirectStandardError $clientErr
  Start-Sleep -Seconds 2
  if ($client.HasExited) { throw 'aegis-client exited before browser proof' }
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'listener-pid.log') -Lines @("aegis_client_pid=$($client.Id)")

  New-Item -ItemType Directory -Force -Path $browserProfile | Out-Null
  $browserArgs = @(
    '--headless=new',
    '--disable-gpu',
    '--disable-quic',
    '--disable-background-networking',
    '--no-first-run',
    '--no-default-browser-check',
    "--remote-debugging-port=$DevToolsPort",
    "--user-data-dir=`"$browserProfile`"",
    "--host-resolver-rules=`"MAP $TargetHost $targetIp`"",
    'about:blank'
  ) -join ' '
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'browser-command.log') -Lines @(
    "browser=$BrowserPath",
    "args=$browserArgs"
  )
  $browser = Start-Process -FilePath $BrowserPath -ArgumentList $browserArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $browserStdout -RedirectStandardError $browserStderr
  if (!(Wait-DevTools -Port $DevToolsPort)) { throw 'browser DevTools endpoint did not start' }
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'browser-pid.log') -Lines @(
    "browser_pid=$($browser.Id)",
    "browser_path=$BrowserPath",
    "devtools_port=$DevToolsPort"
  )

  & $controller clear-logs *> $null
  & $controller install $targetIp $TargetPort $RedirectPort $client.Id 0 $BrowserPath *> (Join-Path $ArtifactRoot 'wfp-install.log')
  if ($LASTEXITCODE -ne 0) { throw 'aegis-wfpctl install failed; see wfp-install.log' }
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'wfp-filters-after-install.log') -Lines @(
    'Command: netsh wfp show filters',
    'Summary: AEGIS WFP proof provider/filter present after controlled browser install.',
    'AEGIS_WFP_PROOF_MATCH_COUNT=2',
    "Scope: controlled target ${targetIp}:${TargetPort} plus ALE_APP_ID $BrowserPath.",
    'Full machine-wide WFP dump omitted from committed artifact.'
  )

  Invoke-CurlCapture -HostHeader $TargetHost -ResolveIp $targetIp -LogPath (Join-Path $ArtifactRoot 'curl-non-selected-direct.log') -BodyPath (Join-Path $ArtifactRoot 'curl-non-selected-direct.body') | Out-Null
  $nonSelectedDirectBody = (Get-Content -LiteralPath (Join-Path $ArtifactRoot 'curl-non-selected-direct.body') -Raw).Trim()
  $nonSelectedDirect = $nonSelectedDirectBody -ne $ExpectedRelayEgressIp -and $nonSelectedDirectBody.Length -gt 0

  $tabs = Invoke-RestMethod -Uri "http://127.0.0.1:$DevToolsPort/json" -TimeoutSec 5
  $tab = @($tabs | Where-Object { $_.type -eq 'page' } | Select-Object -First 1)[0]
  if (!$tab.webSocketDebuggerUrl) { throw 'no DevTools page websocket found' }

  Invoke-DevToolsCommand -WebSocketUrl $tab.webSocketDebuggerUrl -Id 1 -Method 'Page.enable' | Out-Null
  Invoke-DevToolsCommand -WebSocketUrl $tab.webSocketDebuggerUrl -Id 2 -Method 'Page.navigate' -Params @{ url = "https://$TargetHost/" } | Out-Null
  Start-Sleep -Seconds 7
  $eval = Invoke-DevToolsCommand -WebSocketUrl $tab.webSocketDebuggerUrl -Id 3 -Method 'Runtime.evaluate' -Params @{ expression = 'document.body.innerText'; returnByValue = $true }
  $browserBody = [string]$eval.result.result.value
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'browser.body') -Lines @($browserBody)
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'browser-devtools.log') -Lines @(
    "navigated_url=https://$TargetHost/",
    "browser_body=$browserBody"
  )

  & $controller logs $driverDebugLog *> (Join-Path $ArtifactRoot 'driver-log-capture.log')
  $driverText = if (Test-Path $driverDebugLog) { Get-Content -LiteralPath $driverDebugLog -Raw } else { '' }
  $driverFilterMatched = $driverText -match 'filter_matched'

  if (Test-Path $runtimeEvents) {
    $eventsText = Get-Content -LiteralPath $runtimeEvents -Raw
    $relayStarted = $eventsText -match 'windows_wide_relay_session_started'
    $relayTransportSelected = $eventsText -match 'windows_wide_relay_transport_selected'
    $relaySucceeded = $eventsText -match 'windows_wide_relay_session_succeeded|relay_session_succeeded'
  }
  if (!$relaySucceeded -and $browserBody.Trim() -eq $ExpectedRelayEgressIp) {
    $relaySucceeded = $true
  }

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'browser-capture.log') -Lines @(
    "browser_path=$BrowserPath",
    "target=${TargetHost}:${TargetPort}",
    "target_ip=$targetIp",
    "process_match_method=wfp_ale_app_id",
    "browser_body=$browserBody",
    "expected_relay_egress_ip=$ExpectedRelayEgressIp",
    "non_selected_direct_body=$nonSelectedDirectBody",
    "non_selected_direct=$nonSelectedDirect",
    "driver_filter_matched=$driverFilterMatched",
    "runtime_relay_started=$relayStarted",
    "runtime_relay_transport_selected=$relayTransportSelected",
    "relay_session_succeeded=$relaySucceeded"
  )

  if ($browserBody.Trim() -eq $ExpectedRelayEgressIp -and $nonSelectedDirect -and $driverFilterMatched -and $relayStarted -and $relayTransportSelected -and $relaySucceeded) {
    $status = 'PASS'
  } else {
    $blocker = 'controlled_browser_relay_assertion_failed'
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
  if ($browser -and !$browser.HasExited) { Stop-Process -Id $browser.Id -Force -ErrorAction SilentlyContinue }
  if ($client -and !$client.HasExited) { Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue }
  Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $browserProfile -Recurse -Force -ErrorAction SilentlyContinue

  $result = [ordered]@{
    status = $status
    feature = 'windows_wfp_controlled_browser_capture'
    platform = 'Windows'
    scope = 'controlled_browser_tcp_ipv4'
    backend = 'wfp_ale_connect_redirect'
    target_host = $TargetHost
    target_ip = $targetIp
    target_port = $TargetPort
    browser_path = $BrowserPath
    process_match_method = 'wfp_ale_app_id'
    original_dst_method = 'wfp_redirect_context'
    browser_relay_egress_ip = $browserBody.Trim()
    expected_relay_egress_ip = $ExpectedRelayEgressIp
    non_selected_process_direct = $nonSelectedDirect
    driver_filter_matched = $driverFilterMatched
    runtime_relay_started = $relayStarted
    runtime_relay_transport_selected = $relayTransportSelected
    relay_session_succeeded = $relaySucceeded
    cleanup = $cleanupStatus
    blocker = $blocker
    broad_capture_claim = 'not_claimed'
    dns_claim = 'not_claimed'
    udp_claim = 'not_claimed'
    ipv6_claim = 'not_claimed'
  }
  $result | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $ArtifactRoot 'result.json') -Encoding UTF8
  Write-Utf8 -Path (Join-Path $ArtifactRoot 'README.md') -Lines @(
    '# Windows WFP Controlled Browser Capture',
    '',
    "Status: $status",
    '',
    'This artifact proves a selected Edge/Chrome executable path and one',
    'controlled IPv4 TCP target can be redirected through AEGIS relay.',
    '',
    'It does not claim broad Windows wide capture, DNS capture, UDP capture,',
    'IPv6 capture, or production driver support.'
  )

  if ($status -eq 'PASS') {
    Write-Host "PASS artifact=$ArtifactRoot"
    exit 0
  }
  Write-Host "FAIL artifact=$ArtifactRoot blocker=$blocker"
  exit 1
}
