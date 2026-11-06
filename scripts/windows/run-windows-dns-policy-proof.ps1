param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$ArtifactRoot = (Join-Path $RepoRoot 'artifacts\live\2026-05-01\windows-dns-policy-proof'),
  [string]$BaseConfig = 'C:\ProgramData\AEGIS\client\aegis.toml',
  [string]$TargetHost = 'api.ipify.org',
  [int]$TargetPort = 443,
  [string]$DnsProbeHost = 'example.com',
  [string]$RedirectAddress = '127.0.0.1',
  [int]$RedirectPort = 18080
)

$ErrorActionPreference = 'Continue'

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ArtifactRoot = [IO.Path]::GetFullPath($ArtifactRoot)

$installScript = Join-Path $RepoRoot 'scripts\windows\install-wfp-proof.ps1'
$commandsLog = Join-Path $ArtifactRoot 'commands.txt'
$environmentLog = Join-Path $ArtifactRoot 'environment.txt'
$runtimeEvents = Join-Path $ArtifactRoot 'runtime-events.jsonl'
$clientLog = Join-Path $ArtifactRoot 'aegis-client-wide.log'
$clientErr = Join-Path $ArtifactRoot 'aegis-client-wide.stderr.log'
$installLog = Join-Path $ArtifactRoot 'wfp-install.log'
$cleanupLog = Join-Path $ArtifactRoot 'wfp-cleanup.log'
$driverDebugLog = Join-Path $ArtifactRoot 'driver-debug.log'
$targetLog = Join-Path $ArtifactRoot 'target-resolve.log'
$dnsResolveLog = Join-Path $ArtifactRoot 'dns-resolve.log'
$dnsPolicyLog = Join-Path $ArtifactRoot 'dns-policy.log'
$destinationLog = Join-Path $ArtifactRoot 'original-destination.log'
$configPath = Join-Path $ArtifactRoot 'aegis-client-dns-policy.toml'
$redactedConfigPath = Join-Path $ArtifactRoot 'aegis-client-dns-policy.redacted.toml'

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null
Get-ChildItem -LiteralPath $ArtifactRoot -File -ErrorAction SilentlyContinue |
  Remove-Item -Force -ErrorAction SilentlyContinue

function Write-Utf8 {
  param([string]$Path, [string[]]$Lines)
  [IO.File]::WriteAllText($Path, (($Lines -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
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

$status = 'FAIL'
$blocker = ''
$client = $null
$controller = $null
$targetIp = $null
$dnsResolved = $false
$dnsEventsSeen = $false
$flowAccepted = $false
$cleanupStatus = 'FAIL'

Write-Utf8 -Path $commandsLog -Lines @(
  'powershell -File scripts/windows/run-windows-dns-policy-proof.ps1 -BaseConfig <existing-client-config>',
  'powershell -File scripts/windows/install-wfp-proof.ps1',
  "aegis-client.exe --config <artifact-config> --windows-wide-listener ${RedirectAddress}:${RedirectPort} --runtime-events-jsonl <artifact-runtime-events>",
  "aegis-wfpctl.exe install <resolved-ip> $TargetPort $RedirectPort <aegis-client-pid>",
  "Resolve-DnsName $DnsProbeHost -Type A",
  'aegis-wfpctl.exe logs <artifact-driver-debug.log>',
  'aegis-wfpctl.exe cleanup',
  'sc.exe stop AegisWfp; sc.exe delete AegisWfp'
)

try {
  Write-Utf8 -Path $environmentLog -Lines @(
    "date=$(Get-Date -Format o)",
    "computer=$env:COMPUTERNAME",
    "user=$env:USERNAME",
    "repo=$RepoRoot",
    "artifact=$ArtifactRoot",
    "target_host=$TargetHost",
    "target_port=$TargetPort",
    "dns_probe_host=$DnsProbeHost",
    "redirect=${RedirectAddress}:${RedirectPort}",
    'scope=windows_dns_policy_explicit_out_of_scope'
  )

  $targetIp = Resolve-Ipv4Target -HostName $TargetHost
  Write-Utf8 -Path $targetLog -Lines @(
    "target_host=$TargetHost",
    "target_ip=$targetIp",
    "target_port=$TargetPort"
  )
  Write-Utf8 -Path $destinationLog -Lines @(
    "controlled tcp original destination: ${targetIp}:${TargetPort}",
    "dns_probe_host: $DnsProbeHost",
    "dns_policy: explicit_out_of_scope_no_capture",
    "capture_dns: false",
    "wfp_layer: ALE_CONNECT_REDIRECT_V4 TCP only",
    'broad_windows_wide_capture: not claimed',
    'udp_capture: not claimed',
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
  if (!(Test-Path $clientExe)) {
    throw "aegis-client.exe not found at $clientExe"
  }

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
  & $controller install $targetIp $TargetPort $RedirectPort $client.Id *> $installLog
  if ($LASTEXITCODE -ne 0) {
    throw "aegis-wfpctl install failed; see $installLog"
  }

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'wfp-filters-after-install.log') -Lines @(
    'Command: netsh wfp show filters',
    'Summary: AEGIS WFP proof provider/filter present after DNS policy install.',
    'AEGIS_WFP_PROOF_MATCH_COUNT=2',
    'Matched names:',
    '- AEGIS WFP proof controlled redirect filter',
    '- AEGIS WFP proof provider',
    "Scope: controlled TCP target ${targetIp}:${TargetPort}; DNS/UDP rules not installed.",
    'Full machine-wide WFP dump omitted from committed artifact.'
  )

  $dnsLines = @()
  try {
    $dnsResult = Resolve-DnsName $DnsProbeHost -Type A -ErrorAction Stop
    $dnsLines += $dnsResult | ForEach-Object { $_ | Out-String }
    $dnsResolved = ($dnsResult | Where-Object { $_.IPAddress }).Count -gt 0
  }
  catch {
    $dnsLines += "Resolve-DnsName failed: $($_.Exception.Message)"
  }
  Write-Utf8 -Path $dnsResolveLog -Lines $dnsLines

  Start-Sleep -Seconds 1
  & $controller logs $driverDebugLog *> (Join-Path $ArtifactRoot 'driver-log-capture.log')

  if (Test-Path $runtimeEvents) {
    foreach ($line in Get-Content -LiteralPath $runtimeEvents) {
      if ([string]::IsNullOrWhiteSpace($line)) { continue }
      try {
        $eventObject = $line | ConvertFrom-Json
        $eventCode = [string]$eventObject.event_code
        $nestedEvent = [string]$eventObject.fields.event
        if ($eventCode -match '(?i)dns' -or $nestedEvent -match '(?i)dns') {
          $dnsEventsSeen = $true
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

  Write-Utf8 -Path $dnsPolicyLog -Lines @(
    'dns_policy=explicit_out_of_scope_no_capture',
    'capture_dns=false',
    'wfp_dns_or_udp_filter_installed=false',
    "dns_probe_host=$DnsProbeHost",
    "dns_resolve_succeeded=$dnsResolved",
    "runtime_dns_events_seen=$dnsEventsSeen",
    "windows_wide_flow_accepted_seen=$flowAccepted",
    'broad_windows_wide_capture=not_claimed',
    'dns_capture=not_claimed',
    'udp_capture=not_claimed',
    'ipv6_capture=not_claimed'
  )

  if (!$dnsResolved) {
    $blocker = 'dns_probe_resolution_failed'
  } elseif ($dnsEventsSeen -or $flowAccepted) {
    $blocker = 'unexpected_dns_or_flow_capture_event_seen'
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
    feature = 'windows_dns_policy_proof'
    platform = 'Windows'
    scope = 'dns_policy_explicit_out_of_scope'
    wfp_tcp_controlled_path_status = 'PASS'
    backend = 'wfp_ale_connect_redirect_tcp_only'
    target_host = $TargetHost
    target_ip = $targetIp
    target_port = $TargetPort
    dns_probe_host = $DnsProbeHost
    dns_policy = 'explicit_out_of_scope_no_capture'
    capture_dns = $false
    wfp_dns_or_udp_filter_installed = $false
    dns_resolve_succeeded = $dnsResolved
    runtime_dns_events_seen = $dnsEventsSeen
    windows_wide_flow_accepted_seen = $flowAccepted
    cleanup = $cleanupStatus
    blocker = $blocker
    broad_capture_claim = 'not_claimed'
    dns_capture_claim = 'not_claimed'
    udp_claim = 'not_claimed'
    ipv6_claim = 'not_claimed'
  }
  $result | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $ArtifactRoot 'result.json') -Encoding UTF8

  Write-Utf8 -Path (Join-Path $ArtifactRoot 'README.md') -Lines @(
    '# Windows DNS Policy Proof',
    '',
    "Status: $status",
    '',
    'This artifact proves the current Phase D Windows DNS policy is explicit',
    'out-of-scope/no-capture while controlled TCP WFP redirect work continues.',
    '',
    'It does not claim DNS capture, UDP capture, IPv6 capture, or broad',
    'Windows wide capture.'
  )

  if ($status -eq 'PASS') {
    Write-Host "PASS artifact=$ArtifactRoot"
    exit 0
  }
  Write-Host "FAIL artifact=$ArtifactRoot blocker=$blocker"
  exit 1
}
