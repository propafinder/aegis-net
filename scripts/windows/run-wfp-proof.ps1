param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$ArtifactRoot = (Join-Path $RepoRoot 'artifacts\live\2026-05-01\windows-wfp-redirect-live-proof'),
  [string]$OriginalAddress = '127.0.0.2',
  [int]$OriginalPort = 19090,
  [string]$RedirectAddress = '127.0.0.1',
  [int]$RedirectPort = 18080
)

$ErrorActionPreference = 'Continue'

$listenerScript = Join-Path $RepoRoot 'scripts\windows\tcp-proof-listener.ps1'
$installScript = Join-Path $RepoRoot 'scripts\windows\install-wfp-proof.ps1'
$listenerLog = Join-Path $ArtifactRoot 'listener.log'
$originalLog = Join-Path $ArtifactRoot 'original-target.log'
$destinationLog = Join-Path $ArtifactRoot 'original-destination.log'
$commandsLog = Join-Path $ArtifactRoot 'commands.txt'
$installLog = Join-Path $ArtifactRoot 'driver-install.log'
$driverDebugLog = Join-Path $ArtifactRoot 'driver-debug.log'
$cleanupLog = Join-Path $ArtifactRoot 'wfp-cleanup.log'

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null

function Start-ProofListener {
  param([string]$Name, [string]$BindAddress, [int]$Port, [string]$LogPath, [string]$Body)
  Start-Process -FilePath powershell.exe -ArgumentList @(
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    $listenerScript,
    '-BindAddress',
    $BindAddress,
    '-Port',
    $Port,
    '-LogPath',
    $LogPath,
    '-Body',
    $Body
  ) -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $ArtifactRoot "$Name.stdout.log") `
    -RedirectStandardError (Join-Path $ArtifactRoot "$Name.stderr.log")
}

function Invoke-CurlCapture {
  param([string]$Url, [string]$LogPath, [string]$BodyPath)
  & curl.exe -v --noproxy '*' --max-time 5 $Url 1> $BodyPath 2> $LogPath
  $code = $LASTEXITCODE
  "curl exit=$code" | Add-Content -Path $LogPath
  return $code
}

$processes = @()
$status = 'FAIL'
$blocker = ''

Set-Content -Path $commandsLog -Value @(
  "powershell -File scripts/windows/install-wfp-proof.ps1",
  "netsh wfp show filters file=$ArtifactRoot\wfp-filters-before.log",
  "curl.exe --noproxy '*' http://${OriginalAddress}:${OriginalPort}/",
  "aegis-wfpctl.exe install $OriginalAddress $OriginalPort $RedirectPort <listener-pid>",
  "aegis-wfpctl.exe clear-logs",
  "netsh wfp show filters file=$ArtifactRoot\wfp-filters-after-install.log",
  "curl.exe --noproxy '*' http://${OriginalAddress}:${OriginalPort}/",
  "aegis-wfpctl.exe logs $driverDebugLog",
  "aegis-wfpctl.exe cleanup",
  "netsh wfp show filters file=$ArtifactRoot\wfp-filters-after-cleanup.log",
  "curl.exe --noproxy '*' http://${OriginalAddress}:${OriginalPort}/"
)

try {
  $install = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installScript -RepoRoot $RepoRoot -ArtifactRoot $ArtifactRoot | ConvertFrom-Json
  $controller = $install.Controller
  if (!$controller -or !(Test-Path $controller)) {
    throw "install-wfp-proof did not produce aegis-wfpctl.exe"
  }

  netsh wfp show filters file="$ArtifactRoot\wfp-filters-before.log" | Out-Null

  $original = Start-ProofListener -Name 'aegis-original-listener' -BindAddress $OriginalAddress -Port $OriginalPort -LogPath $originalLog -Body 'ORIGINAL_TARGET'
  $redirect = Start-ProofListener -Name 'aegis-redirect-listener' -BindAddress $RedirectAddress -Port $RedirectPort -LogPath $listenerLog -Body 'AEGIS_WFP_LISTENER'
  $processes += $original
  $processes += $redirect
  Start-Sleep -Seconds 1

  Set-Content -Path $destinationLog -Value @(
    "controlled original destination: ${OriginalAddress}:${OriginalPort}",
    "redirect destination: ${RedirectAddress}:${RedirectPort}",
    "redirect listener pid: $($redirect.Id)",
    "protocol: TCP IPv4",
    "excluded relay server: 198.51.100.22",
    "loop prevention: filter only matches controlled remote_ip/remote_port; driver permits loopback and relay destinations"
  )

  Invoke-CurlCapture -Url "http://${OriginalAddress}:${OriginalPort}/" -LogPath (Join-Path $ArtifactRoot 'curl-before.log') -BodyPath (Join-Path $ArtifactRoot 'curl-before.body') | Out-Null

  & $controller cleanup *>> $installLog
  & $controller install $OriginalAddress $OriginalPort $RedirectPort $redirect.Id *>> $installLog
  "aegis-wfpctl install exit=$LASTEXITCODE" | Add-Content -Path $installLog
  & $controller clear-logs *>> $installLog
  "aegis-wfpctl clear-logs exit=$LASTEXITCODE" | Add-Content -Path $installLog

  netsh wfp show filters file="$ArtifactRoot\wfp-filters-after-install.log" | Out-Null

  Invoke-CurlCapture -Url "http://${OriginalAddress}:${OriginalPort}/" -LogPath (Join-Path $ArtifactRoot 'curl-redirected.log') -BodyPath (Join-Path $ArtifactRoot 'curl-redirected.body') | Out-Null
  & $controller logs $driverDebugLog *>> $installLog
  "aegis-wfpctl logs exit=$LASTEXITCODE" | Add-Content -Path $installLog

  & $controller cleanup *>> $cleanupLog
  "aegis-wfpctl cleanup exit=$LASTEXITCODE" | Add-Content -Path $cleanupLog
  netsh wfp show filters file="$ArtifactRoot\wfp-filters-after-cleanup.log" | Out-Null

  Invoke-CurlCapture -Url "http://${OriginalAddress}:${OriginalPort}/" -LogPath (Join-Path $ArtifactRoot 'curl-after-cleanup.log') -BodyPath (Join-Path $ArtifactRoot 'curl-after-cleanup.body') | Out-Null

  $beforeBody = Get-Content (Join-Path $ArtifactRoot 'curl-before.body') -Raw -ErrorAction SilentlyContinue
  $redirectBody = Get-Content (Join-Path $ArtifactRoot 'curl-redirected.body') -Raw -ErrorAction SilentlyContinue
  $afterBody = Get-Content (Join-Path $ArtifactRoot 'curl-after-cleanup.body') -Raw -ErrorAction SilentlyContinue
  $listenerText = Get-Content $listenerLog -Raw -ErrorAction SilentlyContinue

  if ($beforeBody -match 'ORIGINAL_TARGET' -and
      $redirectBody -match 'AEGIS_WFP_LISTENER' -and
      $afterBody -match 'ORIGINAL_TARGET' -and
      $listenerText -match 'accepted') {
    $status = 'PASS'
  } else {
    $blocker = 'AEGIS WFP callout/filter installed, but redirected curl did not land on 127.0.0.1:18080.'
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
  foreach ($process in $processes) {
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
  }
}

$result = [ordered]@{
  status = $status
  date = '2026-05-01'
  artifact = $ArtifactRoot
  driver = 'drivers/windows/aegis-wfp'
  controller = 'tools/windows/aegis-wfpctl'
  controlled_target = "${OriginalAddress}:${OriginalPort}"
  redirect_target = "${RedirectAddress}:${RedirectPort}"
  blocker = $blocker
  driver_debug_log = $driverDebugLog
  safe_to_continue_to_aegis_integration = ($status -eq 'PASS')
}
$result | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $ArtifactRoot 'result.json') -Encoding UTF8

if ($status -eq 'PASS') {
  "PASS"
} else {
  "FAIL: $blocker"
}
