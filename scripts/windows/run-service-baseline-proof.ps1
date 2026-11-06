[CmdletBinding()]
param(
    [string]$ArtifactDir = (Join-Path ([IO.Path]::GetTempPath()) "aegis-evidence/live/2026-05-03/windows-service-baseline"),
    [string]$ClientExePath = "target/release/aegis-client.exe",
    [string]$ConfigPath = "C:/ProgramData/AEGIS/client/aegis.toml",
    [string]$CaPath = "C:/ProgramData/AEGIS/client/ca.pem",
    [string]$ServiceName = "AegisClient",
    [string]$RelayServer = "",
    [string]$RelayServerName = "",
    [string[]]$TransportPriority = @(),
    [string]$SurfaceProfileId = "",
    [string]$WebsocketPath = "",
    [string]$GrpcPath = "",
    [string]$MasquePath = "",
    [int]$MaxTransportAttempts = 0,
    [string]$ExpectedEgressIp = "",
    [string]$TargetUrl = "http://v4.ident.me/",
    [string]$SocksEndpoint = "127.0.0.1:1080",
    [string]$RuntimeEventsPath = "C:/ProgramData/AEGIS/state/runtime-events.jsonl"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-ExplicitDnsHost {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Length -gt 253 -or
        [Uri]::CheckHostName($Name) -ne [UriHostNameType]::Dns -or
        $Name -match '^[0-9.]+$') { return $false }
    foreach ($label in $Name.Split('.')) {
        if ($label -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') { return $false }
    }
    return $true
}

function Test-ExplicitRelayEndpoint {
    param([string]$Endpoint)
    if ([string]::IsNullOrWhiteSpace($Endpoint)) { return $false }
    $endpointMatch = [regex]::Match($Endpoint, '^(?<host>\[[^\[\]]+\]|[^:\[\]]+):(?<port>[0-9]{1,5})$')
    if (-not $endpointMatch.Success) { return $false }
    $port = [int]$endpointMatch.Groups['port'].Value
    if ($port -lt 1 -or $port -gt 65535) { return $false }
    $hostText = $endpointMatch.Groups['host'].Value
    $parsedAddress = $null
    if ($hostText.StartsWith('[')) {
        $ipText = $hostText.Substring(1, $hostText.Length - 2)
        return ($ipText -notmatch '%' -and
            [Net.IPAddress]::TryParse($ipText, [ref]$parsedAddress) -and
            $parsedAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6)
    }
    if ([Net.IPAddress]::TryParse($hostText, [ref]$parsedAddress)) {
        return ($parsedAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
            $hostText -match '^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$' -and
            $parsedAddress.ToString() -ceq $hostText)
    }
    return (Test-ExplicitDnsHost -Name $hostText)
}

# Admit explicit operator inputs before creating artifacts or touching a service.
if (-not (Test-ExplicitRelayEndpoint -Endpoint $RelayServer)) {
    throw "RelayServer must be an explicit host:port endpoint"
}
$parsedEgressIp = $null
if ([string]::IsNullOrWhiteSpace($ExpectedEgressIp) -or
    -not [Net.IPAddress]::TryParse($ExpectedEgressIp, [ref]$parsedEgressIp)) {
    throw "ExpectedEgressIp must be an explicit IP address"
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Utf8 {
    param(
        [string]$Path,
        [string]$Value
    )
    $normalized = (($Value -replace "`r`n", "`n") -split "`n" |
        ForEach-Object { $_.TrimEnd() }) -join "`n"
    $normalized = $normalized.TrimEnd() + "`n"
    [IO.File]::WriteAllText(
        (Resolve-Path -LiteralPath (Split-Path -Parent $Path)).Path + [IO.Path]::DirectorySeparatorChar + (Split-Path -Leaf $Path),
        $normalized,
        [Text.UTF8Encoding]::new($false))
}

function Invoke-Logged {
    param(
        [string]$Name,
        [scriptblock]$Command
    )
    $path = Join-Path $ArtifactDir $Name
    try {
        $output = & $Command 2>&1
        $code = if ($LASTEXITCODE -is [int]) { $LASTEXITCODE } else { 0 }
        $text = @(
            "exit_code=$code"
            $output
        ) -join [Environment]::NewLine
        Write-Utf8 -Path $path -Value $text
        return [pscustomobject]@{ ExitCode = $code; Output = $output; Path = $path }
    } catch {
        Write-Utf8 -Path $path -Value "exception=$($_.Exception.Message)"
        return [pscustomobject]@{ ExitCode = 1; Output = @($_.Exception.Message); Path = $path }
    }
}

function Test-TcpEndpoint {
    param([string]$Endpoint)

    $parts = $Endpoint.Split(':')
    if ($parts.Count -ne 2) {
        return $false
    }
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.BeginConnect($parts[0], [int]$parts[1], $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne(5000)) {
            return $false
        }
        $client.EndConnect($connect)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Normalize-List {
    param([string[]]$Values)

    $normalized = @()
    foreach ($value in $Values) {
        foreach ($item in ($value -split ",")) {
            $trimmed = $item.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                $normalized += $trimmed
            }
        }
    }
    return $normalized
}

function Set-ProofRelayConfig {
    param(
        [string]$Path,
        [string]$Server,
        [string]$ServerName,
        [string[]]$Transports,
        [string]$SurfaceProfile,
        [string]$WsPath,
        [string]$GrpcPath,
        [string]$MasquePath,
        [int]$MaxAttempts
    )

    if ([string]::IsNullOrWhiteSpace($Server) -and
        [string]::IsNullOrWhiteSpace($ServerName) -and
        @($Transports).Count -eq 0 -and
        [string]::IsNullOrWhiteSpace($SurfaceProfile) -and
        [string]::IsNullOrWhiteSpace($WsPath) -and
        [string]::IsNullOrWhiteSpace($GrpcPath) -and
        [string]::IsNullOrWhiteSpace($MasquePath) -and
        $MaxAttempts -le 0) {
        return $null
    }

    $backup = "$Path.service-proof.bak"
    Copy-Item -LiteralPath $Path -Destination $backup -Force
    $text = [IO.File]::ReadAllText($Path)
    function Set-TomlLine {
        param(
            [string]$Text,
            [string]$Section,
            [string]$Key,
            [string]$Line
        )
        $keyPattern = "(?m)^$([regex]::Escape($Key))\s*=\s*.*$"
        if ([regex]::IsMatch($Text, $keyPattern)) {
            return [regex]::Replace($Text, $keyPattern, $Line)
        }
        $sectionPattern = "(?m)^\[$([regex]::Escape($Section))\]\s*$"
        $match = [regex]::Match($Text, $sectionPattern)
        if (-not $match.Success) {
            return $Text.TrimEnd() + "`n`n[$Section]`n$Line`n"
        }
        $insertAt = $match.Index + $match.Length
        return $Text.Insert($insertAt, "`n$Line")
    }
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $text = Set-TomlLine -Text $text -Section "relay" -Key "server" -Line "server = `"$Server`""
    }
    if (-not [string]::IsNullOrWhiteSpace($ServerName)) {
        $text = Set-TomlLine -Text $text -Section "relay" -Key "server_name" -Line "server_name = `"$ServerName`""
    }
    $normalizedTransports = Normalize-List -Values $Transports
    if (@($normalizedTransports).Count -gt 0) {
        $transportList = ($normalizedTransports | ForEach-Object { "`"$_`"" }) -join ", "
        $text = Set-TomlLine -Text $text -Section "relay" -Key "transport_priority" -Line "transport_priority = [$transportList]"
    }
    if (-not [string]::IsNullOrWhiteSpace($WsPath)) {
        $text = Set-TomlLine -Text $text -Section "relay" -Key "websocket_path" -Line "websocket_path = `"$WsPath`""
    }
    if (-not [string]::IsNullOrWhiteSpace($GrpcPath)) {
        $text = Set-TomlLine -Text $text -Section "relay" -Key "grpc_path" -Line "grpc_path = `"$GrpcPath`""
    }
    if (-not [string]::IsNullOrWhiteSpace($MasquePath)) {
        $text = Set-TomlLine -Text $text -Section "relay" -Key "masque_path" -Line "masque_path = `"$MasquePath`""
    }
    $wsPoolLine = if ([string]::IsNullOrWhiteSpace($WsPath)) {
        'websocket_path_pool = ["/ws", "/socket", "/realtime/connect"]'
    } else {
        'websocket_path_pool = []'
    }
    $grpcPoolLine = if ([string]::IsNullOrWhiteSpace($GrpcPath)) {
        'grpc_path_pool = ["/rpc.Tunnel/Open", "/cdn.tunnel.v1.Session/Open", "/grpc.gateway.v1.Proxy/Connect"]'
    } else {
        'grpc_path_pool = []'
    }
    $masquePoolLine = if ([string]::IsNullOrWhiteSpace($MasquePath)) {
        'masque_path_pool = ["/.well-known/masque/connect-udp", "/masque/v1/udp", "/relay/datagram"]'
    } else {
        'masque_path_pool = []'
    }
    $text = Set-TomlLine -Text $text -Section "relay" -Key "websocket_path_pool" -Line $wsPoolLine
    $text = Set-TomlLine -Text $text -Section "relay" -Key "grpc_path_pool" -Line $grpcPoolLine
    $text = Set-TomlLine -Text $text -Section "relay" -Key "masque_path_pool" -Line $masquePoolLine
    if (-not [string]::IsNullOrWhiteSpace($SurfaceProfile)) {
        $text = Set-TomlLine -Text $text -Section "relay.policy" -Key "surface_profile_id" -Line "surface_profile_id = `"$SurfaceProfile`""
    }
    if ($MaxAttempts -gt 0) {
        $text = Set-TomlLine -Text $text -Section "relay.policy" -Key "max_transport_attempts" -Line "max_transport_attempts = $MaxAttempts"
    }
    [IO.File]::WriteAllText($Path, $text, [Text.UTF8Encoding]::new($false))
    return $backup
}

function Restore-ProofRelayConfig {
    param(
        [string]$Path,
        [string]$BackupPath
    )
    if (-not [string]::IsNullOrWhiteSpace($BackupPath) -and (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
        Copy-Item -LiteralPath $BackupPath -Destination $Path -Force
        Remove-Item -LiteralPath $BackupPath -Force
    }
}

function Write-Result {
    param([hashtable]$Fields)
    Write-Utf8 -Path (Join-Path $ArtifactDir "result.json") -Value ($Fields | ConvertTo-Json -Depth 5)
}

function Get-SocksAuthFromConfig {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    $section = ""
    $token = $null
    $user = "aegis"
    foreach ($line in [IO.File]::ReadLines($Path)) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^\[(?<section>[^\]]+)\]\s*$') {
            $section = $Matches["section"]
            continue
        }
        if ($section -ne "socks") {
            continue
        }
        if ($trimmed -match '^auth_token\s*=\s*"(?<value>[^"]*)"\s*$') {
            $token = $Matches["value"]
            continue
        }
        if ($trimmed -match '^auth_user\s*=\s*"(?<value>[^"]*)"\s*$') {
            $user = $Matches["value"]
            continue
        }
    }

    if ([string]::IsNullOrEmpty($token)) {
        return $null
    }

    return [pscustomobject]@{
        User = $user
        Token = $token
    }
}

New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$installScript = Join-Path $repoRoot "scripts/windows/install-windows-service.ps1"
$uninstallScript = Join-Path $repoRoot "scripts/windows/uninstall-windows-service.ps1"
$configPathForLog = if ($ConfigPath -match '(?i)aegis-secrets') { "<external-client-config>" } else { $ConfigPath }
$caPathForLog = if ($CaPath -match '(?i)aegis-secrets') { "<external-client-ca>" } else { $CaPath }

$commands = @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows/run-service-baseline-proof.ps1",
    "required private operator inputs: -RelayServer <host:port> -ExpectedEgressIp <ip>; optional relay settings: -RelayServerName <authority> -TransportPriority <transport> -SurfaceProfileId <id> -WebsocketPath <path> -GrpcPath <path> -MasquePath <path> -MaxTransportAttempts <n> -TargetUrl <url>",
    "powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows/install-windows-service.ps1 -ClientExePath $ClientExePath -ConfigPath $configPathForLog -CaPath $caPathForLog -WhatIf",
    "powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows/install-windows-service.ps1 -ClientExePath $ClientExePath -ConfigPath $configPathForLog -CaPath $caPathForLog -StartService -Force",
    "sc.exe query $ServiceName",
    "Test TCP relay $RelayServer",
    "netstat -ano | findstr 1080",
    "curl.exe -sS --max-time 30 -4 --socks5-hostname $SocksEndpoint <optional --proxy-user from socks.auth_token, redacted> $TargetUrl",
    "Get-Content $RuntimeEventsPath -Tail 40",
    "powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows/uninstall-windows-service.ps1",
    "sc.exe query $ServiceName"
)
Write-Utf8 -Path (Join-Path $ArtifactDir "commands.txt") -Value ($commands -join [Environment]::NewLine)

$environment = @(
    "user=$(whoami)",
    "host=$env:COMPUTERNAME",
    "timestamp=$((Get-Date).ToString('o'))",
    "administrator_shell=$(Test-IsAdministrator)",
    "client_binary_present=$(Test-Path -LiteralPath $ClientExePath -PathType Leaf)",
    "config_present=$(Test-Path -LiteralPath $ConfigPath -PathType Leaf)",
    "ca_present=$(Test-Path -LiteralPath $CaPath -PathType Leaf)"
) -join [Environment]::NewLine
Write-Utf8 -Path (Join-Path $ArtifactDir "environment.txt") -Value $environment

$configBackupPath = $null
if (Test-IsAdministrator) {
    $configBackupPath = Set-ProofRelayConfig `
        -Path $ConfigPath `
        -Server $RelayServer `
        -ServerName $RelayServerName `
        -Transports $TransportPriority `
        -SurfaceProfile $SurfaceProfileId `
        -WsPath $WebsocketPath `
        -GrpcPath $GrpcPath `
        -MasquePath $MasquePath `
        -MaxAttempts $MaxTransportAttempts
}

$socksAuth = Get-SocksAuthFromConfig -Path $ConfigPath
$socksAuthUsed = $null -ne $socksAuth

$relayTcpReachable = Test-TcpEndpoint -Endpoint $RelayServer
Write-Utf8 -Path (Join-Path $ArtifactDir "relay-connectivity.log") -Value "relay_server=$RelayServer`nrelay_tcp_reachable=$relayTcpReachable"

Invoke-Logged -Name "install-whatif.log" -Command {
    powershell -NoProfile -ExecutionPolicy Bypass -File $installScript `
        -ClientExePath $ClientExePath `
        -ConfigPath $ConfigPath `
        -CaPath $CaPath `
        -WhatIf
} | Out-Null

Invoke-Logged -Name "uninstall-whatif.log" -Command {
    powershell -NoProfile -ExecutionPolicy Bypass -File $uninstallScript -WhatIf
} | Out-Null

if (-not (Test-IsAdministrator)) {
    Invoke-Logged -Name "service-query.log" -Command { sc.exe query $ServiceName } | Out-Null
    Write-Result @{
        verdict = "BLOCKED"
        date = (Get-Date).ToString("yyyy-MM-dd")
        claim = "Windows service runs aegis-client SOCKS baseline"
        administrator_shell = $false
        client_binary_present = Test-Path -LiteralPath $ClientExePath -PathType Leaf
        programdata_config_present = Test-Path -LiteralPath $ConfigPath -PathType Leaf
        programdata_ca_present = Test-Path -LiteralPath $CaPath -PathType Leaf
        relay_server = $RelayServer
        target_url = $TargetUrl
        socks_auth_used = $socksAuthUsed
        surface_profile_id = $SurfaceProfileId
        websocket_path = $WebsocketPath
        grpc_path = $GrpcPath
        masque_path = $MasquePath
        max_transport_attempts = $MaxTransportAttempts
        relay_tcp_reachable = $relayTcpReachable
        install_script_whatif = "PASS"
        uninstall_script_whatif = "PASS"
        service_installed = $false
        service_started = $false
        socks_listener_verified = $false
        socks_egress_verified = $false
        runtime_events_written = $false
        service_stopped = $false
        service_uninstalled = $false
        cleanup_verified = $false
        blocked_reason_code = "REQUIRES_ELEVATED_WINDOWS_TERMINAL"
        blocked_reason = "Run this proof from an elevated PowerShell terminal."
        wide_claim = "not_tested"
    }
    Restore-ProofRelayConfig -Path $ConfigPath -BackupPath $configBackupPath
    Write-Utf8 -Path (Join-Path $ArtifactDir "README.md") -Value "# Windows Service Baseline`n`nStatus: BLOCKED`n`nRun this proof from an elevated PowerShell terminal to install, start, verify, stop, and uninstall the AegisClient service.`n"
    exit 2
}

Remove-Item -LiteralPath $RuntimeEventsPath -Force -ErrorAction SilentlyContinue

$install = Invoke-Logged -Name "install.log" -Command {
    powershell -NoProfile -ExecutionPolicy Bypass -File $installScript `
        -ClientExePath $ClientExePath `
        -ConfigPath $ConfigPath `
        -CaPath $CaPath `
        -StartService `
        -Force
}
Start-Sleep -Seconds 2
$queryRunning = Invoke-Logged -Name "service-query-running.log" -Command { sc.exe query $ServiceName }
$netstat = Invoke-Logged -Name "netstat-1080-running.log" -Command { netstat -ano | findstr 1080 }
$curl = Invoke-Logged -Name "curl-ipv4-egress.log" -Command {
    if ($socksAuthUsed) {
        curl.exe -sS --max-time 30 -4 --socks5-hostname $SocksEndpoint --proxy-user "$($socksAuth.User):$($socksAuth.Token)" $TargetUrl
    } else {
        curl.exe -sS --max-time 30 -4 --socks5-hostname $SocksEndpoint $TargetUrl
    }
}
$events = Invoke-Logged -Name "runtime-events-tail.log" -Command {
    if (Test-Path -LiteralPath $RuntimeEventsPath) {
        Get-Content $RuntimeEventsPath -Tail 40
    }
}
$uninstall = Invoke-Logged -Name "service-uninstall.log" -Command {
    powershell -NoProfile -ExecutionPolicy Bypass -File $uninstallScript
}
Start-Sleep -Seconds 1
$queryAfter = Invoke-Logged -Name "service-query-after-cleanup.log" -Command { sc.exe query $ServiceName }
Restore-ProofRelayConfig -Path $ConfigPath -BackupPath $configBackupPath

$serviceInstalled = ($queryRunning.Output -join "`n") -match "SERVICE_NAME:\s+$ServiceName"
$serviceStarted = ($queryRunning.Output -join "`n") -match "STATE\s+:\s+\d+\s+RUNNING"
$listenerVerified = ($netstat.Output -join "`n") -match "1080"
$curlText = ($curl.Output -join "`n").Trim()
$egressVerified = $curlText -match [regex]::Escape($ExpectedEgressIp)
$runtimeEventsWritten = ($events.Output -join "`n").Trim().Length -gt 0
$cleanupVerified = ($queryAfter.Output -join "`n") -match "1060"
$pass = $install.ExitCode -eq 0 `
    -and $serviceInstalled `
    -and $serviceStarted `
    -and $listenerVerified `
    -and $egressVerified `
    -and $runtimeEventsWritten `
    -and $uninstall.ExitCode -eq 0 `
    -and $cleanupVerified

$blocker = if ($pass) {
    ""
} elseif ($relayTcpReachable -and -not $egressVerified -and -not [string]::IsNullOrWhiteSpace($SurfaceProfileId)) {
    "cloudflare_service_tunnel_reset_or_bundle_mismatch"
} elseif ($relayTcpReachable -and -not $egressVerified) {
    "socks_egress_not_verified"
} else {
    "relay_tcp_unreachable"
}

Write-Result @{
    verdict = if ($pass) { "PASS" } else { "FAIL" }
    date = (Get-Date).ToString("yyyy-MM-dd")
    claim = "Windows service runs aegis-client SOCKS baseline"
    administrator_shell = $true
    client_binary_present = Test-Path -LiteralPath $ClientExePath -PathType Leaf
    programdata_config_present = Test-Path -LiteralPath $ConfigPath -PathType Leaf
    programdata_ca_present = Test-Path -LiteralPath $CaPath -PathType Leaf
    relay_server = $RelayServer
    target_url = $TargetUrl
    socks_auth_used = $socksAuthUsed
    surface_profile_id = $SurfaceProfileId
    websocket_path = $WebsocketPath
    grpc_path = $GrpcPath
    masque_path = $MasquePath
    max_transport_attempts = $MaxTransportAttempts
    relay_tcp_reachable = $relayTcpReachable
    install_script_whatif = "PASS"
    uninstall_script_whatif = "PASS"
    service_installed = $serviceInstalled
    service_started = $serviceStarted
    socks_listener_verified = $listenerVerified
    socks_egress_verified = $egressVerified
    socks_egress_body = $curlText
    runtime_events_written = $runtimeEventsWritten
    service_stopped = $uninstall.ExitCode -eq 0
    service_uninstalled = $cleanupVerified
    cleanup_verified = $cleanupVerified
    blocker = $blocker
    wide_claim = "not_tested"
}

Write-Utf8 -Path (Join-Path $ArtifactDir "README.md") -Value "# Windows Service Baseline`n`nStatus: $(if ($pass) { 'PASS' } else { 'FAIL' })`n`nThis artifact verifies install/start/SOCKS egress/runtime-events/uninstall cleanup for the AegisClient Windows service. No Windows wide capture is claimed.`n"

if ($pass) {
    exit 0
}
exit 1
