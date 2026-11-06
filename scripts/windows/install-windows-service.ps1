[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ClientExePath,
    [string]$ConfigPath,
    [string]$CaPath,
    [string]$InstallRoot = "$env:ProgramFiles\AEGIS",
    [string]$ProgramDataRoot = "$env:ProgramData\AEGIS",
    [string]$ServiceName = "AegisClient",
    [string]$DisplayName = "AEGIS Client",
    [string]$WindowsWideListener = "",
    [ValidateSet("Manual", "Automatic", "Disabled")]
    [string]$StartupType = "Manual",
    [switch]$StartService,
    [switch]$Force
)

# Refuse before resolving paths, reading credentials, changing ACLs or touching services.
throw "Legacy service installer is retired because it cannot establish private configuration ACLs before writing. No installation changes were made. Use aegis-winctl.exe client install --help from a verified external kit, then follow docs/platforms/windows/windows-install-runbook.md with an independent manifest SHA-256, private configuration and a fresh root. Existing installations are not adopted or removed."

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RepoRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-SourceFile {
    param(
        [string]$Path,
        [string]$Description
    )

    if ($WhatIfPreference) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description not found: $Path"
    }
}

function Copy-ItemIfDifferent {
    param(
        [string]$Source,
        [string]$Destination
    )

    $resolvedSource = (Resolve-Path -LiteralPath $Source).Path
    $resolvedDestination = $null
    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        $resolvedDestination = (Resolve-Path -LiteralPath $Destination).Path
    }

    if ($resolvedDestination -and ($resolvedSource -ieq $resolvedDestination)) {
        return
    }

    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Copy-ClientConfigForService {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$InstalledCaPath
    )

    $text = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Source).Path)
    $escapedCaPath = $InstalledCaPath.Replace("\", "/")
    $caLine = "ca_cert = `"$escapedCaPath`""
    $caPattern = '(?m)^ca_cert\s*=\s*.*$'
    if ([regex]::IsMatch($text, $caPattern)) {
        $text = [regex]::Replace($text, $caPattern, $caLine)
    } else {
        $relayPattern = '(?m)^\[relay\]\s*$'
        $match = [regex]::Match($text, $relayPattern)
        if ($match.Success) {
            $text = $text.Insert($match.Index + $match.Length, "`n$caLine")
        } else {
            $text = $text.TrimEnd() + "`n`n[relay]`n$caLine`n"
        }
    }
    [IO.File]::WriteAllText($Destination, $text, [Text.UTF8Encoding]::new($false))
}

function Invoke-Sc {
    param([string[]]$Arguments)

    $output = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe $($Arguments -join ' ') failed with code ${LASTEXITCODE}: $output"
    }
    return $output
}

function Grant-ServiceDirectoryAccess {
    param(
        [string[]]$Paths,
        [string]$Account
    )

    foreach ($path in $Paths) {
        $output = & icacls.exe $path /grant "${Account}:(OI)(CI)M" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "icacls grant failed for ${path} with code ${LASTEXITCODE}: $output"
        }
    }
}

function Convert-StartupType {
    param([string]$Value)

    switch ($Value) {
        "Manual" { return "demand" }
        "Automatic" { return "auto" }
        "Disabled" { return "disabled" }
    }
}

function Convert-CimStartupType {
    param([string]$Value)

    switch ($Value) {
        "Manual" { return "Manual" }
        "Automatic" { return "Automatic" }
        "Disabled" { return "Disabled" }
    }
}

$repoRoot = Resolve-RepoRoot
if ([string]::IsNullOrWhiteSpace($ClientExePath)) {
    $ClientExePath = Join-Path $repoRoot "target\release\aegis-client.exe"
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $repoRoot "aegis.toml"
}
if ([string]::IsNullOrWhiteSpace($CaPath)) {
    $CaPath = Join-Path $repoRoot "ca.pem"
}

$installBinDir = Join-Path $InstallRoot "bin"
$clientDest = Join-Path $installBinDir "aegis-client.exe"
$clientConfigDir = Join-Path $ProgramDataRoot "client"
$configDest = Join-Path $clientConfigDir "aegis.toml"
$caDest = Join-Path $clientConfigDir "ca.pem"
$stateDir = Join-Path $ProgramDataRoot "state"
$logDir = Join-Path $ProgramDataRoot "logs"
$runtimeEventsPath = Join-Path $stateDir "runtime-events.jsonl"
$manifestPath = Join-Path $stateDir "install-manifest.json"

if (-not $WhatIfPreference -and -not (Test-IsAdministrator)) {
    throw "Administrator privileges are required to install the $ServiceName service."
}

Assert-SourceFile -Path $ClientExePath -Description "aegis-client.exe"
Assert-SourceFile -Path $ConfigPath -Description "client config"
Assert-SourceFile -Path $CaPath -Description "client CA"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and -not $Force -and -not $WhatIfPreference) {
    throw "Service $ServiceName already exists. Re-run with -Force to replace the service registration."
}

if ($PSCmdlet.ShouldProcess("Windows service $ServiceName", "install AEGIS client service")) {
    if ($existing -and $Force) {
        if ($existing.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        }
        Invoke-Sc -Arguments @("delete", $ServiceName) | Out-Null
        Start-Sleep -Seconds 1
    }

    New-Item -ItemType Directory -Force -Path $installBinDir, $clientConfigDir, $stateDir, $logDir | Out-Null
    $serviceAccount = "NT AUTHORITY\LocalService"
    Grant-ServiceDirectoryAccess -Paths @($clientConfigDir, $stateDir, $logDir) -Account $serviceAccount
    Copy-ItemIfDifferent -Source $ClientExePath -Destination $clientDest
    Copy-ItemIfDifferent -Source $CaPath -Destination $caDest
    Copy-ClientConfigForService -Source $ConfigPath -Destination $configDest -InstalledCaPath $caDest

    $serviceCommand = "`"$clientDest`" --config `"$configDest`" --runtime-events-jsonl `"$runtimeEventsPath`""
    if (-not [string]::IsNullOrWhiteSpace($WindowsWideListener)) {
        $serviceCommand += " --windows-wide-listener `"$WindowsWideListener`""
    }
    $serviceCommand += " --windows-service"
    $createResult = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
        Name = $ServiceName
        DisplayName = $DisplayName
        PathName = $serviceCommand
        StartMode = Convert-CimStartupType -Value $StartupType
        StartName = $serviceAccount
    }
    if ($createResult.ReturnValue -ne 0) {
        throw "Win32_Service.Create failed with return value $($createResult.ReturnValue)"
    }
    Invoke-Sc -Arguments @(
        "description", $ServiceName,
        "AEGIS client local SOCKS runtime using ProgramData configuration"
    ) | Out-Null

    $manifest = [ordered]@{
        installed_at = (Get-Date).ToUniversalTime().ToString("o")
        service_name = $ServiceName
        display_name = $DisplayName
        account = $serviceAccount
        startup_type = $StartupType
        binary_path = $clientDest
        config_path = $configDest
        ca_path = $caDest
        state_dir = $stateDir
        logs_dir = $logDir
        runtime_events_jsonl = $runtimeEventsPath
        windows_wide_listener = $WindowsWideListener
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path $manifestPath

    if ($StartService) {
        Start-Service -Name $ServiceName
    }
}

Write-Host "AEGIS Windows service install path:"
Write-Host "  Service: $ServiceName"
Write-Host "  Binary:  $clientDest"
Write-Host "  Config:  $configDest"
Write-Host "  CA:      $caDest"
Write-Host "  Events:  $runtimeEventsPath"
Write-Host ""
Write-Host "Verify:"
Write-Host "  sc.exe query $ServiceName"
Write-Host "  netstat -ano | findstr 1080"
Write-Host "  curl.exe -4 --socks5-hostname 127.0.0.1:1080 http://ifconfig.me"
