[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ServiceName = "AegisClient",
    [string]$InstallRoot = "$env:ProgramFiles\AEGIS",
    [string]$ProgramDataRoot = "$env:ProgramData\AEGIS",
    [switch]$Purge
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Sc {
    param([string[]]$Arguments)

    $output = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe $($Arguments -join ' ') failed with code ${LASTEXITCODE}: $output"
    }
    return $output
}

if (-not $WhatIfPreference -and -not (Test-IsAdministrator)) {
    throw "Administrator privileges are required to uninstall the $ServiceName service."
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($PSCmdlet.ShouldProcess("Windows service $ServiceName", "stop and delete")) {
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        }
        Invoke-Sc -Arguments @("delete", $ServiceName) | Out-Null
    }
} else {
    Write-Host "Service $ServiceName is not installed."
}

if ($Purge) {
    foreach ($path in @($InstallRoot, $ProgramDataRoot)) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }
        if ($PSCmdlet.ShouldProcess($path, "remove AEGIS-owned directory")) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Recurse -Force
            }
        }
    }
} else {
    Write-Host "Preserved installed files, config, logs, and state."
    Write-Host "Re-run with -Purge to remove:"
    Write-Host "  $InstallRoot"
    Write-Host "  $ProgramDataRoot"
}
