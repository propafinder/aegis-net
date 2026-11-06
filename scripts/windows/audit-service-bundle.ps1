[CmdletBinding()]
param(
    [string]$ArtifactDir = (Join-Path ([IO.Path]::GetTempPath()) "aegis-evidence/live/2026-05-03/windows-service-bundle-audit"),
    [string]$ConfigPath = "C:/ProgramData/AEGIS/client/aegis.toml",
    [string]$CaPath = "C:/ProgramData/AEGIS/client/ca.pem",
    [string]$ExpectedFront = "",
    [string]$ExpectedServerName = "",
    [string]$ExpectedOrigin = ""
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
if (-not (Test-ExplicitRelayEndpoint -Endpoint $ExpectedFront)) {
    throw "ExpectedFront must be an explicit host:port endpoint"
}
if (-not (Test-ExplicitRelayEndpoint -Endpoint $ExpectedOrigin)) {
    throw "ExpectedOrigin must be an explicit host:port endpoint"
}
if (-not (Test-ExplicitDnsHost -Name $ExpectedServerName)) {
    throw "ExpectedServerName must be an explicit TLS server name"
}

function Write-Utf8 {
    param(
        [string]$Path,
        [string]$Value
    )
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $normalized = ($Value -replace "`r`n", "`n").TrimEnd() + "`n"
    [IO.File]::WriteAllText($Path, $normalized, [Text.UTF8Encoding]::new($false))
}

function Get-TomlSection {
    param(
        [string]$Text,
        [string]$Section
    )
    $pattern = "(?ms)^\[$([regex]::Escape($Section))\]\s*(.*?)(?=^\[|\z)"
    $match = [regex]::Match($Text, $pattern)
    if (-not $match.Success) {
        return ""
    }
    return $match.Groups[1].Value
}

function Get-TomlString {
    param(
        [string]$SectionText,
        [string]$Key
    )
    $pattern = "(?m)^\s*$([regex]::Escape($Key))\s*=\s*`"([^`"]*)`"\s*$"
    $match = [regex]::Match($SectionText, $pattern)
    if (-not $match.Success) {
        return ""
    }
    return $match.Groups[1].Value
}

function Get-Sha256Prefix {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ""
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString("x2") }) -join "").Substring(0, 16)
    } finally {
        $sha.Dispose()
    }
}

function Get-FileSha256 {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ""
    }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

$commands = @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows/audit-service-bundle.ps1",
    "ConfigPath=$ConfigPath",
    "CaPath=$CaPath",
    "ExpectedFront=$ExpectedFront",
    "ExpectedServerName=$ExpectedServerName",
    "ExpectedOrigin=$ExpectedOrigin"
) -join [Environment]::NewLine
Write-Utf8 -Path (Join-Path $ArtifactDir "commands.txt") -Value $commands

$configPresent = Test-Path -LiteralPath $ConfigPath -PathType Leaf
$caPresent = Test-Path -LiteralPath $CaPath -PathType Leaf
$configText = if ($configPresent) { [IO.File]::ReadAllText($ConfigPath) } else { "" }
$relaySection = Get-TomlSection -Text $configText -Section "relay"
$installedServer = Get-TomlString -SectionText $relaySection -Key "server"
$installedServerName = Get-TomlString -SectionText $relaySection -Key "server_name"
$authToken = Get-TomlString -SectionText $relaySection -Key "auth_token"
$authTokenPrefix = Get-Sha256Prefix -Value $authToken
$caSha256 = Get-FileSha256 -Path $CaPath

$cloudflareBundleConfigPresent = (
    $installedServer -ieq $ExpectedFront -and
    $installedServerName -ieq $ExpectedServerName
)
$bundleMismatch = -not $cloudflareBundleConfigPresent

$redactedConfig = if ($configPresent) {
    (($configText -split "`r?`n") | ForEach-Object {
        if ($_ -match '^\s*auth_token\s*=') {
            'auth_token = "<redacted sha256_prefix={0}>"' -f $authTokenPrefix
        } else {
            $_
        }
    }) -join "`n"
} else {
    "config_missing"
}
Write-Utf8 -Path (Join-Path $ArtifactDir "config-redacted.txt") -Value $redactedConfig

$environment = @(
    "user=$(whoami)",
    "host=$env:COMPUTERNAME",
    "timestamp=$((Get-Date).ToUniversalTime().ToString('o'))",
    "config_present=$configPresent",
    "ca_present=$caPresent"
) -join [Environment]::NewLine
Write-Utf8 -Path (Join-Path $ArtifactDir "environment.txt") -Value $environment

$result = [ordered]@{
    status = if ($configPresent -and $caPresent) { "PASS" } else { "FAIL" }
    feature = "windows_service_bundle_audit"
    config_path = $ConfigPath
    ca_path = $CaPath
    expected_cloudflare_front = $ExpectedFront
    expected_cloudflare_origin = $ExpectedOrigin
    expected_server_name = $ExpectedServerName
    installed_server = $installedServer
    installed_server_name = $installedServerName
    relay_auth_token_sha256_prefix = $authTokenPrefix
    ca_sha256 = $caSha256
    cloudflare_bundle_config_present = $cloudflareBundleConfigPresent
    bundle_mismatch = $bundleMismatch
    service_baseline_blocker = "cloudflare_service_tunnel_reset_or_bundle_mismatch"
    blocker = if ($bundleMismatch) { "cloudflare_service_bundle_missing_or_stale" } else { "" }
    broad_windows_wide_claim = "not_claimed"
    dns_claim = "not_proven"
    udp_claim = "not_proven"
    ipv6_claim = "not_proven"
}
Write-Utf8 -Path (Join-Path $ArtifactDir "result.json") -Value ($result | ConvertTo-Json -Depth 4)

$readme = @(
    "# Windows Service Bundle Audit",
    "",
    "Status: $($result.status)",
    "",
    "This artifact audits the installed Windows service client bundle without writing the plaintext relay auth token.",
    "",
    "- Expected Cloudflare front: ``$ExpectedFront``",
    "- Expected Cloudflare origin: ``$ExpectedOrigin``",
    "- Installed relay server: ``$installedServer``",
    "- Installed server name: ``$installedServerName``",
    "- Cloudflare bundle config present: ``$cloudflareBundleConfigPresent``",
    "- Blocker: ``$($result.blocker)``",
    "",
    "No broad Windows wide, DNS, UDP, or IPv6 support is claimed."
) -join [Environment]::NewLine
Write-Utf8 -Path (Join-Path $ArtifactDir "README.md") -Value $readme

if ($result.status -eq "PASS") {
    exit 0
}
exit 1
