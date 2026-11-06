[CmdletBinding()]
param([string]$InstallerPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Run this whole-script fixture in a fresh, independently bounded PowerShell
# process. It never launches services, ACL tools or another child process.
if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    Write-Output 'AEGIS_LEGACY_SERVICE_REFUSAL_INVALID missing_installer'
    exit 2
}
try {
    $source = [IO.File]::ReadAllBytes($InstallerPath)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $sourceHash = ([BitConverter]::ToString($sha.ComputeHash($source))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
} catch {
    Write-Output 'AEGIS_LEGACY_SERVICE_REFUSAL_INVALID source_read'
    exit 2
}
# Exact original/candidate admission ensures that the baseline's first path
# callback remains the verified, unqualified Join-Path call. No arbitrary script
# is allowed to escape that recorder and reach native operations.
$admittedSources = @('556bf8f2a5026bfdecfc7e0d3ab4e62ebd19b72cc0eede21673d7c2fef30d353', '6d5c926705ca3d23f1a7973f4ef9de0e4784926021619874fe6383509b80ee9b', '3e3562598f3feba3c07459f05da91da74a5405360cd491ebe4ffb6e79a0f7bdb', 'e092f3126562d63f159ea6464bff0e1fad4742706875ce61308243aa7e8badce')
if ($sourceHash -notin $admittedSources) {
    Write-Output 'AEGIS_LEGACY_SERVICE_REFUSAL_INVALID unknown_source'
    exit 2
}
$tokens = $null
$parseErrors = $null
$null = [Management.Automation.Language.Parser]::ParseFile($InstallerPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    Write-Output 'AEGIS_LEGACY_SERVICE_REFUSAL_INVALID syntax'
    exit 2
}

function Snapshot-OwnedTree([string]$Root) {
    $entries = [Collections.Generic.List[string]]::new()
    foreach ($directory in [IO.Directory]::GetDirectories($Root, '*', [IO.SearchOption]::AllDirectories)) {
        $entries.Add('directory:' + $directory.Substring($Root.Length))
    }
    foreach ($file in [IO.Directory]::GetFiles($Root, '*', [IO.SearchOption]::AllDirectories)) {
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $digest = ([BitConverter]::ToString($hash.ComputeHash([IO.File]::ReadAllBytes($file)))).Replace('-', '') }
        finally { $hash.Dispose() }
        $entries.Add('file:' + $file.Substring($Root.Length) + ':' + $digest)
    }
    return (($entries.ToArray() | Sort-Object) -join "`n")
}

$expectedError = 'Legacy service installer is retired because it cannot establish private configuration ACLs before writing. No installation changes were made. Use aegis-winctl.exe client install --help from a verified external kit, then follow docs/platforms/windows/windows-install-runbook.md with an independent manifest SHA-256, private configuration and a fresh root. Existing installations are not adopted or removed.'
$cases = @(
    @{ name = 'default'; flags = @{} },
    @{ name = 'what_if'; flags = @{ WhatIf = $true } },
    @{ name = 'force'; flags = @{ Force = $true } },
    @{ name = 'start_service'; flags = @{ StartService = $true } },
    @{ name = 'force_and_start'; flags = @{ Force = $true; StartService = $true } },
    @{ name = 'explicit_private_paths'; flags = @{ WhatIf = $true; Force = $true; StartService = $true; ServiceName = 'SyntheticExistingService'; DisplayName = 'SyntheticExistingService'; WindowsWideListener = 'synthetic-private-input-canary' } }
)
$records = [Collections.Generic.List[object]]::new()
$invalid = $false
$passed = 0
$scratch = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'aegis-legacy-service-refusal-' + [Guid]::NewGuid().ToString('N'))
$global:AegisLegacyServiceRefusalRecorder = [pscustomobject]@{ Count = 0 }
# Source calls this before admin detection, source-file reads and all writes.
# Throwing here is an intentional inert baseline seam, never a native mock PASS.
function global:Join-Path {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Path, [Parameter(Position = 1)][string]$ChildPath)
    $global:AegisLegacyServiceRefusalRecorder.Count++
    throw 'AEGIS_FIXTURE_FIRST_PATH_CALLBACK'
}
try {
    $null = [IO.Directory]::CreateDirectory($scratch)
    $installRoot = [IO.Path]::Combine($scratch, 'installation')
    $dataRoot = [IO.Path]::Combine($scratch, 'program-data')
    $null = [IO.Directory]::CreateDirectory($installRoot)
    $null = [IO.Directory]::CreateDirectory($dataRoot)
    $client = [IO.Path]::Combine($installRoot, 'existing-client.exe')
    $config = [IO.Path]::Combine($dataRoot, 'existing-config.toml')
    $ca = [IO.Path]::Combine($dataRoot, 'existing-ca.pem')
    $identity = [IO.Path]::Combine($dataRoot, 'existing-device-identity')
    $floor = [IO.Path]::Combine($dataRoot, 'existing-release-floor')
    foreach ($path in @($client, $config, $ca, $identity, $floor)) {
        [IO.File]::WriteAllBytes($path, [Text.Encoding]::UTF8.GetBytes('synthetic-preserved-record'))
    }
    $before = Snapshot-OwnedTree $scratch
    foreach ($case in $cases) {
        $global:AegisLegacyServiceRefusalRecorder.Count = 0
        $arguments = @{ ClientExePath = $client; ConfigPath = $config; CaPath = $ca; InstallRoot = $installRoot; ProgramDataRoot = $dataRoot; Confirm = $false }
        foreach ($key in $case.flags.Keys) { $arguments[$key] = $case.flags[$key] }
        $caught = $null
        try { & $InstallerPath @arguments *> $null }
        catch { $caught = $_.Exception.Message }
        $callbacks = $global:AegisLegacyServiceRefusalRecorder.Count
        $unchanged = (Snapshot-OwnedTree $scratch) -ceq $before
        $deprecation = $caught -ceq $expectedError
        $baselineBoundary = ($callbacks -eq 1) -and ($caught -ceq 'AEGIS_FIXTURE_FIRST_PATH_CALLBACK')
        $valid = $unchanged -and (($deprecation -and $callbacks -eq 0) -or $baselineBoundary)
        $result = if (-not $valid) { 'INVALID' } elseif ($deprecation) { 'PASS' } else { 'FAIL' }
        if ($result -eq 'PASS') { $passed++ }
        if ($result -eq 'INVALID') { $invalid = $true }
        $record = [ordered]@{ case = $case.name; result = $result; first_path_callbacks = $callbacks; exact_deprecation = $deprecation; original_path_boundary_observed = $baselineBoundary; owned_installation_unchanged = $unchanged; after_invocation_observed = $true; native_operations_executed = $false }
        $records.Add($record)
        Write-Output ('AEGIS_LEGACY_SERVICE_REFUSAL_CASE ' + ($record | ConvertTo-Json -Compress))
    }
} catch {
    $invalid = $true
    Write-Output 'AEGIS_LEGACY_SERVICE_REFUSAL_INVALID fixture_exception'
} finally {
    Remove-Item Function:\Join-Path -ErrorAction SilentlyContinue
    Remove-Variable AegisLegacyServiceRefusalRecorder -Scope Global -ErrorAction SilentlyContinue
    if ([IO.Directory]::Exists($scratch)) { [IO.Directory]::Delete($scratch, $true) }
}
$summary = [ordered]@{ selected = $records.Count; passed = $passed; failed = (@($records | Where-Object { $_.result -eq 'FAIL' })).Count; invalid = $invalid; source_sha256 = $sourceHash; powershell_version = $PSVersionTable.PSVersion.ToString(); powershell_edition = $PSVersionTable.PSEdition; native_acl_acceptance = $false }
Write-Output ('AEGIS_LEGACY_SERVICE_REFUSAL_SUMMARY ' + ($summary | ConvertTo-Json -Compress))
if ($invalid -or $records.Count -ne 6) { exit 2 }
if ($passed -ne 6) { exit 1 }
exit 0
