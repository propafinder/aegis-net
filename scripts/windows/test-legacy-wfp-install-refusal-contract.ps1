[CmdletBinding()]
param([string]$InstallerPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Fresh actual PowerShell process under root's independent bounded supervisor.
# The fixture never invokes a kernel service, signing tool or nested child.
if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    Write-Output 'AEGIS_LEGACY_WFP_REFUSAL_INVALID missing_installer'
    exit 2
}
try {
    $bytes = [IO.File]::ReadAllBytes($InstallerPath)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $sourceHash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
} catch {
    Write-Output 'AEGIS_LEGACY_WFP_REFUSAL_INVALID source_read'
    exit 2
}
# Exact source bytes (LF or mechanical CRLF) ensure the original first write is
# the unqualified New-Item below. Unknown source is never executed by this seam.
$admittedSources = @('3da619ae5cb15a1c48112c31114e0e1a9bd4eca39063f366147c1717de3a38db', 'fad2c2a0f17635d557d20177eb19d422dda1035efc509f669dc236f2eb1f34ba', 'e4b478bc83269d515a2a2eefc228449585ee25c148d982c4b5122245fc88a834', '230b7204f1618b0e03702b2c23000dc8558bc4c5ddc4e4b8082882ce756a5cbb')
if ($sourceHash -notin $admittedSources) {
    Write-Output 'AEGIS_LEGACY_WFP_REFUSAL_INVALID unknown_source'
    exit 2
}
$tokens = $null
$parseErrors = $null
$null = [Management.Automation.Language.Parser]::ParseFile($InstallerPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    Write-Output 'AEGIS_LEGACY_WFP_REFUSAL_INVALID syntax'
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
$expectedError = 'Legacy WFP driver installer is retired because artifact-directory staging does not establish machine-owned ACL, hash and signature custody before kernel-service start. No driver or service was changed. There is currently no supported protected Rust WFP driver staging/load entry point; preserve existing installations and consult scripts/windows/README.md. Do not relax ACLs or use automatic signing to bypass this refusal.'
$cases = @(
    @{ name = 'existing_owned_paths'; repo = 'repository'; artifact = 'existing-artifacts' },
    @{ name = 'fresh_owned_artifact_path'; repo = 'repository'; artifact = 'fresh-artifacts' },
    @{ name = 'paths_with_spaces'; repo = 'repository space'; artifact = 'artifact space' },
    @{ name = 'literal_quoted_path'; repo = "repository'canary"; artifact = "artifact'canary" }
)
$records = [Collections.Generic.List[object]]::new()
$passed = 0
$invalid = $false
$scratch = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'aegis-legacy-wfp-refusal-' + [Guid]::NewGuid().ToString('N'))
$global:AegisLegacyWfpRefusalRecorder = [pscustomobject]@{ Count = 0 }
# Exact original New-Item is its first filesystem write, before log writes,
# sc.exe stop/delete, builds, signing and driver copying. Do not execute it.
function global:New-Item {
    [CmdletBinding()]
    param([string]$ItemType, [switch]$Force, [string[]]$Path)
    $global:AegisLegacyWfpRefusalRecorder.Count++
    throw 'AEGIS_FIXTURE_FIRST_DIRECTORY_WRITE'
}
try {
    $null = [IO.Directory]::CreateDirectory($scratch)
    foreach ($case in $cases) {
        $repo = [IO.Path]::Combine($scratch, $case.repo)
        $artifact = [IO.Path]::Combine($scratch, $case.artifact)
        $null = [IO.Directory]::CreateDirectory($repo)
        if ($case.name -ne 'fresh_owned_artifact_path') { $null = [IO.Directory]::CreateDirectory($artifact) }
        foreach ($name in @('existing-driver.sys', 'existing-service-state', 'existing-device-identity', 'existing-release-floor')) {
            [IO.File]::WriteAllBytes([IO.Path]::Combine($repo, $name), [Text.Encoding]::UTF8.GetBytes('synthetic-preserved-record'))
        }
    }
    $before = Snapshot-OwnedTree $scratch
    foreach ($case in $cases) {
        $repo = [IO.Path]::Combine($scratch, $case.repo)
        $artifact = [IO.Path]::Combine($scratch, $case.artifact)
        $global:AegisLegacyWfpRefusalRecorder.Count = 0
        $caught = $null
        try { & $InstallerPath -RepoRoot $repo -ArtifactRoot $artifact *> $null }
        catch { $caught = $_.Exception.Message }
        $callbacks = $global:AegisLegacyWfpRefusalRecorder.Count
        $unchanged = (Snapshot-OwnedTree $scratch) -ceq $before
        $deprecation = $caught -ceq $expectedError
        $oldBoundary = ($callbacks -eq 1) -and ($caught -ceq 'AEGIS_FIXTURE_FIRST_DIRECTORY_WRITE')
        $valid = $unchanged -and (($deprecation -and $callbacks -eq 0) -or $oldBoundary)
        $result = if (-not $valid) { 'INVALID' } elseif ($deprecation) { 'PASS' } else { 'FAIL' }
        if ($result -eq 'PASS') { $passed++ }
        if ($result -eq 'INVALID') { $invalid = $true }
        $record = [ordered]@{ case = $case.name; result = $result; first_write_callbacks = $callbacks; exact_refusal = $deprecation; old_write_boundary_observed = $oldBoundary; owned_tree_unchanged = $unchanged; after_invocation_observed = $true; native_operations_executed = $false }
        $records.Add($record)
        Write-Output ('AEGIS_LEGACY_WFP_REFUSAL_CASE ' + ($record | ConvertTo-Json -Compress))
    }
} catch {
    $invalid = $true
    Write-Output 'AEGIS_LEGACY_WFP_REFUSAL_INVALID fixture_exception'
} finally {
    Remove-Item Function:\New-Item -ErrorAction SilentlyContinue
    Remove-Variable AegisLegacyWfpRefusalRecorder -Scope Global -ErrorAction SilentlyContinue
    if ([IO.Directory]::Exists($scratch)) { [IO.Directory]::Delete($scratch, $true) }
}
$summary = [ordered]@{ selected = $records.Count; passed = $passed; failed = (@($records | Where-Object { $_.result -eq 'FAIL' })).Count; invalid = $invalid; source_sha256 = $sourceHash; powershell_version = $PSVersionTable.PSVersion.ToString(); powershell_edition = $PSVersionTable.PSEdition; protected_stage_available = $false; native_driver_acceptance = $false }
Write-Output ('AEGIS_LEGACY_WFP_REFUSAL_SUMMARY ' + ($summary | ConvertTo-Json -Compress))
if ($invalid -or $records.Count -ne 4) { exit 2 }
if ($passed -ne 4) { exit 1 }
exit 0
