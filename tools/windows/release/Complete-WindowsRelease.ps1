[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Package,
  [Parameter(Mandatory)][string]$Archive,
  [Parameter(Mandatory)][string]$AuthenticodeHandoff,
  [Parameter(Mandatory)][string]$ManifestSignature,
  [Parameter(Mandatory)][string]$Provenance,
  [Parameter(Mandatory)][string]$ProvenanceSignature,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedSourceCommit,
  [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:.+$')][string]$ExpectedWorkflow,
  [Parameter(Mandatory)][ValidatePattern('^refs/(heads|tags)/[A-Za-z0-9._/-]+$')][string]$ExpectedRef,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedInnerZipSha256,
  [Parameter(Mandatory)][ValidatePattern('^(not-used|[a-f0-9]{64})$')][string]$ExpectedGithubArtifactDigest,
  [Parameter(Mandatory)][string]$OutputDelivery,
  [string]$Policy = (Join-Path $PSScriptRoot 'authenticode-policy.json')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ResearchInventory.ps1')
$outputPath = [IO.Path]::GetFullPath($OutputDelivery)
if (Test-Path -LiteralPath $outputPath) { throw 'Final delivery output must not already exist' }
. (Join-Path $PSScriptRoot 'PrivateSnapshot.ps1')
$snapshot = New-PrivateReleaseSnapshot -Package $Package -ManifestSignature $ManifestSignature -Policy $Policy -Archive $Archive -AuthenticodeHandoff $AuthenticodeHandoff -Provenance $Provenance -ProvenanceSignature $ProvenanceSignature
$locks = Open-PrivateSnapshotLocks $snapshot
try {
$root = $snapshot.Package
$archivePath = $snapshot.Archive
$handoffPath = $snapshot.Handoff
$signaturePath = $snapshot.Signature
$Policy = $snapshot.Policy
if (-not (Test-Path -LiteralPath $signaturePath -PathType Leaf) -or (Get-Item -LiteralPath $signaturePath).Length -ne 64) {
  throw 'Detached Ed25519 manifest signature sidecar must be exactly 64 bytes'
}
if ([IO.Path]::GetDirectoryName($signaturePath) -eq $root) {
  throw 'Detached manifest signature must remain outside the exact package directory'
}
# This secret-free verifier authenticates winctl before execution, verifies the
# detached Ed25519 signature, then repeats Authenticode and Wintun validation.
try {
  & (Join-Path $PSScriptRoot 'Verify-WindowsRelease.ps1') -Package $root -ManifestSignature $signaturePath -Policy $Policy | Out-Host
  if (-not $?) { throw 'validator returned failure' }
} catch { throw "Signed package verification failed: $($_.Exception.Message)" }
$handoff = Get-Content -Raw -LiteralPath $handoffPath | ConvertFrom-Json
$handoffFields = @($handoff.PSObject.Properties.Name | Sort-Object)
$expectedHandoffFields = @('archive','archive_sha256','manifest_sha256','manifest_signature_status','ref','schema','signed_release','source_commit','workflow')
if (Compare-Object $expectedHandoffFields $handoffFields) { throw 'Authenticode handoff schema rejected' }
$manifestPath = Join-Path $root 'manifest.json'
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($handoff.schema -ne 'aegis_windows_authenticode_handoff_v1' -or
    $handoff.source_commit -ne $manifest.source_commit -or $handoff.source_commit -ne $ExpectedSourceCommit -or
    $handoff.workflow -ne $ExpectedWorkflow -or $handoff.ref -ne $ExpectedRef -or
    $handoff.archive -ne $snapshot.ArchiveName -or
    $handoff.archive_sha256 -ne $archiveHash -or $archiveHash -ne $ExpectedInnerZipSha256 -or
    $handoff.manifest_sha256 -ne $manifestHash -or
    $handoff.signed_release -ne $false -or $handoff.manifest_signature_status -ne 'required_external_sidecar') {
  throw 'Authenticode handoff does not bind the final archive and manifest'
}
$global:LASTEXITCODE = 0
& (Join-Path $root 'aegis-winctl.exe') package verify-provenance `
  --provenance $snapshot.Provenance --signature $snapshot.ProvenanceSignature `
  --expected-source-commit $ExpectedSourceCommit --expected-workflow $ExpectedWorkflow `
  --expected-ref $ExpectedRef --expected-manifest-sha256 $manifestHash `
  --expected-inner-zip-sha256 $ExpectedInnerZipSha256 `
  --expected-github-artifact-digest $ExpectedGithubArtifactDigest | Out-Host
if (-not $? -or $global:LASTEXITCODE -ne 0) { throw 'Signed provenance envelope rejected' }
$expected = (Get-WindowsKitInventory -Package $root).Files
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
  $entries = @($zip.Entries | ForEach-Object FullName | Sort-Object)
  if ($zip.Entries.Count -ne $expected.Count -or (Compare-Object ($expected | Sort-Object) $entries)) {
    throw 'Final ZIP file set rejected; signature must remain an external sidecar'
  }
  foreach ($name in $expected) {
    $entry = $zip.GetEntry($name)
    $stream = $entry.Open()
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $entryHash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
    if ($entryHash -ne (Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash.ToLowerInvariant()) {
      throw "Final ZIP/package mismatch: $name"
    }
  }
} finally { $zip.Dispose() }
$delivery = [ordered]@{
  schema = 'aegis_windows_delivery_v1'
  source_commit = [string]$manifest.source_commit
  workflow = [string]$handoff.workflow
  ref = [string]$handoff.ref
  archive = $snapshot.ArchiveName
  inner_zip_sha256 = $archiveHash
  github_artifact_digest = $ExpectedGithubArtifactDigest
  manifest_sha256 = $manifestHash
  manifest_signature = [IO.Path]::GetFileName([IO.Path]::GetFullPath($ManifestSignature))
  manifest_signature_sha256 = (Get-FileHash -LiteralPath $signaturePath -Algorithm SHA256).Hash.ToLowerInvariant()
  manifest_signature_external_sidecar = $true
  provenance = [IO.Path]::GetFileName([IO.Path]::GetFullPath($Provenance))
  provenance_sha256 = (Get-FileHash -LiteralPath $snapshot.Provenance -Algorithm SHA256).Hash.ToLowerInvariant()
  provenance_signature = [IO.Path]::GetFileName([IO.Path]::GetFullPath($ProvenanceSignature))
  provenance_signature_sha256 = (Get-FileHash -LiteralPath $snapshot.ProvenanceSignature -Algorithm SHA256).Hash.ToLowerInvariant()
  signed_release = $true
}
$deliveryBytes = [Text.UTF8Encoding]::new($false).GetBytes((($delivery | ConvertTo-Json) + "`n"))
$deliveryFile = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
try { $deliveryFile.Write($deliveryBytes, 0, $deliveryBytes.Length); $deliveryFile.Flush($true) }
finally { $deliveryFile.Dispose() }
$delivery | ConvertTo-Json
} finally {
  foreach ($lock in $locks) { $lock.Dispose() }
  if (Test-Path -LiteralPath $snapshot.Root) { Remove-Item -LiteralPath $snapshot.Root -Recurse -Force }
}
