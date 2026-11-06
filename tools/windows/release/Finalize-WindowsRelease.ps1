[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$SignedInput,
  [Parameter(Mandatory)][string]$Output,
  [Parameter(Mandatory)][string]$ProviderAttestations,
  [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:.+$')][string]$ExpectedWorkflow,
  [Parameter(Mandatory)][ValidatePattern('^refs/(heads|tags)/[A-Za-z0-9._/-]+$')][string]$ExpectedRef,
  [string]$Policy = (Join-Path $PSScriptRoot 'authenticode-policy.json')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ResearchInventory.ps1')
$source = [IO.Path]::GetFullPath($SignedInput)
$destination = [IO.Path]::GetFullPath($Output)
if ((Test-Path -LiteralPath $source) -and
    (Get-WindowsKitInventory -Package $source).Manifest.platform -cne 'windows-x86_64') {
  throw 'Signed release finalizer accepts only windows-x86_64 candidates'
}
if (Test-Path -LiteralPath $destination) { throw 'Final release output must not already exist' }
. (Join-Path $PSScriptRoot 'PrivateSnapshot.ps1')
. (Join-Path $PSScriptRoot 'Read-AuthenticodePolicy.ps1')
. (Join-Path $PSScriptRoot 'AdapterCustody.ps1')
$policySha256 = $null
$policyData = Read-AuthenticodePolicy -Policy $Policy -RawSha256 ([ref]$policySha256)
$adapters = Open-AuthenticodeAdapters -PolicyData $policyData
try {
$snapshot = New-PrivateReleaseSnapshot -Package $source -Policy $Policy -ProviderAttestations $ProviderAttestations
$locks = Open-PrivateSnapshotLocks $snapshot
try {
$source = $snapshot.Package
$Policy = $snapshot.Policy
$ProviderAttestations = $snapshot.ProviderAttestations
try {
  & (Join-Path $PSScriptRoot 'Test-AuthenticodePolicy.ps1') -Package $source -Policy $Policy -ExpectedPolicySha256 $policySha256 | Out-Host
  if (-not $?) { throw 'validator returned failure' }
} catch { throw "Signed input verification failed: $($_.Exception.Message)" }
$candidate = Get-Content -Raw -LiteralPath (Join-Path $source 'manifest.json') | ConvertFrom-Json
if ($candidate.schema -notin @(2,4) -or $candidate.platform -cne 'windows-x86_64' -or
    $candidate.signed_release -ne $false -or [string]$candidate.source_commit -notmatch '^[a-f0-9]{40}$') {
  throw 'Finalizer requires the original explicit unsigned candidate manifest'
}
# The original policy's exact first raw bytes are bound to the staged verifier
# read; reviewed entry handles remain held across all finalizer calls.
$attestationNames = @(Get-ChildItem -Force -LiteralPath $ProviderAttestations | ForEach-Object Name | Sort-Object)
$inventory=Get-WindowsKitInventory -Package $source
if ($inventory.ProjectLicenses) { Assert-WindowsProjectLicenseHashes -Package $source -Manifest $candidate }
$expectedAttestations = $inventory.Attestations
if ($attestationNames.Count -ne $expectedAttestations.Count -or (Compare-Object $expectedAttestations $attestationNames)) { throw 'Provider attestation file set rejected' }
foreach ($name in $inventory.Executables) {
  $unsignedHash = [string]$candidate.files.$name
  if ($unsignedHash -notmatch '^[a-f0-9]{64}$') { throw "Unsigned candidate digest unavailable: $name" }
  $global:LASTEXITCODE = 0
  Invoke-PinnedAdapter -Lease $adapters.Attestation -Parameters @{
    UnsignedSha256 = $unsignedHash; SignedOutput = (Join-Path $source $name)
    Attestation = (Join-Path $ProviderAttestations "$name.attestation")
    ExpectedSourceCommit = [string]$candidate.source_commit
    PublisherCertificateSha256 = $policyData.publisher_certificate_sha256; RequireExactInputBinding = $true
  }
  if (-not $? -or $global:LASTEXITCODE -ne 0) { throw "Provider attestation rejected during finalization: $name" }
}
if ($inventory.Research) {
  $meta=Join-Path $source 'research-operators.json'
  if ((Get-FileHash -LiteralPath $meta -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$candidate.files.'research-operators.json') { throw 'Research provenance changed after candidate signing admission' }
  Assert-WindowsResearchMetadata -Package $source -ExpectedSourceCommit ([string]$candidate.source_commit) -Signed -UnsignedFiles $candidate.files
}
$names = $inventory.Payload
Assert-AuthenticodeAdaptersCurrent $adapters
[IO.Directory]::CreateDirectory($destination) | Out-Null
$files = [ordered]@{}
foreach ($name in $names) {
  $from = Join-Path $source $name
  $to = Join-Path $destination $name
  [IO.File]::Copy($from, $to, $false)
  $files[$name] = (Get-FileHash -LiteralPath $to -Algorithm SHA256).Hash.ToLowerInvariant()
}
$manifest = [ordered]@{
  schema = $(if ($inventory.Research) { 5 } else { 3 })
  project_licenses = [bool]$inventory.ProjectLicenses
  platform = 'windows-x86_64'
  source_commit = [string]$candidate.source_commit
  signed_release = $true
  authenticode = [ordered]@{
    publisher_certificate_sha256 = ([string]$policyData.publisher_certificate_sha256).ToLowerInvariant()
    timestamp = 'rfc3161'
    executables = $inventory.Executables
  }
  files = $files
}
# Signing changes executable bytes only; licensed payloads retain the original
# candidate digests rather than silently re-authorizing modified license text.
if ($inventory.ProjectLicenses) { Assert-WindowsProjectLicenseHashes -Package $destination -Manifest $candidate }
$manifestPath = Join-Path $destination 'manifest.json'
[IO.File]::WriteAllText($manifestPath, (($manifest | ConvertTo-Json -Depth 5) + "`n"), [Text.UTF8Encoding]::new($false))
$archive = "$destination.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($destination, $archive)
$handoff = [ordered]@{
  schema = 'aegis_windows_authenticode_handoff_v1'
  source_commit = [string]$candidate.source_commit
  workflow = $ExpectedWorkflow
  ref = $ExpectedRef
  archive = [IO.Path]::GetFileName($archive)
  archive_sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  signed_release = $false
  manifest_signature_status = 'required_external_sidecar'
}
[IO.File]::WriteAllText("$destination.authenticode-handoff.json", (($handoff | ConvertTo-Json) + "`n"), [Text.UTF8Encoding]::new($false))
Assert-AuthenticodeAdaptersCurrent $adapters
$handoff | ConvertTo-Json
} finally {
  foreach ($lock in $locks) { $lock.Dispose() }
  if (Test-Path -LiteralPath $snapshot.Root) { Remove-Item -LiteralPath $snapshot.Root -Recurse -Force }
}
} finally { Close-AuthenticodeAdapters $adapters }
