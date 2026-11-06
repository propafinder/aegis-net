[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Candidate,
  [Parameter(Mandatory)][string]$Output,
  [Parameter(Mandatory)][string]$AttestationOutput,
  [Parameter(Mandatory)][string]$ProviderPath,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedSourceCommit,
  [string]$Policy = (Join-Path $PSScriptRoot 'authenticode-policy.json'),
  [Parameter(Mandatory)][ValidatePattern('^https://')][string]$TimestampUrl
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ResearchInventory.ps1')
. (Join-Path $PSScriptRoot 'Read-AuthenticodePolicy.ps1')
. (Join-Path $PSScriptRoot 'AdapterCustody.ps1')
$candidateRoot = [IO.Path]::GetFullPath($Candidate)
$outputRoot = [IO.Path]::GetFullPath($Output)
$attestationRoot = [IO.Path]::GetFullPath($AttestationOutput)
# The signed release provider and its policy are still x86_64-only. Refuse an
# ARM64 engineering kit before acquiring adapters or creating a snapshot.
if ((Test-Path -LiteralPath $candidateRoot) -and
    (Get-WindowsKitInventory -Package $candidateRoot).Manifest.platform -cne 'windows-x86_64') {
  throw 'Authenticode provider accepts only windows-x86_64 candidates'
}
if ((Test-Path -LiteralPath $outputRoot) -or (Test-Path -LiteralPath $attestationRoot)) { throw 'Signing outputs must not already exist' }
if (-not (Test-Path -LiteralPath $ProviderPath -PathType Leaf)) { throw 'Configured Authenticode provider executable/script is unavailable' }
$policySha256 = $null
$policyData = Read-AuthenticodePolicy -Policy $Policy -RawSha256 ([ref]$policySha256)
$publisherPin = $policyData.publisher_certificate_sha256
$adapters = Open-AuthenticodeAdapters -PolicyData $policyData -ProviderPath $ProviderPath
try {
try {
  & (Join-Path $PSScriptRoot 'Test-UnsignedCandidate.ps1') -Candidate $candidateRoot -ExpectedSourceCommit $ExpectedSourceCommit | Out-Host
  if (-not $?) { throw 'validator returned failure' }
} catch { throw "Unsigned candidate rejected before signing: $($_.Exception.Message)" }
$snapshot = Join-Path ([IO.Path]::GetTempPath()) ("aegis-signing-input-" + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($snapshot) | Out-Null
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetOwner($identity.User); $acl.SetAccessRuleProtection($true, $false)
  $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity.User, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
  [void]$acl.AddAccessRule($rule); [IO.Directory]::SetAccessControl($snapshot, $acl)
  $inventory=Get-WindowsKitInventory -Package $candidateRoot
  if ($inventory.Manifest.platform -cne 'windows-x86_64') { throw 'Signing input platform changed' }
  $candidateFiles = $inventory.Files
  foreach ($name in $candidateFiles) {
    [IO.File]::Copy((Join-Path $candidateRoot $name), (Join-Path $snapshot $name), $false)
  }
  # Validate the immutable handoff snapshot a second time. The provider never
  # receives a path in the mutable downloaded artifact directory.
  try {
    & (Join-Path $PSScriptRoot 'Test-UnsignedCandidate.ps1') -Candidate $snapshot -ExpectedSourceCommit $ExpectedSourceCommit | Out-Host
    if (-not $?) { throw 'snapshot validator returned failure' }
  } catch { throw "Signing input snapshot rejected: $($_.Exception.Message)" }
  if ((Get-WindowsKitInventory -Package $snapshot).Manifest.platform -cne 'windows-x86_64') {
    throw 'Signing input snapshot platform changed'
  }
  [IO.Directory]::CreateDirectory($outputRoot) | Out-Null
  [IO.Directory]::CreateDirectory($attestationRoot) | Out-Null
  foreach ($name in @($inventory.Files | Where-Object { $_ -notin $inventory.Executables })) {
    [IO.File]::Copy((Join-Path $snapshot $name), (Join-Path $outputRoot $name), $false)
  }
  foreach ($name in $inventory.Executables) {
    $signedPath = Join-Path $outputRoot $name
    $unsignedPath = Join-Path $snapshot $name
    $attestationPath = Join-Path $attestationRoot "$name.attestation"
    $unsignedHash = (Get-FileHash -LiteralPath $unsignedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $global:LASTEXITCODE = 0
    Invoke-PinnedAdapter -Lease $adapters.Provider -Parameters @{
      InputPath = $unsignedPath; OutputPath = $signedPath; TimestampUrl = $TimestampUrl; AttestationOutput = $attestationPath
    }
    $providerInvocationSucceeded = $?
    $providerExitCode = $global:LASTEXITCODE
    if (-not $providerInvocationSucceeded -or $providerExitCode -ne 0 -or
        -not (Test-Path -LiteralPath $signedPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $attestationPath -PathType Leaf)) { throw "Authenticode provider failed for $name" }
    $global:LASTEXITCODE = 0
    Invoke-PinnedAdapter -Lease $adapters.Attestation -Parameters @{
      UnsignedInput = $unsignedPath; UnsignedSha256 = $unsignedHash; SignedOutput = $signedPath
      Attestation = $attestationPath; ExpectedSourceCommit = $ExpectedSourceCommit
      PublisherCertificateSha256 = $publisherPin; RequireExactInputBinding = $true
    }
    if (-not $? -or $global:LASTEXITCODE -ne 0) { throw "Provider attestation did not bind signed output to candidate: $name" }
  }
  try {
    & (Join-Path $PSScriptRoot 'Test-AuthenticodePolicy.ps1') -Package $outputRoot -Policy $Policy -ExpectedPolicySha256 $policySha256 | Out-Host
    if (-not $?) { throw 'validator returned failure' }
  } catch { throw "Provider output verification failed: $($_.Exception.Message)" }
  Assert-AuthenticodeAdaptersCurrent $adapters
} finally {
  if (Test-Path -LiteralPath $snapshot) { Remove-Item -LiteralPath $snapshot -Recurse -Force }
}
} finally { Close-AuthenticodeAdapters $adapters }
