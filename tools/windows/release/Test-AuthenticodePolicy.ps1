[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Package,
  [string]$Policy = (Join-Path $PSScriptRoot 'authenticode-policy.json'),
  [ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$ExpectedPolicySha256,
  [switch]$BootstrapOnly
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ResearchInventory.ps1')
. (Join-Path $PSScriptRoot 'Read-AuthenticodePolicy.ps1')
. (Join-Path $PSScriptRoot 'AdapterCustody.ps1')
$packageRoot = [IO.Path]::GetFullPath($Package)
$expectedPolicy = @{}
if ($ExpectedPolicySha256) { $expectedPolicy.ExpectedSha256 = $ExpectedPolicySha256 }
$policyData = Read-AuthenticodePolicy -Policy $Policy @expectedPolicy
$pin = $policyData.publisher_certificate_sha256
$adapters = Open-AuthenticodeAdapters -PolicyData $policyData
try {
function Get-CertificateSha256($Certificate) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Certificate.RawData))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}
function Assert-AegisSignature([string]$Name) {
  $path = Join-Path $packageRoot $Name
  $signature = Get-AuthenticodeSignature -LiteralPath $path
  # Status=Valid is Windows WinVerifyTrust chain and policy validation.
  if ($signature.Status -ne 'Valid') { throw "Authenticode chain rejected for ${Name}: $($signature.Status)" }
  if ((Get-CertificateSha256 $signature.SignerCertificate) -ne $pin) { throw "Publisher certificate SHA-256 mismatch for $Name" }
  if ($null -eq $signature.TimeStamperCertificate) { throw "Trusted timestamp missing for $Name" }
  $global:LASTEXITCODE = 0
  Invoke-PinnedAdapter -Lease $adapters.Structural -Parameters @{
    File = $path; PublisherCertificateSha256 = $pin; RequireRfc3161 = $true
    VerifyMessageImprint = $true; VerifyTimestampChain = $true
  }
  if (-not $? -or $global:LASTEXITCODE -ne 0) { throw "Structural RFC3161 verification failed for $Name" }
}

Assert-AegisSignature 'aegis-winctl.exe'
if (-not $BootstrapOnly) {
  $inventory=Get-WindowsKitInventory -Package $packageRoot
  foreach ($name in $inventory.Executables) { if ($name -ne 'aegis-winctl.exe') { Assert-AegisSignature $name } }
  $wintun = Join-Path $packageRoot 'wintun.dll'
  if ((Get-FileHash -LiteralPath $wintun -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$policyData.wintun_sha256) {
    throw 'Pinned Wintun SHA-256 mismatch'
  }
  $wintunSignature = Get-AuthenticodeSignature -LiteralPath $wintun
  if ($wintunSignature.Status -ne 'Valid') { throw "Wintun Authenticode chain rejected: $($wintunSignature.Status)" }
}
Assert-AuthenticodeAdaptersCurrent $adapters
[ordered]@{ ok = $true; publisher_certificate_sha256 = $pin; rfc3161 = $true; wintun_verified = -not $BootstrapOnly } | ConvertTo-Json -Compress
} finally { Close-AuthenticodeAdapters $adapters }
