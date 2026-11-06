[CmdletBinding()]
param([string]$RepoRoot = (Join-Path $PSScriptRoot '../..'))
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($RepoRoot)
. (Join-Path $root 'tools/windows/release/Read-AuthenticodePolicy.ps1')
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('aegis-policy-digest-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture) | Out-Null
try {
  $trap = Join-Path $fixture 'never-invoke.ps1'
  [IO.File]::WriteAllText($trap, "throw 'inert adapter must never execute'`n", [Text.UTF8Encoding]::new($false))
  $shape = [ordered]@{
    schema = 'aegis_windows_authenticode_policy_v2'; publisher_certificate_sha256 = ('1' * 64)
    timestamp_protocol = 'rfc3161'; timestamp_attribute_oid = '1.3.6.1.4.1.311.3.3.1'
    rfc3161_structural_verifier = $trap; provider_attestation_verifier = $trap
    authenticode_provider_sha256 = ('1' * 64); rfc3161_structural_verifier_sha256 = ('1' * 64)
    provider_attestation_verifier_sha256 = ('1' * 64)
    wintun_sha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
  }
  $policy = Join-Path $fixture 'policy.json'
  $staged = Join-Path $fixture 'staged-policy.json'
  $raw = ($shape | ConvertTo-Json -Compress) + "`n"
  [IO.File]::WriteAllText($policy, $raw, [Text.UTF8Encoding]::new($false))
  $first = $null
  $parsed = Read-AuthenticodePolicy -Policy $policy -RawSha256 ([ref]$first)
  $actual = (Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($first -cne $actual -or @($parsed.PSObject.Properties).Count -ne 10) {
    throw 'First raw digest capture or parsed ten-field shape was changed'
  }
  # Positive metadata checks prove that the added comparison is not an
  # always-refusing substitute for actual signature/candidate verification.
  $same = Read-AuthenticodePolicy -Policy $policy -ExpectedSha256 $first
  [IO.File]::Copy($policy, $staged, $false)
  $copy = Read-AuthenticodePolicy -Policy $staged -ExpectedSha256 $first
  if ($same.publisher_certificate_sha256 -cne $parsed.publisher_certificate_sha256 -or
      $copy.publisher_certificate_sha256 -cne $parsed.publisher_certificate_sha256) {
    throw 'Matching original/staged policy digest did not preserve parsed identity'
  }
  $signatureMarker = Join-Path $fixture 'unexpected-signature-call'
  function Get-AuthenticodeSignature {
    param([string]$LiteralPath)
    [IO.File]::WriteAllText($signatureMarker, 'unexpected')
    throw 'signature sentinel always refuses'
  }
  function Assert-DigestRefused([string]$Path, [string]$Name) {
    $message = $null
    try {
      & (Join-Path $root 'tools/windows/release/Test-AuthenticodePolicy.ps1') `
        -Package (Join-Path $fixture 'absent-package') -Policy $Path -ExpectedPolicySha256 $first | Out-Null
    } catch { $message = $_.Exception.ToString() }
    if ($null -eq $message -or -not $message.Contains('Authenticode policy raw SHA-256 differs from the first validated policy')) {
      throw "Expected first-policy digest refusal at ${Name}: $message"
    }
    if (Test-Path -LiteralPath $signatureMarker) { throw 'Policy drift reached signature validation' }
  }
  # A different complete policy at the same original path cannot become the
  # provider's later verification policy after its adapter tuple was captured.
  $shape.publisher_certificate_sha256 = '2' * 64
  [IO.File]::WriteAllText($policy, ($shape | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
  Assert-DigestRefused $policy 'changed original policy'
  # A later staged copy B must also match the original first-read bytes A.
  [IO.File]::Copy($policy, $staged, $true)
  Assert-DigestRefused $staged 'changed staged policy'
  # Raw-byte equality, not merely equality of decoded values, is required.
  [IO.File]::WriteAllText($staged, $raw + ' ', [Text.UTF8Encoding]::new($false))
  Assert-DigestRefused $staged 'same decoded policy with different bytes'
  # Comparison occurs before decoding: changed malformed JSON has the same
  # digest-refusal diagnostic, and still never reaches a trust API.
  [IO.File]::WriteAllText($staged, '{', [Text.UTF8Encoding]::new($false))
  Assert-DigestRefused $staged 'changed bytes before JSON decoding'
  Write-Output 'Authenticode policy generation: PASS (first raw digest; metadata/caller refusals only; no signing or trust success)'
} finally {
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
