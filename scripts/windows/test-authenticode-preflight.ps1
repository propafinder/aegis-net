[CmdletBinding()]
param([string]$RepoRoot = (Join-Path $PSScriptRoot '../..'))
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($RepoRoot)
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('aegis-policy-preflight-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture) | Out-Null
try {
  foreach ($name in @('Invoke-AuthenticodeProvider.ps1', 'Test-AuthenticodePolicy.ps1', 'Read-AuthenticodePolicy.ps1', 'AdapterCustody.ps1','ResearchInventory.ps1')) {
    [IO.File]::Copy((Join-Path $root "tools/windows/release/$name"), (Join-Path $fixture $name), $false)
    $tokens = $null; $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $fixture $name), [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw "PowerShell syntax rejected: $name" }
  }
  $providerMarker = Join-Path $fixture 'provider-called'
  $candidateMarker = Join-Path $fixture 'candidate-validation-called'
  $signatureMarker = Join-Path $fixture 'signature-verification-called'
  $trap = Join-Path $fixture 'never-sign.ps1'
  # These sentinels only record an unexpected call and throw. Neither creates
  # a signature, accepts a candidate nor returns a fake verification success.
  [IO.File]::WriteAllText($trap, @'
[CmdletBinding()]
param([string]$InputPath, [string]$OutputPath, [string]$TimestampUrl, [string]$AttestationOutput)
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'provider-called'), 'unexpected call')
throw 'Test sentinel must never sign or verify'
'@)
  [IO.File]::WriteAllText((Join-Path $fixture 'Test-UnsignedCandidate.ps1'), @'
param([string]$Candidate, [string]$ExpectedSourceCommit)
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'candidate-validation-called'), 'unexpected call')
throw 'Invalid policy reached candidate validation before provisioning preflight'
'@)
  function Get-AuthenticodeSignature {
    param([string]$LiteralPath)
    [IO.File]::WriteAllText($signatureMarker, 'unexpected call')
    throw 'Invalid policy reached signature verification before provisioning preflight'
  }
  # Shape-only data for rejection tests, never a trusted/provisioned policy.
  # Every test below has at least one invalid field or malformed JSON token.
  $base = [ordered]@{
    schema = 'aegis_windows_authenticode_policy_v2'
    publisher_certificate_sha256 = ('1' * 64)
    timestamp_protocol = 'rfc3161'
    timestamp_attribute_oid = '1.3.6.1.4.1.311.3.3.1'
    rfc3161_structural_verifier = $trap
    provider_attestation_verifier = $trap
    authenticode_provider_sha256 = ('1' * 64)
    rfc3161_structural_verifier_sha256 = ('1' * 64)
    provider_attestation_verifier_sha256 = ('1' * 64)
    wintun_sha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
  }
  $cases = [Collections.Generic.List[object]]::new()
  $changes = @(
    @('schema', 'other-policy'), @('schema', $null), @('schema', 1),
    @('publisher_certificate_sha256', $null), @('publisher_certificate_sha256', ('g' * 64)),
    @('publisher_certificate_sha256', (('1' * 64) + "`n")),
    @('timestamp_protocol', 'authenticode'), @('timestamp_attribute_oid', '1.2.3'),
    @('wintun_sha256', ('0' * 64)), @('wintun_sha256', $true),
    @('rfc3161_structural_verifier', $null), @('rfc3161_structural_verifier', (Join-Path $fixture 'missing-verifier')),
    @('provider_attestation_verifier', $null), @('provider_attestation_verifier', (Join-Path $fixture 'missing-attestation-verifier')),
    @('schema', 'aegis_windows_authenticode_policy_v1'),
    @('authenticode_provider_sha256', $null), @('authenticode_provider_sha256', ('z' * 64)),
    @('rfc3161_structural_verifier_sha256', $null), @('rfc3161_structural_verifier_sha256', @{}),
    @('provider_attestation_verifier_sha256', $null), @('provider_attestation_verifier_sha256', 1)
  )
  $index = 0
  foreach ($change in $changes) {
    $policy = [ordered]@{}
    foreach ($key in $base.Keys) { $policy[$key] = $base[$key] }
    $policy[$change[0]] = $change[1]
    $cases.Add([PSCustomObject]@{ Name = "field-$index"; Raw = ($policy | ConvertTo-Json -Depth 4 -Compress) })
    $index++
  }
  $raw = $base | ConvertTo-Json -Compress
  # A complete shape is readable metadata, not certificate/provider approval.
  # This prevents a reader that always throws from passing all negative cases.
  . (Join-Path $fixture 'Read-AuthenticodePolicy.ps1')
  $shapePath = Join-Path $fixture 'shape-only.json'
  [IO.File]::WriteAllText($shapePath, $raw, [Text.UTF8Encoding]::new($false))
  $shapeOnly = Read-AuthenticodePolicy -Policy $shapePath
  if ($shapeOnly.schema -cne $base.schema -or @($shapeOnly.PSObject.Properties).Count -ne 10 -or
      $shapeOnly.publisher_certificate_sha256 -cne $base.publisher_certificate_sha256 -or
      (Test-Path -LiteralPath $providerMarker) -or (Test-Path -LiteralPath $signatureMarker)) {
    throw 'Complete metadata shape was not read without invoking an adapter'
  }
  $cases.Add([PSCustomObject]@{ Name = 'default-unprovisioned'; Raw = [IO.File]::ReadAllText((Join-Path $root 'tools/windows/release/authenticode-policy.json')) })
  $cases.Add([PSCustomObject]@{ Name = 'duplicate'; Raw = $raw.Replace('{', '{"schema":"aegis_windows_authenticode_policy_v2",') })
  $cases.Add([PSCustomObject]@{ Name = 'escaped-duplicate'; Raw = $raw.Replace('{', '{"\u0073chema":"aegis_windows_authenticode_policy_v2",') })
  $cases.Add([PSCustomObject]@{ Name = 'escaped-duplicate-ten-fields'; Raw = $raw.Replace('"timestamp_protocol":"rfc3161",', '').Replace('{', '{"\u0073chema":"aegis_windows_authenticode_policy_v2",') })
  $cases.Add([PSCustomObject]@{ Name = 'unknown'; Raw = $raw.Replace('{', '{"unknown":null,') })
  $cases.Add([PSCustomObject]@{ Name = 'escaped-unknown'; Raw = $raw.Replace('"schema":', '"\u0073chemx":') })
  $cases.Add([PSCustomObject]@{ Name = 'missing'; Raw = $raw.Replace('"timestamp_protocol":"rfc3161",', '') })
  $cases.Add([PSCustomObject]@{ Name = 'array'; Raw = '[' + $raw + ']' })
  $cases.Add([PSCustomObject]@{ Name = 'array-field'; Raw = $raw.Replace('"timestamp_protocol":"rfc3161"', '"timestamp_protocol":["rfc3161"]') })
  $cases.Add([PSCustomObject]@{ Name = 'nested-field'; Raw = $raw.Replace('"timestamp_protocol":"rfc3161"', '"timestamp_protocol":{"value":"rfc3161"}') })
  $cases.Add([PSCustomObject]@{ Name = 'invalid-escape'; Raw = $raw.Replace('"rfc3161"', '"\q"') })
  $cases.Add([PSCustomObject]@{ Name = 'unicode-high'; Raw = $raw.Replace('"rfc3161"', '"\ud800"') })
  $cases.Add([PSCustomObject]@{ Name = 'unicode-low'; Raw = $raw.Replace('"rfc3161"', '"\udc00"') })
  $cases.Add([PSCustomObject]@{ Name = 'unicode-separated'; Raw = $raw.Replace('"rfc3161"', '"\ud800x\udc00"') })
  $cases.Add([PSCustomObject]@{ Name = 'trailing-object'; Raw = $raw + '{}' })
  $cases.Add([PSCustomObject]@{ Name = 'non-json-whitespace'; Raw = [string][char]0x0085 + $raw })
  $cases.Add([PSCustomObject]@{ Name = 'invalid-utf8'; Bytes = [byte[]]@(0xff, 0x7b, 0x7d) })
  $cases.Add([PSCustomObject]@{ Name = 'oversized'; Raw = (' ' * 65537) + $raw })
  # Valid JSON below the byte cap reaches the anchored flat-object grammar;
  # long permitted whitespace must not turn its array refusal into a hang.
  $nearShape = $raw.Replace('"timestamp_protocol":"rfc3161"', '"timestamp_protocol":["rfc3161"]')
  $padding = 65500 - [Text.Encoding]::UTF8.GetByteCount($nearShape)
  $cases.Add([PSCustomObject]@{ Name = 'near-cap-flat-grammar'; Raw = $nearShape.Insert(1, (' ' * $padding)) })
  foreach ($case in $cases) {
    $policyPath = Join-Path $fixture "$($case.Name).json"
    if ($null -ne $case.Bytes) { [IO.File]::WriteAllBytes($policyPath, $case.Bytes) }
    else { [IO.File]::WriteAllText($policyPath, $case.Raw, [Text.UTF8Encoding]::new($false)) }
    $output = Join-Path $fixture "$($case.Name)-output"
    $attestations = Join-Path $fixture "$($case.Name)-attestations"
    $rejected = $false
    try {
      & (Join-Path $fixture 'Invoke-AuthenticodeProvider.ps1') -Candidate (Join-Path $fixture 'absent-candidate') `
        -Output $output -AttestationOutput $attestations -ProviderPath $trap -Policy $policyPath `
        -ExpectedSourceCommit ('a' * 40) -TimestampUrl 'https://timestamp.invalid'
    } catch { $rejected = $true }
    if (-not $rejected -or (Test-Path -LiteralPath $providerMarker) -or
        (Test-Path -LiteralPath $candidateMarker) -or (Test-Path -LiteralPath $output) -or
        (Test-Path -LiteralPath $attestations)) {
      throw "Invalid policy reached signing preparation/provider or created output: $($case.Name)"
    }
    $rejected = $false
    try { & (Join-Path $fixture 'Test-AuthenticodePolicy.ps1') -Package (Join-Path $fixture 'absent-package') -Policy $policyPath }
    catch { $rejected = $true }
    if (-not $rejected -or (Test-Path -LiteralPath $signatureMarker) -or (Test-Path -LiteralPath $providerMarker)) {
      throw "Invalid policy reached signature/adapter verification: $($case.Name)"
    }
  }
  Write-Output "Authenticode shared provisioning preflight: PASS ($($cases.Count) rejected policies; provider/signature calls zero; no signing output)"
} finally {
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
