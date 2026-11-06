[CmdletBinding()]
param([string]$RepoRoot = (Join-Path $PSScriptRoot '../..'))
$ErrorActionPreference = 'Stop'
if ($env:OS -cne 'Windows_NT') { throw 'Adapter custody regression requires actual Windows file sharing' }
$root = [IO.Path]::GetFullPath($RepoRoot)
. (Join-Path $root 'tools/windows/release/AdapterCustody.ps1')
. (Join-Path $root 'tools/windows/release/Read-AuthenticodePolicy.ps1')
Initialize-AdapterCustody
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('aegis-adapter-custody-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture) | Out-Null
$lease = $null
try {
  $entry = Join-Path $fixture 'entry.ps1'
  [IO.File]::WriteAllText($entry, "throw 'inert entry must not be executed'`n", [Text.UTF8Encoding]::new($false))
  $pin = (Get-FileHash -LiteralPath $entry -Algorithm SHA256).Hash.ToLowerInvariant()
  function Assert-Refused([scriptblock]$Action, [string]$Name) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw "Adapter custody did not refuse: $Name" }
  }
  Assert-Refused { [Aegis.Release.AdapterLease]::Acquire($entry, ('0' * 64)).Dispose() } 'wrong entry pin'
  Assert-Refused { [Aegis.Release.AdapterLease]::Acquire('entry.ps1', $pin).Dispose() } 'relative path'
  Assert-Refused { [Aegis.Release.AdapterLease]::Acquire("${entry}:alternate.ps1", $pin).Dispose() } 'alternate data stream'
  Assert-Refused { [Aegis.Release.AdapterLease]::Acquire((Join-Path $fixture '.\entry.ps1'), $pin).Dispose() } 'noncanonical path'
  $lease = [Aegis.Release.AdapterLease]::Acquire($entry, $pin)
  Assert-Refused { [IO.File]::WriteAllText($entry, 'different bytes') } 'write while held'
  Assert-Refused { [IO.File]::Delete($entry) } 'delete while held'
  Assert-Refused { [IO.File]::Move($entry, (Join-Path $fixture 'renamed.ps1')) } 'rename while held'
  $replacement = Join-Path $fixture 'replacement.ps1'
  [IO.File]::WriteAllText($replacement, 'different bytes')
  Assert-Refused { [IO.File]::Replace($replacement, $entry, $null) } 'replace while held'
  Assert-Refused { [IO.Directory]::Move($fixture, "$fixture-moved") } 'ancestor rename while held'
  $lease.Verify()
  $lease.Dispose(); $lease = $null
  [IO.File]::WriteAllText($entry, 'changed after release')
  Assert-Refused { [Aegis.Release.AdapterLease]::Acquire($entry, $pin).Dispose() } 'replacement after release with old pin'
  $pin = (Get-FileHash -LiteralPath $entry -Algorithm SHA256).Hash.ToLowerInvariant()
  $hardlink = Join-Path $fixture 'hardlink.ps1'
  New-Item -ItemType HardLink -Path $hardlink -Target $entry | Out-Null
  Assert-Refused { [Aegis.Release.AdapterLease]::Acquire($entry, $pin).Dispose() } 'multiple hard links'
  Remove-Item -LiteralPath $hardlink
  $junction = Join-Path $fixture 'junction'
  $target = Join-Path $fixture 'target'
  [IO.Directory]::CreateDirectory($target) | Out-Null
  [IO.File]::WriteAllText((Join-Path $target 'entry.ps1'), 'inert target')
  $targetPin = (Get-FileHash -LiteralPath (Join-Path $target 'entry.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
  New-Item -ItemType Junction -Path $junction -Target $target | Out-Null
  Assert-Refused { [Aegis.Release.AdapterLease]::Acquire((Join-Path $junction 'entry.ps1'), $targetPin).Dispose() } 'reparse ancestor'
  # Remove only the junction entry, before fixture recursion, never its target.
  [IO.Directory]::Delete($junction)

  $failed = Join-Path $fixture 'fails.ps1'
  [IO.File]::WriteAllText($failed, "param([string]`$InputPath)`nWrite-Output 'untrusted failure diagnostic'`nexit 23`n", [Text.UTF8Encoding]::new($false))
  $failedPin = (Get-FileHash -LiteralPath $failed -Algorithm SHA256).Hash.ToLowerInvariant()
  $lease = [Aegis.Release.AdapterLease]::Acquire($failed, $failedPin)
  $returned = @(); $rejected = $false
  try { $returned = @(Invoke-PinnedAdapter -Lease $lease -Parameters @{ InputPath = 'inert input only' }) }
  catch { $rejected = $true }
  $rejectedExitCode = $global:LASTEXITCODE
  if (-not $rejected -or $returned.Count -ne 0 -or $rejectedExitCode -ne 23) {
    throw "Expected adapter exit 23 with rejection and withheld stdout; observed exit: $rejectedExitCode"
  }
  $lease.Verify()
  $lease.Dispose(); $lease = $null
  # Only this fully asserted expected-error fixture is cleared. Otherwise the
  # surrounding CI PowerShell shell inherits its deliberate exit 23 despite
  # successful test assertions. Exceptions and product helper errors stay fatal.
  $global:LASTEXITCODE = 0

  # Exercise the actual signing/verifier/finalizer boundaries with complete
  # metadata and one wrong real entry hash. Throwing downstream sentinels make
  # refusal ordering observable; none approves a candidate, snapshot or signature.
  $callers = Join-Path $fixture 'callers'
  [IO.Directory]::CreateDirectory($callers) | Out-Null
  foreach ($name in @('Invoke-AuthenticodeProvider.ps1','Test-AuthenticodePolicy.ps1','Finalize-WindowsRelease.ps1','Read-AuthenticodePolicy.ps1','AdapterCustody.ps1','ResearchInventory.ps1')) {
    [IO.File]::Copy((Join-Path $root "tools/windows/release/$name"), (Join-Path $callers $name), $false)
  }
  $candidateMarker = Join-Path $fixture 'unexpected-candidate-call'
  $snapshotMarker = Join-Path $fixture 'unexpected-snapshot-call'
  $signatureMarker = Join-Path $fixture 'unexpected-signature-call'
  $escapedCandidate = $candidateMarker.Replace("'", "''")
  $escapedSnapshot = $snapshotMarker.Replace("'", "''")
  [IO.File]::WriteAllText((Join-Path $callers 'Test-UnsignedCandidate.ps1'),
    "param([string]`$Candidate, [string]`$ExpectedSourceCommit)`n[IO.File]::WriteAllText('$escapedCandidate','unexpected')`nthrow 'candidate sentinel refuses'`n", [Text.UTF8Encoding]::new($false))
  [IO.File]::WriteAllText((Join-Path $callers 'PrivateSnapshot.ps1'),
    "function New-PrivateReleaseSnapshot { param(`$Package,`$Policy,`$ProviderAttestations)`n[IO.File]::WriteAllText('$escapedSnapshot','unexpected')`nthrow 'snapshot sentinel refuses'`n}`n", [Text.UTF8Encoding]::new($false))
  function Get-AuthenticodeSignature {
    param([string]$LiteralPath)
    [IO.File]::WriteAllText($signatureMarker, 'unexpected')
    throw 'signature sentinel refuses'
  }
  $policy = [ordered]@{
    schema = 'aegis_windows_authenticode_policy_v2'; publisher_certificate_sha256 = ('1' * 64)
    timestamp_protocol = 'rfc3161'; timestamp_attribute_oid = '1.3.6.1.4.1.311.3.3.1'
    rfc3161_structural_verifier = $failed; provider_attestation_verifier = $failed
    authenticode_provider_sha256 = $failedPin; rfc3161_structural_verifier_sha256 = $failedPin
    provider_attestation_verifier_sha256 = $failedPin
    wintun_sha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
  }
  $policyFile = Join-Path $fixture 'policy.json'
  $output = Join-Path $fixture 'signing-output'
  $attestations = Join-Path $fixture 'attestation-output'
  function Assert-PinRefused([scriptblock]$Action, [string]$Name) {
    $errorMessage = $null
    try { & $Action | Out-Null } catch { $errorMessage = $_.Exception.ToString() }
    if ($null -eq $errorMessage -or -not $errorMessage.Contains('Adapter held SHA-256/identity mismatch')) {
      throw "Expected adapter pin refusal at ${Name}: $errorMessage"
    }
  }
  $policy.authenticode_provider_sha256 = '0' * 64
  [IO.File]::WriteAllText($policyFile, ($policy | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
  Assert-PinRefused {
    & (Join-Path $callers 'Invoke-AuthenticodeProvider.ps1') -Candidate (Join-Path $fixture 'absent-candidate') `
      -Output $output -AttestationOutput $attestations -ProviderPath $failed -ExpectedSourceCommit ('a' * 40) `
      -Policy $policyFile -TimestampUrl 'https://timestamp.invalid'
  } 'wrong provider pin before candidate/output'
  if (Test-Path -LiteralPath $candidateMarker) { throw 'Wrong provider pin reached candidate validation' }
  if ((Test-Path -LiteralPath $output) -or (Test-Path -LiteralPath $attestations)) { throw 'Wrong adapter pin created signing output' }
  $policy.authenticode_provider_sha256 = $failedPin
  $policy.rfc3161_structural_verifier_sha256 = '0' * 64
  [IO.File]::WriteAllText($policyFile, ($policy | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
  Assert-PinRefused {
    & (Join-Path $callers 'Test-AuthenticodePolicy.ps1') -Package (Join-Path $fixture 'absent-package') -Policy $policyFile
  } 'wrong structural verifier pin before OS trust'
  if (Test-Path -LiteralPath $signatureMarker) { throw 'Wrong structural verifier pin reached signature validation' }
  $policy.rfc3161_structural_verifier_sha256 = $failedPin
  $policy.provider_attestation_verifier_sha256 = '0' * 64
  [IO.File]::WriteAllText($policyFile, ($policy | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
  Assert-PinRefused {
    & (Join-Path $callers 'Finalize-WindowsRelease.ps1') -SignedInput (Join-Path $fixture 'absent-package') `
      -Output $output -ProviderAttestations (Join-Path $fixture 'absent-attestations') -Policy $policyFile `
      -ExpectedWorkflow 'example-org/aegis:.github/workflows/windows-package.yml' -ExpectedRef 'refs/heads/main'
  } 'wrong attestation verifier pin before snapshot/promotion'
  if (Test-Path -LiteralPath $snapshotMarker) { throw 'Wrong attestation verifier pin reached snapshot creation' }
  if (Test-Path -LiteralPath $output) { throw 'Wrong adapter pin produced a promoted package' }
  Write-Output 'Authenticode adapter entry custody: PASS (ordinary Windows locks/refusals only; no signature or provider trust)'
} finally {
  if ($null -ne $lease) { $lease.Dispose() }
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
