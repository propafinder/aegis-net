[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepoRoot)
$ErrorActionPreference='Stop'
# This invokes the REAL finalizer with inert local policy/adapter/snapshot fixtures.
# Unsigned metadata and project-license binding are under test; signatures and native custody
# are deliberately mocked and are not accepted by this fixture.
$root=Join-Path ([IO.Path]::GetTempPath()) ('aegis-research-finalizer-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
  $callers=Join-Path $root 'callers'; [IO.Directory]::CreateDirectory($callers) | Out-Null
  foreach ($name in @('Finalize-WindowsRelease.ps1','ResearchInventory.ps1')) {
    [IO.File]::Copy((Join-Path $RepoRoot "tools/windows/release/$name"),(Join-Path $callers $name),$false)
  }
  [IO.File]::WriteAllText((Join-Path $callers 'Read-AuthenticodePolicy.ps1'),@'
function Read-AuthenticodePolicy([string]$Policy,[ref]$RawSha256) {
  $RawSha256.Value='a'*64
  return [PSCustomObject]@{publisher_certificate_sha256=('b'*64)}
}
'@)
  [IO.File]::WriteAllText((Join-Path $callers 'AdapterCustody.ps1'),@'
function Open-AuthenticodeAdapters { return [PSCustomObject]@{Attestation='inert'} }
function Close-AuthenticodeAdapters { }
function Assert-AuthenticodeAdaptersCurrent { }
function Invoke-PinnedAdapter([object]$Lease,[hashtable]$Parameters) {
  $expected=[IO.File]::ReadAllText($Parameters.Attestation)
  if ($Parameters.UnsignedSha256 -cne $expected -or -not $Parameters.RequireExactInputBinding) { throw 'Fixture original attestation mismatch' }
  $global:LASTEXITCODE=0
}
'@)
  [IO.File]::WriteAllText((Join-Path $callers 'PrivateSnapshot.ps1'),@'
function New-PrivateReleaseSnapshot([string]$Package,[string]$Policy,[string]$ProviderAttestations) {
  $base=Join-Path ([IO.Path]::GetTempPath()) ('aegis-finalizer-fixture-snapshot-'+[Guid]::NewGuid().ToString('N'))
  [IO.Directory]::CreateDirectory($base) | Out-Null
  $pkg=Join-Path $base 'package'; $att=Join-Path $base 'attestations'
  [IO.Directory]::CreateDirectory($pkg) | Out-Null; [IO.Directory]::CreateDirectory($att) | Out-Null
  foreach ($f in Get-ChildItem -LiteralPath $Package -File) { [IO.File]::Copy($f.FullName,(Join-Path $pkg $f.Name),$false) }
  foreach ($f in Get-ChildItem -LiteralPath $ProviderAttestations -File) { [IO.File]::Copy($f.FullName,(Join-Path $att $f.Name),$false) }
  return [PSCustomObject]@{Root=$base;Package=$pkg;Policy=$Policy;ProviderAttestations=$att}
}
function Open-PrivateSnapshotLocks { return @() }
'@)
  [IO.File]::WriteAllText((Join-Path $callers 'Test-AuthenticodePolicy.ps1'),@'
param([string]$Package,[string]$Policy,[string]$ExpectedPolicySha256)
# Native signatures deliberately outside this synthetic relation fixture.
'@)
  $source='c'*40
  $capsMeasure=@('private-control','poisson-control','poisson-insertion','privacy-pcap-export','privacy-study-assemble','privacy-frontier','brain-outcome-replay')
  $capsLab=@('dependencies','topology','awgn','poisson-channel','privacy-channel','bittraps-channel')
  function New-Info([string]$Tool,[string]$Version,[string[]]$Caps,[string]$UnsignedHash) {
    return [ordered]@{schema='aegis_research_tool_build_info_v1';tool=$Tool;crate_version=$Version;source_commit=$source;
      cargo_lock_sha256=('d'*64);target_triple='x86_64-pc-windows-msvc';build_features='none';rustc_version='rustc 1.97.1 (fixture)';
      binary_sha256=$UnsignedHash;capabilities=$Caps}
  }
  foreach ($case in @('control','measure-mismatch','lab-mismatch','licensed-control','licensed-apache-mismatch','licensed-mit-mismatch','licensed-notice-mismatch','licensed-missing-license','licensed-bad-bool','licensed-missing-declaration','legacy-extra-license')) {
    $dir=Join-Path $root $case; $att=Join-Path $root ($case+'-att'); $out=Join-Path $root ($case+'-output')
    [IO.Directory]::CreateDirectory($dir) | Out-Null; [IO.Directory]::CreateDirectory($att) | Out-Null
    $files=[ordered]@{}
    foreach ($name in @('README.txt','WINTUN-LICENSE.txt','aegis-client.exe','aegis-winctl.exe','wintun.dll','aegis-measure.exe','aegis-transport-lab.exe')) {
      [IO.File]::WriteAllText((Join-Path $dir $name),('inert unsigned '+$name))
      $files[$name]=(Get-FileHash -LiteralPath (Join-Path $dir $name) -Algorithm SHA256).Hash.ToLowerInvariant()
      if ($name.EndsWith('.exe')) {
        [IO.File]::WriteAllText((Join-Path $att ($name+'.attestation')),$files[$name])
        # Actual signed-byte distinction without any real signature claim.
        [IO.File]::AppendAllText((Join-Path $dir $name),' inert signature fixture')
      }
    }
    $pair=[ordered]@{schema='aegis_windows_research_operators_v1';
      measure=New-Info 'aegis-measure' '0.3.12' $capsMeasure $files['aegis-measure.exe'];
      transport_lab=New-Info 'aegis-transport-lab' '0.1.0' $capsLab $files['aegis-transport-lab.exe']}
    if ($case -eq 'measure-mismatch') { $pair.measure.binary_sha256='e'*64 }
    if ($case -eq 'lab-mismatch') { $pair.transport_lab.binary_sha256='e'*64 }
    [IO.File]::WriteAllText((Join-Path $dir 'research-operators.json'),($pair | ConvertTo-Json -Depth 6))
    $files['research-operators.json']=(Get-FileHash -LiteralPath (Join-Path $dir 'research-operators.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $licensed=$case.StartsWith('licensed-')
    if ($licensed) {
      foreach ($name in @('LICENSE-APACHE','LICENSE-MIT','NOTICE')) {
        [IO.File]::Copy((Join-Path $RepoRoot $name),(Join-Path $dir $name),$false)
        $files[$name]=(Get-FileHash -LiteralPath (Join-Path $dir $name) -Algorithm SHA256).Hash.ToLowerInvariant()
      }
    }
    if ($case -eq 'legacy-extra-license') {
      [IO.File]::WriteAllText((Join-Path $dir 'NOTICE'),'unadmitted extra license')
      $files['NOTICE']=(Get-FileHash -LiteralPath (Join-Path $dir 'NOTICE') -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $manifest=[ordered]@{schema=4;platform='windows-x86_64';source_commit=$source;signed_release=$false;files=$files}
    if ($licensed -and $case -ne 'licensed-missing-declaration') { $manifest.project_licenses=$true }
    if ($case -eq 'licensed-bad-bool') { $manifest.project_licenses='true' }
    $tamperedLicense=switch ($case) {
      'licensed-apache-mismatch' { 'LICENSE-APACHE' }
      'licensed-mit-mismatch' { 'LICENSE-MIT' }
      'licensed-notice-mismatch' { 'NOTICE' }
      default { $null }
    }
    if ($null -ne $tamperedLicense) { [IO.File]::AppendAllText((Join-Path $dir $tamperedLicense),' fixture tamper') }
    if ($case -eq 'licensed-missing-license') { Remove-Item -LiteralPath (Join-Path $dir 'NOTICE') }

    [IO.File]::WriteAllText((Join-Path $dir 'manifest.json'),($manifest | ConvertTo-Json -Depth 6))
    $refusal=$null
    try {
      & (Join-Path $callers 'Finalize-WindowsRelease.ps1') -SignedInput $dir -Output $out -ProviderAttestations $att -ExpectedWorkflow 'example-org/aegis:.github/workflows/windows-package.yml' -ExpectedRef 'refs/heads/main' -Policy 'inert-unused-policy' | Out-Null
    } catch { $refusal=$_.Exception.Message }
    if ($case -in @('control','licensed-control')) {
      if ($null -ne $refusal) { throw "Control finalizer refused: $refusal" }
      $final=Get-Content -Raw -LiteralPath (Join-Path $out 'manifest.json') | ConvertFrom-Json
      $expectedCount=$(if ($licensed) { 12 } else { 9 })
      if ($final.schema -ne 5 -or $final.authenticode.executables.Count -ne 4 -or
          $final.project_licenses -isnot [bool] -or $final.project_licenses -ne $licensed -or
          (Get-ChildItem -LiteralPath $out -File).Count -ne $expectedCount) { throw 'Control finalizer inventory changed' }
      if ($licensed) {
        foreach ($name in @('LICENSE-APACHE','LICENSE-MIT','NOTICE')) {
          if ($final.files.$name -cne $files[$name] -or
              (Get-FileHash -LiteralPath (Join-Path $out $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $files[$name]) { throw 'Finalizer changed licensed candidate payload' }
        }
      }
      $retained=Get-Content -Raw -LiteralPath (Join-Path $out 'research-operators.json') | ConvertFrom-Json
      if ($retained.measure.binary_sha256 -cne $files['aegis-measure.exe'] -or $retained.transport_lab.binary_sha256 -cne $files['aegis-transport-lab.exe']) { throw 'Unsigned identity changed during finalization' }
      if ($final.files.'aegis-measure.exe' -ceq $retained.measure.binary_sha256) { throw 'Control failed to distinguish signed and unsigned bytes' }
    } else {
      $expectedRefusal=switch ($case) {
        { $_ -in @('measure-mismatch','lab-mismatch') } { 'Research unsigned metadata/candidate digest mismatch' }
        { $_ -in @('licensed-apache-mismatch','licensed-mit-mismatch','licensed-notice-mismatch') } { 'Project license candidate digest mismatch' }
        'licensed-bad-bool' { 'Project license declaration must be boolean' }
        { $_ -in @('licensed-missing-declaration','legacy-extra-license') } { 'Manifest payload inventory rejected' }
        default { $null }
      }
      if ($null -eq $refusal -or ($null -ne $expectedRefusal -and $refusal -cne $expectedRefusal)) { throw "Wrong/missing direct finalizer refusal: $case" }
      if ((Test-Path -LiteralPath $out) -or (Test-Path -LiteralPath ($out+'.zip')) -or (Test-Path -LiteralPath ($out+'.authenticode-handoff.json'))) { throw 'Finalizer wrote output before digest refusal' }
    }
  }
  Write-Output 'Research/license finalizer binding: PASS (two synthetic controls/nine refusals; no signature/native acceptance)'
} finally { if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force } }
