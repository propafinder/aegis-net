[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepoRoot)
$ErrorActionPreference='Stop'
. (Join-Path $RepoRoot 'tools/windows/release/ResearchInventory.ps1')
$dir=Join-Path ([IO.Path]::GetTempPath()) ('aegis-research-metadata-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($dir) | Out-Null
$source='a'*40
try {
  foreach ($name in @('aegis-measure.exe','aegis-transport-lab.exe')) { [IO.File]::WriteAllBytes((Join-Path $dir $name),[byte[]](1,2,3)) }
  function New-Info([string]$Tool,[string]$Version,[string[]]$Caps) {
    return [ordered]@{ schema='aegis_research_tool_build_info_v1'; tool=$Tool; crate_version=$Version; source_commit=$source;
      cargo_lock_sha256=('b'*64); target_triple='x86_64-pc-windows-msvc'; build_features='none'; rustc_version='rustc 1.97.0 (synthetic 2026-01-01)';
      binary_sha256=(Get-FileHash (Join-Path $dir ($Tool+'.exe')) -Algorithm SHA256).Hash.ToLowerInvariant(); capabilities=$Caps }
  }
  $pair=[ordered]@{ schema='aegis_windows_research_operators_v1';
    measure=New-Info 'aegis-measure' '0.3.12' @('private-control','poisson-control','poisson-insertion','privacy-pcap-export','privacy-study-assemble','privacy-frontier','brain-outcome-replay');
    transport_lab=New-Info 'aegis-transport-lab' '0.1.0' @('dependencies','topology','awgn','poisson-channel','privacy-channel','bittraps-channel') }
  $meta=Join-Path $dir 'research-operators.json'
  $good=$pair | ConvertTo-Json -Depth 6
  [IO.File]::WriteAllText($meta,$good)
  Assert-WindowsResearchMetadata -Package $dir -ExpectedSourceCommit $source
  $cases=0
  foreach ($field in @('source_commit','cargo_lock_sha256','target_triple','rustc_version','crate_version','build_features','binary_sha256')) {
    $q=$good | ConvertFrom-Json; $q.measure.$field='incorrect'
    [IO.File]::WriteAllText($meta,($q | ConvertTo-Json -Depth 6))
    $refused=$false; try { Assert-WindowsResearchMetadata -Package $dir -ExpectedSourceCommit $source } catch { $refused=$true }
    if (-not $refused) { throw "Mutation unexpectedly admitted: $field" }; $cases++
  }
  $q=$good | ConvertFrom-Json; $q.measure.capabilities=@($q.measure.capabilities)[6..0]
  [IO.File]::WriteAllText($meta,($q | ConvertTo-Json -Depth 6)); $refused=$false
  try { Assert-WindowsResearchMetadata -Package $dir -ExpectedSourceCommit $source } catch { $refused=$true }
  if (-not $refused) { throw 'Capability order substitution admitted' }; $cases++
  foreach ($bad in @($good.Replace('{','{"unknown":"x",'),$good.Replace('{','{"schema":"duplicate",'),(' '*16385))) {
    [IO.File]::WriteAllText($meta,$bad); $refused=$false
    try { Assert-WindowsResearchMetadata -Package $dir -ExpectedSourceCommit $source } catch { $refused=$true }
    if (-not $refused) { throw 'Malformed metadata admitted' }; $cases++
  }
  [IO.File]::WriteAllText($meta,$good)
  Remove-Item -LiteralPath (Join-Path $dir 'aegis-transport-lab.exe')
  $refused=$false; try { Assert-WindowsResearchMetadata -Package $dir -ExpectedSourceCommit $source } catch { $refused=$true }
  if (-not $refused) { throw 'Missing paired executable admitted' }; $cases++
  Write-Output "Research kit metadata: PASS ($cases refusals; synthetic metadata only, no PE/signature/build acceptance)"
} finally { if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force } }
