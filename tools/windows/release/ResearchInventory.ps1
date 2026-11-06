# Exact opt-in schema inventory. Legacy 2/3 remains unchanged.
function Get-WindowsKitInventory([string]$Package) {
  $path = Join-Path $Package 'manifest.json'
  if ((Get-Item -Force -LiteralPath $path).Length -gt 65536) { throw 'Manifest oversized' }
  $manifest = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
  if ($manifest.schema -notin @(2,3,4,5)) { throw 'Kit schema rejected' }
  $research = $manifest.schema -in @(4,5)
  $projectLicenses = $false
  $licenseDeclaration = $manifest.PSObject.Properties['project_licenses']
  if ($null -ne $licenseDeclaration) {
    if ($licenseDeclaration.Value -isnot [bool]) { throw 'Project license declaration must be boolean' }
    $projectLicenses = $licenseDeclaration.Value
  }
  $payload = @('README.txt','WINTUN-LICENSE.txt','aegis-client.exe','aegis-winctl.exe','wintun.dll')
  $executables = @('aegis-client.exe','aegis-winctl.exe')
  if ($projectLicenses) { $payload += @('LICENSE-APACHE','LICENSE-MIT','NOTICE') }
  if ($research) {
    $payload += @('aegis-measure.exe','aegis-transport-lab.exe','research-operators.json')
    $executables += @('aegis-measure.exe','aegis-transport-lab.exe')
  }
  $declaredFiles = @($manifest.files.PSObject.Properties.Name)
  if ($declaredFiles.Count -ne $payload.Count -or (Compare-Object $payload $declaredFiles)) { throw 'Manifest payload inventory rejected' }
  if ($projectLicenses) { Assert-WindowsProjectLicenseHashes -Package $Package -Manifest $manifest }
  return [PSCustomObject]@{ ProjectLicenses=$projectLicenses; Research=$research; Manifest=$manifest; Payload=$payload; Files=@($payload)+@('manifest.json'); Executables=$executables; Attestations=@($executables | ForEach-Object { "$_.attestation" }) }
}

function Assert-WindowsProjectLicenseHashes([string]$Package,[object]$Manifest) {
  foreach ($name in @('LICENSE-APACHE','LICENSE-MIT','NOTICE')) {
    $expected = $Manifest.files.$name
    if ($expected -isnot [string] -or $expected -cnotmatch '^[a-f0-9]{64}$') { throw 'Project license candidate digest rejected' }
    $path = Join-Path $Package $name
    $item = Get-Item -Force -LiteralPath $path
    if ($item -isnot [IO.FileInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Project license must be a regular file' }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected) { throw 'Project license candidate digest mismatch' }
  }
}

function Assert-WindowsResearchMetadata([string]$Package,[string]$ExpectedSourceCommit,[switch]$Signed,[object]$UnsignedFiles) {
  $path = Join-Path $Package 'research-operators.json'
  if ((Get-Item -Force -LiteralPath $path).Length -gt 16384) { throw 'Research metadata oversized' }
  $raw = Get-Content -Raw -LiteralPath $path
  $keys = [regex]::Matches($raw, '"(?:[^"\\]|\\.)*"\s*:')
  if ($keys.Count -ne 23) { throw 'Research metadata duplicate/unknown keys' }
  $pair = $raw | ConvertFrom-Json
  if ((Compare-Object @('measure','schema','transport_lab') @($pair.PSObject.Properties.Name | Sort-Object)) -or $pair.schema -cne 'aegis_windows_research_operators_v1') { throw 'Research pair schema rejected' }
  $measure = @('private-control','poisson-control','poisson-insertion','privacy-pcap-export','privacy-study-assemble','privacy-frontier','brain-outcome-replay')
  $lab = @('dependencies','topology','awgn','poisson-channel','privacy-channel','bittraps-channel')
  $rows = @(@($pair.measure,'aegis-measure','0.3.12',$measure),@($pair.transport_lab,'aegis-transport-lab','0.1.0',$lab))
  $expectedFields=@('binary_sha256','build_features','capabilities','cargo_lock_sha256','crate_version','rustc_version','schema','source_commit','target_triple','tool')
  foreach ($row in $rows) {
    $info=$row[0]; $caps=@($row[3]); $actual=@($info.capabilities)
    if ((Compare-Object $expectedFields @($info.PSObject.Properties.Name | Sort-Object)) -or
        $info.schema -cne 'aegis_research_tool_build_info_v1' -or $info.tool -cne $row[1] -or
        $info.crate_version -cne $row[2] -or $info.source_commit -cnotmatch '^[a-f0-9]{40}$' -or $info.source_commit -cne $ExpectedSourceCommit -or
        $info.cargo_lock_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $info.binary_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $info.target_triple -cne 'x86_64-pc-windows-msvc' -or $info.build_features -cne 'none' -or
        $info.rustc_version.Length -gt 512 -or $info.rustc_version -cnotmatch '^rustc [\x20-\x7e]+$' -or
        $actual.Count -ne $caps.Count -or (@($actual) -join '|') -cne (@($caps) -join '|')) { throw 'Research tool identity rejected' }
    if ($Signed) {
      $unsigned=$null
      if ($null -ne $UnsignedFiles) { $unsigned=$UnsignedFiles.PSObject.Properties[($info.tool+'.exe')] }
      if ($null -eq $unsigned -or $unsigned.Value -isnot [string] -or
          $unsigned.Value -cnotmatch '^[a-f0-9]{64}$' -or $info.binary_sha256 -cne $unsigned.Value) {
        throw 'Research unsigned metadata/candidate digest mismatch'
      }
    }
    if (-not $Signed) {
      $exe=Join-Path $Package ($info.tool+'.exe')
      if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $info.binary_sha256) { throw 'Unsigned research executable hash mismatch' }
    }
  }
  foreach ($field in @('source_commit','cargo_lock_sha256','target_triple','rustc_version')) {
    if ($pair.measure.$field -cne $pair.transport_lab.$field) { throw 'Mixed research tool build identities' }
  }
  # Metadata describes unsigned bytes. It is never a signature/attestation proof.
}
