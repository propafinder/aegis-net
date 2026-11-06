. (Join-Path $PSScriptRoot 'ResearchInventory.ps1')
function Assert-ReleaseSourceFile([string]$Path) {
  $full = [IO.Path]::GetFullPath($Path)
  $current = $full
  while ($current) {
    if ((Get-Item -Force -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw "Release input ancestry contains a reparse point: $current"
    }
    $current = [IO.Path]::GetDirectoryName($current)
  }
  if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Release input is not a regular file: $full" }
  $fsutil = Join-Path $env:SystemRoot 'System32/fsutil.exe'
  $global:LASTEXITCODE = 0
  $links = @(& $fsutil hardlink list $full 2>$null)
  if ($global:LASTEXITCODE -ne 0 -or $links.Count -ne 1) { throw "Release input must have exactly one hard link: $full" }
}
function New-PrivateReleaseSnapshot {
  param(
    [Parameter(Mandatory)][string]$Package,
    [string]$ManifestSignature,
    [Parameter(Mandatory)][string]$Policy,
    [string]$Archive,
    [string]$AuthenticodeHandoff,
    [string]$Provenance,
    [string]$ProvenanceSignature,
    [string]$ProviderAttestations
  )
  $base = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
  $root = Join-Path $base ("aegis-release-verify-" + [Guid]::NewGuid().ToString('N'))
  [IO.Directory]::CreateDirectory($root) | Out-Null
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetOwner($identity.User)
  $acl.SetAccessRuleProtection($true, $false)
  $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  $propagate = [Security.AccessControl.PropagationFlags]::None
  foreach ($sid in @($identity.User, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, $propagate, 'Allow')
    [void]$acl.AddAccessRule($rule)
  }
  [IO.Directory]::SetAccessControl($root, $acl)
  $packageCopy = Join-Path $root 'package'
  [IO.Directory]::CreateDirectory($packageCopy) | Out-Null
  $inventory=Get-WindowsKitInventory -Package $Package
  $expected = $inventory.Files
  $actual = @(Get-ChildItem -Force -LiteralPath $Package | ForEach-Object Name | Sort-Object)
  if ($actual.Count -ne $expected.Count -or (Compare-Object ($expected | Sort-Object) $actual)) { throw 'Release package file set rejected before snapshot' }
  foreach ($name in $expected) {
    $source = Join-Path $Package $name
    Assert-ReleaseSourceFile $source
    [IO.File]::Copy($source, (Join-Path $packageCopy $name), $false)
  }
  $signatureCopy = $null
  if ($ManifestSignature) {
    Assert-ReleaseSourceFile $ManifestSignature
    $signatureCopy = Join-Path $root 'manifest.json.sig'
    [IO.File]::Copy($ManifestSignature, $signatureCopy, $false)
  }
  Assert-ReleaseSourceFile $Policy
  $policyCopy = Join-Path $root 'authenticode-policy.json'
  [IO.File]::Copy($Policy, $policyCopy, $false)
  $result = [ordered]@{ Root=$root; Package=$packageCopy; Signature=$signatureCopy; Policy=$policyCopy; Archive=$null; ArchiveName=$null; Handoff=$null; Provenance=$null; ProvenanceSignature=$null; ProviderAttestations=$null }
  if ($Archive) {
    Assert-ReleaseSourceFile $Archive
    $result.Archive = Join-Path $root 'release.zip'
    $result.ArchiveName = [IO.Path]::GetFileName([IO.Path]::GetFullPath($Archive))
    [IO.File]::Copy($Archive, $result.Archive, $false)
  }
  if ($AuthenticodeHandoff) {
    Assert-ReleaseSourceFile $AuthenticodeHandoff
    $result.Handoff = Join-Path $root 'authenticode-handoff.json'
    [IO.File]::Copy($AuthenticodeHandoff, $result.Handoff, $false)
  }
  if ($Provenance) {
    Assert-ReleaseSourceFile $Provenance
    $result.Provenance = Join-Path $root 'windows-release.provenance.json'
    [IO.File]::Copy($Provenance, $result.Provenance, $false)
  }
  if ($ProvenanceSignature) {
    Assert-ReleaseSourceFile $ProvenanceSignature
    $result.ProvenanceSignature = Join-Path $root 'windows-release.provenance.json.sig'
    [IO.File]::Copy($ProvenanceSignature, $result.ProvenanceSignature, $false)
  }
  if ($ProviderAttestations) {
    $expectedAttestations = $inventory.Attestations
    $actualAttestations = @(Get-ChildItem -Force -LiteralPath $ProviderAttestations | ForEach-Object Name | Sort-Object)
    if ($actualAttestations.Count -ne $expectedAttestations.Count -or (Compare-Object $expectedAttestations $actualAttestations)) { throw 'Provider attestation file set rejected before snapshot' }
    $result.ProviderAttestations = Join-Path $root 'provider-attestations'
    [IO.Directory]::CreateDirectory($result.ProviderAttestations) | Out-Null
    foreach ($name in $expectedAttestations) {
      $source = Join-Path $ProviderAttestations $name; Assert-ReleaseSourceFile $source
      [IO.File]::Copy($source, (Join-Path $result.ProviderAttestations $name), $false)
    }
  }
  [PSCustomObject]$result
}
function Open-PrivateSnapshotLocks($Snapshot) {
  $paths = @($Snapshot.Policy) + @(Get-ChildItem -LiteralPath $Snapshot.Package -File | ForEach-Object FullName)
  if ($Snapshot.Signature) { $paths += $Snapshot.Signature }
  if ($Snapshot.Archive) { $paths += $Snapshot.Archive }
  if ($Snapshot.Handoff) { $paths += $Snapshot.Handoff }
  if ($Snapshot.Provenance) { $paths += $Snapshot.Provenance }
  if ($Snapshot.ProvenanceSignature) { $paths += $Snapshot.ProvenanceSignature }
  if ($Snapshot.ProviderAttestations) { $paths += @(Get-ChildItem -LiteralPath $Snapshot.ProviderAttestations -File | ForEach-Object FullName) }
  @($paths | ForEach-Object { [IO.File]::Open($_, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read) })
}
