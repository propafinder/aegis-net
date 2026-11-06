[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Candidate,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedSourceCommit
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ResearchInventory.ps1')
$root = [IO.Path]::GetFullPath($Candidate)
function Assert-NoReparseAncestry([string]$Path) {
  $current = $Path
  while ($current) {
    if (Test-Path -LiteralPath $current) {
      if ((Get-Item -Force -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Unsigned candidate ancestry contains a reparse point: $current"
      }
    }
    $current = [IO.Path]::GetDirectoryName($current)
  }
}
function Assert-PeMachine([string]$Path, [byte[]]$ExpectedMachine) {
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    $header = [byte[]]::new(64)
    if ($stream.Read($header, 0, $header.Length) -ne $header.Length -or $header[0] -ne 0x4d -or $header[1] -ne 0x5a) {
      throw "Candidate executable lacks an MZ header: $Path"
    }
    $peOffset = [BitConverter]::ToUInt32($header, 60)
    if ($peOffset -gt $stream.Length - 6) { throw "Candidate executable has an invalid PE offset: $Path" }
    $stream.Position = $peOffset
    $pe = [byte[]]::new(6)
    if ($stream.Read($pe, 0, 6) -ne 6 -or $pe[0] -ne 0x50 -or $pe[1] -ne 0x45 -or
        $pe[2] -ne 0 -or $pe[3] -ne 0 -or $pe[4] -ne $ExpectedMachine[0] -or $pe[5] -ne $ExpectedMachine[1]) {
      throw "Candidate executable machine does not match manifest: $Path"
    }
  } finally { $stream.Dispose() }
}
Assert-NoReparseAncestry $root
$inventory=Get-WindowsKitInventory -Package $root
$expectedFiles = $inventory.Files
$expectedPayload = $inventory.Payload
$items = @(Get-ChildItem -Force -LiteralPath $root)
if ($items.Count -ne $expectedFiles.Count -or
    (Compare-Object ($expectedFiles | Sort-Object) @($items | ForEach-Object Name | Sort-Object))) {
  throw 'Unsigned candidate has an unexpected file set'
}
foreach ($item in $items) {
  if (-not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
  throw "Unsigned candidate contains a directory or reparse point: $($item.Name)"
}
$manifestPath = Join-Path $root 'manifest.json'
if ((Get-Item -LiteralPath $manifestPath).Length -gt 65536) { throw 'Unsigned manifest is oversized' }
$raw = Get-Content -Raw -LiteralPath $manifestPath
$jsonKeys = [regex]::Matches($raw, '"(?:[^"\\]|\\.)*"\s*:')
$manifest = $raw | ConvertFrom-Json
$expectedTopFields = @('files','platform','schema','signed_release','source_commit')
$licenseDeclaration = $manifest.PSObject.Properties['project_licenses']
if ($null -ne $licenseDeclaration) {
  if ($licenseDeclaration.Value -isnot [bool]) { throw 'Project license declaration must be boolean' }
  $expectedTopFields += 'project_licenses'
}
if ($jsonKeys.Count -ne ($expectedTopFields.Count+$expectedPayload.Count)) { throw 'Unsigned manifest contains duplicate or unexpected JSON keys' }
$topFields = @($manifest.PSObject.Properties.Name | Sort-Object)
if (Compare-Object ($expectedTopFields | Sort-Object) $topFields) {
  throw 'Unsigned manifest has an unexpected schema'
}
if ($manifest.schema -notin @(2,4) -or $manifest.platform -notin @('windows-x86_64','windows-aarch64') -or
    ($manifest.platform -eq 'windows-aarch64' -and $manifest.schema -ne 2) -or
    $manifest.signed_release -ne $false -or [string]$manifest.source_commit -cne $ExpectedSourceCommit) {
  throw 'Unsigned manifest identity does not match the trusted source'
}
$machine = if ($manifest.platform -eq 'windows-aarch64') { [byte[]]@(0x64,0xaa) } else { [byte[]]@(0x64,0x86) }
$wintunPin = if ($manifest.platform -eq 'windows-aarch64') { 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80' } else { 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce' }
$fileFields = @($manifest.files.PSObject.Properties.Name | Sort-Object)
if (Compare-Object ($expectedPayload | Sort-Object) $fileFields) { throw 'Unsigned manifest payload set mismatch' }
foreach ($name in $expectedPayload) {
  $digest = [string]$manifest.files.PSObject.Properties[$name].Value
  if ($digest -cnotmatch '^[a-f0-9]{64}$') { throw "Invalid manifest SHA-256 for $name" }
  $path = Join-Path $root $name
  if ((Get-Item -LiteralPath $path).Length -gt 256MB) { throw "Candidate payload is oversized: $name" }
  if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) {
    throw "Candidate payload SHA-256 mismatch: $name"
  }
}
foreach ($name in $inventory.Executables) { Assert-PeMachine (Join-Path $root $name) $machine }
if ($inventory.Research) { Assert-WindowsResearchMetadata -Package $root -ExpectedSourceCommit $ExpectedSourceCommit }
if ([string]$manifest.files.'wintun.dll' -cne $wintunPin -or
    [string]$manifest.files.'WINTUN-LICENSE.txt' -cne '183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2') {
  throw 'Unsigned candidate does not contain the pinned Wintun distribution'
}
[ordered]@{ ok = $true; source_commit = $ExpectedSourceCommit; files_verified = $expectedPayload.Count; signed_release = $false } | ConvertTo-Json -Compress
