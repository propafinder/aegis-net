[CmdletBinding()]
param([string]$Destination = (Join-Path $PSScriptRoot '../../target/wintun-pinned'))
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($Destination)
function Assert-NoReparseAncestry([string]$candidate) {
  $ancestor = $candidate
  while ($ancestor) {
    if (Test-Path -LiteralPath $ancestor) {
        if ((Get-Item -Force -LiteralPath $ancestor).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Wintun output ancestry contains a reparse point'
        }
    }
    $ancestor = [IO.Path]::GetDirectoryName($ancestor)
  }
}
Assert-NoReparseAncestry $root
[IO.Directory]::CreateDirectory($root) | Out-Null
$archive = Join-Path $root 'wintun-0.14.1.zip'
Assert-NoReparseAncestry $archive
$archiveHash = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $archiveHash) {
    throw 'Official Wintun archive hash mismatch; output retained for inspection'
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
    foreach ($member in @('bin/amd64/wintun.dll', 'bin/arm64/wintun.dll', 'LICENSE.txt', 'include/wintun.h')) {
        $entry = $zip.GetEntry("wintun/$member")
        if ($null -eq $entry -or $entry.Length -gt 2MB) { throw 'Pinned archive member missing or oversized' }
        $path = Join-Path $root $member
        Assert-NoReparseAncestry $path
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null
        if (-not (Test-Path -LiteralPath $path)) {
            $inputStream = $entry.Open()
            $outputStream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            try { $inputStream.CopyTo($outputStream); $outputStream.Flush($true) }
            finally { $outputStream.Dispose(); $inputStream.Dispose() }
        }
    }
} finally { $zip.Dispose() }
foreach ($pin in @(
    @{ arch = 'amd64'; sha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce' },
    @{ arch = 'arm64'; sha256 = 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80' }
)) {
    $dll = Join-Path $root "bin/$($pin.arch)/wintun.dll"
    if ((Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pin.sha256) { throw "Wintun $($pin.arch) DLL hash mismatch" }
    if ((Get-AuthenticodeSignature -LiteralPath $dll).Status -ne 'Valid') { throw "Wintun $($pin.arch) Authenticode validation failed" }
}
if ((Get-FileHash -LiteralPath (Join-Path $root 'LICENSE.txt') -Algorithm SHA256).Hash.ToLowerInvariant() -ne '183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2') { throw 'Wintun license hash mismatch' }
[PSCustomObject]@{
    wintun_root = $root
    dll = Join-Path $root 'bin/amd64/wintun.dll'
    archive_sha256 = $archiveHash
    dll_sha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
    arm64_dll = Join-Path $root 'bin/arm64/wintun.dll'
    arm64_dll_sha256 = 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80'
    authenticode = 'Valid'
} | ConvertTo-Json
