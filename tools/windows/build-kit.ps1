[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Output,
    [switch]$Bootstrap,
    [switch]$IncludeResearchOperators
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$kit = [IO.Path]::GetFullPath($Output)
$archive = "$kit.zip"
$delivery = "$kit.delivery.json"
$researchOutput = "$kit.research"
$researchArchive = "$researchOutput.zip"
foreach ($path in @($kit, $archive, $delivery) + $(if ($IncludeResearchOperators) { @($researchOutput,$researchArchive) } else { @() })) {
    if (Test-Path -LiteralPath $path) { throw "Output already exists: $path" }
}
Push-Location $repo
try {
    $dirty = git status --porcelain --untracked-files=normal
    if ($LASTEXITCODE -ne 0 -or $dirty) { throw 'Commit the source before building an attributable distribution' }
    $source = git rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $source -notmatch '^[a-f0-9]{40}$') { throw 'Source commit unavailable' }
    & "$PSScriptRoot/prepare-build.ps1" -Bootstrap:$Bootstrap
    & "$PSScriptRoot/fetch-wintun.ps1" -Destination (Join-Path $repo 'target/wintun-pinned') | Out-Host
    $env:AEGIS_BUILD_GIT_SHA = $source
    if ($IncludeResearchOperators) {
        $env:AEGIS_RESEARCH_RUSTC_VERSION = (& rustc --version)
        if ($LASTEXITCODE -ne 0 -or $env:AEGIS_RESEARCH_RUSTC_VERSION.Length -gt 512) { throw 'Actual rustc identity unavailable' }
    }
    $env:AEGIS_BUILD_TIMESTAMP = [DateTime]::UtcNow.ToString('o')
    $env:AEGIS_CARGO_LOCK_SHA256 = (Get-FileHash -LiteralPath Cargo.lock -Algorithm SHA256).Hash.ToLowerInvariant()
    . (Join-Path $PSScriptRoot 'release/KitCargoBuild.ps1')
    Invoke-WindowsKitCargoBuild -IncludeResearchOperators:$IncludeResearchOperators
    $version = & ./target/release/aegis-client.exe --version
    if ($LASTEXITCODE -ne 0 -or $version -notmatch 'chrome-like-tls' -or $version -notmatch 'chrome-like-quic') {
        throw 'Client binary lacks required TLS/QUIC build provenance'
    }
    # Refuse source/lock drift after build; identities came from this one clean source.
    if ((git rev-parse HEAD) -cne $source -or (git status --porcelain --untracked-files=normal) -or
        (Get-FileHash -LiteralPath Cargo.lock -Algorithm SHA256).Hash.ToLowerInvariant() -cne $env:AEGIS_CARGO_LOCK_SHA256) { throw 'Build source/lock changed' }
    $researchArgs=@()
    if ($IncludeResearchOperators) {
        $release=Join-Path $repo 'target/release'
        function Read-OwnBuildInfo([string]$Exe,[string]$Argument) {
            $p=[Diagnostics.Process]::new(); $p.StartInfo.FileName=$Exe; $p.StartInfo.Arguments=$Argument
            $p.StartInfo.UseShellExecute=$false; $p.StartInfo.RedirectStandardOutput=$true; $p.StartInfo.RedirectStandardError=$true
            $started=$false
            try {
                if (-not $p.Start()) { throw 'Build-info child did not start' }
                $started=$true
                $o=$p.StandardOutput.ReadToEndAsync(); $e=$p.StandardError.ReadToEndAsync()
                if (-not $p.WaitForExit(15000)) { $p.Kill(); if (-not $p.WaitForExit(2000)) { throw 'Build-info child terminal unknown' }; throw 'Build-info child timed out' }
                if (-not $o.Wait(1000) -or -not $e.Wait(1000)) { throw 'Build-info descendant pipe custody unknown' }
                if ($p.ExitCode -ne 0 -or $e.Result.Length -ne 0 -or $o.Result.Length -gt 16384) { throw 'Build-info child refused/oversized' }
                return ($o.Result | ConvertFrom-Json)
            } finally {
                if ($started -and -not $p.HasExited) { $p.Kill(); $null=$p.WaitForExit(2000) }
                $p.Dispose()
            }
        }
        $pair=[ordered]@{ schema='aegis_windows_research_operators_v1'
            measure=Read-OwnBuildInfo (Join-Path $release 'aegis-research-measure.exe') 'research-build-info'
            transport_lab=Read-OwnBuildInfo (Join-Path $release 'aegis-transport-lab.exe') '--build-info' }
        $bytes=[Text.Encoding]::UTF8.GetBytes(($pair | ConvertTo-Json -Depth 6))
        if ($bytes.Length -gt 16384) { throw 'Paired research metadata oversized' }
        . (Join-Path $PSScriptRoot 'release/ResearchStage.ps1')
        $stage=New-WindowsResearchStage -Release $release -StageParent (Join-Path $repo 'target') -Metadata $bytes
        $researchArgs=@('--research-operators',$stage)
        # The kit is still an engineering kit (client/winctl/Wintun + optional
        # tools). Only this independently inventoried sibling is research-only.
        $null=New-Item -ItemType Directory -Path $researchOutput -ErrorAction Stop
        $bin=Join-Path $researchOutput 'bin'; $docs=Join-Path $researchOutput 'research'
        $null=New-Item -ItemType Directory -Path $bin,$docs -ErrorAction Stop
        foreach ($name in @('aegis-measure','aegis-transport-lab')) {
            [IO.File]::Copy((Join-Path $stage ($name+'.exe')),(Join-Path $bin ($name+'.exe')),$false)
            $info=$(if ($name -eq 'aegis-measure') { $pair.measure } else { $pair.transport_lab })
            $capture=[Text.Encoding]::UTF8.GetBytes(($info | ConvertTo-Json -Depth 6))
            if ($capture.Length -eq 0 -or $capture.Length -gt 8192) { throw 'Research capture size refused' }
            $f=[IO.File]::Open((Join-Path $docs ($name+'.build-info.json')),[IO.FileMode]::CreateNew)
            try { $f.Write($capture,0,$capture.Length); $f.Flush($true) } finally { $f.Dispose() }
        }
        $guides=@(Get-Content -LiteralPath (Join-Path $repo 'packaging/research-operator-guides.txt'))
        if ($guides.Count -eq 0 -or $guides.Count -gt 32 -or @($guides | Select-Object -Unique).Count -ne $guides.Count) { throw 'Private research guide inventory refused' }
        foreach ($name in $guides) {
            if ($name -cnotmatch '^[a-z0-9][a-z0-9-]*\.md$') { throw 'Private research guide name refused' }
            $from=Join-Path $repo ('docs/research/'+$name)
            $item=Get-Item -Force -LiteralPath $from
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -eq 0 -or $item.Length -gt 8388608) { throw 'Private research guide input refused' }
            [IO.File]::Copy($from,(Join-Path $docs $name),$false)
        }
        [IO.File]::Copy((Join-Path $docs 'private-operator-delivery.md'),(Join-Path $docs 'README.md'),$false)
        function Invoke-OwnResearchBuilder([string[]]$Arguments,[int]$BoundMs) {
            $p=[Diagnostics.Process]::new(); $p.StartInfo.FileName=Join-Path $release 'aegis-measure.exe'
            $p.StartInfo.UseShellExecute=$false; $p.StartInfo.RedirectStandardOutput=$true; $p.StartInfo.RedirectStandardError=$true
            foreach ($argument in $Arguments) { $p.StartInfo.ArgumentList.Add($argument) }
            $started=$false
            try {
                if (-not $p.Start()) { throw 'Private research builder did not start' }
                $started=$true; $o=$p.StandardOutput.ReadToEndAsync(); $e=$p.StandardError.ReadToEndAsync()
                if (-not $p.WaitForExit($BoundMs)) { $p.Kill(); if (-not $p.WaitForExit(2000)) { throw 'Private research builder terminal unknown' }; throw 'Private research builder timed out' }
                if (-not $o.Wait(1000) -or -not $e.Wait(1000)) { throw 'Private research builder pipe custody unknown' }
                if ($p.ExitCode -ne 0 -or $e.Result.Length -ne 0 -or $o.Result.Length -gt 16384) { throw 'Private research builder refused/oversized' }
                return $o.Result
            } finally {
                if ($started -and -not $p.HasExited) { $p.Kill(); if (-not $p.WaitForExit(2000)) { throw 'Private research builder cleanup unconfirmed' } }
                $p.Dispose()
            }
        }
        $null=Invoke-OwnResearchBuilder @('research-tool-notices','--root',$repo,'--target','x86_64-pc-windows-msvc','--output',(Join-Path $docs 'THIRD-PARTY-NOTICES.txt')) 30000
        $releaseVersion=(Invoke-OwnResearchBuilder @('print-cargo-package-version','--root',$repo,'--package-name','aegis-server') 15000).Trim()
        $researchManifest=(Invoke-OwnResearchBuilder @('build-private-research-manifest','--bundle-dir',$researchOutput,'--version',$releaseVersion,'--arch','x86_64','--target-triple','x86_64-pc-windows-msvc','--git-sha',$source,'--cargo-lock-sha256',$env:AEGIS_CARGO_LOCK_SHA256) 15000) | ConvertFrom-Json
        if ($researchManifest.ok -ne $true -or $researchManifest.signed_release -ne $false -or $researchManifest.manifest_sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Private research manifest refused' }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($researchOutput,$researchArchive)
        # Inspect every member against the manifest over one retained public
        # build-artifact stream; never treat kit metadata as the research boundary.
        $manifestValue=Get-Content -Raw -LiteralPath (Join-Path $researchOutput 'research.manifest.json') | ConvertFrom-Json
        $expected=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
        foreach ($property in $manifestValue.files.PSObject.Properties) { $expected.Add($property.Name,[string]$property.Value) }
        $expected.Add('research.manifest.json',$researchManifest.manifest_sha256)
        $expected.Add('SHA256SUMS',(Get-FileHash -LiteralPath (Join-Path $researchOutput 'SHA256SUMS') -Algorithm SHA256).Hash.ToLowerInvariant())
        $stream=[IO.File]::Open($researchArchive,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $archiveLength=$stream.Length
            if ($archiveLength -le 0 -or $archiveLength -gt 2147483648) { throw 'Private research ZIP size refused' }
            $algorithm=[Security.Cryptography.SHA256]::Create()
            try { $researchArchiveSha=([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-','').ToLowerInvariant() } finally { $algorithm.Dispose() }
            $null=$stream.Seek(0,[IO.SeekOrigin]::Begin)
            $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read,$true)
            try {
                $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                if ($zip.Entries.Count -gt ($expected.Count+2)) { throw 'Private research ZIP inventory refused' }
                foreach ($entry in $zip.Entries) {
                    $name=$entry.FullName
                    if ($name.EndsWith('/')) {
                        if ($name -cnotin @('bin/','research/') -or $entry.Length -ne 0) { throw 'Private research ZIP directory refused' }
                        continue
                    }
                    if (-not $expected.ContainsKey($name) -or -not $seen.Add($name)) { throw 'Private research ZIP unknown/duplicate member refused' }
                    $cap=$(if ($name.StartsWith('bin/')) { 536870912 } elseif ($name.EndsWith('.build-info.json')) { 8192 } elseif ($name -ceq 'research.manifest.json') { 65536 } elseif ($name -ceq 'SHA256SUMS') { 16384 } else { 8388608 })
                    if ($entry.Length -le 0 -or $entry.Length -gt $cap -or (($entry.ExternalAttributes -shr 16) -band 0xf000) -notin @(0,0x8000)) { throw 'Private research ZIP member size/type refused' }
                    $member=$entry.Open(); $hash=[Security.Cryptography.SHA256]::Create()
                    try {
                        $buffer=[byte[]]::new(65536); $count=0L
                        while (($n=$member.Read($buffer,0,$buffer.Length)) -ne 0) {
                            $count+=$n
                            if ($count -gt $entry.Length -or $count -gt $cap) { throw 'Private research ZIP inflated member refused' }
                            $null=$hash.TransformBlock($buffer,0,$n,$buffer,0)
                        }
                        $null=$hash.TransformFinalBlock([byte[]]::new(0),0,0)
                        $digest=([BitConverter]::ToString($hash.Hash)).Replace('-','').ToLowerInvariant()
                        if ($count -ne $entry.Length -or $digest -cne $expected[$name]) { throw 'Private research ZIP member hash refused' }
                    } finally { $hash.Dispose(); $member.Dispose() }
                }
                if ($seen.Count -ne $expected.Count -or $stream.Length -ne $archiveLength) { throw 'Private research ZIP completeness refused' }
            } finally { $zip.Dispose() }
        } finally { $stream.Dispose() }
        $researchRecord=[ordered]@{ distribution='private_research_only'; signed_release=$false;
            source_commit=$source; target_triple='x86_64-pc-windows-msvc';
            archive=[IO.Path]::GetFileName($researchArchive);
            archive_sha256=$researchArchiveSha;
            manifest_sha256=$researchManifest.manifest_sha256; automatic_service_activation=$false; installed_fullwide_owner=$false }

    }
    $result = & ./target/release/aegis-winctl.exe package build --client ./target/release/aegis-client.exe --winctl ./target/release/aegis-winctl.exe --wintun ./target/wintun-pinned --output $kit --source-commit $source @researchArgs
    if ($LASTEXITCODE -ne 0) { throw 'Windows package verification failed' }
    $manifest = $result | ConvertFrom-Json
    # Refuse inconsistent builder/manifest metadata before recording the
    # unsigned candidate's platform. This is not release signing or an
    # installed-machine acceptance check.
    $manifestPath = Join-Path $kit 'manifest.json'
    $manifestFile = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($manifest.ok -ne $true -or $manifest.signed_release -ne $false -or
        $manifest.manifest_sha256 -cne $manifestHash -or
        $manifestFile.source_commit -cne $source -or $manifestFile.signed_release -ne $false -or
        $manifestFile.platform -cnotin @('windows-x86_64', 'windows-aarch64') -or
        ($manifestFile.schema -ne $(if ($IncludeResearchOperators) { 4 } else { 2 })) -or
        ($IncludeResearchOperators -and $manifestFile.platform -cne 'windows-x86_64')) {
        throw 'Unsigned Windows kit delivery identity rejected'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($kit, $archive)
    # Verify the actual ZIP member set and every archived payload against the
    # pre-archive manifest hash. The verifier returns the hash of those same
    # inspected ZIP bytes for the unsigned delivery record.
    $python = (Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $archiveArgs = @('--archive', $archive, '--source-commit', $source,
        '--manifest-sha256', $manifestHash)
    if ($IncludeResearchOperators) { $archiveArgs += '--research' }
    $archiveResult = & $python -I -B (Join-Path $repo 'scripts/windows/verify-unsigned-kit-archive.py') @archiveArgs
    if ($LASTEXITCODE -ne 0) { throw 'Unsigned Windows kit archive verification failed' }
    $archiveEvidence = $archiveResult | ConvertFrom-Json
    if ($archiveEvidence.source_commit -cne $source -or
        $archiveEvidence.platform -cne $manifestFile.platform -or
        $archiveEvidence.manifest_sha256 -cne $manifestHash -or
        $archiveEvidence.archive_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $archiveEvidence.signed_release -ne $false) {
        throw 'Unsigned Windows kit archive verifier identity rejected'
    }
    $record = [ordered]@{
        source_commit = $source
        platform = $manifestFile.platform
        client_version = $version
        archive = $archive
        archive_sha256 = $archiveEvidence.archive_sha256
        manifest_sha256 = $manifestHash
        signed_release = $false
    }
    if ($IncludeResearchOperators) {
        $record.research_operators = $true
        $record.distribution_scope = 'private_unsigned_engineering_candidate'
        $record.research_delivery = $researchRecord
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Depth 6))
    $file = [IO.File]::Open($delivery, [IO.FileMode]::CreateNew)
    try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
    $record | ConvertTo-Json -Depth 6
} finally { Pop-Location }
