[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepoRoot)
$ErrorActionPreference = 'Stop'
. (Join-Path $RepoRoot 'tools/windows/release/ResearchStage.ps1')
$root = Join-Path ([IO.Path]::GetTempPath()) ('aegis-research-stage-test-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root -ErrorAction Stop
$release = Join-Path $root 'release'
$null = New-Item -ItemType Directory -Path $release -ErrorAction Stop
try {
    foreach ($name in @('aegis-research-measure.exe', 'aegis-transport-lab.exe')) {
        [IO.File]::WriteAllBytes((Join-Path $release $name), [byte[]](1, 2, 3))
    }
    [IO.File]::WriteAllBytes((Join-Path $release 'aegis-measure.exe'), [byte[]](9, 9, 9))
    $sources = @{ 'aegis-measure.exe' = 'aegis-research-measure.exe'; 'aegis-transport-lab.exe' = 'aegis-transport-lab.exe' }
    # A predecessor left this leaf behind; neither attempt may overwrite or consume it.
    $old = Join-Path $release 'research-operators.json'
    [IO.File]::WriteAllText($old, 'retained predecessor metadata')
    $before = (Get-FileHash -LiteralPath $old -Algorithm SHA256).Hash
    $first = New-WindowsResearchStage -Release $release -StageParent $root -Metadata ([byte[]](4, 5, 6))
    $second = New-WindowsResearchStage -Release $release -StageParent $root -Metadata ([byte[]](7, 8, 9))
    if ($first -ceq $second -or (Get-FileHash -LiteralPath $old -Algorithm SHA256).Hash -cne $before) {
        throw 'Repeat attempt overwrote or reused predecessor'
    }
    foreach ($stage in @($first, $second)) {
        if (@(Get-ChildItem -LiteralPath $stage).Count -ne 3) { throw 'Staged pair inventory changed' }
        foreach ($name in @('aegis-measure.exe', 'aegis-transport-lab.exe')) {
            if ((Get-FileHash -LiteralPath (Join-Path $stage $name) -Algorithm SHA256).Hash -cne
                (Get-FileHash -LiteralPath (Join-Path $release $sources[$name]) -Algorithm SHA256).Hash) {
                throw 'Staged executable bytes differ'
            }
        }
    }
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $first 'research-operators.json'))) -cne 'BAUG' -or
        [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $second 'research-operators.json'))) -cne 'BwgJ') {
        throw 'Per-attempt metadata custody failed'
    }
    $count = @(Get-ChildItem -LiteralPath $root).Count
    $refused = $false
    try { $null = New-WindowsResearchStage -Release $release -StageParent $root -Metadata ([byte[]]::new(16385)) }
    catch { $refused = $true }
    if (-not $refused -or @(Get-ChildItem -LiteralPath $root).Count -ne $count) { throw 'Oversized metadata created stage' }
    # The unrestricted tool remains present: it is never a missing-role fallback.
    Remove-Item -LiteralPath (Join-Path $release 'aegis-research-measure.exe')
    $refused = $false
    try { $null = New-WindowsResearchStage -Release $release -StageParent $root -Metadata ([byte[]](1)) }
    catch { $refused = $true }
    if (-not $refused -or @(Get-ChildItem -LiteralPath $root).Count -ne $count) { throw 'Missing restricted producer used full fallback or created stage' }
    [IO.File]::WriteAllBytes((Join-Path $release 'aegis-research-measure.exe'), [byte[]](1, 2, 3))
    Remove-Item -LiteralPath (Join-Path $release 'aegis-transport-lab.exe')
    $refused = $false
    try { $null = New-WindowsResearchStage -Release $release -StageParent $root -Metadata ([byte[]](1)) }
    catch { $refused = $true }
    if (-not $refused -or @(Get-ChildItem -LiteralPath $root).Count -ne $count) { throw 'Missing pair created stage' }
    Write-Output 'Research staging: PASS (two distinct retained attempts, prior metadata unchanged, exact restricted copies, three pre-stage refusals; synthetic bytes, no PE/signature/build acceptance)'
} finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
