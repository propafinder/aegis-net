# Private per-attempt staging only. Final Rust packaging validates PE and metadata.
function New-WindowsResearchStage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Release,
        [Parameter(Mandatory)][string]$StageParent,
        [Parameter(Mandatory)][byte[]]$Metadata
    )
    if ($Metadata.Length -eq 0 -or $Metadata.Length -gt 16384) { throw 'Paired research metadata size refused' }
    foreach ($directory in @($Release, $StageParent)) {
        $item = Get-Item -LiteralPath $directory -ErrorAction Stop
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Research staging directory refused'
        }
    }
    $sources = [ordered]@{
        'aegis-measure.exe' = 'aegis-research-measure.exe'
        'aegis-transport-lab.exe' = 'aegis-transport-lab.exe'
    }
    $names = @($sources.Keys)
    $hashes = @{}
    foreach ($name in $names) {
        $path = Join-Path $Release $sources[$name]
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.Length -eq 0 -or $item.Length -gt 268435456) { throw 'Research staging input refused' }
        $hashes[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    $stage = Join-Path $StageParent ('research-operators-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $stage -ErrorAction Stop
    # Retain this owned attempt, including a failed prefix; never overwrite an old stage.
    foreach ($name in $names) {
        $source = Join-Path $Release $sources[$name]
        $copy = Join-Path $stage $name
        [IO.File]::Copy($source, $copy, $false)
        if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -cne $hashes[$name] -or
            (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -cne $hashes[$name]) {
            throw 'Research staging source changed'
        }
    }
    $meta = Join-Path $stage 'research-operators.json'
    $file = [IO.File]::Open($meta, [IO.FileMode]::CreateNew)
    try { $file.Write($Metadata, 0, $Metadata.Length); $file.Flush($true) } finally { $file.Dispose() }
    return $stage
}
