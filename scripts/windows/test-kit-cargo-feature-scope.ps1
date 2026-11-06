[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepoRoot)
$ErrorActionPreference = 'Stop'
. (Join-Path $RepoRoot 'tools/windows/release/KitCargoBuild.ps1')
$priorTestFeatures = $env:AEGIS_BUILD_FEATURES
$priorTestExit = $global:LASTEXITCODE
$script:kitCalls = [Collections.Generic.List[object]]::new()
$script:kitFailAt = 0
$script:kitThrowAt = 0
# This scoped command sentinel never launches Cargo, an executable or a signer.
function cargo {
    $script:kitCalls.Add([pscustomobject]@{ Arguments = @($args); Features = $env:AEGIS_BUILD_FEATURES })
    $global:LASTEXITCODE = 0
    if ($script:kitCalls.Count -eq $script:kitThrowAt) { throw 'Synthetic Cargo launch refusal' }
    if ($script:kitCalls.Count -eq $script:kitFailAt) { $global:LASTEXITCODE = 17 }
}
function Assert-KitCalls([int]$Count) {
    if ($script:kitCalls.Count -ne $Count) { throw 'Build continuation count changed' }
    $first = $script:kitCalls[0]
    $clientArgs = 'build|--locked|--release|-p|aegis-client|-p|aegis-winctl|--no-default-features|--features|aegis-client/chrome-like-tls,aegis-client/chrome-like-quic'
    if (($first.Arguments -join '|') -cne $clientArgs -or
        $first.Features -cne 'chrome-like-tls,chrome-like-quic') { throw 'Client build identity/arguments changed' }
    if ($Count -eq 2) {
        $second = $script:kitCalls[1]
        $operatorArgs = 'build|--locked|--release|-p|aegis-measure|-p|aegis-transport-lab|--no-default-features|--bins'
        if (($second.Arguments -join '|') -cne $operatorArgs -or $second.Features -cne 'none') {
            throw 'Research build borrowed client feature identity/arguments'
        }
    }
}
try {
    $cases = 0
    foreach ($initial in @($null, 'retained-caller-features')) {
        foreach ($research in @($false, $true)) {
            foreach ($failure in @('success', 'client-exit', 'client-launch', 'operator-exit', 'operator-launch')) {
                if (-not $research -and $failure.StartsWith('operator-')) { continue }
                $env:AEGIS_BUILD_FEATURES = $initial
                $script:kitCalls.Clear(); $script:kitFailAt = 0; $script:kitThrowAt = 0
                switch ($failure) {
                    'client-exit' { $script:kitFailAt = 1 }
                    'client-launch' { $script:kitThrowAt = 1 }
                    'operator-exit' { $script:kitFailAt = 2 }
                    'operator-launch' { $script:kitThrowAt = 2 }
                }
                $refused = $false
                try { Invoke-WindowsKitCargoBuild -IncludeResearchOperators:$research } catch { $refused = $true }
                if ($refused -ne ($failure -cne 'success')) { throw 'Build error was suppressed or invented' }
                $count = if ($research -and -not $failure.StartsWith('client-')) { 2 } else { 1 }
                Assert-KitCalls $count
                if ($env:AEGIS_BUILD_FEATURES -cne $initial) { throw 'Caller feature environment was not restored' }
                $cases++
            }
        }
    }
    if ($cases -ne 16) { throw 'Feature-scope test coverage changed' }
    Write-Output 'Windows kit feature scope: PASS (16 sentinel cases; exact separate package arguments, first/second failure and caller environment restoration; no actual PE/build/signature acceptance)'
} finally {
    $env:AEGIS_BUILD_FEATURES = $priorTestFeatures
    $global:LASTEXITCODE = $priorTestExit
    Remove-Item Function:cargo
}
