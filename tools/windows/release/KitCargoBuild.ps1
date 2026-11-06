# Each Cargo invocation has one package feature identity. Research operators
# must not overwrite the client's compiled transport provenance.
function Invoke-WindowsKitCargoBuild {
    [CmdletBinding()]
    param([switch]$IncludeResearchOperators)
    $priorKitFeatures = $env:AEGIS_BUILD_FEATURES
    try {
        $env:AEGIS_BUILD_FEATURES = 'chrome-like-tls,chrome-like-quic'
        cargo build --locked --release -p aegis-client -p aegis-winctl --no-default-features --features 'aegis-client/chrome-like-tls,aegis-client/chrome-like-quic'
        if ($LASTEXITCODE -ne 0) { throw 'Windows full transport build failed' }
        if ($IncludeResearchOperators) {
            $env:AEGIS_BUILD_FEATURES = 'none'
            cargo build --locked --release -p aegis-measure -p aegis-transport-lab --no-default-features --bins
            if ($LASTEXITCODE -ne 0) { throw 'Windows research operator build failed' }
        }
    } finally {
        $env:AEGIS_BUILD_FEATURES = $priorKitFeatures
    }
}
