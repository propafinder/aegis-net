[CmdletBinding()]
param([switch]$Bootstrap)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$localTools = Join-Path $repo 'target/windows-build-tools'
$cmake = Join-Path $localTools 'cmake/data/bin'
function Find-LocalNinja {
    # The pinned wheel installs ninja.exe through its .data/scripts entry.
    # pip's target scheme may use bin or Scripts; do not assume package data.
    foreach ($relative in @('bin', 'Scripts', 'ninja/data/bin')) {
        $candidate = Join-Path $localTools $relative
        if (Test-Path -LiteralPath (Join-Path $candidate 'ninja.exe') -PathType Leaf) { return $candidate }
    }
    return (Join-Path $localTools 'bin')
}
function Get-PinnedWindowsBuildToolsRequirements([object]$Identity, [string]$RequirementsRoot) {
    # The shipped native build owners are x64. Python3.7 would require
    # additional CMake dependencies outside this frozen three-wheel closure.
    if ($Identity.implementation -cne 'cpython' -or $Identity.platform -cne 'win_amd64' -or
        $Identity.pointer_bits -ne 64 -or $Identity.major -ne 3 -or $Identity.minor -lt 8) {
        throw 'Windows build-tool bootstrap requires CPython 3.8+ for win_amd64'
    }
    $requirements = Join-Path $RequirementsRoot 'build-tools-win_amd64.requirements.txt'
    $entry = Get-Item -LiteralPath $requirements -Force -ErrorAction Stop
    if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $entry.Length -le 0 -or $entry.Length -gt 4096) {
        throw 'Pinned Windows build-tool requirements refused'
    }
    return $entry.FullName
}
$ninja = Find-LocalNinja
$clang = Join-Path $localTools 'clang/native'
if ($Bootstrap) {
    # Local build dependencies only; no system Python or PATH installation.
    # Rust caches can retain these directories while pruning their binaries.
    # Replace incomplete local package directories instead of pip silently
    # keeping them and reporting a successful but unusable bootstrap.
    $python = (Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $identityOutput = & $python -I -B -c 'import json,struct,sys,sysconfig; print(json.dumps({"implementation":sys.implementation.name,"platform":sysconfig.get_platform().replace("-","_"),"pointer_bits":struct.calcsize("P")*8,"major":sys.version_info.major,"minor":sys.version_info.minor}))'
    if ($LASTEXITCODE -ne 0 -or $identityOutput.Length -gt 512) { throw 'Windows build-tool Python identity unavailable' }
    try { $identity = $identityOutput | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Windows build-tool Python identity refused' }
    $requirements = Get-PinnedWindowsBuildToolsRequirements $identity $PSScriptRoot
    $previousPipConfig = [Environment]::GetEnvironmentVariable('PIP_CONFIG_FILE', 'Process')
    try {
        # --isolated alone still permits global/site configuration. NUL is
        # Python's Windows os.devnull and disables all pip configuration files.
        [Environment]::SetEnvironmentVariable('PIP_CONFIG_FILE', 'nul', 'Process')
        & $python -I -m pip --isolated --disable-pip-version-check --no-input install --upgrade --target $localTools --require-hashes --only-binary=:all: --no-deps --no-index --no-cache-dir --requirement $requirements
        if ($LASTEXITCODE -ne 0) { throw 'Windows native build dependency bootstrap failed' }
    } finally {
        [Environment]::SetEnvironmentVariable('PIP_CONFIG_FILE', $previousPipConfig, 'Process')
    }
    $ninja = Find-LocalNinja
}
if ($Bootstrap) {
    foreach ($required in @((Join-Path $cmake 'cmake.exe'), (Join-Path $ninja 'ninja.exe'), (Join-Path $clang 'libclang.dll'))) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Pinned native build tool is missing after bootstrap: $required" }
    }
}
if (Test-Path -LiteralPath $cmake) { $env:PATH = "$cmake;$ninja;$env:PATH" }
$env:AEGIS_NATIVE_NINJA_PATH = $ninja
if (Test-Path -LiteralPath (Join-Path $clang 'libclang.dll')) { $env:LIBCLANG_PATH = $clang }
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) { throw 'CMake is required; run prepare-build.ps1 -Bootstrap' }
if (-not (Get-Command ninja -ErrorAction SilentlyContinue)) { throw 'Ninja is required; run prepare-build.ps1 -Bootstrap' }
# Use the native CMake binary, not pip's Python entry-point shim beside ninja.
$env:CMAKE = (Get-Command cmake -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$env:AEGIS_NATIVE_CMAKE_PATH = Split-Path -Parent $env:CMAKE
& $env:CMAKE --version
if ($LASTEXITCODE -ne 0) { throw 'CMake exists but cannot execute' }
& ninja --version
if ($LASTEXITCODE -ne 0) { throw 'Ninja exists but cannot execute' }
if (-not $env:LIBCLANG_PATH) { throw 'Set LIBCLANG_PATH or run prepare-build.ps1 -Bootstrap' }
# CMake 3.31 cannot generate VS 2026 projects. Use the pinned Ninja backend
# with the MSVC compiler/environment discovered by the Rust cmake/cc crates.
$env:CMAKE_GENERATOR = 'Ninja'
# AWS-LC's pinned x64 non-FIPS crate includes prebuilt NASM objects.
$env:AWS_LC_SYS_PREBUILT_NASM = '1'
$env:CARGO_INCREMENTAL = '0'
