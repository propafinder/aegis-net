[CmdletBinding()]
param([string]$RepoRoot = (Join-Path $PSScriptRoot "../.."))
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -lt 7) { throw "PowerShell 7 required for bounded admission contract" }
$exe = (Get-Process -Id $PID).Path
$root = [IO.Path]::GetFullPath($RepoRoot)
$temp = Join-Path ([IO.Path]::GetTempPath()) ("aegis-private-endpoint-contract-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temp | Out-Null
$count = 0
try {
    $owners = @(
        @{ Name = "audit"; Path = "scripts/windows/audit-service-bundle.ps1"; Boundary = "function Write-Utf8";
           Inputs = @{ ExpectedFront = "front.example.invalid:443"; ExpectedServerName = "front.example.invalid"; ExpectedOrigin = "192.0.2.44:443" } },
        @{ Name = "baseline"; Path = "scripts/windows/run-service-baseline-proof.ps1"; Boundary = "function Test-IsAdministrator";
           Inputs = @{ RelayServer = "relay.example.invalid:443"; ExpectedEgressIp = "192.0.2.45" } }
    )
    foreach ($owner in $owners) {
        $source = [IO.File]::ReadAllText((Join-Path $root $owner.Path))
        $index = $source.IndexOf($owner.Boundary, [StringComparison]::Ordinal)
        if ($index -lt 0 -or $source.IndexOf($owner.Boundary, $index + 1, [StringComparison]::Ordinal) -ge 0) { throw "admission boundary invalid" }
        $prefix = Join-Path $temp ($owner.Name + ".ps1")
        [IO.File]::WriteAllText($prefix, $source.Substring(0, $index) + "`n[Console]::Out.WriteLine('ADMITTED')`n")
        $cases = @(@{ Name = "positive"; Field = ""; Value = ""; Pass = $true })
        foreach ($field in $owner.Inputs.Keys) {
            $cases += @{ Name = "missing-" + $field; Field = $field; Value = $null; Pass = $false }
            $cases += @{ Name = "malformed-" + $field; Field = $field; Value = " "; Pass = $false }
        }
        $endpointFields = if ($owner.Name -eq "audit") { @("ExpectedFront", "ExpectedOrigin") } else { @("RelayServer") }
        foreach ($field in $endpointFields) {
            $cases += @{ Name = "valid-ipv4-" + $field; Field = $field; Value = "192.0.2.46:443"; Pass = $true }
            $cases += @{ Name = "valid-ipv6-" + $field; Field = $field; Value = "[2001:db8::46]:443"; Pass = $true }
            foreach ($badEndpoint in @("[::::]:443", "relay.example.invalid:0", "relay.example.invalid:65536", "999.1.1.1:443", "bad..example.invalid:443", "https://relay.example.invalid:443")) {
                $cases += @{ Name = "invalid-endpoint-" + $field; Field = $field; Value = $badEndpoint; Pass = $false }
            }
        }
        if ($owner.Name -eq "baseline") {
            $cases += @{ Name = "bad-ip"; Field = "ExpectedEgressIp"; Value = "not-an-ip"; Pass = $false }
        } else {
            foreach ($badSni in @("", "bad..example.invalid", "-bad.example.invalid", "bad_name.example.invalid", "front.example.invalid:443", "https://front.example.invalid", "192.0.2.47")) {
                $cases += @{ Name = "invalid-sni"; Field = "ExpectedServerName"; Value = $badSni; Pass = $false }
            }
        }
        foreach ($case in $cases) {
            $arguments = @("-NoProfile", "-NonInteractive", "-File", $prefix)
            foreach ($field in $owner.Inputs.Keys) {
                if ($field -eq $case.Field -and $null -eq $case.Value) { continue }
                $arguments += "-" + $field
                $arguments += $(if ($field -eq $case.Field) { $case.Value } else { $owner.Inputs[$field] })
            }
            $info = [Diagnostics.ProcessStartInfo]::new($exe)
            $info.UseShellExecute = $false
            $info.RedirectStandardOutput = $true
            $info.RedirectStandardError = $true
            foreach ($argument in $arguments) { $info.ArgumentList.Add($argument) }
            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $info
            $started = $false
            try {
                [void]$process.Start()
                $started = $true
                $outTask = $process.StandardOutput.ReadToEndAsync()
                $errTask = $process.StandardError.ReadToEndAsync()
                if (-not $process.WaitForExit(10000)) { $process.Kill(); [void]$process.WaitForExit(3000); throw "admission case timeout" }
                $out = $outTask.GetAwaiter().GetResult()
                $err = $errTask.GetAwaiter().GetResult()
                if ($case.Pass) {
                    if ($process.ExitCode -ne 0 -or $out.Trim() -ne "ADMITTED") { throw "positive admission control failed" }
                } elseif ($process.ExitCode -eq 0 -or $out.Contains("ADMITTED") -or -not $err.Contains("must be an explicit")) { throw "invalid input admitted" }
                $count++
            } finally {
                if ($started -and -not $process.HasExited) {
                    $process.Kill()
                    if (-not $process.WaitForExit(3000)) { throw "admission child cleanup failed" }
                }
                $process.Dispose()
            }
        }
    }
    Write-Output ("PASS explicit-input admission cases=" + $count + "; service and network not exercised")
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
