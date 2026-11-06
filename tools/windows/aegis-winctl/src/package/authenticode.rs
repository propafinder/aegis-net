//! Literal PowerShell argument routing and owned static verification script.
#[cfg(any(windows, test))]
use std::{path::Path, process::Command};

#[cfg(test)]
#[path = "authenticode_tests.rs"]
mod tests;

#[cfg(any(windows, test))]
const SCRIPT: &str = r#"
param([string]$Package,[string]$PublisherPin,[string]$StructuralVerifier,[string]$Research)
$ErrorActionPreference='Stop'
function Cert-Sha256($Cert) {
  $sha=[Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Cert.RawData))).Replace('-','').ToLowerInvariant() }
  finally { $sha.Dispose() }
}
$names=@('aegis-client.exe','aegis-winctl.exe')
if($Research -eq '1') { $names+=@('aegis-measure.exe','aegis-transport-lab.exe') }
foreach($name in $names) {
  $file=Join-Path $Package $name
  $sig=Get-AuthenticodeSignature -LiteralPath $file
  if($sig.Status -ne 'Valid') { throw "invalid Authenticode chain: $name" }
  if((Cert-Sha256 $sig.SignerCertificate) -ne $PublisherPin) { throw "publisher pin mismatch: $name" }
  if($null -eq $sig.TimeStamperCertificate) { throw "timestamp missing: $name" }
  $global:LASTEXITCODE=0
  & $StructuralVerifier -File $file -PublisherCertificateSha256 $PublisherPin -RequireRfc3161 -VerifyMessageImprint -VerifyTimestampChain
  if(-not $? -or $global:LASTEXITCODE -ne 0) { throw "structural RFC3161 verification failed: $name" }
}
$wintun=Join-Path $Package 'wintun.dll'
if((Get-AuthenticodeSignature -LiteralPath $wintun).Status -ne 'Valid') { throw 'invalid Wintun Authenticode chain' }
if((Get-FileHash -LiteralPath $wintun -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce') { throw 'Wintun hash mismatch' }
"#;

#[cfg(any(windows, test))]
fn command(
    powershell: &Path,
    script: &Path,
    package: &Path,
    publisher_pin: &str,
    structural_verifier: &Path,
    research: bool,
) -> Command {
    let mut command = Command::new(powershell);
    command
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
        .arg(script)
        .arg(package)
        .arg(publisher_pin)
        .arg(structural_verifier)
        .arg(if research { "1" } else { "0" });
    command
}

#[cfg(windows)]
struct VerificationScript {
    path: tempfile::TempPath,
    lease: super::adapter::AdapterLease,
}

#[cfg(windows)]
impl VerificationScript {
    fn create() -> Result<Self, super::WinctlError> {
        use std::io::Write;
        let parent = std::env::temp_dir().canonicalize()?;
        let text = parent.to_str().ok_or_else(super::invalid)?;
        let parent = std::path::PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(text));
        aegis_core::windows_file::trusted_directory(&parent)?;
        let mut script = tempfile::Builder::new()
            .prefix("aegis-authenticode-")
            .suffix(".ps1")
            // Retain an unknown or failed partial file instead of blind Drop deletion.
            .disable_cleanup(true)
            .make_in(&parent, |path| {
                aegis_core::windows_file::create_private_file(path, false)
            })?;
        script.write_all(SCRIPT.as_bytes())?;
        script.as_file().sync_all()?;
        let path = script.into_temp_path();
        let lease = super::adapter::AdapterLease::acquire(&path, &super::hash(SCRIPT.as_bytes()))?;
        Ok(Self { path, lease })
    }

    fn finish(self) -> Result<(), super::WinctlError> {
        // Verify while write/delete and ancestry replacement are still denied.
        self.lease.verify()?;
        // Keep the private static script. Releasing the lease before unlinking
        // by name would lose the bound file/ancestry custody. TempPath's Drop
        // cleanup was disabled at creation, including every failure path.
        drop(self.lease);
        Ok(())
    }
}

#[cfg(windows)]
pub(super) fn invoke(
    powershell: &Path,
    package: &Path,
    publisher_pin: &str,
    structural_verifier: &Path,
    research: bool,
) -> Result<std::process::ExitStatus, super::WinctlError> {
    let script = VerificationScript::create()?;
    let result = command(
        powershell,
        &script.path,
        package,
        publisher_pin,
        structural_verifier,
        research,
    )
    .status();
    // Always verify before releasing leases; retain the private static script.
    let custody = script.finish();
    let status = result?;
    custody?;
    Ok(status)
}
