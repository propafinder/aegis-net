//! An exact client-only Windows kit. Integrity pins are supplied independently;
//! this local developer package does not claim a release signature.
use super::WinctlError;
#[cfg(windows)]
mod adapter;
mod authenticode;
mod research;
pub(super) mod trust;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const MAX_BINARY: u64 = 256 * 1024 * 1024;
// Project terms only; this is not a complete third-party notice inventory.
const PROJECT_LICENSE_FILES: [(&str, &[u8]); 3] = [
    (
        "LICENSE-APACHE",
        include_bytes!("../../../../LICENSE-APACHE"),
    ),
    ("LICENSE-MIT", include_bytes!("../../../../LICENSE-MIT")),
    ("NOTICE", include_bytes!("../../../../NOTICE")),
];
const README: &str = concat!(
    "AEGIS Windows developer kit\n\nFor legacy/offline profiles, use aegis-winctl client prepare-config --help,\nthen aegis-winctl client install --help. For managed online device identities\nand the private HTTPS bridge, follow the appended native preparation guide. Supply a manifest SHA-256 obtained\nthrough an authenticated channel, or a detached publisher signature.\nThis developer kit is not a signed stable release.\nThe client includes Chrome-like TLS and QUIC backends. A windows_tunnel\nconfiguration selects the signed Wintun system ingress. The full tunnel\nrequires Administrator or its LocalSystem service.\nUse aegis-winctl client connect, disconnect and doctor for an installed client.\nStopping the service retains the kill switch; client disconnect removes\nthe owned tunnel routes and filters to restore ordinary networking.\nNo access configuration, CA, credentials, server or source is included.\n",
    "\nManaged online identity and private HTTPS bridge\n\n",
    include_str!("../../../../docs/operations/https-bridge.md"),
);
#[cfg(windows)]
#[derive(Args, Default)]
pub(super) struct AuthenticodePolicyArgs {
    /// Independently provisioned v2 policy; never inferred from the package.
    #[arg(long)]
    pub(super) authenticode_policy: Option<PathBuf>,
}

#[cfg(windows)]
impl AuthenticodePolicyArgs {
    pub(super) fn path(&self) -> Option<&Path> {
        self.authenticode_policy.as_deref()
    }
}

#[derive(Args)]
pub(super) struct PackageArgs {
    #[command(subcommand)]
    command: PackageCommand,
}
#[derive(Subcommand)]
enum PackageCommand {
    Build {
        #[arg(long)]
        client: PathBuf,
        #[arg(long)]
        winctl: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        source_commit: String,
        /// Extracted official Wintun directory containing the matching bin/amd64
        /// or bin/arm64 DLL and LICENSE.txt.
        #[arg(long)]
        wintun: Option<PathBuf>,
        /// Explicit private research pair; directory has two EXEs and research-operators.json.
        #[arg(long)]
        research_operators: Option<PathBuf>,
    },
    Verify {
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        manifest_sha256: String,
    },
    /// Verify a detached Ed25519 manifest signature using the pinned AEGIS publisher key.
    VerifySignature {
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        /// Independently provisioned policy; never load this from the package.
        #[arg(long)]
        authenticode_policy: Option<PathBuf>,
    },
    /// Verify the signed Windows provenance envelope against trusted CI inputs.
    VerifyProvenance {
        #[arg(long)]
        provenance: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        expected_source_commit: String,
        #[arg(long)]
        expected_workflow: String,
        #[arg(long)]
        expected_ref: String,
        #[arg(long)]
        expected_manifest_sha256: String,
        #[arg(long)]
        expected_inner_zip_sha256: String,
        #[arg(long)]
        expected_github_artifact_digest: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    schema: u32,
    platform: String,
    source_commit: String,
    signed_release: bool,
    /// False/missing retains the old closed inventory; new kits require all three.
    #[serde(default)]
    project_licenses: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authenticode: Option<Authenticode>,
    files: BTreeMap<String, String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authenticode {
    publisher_certificate_sha256: String,
    timestamp: String,
    executables: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsProvenance {
    schema: String,
    source_commit: String,
    workflow: String,
    r#ref: String,
    manifest_sha256: String,
    inner_zip_sha256: String,
    github_artifact_digest: String,
}
#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedAuthenticodePolicy {
    schema: String,
    publisher_certificate_sha256: Option<String>,
    timestamp_protocol: String,
    timestamp_attribute_oid: String,
    rfc3161_structural_verifier: Option<PathBuf>,
    provider_attestation_verifier: Option<PathBuf>,
    authenticode_provider_sha256: Option<String>,
    rfc3161_structural_verifier_sha256: Option<String>,
    provider_attestation_verifier_sha256: Option<String>,
    wintun_sha256: String,
}
pub(super) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn invalid() -> WinctlError {
    WinctlError::ArtifactValidation("Windows package identity, file set or hash rejected".into())
}
pub(super) fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>, WinctlError> {
    #[cfg(windows)]
    aegis_core::windows_file::reject_reparse_ancestry(path)?;
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > limit {
        return Err(invalid());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid());
    }
    Ok(bytes)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PeMachine {
    X64,
    Arm64,
}

impl PeMachine {
    fn platform(self) -> &'static str {
        match self {
            Self::X64 => "windows-x86_64",
            Self::Arm64 => "windows-aarch64",
        }
    }

    fn wintun(self) -> (&'static str, &'static str) {
        match self {
            Self::X64 => (
                "bin/amd64/wintun.dll",
                "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
            ),
            Self::Arm64 => (
                "bin/arm64/wintun.dll",
                "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
            ),
        }
    }

    fn from_platform(value: &str) -> Result<Self, WinctlError> {
        match value {
            "windows-x86_64" => Ok(Self::X64),
            "windows-aarch64" => Ok(Self::Arm64),
            _ => Err(invalid()),
        }
    }
}

fn pe_machine(bytes: &[u8]) -> Result<PeMachine, WinctlError> {
    if bytes.len() < 64 || &bytes[..2] != b"MZ" {
        return Err(invalid());
    }
    let offset = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
    match bytes.get(offset..offset.saturating_add(6)) {
        Some(b"PE\0\0\x64\x86") => Ok(PeMachine::X64),
        Some(b"PE\0\0\x64\xaa") => Ok(PeMachine::Arm64),
        _ => Err(invalid()),
    }
}

fn verify_pe(bytes: &[u8], expected: PeMachine) -> Result<(), WinctlError> {
    if pe_machine(bytes)? != expected {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn verify(
    path: &Path,
    expected: &str,
) -> Result<BTreeMap<String, Vec<u8>>, WinctlError> {
    verify_with_policy(path, expected, None).map(|(files, _)| files)
}
#[cfg(any(windows, test))]
pub(super) fn verify_for_install(
    path: &Path,
    expected: &str,
    trusted_policy: Option<&Path>,
) -> Result<BTreeMap<String, Vec<u8>>, WinctlError> {
    verify_with_policy(path, expected, trusted_policy).map(|(files, _)| files)
}

fn verify_with_policy(
    path: &Path,
    expected: &str,
    trusted_policy: Option<&Path>,
) -> Result<(BTreeMap<String, Vec<u8>>, Manifest), WinctlError> {
    if expected.len() != 64 || !expected.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let raw = read_regular(&path.join("manifest.json"), 65536)?;
    if !hash(&raw).eq_ignore_ascii_case(expected) {
        return Err(invalid());
    }
    let manifest: Manifest = serde_json::from_slice(&raw).map_err(|_| invalid())?;
    let machine = PeMachine::from_platform(&manifest.platform)?;
    if ![1, 2, 3, 4, 5].contains(&manifest.schema)
        || (machine == PeMachine::Arm64 && (manifest.signed_release || manifest.schema >= 3))
        || manifest.source_commit.len() != 40
        || !manifest
            .source_commit
            .bytes()
            .all(|c| c.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    let signed_metadata_valid = match (&manifest.authenticode, manifest.signed_release) {
        (None, false) => ![3, 5].contains(&manifest.schema),
        (Some(auth), true) => {
            [3, 5].contains(&manifest.schema)
                && auth.publisher_certificate_sha256.len() == 64
                && auth
                    .publisher_certificate_sha256
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit())
                && auth.timestamp == "rfc3161"
                && auth
                    .executables
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    == if manifest.schema == 5 {
                        research::EXES.to_vec()
                    } else {
                        vec!["aegis-client.exe", "aegis-winctl.exe"]
                    }
        }
        _ => false,
    };
    if !signed_metadata_valid {
        return Err(invalid());
    }
    let mut expected_names = if manifest.schema >= 4 {
        vec![
            "README.txt",
            "WINTUN-LICENSE.txt",
            "aegis-client.exe",
            "aegis-measure.exe",
            "aegis-transport-lab.exe",
            "aegis-winctl.exe",
            "research-operators.json",
            "wintun.dll",
        ]
    } else if manifest.schema >= 2 {
        vec![
            "README.txt",
            "WINTUN-LICENSE.txt",
            "aegis-client.exe",
            "aegis-winctl.exe",
            "wintun.dll",
        ]
    } else {
        vec!["README.txt", "aegis-client.exe", "aegis-winctl.exe"]
    };
    if manifest.project_licenses {
        expected_names.extend(PROJECT_LICENSE_FILES.iter().map(|(name, _)| *name));
        expected_names.sort_unstable();
    }
    if manifest
        .files
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != expected_names
    {
        return Err(invalid());
    }
    let mut entries = fs::read_dir(path)?
        .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<Vec<_>>>()?;
    entries.sort();
    let mut expected_entries = expected_names.clone();
    expected_entries.push("manifest.json");
    expected_entries.sort();
    if entries != expected_entries {
        return Err(invalid());
    }
    let mut files = BTreeMap::new();
    for (name, digest) in &manifest.files {
        let bytes = read_regular(&path.join(name), MAX_BINARY)?;
        if hash(&bytes) != *digest {
            return Err(invalid());
        }
        if name.ends_with(".exe") || name.ends_with(".dll") {
            verify_pe(&bytes, machine)?;
        }
        if name == "wintun.dll" && hash(&bytes) != machine.wintun().1 {
            return Err(invalid());
        }
        if name == "WINTUN-LICENSE.txt"
            && hash(&bytes) != "183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2"
        {
            return Err(invalid());
        }
        files.insert(name.clone(), bytes);
    }
    if manifest.schema >= 4 {
        research::validate_for_build(
            files.get(research::LEAF).ok_or_else(invalid)?,
            &files,
            &manifest.source_commit,
            manifest.signed_release,
        )?;
    }
    if manifest.signed_release {
        verify_signed_authenticode(
            path,
            manifest.authenticode.as_ref().ok_or_else(invalid)?,
            trusted_policy.ok_or_else(invalid)?,
        )?;
    }
    Ok((files, manifest))
}

#[cfg(not(windows))]
fn verify_signed_authenticode(
    _path: &Path,
    _manifest_policy: &Authenticode,
    _trusted_policy: &Path,
) -> Result<(), WinctlError> {
    // WinVerifyTrust is the authority for this claim. Cross-platform tools may
    // inspect a signed manifest, but cannot promote it to signed_release.
    Err(invalid())
}

#[cfg(windows)]
fn verify_signed_authenticode(
    path: &Path,
    manifest_policy: &Authenticode,
    trusted_policy_path: &Path,
) -> Result<(), WinctlError> {
    let trusted_raw = read_regular(trusted_policy_path, 65536)?;
    let trusted: TrustedAuthenticodePolicy =
        serde_json::from_slice(&trusted_raw).map_err(|_| invalid())?;
    let trusted_pin = trusted.publisher_certificate_sha256.ok_or_else(invalid)?;
    let structural_verifier = trusted.rfc3161_structural_verifier.ok_or_else(invalid)?;
    // Candidate/output binding is enforced before finalization. Requiring the
    // independently provisioned verifier here prevents a policy stripped of
    // that release-stage trust anchor from promoting signed_release.
    let provider_attestation_verifier =
        trusted.provider_attestation_verifier.ok_or_else(invalid)?;
    let provider_pin = trusted.authenticode_provider_sha256.ok_or_else(invalid)?;
    let structural_pin = trusted
        .rfc3161_structural_verifier_sha256
        .ok_or_else(invalid)?;
    let attestation_pin = trusted
        .provider_attestation_verifier_sha256
        .ok_or_else(invalid)?;
    if trusted.schema != "aegis_windows_authenticode_policy_v2"
        || trusted.timestamp_protocol != "rfc3161"
        || trusted.timestamp_attribute_oid != "1.3.6.1.4.1.311.3.3.1"
        || trusted.wintun_sha256
            != "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
        || trusted_pin.len() != 64
        || !trusted_pin.bytes().all(|c| c.is_ascii_hexdigit())
        || !trusted_pin.eq_ignore_ascii_case(&manifest_policy.publisher_certificate_sha256)
        || provider_pin.len() != 64
        || !provider_pin.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    // A client never opens/invokes the signing provider. Only its applicable
    // verifier entries get leases, retained across the actual child wait.
    let structural = adapter::AdapterLease::acquire(&structural_verifier, &structural_pin)?;
    let attestation =
        adapter::AdapterLease::acquire(&provider_attestation_verifier, &attestation_pin)?;
    let system_root = std::env::var_os("SystemRoot").ok_or_else(invalid)?;
    let powershell =
        PathBuf::from(system_root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    structural.verify()?;
    attestation.verify()?;
    let result = authenticode::invoke(
        &powershell,
        path,
        &trusted_pin.to_ascii_lowercase(),
        &structural_verifier,
        manifest_policy.executables.len() == 4,
    );
    // Evaluate cleanup/readback even on a failed child, but preserve its error.
    let custody = structural.verify().and_then(|_| attestation.verify());
    let status = result?;
    if !status.success() {
        return Err(invalid());
    }
    custody?;
    Ok(())
}
pub(super) fn build(
    client: &Path,
    winctl: &Path,
    output: &Path,
    source_commit: String,
) -> Result<Value, WinctlError> {
    build_with_wintun(client, winctl, output, source_commit, None)
}
pub(super) fn build_with_wintun(
    client: &Path,
    winctl: &Path,
    output: &Path,
    source_commit: String,
    wintun: Option<&Path>,
) -> Result<Value, WinctlError> {
    build_with_research(client, winctl, output, source_commit, wintun, None)
}
fn build_with_research(
    client: &Path,
    winctl: &Path,
    output: &Path,
    source_commit: String,
    wintun: Option<&Path>,
    research_dir: Option<&Path>,
) -> Result<Value, WinctlError> {
    if research_dir.is_some() && wintun.is_none() {
        return Err(invalid());
    }
    if source_commit.len() != 40 || !source_commit.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let mut files = BTreeMap::from([
        (
            "aegis-client.exe".to_string(),
            read_regular(client, MAX_BINARY)?,
        ),
        (
            "aegis-winctl.exe".to_string(),
            read_regular(winctl, MAX_BINARY)?,
        ),
        ("README.txt".to_string(), README.as_bytes().to_vec()),
    ]);
    for (name, bytes) in PROJECT_LICENSE_FILES {
        files.insert(name.into(), bytes.to_vec());
    }
    let machine = pe_machine(&files["aegis-client.exe"])?;
    verify_pe(&files["aegis-winctl.exe"], machine)?;
    if machine == PeMachine::Arm64 && research_dir.is_some() {
        // The private research metadata and builder remain x86_64-only.
        return Err(invalid());
    }
    if let Some(root) = wintun {
        let (member, pin) = machine.wintun();
        let dll = read_regular(&root.join(member), 2 * 1024 * 1024)?;
        if hash(&dll) != pin || pe_machine(&dll)? != machine {
            return Err(invalid());
        }
        files.insert("wintun.dll".into(), dll);
        files.insert(
            "WINTUN-LICENSE.txt".into(),
            read_regular(&root.join("LICENSE.txt"), 65536)?,
        );
    }
    if let Some(dir) = research_dir {
        for name in ["aegis-measure.exe", "aegis-transport-lab.exe"] {
            files.insert(name.into(), read_regular(&dir.join(name), MAX_BINARY)?);
        }
        let metadata = read_regular(&dir.join(research::LEAF), 16384)?;
        research::validate_for_build(&metadata, &files, &source_commit, false)?;
        files.insert(research::LEAF.into(), metadata);
        files.get_mut("README.txt").ok_or_else(invalid)?.extend_from_slice(b"\nPrivate research operators (experimental)\nThis kit also includes aegis-measure.exe and aegis-transport-lab.exe.\nUse aegis-measure.exe research-build-info and aegis-transport-lab.exe --build-info\nto inspect local build identity. The retained research-operators.json hashes\nrefer to unsigned candidate bytes; signed EXE hashes are in manifest.json.\nUse aegis-measure.exe private-control --help, poisson-control --help, or\npoisson-insertion --help for explicitly owned, authenticated operator sessions.\nNo profiles, keys or access credentials are included. Transport-lab models\nare offline analyses; this kit does not prove field, native or beta acceptance.\n");
    }
    verify_pe(&files["aegis-client.exe"], machine)?;
    verify_pe(&files["aegis-winctl.exe"], machine)?;
    let manifest = Manifest {
        schema: if research_dir.is_some() {
            4
        } else if wintun.is_some() {
            2
        } else {
            1
        },
        platform: machine.platform().into(),
        source_commit,
        signed_release: false,
        project_licenses: true,
        authenticode: None,
        files: files
            .iter()
            .map(|(name, bytes)| (name.clone(), hash(bytes)))
            .collect(),
    };
    let raw = serde_json::to_vec_pretty(&manifest)?;
    fs::create_dir(output)?;
    for (name, bytes) in files {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(output.join(name))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output.join("manifest.json"))?;
    file.write_all(&raw)?;
    file.sync_all()?;
    drop(file);
    verify(output, &hash(&raw))?;
    Ok(
        json!({"ok":true,"package":output,"manifest_sha256":hash(&raw),"signed_release":false,"client_only":research_dir.is_none()}),
    )
}
pub(super) fn run(args: PackageArgs) -> Result<Value, WinctlError> {
    match args.command {
        PackageCommand::VerifyProvenance {
            provenance,
            signature,
            expected_source_commit,
            expected_workflow,
            expected_ref,
            expected_manifest_sha256,
            expected_inner_zip_sha256,
            expected_github_artifact_digest,
        } => {
            let raw = trust::verify_detached(&provenance, &signature)?;
            let envelope: WindowsProvenance =
                serde_json::from_slice(&raw).map_err(|_| invalid())?;
            let hex = |value: &str, length: usize| {
                value.len() == length && value.bytes().all(|c| c.is_ascii_hexdigit())
            };
            if envelope.schema != "aegis_windows_release_provenance_v1"
                || !hex(&expected_source_commit, 40)
                || !hex(&expected_manifest_sha256, 64)
                || !hex(&expected_inner_zip_sha256, 64)
                || !(expected_github_artifact_digest == "not-used"
                    || hex(&expected_github_artifact_digest, 64))
                || !envelope
                    .source_commit
                    .eq_ignore_ascii_case(&expected_source_commit)
                || envelope.workflow != expected_workflow
                || envelope.r#ref != expected_ref
                || !envelope
                    .manifest_sha256
                    .eq_ignore_ascii_case(&expected_manifest_sha256)
                || !envelope
                    .inner_zip_sha256
                    .eq_ignore_ascii_case(&expected_inner_zip_sha256)
                || !envelope
                    .github_artifact_digest
                    .eq_ignore_ascii_case(&expected_github_artifact_digest)
            {
                return Err(invalid());
            }
            Ok(json!({"ok":true,"provenance_signature_verified":true,
                "source_commit":envelope.source_commit,
                "manifest_sha256":envelope.manifest_sha256,
                "inner_zip_sha256":envelope.inner_zip_sha256,
                "github_artifact_digest":envelope.github_artifact_digest}))
        }
        PackageCommand::VerifySignature {
            package,
            signature,
            authenticode_policy,
        } => {
            let digest = trust::verify_signature(&package, &signature)?;
            let (_, manifest) =
                verify_with_policy(&package, &digest, authenticode_policy.as_deref())?;
            Ok(json!({"ok":true,"package":package,"manifest_sha256":digest,
                "publisher_signature_verified":true,
                "signed_release":manifest.signed_release,
                "authenticode_verified":manifest.signed_release}))
        }
        PackageCommand::Build {
            client,
            winctl,
            output,
            source_commit,
            wintun,
            research_operators,
        } => {
            if let Some(research) = research_operators {
                return build_with_research(
                    &client,
                    &winctl,
                    &output,
                    source_commit,
                    wintun.as_deref(),
                    Some(&research),
                );
            }
            if let Some(wintun) = wintun {
                build_with_wintun(&client, &winctl, &output, source_commit, Some(&wintun))
            } else {
                build(&client, &winctl, &output, source_commit)
            }
        }
        PackageCommand::Verify {
            package,
            manifest_sha256,
        } => {
            verify(&package, &manifest_sha256)?;
            Ok(json!({"ok":true,"verified":true,"signed_release":false,"package":package}))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn unprovisioned_adapter_v2_and_legacy_v1_cannot_start_signed_verification() {
        let raw = include_bytes!("../../release/authenticode-policy.json");
        let policy: TrustedAuthenticodePolicy = serde_json::from_slice(raw).unwrap();
        assert_eq!(policy.schema, "aegis_windows_authenticode_policy_v2");
        assert!(policy.authenticode_provider_sha256.is_none());
        assert!(policy.rfc3161_structural_verifier_sha256.is_none());
        assert!(policy.provider_attestation_verifier_sha256.is_none());
        let directory = tempfile::tempdir().unwrap();
        let trusted = directory.path().join("policy.json");
        fs::write(&trusted, raw).unwrap();
        let manifest = Authenticode {
            publisher_certificate_sha256: "1".repeat(64),
            timestamp: "rfc3161".into(),
            executables: vec!["aegis-client.exe".into(), "aegis-winctl.exe".into()],
        };
        assert!(verify_signed_authenticode(directory.path(), &manifest, &trusted).is_err());
        let mut complete: serde_json::Value = serde_json::from_slice(raw).unwrap();
        complete["schema"] = json!("aegis_windows_authenticode_policy_v1");
        complete["publisher_certificate_sha256"] = json!("1".repeat(64));
        // Nonexistent entries are intentional: the legacy-schema refusal must
        // occur before any adapter open or PowerShell command can be attempted.
        for name in [
            "rfc3161_structural_verifier",
            "provider_attestation_verifier",
        ] {
            complete[name] = json!(directory.path().join("absent.ps1"));
        }
        for name in [
            "authenticode_provider_sha256",
            "rfc3161_structural_verifier_sha256",
            "provider_attestation_verifier_sha256",
        ] {
            complete[name] = json!("1".repeat(64));
        }
        fs::write(&trusted, serde_json::to_vec(&complete).unwrap()).unwrap();
        assert!(verify_signed_authenticode(directory.path(), &manifest, &trusted).is_err());
        complete["unexpected"] = json!(null);
        assert!(serde_json::from_value::<TrustedAuthenticodePolicy>(complete.clone()).is_err());
        complete.as_object_mut().unwrap().remove("unexpected");
        complete["authenticode_provider_sha256"] = json!(1);
        assert!(serde_json::from_value::<TrustedAuthenticodePolicy>(complete).is_err());
        let duplicate = br#"{"schema":"aegis_windows_authenticode_policy_v2","schema":"aegis_windows_authenticode_policy_v2"}"#;
        assert!(serde_json::from_slice::<TrustedAuthenticodePolicy>(duplicate).is_err());
    }
    fn fixture() -> (tempfile::TempDir, PathBuf, String) {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("source.exe");
        let mut bytes = vec![0; 128];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..70].copy_from_slice(b"PE\0\0\x64\x86");
        fs::write(&exe, bytes).unwrap();
        let output = dir.path().join("kit");
        let result = build(&exe, &exe, &output, "a".repeat(40)).unwrap();
        (
            dir,
            output,
            result["manifest_sha256"].as_str().unwrap().to_string(),
        )
    }
    #[test]
    fn arm64_unsigned_kit_binds_both_executable_machines_and_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let client = dir.path().join("client.exe");
        let winctl = dir.path().join("winctl.exe");
        let mut arm64 = vec![0; 128];
        arm64[..2].copy_from_slice(b"MZ");
        arm64[60..64].copy_from_slice(&64u32.to_le_bytes());
        arm64[64..70].copy_from_slice(b"PE\0\0\x64\xaa");
        fs::write(&client, &arm64).unwrap();
        fs::write(&winctl, &arm64).unwrap();
        let kit = dir.path().join("kit");
        let result = build(&client, &winctl, &kit, "a".repeat(40)).unwrap();
        let pin = result["manifest_sha256"].as_str().unwrap();
        let (_, manifest) = verify_with_policy(&kit, pin, None).unwrap();
        assert_eq!(manifest.platform, "windows-aarch64");
        assert!(!manifest.signed_release);

        let mut x64 = arm64.clone();
        x64[69] = 0x86;
        fs::write(&winctl, &x64).unwrap();
        assert!(build(&client, &winctl, &dir.path().join("mixed"), "a".repeat(40)).is_err());

        let path = kit.join("manifest.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["platform"] = json!("windows-x86_64");
        let raw = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &raw).unwrap();
        assert!(verify(&kit, &hash(&raw)).is_err());
    }
    #[test]
    fn project_license_builder_copies_exact_source_bytes_and_pins_inventory() {
        let (_dir, kit, pin) = fixture();
        let (files, manifest) = verify_with_policy(&kit, &pin, None).unwrap();
        assert!(manifest.project_licenses);
        for (name, expected) in PROJECT_LICENSE_FILES {
            assert_eq!(files[name], expected);
            assert_eq!(fs::read(kit.join(name)).unwrap(), expected);
            assert_eq!(manifest.files[name], hash(expected));
        }
        assert_eq!(manifest.files.len(), 6);
    }

    #[test]
    fn project_license_inventory_refuses_missing_and_tampered_files() {
        for (name, _) in PROJECT_LICENSE_FILES {
            let (_dir, kit, pin) = fixture();
            let original = fs::read(kit.join(name)).unwrap();
            fs::remove_file(kit.join(name)).unwrap();
            assert!(verify(&kit, &pin).is_err(), "missing {name}");
            fs::write(kit.join(name), b"synthetic changed project license").unwrap();
            assert!(verify(&kit, &pin).is_err(), "tampered {name}");
            fs::write(kit.join(name), original).unwrap();
            verify(&kit, &pin).unwrap();
        }
    }

    #[test]
    fn project_license_declaration_preserves_exact_legacy_inventory() {
        let (_dir, kit, _pin) = fixture();
        let path = kit.join("manifest.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value.as_object_mut().unwrap().remove("project_licenses");
        for (name, _) in PROJECT_LICENSE_FILES {
            value["files"].as_object_mut().unwrap().remove(name);
            fs::remove_file(kit.join(name)).unwrap();
        }
        let raw = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &raw).unwrap();
        let (_, manifest) = verify_with_policy(&kit, &hash(&raw), None).unwrap();
        assert!(!manifest.project_licenses);
        fs::write(kit.join("NOTICE"), b"unmanifested extra").unwrap();
        assert!(verify(&kit, &hash(&raw)).is_err());
        fs::remove_file(kit.join("NOTICE")).unwrap();
        value["project_licenses"] = json!(true);
        let raw = serde_json::to_vec(&value).unwrap();
        fs::write(path, &raw).unwrap();
        assert!(
            verify(&kit, &hash(&raw)).is_err(),
            "declared current kit cannot omit project licenses"
        );
    }

    #[test]
    fn exact_kit_rejects_extra_credentials_and_tampering() {
        let (_dir, kit, pin) = fixture();
        verify(&kit, &pin).unwrap();
        fs::write(kit.join("access.toml"), b"synthetic").unwrap();
        assert!(verify(&kit, &pin).is_err());
        fs::remove_file(kit.join("access.toml")).unwrap();
        fs::write(kit.join("aegis-client.exe"), b"tamper").unwrap();
        assert!(verify(&kit, &pin).is_err());
    }
    #[test]
    fn wrong_independent_pin_rejected() {
        let (_dir, kit, _pin) = fixture();
        assert!(verify(&kit, &"b".repeat(64)).is_err());
    }
    #[test]
    fn path_traversal_manifest_rejected_even_with_matching_pin() {
        let (_dir, kit, _pin) = fixture();
        let path = kit.join("manifest.json");
        let mut manifest: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let value = manifest.files.remove("aegis-client.exe").unwrap();
        manifest.files.insert("../aegis-client.exe".into(), value);
        let raw = serde_json::to_vec(&manifest).unwrap();
        fs::write(path, &raw).unwrap();
        assert!(verify(&kit, &hash(&raw)).is_err());
    }
    #[test]
    fn signed_release_claim_needs_real_platform_signatures() {
        let (_dir, kit, _pin) = fixture();
        let path = kit.join("manifest.json");
        let mut manifest: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        manifest.schema = 3;
        manifest.signed_release = true;
        manifest.authenticode = Some(Authenticode {
            publisher_certificate_sha256: "a".repeat(64),
            timestamp: "rfc3161".into(),
            executables: vec!["aegis-client.exe".into(), "aegis-winctl.exe".into()],
        });
        let raw = serde_json::to_vec(&manifest).unwrap();
        fs::write(path, &raw).unwrap();
        // Synthetic PE headers and a made-up pin can never promote a candidate.
        assert!(verify(&kit, &hash(&raw)).is_err());
    }
    #[test]
    fn unsigned_candidate_cannot_use_signed_schema() {
        let (_dir, kit, _pin) = fixture();
        let path = kit.join("manifest.json");
        let mut manifest: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        manifest.schema = 3;
        let raw = serde_json::to_vec(&manifest).unwrap();
        fs::write(path, &raw).unwrap();
        assert!(verify(&kit, &hash(&raw)).is_err());
    }
}
