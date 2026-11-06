//! Build-side role admission only; no input executable, service or signer is run.
use crate::research_operator_delivery;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    io::Write,
    path::Path,
};

const MANIFEST: &str = "research.manifest.json";
const SUMS: &str = "SHA256SUMS";

fn refuse() -> Box<dyn std::error::Error> {
    io::Error::other("private delivery role refused").into()
}
fn read(path: &Path, cap: u64, executable: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    research_operator_delivery::read(
        path,
        usize::try_from(cap).map_err(|_| refuse())?,
        executable,
    )
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn version(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 10
                && p.bytes().all(|b| b.is_ascii_digit())
                && (*p == "0" || !p.starts_with('0'))
        })
}
pub struct Inputs<'a> {
    pub directory: &'a Path,
    pub version: &'a str,
    pub source: &'a str,
    pub lock: &'a str,
    pub arch: &'a str,
    pub target: &'a str,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    distribution: String,
    version: String,
    source_commit: String,
    cargo_lock_sha256: String,
    arch: String,
    target_triple: String,
    signed_release: bool,
    research_operators: Value,
    files: BTreeMap<String, String>,
}

fn expected(inputs: &Inputs<'_>) -> Result<Manifest, Box<dyn std::error::Error>> {
    if !version(inputs.version) || !hex(inputs.source, 40) || !hex(inputs.lock, 64) {
        return Err(refuse());
    }
    let pair = research_operator_delivery::admit_required(
        inputs.directory,
        inputs.source,
        inputs.lock,
        inputs.arch,
        inputs.target,
    )?;
    let leaves = pair["leaf_sha256"].as_object().ok_or_else(refuse)?;
    let files: BTreeMap<String, String> = leaves
        .iter()
        .map(|(path, digest)| {
            let digest = digest.as_str().filter(|s| hex(s, 64)).ok_or_else(refuse)?;
            Ok((path.clone(), digest.to_owned()))
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;
    // Exactly two fixed directories. Reject any administrative executable,
    // source/config/helper, symlink, special file or unknown directory before output.
    for name in ["bin", "research"] {
        let meta = fs::symlink_metadata(inputs.directory.join(name))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(refuse());
        }
    }
    for entry in fs::read_dir(inputs.directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(refuse)?;
        if !matches!(name, "bin" | "research" | MANIFEST | SUMS) {
            return Err(refuse());
        }
        if matches!(name, MANIFEST | SUMS) && !entry.file_type()?.is_file() {
            return Err(refuse());
        }
    }
    let expected_bins: Vec<_> = files
        .keys()
        .filter_map(|p| p.strip_prefix("bin/"))
        .collect();
    let mut seen = 0;
    for entry in fs::read_dir(inputs.directory.join("bin"))? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || !expected_bins.contains(&entry.file_name().to_str().ok_or_else(refuse)?)
        {
            return Err(refuse());
        }
        seen += 1;
    }
    if seen != 2 {
        return Err(refuse());
    }
    Ok(Manifest {
        schema: "aegis_private_research_delivery_manifest_v1".into(),
        distribution: "private_research_only".into(),
        version: inputs.version.into(),
        source_commit: inputs.source.into(),
        cargo_lock_sha256: inputs.lock.into(),
        arch: inputs.arch.into(),
        target_triple: inputs.target.into(),
        signed_release: false,
        research_operators: pair,
        files,
    })
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn sums(manifest: &Manifest, manifest_bytes: &[u8]) -> Vec<u8> {
    let mut files = manifest.files.clone();
    files.insert(MANIFEST.into(), hash(manifest_bytes));
    files
        .into_iter()
        .map(|(path, digest)| format!("{digest}  {path}\n"))
        .collect::<String>()
        .into_bytes()
}
pub fn build(inputs: &Inputs<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = expected(inputs)?;
    for name in [MANIFEST, SUMS] {
        if fs::symlink_metadata(inputs.directory.join(name)).is_ok() {
            return Err(refuse());
        }
    }
    let bytes = (serde_json::to_string_pretty(&manifest)? + "\n").into_bytes();
    if bytes.len() > 65536 {
        return Err(refuse());
    }
    write_new(&inputs.directory.join(MANIFEST), &bytes)?;
    write_new(&inputs.directory.join(SUMS), &sums(&manifest, &bytes))?;
    Ok(())
}
pub fn verify(inputs: &Inputs<'_>) -> Result<String, Box<dyn std::error::Error>> {
    let actual = read(&inputs.directory.join(MANIFEST), 65536, false)?;
    let parsed: Manifest = serde_json::from_slice(&actual)?;
    let expected = expected(inputs)?;
    if parsed != expected
        || read(&inputs.directory.join(SUMS), 16384, false)? != sums(&expected, &actual)
    {
        return Err(refuse());
    }
    Ok(hash(&actual))
}

pub fn admit_administrative(
    directory: &Path,
    arch: &str,
    target: &str,
    expected_measure: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if !matches!(arch, "x86_64" | "aarch64")
        || target != format!("{arch}-unknown-linux-gnu")
        || !hex(expected_measure, 64)
    {
        return Err(refuse());
    }
    if fs::symlink_metadata(directory.join("research")).is_ok()
        || fs::symlink_metadata(directory.join("bin/aegis-transport-lab")).is_ok()
    {
        return Err(refuse());
    }
    let bytes = read(
        &directory.join("bin/aegis-measure"),
        512 * 1024 * 1024,
        true,
    )?;
    if !research_operator_delivery::linux_executable(&bytes, arch)
        || hash(&bytes) != expected_measure
    {
        return Err(refuse());
    }
    Ok(hash(&bytes))
}

fn archive_hash(
    path: &Path,
    directory: &str,
    files: &BTreeMap<String, String>,
) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::{BufRead, Read, Seek, SeekFrom};
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        aegis_core::secret_file::trusted_parent(path)?;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        aegis_core::windows_file::reject_reparse_ancestry(path)?;
        options.custom_flags(0x00200000).share_mode(1);
    }
    #[cfg(not(any(unix, windows)))]
    {
        return Err(refuse());
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    const CAP: u64 = 2 * 1024 * 1024 * 1024;
    if !before.is_file() || before.len() == 0 || before.len() > CAP {
        return Err(refuse());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid only reads this process's effective identity.
        let uid = unsafe { libc::geteuid() };
        if before.nlink() != 1
            || before.mode() & 0o022 != 0
            || (before.uid() != 0 && before.uid() != uid)
        {
            return Err(refuse());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if before.file_attributes() & 0x400 != 0 {
            return Err(refuse());
        }
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).ok_or_else(refuse)?;
        if count > before.len() || count > CAP {
            return Err(refuse());
        }
        digest.update(&buffer[..n]);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut archive = tar::Archive::new(
        flate2::bufread::GzDecoder::new(std::io::BufReader::new(&mut file)).take(CAP),
    );
    let mut seen = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut entries = 0usize;
    for entry in archive.entries()? {
        let mut entry = entry?;
        entries += 1;
        if entries > files.len() + 3
            || entry.header().mode()? & 0o7000 != 0
            || entry.header().link_name()?.is_some()
        {
            return Err(refuse());
        }
        let path = entry.path()?.into_owned();
        if !path
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
        {
            return Err(refuse());
        }
        let relative = path
            .strip_prefix(directory)?
            .to_str()
            .ok_or_else(refuse)?
            .to_owned();
        if entry.header().entry_type().is_dir() {
            if !matches!(relative.as_str(), "" | "bin" | "research")
                || entry.size() != 0
                || !directories.insert(relative)
            {
                return Err(refuse());
            }
            continue;
        }
        if !entry.header().entry_type().is_file() || !seen.insert(relative.clone()) {
            return Err(refuse());
        }
        let expected = files.get(&relative).ok_or_else(refuse)?;
        let cap = if relative.starts_with("bin/") {
            512 * 1024 * 1024
        } else if relative.ends_with(".build-info.json") {
            8192
        } else if relative == MANIFEST {
            65536
        } else if relative == SUMS {
            16384
        } else {
            8 * 1024 * 1024
        };
        if entry.size() == 0 || entry.size() > cap {
            return Err(refuse());
        }
        let mut member_hash = Sha256::new();
        let mut member_count = 0u64;
        loop {
            let n = entry.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            member_count += n as u64;
            if member_count > cap {
                return Err(refuse());
            }
            member_hash.update(&buffer[..n]);
        }
        if member_count != entry.size() || format!("{:x}", member_hash.finalize()) != *expected {
            return Err(refuse());
        }
    }
    if seen != files.keys().cloned().collect::<BTreeSet<_>>() {
        return Err(refuse());
    }
    let mut decoded = archive.into_inner();
    loop {
        let n = decoded.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if buffer[..n].iter().any(|b| *b != 0) {
            return Err(refuse());
        }
    }
    if decoded.limit() == 0 {
        return Err(refuse());
    }
    let mut remainder = decoded.into_inner().into_inner();
    if !remainder.fill_buf()?.is_empty() {
        return Err(refuse());
    }
    drop(remainder);
    let after = file.metadata()?;
    if count != before.len() || after.len() != before.len() {
        return Err(refuse());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (
            before.dev(),
            before.ino(),
            before.mode(),
            before.uid(),
            before.gid(),
            before.nlink(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.mode(),
            after.uid(),
            after.gid(),
            after.nlink(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) {
            return Err(refuse());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (
            before.file_attributes(),
            before.creation_time(),
            before.last_write_time(),
        ) != (
            after.file_attributes(),
            after.creation_time(),
            after.last_write_time(),
        ) {
            return Err(refuse());
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub fn linux_release_entry(
    output: &Path,
    version: &str,
    source: &str,
    lock: &str,
    arch: &str,
    target: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let name = format!("aegis-research-{version}-linux-{arch}");
    let directory = output.join(&name);
    let manifest_hash = verify(&Inputs {
        directory: &directory,
        version,
        source,
        lock,
        arch,
        target,
    })?;
    let archive_name = format!("{name}.tar.gz");
    let parsed: Manifest = serde_json::from_slice(&read(&directory.join(MANIFEST), 65536, false)?)?;
    let mut files = parsed.files;
    files.insert(MANIFEST.into(), manifest_hash.clone());
    files.insert(
        SUMS.into(),
        hash(&read(&directory.join(SUMS), 16384, false)?),
    );
    let digest = archive_hash(&output.join(&archive_name), &name, &files)?;
    let sidecar_name = format!("{archive_name}.sha256");
    let sidecar = read(&output.join(&sidecar_name), 512, false)?;
    if sidecar != format!("{digest}  {archive_name}\n").as_bytes() {
        return Err(refuse());
    }
    Ok(
        json!({"schema":"aegis_private_research_delivery_v1", "distribution":"private_research_only",
        "directory":name, "target_triple":target, "source_commit":source,
        "manifest_path":format!("{name}/{MANIFEST}"), "manifest_sha256":manifest_hash,
        "archive":{"path":archive_name,"sha256_path":sidecar_name,"sha256":digest},
        "automatic_service_activation":false,"installed_fullwide_owner":false}),
    )
}

#[cfg(all(test, unix))]
#[path = "private_research_delivery_tests.rs"]
mod tests;
