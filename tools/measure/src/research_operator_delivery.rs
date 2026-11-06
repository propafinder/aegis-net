//! Private build-side admission. Never executes an input path or signs a key.
use crate::research_build_info::{BuildInfo, LAB_CAPABILITIES, MEASURE_CAPABILITIES};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, io, path::Path};
const GUIDE_INVENTORY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../packaging/research-operator-guides.txt"
));
fn refuse() -> Box<dyn std::error::Error> {
    io::Error::other("private research operator input refused").into()
}
#[cfg(not(windows))]
pub(crate) fn read(
    path: &Path,
    cap: usize,
    executable: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(aegis_core::operator_artifact::read_operator_artifact(
        path, cap as u64, executable,
    )?)
}
#[cfg(windows)]
pub(crate) fn read(
    path: &Path,
    cap: usize,
    _executable: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::io::Read;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    if cap == 0 || cap > 512 * 1024 * 1024 {
        return Err(refuse());
    }
    aegis_core::windows_file::reject_reparse_ancestry(path)?;
    // SDK FILE_FLAG_OPEN_REPARSE_POINT / FILE_SHARE_READ. Deny write and
    // delete sharing while reading public build artifacts, not private input.
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x00200000)
        .share_mode(1)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.file_attributes() & 0x400 != 0
        || before.len() == 0
        || before.len() > cap as u64
    {
        return Err(refuse());
    }
    let mut bytes = Vec::new();
    (&mut file).take(cap as u64 + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || bytes.len() > cap
        || (
            before.file_attributes(),
            before.creation_time(),
            before.last_write_time(),
            before.file_size(),
        ) != (
            after.file_attributes(),
            after.creation_time(),
            after.last_write_time(),
            after.file_size(),
        )
    {
        return Err(refuse());
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(crate) fn linux_executable(bytes: &[u8], arch: &str) -> bool {
    let machine: u16 = match arch {
        "x86_64" => 62,
        "aarch64" => 183,
        _ => return false,
    };
    bytes.len() >= 64
        && &bytes[..7] == b"\x7fELF\x02\x01\x01"
        && matches!(u16::from_le_bytes([bytes[16], bytes[17]]), 2 | 3)
        && u16::from_le_bytes([bytes[18], bytes[19]]) == machine
        && u32::from_le_bytes(bytes[20..24].try_into().unwrap()) == 1
        && u16::from_le_bytes([bytes[52], bytes[53]]) == 64
}
fn laboratory_version() -> Result<&'static str, Box<dyn std::error::Error>> {
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../transport-lab/Cargo.toml"
    ))
    .lines()
    .find_map(|line| {
        line.strip_prefix("version = \"")
            .and_then(|s| s.strip_suffix('"'))
    })
    .ok_or_else(refuse)
}
fn documents(bundle: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // The same bounded source manifest drives Bash staging and Rust admission.
    // No input directory traversal discovers additional payload or link targets.
    let mut guides = BTreeSet::new();
    for name in GUIDE_INVENTORY.lines() {
        let stem = name.strip_suffix(".md").ok_or_else(refuse)?;
        if stem.is_empty()
            || !stem.as_bytes()[0].is_ascii_alphanumeric()
            || !stem
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !guides.insert(name)
            || guides.len() > 32
        {
            return Err(refuse());
        }
    }
    if guides.is_empty() {
        return Err(refuse());
    }
    let documents: Vec<_> = ["README.md", "THIRD-PARTY-NOTICES.txt"]
        .into_iter()
        .chain(guides)
        .collect();
    let mut expected: BTreeSet<_> = documents
        .iter()
        .copied()
        .chain([
            "aegis-measure.build-info.json",
            "aegis-transport-lab.build-info.json",
        ])
        .collect();
    for entry in fs::read_dir(bundle.join("research"))? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || !expected.remove(entry.file_name().to_str().ok_or_else(refuse)?)
        {
            return Err(refuse());
        }
    }
    if !expected.is_empty() {
        return Err(refuse());
    }
    Ok(documents
        .into_iter()
        .map(|name| format!("research/{name}"))
        .collect())
}
/// A legacy bundle without either tool stays byte-compatible. A partial pair
/// or an unbound producer capture refuses before the manifest/SHA256SUMS write.
pub fn admit(
    bundle: &Path,
    source: &str,
    lock: &str,
    arch: &str,
    target: &str,
) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    if target != format!("{arch}-unknown-linux-gnu") {
        return Err(refuse());
    }
    admit_pair(bundle, source, lock, arch, target)
}
/// Standalone research output has a mandatory exact pair and supported target.
pub fn admit_required(
    bundle: &Path,
    source: &str,
    lock: &str,
    arch: &str,
    target: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    admit_pair(bundle, source, lock, arch, target)?.ok_or_else(refuse)
}
fn admit_pair(
    bundle: &Path,
    source: &str,
    lock: &str,
    arch: &str,
    target: &str,
) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    let suffix = match (arch, target) {
        ("x86_64", "x86_64-pc-windows-msvc") => ".exe",
        ("x86_64", "x86_64-unknown-linux-gnu") | ("aarch64", "aarch64-unknown-linux-gnu") => "",
        _ => return Err(refuse()),
    };
    let names = ["aegis-measure", "aegis-transport-lab"];
    let paths: Vec<_> = names
        .iter()
        .flat_map(|n| {
            [
                bundle.join(format!("bin/{n}{suffix}")),
                bundle.join(format!("research/{n}.build-info.json")),
            ]
        })
        .collect();
    let present: Vec<_> = paths
        .iter()
        .map(|p| fs::symlink_metadata(p).is_ok())
        .collect();
    if present.iter().all(|p| !p) {
        return Ok(None);
    }
    if present.iter().any(|p| !p)
        || !matches!(arch, "x86_64" | "aarch64")
        || source.len() != 40
        || !source
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || lock.len() != 64
        || !lock
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(refuse());
    }
    let mut infos = Vec::new();
    let mut capture_hashes = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let bytes = read(&paths[i * 2], 512 * 1024 * 1024, true)?;
        let capture = read(&paths[i * 2 + 1], 8192, false)?;
        let capture_hash = digest(&capture);
        let info: BuildInfo = serde_json::from_slice(&capture)?;
        let caps = if i == 0 {
            MEASURE_CAPABILITIES
        } else {
            LAB_CAPABILITIES
        };
        let version = if i == 0 {
            env!("CARGO_PKG_VERSION")
        } else {
            laboratory_version()?
        };
        let executable = if suffix.is_empty() {
            linux_executable(&bytes, arch)
        } else {
            bytes.len() >= 64 && &bytes[..2] == b"MZ" && {
                let offset = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
                bytes.get(offset..offset.saturating_add(6)) == Some(b"PE\0\0\x64\x86")
            }
        };
        if !executable
            || info.schema != "aegis_research_tool_build_info_v1"
            || info.tool != *name
            || info.source_commit != source
            || info.cargo_lock_sha256 != lock
            || info.target_triple != target
            || info.crate_version != version
            || info.build_features != "none"
            || info.binary_sha256 != digest(&bytes)
            || info
                .capabilities
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != caps
            || !info.rustc_version.starts_with("rustc 1.97.1 ")
            || info.rustc_version.len() > 512
            || !info
                .rustc_version
                .bytes()
                .all(|b| b.is_ascii_graphic() || b == b' ')
        {
            return Err(refuse());
        }
        infos.push(info);
        capture_hashes.push(capture_hash);
    }
    if infos[0].rustc_version != infos[1].rustc_version {
        return Err(refuse());
    }
    let mut leaves = serde_json::Map::new();
    for path in documents(bundle)? {
        let bytes = read(&bundle.join(&path), 8 * 1024 * 1024, false)?;
        leaves.insert(path, json!(digest(&bytes)));
    }
    for (i, name) in names.iter().enumerate() {
        leaves.insert(format!("bin/{name}{suffix}"), json!(infos[i].binary_sha256));
        leaves.insert(
            format!("research/{name}.build-info.json"),
            json!(capture_hashes[i]),
        );
    }
    Ok(Some(
        json!({"schema":"aegis_private_research_operators_v1", "tools":infos, "leaf_sha256":leaves,
        "execution":"explicit_operator_only", "automatic_service_activation":false,
        "installed_fullwide_owner":false,"scientific_or_field_acceptance":false}),
    ))
}
#[cfg(all(test, unix))]
#[path = "research_operator_delivery_tests.rs"]
mod tests;
