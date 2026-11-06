//! Public distribution is constructed from explicit leaves, never a checkout copy.
use crate::artifact::{read_json, write_json};
use flate2::{bufread::GzDecoder, write::GzEncoder, Compression};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Cursor, Read},
    path::{Component, Path, PathBuf},
    process::Command,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[cfg(test)]
struct Scratch(PathBuf);
#[cfg(test)]
impl Scratch {
    fn new() -> Result<Self> {
        for attempt in 0..100 {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "aegis-public-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err("cannot create private validation scratch directory".into())
    }
}
#[cfg(test)]
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
// This is a versioned publishing policy, independent of the downloaded manifest.
const PAYLOAD: &[&str] = &[
    "bin/aegis-client",
    "install.sh",
    "config.example.toml",
    "scripts/setup-wide-linux-redirect.sh",
    "scripts/setup-wide-linux-tproxy.sh",
    "scripts/aegis-wide-enable.sh",
    "scripts/aegis-wide-disable.sh",
    "scripts/aegis-wide-persist-install.sh",
    "scripts/purge-installed-aegis.sh",
    "scripts/aegis-ubuntu-uninstall.sh",
    "scripts/janitor-wide-linux-tproxy.sh",
    "scripts/aegis-rpi-gateway.sh",
    "scripts/lib/root-state.sh",
    "packaging/systemd/aegis-client.service",
    "packaging/env/aegis-client.env.example",
    "README.txt",
    "THIRD-PARTY-NOTICES.txt",
];
const CLIENT_BUNDLE_SCHEMA_V1: &str = "aegis_client_release_bundle_manifest_v1";
const CLIENT_BUNDLE_SCHEMA_V2: &str = "aegis_client_release_bundle_manifest_v2";
const CLIENT_BUNDLE_SCHEMA_V3: &str = "aegis_client_release_bundle_manifest_v3";
const DEVICE_GUARD_PAYLOAD: &str = "scripts/aegis-device-egress-guard.sh";

fn payload_for_schema(schema: &str) -> Result<BTreeSet<&'static str>> {
    check(
        matches!(
            schema,
            CLIENT_BUNDLE_SCHEMA_V1 | CLIENT_BUNDLE_SCHEMA_V2 | CLIENT_BUNDLE_SCHEMA_V3
        ),
        "unsupported public client payload schema",
    )?;
    let mut payload: BTreeSet<_> = PAYLOAD.iter().copied().collect();
    if schema == CLIENT_BUNDLE_SCHEMA_V2 || schema == CLIENT_BUNDLE_SCHEMA_V3 {
        payload.insert(DEVICE_GUARD_PAYLOAD);
    }
    if schema == CLIENT_BUNDLE_SCHEMA_V3 {
        payload.insert(crate::shipping_client_inventory::LEAF);
    }
    Ok(payload)
}

fn check(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn ed25519_public_key(pem_bytes: &[u8]) -> Result<[u8; 32]> {
    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let normalized = std::str::from_utf8(pem_bytes)?.replace("\r\n", "\n");
    let blocks = pem::parse_many(&normalized)?;
    check(blocks.len() == 1, "expected one public key PEM block")?;
    check(blocks[0].tag() == "PUBLIC KEY", "expected public key PEM")?;
    let canonical = pem::encode_config(
        &blocks[0],
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    );
    check(
        normalized.trim_matches(|ch: char| ch.is_ascii_whitespace())
            == canonical.trim_matches(|ch: char| ch.is_ascii_whitespace()),
        "noncanonical or extraneous public key PEM text",
    )?;
    let der = blocks[0].contents();
    check(
        der.len() == SPKI_PREFIX.len() + 32 && der.starts_with(&SPKI_PREFIX),
        "expected exact Ed25519 SPKI public key",
    )?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&der[SPKI_PREFIX.len()..]);
    Ok(key)
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("missing {key}").into())
}
fn keys(value: &Value, expected: &[&str]) -> Result<()> {
    let actual = value.as_object().ok_or("expected metadata object")?;
    check(
        actual.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == expected.iter().copied().collect(),
        "metadata fields differ from public distribution policy",
    )
}
// Bounded signed policy, not a persistent TUF client. Legacy signed artifacts
// remain readable for historical audits; new workflow signatures include it.
fn validate_release_policy(manifest: &Value, now: u64) -> Result<()> {
    let policy = &manifest["release_policy"];
    keys(
        policy,
        &[
            "schema",
            "authority",
            "sequence",
            "tag",
            "issued_at_unix",
            "expires_at_unix",
        ],
    )?;
    check(
        policy["schema"] == "aegis_release_policy_v1",
        "unsupported release policy",
    )?;
    let repository = text(policy, "authority")?
        .strip_prefix("github:")
        .and_then(|s| s.strip_suffix(":.github/workflows/release.yml"))
        .ok_or("invalid release policy authority")?;
    check(
        repository.split('/').count() == 2
            && repository.split('/').all(|s| !s.is_empty())
            && repository
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b)),
        "invalid workflow authority",
    )?;
    let sequence = policy["sequence"]
        .as_u64()
        .ok_or("invalid release sequence")?;
    let issued = policy["issued_at_unix"]
        .as_u64()
        .ok_or("invalid issue time")?;
    let expires = policy["expires_at_unix"]
        .as_u64()
        .ok_or("invalid expiry time")?;
    check(
        sequence > 0
            && sequence < (1u64 << 53)
            && issued > 0
            && issued < expires
            && expires - issued <= 30 * 86400
            && issued <= now.saturating_add(300)
            && now < expires,
        "release policy expired, future-dated or invalid",
    )?;
    let version = text(manifest, "version")?;
    let channel = text(manifest, "channel")?;
    let tag = text(policy, "tag")?;
    let valid_tag = if channel == "stable" {
        tag == format!("v{version}") && manifest["prerelease"] == false
    } else if matches!(channel, "rc" | "nightly") {
        tag.strip_prefix(&format!("v{version}-{channel}."))
            .and_then(|suffix| {
                suffix
                    .parse::<u64>()
                    .ok()
                    .map(|number| number.to_string() == suffix)
            })
            .unwrap_or(false)
            && manifest["prerelease"] == true
    } else {
        false
    };
    check(valid_tag, "release policy tag disagrees with manifest")
}

fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    check(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= limit,
        "expected bounded regular file",
    )?;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    check(
        bytes.len() as u64 <= limit,
        "file changed beyond size limit",
    )?;
    Ok(bytes)
}

fn read_scoped_notice(base: &Path, relative: &Path, limit: u64) -> Result<Vec<u8>> {
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err("notice path must stay package-relative"),
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    check(!components.is_empty(), "notice path is empty")?;

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        // Open the absolute anchor one component at a time from a held root fd.
        // A swapped symlink in the package path or any ancestor must not redirect
        // the subsequent relative walk to a different directory.
        check(base.is_absolute(), "notice base must be absolute")?;
        let mut parent = fs::File::open("/")?;
        for component in base.components() {
            let name = match component {
                Component::RootDir => continue,
                Component::Normal(name) => name,
                _ => return Err("notice base must be canonical".into()),
            };
            let name = CString::new(name.as_bytes())?;
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            parent = unsafe { fs::File::from_raw_fd(fd) };
        }
        check(
            parent.metadata()?.is_dir(),
            "notice package base is not a directory",
        )?;
        for (index, name) in components.iter().enumerate() {
            let name = CString::new(name.as_bytes())?;
            let last = index + 1 == components.len();
            let flags = libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | if last {
                    libc::O_NONBLOCK
                } else {
                    libc::O_DIRECTORY
                };
            let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let opened = unsafe { fs::File::from_raw_fd(fd) };
            let meta = opened.metadata()?;
            if last {
                check(
                    meta.is_file() && meta.len() <= limit,
                    "notice must be a bounded regular file",
                )?;
                let mut bytes = Vec::new();
                opened.take(limit + 1).read_to_end(&mut bytes)?;
                check(
                    bytes.len() as u64 <= limit,
                    "notice changed beyond size limit",
                )?;
                return Ok(bytes);
            }
            check(meta.is_dir(), "notice parent must be a directory")?;
            parent = opened;
        }
        unreachable!();
    }

    #[cfg(windows)]
    {
        read_scoped_notice_windows(base, relative, limit)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (base, limit);
        Err("unsupported notice file platform".into())
    }
}

#[cfg(windows)]
fn read_scoped_notice_windows(base: &Path, relative: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    // Keep each directory open without FILE_SHARE_DELETE while resolving the
    // next component. An ancestor cannot be renamed out from under the path
    // walk after its handle is accepted. OPEN_REPARSE_POINT makes a junction or
    // symlink visible to the check instead of following it at the final leaf.
    // The caller has already chosen the reviewed package anchor. Never
    // recanonicalize it here: a replacement junction could become a new
    // (unreviewed) anchor between the caller's check and this read.
    check(base.is_absolute(), "notice base must be absolute")?;
    check(
        base.components().all(|part| {
            matches!(
                part,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        }),
        "notice base must have no relative components",
    )?;
    let mut held = Vec::new();
    let mut ancestors: Vec<_> = base.ancestors().filter(|p| p.is_absolute()).collect();
    ancestors.reverse();
    for path in ancestors {
        let directory = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let metadata = directory.metadata()?;
        check(
            metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "notice package ancestor must be a regular directory",
        )?;
        held.push(directory);
    }
    let mut path = base.to_path_buf();
    let parts: Vec<_> = relative.components().collect();
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err("notice path must stay package-relative".into());
        };
        path.push(name);
        let last = index + 1 == parts.len();
        let file = fs::OpenOptions::new()
            .read(true)
            // A held leaf refuses both a pre-existing writer and a new writer
            // until the bounded read completes. Parents still allow child
            // writes, but disallow rename/delete while their handles are held.
            .share_mode(if last {
                FILE_SHARE_READ
            } else {
                FILE_SHARE_READ | FILE_SHARE_WRITE
            })
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        let metadata = file.metadata()?;
        check(
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "notice reparse point forbidden",
        )?;
        if last {
            check(
                metadata.is_file() && metadata.len() <= limit,
                "notice must be a bounded regular file",
            )?;
            let mut bytes = Vec::new();
            file.take(limit + 1).read_to_end(&mut bytes)?;
            check(
                bytes.len() as u64 <= limit,
                "notice changed beyond size limit",
            )?;
            return Ok(bytes);
        }
        check(metadata.is_dir(), "notice parent must be a directory")?;
        held.push(file);
    }
    unreachable!()
}
fn exact_directory(path: &Path, expected: &BTreeSet<String>) -> Result<()> {
    fn walk(root: &Path, path: &Path, files: &mut BTreeSet<String>) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                walk(root, &entry.path(), files)?;
            } else {
                check(
                    kind.is_file(),
                    "links/special files forbidden in public delivery",
                )?;
                files.insert(
                    entry
                        .path()
                        .strip_prefix(root)?
                        .to_str()
                        .ok_or("non-UTF8 path")?
                        .to_string(),
                );
            }
        }
        Ok(())
    }
    check(
        fs::symlink_metadata(path)?.is_dir(),
        "delivery root must be a directory",
    )?;
    let mut actual = BTreeSet::new();
    walk(path, path, &mut actual)?;
    check(
        &actual == expected,
        "public delivery inventory differs from approved leaves",
    )
}
fn notices(root: &Path, triple: &str) -> Result<Vec<u8>> {
    notices_for_roots(
        root,
        triple,
        &["aegis-client"],
        "AEGIS client — third-party license notices\n\n",
    )
}
pub(crate) fn research_notices(root: &Path, triple: &str) -> Result<Vec<u8>> {
    notices_for_roots(
        root,
        triple,
        &["aegis-measure", "aegis-transport-lab"],
        "AEGIS private research operators — third-party license notices\n\n",
    )
}
fn notices_for_roots(root: &Path, triple: &str, roots: &[&str], title: &str) -> Result<Vec<u8>> {
    // Build-side operation only. License texts are carried in the client archive.
    let output = Command::new("cargo")
        .current_dir(root)
        .args([
            "metadata",
            "--locked",
            "--format-version=1",
            "--filter-platform",
            triple,
            "--features",
            "aegis-client/raw-socket,aegis-client/chrome-like-tls,aegis-client/chrome-like-quic",
        ])
        .output()?;
    check(
        output.status.success(),
        "cannot collect dependency license notices",
    )?;
    let meta: Value = serde_json::from_slice(&output.stdout)?;
    notices_from_metadata(root, &meta, roots, title)
}

// Explicit audited leaves, not a recursive third-party source crawl. Unknown
// ring versions/sources require notice-policy review before packaging.
fn ring_notice_leaves(package: &Value, base: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    if package["name"] != "ring" {
        return Ok(BTreeMap::new());
    }
    check(
        package["version"] == "0.17.14"
            && package["source"] == "registry+https://github.com/rust-lang/crates.io-index",
        "ring notice policy requires reviewed version and registry source",
    )?;
    let base_meta = fs::symlink_metadata(base)?;
    check(
        base_meta.is_dir() && !base_meta.file_type().is_symlink(),
        "ring package directory must be a regular directory",
    )?;
    let canonical_base = fs::canonicalize(base)?;
    let mut leaves = BTreeMap::new();
    for leaf in [
        "third_party/fiat/LICENSE",
        "src/polyfill/once_cell/LICENSE-MIT",
    ] {
        let mut path = base.to_path_buf();
        let components: Vec<_> = Path::new(leaf).components().collect();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(component) = component else {
                return Err("invalid fixed ring notice path".into());
            };
            path.push(component);
            let meta = fs::symlink_metadata(&path)?;
            check(
                !meta.file_type().is_symlink(),
                "ring notice links forbidden",
            )?;
            if index + 1 == components.len() {
                check(
                    meta.is_file() && meta.len() > 0 && meta.len() <= 65536,
                    "ring notice must be bounded regular text",
                )?;
            } else {
                check(meta.is_dir(), "ring notice parent must be directory")?;
            }
        }
        check(
            fs::canonicalize(&path)?.starts_with(&canonical_base),
            "ring notice escapes reviewed package",
        )?;
        // Keep these bounded, validated bytes for rendering; do not reopen
        // nested notices through the generic wider top-level reader.
        let bytes = read_scoped_notice(&canonical_base, Path::new(leaf), 65536)?;
        check(!bytes.is_empty(), "ring notice must not be empty")?;
        std::str::from_utf8(&bytes)?;
        leaves.insert(path, bytes);
    }
    Ok(leaves)
}

fn notices_from_metadata(
    root: &Path,
    meta: &Value,
    roots: &[&str],
    title: &str,
) -> Result<Vec<u8>> {
    let reviewed_root = fs::canonicalize(root)?;
    let metadata_root = fs::canonicalize(Path::new(text(meta, "workspace_root")?))?;
    check(
        metadata_root == reviewed_root,
        "notice metadata workspace differs from reviewed root",
    )?;
    let workspace_members = meta["workspace_members"]
        .as_array()
        .ok_or("missing cargo workspace members")?;
    let packages = meta["packages"]
        .as_array()
        .ok_or("missing cargo packages")?;
    let nodes = meta["resolve"]["nodes"]
        .as_array()
        .ok_or("missing cargo dependency graph")?;
    let mut ids = BTreeSet::new();
    let mut pending = Vec::new();
    for name in roots {
        let package = packages
            .iter()
            .find(|p| p["name"] == *name)
            .ok_or("notice root missing")?;
        pending.push(text(package, "id")?.to_string());
    }
    while let Some(id) = pending.pop() {
        if !ids.insert(id.clone()) {
            continue;
        }
        check(
            packages.iter().any(|package| package["id"] == id),
            "notice dependency package missing",
        )?;
        let node = nodes
            .iter()
            .find(|node| node["id"] == id)
            .ok_or("notice dependency graph node missing")?;
        for dep in node["deps"].as_array().ok_or("missing dependency edges")? {
            pending.push(text(dep, "pkg")?.to_string());
        }
    }
    let mut output = String::from(title);
    for package in packages
        .iter()
        .filter(|p| p["id"].as_str().is_some_and(|id| ids.contains(id)))
    {
        output.push_str(&format!(
            "\n{} {} — {}\n",
            text(package, "name")?,
            text(package, "version")?,
            package["license"]
                .as_str()
                .unwrap_or("see included license file")
        ));
        let manifest = Path::new(text(package, "manifest_path")?);
        let base = manifest.parent().ok_or("missing package directory")?;
        let canonical_base = fs::canonicalize(base)?;
        let mut candidates = BTreeSet::new();
        let mut workspace_candidates = BTreeSet::new();
        // Cargo resolves an inherited license expression but does not move its
        // source text into each member directory. Only verified local members
        // that inherit the reviewed workspace license may use its fixed leaves.
        let member = workspace_members.iter().any(|id| id == &package["id"]);
        if member && package["source"].is_null() {
            let canonical_manifest = fs::canonicalize(manifest)?;
            if canonical_manifest.starts_with(&reviewed_root) {
                let bytes = read_scoped_notice(
                    &reviewed_root,
                    canonical_manifest.strip_prefix(&reviewed_root)?,
                    512 * 1024,
                )?;
                let member_manifest: toml::Value = toml::from_str(std::str::from_utf8(&bytes)?)?;
                if member_manifest
                    .get("package")
                    .and_then(|p| p.get("license"))
                    .and_then(|license| license.get("workspace"))
                    .and_then(toml::Value::as_bool)
                    == Some(true)
                {
                    for leaf in ["LICENSE-MIT", "LICENSE-APACHE", "NOTICE"] {
                        let path = reviewed_root.join(leaf);
                        check(path.is_file(), "workspace license or notice text missing")?;
                        let canonical_text = fs::canonicalize(&path)?;
                        check(
                            canonical_text.parent() == Some(reviewed_root.as_path()),
                            "workspace notice text escapes reviewed root",
                        )?;
                        candidates.insert(path);
                        workspace_candidates.insert(canonical_text);
                    }
                }
            }
        }
        if let Some(file) = package["license_file"].as_str() {
            check(
                !file.is_empty()
                    && Path::new(file)
                        .components()
                        .all(|component| matches!(component, Component::Normal(_))),
                "license_file must be a package-relative path",
            )?;
            candidates.insert(base.join(file));
        }
        for entry in fs::read_dir(base)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_uppercase();
            if entry.file_type()?.is_file()
                && ["LICENSE", "COPYING", "NOTICE", "COPYRIGHT"]
                    .iter()
                    .any(|p| name.starts_with(p))
            {
                candidates.insert(entry.path());
            }
        }
        let nested = ring_notice_leaves(package, base)?;
        candidates.extend(nested.keys().cloned());
        for path in candidates {
            let canonical_text = fs::canonicalize(&path)?;
            check(
                canonical_text.starts_with(&canonical_base)
                    || workspace_candidates.contains(&canonical_text),
                "notice text escapes package directory",
            )?;
            let bytes = if let Some(bytes) = nested.get(&path) {
                bytes.clone()
            } else if workspace_candidates.contains(&canonical_text) {
                read_scoped_notice(
                    &reviewed_root,
                    path.strip_prefix(&reviewed_root)?,
                    512 * 1024,
                )?
            } else {
                read_scoped_notice(&canonical_base, path.strip_prefix(base)?, 512 * 1024)?
            };
            output.push_str(std::str::from_utf8(&bytes)?);
            output.push('\n');
        }
    }
    check(
        output.len() < 8 * 1024 * 1024,
        "license notices exceed expected bounds",
    )?;
    Ok(output.into_bytes())
}
pub fn build(
    root: &Path,
    operator: &Path,
    out: &Path,
    channel: &str,
    prerelease: bool,
) -> Result<()> {
    let old = read_json(&operator.join("bundle.manifest.json"))?;
    check(
        old["schema"] == "aegis_release_bundle_manifest_v2",
        "unsupported operator bundle",
    )?;
    let version = text(&old, "version")?;
    let arch = text(&old, "arch")?;
    check(
        ["x86_64", "aarch64"].contains(&arch),
        "unsupported client architecture",
    )?;
    check(
        version.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
        "invalid release version",
    )?;
    let directory = format!("aegis-client-{version}-linux-{arch}");
    let destination = out.join(&directory);
    check(
        !destination.exists(),
        "client output exists; use a fresh output directory",
    )?;
    let mut contents = BTreeMap::new();
    check(
        hash(&read_file(&root.join("Cargo.lock"), 4 * 1024 * 1024)?) == old["cargo_lock_sha256"],
        "operator bundle dependency provenance differs from builder",
    )?;
    let sums_bytes = read_file(&operator.join("SHA256SUMS"), 65536)?;
    let sums_text = std::str::from_utf8(&sums_bytes)?;
    let source_sums: BTreeMap<&str, &str> = sums_text
        .lines()
        .filter_map(|line| {
            line.split_once("  ")
                .map(|(digest, name)| (name.trim_start_matches("./"), digest))
        })
        .collect();
    for name in payload_for_schema(CLIENT_BUNDLE_SCHEMA_V2)? {
        let bytes = match name {
            "README.txt" => read_file(&root.join("packaging/client/README.txt"), 65536)?,
            "THIRD-PARTY-NOTICES.txt" => notices(root, text(&old, "target_triple")?)?,
            _ => {
                let bytes = read_file(&operator.join(name), MAX_ARCHIVE)?;
                check(
                    source_sums.get(name).copied() == Some(hash(&bytes).as_str()),
                    "client input differs from operator bundle checksums",
                )?;
                bytes
            }
        };
        contents.insert(name.to_string(), bytes);
    }
    check(
        hash(&contents["bin/aegis-client"]) == old["binaries"]["aegis-client"]["sha256"],
        "client binary differs from operator provenance",
    )?;
    let inventory = crate::shipping_client_inventory::generate(
        root,
        operator,
        &old,
        &contents["bin/aegis-client"],
    )?;
    contents.insert(crate::shipping_client_inventory::LEAF.into(), inventory);
    let sums: String = contents
        .iter()
        .map(|(name, bytes)| format!("{}  {name}\n", hash(bytes)))
        .collect();
    contents.insert("SHA256SUMS".into(), sums.into_bytes());
    let inner = json!({
        "schema": CLIENT_BUNDLE_SCHEMA_V3, "distribution": "public_client",
        "bundle_name": directory, "version": version, "arch": arch, "platform": "linux",
        "target_triple": old["target_triple"], "git_sha": old["git_sha"], "build_timestamp": old["build_timestamp"],
        "cargo_lock_sha256": old["cargo_lock_sha256"],
        "runtime_abi": {"libc_family":"glibc", "generic_linux_min_glibc": old["runtime_abi"]["generic_linux_min_glibc"],
            "binary_required_glibc": {"aegis-client": old["runtime_abi"]["binary_required_glibc"]["aegis-client"]}},
        "binaries": {"aegis-client": old["binaries"]["aegis-client"]},
        "files": contents.keys().collect::<Vec<_>>(), "install_entrypoints": ["./install.sh client --bundle /path/to/private-bundle"]
    });
    contents.insert(
        "bundle.manifest.json".into(),
        serde_json::to_vec_pretty(&inner)?,
    );
    // Preflight every staged path before creating any output. append_data can
    // otherwise silently insert a GNU LongLink even for a USTAR header.
    let headers = public_ustar_headers(&directory, &contents)?;
    fs::create_dir_all(&destination)?;
    for (name, bytes) in &contents {
        let path = destination.join(name);
        fs::create_dir_all(path.parent().ok_or("missing parent")?)?;
        fs::write(&path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(if name.ends_with(".sh") || name.starts_with("bin/") {
                    0o755
                } else {
                    0o644
                }),
            )?;
        }
    }
    let archive_name = format!("{directory}.tar.gz");
    let compressor = GzEncoder::new(
        fs::File::create(out.join(&archive_name))?,
        Compression::default(),
    );
    let mut archive = tar::Builder::new(compressor);
    for ((name, bytes), mut header) in contents.iter().zip(headers) {
        header.set_size(bytes.len() as u64);
        header.set_mode(if name.ends_with(".sh") || name.starts_with("bin/") {
            0o755
        } else {
            0o644
        });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive.append(&header, bytes.as_slice())?;
    }
    archive.into_inner()?.finish()?;
    let archive_bytes = read_file(&out.join(&archive_name), MAX_ARCHIVE)?;
    validate_archive(&archive_bytes, &inner)?;
    fs::write(
        out.join(format!("{archive_name}.sha256")),
        format!("{}  {archive_name}\n", hash(&archive_bytes)),
    )?;
    let bootstrap = read_file(&root.join("bootstrap-install.sh"), 256 * 1024)?;
    fs::write(out.join("bootstrap-install.sh"), &bootstrap)?;
    let manifest = json!({
        "schema": "aegis_linux_release_manifest_v1", "distribution":"public_client",
        "version":version, "arch":arch, "platform":"linux", "target_triple":old["target_triple"],
        "git_sha":old["git_sha"], "build_timestamp":old["build_timestamp"], "channel":channel, "prerelease":prerelease,
        "artifacts":{"bundle":{"status":"ready", "directory":directory, "archive":{"path":archive_name,"sha256":hash(&archive_bytes),"sha256_path":format!("{archive_name}.sha256")}}},
        "bootstrap":{"path":"bootstrap-install.sh", "sha256":hash(&bootstrap)},
        "delivery_contract":{"roles":["client"],"role_config_install_requires_bundle":true,"source_checkout_required":false,"github_required":false}
    });
    write_json(
        &out.join(if arch == "aarch64" {
            "client-release.manifest-aarch64.json"
        } else {
            "client-release.manifest.json"
        }),
        &manifest,
    )?;
    Ok(())
}

fn public_ustar_headers(
    directory: &str,
    contents: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<tar::Header>> {
    contents
        .keys()
        .map(|name| {
            let mut header = tar::Header::new_ustar();
            header
                .set_path(format!("{directory}/{name}"))
                .map_err(|_| "public archive path exceeds USTAR bounds")?;
            Ok(header)
        })
        .collect()
}

fn validate_archive(bytes: &[u8], expected_inner: &Value) -> Result<()> {
    let directory = text(expected_inner, "bundle_name")?;
    let mut gzip = GzDecoder::new(bytes);
    let mut expanded = Vec::new();
    gzip.by_ref()
        .take(MAX_ARCHIVE + 1)
        .read_to_end(&mut expanded)?;
    check(
        expanded.len() as u64 <= MAX_ARCHIVE,
        "expanded archive exceeds limit",
    )?;
    check(
        gzip.into_inner().is_empty(),
        "trailing data or extra gzip member forbidden",
    )?;
    let mut archive = tar::Archive::new(Cursor::new(expanded));
    let allowed: BTreeSet<String> = payload_for_schema(text(expected_inner, "schema")?)?
        .into_iter()
        .chain(["SHA256SUMS", "bundle.manifest.json"])
        .map(str::to_string)
        .collect();
    let mut contents = BTreeMap::new();
    let mut total = 0;
    for entry in archive.entries()? {
        let mut entry = entry?;
        check(
            entry.header().entry_type().is_file(),
            "public archive contains a non-regular entry",
        )?;
        check(
            entry.header().mode()? & 0o7000 == 0,
            "special file modes forbidden",
        )?;
        let path = entry.path()?.into_owned();
        check(
            path.components().all(|c| matches!(c, Component::Normal(_))),
            "unsafe archive path",
        )?;
        let relative = path
            .strip_prefix(directory)?
            .to_str()
            .ok_or("non-UTF8 archive path")?
            .to_string();
        check(
            allowed.contains(&relative) && !contents.contains_key(&relative),
            "unexpected or duplicate public archive file",
        )?;
        total += entry.size();
        check(total <= MAX_ARCHIVE, "expanded archive exceeds limit")?;
        let mut body = Vec::new();
        entry.read_to_end(&mut body)?;
        contents.insert(relative, body);
    }
    let remainder = archive.into_inner();
    check(
        remainder.get_ref()[remainder.position() as usize..]
            .iter()
            .all(|b| *b == 0),
        "nonzero trailing tar data forbidden",
    )?;
    check(
        contents.keys().cloned().collect::<BTreeSet<_>>() == allowed,
        "incomplete public archive",
    )?;
    let inner: Value = serde_json::from_slice(&contents["bundle.manifest.json"])?;
    check(&inner == expected_inner, "inner client provenance mismatch")?;
    payload_for_schema(text(&inner, "schema")?)?;
    keys(
        &inner,
        &[
            "schema",
            "distribution",
            "bundle_name",
            "version",
            "arch",
            "platform",
            "target_triple",
            "git_sha",
            "build_timestamp",
            "cargo_lock_sha256",
            "runtime_abi",
            "binaries",
            "files",
            "install_entrypoints",
        ],
    )?;
    keys(&inner["binaries"], &["aegis-client"])?;
    keys(
        &inner["binaries"]["aegis-client"],
        &["features", "path", "sha256"],
    )?;
    let features = inner["binaries"]["aegis-client"]["features"]
        .as_array()
        .ok_or("missing client build features")?;
    check(
        features
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>()
            == ["raw-socket", "chrome-like-tls", "chrome-like-quic"]
                .into_iter()
                .collect()
            && features.len() == 3,
        "unexpected public client build features",
    )?;
    check(
        inner["distribution"] == "public_client"
            && inner["binaries"]["aegis-client"]["path"] == "bin/aegis-client",
        "invalid client scope",
    )?;
    check(
        hash(&contents["bin/aegis-client"]) == inner["binaries"]["aegis-client"]["sha256"],
        "client executable digest mismatch",
    )?;
    if inner["schema"] == CLIENT_BUNDLE_SCHEMA_V3 {
        crate::shipping_client_inventory::validate(
            &contents[crate::shipping_client_inventory::LEAF],
            &inner,
            &contents["bin/aegis-client"],
        )?;
    }
    let mut expected_sums = String::new();
    for (name, body) in &contents {
        if name != "SHA256SUMS" && name != "bundle.manifest.json" {
            expected_sums.push_str(&format!("{}  {name}\n", hash(body)));
        }
    }
    check(
        contents["SHA256SUMS"] == expected_sums.as_bytes(),
        "client file checksums mismatch",
    )?;
    let listed: BTreeSet<String> = inner["files"]
        .as_array()
        .ok_or("missing inner file list")?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    check(
        listed.len() == inner["files"].as_array().unwrap().len(),
        "duplicate inner inventory entry",
    )?;
    check(
        listed
            == allowed
                .into_iter()
                .filter(|s| s != "bundle.manifest.json")
                .collect(),
        "client provenance inventory mismatch",
    )
}

pub fn stage(release: &Path, out: &Path, public_key: &Path, source: &str) -> Result<()> {
    check(!out.exists(), "mirror destination must not already exist")?;
    check(
        source.len() == 40 && source.bytes().all(|b| b.is_ascii_hexdigit()),
        "exact expected source required",
    )?;
    let mut files = BTreeMap::new();
    let key = ed25519_public_key(&read_file(public_key, 4096)?)?;
    let mut release_identity = None;
    let mut payload_schema = None;
    for (arch, name) in [
        ("x86_64", "client-release.manifest.json"),
        ("aarch64", "client-release.manifest-aarch64.json"),
    ] {
        let manifest_bytes = read_file(&release.join(name), 65536)?;
        let signature = read_file(&release.join(format!("{name}.sig")), 64)?;
        check(signature.len() == 64, "invalid signature length")?;
        // Verify the same bounded bytes that will be staged, never reread mutable inputs.
        UnparsedPublicKey::new(&ED25519, key)
            .verify(&manifest_bytes, &signature)
            .map_err(|_| "public client signature verification failed")?;
        let m: Value = serde_json::from_slice(&manifest_bytes)?;
        let mut outer_fields = vec![
            "schema",
            "distribution",
            "version",
            "arch",
            "platform",
            "target_triple",
            "git_sha",
            "build_timestamp",
            "channel",
            "prerelease",
            "artifacts",
            "bootstrap",
            "delivery_contract",
        ];
        if m.get("release_policy").is_some() {
            outer_fields.push("release_policy");
            validate_release_policy(
                &m,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            )?;
        }
        keys(&m, &outer_fields)?;
        keys(&m["bootstrap"], &["path", "sha256"])?;
        keys(
            &m["artifacts"]["bundle"],
            &["status", "directory", "archive"],
        )?;
        keys(
            &m["artifacts"]["bundle"]["archive"],
            &["path", "sha256", "sha256_path"],
        )?;
        check(
            m["delivery_contract"]
                == json!({"roles":["client"], "role_config_install_requires_bundle":true, "source_checkout_required":false, "github_required":false}),
            "invalid public delivery contract",
        )?;
        let identity = json!([
            m["version"],
            m["channel"],
            m["prerelease"],
            m["bootstrap"],
            m["release_policy"]
        ]);
        if let Some(previous) = &release_identity {
            check(
                previous == &identity,
                "architectures describe different releases",
            )?;
        }
        release_identity = Some(identity);
        check(
            m["distribution"] == "public_client"
                && m["git_sha"] == source
                && m["arch"] == arch
                && m["platform"] == "linux",
            "public release identity/scope mismatch",
        )?;
        check(
            text(&m, "version")?
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'.'),
            "invalid release version",
        )?;
        check(
            m["schema"] == "aegis_linux_release_manifest_v1"
                && m["target_triple"] == format!("{arch}-unknown-linux-gnu"),
            "unexpected client platform metadata",
        )?;
        check(
            m["artifacts"]
                .as_object()
                .is_some_and(|a| a.len() == 1 && a.contains_key("bundle")),
            "public manifest must not reference operator artifacts",
        )?;
        let directory = format!("aegis-client-{}-linux-{arch}", text(&m, "version")?);
        let archive_name = format!("{directory}.tar.gz");
        check(
            m["artifacts"]["bundle"]["status"] == "ready"
                && m["artifacts"]["bundle"]["directory"] == directory
                && m["artifacts"]["bundle"]["archive"]["sha256_path"]
                    == format!("{archive_name}.sha256")
                && m["bootstrap"]["path"] == "bootstrap-install.sh",
            "invalid artifact metadata",
        )?;
        check(
            m["artifacts"]["bundle"]["archive"]["path"] == archive_name,
            "noncanonical public archive path",
        )?;
        let archive_bytes = read_file(&release.join(&archive_name), MAX_ARCHIVE)?;
        check(
            hash(&archive_bytes) == m["artifacts"]["bundle"]["archive"]["sha256"],
            "signed archive digest mismatch",
        )?;
        // Read the inner metadata without extracting any archive entry to disk.
        let mut a =
            tar::Archive::new(GzDecoder::new(archive_bytes.as_slice()).take(MAX_ARCHIVE + 1));
        let mut inner = None;
        for entry in a.entries()? {
            let mut entry = entry?;
            if entry.path()? == Path::new(&format!("{directory}/bundle.manifest.json")) {
                let mut body = Vec::new();
                entry.by_ref().take(65537).read_to_end(&mut body)?;
                check(body.len() <= 65536, "inner manifest too large")?;
                inner = Some(serde_json::from_slice::<Value>(&body)?);
                break;
            }
        }
        let inner = inner.ok_or("missing client inner manifest")?;
        check(
            inner["git_sha"] == source
                && inner["arch"] == arch
                && inner["bundle_name"] == directory
                && inner["version"] == m["version"]
                && inner["platform"] == m["platform"]
                && inner["target_triple"] == m["target_triple"]
                && inner["build_timestamp"] == m["build_timestamp"],
            "inner release identity mismatch",
        )?;
        validate_archive(&archive_bytes, &inner)?;
        let schema = text(&inner, "schema")?;
        if let Some(previous) = payload_schema {
            check(
                previous == schema,
                "architectures use different public payload schemas",
            )?;
        }
        payload_schema = Some(schema.to_string());
        let bootstrap = read_file(&release.join("bootstrap-install.sh"), 256 * 1024)?;
        check(
            hash(&bootstrap) == m["bootstrap"]["sha256"],
            "bootstrap differs from signed client manifest",
        )?;
        let checksum = read_file(&release.join(format!("{archive_name}.sha256")), 1024)?;
        check(
            checksum == format!("{}  {archive_name}\n", hash(&archive_bytes)).as_bytes(),
            "archive checksum sidecar mismatch",
        )?;
        files.insert(archive_name.clone(), archive_bytes);
        files.insert(format!("{archive_name}.sha256"), checksum);
        files.insert(name.to_string(), manifest_bytes);
        files.insert(format!("{name}.sig"), signature);
        files.insert("bootstrap-install.sh".to_string(), bootstrap);
    }
    // No source access or credentials are required by the uploader after this stage.
    fs::create_dir(out)?;
    for (name, bytes) in &files {
        fs::write(out.join(name), bytes)?;
    }
    exact_directory(out, &files.keys().cloned().collect())?;
    println!(
        "public-client-mirror: PASS ({} objects, two signed architectures)",
        files.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ring_nested_notice_invalid_text_and_nonregular_inputs_are_refused() {
        let (_work, root, ring, meta) = ring_notice_fixture();
        for leaf in [
            "third_party/fiat/LICENSE",
            "src/polyfill/once_cell/LICENSE-MIT",
        ] {
            let path = ring.join(leaf);
            let original = fs::read(&path).unwrap();
            let boundary = vec![b'x'; 65536];
            fs::write(&path, &boundary).unwrap();
            let rendered = String::from_utf8(
                notices_from_metadata(&root, &meta, &["ring"], "fixture\n").unwrap(),
            )
            .unwrap();
            assert_eq!(
                rendered
                    .matches(std::str::from_utf8(&boundary).unwrap())
                    .count(),
                1
            );
            for invalid in [Vec::new(), vec![b'x'; 65537], vec![0xff]] {
                fs::write(&path, invalid).unwrap();
                assert!(notices_from_metadata(&root, &meta, &["ring"], "fixture\n").is_err());
            }
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();
            assert!(notices_from_metadata(&root, &meta, &["ring"], "fixture\n").is_err());
            fs::remove_dir(&path).unwrap();
            fs::write(&path, original).unwrap();
        }
        // A non-directory package base must fail without traversal.
        let file_base = ring.join("not-a-directory");
        fs::write(&file_base, "fixture\n").unwrap();
        assert!(ring_notice_leaves(&meta["packages"][0], &file_base).is_err());
    }

    #[test]
    fn unreachable_unreviewed_ring_metadata_does_not_affect_other_roots() {
        let (_work, root, ring, mut meta) = ring_notice_fixture();
        fs::write(root.join("Cargo.toml"), "[package]\nname = \"other\"\n").unwrap();
        fs::write(root.join("LICENSE"), "other root fixture\n").unwrap();
        meta["packages"][0]["version"] = json!("0.17.15");
        meta["packages"][0]["source"] = json!("git+https://example.invalid/ring");
        meta["packages"].as_array_mut().unwrap().push(json!({
            "id":"other","name":"other","version":"1","license":"MIT",
            "manifest_path":root.join("Cargo.toml"),"source":null
        }));
        meta["resolve"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"other","deps":[]}));
        let rendered = String::from_utf8(
            notices_from_metadata(&root, &meta, &["other"], "fixture\n").unwrap(),
        )
        .unwrap();
        assert!(rendered.contains("other root fixture"));
        assert!(!rendered.contains("ring 0.17.15"));
        assert!(!rendered.contains("unique nested fixture"));
        fs::remove_file(ring.join("third_party/fiat/LICENSE")).unwrap();
        assert!(notices_from_metadata(&root, &meta, &["other"], "fixture\n").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn ring_package_base_symlink_and_retained_owned_bytes_are_checked() {
        let (work, root, ring, mut meta) = ring_notice_fixture();
        let owned = ring_notice_leaves(&meta["packages"][0], &ring).unwrap();
        let leaf = ring.join("third_party/fiat/LICENSE");
        let bytes = owned.get(&leaf).unwrap().clone();
        fs::write(&leaf, "changed after validation\n").unwrap();
        assert_eq!(owned.get(&leaf).unwrap(), &bytes);
        let alias = work.0.join("package-alias");
        std::os::unix::fs::symlink(&ring, &alias).unwrap();
        meta["packages"][0]["manifest_path"] = json!(alias.join("Cargo.toml"));
        assert!(notices_from_metadata(&root, &meta, &["ring"], "fixture\n").is_err());
    }

    fn ring_notice_fixture() -> (Scratch, PathBuf, PathBuf, Value) {
        let work = Scratch::new().unwrap();
        let root = work.0.join("workspace");
        let ring = work.0.join("ring-0.17.14");
        fs::create_dir_all(&root).unwrap();
        for leaf in [
            "third_party/fiat/LICENSE",
            "src/polyfill/once_cell/LICENSE-MIT",
        ] {
            fs::create_dir_all(ring.join(leaf).parent().unwrap()).unwrap();
            fs::write(ring.join(leaf), format!("unique nested fixture: {leaf}\n")).unwrap();
        }
        fs::write(
            ring.join("Cargo.toml"),
            "[package]\nname = \"ring\"\nversion = \"0.17.14\"\n",
        )
        .unwrap();
        fs::write(ring.join("LICENSE"), "unique root fixture\n").unwrap();
        let meta = json!({
            "workspace_root":root,"workspace_members":[],
            "packages":[{"id":"ring","name":"ring","version":"0.17.14","license":"Apache-2.0 AND ISC",
                "manifest_path":ring.join("Cargo.toml"),"source":"registry+https://github.com/rust-lang/crates.io-index"}],
            "resolve":{"nodes":[{"id":"ring","deps":[]}]}
        });
        (work, root, ring, meta)
    }

    #[test]
    fn ring_nested_notice_texts_are_included_once_with_root_text() {
        let (_work, root, _ring, meta) = ring_notice_fixture();
        let rendered =
            String::from_utf8(notices_from_metadata(&root, &meta, &["ring"], "fixture\n").unwrap())
                .unwrap();
        for body in [
            "unique root fixture",
            "unique nested fixture: third_party/fiat/LICENSE",
            "unique nested fixture: src/polyfill/once_cell/LICENSE-MIT",
        ] {
            assert_eq!(rendered.matches(body).count(), 1);
        }
    }

    #[test]
    fn ring_nested_notices_require_reviewed_identity_and_present_leaves() {
        let (_work, root, ring, meta) = ring_notice_fixture();
        for (key, value) in [
            ("version", "0.17.15"),
            ("source", "git+https://example.invalid/ring"),
        ] {
            let mut changed = meta.clone();
            changed["packages"][0][key] = json!(value);
            assert!(notices_from_metadata(&root, &changed, &["ring"], "fixture\n").is_err());
        }
        for leaf in [
            "third_party/fiat/LICENSE",
            "src/polyfill/once_cell/LICENSE-MIT",
        ] {
            let path = ring.join(leaf);
            let bytes = fs::read(&path).unwrap();
            fs::remove_file(&path).unwrap();
            assert!(notices_from_metadata(&root, &meta, &["ring"], "fixture\n").is_err());
            fs::write(path, bytes).unwrap();
        }
    }

    #[test]
    fn notices_refuse_incomplete_reachable_cargo_graph() {
        let (_work, root, _ring, meta) = ring_notice_fixture();
        let mut missing_nodes = meta.clone();
        missing_nodes["resolve"]["nodes"] = json!([]);
        assert!(notices_from_metadata(&root, &missing_nodes, &["ring"], "fixture\n").is_err());

        let mut missing_package = meta.clone();
        missing_package["resolve"]["nodes"][0]["deps"] = json!([{"pkg":"absent"}]);
        assert!(notices_from_metadata(&root, &missing_package, &["ring"], "fixture\n").is_err());

        let mut missing_dependency_node = meta.clone();
        missing_dependency_node["resolve"]["nodes"][0]["deps"] = json!([{"pkg":"other"}]);
        missing_dependency_node["packages"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"other","name":"other","version":"1","license":"MIT",
                "manifest_path":root.join("other/Cargo.toml"),"source":null
            }));
        assert!(
            notices_from_metadata(&root, &missing_dependency_node, &["ring"], "fixture\n").is_err()
        );
    }

    #[test]
    fn notices_refuse_license_file_outside_package() {
        let (work, root, ring, meta) = ring_notice_fixture();
        let outside = work.0.join("outside-license");
        fs::write(&outside, "outside text must not enter notices\n").unwrap();
        for file in ["../outside-license", outside.to_str().unwrap()] {
            let mut changed = meta.clone();
            changed["packages"][0]["license_file"] = json!(file);
            assert!(notices_from_metadata(&root, &changed, &["ring"], "fixture\n").is_err());
        }
        fs::write(ring.join("LICENSE-CUSTOM"), "package-local license\n").unwrap();
        let mut valid = meta;
        valid["packages"][0]["license_file"] = json!("LICENSE-CUSTOM");
        let rendered = notices_from_metadata(&root, &valid, &["ring"], "fixture\n").unwrap();
        assert!(String::from_utf8(rendered)
            .unwrap()
            .contains("package-local license"));
    }

    #[cfg(unix)]
    #[test]
    fn notices_refuse_license_file_parent_symlink_escape() {
        let (work, root, ring, mut meta) = ring_notice_fixture();
        let outside = work.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(
            outside.join("LICENSE"),
            "outside text must not enter notices\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, ring.join("linked")).unwrap();
        meta["packages"][0]["license_file"] = json!("linked/LICENSE");
        assert!(notices_from_metadata(&root, &meta, &["ring"], "fixture\n").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn scoped_notice_read_never_follows_a_swapped_parent_link() {
        use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

        let work = Scratch::new().unwrap();
        let package = work.0.join("package");
        let outside = work.0.join("outside");
        fs::create_dir(&package).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::create_dir(package.join("entry")).unwrap();
        fs::write(package.join("entry/LICENSE"), "inside\n").unwrap();
        fs::write(outside.join("LICENSE"), "outside\n").unwrap();
        std::os::unix::fs::symlink(&outside, package.join("alias")).unwrap();
        let canonical_package = fs::canonicalize(&package).unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let writer_running = Arc::clone(&running);
        let writer_package = package.clone();
        let writer = std::thread::spawn(move || {
            let mut swaps = 0;
            while writer_running.load(Ordering::Relaxed) {
                fs::rename(writer_package.join("entry"), writer_package.join("parked")).unwrap();
                fs::rename(writer_package.join("alias"), writer_package.join("entry")).unwrap();
                fs::rename(writer_package.join("entry"), writer_package.join("alias")).unwrap();
                fs::rename(writer_package.join("parked"), writer_package.join("entry")).unwrap();
                swaps += 1;
            }
            swaps
        });
        let mut accepted = 0;
        for _ in 0..2000 {
            if let Ok(bytes) =
                read_scoped_notice(&canonical_package, Path::new("entry/LICENSE"), 65536)
            {
                assert_eq!(bytes, b"inside\n");
                accepted += 1;
            }
        }
        running.store(false, Ordering::Relaxed);
        assert!(writer.join().unwrap() > 0);
        assert!(accepted > 0);
    }

    #[cfg(windows)]
    #[test]
    fn scoped_notice_windows_reads_held_file_and_refuses_parent_escape() {
        let work = Scratch::new().unwrap();
        let package = work.0.join("package");
        fs::create_dir(&package).unwrap();
        fs::write(package.join("LICENSE"), b"inside\n").unwrap();
        assert_eq!(
            read_scoped_notice(&package, Path::new("LICENSE"), 64).unwrap(),
            b"inside\n"
        );
        assert!(read_scoped_notice(&package, Path::new("../LICENSE"), 64).is_err());
        assert!(read_scoped_notice(&package, Path::new("LICENSE"), 2).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn scoped_notice_windows_refuses_package_junction_after_anchor_review() {
        let work = Scratch::new().unwrap();
        let package = work.0.join("package");
        let parked = work.0.join("parked");
        let outside = work.0.join("outside");
        fs::create_dir(&package).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(package.join("LICENSE"), b"inside\n").unwrap();
        fs::write(outside.join("LICENSE"), b"outside\n").unwrap();
        let reviewed = fs::canonicalize(&package).unwrap();
        assert_eq!(
            read_scoped_notice(&reviewed, Path::new("LICENSE"), 64).unwrap(),
            b"inside\n"
        );
        fs::rename(&package, &parked).unwrap();
        let mklink = Command::new("cmd.exe")
            .args(["/C", "mklink", "/J"])
            .arg(&package)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            mklink.status.success(),
            "junction fixture failed: {:?}",
            mklink.status
        );
        assert!(read_scoped_notice(&reviewed, Path::new("LICENSE"), 64).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn scoped_notice_windows_refuses_existing_leaf_writer() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let work = Scratch::new().unwrap();
        let package = work.0.join("package");
        fs::create_dir(&package).unwrap();
        let leaf = package.join("LICENSE");
        fs::write(&leaf, b"stable\n").unwrap();
        let writer = fs::OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&leaf)
            .unwrap();
        assert!(read_scoped_notice(&package, Path::new("LICENSE"), 64).is_err());
        drop(writer);
        assert_eq!(
            read_scoped_notice(&package, Path::new("LICENSE"), 64).unwrap(),
            b"stable\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn scoped_notice_read_never_follows_a_swapped_base_link() {
        use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

        let work = Scratch::new().unwrap();
        let package = work.0.join("package");
        let outside = work.0.join("outside");
        fs::create_dir(&package).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(package.join("LICENSE"), "inside\n").unwrap();
        fs::write(outside.join("LICENSE"), "outside\n").unwrap();
        std::os::unix::fs::symlink(&outside, work.0.join("alias")).unwrap();
        let canonical_package = fs::canonicalize(&package).unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let writer_running = Arc::clone(&running);
        let writer_root = work.0.clone();
        let writer = std::thread::spawn(move || {
            let mut swaps = 0;
            while writer_running.load(Ordering::Relaxed) {
                fs::rename(writer_root.join("package"), writer_root.join("parked")).unwrap();
                fs::rename(writer_root.join("alias"), writer_root.join("package")).unwrap();
                fs::rename(writer_root.join("package"), writer_root.join("alias")).unwrap();
                fs::rename(writer_root.join("parked"), writer_root.join("package")).unwrap();
                swaps += 1;
            }
            swaps
        });
        let mut accepted = 0;
        for _ in 0..2000 {
            if let Ok(bytes) = read_scoped_notice(&canonical_package, Path::new("LICENSE"), 65536) {
                assert_eq!(bytes, b"inside\n");
                accepted += 1;
            }
        }
        running.store(false, Ordering::Relaxed);
        assert!(writer.join().unwrap() > 0);
        assert!(accepted > 0);
    }

    #[cfg(unix)]
    #[test]
    fn ring_nested_notice_symlink_escape_is_refused() {
        let (work, root, ring, meta) = ring_notice_fixture();
        let outside = work.0.join("outside-license");
        fs::write(&outside, "must not be copied\n").unwrap();
        let leaf = ring.join("third_party/fiat/LICENSE");
        fs::remove_file(&leaf).unwrap();
        std::os::unix::fs::symlink(&outside, &leaf).unwrap();
        assert!(notices_from_metadata(&root, &meta, &["ring"], "fixture\n").is_err());
        fs::remove_file(&leaf).unwrap();
        fs::write(&leaf, "restored fixture\n").unwrap();
        let directory = ring.join("src/polyfill/once_cell");
        fs::remove_file(directory.join("LICENSE-MIT")).unwrap();
        fs::remove_dir(&directory).unwrap();
        std::os::unix::fs::symlink(work.0.join("outside-directory"), &directory).unwrap();
        assert!(notices_from_metadata(&root, &meta, &["ring"], "fixture\n").is_err());
    }

    #[test]
    fn workspace_license_texts_follow_verified_members_not_external_siblings() {
        let work = Scratch::new().unwrap();
        let root = work.0.join("workspace");
        let own = root.join("aegis-client");
        let external = work.0.join("external-crate");
        fs::create_dir_all(&own).unwrap();
        fs::create_dir_all(&external).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\n[workspace.package]\nlicense = \"MIT OR Apache-2.0\"\n",
        )
        .unwrap();
        fs::write(
            own.join("Cargo.toml"),
            "[package]\nname = \"aegis-client\"\nlicense.workspace = true\n",
        )
        .unwrap();
        fs::write(
            external.join("Cargo.toml"),
            "[package]\nname = \"external-crate\"\nlicense = \"BSD-2-Clause\"\n",
        )
        .unwrap();
        for (leaf, body) in [
            ("LICENSE-MIT", "actual workspace MIT text fixture"),
            ("LICENSE-APACHE", "actual workspace Apache text fixture"),
            ("NOTICE", "actual workspace attribution fixture"),
        ] {
            fs::write(root.join(leaf), body).unwrap();
        }
        fs::write(external.join("LICENSE"), "external BSD text fixture").unwrap();
        let meta = json!({
            "workspace_root": root,
            // Also claim the sibling as a member: containment must independently
            // prevent our license texts from being assigned to an external crate.
            "workspace_members": ["own", "external"],
            "packages": [
                {"id":"own", "name":"aegis-client", "version":"1", "license":"MIT OR Apache-2.0", "manifest_path":own.join("Cargo.toml"), "source":null},
                {"id":"external", "name":"external-crate", "version":"1", "license":"BSD-2-Clause", "manifest_path":external.join("Cargo.toml"), "source":null}
            ],
            "resolve":{"nodes":[{"id":"own", "deps":[{"pkg":"external"}]}, {"id":"external", "deps":[]}]}
        });
        let rendered = String::from_utf8(
            notices_from_metadata(&root, &meta, &["aegis-client"], "fixture notices\n").unwrap(),
        )
        .unwrap();
        let (own_section, external_section) = rendered.split_once("external-crate 1").unwrap();
        for body in [
            "actual workspace MIT text fixture",
            "actual workspace Apache text fixture",
            "actual workspace attribution fixture",
        ] {
            assert!(own_section.contains(body));
            assert!(!external_section.contains(body));
        }
        assert!(external_section.contains("external BSD text fixture"));
        let mut wrong_root = meta.clone();
        wrong_root["workspace_root"] = json!(external);
        assert!(
            notices_from_metadata(&root, &wrong_root, &["aegis-client"], "fixture notices\n")
                .is_err()
        );
        for leaf in ["LICENSE-MIT", "LICENSE-APACHE", "NOTICE"] {
            let path = root.join(leaf);
            let bytes = fs::read(&path).unwrap();
            fs::remove_file(&path).unwrap();
            assert!(
                notices_from_metadata(&root, &meta, &["aegis-client"], "fixture notices\n")
                    .is_err()
            );
            fs::write(path, bytes).unwrap();
        }
    }
    use super::*;
    use std::io::Write;

    #[test]
    fn signed_release_policy_is_bounded_and_matches_identity() {
        let mut manifest = json!({"version":"1.2.3", "channel":"rc", "prerelease":true,
            "release_policy":{"schema":"aegis_release_policy_v1",
                "authority":"github:fixture/repository:.github/workflows/release.yml",
                "sequence":123, "tag":"v1.2.3-rc.4", "issued_at_unix":1000,
                "expires_at_unix":2000}});
        validate_release_policy(&manifest, 1500).unwrap();
        assert!(validate_release_policy(&manifest, 2000).is_err());
        assert!(validate_release_policy(&manifest, 699).is_err());
        for (key, value) in [
            ("sequence", json!(true)),
            ("sequence", json!(0)),
            ("tag", json!("v1.2.3")),
            ("tag", json!("v1.2.3-rc.04")),
            (
                "authority",
                json!("github:fixture/repository:.github/workflows/other.yml"),
            ),
            ("expires_at_unix", json!(1000 + 31 * 86400)),
        ] {
            let mut bad = manifest.clone();
            bad["release_policy"][key] = value;
            assert!(validate_release_policy(&bad, 1500).is_err());
        }
        manifest["release_policy"]["unexpected"] = json!("extra");
        assert!(validate_release_policy(&manifest, 1500).is_err());
    }

    // Inert fixtures only: these are never executed or published as releases.
    fn fixture(arch: &str) -> (Value, BTreeMap<String, Vec<u8>>) {
        fixture_schema(arch, CLIENT_BUNDLE_SCHEMA_V1)
    }
    fn fixture_schema(arch: &str, schema: &str) -> (Value, BTreeMap<String, Vec<u8>>) {
        let directory = format!("aegis-client-0.0.0-linux-{arch}");
        let mut files: BTreeMap<String, Vec<u8>> = payload_for_schema(schema)
            .unwrap()
            .into_iter()
            .map(|name| {
                (
                    name.to_string(),
                    format!("inert fixture: {name}\n").into_bytes(),
                )
            })
            .collect();
        let sums: String = files
            .iter()
            .map(|(name, body)| format!("{}  {name}\n", hash(body)))
            .collect();
        files.insert("SHA256SUMS".into(), sums.into_bytes());
        let inner = json!({"schema":schema, "distribution":"public_client",
            "bundle_name":directory, "version":"0.0.0", "arch":arch, "platform":"linux", "target_triple":format!("{arch}-unknown-linux-gnu"),
            "git_sha":"a".repeat(40), "build_timestamp":"2026-09-08T00:00:00Z", "cargo_lock_sha256":"b".repeat(64),
            "runtime_abi":{}, "binaries":{"aegis-client":{"path":"bin/aegis-client", "features":["raw-socket","chrome-like-tls","chrome-like-quic"], "sha256":hash(&files["bin/aegis-client"])}},
            "files":files.keys().collect::<Vec<_>>(), "install_entrypoints":[]});
        files.insert(
            "bundle.manifest.json".into(),
            serde_json::to_vec(&inner).unwrap(),
        );
        (inner, files)
    }
    fn encode(
        inner: &Value,
        files: &BTreeMap<String, Vec<u8>>,
        duplicate: bool,
        link: bool,
    ) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (name, bytes) in files {
            let mut header = tar::Header::new_ustar();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(
                &mut header,
                format!("{}/{name}", inner["bundle_name"].as_str().unwrap()),
                bytes.as_slice(),
            )
            .unwrap();
            if duplicate && name == "README.txt" {
                tar.append_data(
                    &mut header,
                    format!("{}/{name}", inner["bundle_name"].as_str().unwrap()),
                    bytes.as_slice(),
                )
                .unwrap();
            }
        }
        if link {
            let mut h = tar::Header::new_ustar();
            h.set_size(0);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_link_name("README.txt").unwrap();
            h.set_cksum();
            tar.append_data(
                &mut h,
                format!("{}/alias", inner["bundle_name"].as_str().unwrap()),
                &[][..],
            )
            .unwrap();
        }
        compress(&tar.into_inner().unwrap())
    }
    fn compress(raw: &[u8]) -> Vec<u8> {
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(raw).unwrap();
        gzip.finish().unwrap()
    }
    #[test]
    fn public_ustar_preflight_rejects_overlong_staged_leaf() {
        let (inner, mut files) = fixture("x86_64");
        let directory = inner["bundle_name"].as_str().unwrap();
        files.insert(format!("scripts/{}", "x".repeat(101)), b"inert".to_vec());
        assert!(public_ustar_headers(directory, &files).is_err());
        // Demonstrate the old path-writing API's extension fallback for this
        // same input; choosing new_ustar alone is insufficient.
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(5);
        archive
            .append_data(
                &mut header,
                format!("{directory}/scripts/{}", "x".repeat(101)),
                &b"inert"[..],
            )
            .unwrap();
        let raw = archive.into_inner().unwrap();
        assert_eq!(raw[156], b'L');
    }

    #[test]
    fn public_ustar_preflight_preserves_current_fixed_payload_paths() {
        for arch in ["x86_64", "aarch64"] {
            let (inner, files) = fixture_schema(arch, CLIENT_BUNDLE_SCHEMA_V3);
            let directory = inner["bundle_name"].as_str().unwrap();
            let headers = public_ustar_headers(directory, &files).unwrap();
            let mut archive = tar::Builder::new(Vec::new());
            for ((name, bytes), mut header) in files.iter().zip(headers) {
                assert_eq!(
                    header.path().unwrap(),
                    Path::new(&format!("{directory}/{name}"))
                );
                header.set_size(bytes.len() as u64);
                header.set_cksum();
                archive.append(&header, bytes.as_slice()).unwrap();
            }
            let raw = archive.into_inner().unwrap();
            let mut offset = 0;
            let mut count = 0;
            while raw[offset..offset + 512].iter().any(|byte| *byte != 0) {
                let header = tar::Header::from_byte_slice(&raw[offset..offset + 512]);
                assert!(header.entry_type().is_file());
                assert!(header.as_ustar().is_some());
                offset += 512 + header.size().unwrap().div_ceil(512) as usize * 512;
                count += 1;
            }
            assert_eq!(count, files.len());
        }
    }
    #[test]
    fn archive_policy_rejects_unapproved_or_inconsistent_content() {
        let (inner, files) = fixture("x86_64");
        let good = encode(&inner, &files, false, false);
        validate_archive(&good, &inner).unwrap();
        for extra in [
            "src/example.rs",
            "Cargo.lock",
            "bin/aegis-server",
            "scripts/operator-review.sh",
        ] {
            let mut changed = files.clone();
            changed.insert(extra.into(), b"inert fixture".to_vec());
            assert!(
                validate_archive(&encode(&inner, &changed, false, false), &inner).is_err(),
                "{extra}"
            );
        }
        assert!(validate_archive(&encode(&inner, &files, true, false), &inner).is_err());
        assert!(validate_archive(&encode(&inner, &files, false, true), &inner).is_err());
        let mut missing = files.clone();
        missing.remove("README.txt");
        assert!(validate_archive(&encode(&inner, &missing, false, false), &inner).is_err());
        let mut changed = files.clone();
        changed.insert(
            "bin/aegis-client".into(),
            b"different inert fixture".to_vec(),
        );
        assert!(validate_archive(&encode(&inner, &changed, false, false), &inner).is_err());
    }
    #[test]
    fn device_guard_is_exactly_one_versioned_public_payload_addition() {
        let legacy = payload_for_schema(CLIENT_BUNDLE_SCHEMA_V1).unwrap();
        let current = payload_for_schema(CLIENT_BUNDLE_SCHEMA_V2).unwrap();
        assert_eq!(legacy.len(), 17);
        assert_eq!(
            current.difference(&legacy).copied().collect::<Vec<_>>(),
            [DEVICE_GUARD_PAYLOAD]
        );
        assert!(legacy.is_subset(&current));
        assert!(payload_for_schema("aegis_client_release_bundle_manifest_v4").is_err());
        let (legacy_inner, mut legacy_files) = fixture("x86_64");
        legacy_files.insert(DEVICE_GUARD_PAYLOAD.into(), b"inert guard".to_vec());
        assert!(validate_archive(
            &encode(&legacy_inner, &legacy_files, false, false),
            &legacy_inner
        )
        .is_err());
        let (inner, files) = fixture_schema("x86_64", CLIENT_BUNDLE_SCHEMA_V2);
        validate_archive(&encode(&inner, &files, false, false), &inner).unwrap();
        let mut missing = files.clone();
        missing.remove(DEVICE_GUARD_PAYLOAD);
        assert!(validate_archive(&encode(&inner, &missing, false, false), &inner).is_err());
        let mut changed = files.clone();
        changed.insert(DEVICE_GUARD_PAYLOAD.into(), b"changed guard bytes".to_vec());
        assert!(validate_archive(&encode(&inner, &changed, false, false), &inner).is_err());
        for extra in [
            "device.key",
            "server.key",
            "aegis-server.toml",
            "bin/aegis-server",
            "src/main.rs",
        ] {
            let mut changed = files.clone();
            changed.insert(extra.into(), b"forbidden public file".to_vec());
            assert!(
                validate_archive(&encode(&inner, &changed, false, false), &inner).is_err(),
                "{extra}"
            );
        }
    }

    #[test]
    fn shipping_inventory_is_v3_only_and_semantically_bound() {
        let v2 = payload_for_schema(CLIENT_BUNDLE_SCHEMA_V2).unwrap();
        let v3 = payload_for_schema(CLIENT_BUNDLE_SCHEMA_V3).unwrap();
        assert_eq!(
            v3.difference(&v2).copied().collect::<Vec<_>>(),
            [crate::shipping_client_inventory::LEAF]
        );
        let (mut inner, mut files) = fixture_schema("x86_64", CLIENT_BUNDLE_SCHEMA_V3);
        let features = json!(["chrome-like-quic", "chrome-like-tls", "raw-socket"]);
        let identity = "c".repeat(64);
        let root = format!("aegis-client@1.0.0#{identity}");
        let inventory = json!({"schema":"aegis_shipping_client_cargo_inventory_v1","scope":"selected_target_filtered_cargo_graph_not_compiler_linkage","native_payload_complete":false,"compiler_linkage_proven":false,"source_revision":inner["git_sha"],"target_triple":inner["target_triple"],"default_features":true,"requested_features":features,"cargo_lock_sha256":inner["cargo_lock_sha256"],"client_binary_sha256":inner["binaries"]["aegis-client"]["sha256"],"cargo_metadata_sha256":"d".repeat(64),"root_component":root,"components":[{"key":root,"name":"aegis-client","version":"1.0.0","source_kind":"reviewed_local_manifest","source_identity_sha256":identity,"features":features,"dependencies":[]}],"producer":{"schema":"aegis_linux_client_build_record_v1","source_revision":inner["git_sha"],"target_triple":inner["target_triple"],"cargo_lock_sha256":inner["cargo_lock_sha256"],"binary_sha256":inner["binaries"]["aegis-client"]["sha256"],"default_features":true,"requested_features":features,"resolved_root_features":features,"compiler_artifact_message_sha256":"e".repeat(64),"build_message_stream_sha256":"f".repeat(64),"target_evidence":"explicit_cargo_target_and_fixed_producer_invocation"}});
        files.insert(
            crate::shipping_client_inventory::LEAF.into(),
            serde_json::to_vec(&inventory).unwrap(),
        );
        fn rehash(inner: &mut Value, files: &mut BTreeMap<String, Vec<u8>>) {
            let sums: String = files
                .iter()
                .filter(|(n, _)| n.as_str() != "SHA256SUMS" && n.as_str() != "bundle.manifest.json")
                .map(|(n, b)| format!("{}  {n}\n", hash(b)))
                .collect();
            files.insert("SHA256SUMS".into(), sums.into_bytes());
            inner["files"] = json!(files
                .keys()
                .filter(|n| n.as_str() != "bundle.manifest.json")
                .collect::<Vec<_>>());
            files.insert(
                "bundle.manifest.json".into(),
                serde_json::to_vec(inner).unwrap(),
            );
        }
        rehash(&mut inner, &mut files);
        validate_archive(&encode(&inner, &files, false, false), &inner).unwrap();
        let mut missing = files.clone();
        missing.remove(crate::shipping_client_inventory::LEAF);
        assert!(validate_archive(&encode(&inner, &missing, false, false), &inner).is_err());
        for field in [
            "source_revision",
            "target_triple",
            "cargo_lock_sha256",
            "client_binary_sha256",
        ] {
            let mut wrong = inventory.clone();
            wrong[field] = json!("incorrect");
            let mut bad_files = files.clone();
            bad_files.insert(
                crate::shipping_client_inventory::LEAF.into(),
                serde_json::to_vec(&wrong).unwrap(),
            );
            let mut bad_inner = inner.clone();
            rehash(&mut bad_inner, &mut bad_files);
            assert!(
                validate_archive(&encode(&bad_inner, &bad_files, false, false), &bad_inner)
                    .is_err()
            );
        }
        let mut old = inner.clone();
        old["schema"] = json!(CLIENT_BUNDLE_SCHEMA_V2);
        assert!(validate_archive(&encode(&old, &files, false, false), &old).is_err());
    }

    #[test]
    fn archive_policy_checks_complete_compressed_and_tar_streams() {
        let (inner, files) = fixture("x86_64");
        let good = encode(&inner, &files, false, false);
        let mut concatenated = good.clone();
        concatenated.extend_from_slice(&good);
        assert!(validate_archive(&concatenated, &inner).is_err());
        assert!(validate_archive(&good[..good.len() - 3], &inner).is_err());
        let mut raw = Vec::new();
        GzDecoder::new(good.as_slice())
            .read_to_end(&mut raw)
            .unwrap();
        raw.extend_from_slice(b"unapproved trailing content");
        assert!(validate_archive(&compress(&raw), &inner).is_err());
    }
    fn signed_release(root: &Path) -> PathBuf {
        signed_release_schemas(root, [CLIENT_BUNDLE_SCHEMA_V1; 2])
    }
    fn signed_release_schemas(root: &Path, schemas: [&str; 2]) -> PathBuf {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let private_der = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(private_der.as_ref()).unwrap();
        let private = root.join("test-key.pem");
        let public = root.join("test-key.pub");
        fs::write(
            &private,
            pem::encode(&pem::Pem::new("PRIVATE KEY", private_der.as_ref().to_vec())),
        )
        .unwrap();
        let mut public_der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        public_der.extend_from_slice(pair.public_key().as_ref());
        fs::write(
            &public,
            pem::encode(&pem::Pem::new("PUBLIC KEY", public_der)),
        )
        .unwrap();
        let bootstrap = b"inert bootstrap fixture\n";
        fs::write(root.join("bootstrap-install.sh"), bootstrap).unwrap();
        for (index, (arch, name)) in [
            ("x86_64", "client-release.manifest.json"),
            ("aarch64", "client-release.manifest-aarch64.json"),
        ]
        .into_iter()
        .enumerate()
        {
            let (inner, files) = fixture_schema(arch, schemas[index]);
            let bytes = encode(&inner, &files, false, false);
            let directory = inner["bundle_name"].as_str().unwrap();
            let archive = format!("{directory}.tar.gz");
            fs::write(root.join(&archive), &bytes).unwrap();
            fs::write(
                root.join(format!("{archive}.sha256")),
                format!("{}  {archive}\n", hash(&bytes)),
            )
            .unwrap();
            let m = json!({"schema":"aegis_linux_release_manifest_v1", "distribution":"public_client",
                "version":"0.0.0", "arch":arch, "platform":"linux", "target_triple":inner["target_triple"],
                "git_sha":inner["git_sha"], "build_timestamp":inner["build_timestamp"], "channel":"rc", "prerelease":true,
                "artifacts":{"bundle":{"status":"ready", "directory":directory, "archive":{"path":archive,"sha256":hash(&bytes),"sha256_path":format!("{archive}.sha256")}}},
                "bootstrap":{"path":"bootstrap-install.sh","sha256":hash(bootstrap)},
                "delivery_contract":{"roles":["client"],"role_config_install_requires_bundle":true,"source_checkout_required":false,"github_required":false}});
            write_json(&root.join(name), &m).unwrap();
            sign(root, name);
        }
        public
    }
    fn sign(root: &Path, name: &str) {
        use ring::signature::Ed25519KeyPair;
        let private_pem = fs::read_to_string(root.join("test-key.pem")).unwrap();
        let private = pem::parse(private_pem).unwrap();
        assert_eq!(private.tag(), "PRIVATE KEY");
        let pair = Ed25519KeyPair::from_pkcs8(private.contents()).unwrap();
        let manifest = fs::read(root.join(name)).unwrap();
        fs::write(
            root.join(format!("{name}.sig")),
            pair.sign(&manifest).as_ref(),
        )
        .unwrap();
    }
    #[test]
    fn ed25519_public_key_refuses_wrong_tag_algorithm_and_duplicate_blocks() {
        let work = Scratch::new().unwrap();
        let public = signed_release(&work.0);
        let valid = fs::read(public).unwrap();
        let block = pem::parse(&valid).unwrap();
        assert!(ed25519_public_key(&valid).is_ok());
        let wrong_tag = pem::encode(&pem::Pem::new("CERTIFICATE", block.contents().to_vec()));
        assert!(ed25519_public_key(wrong_tag.as_bytes()).is_err());
        let mut wrong_algorithm = block.contents().to_vec();
        wrong_algorithm[8] ^= 1;
        let wrong_algorithm = pem::encode(&pem::Pem::new("PUBLIC KEY", wrong_algorithm));
        assert!(ed25519_public_key(wrong_algorithm.as_bytes()).is_err());
        let duplicate = [valid.as_slice(), valid.as_slice()].concat();
        assert!(ed25519_public_key(&duplicate).is_err());
        let prefix = [b"untrusted prefix\n".as_slice(), valid.as_slice()].concat();
        assert!(ed25519_public_key(&prefix).is_err());
        let suffix = [valid.as_slice(), b"untrusted suffix\n".as_slice()].concat();
        assert!(ed25519_public_key(&suffix).is_err());
        let partial_second =
            [valid.as_slice(), b"-----BEGIN PUBLIC KEY-----\n".as_slice()].concat();
        assert!(ed25519_public_key(&partial_second).is_err());
    }
    #[test]
    fn openssl_ed25519_signature_interoperates_and_binds_key_and_bytes() {
        const PUBLIC: &[u8] = include_bytes!("../tests/fixtures/ed25519-openssl-r1/public.pem");
        const MESSAGE: &[u8] = include_bytes!("../tests/fixtures/ed25519-openssl-r1/message.bin");
        const SIGNATURE: &[u8] =
            include_bytes!("../tests/fixtures/ed25519-openssl-r1/signature.bin");
        let key = ed25519_public_key(PUBLIC).unwrap();
        assert!(UnparsedPublicKey::new(&ED25519, key)
            .verify(MESSAGE, SIGNATURE)
            .is_ok());
        let mut changed = MESSAGE.to_vec();
        changed[0] ^= 1;
        assert!(UnparsedPublicKey::new(&ED25519, key)
            .verify(&changed, SIGNATURE)
            .is_err());
        let work = Scratch::new().unwrap();
        let other = signed_release(&work.0);
        let other_key = ed25519_public_key(&fs::read(other).unwrap()).unwrap();
        assert!(UnparsedPublicKey::new(&ED25519, other_key)
            .verify(MESSAGE, SIGNATURE)
            .is_err());
    }
    #[test]
    fn signed_stage_emits_nine_files_without_private_builder_inputs() {
        let work = Scratch::new().unwrap();
        let public = signed_release(&work.0);
        fs::write(work.0.join("private-operator.txt"), b"inert fixture").unwrap();
        let out = work.0.join("public");
        stage(&work.0, &out, &public, &"a".repeat(40)).unwrap();
        assert_eq!(fs::read_dir(&out).unwrap().count(), 9);
        assert!(!out.join("test-key.pem").exists());
        assert!(!out.join("private-operator.txt").exists());
        assert!(stage(&work.0, &out, &public, &"a".repeat(40)).is_err());
    }
    #[test]
    fn signed_v2_stage_is_public_only_and_rejects_mixed_schema_architectures() {
        let work = Scratch::new().unwrap();
        let public = signed_release_schemas(&work.0, [CLIENT_BUNDLE_SCHEMA_V2; 2]);
        fs::write(work.0.join("server.key"), b"inert forbidden input").unwrap();
        let out = work.0.join("public");
        stage(&work.0, &out, &public, &"a".repeat(40)).unwrap();
        assert_eq!(fs::read_dir(&out).unwrap().count(), 9);
        assert!(!out.join("test-key.pem").exists());
        assert!(!out.join("server.key").exists());
        let work = Scratch::new().unwrap();
        let public =
            signed_release_schemas(&work.0, [CLIENT_BUNDLE_SCHEMA_V1, CLIENT_BUNDLE_SCHEMA_V2]);
        let out = work.0.join("public");
        assert!(stage(&work.0, &out, &public, &"a".repeat(40)).is_err());
        assert!(!out.exists());
    }

    #[test]
    fn stage_rejects_bad_signature_source_bootstrap_and_mixed_release_before_output() {
        for change in [
            "signature",
            "manifest-byte",
            "source",
            "bootstrap",
            "mixed",
            "operator-reference",
        ] {
            let work = Scratch::new().unwrap();
            let public = signed_release(&work.0);
            let name = "client-release.manifest-aarch64.json";
            match change {
                "signature" => fs::write(work.0.join(format!("{name}.sig")), [0u8; 64]).unwrap(),
                "manifest-byte" => {
                    let mut m = read_json(&work.0.join(name)).unwrap();
                    m["version"] = json!("0.0.1");
                    write_json(&work.0.join(name), &m).unwrap();
                }
                "bootstrap" => fs::write(
                    work.0.join("bootstrap-install.sh"),
                    b"changed inert fixture",
                )
                .unwrap(),
                "mixed" | "operator-reference" => {
                    let mut m = read_json(&work.0.join(name)).unwrap();
                    if change == "mixed" {
                        m["channel"] = json!("nightly");
                    } else {
                        m["artifacts"]["server"] = json!({"path":"private-operator.tar.gz"});
                    }
                    write_json(&work.0.join(name), &m).unwrap();
                    sign(&work.0, name);
                }
                _ => {}
            }
            let out = work.0.join("public");
            let source = if change == "source" {
                "c".repeat(40)
            } else {
                "a".repeat(40)
            };
            assert!(stage(&work.0, &out, &public, &source).is_err(), "{change}");
            assert!(!out.exists(), "{change} emitted partial public files");
        }
    }
}
