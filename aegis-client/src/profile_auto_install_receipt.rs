//! Experimental Linux AUTO installed-receipt producer.
//! Private candidate: not linked into the current administrative CLI.
//! Public payload provenance is distinct from the private client-config bundle.
//! No network, service, executable launch, arbitrary metadata path or claimed
//! caller hash. Descriptor-minted inputs must be sealed by the actual Store.

use crate::profile_auto_capture::{CaptureLimits, CapturedInput, CapturedTree, InputRole};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
const REFUSED: &str = "Administrative installed receipt refused";
const MANIFEST_MAX: u64 = 1024 * 1024;
const BINARY_MAX: u64 = 512 * 1024 * 1024;

fn absolute(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.to_str().is_none()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || path.as_os_str().as_encoded_bytes().contains(&0)
    {
        return Err(REFUSED);
    }
    Ok(())
}
fn text(value: &str, max: usize) -> Result<String> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(REFUSED);
    }
    Ok(value.to_owned())
}
fn optional_field(
    fields: &BTreeMap<String, serde_json::Value>,
    key: &str,
) -> Result<Option<String>> {
    match fields.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(v)) => Ok(Some(text(v, 4096)?)),
        _ => Err(REFUSED),
    }
}

/// Reject duplicate top-level provenance fields rather than accepting the last
/// spelling. Unknown public-manifest keys remain available to their real release
/// validator; this projection never claims signature/inventory admission.
struct UniqueManifest(BTreeMap<String, serde_json::Value>);
impl<'de> Deserialize<'de> for UniqueManifest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueManifest;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("unique manifest object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut fields = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if fields.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate provenance field"));
                    }
                }
                Ok(UniqueManifest(fields))
            }
        }
        d.deserialize_map(Visitor)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Provenance {
    version: Option<String>,
    git_sha: String,
    build_timestamp: Option<String>,
    platform: Option<String>,
    arch: Option<String>,
    target_triple: Option<String>,
    bundle_manifest_path: Option<String>,
    source_manifest_url: Option<String>,
    source_release_channel: Option<String>,
    declared_client_path: Option<PathBuf>,
    declared_client_sha256: Option<String>,
}
impl Provenance {
    fn from_bytes(
        bytes: Option<&[u8]>,
        path: &Path,
        source_url: Option<&str>,
        channel: Option<&str>,
    ) -> Result<Self> {
        absolute(path)?;
        let fields = match bytes {
            Some(b) if b.len() as u64 <= MANIFEST_MAX => {
                serde_json::from_slice::<UniqueManifest>(b)
                    .map_err(|_| REFUSED)?
                    .0
            }
            Some(_) => return Err(REFUSED),
            None => BTreeMap::new(),
        };
        let source_manifest_url = source_url.map(|s| text(s, 4096)).transpose()?;
        let source_release_channel = channel.map(|s| text(s, 128)).transpose()?;
        let (declared_client_path, declared_client_sha256) = if bytes.is_some() {
            let schema = fields
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .ok_or(REFUSED)?;
            if !matches!(
                schema,
                "aegis_client_release_bundle_manifest_v1"
                    | "aegis_client_release_bundle_manifest_v2"
                    | "aegis_client_release_bundle_manifest_v3"
                    | "aegis_release_bundle_manifest_v2"
            ) {
                return Err(REFUSED);
            }
            let binary = fields
                .get("binaries")
                .and_then(|v| v.get("aegis-client"))
                .ok_or(REFUSED)?;
            if binary.get("path").and_then(serde_json::Value::as_str) != Some("bin/aegis-client") {
                return Err(REFUSED);
            }
            let sha = binary
                .get("sha256")
                .and_then(serde_json::Value::as_str)
                .ok_or(REFUSED)?;
            if sha.len() != 64
                || !sha
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                return Err(REFUSED);
            }
            (
                Some(path.parent().ok_or(REFUSED)?.join("bin/aegis-client")),
                Some(sha.to_owned()),
            )
        } else {
            (None, None)
        };
        let result = Self {
            version: optional_field(&fields, "version")?,
            git_sha: optional_field(&fields, "git_sha")?.unwrap_or_else(|| "unknown".into()),
            build_timestamp: optional_field(&fields, "build_timestamp")?,
            platform: optional_field(&fields, "platform")?,
            arch: optional_field(&fields, "arch")?,
            target_triple: optional_field(&fields, "target_triple")?,
            bundle_manifest_path: bytes
                .map(|_| path.to_str().ok_or(REFUSED).map(str::to_owned))
                .transpose()?,
            source_manifest_url,
            source_release_channel,
            declared_client_path,
            declared_client_sha256,
        };
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn binds_manifest(&self, path: &Path) -> bool {
        self.bundle_manifest_path
            .as_deref()
            .is_none_or(|p| Path::new(p) == path)
    }
    pub(crate) fn admit_candidate(
        &self,
        path: &Path,
        fingerprint: &BinaryFingerprint,
    ) -> Result<()> {
        fingerprint.validate()?;
        match (&self.declared_client_path, &self.declared_client_sha256) {
            (Some(expected_path), Some(expected_sha))
                if expected_path == path && expected_sha == &fingerprint.sha256 =>
            {
                Ok(())
            }
            (None, None) if self.bundle_manifest_path.is_none() => Ok(()),
            _ => Err(REFUSED),
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        for value in [
            &self.version,
            &self.build_timestamp,
            &self.platform,
            &self.arch,
            &self.target_triple,
        ]
        .into_iter()
        .flatten()
        {
            text(value, 4096)?;
        }
        text(&self.git_sha, 4096)?;
        if let Some(p) = &self.bundle_manifest_path {
            absolute(Path::new(p))?;
        }
        if let Some(url) = &self.source_manifest_url {
            text(url, 4096)?;
        }
        if let Some(channel) = &self.source_release_channel {
            text(channel, 128)?;
        }
        match (&self.declared_client_path, &self.declared_client_sha256) {
            (Some(path), Some(sha)) if self.bundle_manifest_path.is_some() => {
                absolute(path)?;
                let manifest = Path::new(self.bundle_manifest_path.as_deref().ok_or(REFUSED)?);
                if manifest.parent().ok_or(REFUSED)?.join("bin/aegis-client") != *path
                    || sha.len() != 64
                    || !sha
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                {
                    return Err(REFUSED);
                }
            }
            (None, None) if self.bundle_manifest_path.is_none() => {}
            _ => return Err(REFUSED),
        }
        Ok(())
    }
}

/// Kept alive through initial sealing so source replacement is a refusal. An
/// absent public manifest is honest source-layout provenance, not authority to
/// bypass the installer's authenticated binary/release admission.
pub(crate) struct CapturedProvenance {
    capture: CapturedInput,
    pub(crate) fields: Provenance,
}
impl CapturedProvenance {
    pub(crate) fn capture(
        public_payload_root: &Path,
        operator_uid: u32,
        source_url: Option<&str>,
        channel: Option<&str>,
    ) -> Result<Self> {
        absolute(public_payload_root)?;
        let path = public_payload_root.join("bundle.manifest.json");
        let limits = CaptureLimits {
            file_bytes: MANIFEST_MAX,
            tree_bytes: MANIFEST_MAX,
            ..CaptureLimits::default()
        };
        let capture = CapturedTree::capture_optional(
            &path,
            public_payload_root.to_path_buf(),
            InputRole::ExplicitBundleData {
                operator_uid,
                administrator_uid: 0,
            },
            limits,
            false,
        )
        .map_err(|_| REFUSED)?;
        let bytes = match &capture {
            CapturedInput::Present(tree) => Some(
                tree.bytes(Path::new("bundle.manifest.json"))
                    .map_err(|_| REFUSED)?,
            ),
            CapturedInput::Absent(_) => None,
        };
        let fields = Provenance::from_bytes(bytes, &path, source_url, channel)?;
        Ok(Self { capture, fields })
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.capture
            .revalidate_original_generation()
            .map_err(|_| REFUSED)
    }
    pub(crate) fn generation(&self) -> Result<crate::profile_auto_capture::GenerationRecord> {
        // Export only after the original held capture is still admitted. The
        // candidate hash may have taken time since public provenance capture.
        self.revalidate()?;
        self.capture
            .export_private_generation()
            .map_err(|_| REFUSED)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BinaryFingerprint {
    size: u64,
    sha256: String,
}
impl BinaryFingerprint {
    pub(crate) fn sha256(&self) -> Result<&str> {
        self.validate()?;
        Ok(&self.sha256)
    }
    fn validate(&self) -> Result<()> {
        if self.size == 0
            || self.size > BINARY_MAX
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(REFUSED);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileExt, MetadataExt};

    #[derive(Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Identity {
        dev: u64,
        ino: u64,
        uid: u32,
        gid: u32,
        mode: u32,
        size: u64,
        mtime: i64,
        mtime_ns: i64,
        ctime: i64,
        ctime_ns: i64,
    }
    fn identity(file: &File) -> Result<Identity> {
        let m = file.metadata().map_err(|_| REFUSED)?;
        Ok(Identity {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            size: m.size(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        })
    }
    fn same_parent(a: &Identity, b: &Identity) -> bool {
        a.dev == b.dev && a.ino == b.ino && a.uid == b.uid && a.gid == b.gid && a.mode == b.mode
    }
    fn openat(parent: i32, name: &std::ffi::OsStr, directory: bool) -> Result<File> {
        let name = CString::new(name.as_bytes()).map_err(|_| REFUSED)?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if directory { libc::O_DIRECTORY } else { 0 };
        let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(REFUSED);
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(File::from(owned))
    }
    struct Parent {
        file: File,
        identity: Identity,
        name_from_parent: Option<std::ffi::OsString>,
    }
    /// Held descriptor chain; never follows a symlink or treats a FIFO as a
    /// regular executable. Final installed executable must be root-owned.
    pub(crate) struct CapturedBinary {
        parents: Vec<Parent>,
        file: File,
        leaf: std::ffi::OsString,
        identity: Identity,
        fingerprint: BinaryFingerprint,
        source: PathBuf,
        operator_uid: u32,
        installed: bool,
    }
    /// Private stage record only. It is not accepted as public CLI input or
    /// unsigned caller JSON. Store must authenticate this exact serialized leaf
    /// before metadata-only reopening, including source role and recipe nonce.
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct BinaryGeneration {
        source: PathBuf,
        operator_uid: u32,
        installed: bool,
        parents: Vec<Identity>,
        identity: Identity,
        fingerprint: BinaryFingerprint,
    }
    impl BinaryGeneration {
        pub(crate) fn binds(&self, source: &Path, operator_uid: u32, installed: bool) -> bool {
            self.source == source
                && self.operator_uid == operator_uid
                && self.installed == installed
        }
        pub(crate) fn fingerprint(&self) -> Result<&BinaryFingerprint> {
            self.fingerprint.validate()?;
            Ok(&self.fingerprint)
        }
        /// Admit the actual readable executable FD held by the active-service
        /// observer, never a pathname/caller hash or cached executable name.
        /// Caller owns anchored proc/pidfd/cgroup/epoch checks around this call.
        /// This does not discover a process or certify that it is the service.
        pub(crate) fn admit_running_executable(&self, executable: &File) -> Result<()> {
            if !self.installed || self.operator_uid != 0 || self.identity.uid != 0 {
                return Err(REFUSED);
            }
            self.validate_current()?;
            // Own a duplicate for the complete check. Positional reads preserve
            // the caller's file cursor, including its other cloned descriptors.
            let held = executable.try_clone().map_err(|_| REFUSED)?;
            let before = identity(&held)?;
            let metadata = held.metadata().map_err(|_| REFUSED)?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != 0
                || before != self.identity
                || before.mode & 0o022 != 0
                || before.mode & 0o111 == 0
                || before.size == 0
                || before.size > BINARY_MAX
            {
                return Err(REFUSED);
            }
            let mut hash = Sha256::new();
            let mut bytes = Zeroizing::new(vec![0; 64 * 1024]);
            let mut offset = 0u64;
            while offset < before.size {
                let remaining = (before.size - offset).min(bytes.len() as u64) as usize;
                let read = held
                    .read_at(&mut bytes[..remaining], offset)
                    .map_err(|_| REFUSED)?;
                if read == 0 {
                    return Err(REFUSED);
                }
                offset = offset.checked_add(read as u64).ok_or(REFUSED)?;
                if offset > before.size || offset > BINARY_MAX {
                    return Err(REFUSED);
                }
                hash.update(&bytes[..read]);
            }
            let mut extra = [0u8; 1];
            if held.read_at(&mut extra, offset).map_err(|_| REFUSED)? != 0
                || identity(&held)? != before
                || hex::encode(hash.finalize()) != self.fingerprint.sha256
            {
                return Err(REFUSED);
            }
            self.validate_current()?;
            if identity(&held)? != self.identity {
                return Err(REFUSED);
            }
            Ok(())
        }
        /// Holds no source byte read and cannot regenerate a replacement hash.
        /// The original fingerprint remains a protected descriptor-minted fact.
        pub(crate) fn validate_current(&self) -> Result<()> {
            absolute(&self.source)?;
            self.fingerprint.validate()?;
            if self.identity.size != self.fingerprint.size
                || self.identity.mode & 0o022 != 0
                || self.identity.mode & 0o111 == 0
                || self.parents.is_empty()
                || self.parents.len() > 64
            {
                return Err(REFUSED);
            }
            let mut names = self
                .source
                .components()
                .filter_map(|c| match c {
                    Component::Normal(n) => Some(n.to_os_string()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let leaf = names.pop().ok_or(REFUSED)?;
            if self.parents.len() != names.len() + 1 {
                return Err(REFUSED);
            }
            let mut parent = openat(libc::AT_FDCWD, std::ffi::OsStr::new("/"), true)?;
            if !same_parent(&identity(&parent)?, &self.parents[0]) {
                return Err(REFUSED);
            }
            for (name, expected) in names.iter().zip(self.parents.iter().skip(1)) {
                let next = openat(parent.as_raw_fd(), name, true)?;
                if !same_parent(&identity(&next)?, expected) {
                    return Err(REFUSED);
                }
                parent = next;
            }
            let file = openat(parent.as_raw_fd(), &leaf, false)?;
            let m = file.metadata().map_err(|_| REFUSED)?;
            if !m.is_file()
                || m.nlink() != 1
                || identity(&file)? != self.identity
                || !(m.uid() == 0 || !self.installed && m.uid() == self.operator_uid)
            {
                return Err(REFUSED);
            }
            Ok(())
        }
    }
    impl CapturedBinary {
        pub(crate) fn capture(path: &Path, operator_uid: u32, installed: bool) -> Result<Self> {
            absolute(path)?;
            let mut names = path
                .components()
                .filter_map(|c| match c {
                    Component::Normal(n) => Some(n.to_os_string()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if names.len() > 64 {
                return Err(REFUSED);
            }
            let leaf = names.pop().ok_or(REFUSED)?;
            let root = openat(libc::AT_FDCWD, std::ffi::OsStr::new("/"), true)?;
            let mut parents = Vec::new();
            let root_identity = identity(&root)?;
            if root_identity.uid != 0 || root_identity.mode & 0o022 != 0 {
                return Err(REFUSED);
            }
            parents.push(Parent {
                file: root,
                identity: root_identity,
                name_from_parent: None,
            });
            for name in names {
                let parent = parents.last().ok_or(REFUSED)?;
                let file = openat(parent.file.as_raw_fd(), &name, true)?;
                let id = identity(&file)?;
                if id.mode & 0o022 != 0 || !(id.uid == 0 || !installed && id.uid == operator_uid) {
                    return Err(REFUSED);
                }
                parents.push(Parent {
                    file,
                    identity: id,
                    name_from_parent: Some(name),
                });
            }
            let mut file = openat(
                parents.last().ok_or(REFUSED)?.file.as_raw_fd(),
                &leaf,
                false,
            )?;
            let before = identity(&file)?;
            let m = file.metadata().map_err(|_| REFUSED)?;
            if !m.is_file()
                || m.nlink() != 1
                || before.mode & 0o022 != 0
                || before.mode & 0o111 == 0
                || !(before.uid == 0 || !installed && before.uid == operator_uid)
                || before.size == 0
                || before.size > BINARY_MAX
            {
                return Err(REFUSED);
            }
            let mut hash = Sha256::new();
            let mut bytes = Zeroizing::new(vec![0; 64 * 1024]);
            let mut total = 0u64;
            loop {
                let n = file.read(&mut bytes).map_err(|_| REFUSED)?;
                if n == 0 {
                    break;
                }
                total = total.checked_add(n as u64).ok_or(REFUSED)?;
                if total > BINARY_MAX || total > before.size {
                    return Err(REFUSED);
                }
                hash.update(&bytes[..n]);
            }
            if total != before.size || identity(&file)? != before {
                return Err(REFUSED);
            }
            let fingerprint = BinaryFingerprint {
                size: total,
                sha256: hex::encode(hash.finalize()),
            };
            let captured = Self {
                parents,
                file,
                leaf,
                identity: before,
                fingerprint,
                source: path.to_path_buf(),
                operator_uid,
                installed,
            };
            captured.revalidate()?;
            Ok(captured)
        }
        pub(crate) fn fingerprint(&self) -> &BinaryFingerprint {
            &self.fingerprint
        }
        pub(crate) fn generation_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
            self.revalidate()?;
            let value = serde_json::json!({
                "source": self.source, "operator_uid": self.operator_uid,
                "installed": self.installed,
                "parents": self.parents.iter().map(|p| &p.identity).collect::<Vec<_>>(),
                "identity": self.identity, "fingerprint": self.fingerprint,
            });
            let bytes = serde_json::to_vec(&value).map_err(|_| REFUSED)?;
            if bytes.len() > 32 * 1024 {
                return Err(REFUSED);
            }
            Ok(Zeroizing::new(bytes))
        }
        pub(crate) fn revalidate(&self) -> Result<()> {
            if identity(&self.file)? != self.identity {
                return Err(REFUSED);
            }
            for (i, parent) in self.parents.iter().enumerate() {
                if !same_parent(&identity(&parent.file)?, &parent.identity) {
                    return Err(REFUSED);
                }
                let current = if i == 0 {
                    openat(libc::AT_FDCWD, std::ffi::OsStr::new("/"), true)?
                } else {
                    openat(
                        self.parents[i - 1].file.as_raw_fd(),
                        parent.name_from_parent.as_deref().ok_or(REFUSED)?,
                        true,
                    )?
                };
                if !same_parent(&identity(&current)?, &parent.identity) {
                    return Err(REFUSED);
                }
            }
            let current = openat(
                self.parents.last().ok_or(REFUSED)?.file.as_raw_fd(),
                &self.leaf,
                false,
            )?;
            if identity(&current)? != self.identity {
                return Err(REFUSED);
            }
            Ok(())
        }
    }
}
#[cfg(target_os = "linux")]
pub(crate) use linux::{BinaryGeneration, CapturedBinary};

/// Closed compatibility record. No Debug/display implementation: provenance
/// URLs and local paths must not be emitted as diagnostic fragments.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstalledReceipt {
    schema: String,
    role: String,
    version: Option<String>,
    git_sha: String,
    build_timestamp: Option<String>,
    installed_at: String,
    source_manifest_url: Option<String>,
    source_release_channel: Option<String>,
    binary_path: String,
    binary_sha256: String,
    binary_version: Option<String>,
    platform: Option<String>,
    arch: Option<String>,
    target_triple: Option<String>,
    bundle_manifest_path: Option<String>,
}
impl InstalledReceipt {
    pub(crate) fn create(
        provenance: &Provenance,
        target: &Path,
        expected: &BinaryFingerprint,
        actual: &BinaryFingerprint,
        installed_at: &str,
    ) -> Result<Self> {
        provenance.validate()?;
        absolute(target)?;
        expected.validate()?;
        actual.validate()?;
        if expected != actual || !utc_seconds(installed_at) {
            return Err(REFUSED);
        }
        Ok(Self {
            schema: "aegis_install_manifest_v1".into(),
            role: "client".into(),
            version: provenance.version.clone(),
            git_sha: provenance.git_sha.clone(),
            build_timestamp: provenance.build_timestamp.clone(),
            installed_at: installed_at.into(),
            source_manifest_url: provenance.source_manifest_url.clone(),
            source_release_channel: provenance.source_release_channel.clone(),
            binary_path: target.to_str().ok_or(REFUSED)?.into(),
            binary_sha256: actual.sha256.clone(),
            // No new child execution is hidden in metadata publication. Legacy
            // record already permitted None when --version was unavailable.
            binary_version: None,
            platform: provenance.platform.clone(),
            arch: provenance.arch.clone(),
            target_triple: provenance.target_triple.clone(),
            bundle_manifest_path: provenance.bundle_manifest_path.clone(),
        })
    }
    pub(crate) fn validate_readback(bytes: &[u8]) -> Result<()> {
        if bytes.len() > 32 * 1024 {
            return Err(REFUSED);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
        if value.schema != "aegis_install_manifest_v1"
            || value.role != "client"
            || !utc_seconds(&value.installed_at)
            || value.binary_version.is_some()
        {
            return Err(REFUSED);
        }
        absolute(Path::new(&value.binary_path))?;
        if value.binary_sha256.len() != 64
            || !value
                .binary_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(REFUSED);
        }
        Ok(())
    }
    pub(crate) fn bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|_| REFUSED)?;
        bytes.push(b'\n');
        if bytes.len() > 32 * 1024 {
            return Err(REFUSED);
        }
        Ok(Zeroizing::new(bytes))
    }
}
fn utc_seconds(s: &str) -> bool {
    if s.len() != 20 || !s.is_ascii() {
        return false;
    }
    let b = s.as_bytes();
    if b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return false;
    }
    let number = |a, z| {
        s.get(a..z)
            .filter(|v| v.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|v| v.parse::<u32>().ok())
    };
    let (Some(y), Some(m), Some(d), Some(h), Some(n), Some(sec)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        _ => return false,
    };
    y >= 1970 && d >= 1 && d <= days && h <= 23 && n <= 59 && sec <= 59
}

/// Timestamp is minted by the root coordinator at actual receipt sealing,
/// never accepted as a public CLI flag.
#[cfg(target_os = "linux")]
pub(crate) fn current_utc_seconds() -> Result<String> {
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    if now < 0 {
        return Err(REFUSED);
    }
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    if unsafe { libc::gmtime_r(&now, tm.as_mut_ptr()) }.is_null() {
        return Err(REFUSED);
    }
    let tm = unsafe { tm.assume_init() };
    let stamp = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    );
    if !utc_seconds(&stamp) {
        return Err(REFUSED);
    }
    Ok(stamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> serde_json::Value {
        serde_json::json!({"schema":"aegis_client_release_bundle_manifest_v2","version":"v0.3.50","git_sha":"unknown","platform":"linux","arch":"x86_64","binaries":{"aegis-client":{"path":"bin/aegis-client","sha256":"a".repeat(64)}}})
    }
    fn provenance() -> Provenance {
        Provenance::from_bytes(
            Some(&serde_json::to_vec(&manifest()).unwrap()),
            Path::new("/opt/public/bundle.manifest.json"),
            None,
            None,
        )
        .unwrap()
    }
    fn fingerprint() -> BinaryFingerprint {
        BinaryFingerprint {
            size: 42,
            sha256: "a".repeat(64),
        }
    }
    #[test]
    fn receipt_has_exact_fifteen_legacy_fields_and_client_role() {
        let p = provenance();
        let f = fingerprint();
        let r = InstalledReceipt::create(
            &p,
            Path::new("/usr/local/bin/aegis-client"),
            &f,
            &f,
            "2026-10-12T01:02:03Z",
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&r.bytes().unwrap()).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 15);
        assert_eq!(v["role"], "client");
        assert_eq!(v["schema"], "aegis_install_manifest_v1");
        assert!(v["binary_version"].is_null());
    }
    #[test]
    fn receipt_refuses_replaced_binary_even_when_path_matches() {
        let p = provenance();
        let f = fingerprint();
        let mut replaced = fingerprint();
        replaced.sha256 = "b".repeat(64);
        assert!(InstalledReceipt::create(
            &p,
            Path::new("/usr/local/bin/aegis-client"),
            &f,
            &replaced,
            "2026-10-12T01:02:03Z"
        )
        .is_err());
    }
    #[test]
    fn source_layout_absence_is_null_provenance_not_private_bundle_provenance() {
        let p = Provenance::from_bytes(
            None,
            Path::new("/opt/source/bundle.manifest.json"),
            None,
            None,
        )
        .unwrap();
        assert!(p.bundle_manifest_path.is_none());
        assert_eq!(p.git_sha, "unknown");
        let public = provenance();
        assert_eq!(
            public.bundle_manifest_path.as_deref(),
            Some("/opt/public/bundle.manifest.json")
        );
    }
    #[test]
    fn manifest_duplicate_fields_and_wrong_field_types_refuse() {
        let base = serde_json::to_string(&manifest()).unwrap();
        let duplicate = format!(
            "{},\"version\":\"different\"}}",
            base.strip_suffix('}').unwrap()
        );
        assert!(Provenance::from_bytes(
            Some(duplicate.as_bytes()),
            Path::new("/opt/public/bundle.manifest.json"),
            None,
            None
        )
        .is_err());
        for (key, value) in [
            ("git_sha", serde_json::json!(42)),
            ("arch", serde_json::json!(true)),
        ] {
            let mut v = manifest();
            v[key] = value;
            assert!(Provenance::from_bytes(
                Some(&serde_json::to_vec(&v).unwrap()),
                Path::new("/opt/public/bundle.manifest.json"),
                None,
                None
            )
            .is_err());
        }
        assert!(Provenance::from_bytes(
            Some(b"[]"),
            Path::new("/opt/public/bundle.manifest.json"),
            None,
            None
        )
        .is_err());
    }
    #[test]
    fn unknown_manifest_content_is_not_dropped_into_receipt() {
        let mut v = manifest();
        v["arbitrary"] = serde_json::json!({"token":"synthetic"});
        let p = Provenance::from_bytes(
            Some(&serde_json::to_vec(&v).unwrap()),
            Path::new("/opt/public/bundle.manifest.json"),
            None,
            None,
        )
        .unwrap();
        let f = fingerprint();
        let r = InstalledReceipt::create(
            &p,
            Path::new("/usr/local/bin/aegis-client"),
            &f,
            &f,
            "2026-10-12T01:02:03Z",
        )
        .unwrap();
        assert!(!String::from_utf8(r.bytes().unwrap().to_vec())
            .unwrap()
            .contains("synthetic"));
    }
    #[test]
    fn captured_manifest_candidate_path_and_digest_must_both_match() {
        let p = provenance();
        let f = fingerprint();
        p.admit_candidate(Path::new("/opt/public/bin/aegis-client"), &f)
            .unwrap();
        assert!(p
            .admit_candidate(Path::new("/opt/other/bin/aegis-client"), &f)
            .is_err());
        let changed = BinaryFingerprint {
            size: 42,
            sha256: "b".repeat(64),
        };
        assert!(p
            .admit_candidate(Path::new("/opt/public/bin/aegis-client"), &changed)
            .is_err());
        let absent = Provenance::from_bytes(
            None,
            Path::new("/opt/source/bundle.manifest.json"),
            None,
            None,
        )
        .unwrap();
        absent
            .admit_candidate(Path::new("/opt/source/target/release/aegis-client"), &f)
            .unwrap();
    }
    #[test]
    fn utc_and_absolute_destination_contract_refuses_invalid_values() {
        let p = provenance();
        let f = fingerprint();
        for stamp in [
            "2026-02-29T00:00:00Z",
            "2026-10-12T24:00:00Z",
            "2026-10-12T00:00:00+00:00",
            "",
        ] {
            assert!(InstalledReceipt::create(
                &p,
                Path::new("/usr/local/bin/aegis-client"),
                &f,
                &f,
                stamp
            )
            .is_err());
        }
        assert!(utc_seconds("2024-02-29T00:00:00Z"));
        assert!(InstalledReceipt::create(
            &p,
            Path::new("relative"),
            &f,
            &f,
            "2026-10-12T00:00:00Z"
        )
        .is_err());
    }
    #[test]
    fn manifest_size_and_control_character_limits_are_real_refusals() {
        assert!(Provenance::from_bytes(
            Some(&vec![b' '; MANIFEST_MAX as usize + 1]),
            Path::new("/opt/public/bundle.manifest.json"),
            None,
            None
        )
        .is_err());
        assert!(Provenance::from_bytes(
            None,
            Path::new("/opt/public/bundle.manifest.json"),
            Some("https://synthetic.invalid/\n"),
            None
        )
        .is_err());
    }
    #[test]
    fn receipt_deserialization_refuses_extra_fields() {
        let p = provenance();
        let f = fingerprint();
        let r = InstalledReceipt::create(
            &p,
            Path::new("/usr/local/bin/aegis-client"),
            &f,
            &f,
            "2026-10-12T00:00:00Z",
        )
        .unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&r.bytes().unwrap()).unwrap();
        v.as_object_mut().unwrap().insert(
            "caller_hash".into(),
            serde_json::Value::String("synthetic".into()),
        );
        assert!(serde_json::from_value::<InstalledReceipt>(v).is_err());
    }
    #[cfg(target_os = "linux")]
    fn private_root_fixture() -> tempfile::TempDir {
        // These ignored tests are genuine root Linux file-only tests. They must
        // be selected explicitly on a disposable runner; no fallback /tmp with
        // a world-writable ancestor or fabricated effective-root admission.
        assert_eq!(unsafe { libc::geteuid() }, 0);
        tempfile::Builder::new()
            .prefix("aegis-auto-install-receipt-")
            .tempdir_in("/root")
            .unwrap()
    }
    #[cfg(target_os = "linux")]
    fn executable(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "disposable root Linux descriptor filesystem fixture only"]
    fn actual_installed_binary_capture_replacement_and_private_generation_refuse() {
        let d = private_root_fixture();
        let binary = d.path().join("candidate");
        executable(&binary, b"synthetic-data-never-executed");
        let captured = CapturedBinary::capture(&binary, 0, true).unwrap();
        let record: BinaryGeneration =
            serde_json::from_slice(&captured.generation_bytes().unwrap()).unwrap();
        record.validate_current().unwrap();
        assert_eq!(record.fingerprint().unwrap().size, 29);
        // Normal installation may create other entries under a shared admitted
        // ancestor. Parent identity/ownership/mode, not its directory mtime,
        // binds the path chain; executable inode metadata remains exact.
        executable(
            &d.path().join("unrelated-sibling"),
            b"synthetic-never-executed",
        );
        captured.revalidate().unwrap();
        record.validate_current().unwrap();
        let replacement = d.path().join("replacement");
        executable(&replacement, b"synthetic-data-never-executed");
        std::fs::rename(&replacement, &binary).unwrap();
        assert!(captured.revalidate().is_err());
        assert!(record.validate_current().is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "disposable root Linux descriptor filesystem fixture only"]
    fn actual_binary_symlink_hardlink_nonexecutable_and_fifo_refuse() {
        use std::os::unix::{
            ffi::OsStrExt,
            fs::{symlink, PermissionsExt},
        };
        let d = private_root_fixture();
        let binary = d.path().join("candidate");
        executable(&binary, b"synthetic-data-never-executed");
        let link = d.path().join("alias");
        symlink(&binary, &link).unwrap();
        assert!(CapturedBinary::capture(&link, 0, true).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::hard_link(&binary, &link).unwrap();
        assert!(CapturedBinary::capture(&binary, 0, true).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(CapturedBinary::capture(&binary, 0, true).is_err());
        let fifo = d.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o700) }, 0);
        assert!(CapturedBinary::capture(&fifo, 0, true).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "disposable root Linux actual public provenance file capture only"]
    fn actual_public_provenance_capture_matches_candidate_and_replacement_refuses() {
        use std::os::unix::fs::PermissionsExt;
        let d = private_root_fixture();
        let payload = d.path().join("public");
        std::fs::create_dir(&payload).unwrap();
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bin = payload.join("bin");
        std::fs::create_dir(&bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
        let candidate_path = bin.join("aegis-client");
        executable(&candidate_path, b"synthetic-data-never-executed");
        let candidate = CapturedBinary::capture(&candidate_path, 0, false).unwrap();
        let mut public = manifest();
        public["binaries"]["aegis-client"]["sha256"] =
            serde_json::Value::String(candidate.fingerprint().sha256.clone());
        let manifest_path = payload.join("bundle.manifest.json");
        let bytes = serde_json::to_vec(&public).unwrap();
        std::fs::write(&manifest_path, &bytes).unwrap();
        std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let provenance = CapturedProvenance::capture(&payload, 0, None, None).unwrap();
        provenance
            .fields
            .admit_candidate(&candidate_path, candidate.fingerprint())
            .unwrap();
        provenance.revalidate().unwrap();
        let before = serde_json::to_vec(&provenance.fields).unwrap();
        let replacement = payload.join("manifest-new");
        std::fs::write(&replacement, &bytes).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&replacement, &manifest_path).unwrap();
        assert!(provenance.revalidate().is_err());
        assert!(provenance.generation().is_err());
        assert_eq!(serde_json::to_vec(&provenance.fields).unwrap(), before);
        candidate.revalidate().unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "disposable root Linux actual absent source-layout provenance only"]
    fn actual_missing_public_provenance_is_guarded_absence_not_private_bundle_claim() {
        let d = private_root_fixture();
        let candidate_path = d.path().join("source-built-client");
        executable(&candidate_path, b"synthetic-data-never-executed");
        let candidate = CapturedBinary::capture(&candidate_path, 0, false).unwrap();
        let provenance = CapturedProvenance::capture(d.path(), 0, None, None).unwrap();
        assert!(provenance.fields.bundle_manifest_path.is_none());
        assert_eq!(provenance.fields.git_sha, "unknown");
        provenance
            .fields
            .admit_candidate(&candidate_path, candidate.fingerprint())
            .unwrap();
        provenance.revalidate().unwrap();
        std::fs::write(
            d.path().join("bundle.manifest.json"),
            serde_json::to_vec(&manifest()).unwrap(),
        )
        .unwrap();
        assert!(provenance.revalidate().is_err());
        assert!(provenance.generation().is_err());
    }

    #[cfg(target_os = "linux")]
    fn installed_record(path: &Path) -> BinaryGeneration {
        let capture = CapturedBinary::capture(path, 0, true).unwrap();
        serde_json::from_slice(&capture.generation_bytes().unwrap()).unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "disposable root Linux actual held executable FD; synthetic data never executed"]
    fn actual_running_executable_fd_matches_sealed_record_without_moving_cursor() {
        use std::io::{Seek, SeekFrom};
        let d = private_root_fixture();
        let path = d.path().join("installed-client");
        executable(&path, b"synthetic-file-data-never-executed");
        let record = installed_record(&path);
        let mut held = std::fs::File::open(&path).unwrap();
        held.seek(SeekFrom::Start(7)).unwrap();
        record.admit_running_executable(&held).unwrap();
        assert_eq!(held.stream_position().unwrap(), 7);
        record.validate_current().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "disposable root Linux actual held executable FD; synthetic data never executed"]
    fn actual_running_executable_fd_identical_bytes_foreign_inode_refuses() {
        let d = private_root_fixture();
        let path = d.path().join("installed-client");
        let other = d.path().join("different-inode");
        let bytes = b"synthetic-file-data-never-executed";
        executable(&path, bytes);
        let record = installed_record(&path);
        executable(&other, bytes);
        record.validate_current().unwrap();
        assert!(record
            .admit_running_executable(&std::fs::File::open(other).unwrap())
            .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "disposable root Linux actual held executable FD; synthetic data never executed"]
    fn actual_running_executable_fd_old_and_new_handles_refuse_after_target_replacement() {
        let d = private_root_fixture();
        let path = d.path().join("installed-client");
        let replacement = d.path().join("replacement");
        let bytes = b"synthetic-file-data-never-executed";
        executable(&path, bytes);
        let record = installed_record(&path);
        let old = std::fs::File::open(&path).unwrap();
        executable(&replacement, bytes);
        std::fs::rename(replacement, &path).unwrap();
        assert!(record.admit_running_executable(&old).is_err());
        assert!(record
            .admit_running_executable(&std::fs::File::open(path).unwrap())
            .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "disposable root Linux actual held executable FD; synthetic data never executed"]
    fn actual_running_executable_fd_rehash_refuses_bad_sealed_fingerprint() {
        let d = private_root_fixture();
        let path = d.path().join("installed-client");
        executable(&path, b"synthetic-file-data-never-executed");
        let capture = CapturedBinary::capture(&path, 0, true).unwrap();
        let mut negative: serde_json::Value =
            serde_json::from_slice(&capture.generation_bytes().unwrap()).unwrap();
        // A negative malformed expected-record model, not a public authority
        // constructor: the real consumer authenticates the original stage leaf.
        negative["fingerprint"]["sha256"] = serde_json::Value::String("0".repeat(64));
        let record: BinaryGeneration = serde_json::from_value(negative).unwrap();
        record.validate_current().unwrap();
        assert!(record
            .admit_running_executable(&std::fs::File::open(path).unwrap())
            .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "disposable root Linux actual held executable FD; synthetic data never executed"]
    fn actual_running_executable_fd_candidate_role_cannot_mint_installed_proof() {
        let d = private_root_fixture();
        let path = d.path().join("candidate-only");
        executable(&path, b"synthetic-file-data-never-executed");
        let capture = CapturedBinary::capture(&path, 0, false).unwrap();
        let record: BinaryGeneration =
            serde_json::from_slice(&capture.generation_bytes().unwrap()).unwrap();
        record.validate_current().unwrap();
        assert!(record
            .admit_running_executable(&std::fs::File::open(path).unwrap())
            .is_err());
    }
}
