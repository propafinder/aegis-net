//! B-06 v45: the `.aegis-invite` invitation package a friend joins with.
//!
//! One file holds what the hand enrollment of 6 November needed: the device
//! id, the four public bundle files (`aegis_device_bundle_v4`) and the
//! single-use invitation token (64 lowercase hex characters,
//! `enrollment::new_invitation_token`). It is a secret while the token is
//! unspent.
//!
//! Format (`SCHEMA`): one JSON object in canonical form, exactly
//!
//! ```text
//! {"bundle":{"bundle.json":S,"device-ca.pem":S,"inner-ca.pem":S,"outer-ca.pem":S},
//!  "device_id":S,"invitation":S,"schema":"aegis_device_invite_v1"}
//! ```
//!
//! without the line break: keys sorted, no whitespace, strings as serde_json
//! writes them, UTF-8, at most one trailing newline. `encode` writes it and
//! the operator script (`tools/macos/relay-ops/make-invite.py`) writes the
//! same bytes (`json.dumps(sort_keys=True, separators=(',', ':'),
//! ensure_ascii=False)`). `parse` accepts only bytes that re-encode to
//! themselves, so a duplicate key, an unknown or missing key, another key
//! order or any padding is refused before anything is used.
//!
//! Admission, in order: the size cap (`MAX_PACKAGE_BYTES`) before parsing;
//! the canonical form; the schema; the device id (`registry`); every bundle
//! member non-empty, within the public file cap and free of private key
//! material; the bundle's own validation (the production profile validator,
//! an online full-wide UDP v4 profile, each CA and the device CA); the token
//! format. Every refusal is one stable code; none names a path, a byte of
//! the file or the token. The token's own buffers (the read file, the parsed
//! value, the package, the encoding) are zeroized when dropped and `Debug`
//! never shows it; transient copies inside serde_json, the hasher, the
//! enrollment wire codec and TLS are not (as in the aegis-client binary).
use aegis_client::{device_bundle_profile, public_profile_file};
use aegis_core::{
    secure_channel::{enrollment, enrollment::protocol, registry},
    wide_product::WideProductMode,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fmt,
    fs::File,
    io::Read,
    os::{fd::FromRawFd, unix::ffi::OsStrExt},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

/// The file name extension the menu's open panel offers.
pub const EXTENSION: &str = "aegis-invite";
/// The one accepted schema.
pub const SCHEMA: &str = "aegis_device_invite_v1";
/// Four public members of at most 64 KiB each, JSON-escaped (PEM line
/// breaks double), plus the envelope. Refused unread above this.
pub const MAX_PACKAGE_BYTES: usize = 384 * 1024;

/// The bundle members in `public_profile_file::MEMBERS` order.
const MEMBERS: [&str; 4] = public_profile_file::MEMBERS;

/// Every refusal code this module returns.
pub const CODES: [&str; 17] = [
    "invite_path_not_absolute",
    "invite_extension_required",
    "invite_not_canonical_path",
    "invite_missing",
    "invite_unreadable",
    "invite_symlink",
    "invite_not_regular",
    "invite_not_owned",
    "invite_linked",
    "invite_writable_by_others",
    "invite_oversized",
    "invite_not_canonical",
    "invite_schema_mismatch",
    "invite_device_id_invalid",
    "invite_bundle_member_invalid",
    "invite_bundle_invalid",
    "invite_token_invalid",
];

/// One admitted invitation package.
pub struct InvitePackage {
    device_id: String,
    public: [Vec<u8>; 4],
    token: Zeroizing<String>,
}

impl fmt::Debug for InvitePackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InvitePackage")
            .field("device_id", &self.device_id)
            .field("profile_sha256", &self.profile_sha256())
            .field("invitation", &"<redacted>")
            .finish()
    }
}

/// The inode and content of the package file that was read, so a removal
/// takes exactly that file and nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageSource {
    dev: u64,
    ino: u64,
    sha256: String,
}

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// One JSON string as serde_json writes it.
fn json_string(text: &str) -> Zeroizing<String> {
    Zeroizing::new(serde_json::to_string(text).unwrap_or_default())
}

/// The bundle checks every package must pass before it is used.
fn admit_bundle(public: &[Vec<u8>; 4]) -> Result<(), &'static str> {
    for bytes in public {
        if bytes.is_empty()
            || bytes.len() as u64 > public_profile_file::MAX_PUBLIC_BYTES
            || std::str::from_utf8(bytes).is_err()
            || bytes
                .windows(b"PRIVATE KEY".len())
                .any(|window| window == b"PRIVATE KEY")
        {
            return Err("invite_bundle_member_invalid");
        }
    }
    let profile =
        device_bundle_profile::validate_profile(&public[0]).map_err(|_| "invite_bundle_invalid")?;
    if profile.schema != "aegis_device_bundle_v4"
        || profile.enrollment.is_none()
        || !profile.udp
        || profile.mode().map_err(|_| "invite_bundle_invalid")? != WideProductMode::FullWideTun
    {
        return Err("invite_bundle_invalid");
    }
    for bytes in &public[1..] {
        device_bundle_profile::validate_ca(bytes).map_err(|_| "invite_bundle_invalid")?;
    }
    enrollment::validate_device_ca(&public[3]).map_err(|_| "invite_bundle_invalid")?;
    Ok(())
}

fn take_string(object: &mut serde_json::Map<String, Value>, key: &str) -> Option<String> {
    match object.remove(key) {
        Some(Value::String(text)) => Some(text),
        Some(mut other) => {
            scrub(&mut other);
            None
        }
        None => None,
    }
}

/// Overwrite every string of a parsed value before it is dropped.
fn scrub(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(scrub),
        Value::Object(map) => map.values_mut().for_each(scrub),
        _ => {}
    }
}

impl InvitePackage {
    /// A package from its parts, admitted exactly as `parse` admits one.
    pub fn new(
        device_id: &str,
        public: [Vec<u8>; 4],
        token: Zeroizing<String>,
    ) -> Result<Self, &'static str> {
        registry::validate_device_id(device_id).map_err(|_| "invite_device_id_invalid")?;
        admit_bundle(&public)?;
        protocol::digest(&token).map_err(|_| "invite_token_invalid")?;
        Ok(Self {
            device_id: device_id.to_owned(),
            public,
            token,
        })
    }

    /// Admit one package from its bytes (see the module documentation).
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err("invite_oversized");
        }
        let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        let mut value: Value = serde_json::from_slice(body).map_err(|_| "invite_not_canonical")?;
        let parsed = (|| {
            let object = value.as_object_mut().ok_or("invite_not_canonical")?;
            let keys: Vec<&str> = object.keys().map(String::as_str).collect();
            if keys != ["bundle", "device_id", "invitation", "schema"] {
                return Err("invite_not_canonical");
            }
            if object.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
                return Err("invite_schema_mismatch");
            }
            let device_id = take_string(object, "device_id").ok_or("invite_device_id_invalid")?;
            let token =
                Zeroizing::new(take_string(object, "invitation").ok_or("invite_token_invalid")?);
            let mut bundle = match object.remove("bundle") {
                Some(Value::Object(bundle)) => bundle,
                _ => return Err("invite_bundle_member_invalid"),
            };
            let mut names: Vec<&str> = bundle.keys().map(String::as_str).collect();
            let mut expected = MEMBERS.to_vec();
            names.sort_unstable();
            expected.sort_unstable();
            if names != expected {
                return Err("invite_not_canonical");
            }
            let mut public: [Vec<u8>; 4] = Default::default();
            for (slot, name) in public.iter_mut().zip(MEMBERS) {
                *slot = take_string(&mut bundle, name)
                    .ok_or("invite_bundle_member_invalid")?
                    .into_bytes();
            }
            let package = Self::new(&device_id, public, token)?;
            // Canonical form: the admitted values re-encode to the very
            // bytes read, so nothing in the file went unread.
            if package.encode().as_slice() != body {
                return Err("invite_not_canonical");
            }
            Ok(package)
        })();
        scrub(&mut value);
        parsed
    }

    /// The canonical bytes (no trailing newline).
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        // Sized once (JSON escaping at most doubles a member plus the
        // envelope), so the buffer holding the token is never reallocated
        // and left behind unzeroized.
        let capacity = self.public.iter().map(|m| 2 * m.len()).sum::<usize>()
            + 2 * self.device_id.len()
            + 2 * self.token.len()
            + 256;
        let mut out = Zeroizing::new(String::with_capacity(capacity));
        out.push_str("{\"bundle\":{");
        // Sorted member names: bundle.json, device-ca.pem, inner-ca.pem,
        // outer-ca.pem.
        let mut order: Vec<usize> = (0..MEMBERS.len()).collect();
        order.sort_by_key(|index| MEMBERS[*index]);
        for (n, index) in order.into_iter().enumerate() {
            if n > 0 {
                out.push(',');
            }
            out.push_str(&json_string(MEMBERS[index]));
            out.push(':');
            out.push_str(&json_string(&String::from_utf8_lossy(&self.public[index])));
        }
        out.push_str("},\"device_id\":");
        out.push_str(&json_string(&self.device_id));
        out.push_str(",\"invitation\":");
        out.push_str(&json_string(&self.token));
        out.push_str(",\"schema\":");
        out.push_str(&json_string(SCHEMA));
        out.push('}');
        let mut bytes = Zeroizing::new(Vec::with_capacity(out.len()));
        bytes.extend_from_slice(out.as_bytes());
        bytes
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// The four public bundle files, in `MEMBERS` order.
    pub fn public(&self) -> &[Vec<u8>; 4] {
        &self.public
    }

    /// The bundle's four-member profile digest (the identity's pin).
    pub fn profile_sha256(&self) -> String {
        public_profile_file::profile_digest_bytes(&self.public)
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// The name of this package's private staging directory: the same
    /// package always resumes in the same one, another token or bundle
    /// never shares it. A domain-separated digest, never the token or its
    /// authority-side digest.
    pub fn staging_name(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"aegis-enroll-staging-v1\0");
        hash.update(self.device_id.as_bytes());
        hash.update(b"\0");
        hash.update(self.profile_sha256().as_bytes());
        hash.update(b"\0");
        hash.update(self.token.as_bytes());
        hash.finalize()
            .iter()
            .take(16)
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

fn open_nofollow(path: &Path) -> Result<File, &'static str> {
    let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| "invite_unreadable")?;
    // SAFETY: a NUL-terminated path; the flags never create anything.
    let raw = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(match crate::identity_import::last_errno() {
            libc::ENOENT => "invite_missing",
            libc::ELOOP => "invite_symlink",
            _ => "invite_unreadable",
        });
    }
    // SAFETY: `raw` is a fresh descriptor owned by nobody else.
    Ok(unsafe { File::from_raw_fd(raw) })
}

/// Read and admit the package at `path`: absolute, canonical (no symlink
/// anywhere), ending in `.aegis-invite`, a regular file of the caller with
/// one link that no other user can write, within the cap.
pub fn read_package(path: &Path) -> Result<(InvitePackage, PackageSource), &'static str> {
    if !path.is_absolute() {
        return Err("invite_path_not_absolute");
    }
    if path.extension().and_then(|ext| ext.to_str()) != Some(EXTENSION)
        || path.file_stem().is_none_or(|stem| stem.is_empty())
    {
        return Err("invite_extension_required");
    }
    match std::fs::canonicalize(path) {
        Ok(canonical) if canonical == path => {}
        Ok(_) => {
            return Err(
                match std::fs::symlink_metadata(path).map(|meta| meta.file_type().is_symlink()) {
                    Ok(true) => "invite_symlink",
                    _ => "invite_not_canonical_path",
                },
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err("invite_missing"),
        Err(_) => return Err("invite_unreadable"),
    }
    let file = open_nofollow(path)?;
    let stat = crate::identity_import::fstat(&file).map_err(|_| "invite_unreadable")?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err("invite_not_regular");
    }
    // SAFETY: geteuid has no preconditions.
    if stat.st_uid != unsafe { libc::geteuid() } {
        return Err("invite_not_owned");
    }
    if stat.st_nlink != 1 {
        return Err("invite_linked");
    }
    if stat.st_mode & 0o022 != 0 {
        return Err("invite_writable_by_others");
    }
    if stat.st_size < 0 || stat.st_size as u64 > MAX_PACKAGE_BYTES as u64 {
        return Err("invite_oversized");
    }
    // Sized for the cap: a file growing after `fstat` never reallocates
    // (and leaves behind) a buffer holding the token.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PACKAGE_BYTES + 1));
    (&file)
        .take(MAX_PACKAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "invite_unreadable")?;
    let package = InvitePackage::parse(&bytes)?;
    let (dev, ino) = crate::identity_import::id(&stat);
    Ok((
        package,
        PackageSource {
            dev,
            ino,
            sha256: sha_hex(&bytes),
        },
    ))
}

/// Remove the package file that was read, only while `path` still names
/// that inode with those bytes. The parent is opened once and the file is
/// checked, read and unlinked through that held descriptor, so a parent
/// swapped for a link meanwhile cannot redirect the removal. `Err` keeps it.
pub fn remove_package(path: &Path, source: &PackageSource) -> Result<(), &'static str> {
    use crate::identity_import::{fstat, id, stat_at, DIRECTORY_FLAGS};
    use std::os::fd::AsRawFd;
    let (Some(parent), Some(leaf)) = (path.parent(), path.file_name()) else {
        return Err("invite_changed");
    };
    let parent = CString::new(parent.as_os_str().as_bytes()).map_err(|_| "invite_changed")?;
    let leaf = CString::new(leaf.as_bytes()).map_err(|_| "invite_changed")?;
    // SAFETY: a NUL-terminated path; the flags never create anything.
    let raw = unsafe { libc::open(parent.as_ptr(), DIRECTORY_FLAGS) };
    if raw < 0 {
        return Err("invite_changed");
    }
    // SAFETY: `raw` is a fresh descriptor owned by nobody else.
    let dir = unsafe { File::from_raw_fd(raw) };
    let named = stat_at(&dir, &leaf).map_err(|_| "invite_changed")?;
    if id(&named) != (source.dev, source.ino)
        || named.st_mode & libc::S_IFMT != libc::S_IFREG
        || named.st_nlink != 1
    {
        return Err("invite_changed");
    }
    // SAFETY: a NUL-terminated leaf below the held directory.
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err("invite_changed");
    }
    // SAFETY: `raw` is a fresh descriptor owned by nobody else.
    let file = unsafe { File::from_raw_fd(raw) };
    if fstat(&file).map(|stat| id(&stat)) != Ok((source.dev, source.ino)) {
        return Err("invite_changed");
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PACKAGE_BYTES + 1));
    (&file)
        .take(MAX_PACKAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "invite_unreadable")?;
    if sha_hex(&bytes) != source.sha256 {
        return Err("invite_changed");
    }
    // SAFETY: the same leaf below the same held directory.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), leaf.as_ptr(), 0) } != 0 {
        return Err("invite_not_removed");
    }
    let _ = dir.sync_all();
    Ok(())
}

/// v45 (menu app): the app's private inbox below `$HOME`, beside the join
/// staging root.
pub const INBOX_DIR: &str = "Library/Application Support/dev.aegis.macos/join";

/// v45 (menu app): admit the package the user chose (`read_package`) and
/// copy its canonical bytes into the app's private `inbox` (created 0700)
/// as a fresh 0600 file, so the host child reads a file of the app's own
/// and never a privacy-protected folder (Downloads, Desktop) the open panel
/// granted only to the app. Returns the copy and the original's source, for
/// removing the original later (`remove_package`).
pub fn copy_to_inbox(
    original: &Path,
    inbox: &Path,
) -> Result<(std::path::PathBuf, PackageSource), &'static str> {
    use std::{
        io::Write,
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    };
    let (package, source) = read_package(original)?;
    if !inbox.is_absolute() {
        return Err("invite_inbox_refused");
    }
    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(inbox)
    {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err("invite_inbox_refused"),
    }
    let meta = std::fs::symlink_metadata(inbox).map_err(|_| "invite_inbox_refused")?;
    // SAFETY: geteuid has no preconditions.
    if !meta.is_dir()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || std::fs::canonicalize(inbox).ok().as_deref() != Some(inbox)
    {
        return Err("invite_inbox_refused");
    }
    // The copies hold an unspent token: never in a backup.
    crate::host_enroll::exclude_from_backup(inbox);
    let random = enrollment::new_invitation_token();
    let copy = inbox.join(format!("join-{}.{EXTENSION}", &random[..16]));
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&copy)?;
        file.write_all(&package.encode())?;
        file.sync_all()?;
        File::open(inbox)?.sync_all()
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&copy);
        return Err("invite_inbox_refused");
    }
    Ok((copy, source))
}

/// v45 (menu app): at start, remove every copy a quit, crash or force-quit
/// left in the inbox (no join runs yet). The number removed.
pub fn sweep_inbox(inbox: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(inbox) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let copy = entry.path();
        if std::fs::symlink_metadata(&copy).is_ok_and(|meta| meta.is_file()) {
            let before = copy.exists();
            discard_inbox_copy(&copy, inbox);
            if before && !copy.exists() {
                removed += 1;
            }
        }
    }
    removed
}

/// v45 (menu app): remove an inbox copy the host did not remove (a join
/// that did not commit). Only a regular file in `inbox` named by
/// `copy_to_inbox`.
pub fn discard_inbox_copy(copy: &Path, inbox: &Path) {
    let ours = copy.parent() == Some(inbox)
        && copy
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("join-") && name.ends_with(EXTENSION));
    if ours && std::fs::symlink_metadata(copy).is_ok_and(|meta| meta.file_type().is_file()) {
        let _ = std::fs::remove_file(copy);
    }
}

#[cfg(test)]
#[path = "invite_package_tests.rs"]
pub(crate) mod tests;
