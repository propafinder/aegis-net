//! B-06 S14: provider identity import and forget over the authenticated XPC
//! channel.
//!
//! The root provider's App Group container lives under `/private/var/root`,
//! out of reach of the containing app, which runs as the console user. The
//! host therefore sends the identity tree to the provider, which writes it
//! into its own container. Authorization is layered: libxpc delivers only a
//! peer that satisfies the pinned Developer ID requirement (S10); the
//! identity verbs additionally require the peer euid to be the console user,
//! a member of the admin group and no member of `_mbsetupuser`, and an
//! administrator's fresh approval for this one request (`authorization`: an
//! `AuthorizationExternalForm` whose reference holds the password the host's
//! `dev.aegis.macos.identity-change` prompt just took, checked by the
//! provider for Apple's network-configuration right and spent by its first
//! presentation; v30).
//!
//! An import is staged in a fresh 0700 directory inside the container,
//! checked by the production validators (`BoundRelayPolicy::from_snapshot`,
//! `ProtectedOnlineExpectation::open_existing` + `expectation_at`) and then
//! committed with one `renameatx_np` of the whole staged `Aegis` tree:
//! `RENAME_SWAP` over an existing tree or `RENAME_EXCL` for the first one.
//! The bundle and the identity therefore change together; no reader ever
//! sees one from each generation. The reply manifest is computed from the
//! committed bytes, read back through the committed descriptors.
//!
//! Neither verb is a relay ACK, packet permit, Store grant or start request.
use crate::{
    app_group::{
        custody_refusal_code, CapturedBridgeSnapshot, CapturedSfuSnapshot,
        CapturedWebResponseSnapshot, HeldContainer,
    },
    bound_relay_policy::BoundRelayPolicy,
};
use aegis_client::{
    protected_online_expectation::ProtectedOnlineExpectation,
    public_profile_file::profile_digest_bytes,
};
use aegis_core::{
    https_bridge::{ClientSettings as BridgeSettings, SIDECAR},
    secure_channel::registry,
    web_response_profile::WebResponseSettings,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::{c_char, c_int, c_void, CStr, CString},
    fs::File,
    io::{self, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Condvar, Mutex, MutexGuard, PoisonError,
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Proof of administrator presence for the identity verbs (audit fix).
#[path = "identity_authorization.rs"]
pub mod authorization;

/// Payload manifest version. Any other value is refused before its shape.
pub const IMPORT_VERSION: u64 = 1;
/// The manifest frame is refused unparsed above this length.
pub const MAX_MANIFEST_BYTES: usize = 4096;
/// Sum of every file in one import, checked before any byte is copied.
pub const MAX_IMPORT_BYTES: usize = 1024 * 1024;
/// The bridge credential's fixed leaf in the committed identity directory.
pub const BRIDGE_CREDENTIAL: &str = "bridge-credential";
const LOCK: &str = ".lock";
/// Committed path of the Store lock the provider creates (never sent).
pub const LOCK_PATH: &str = "identity/.lock";

const KIB: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dir {
    Bundle,
    Identity,
}
impl Dir {
    pub(crate) fn name(self) -> &'static CStr {
        match self {
            Self::Bundle => c"bundle",
            Self::Identity => c"identity",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Required,
    /// The sidecar and its credential: both or neither.
    Bridge,
    WebResponse,
    SfuMedia,
}

/// One importable file: its XPC key (also its committed path below
/// `Aegis/`), directory, leaf and per-file byte cap.
#[derive(Debug)]
pub struct Member {
    pub(crate) key: &'static CStr,
    pub(crate) dir: Dir,
    pub(crate) leaf: &'static str,
    pub(crate) cap: usize,
    kind: Kind,
}
impl Member {
    pub fn name(&self) -> &'static str {
        // Every key is an ASCII literal below.
        self.key.to_str().unwrap_or("")
    }
    /// Every import carries this file (the bridge pair is optional).
    pub(crate) fn required(&self) -> bool {
        self.kind == Kind::Required
    }
}

const fn member(
    key: &'static CStr,
    dir: Dir,
    leaf: &'static str,
    cap: usize,
    kind: Kind,
) -> Member {
    Member {
        key,
        dir,
        leaf,
        cap,
        kind,
    }
}

/// The fixed import table, in manifest order. The bundle caps match the
/// public profile reader (64 KiB), the identity caps the Store's ordinary
/// (64 KiB) and online (256 KiB) reads, the bridge caps the capture's.
/// No `runtime.json`: the provider derives its binding (S03 part 4). No
/// online request, response or migration journal: the provider capture
/// refuses their presence (S22), so they can never be sent.
pub const IMPORT_MEMBERS: [Member; 19] = [
    member(
        c"bundle/bundle.json",
        Dir::Bundle,
        "bundle.json",
        64 * KIB,
        Kind::Required,
    ),
    member(
        c"bundle/outer-ca.pem",
        Dir::Bundle,
        "outer-ca.pem",
        64 * KIB,
        Kind::Required,
    ),
    member(
        c"bundle/inner-ca.pem",
        Dir::Bundle,
        "inner-ca.pem",
        64 * KIB,
        Kind::Required,
    ),
    member(
        c"bundle/device-ca.pem",
        Dir::Bundle,
        "device-ca.pem",
        64 * KIB,
        Kind::Required,
    ),
    member(
        c"identity/identity.json",
        Dir::Identity,
        "identity.json",
        64 * KIB,
        Kind::Required,
    ),
    member(
        c"identity/device.key",
        Dir::Identity,
        "device.key",
        64 * KIB,
        Kind::Required,
    ),
    member(
        c"identity/device.csr",
        Dir::Identity,
        "device.csr",
        64 * KIB,
        Kind::Required,
    ),
    member(
        c"identity/device.pem",
        Dir::Identity,
        "device.pem",
        64 * KIB,
        Kind::Required,
    ),
    member(
        c"identity/device-ca.pem",
        Dir::Identity,
        "device-ca.pem",
        64 * KIB,
        Kind::Required,
    ),
    member(
        c"identity/bundle-profile.sha256",
        Dir::Identity,
        "bundle-profile.sha256",
        256,
        Kind::Required,
    ),
    member(
        c"identity/online-completed.json",
        Dir::Identity,
        "online-completed.json",
        256 * KIB,
        // S22: an identity without a completed issuance is never imported.
        Kind::Required,
    ),
    member(
        c"identity/https-bridge.toml",
        Dir::Identity,
        SIDECAR,
        8192,
        Kind::Bridge,
    ),
    member(
        c"identity/bridge-credential",
        Dir::Identity,
        BRIDGE_CREDENTIAL,
        65,
        Kind::Bridge,
    ),
    member(
        c"identity/web-response.toml",
        Dir::Identity,
        aegis_client::device_web_response::SIDECAR,
        8192,
        Kind::WebResponse,
    ),
    member(
        c"identity/web-response-credential",
        Dir::Identity,
        WEB_RESPONSE_CREDENTIAL,
        65,
        Kind::WebResponse,
    ),
    member(
        c"identity/sfu-media.toml",
        Dir::Identity,
        crate::sfu_media_custody::SIDECAR,
        8192,
        Kind::SfuMedia,
    ),
    member(
        c"identity/sfu-broker-key",
        Dir::Identity,
        crate::sfu_media_custody::BROKER_KEY,
        65,
        Kind::SfuMedia,
    ),
    member(
        c"identity/sfu-broker-ca.pem",
        Dir::Identity,
        crate::sfu_media_custody::BROKER_CA,
        64 * KIB,
        Kind::SfuMedia,
    ),
    member(
        c"identity/sfu-media-ca.pem",
        Dir::Identity,
        crate::sfu_media_custody::MEDIA_CA,
        64 * KIB,
        Kind::SfuMedia,
    ),
];
// Every cap together fits the total bound, so a manifest or envelope whose
// files are each within their cap is within `MAX_IMPORT_BYTES`.
const _: () = {
    let mut total = 0;
    let mut index = 0;
    while index < IMPORT_MEMBERS.len() {
        total += IMPORT_MEMBERS[index].cap;
        index += 1;
    }
    assert!(total <= MAX_IMPORT_BYTES);
};
const RECORD_MEMBER: usize = 4;
const KEY_MEMBER: usize = 5;
const CSR_MEMBER: usize = 6;
const CERTIFICATE_MEMBER: usize = 7;
const DEVICE_CA_MEMBER: usize = 8;
const COMPLETION_MEMBER: usize = 10;
pub(crate) const SIDECAR_MEMBER: usize = 11;
pub(crate) const CREDENTIAL_MEMBER: usize = 12;
pub const WEB_RESPONSE_CREDENTIAL: &str = "web-response-credential";
pub(crate) const WEB_SIDECAR_MEMBER: usize = 13;
pub(crate) const WEB_CREDENTIAL_MEMBER: usize = 14;
pub(crate) const SFU_SIDECAR_MEMBER: usize = 15;
pub(crate) const SFU_KEY_MEMBER: usize = 16;
pub(crate) const SFU_BROKER_CA_MEMBER: usize = 17;
pub(crate) const SFU_MEDIA_CA_MEMBER: usize = 18;
const BUNDLE_MEMBERS: usize = 4;

fn member_index(name: &str) -> Option<usize> {
    IMPORT_MEMBERS.iter().position(|m| m.name() == name)
}

/// Committed paths a reply may name: every member and the provider's lock.
pub(crate) fn committed_path_allowed(path: &str) -> Option<usize> {
    if path == LOCK_PATH {
        Some(0)
    } else {
        member_index(path).map(|index| IMPORT_MEMBERS[index].cap)
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub(crate) fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// Manifest and payload: shared by the host encoder and the provider decoder.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    pub member: usize,
    pub length: usize,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportManifest {
    pub entries: Vec<ManifestEntry>,
}

impl ImportManifest {
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }
}

pub fn encode_manifest(manifest: &ImportManifest) -> Vec<u8> {
    let files: Vec<Value> = manifest
        .entries
        .iter()
        .map(|entry| {
            json!({
                "name": IMPORT_MEMBERS.get(entry.member).map_or("", Member::name),
                "length": entry.length,
                "sha256": entry.sha256,
            })
        })
        .collect();
    serde_json::to_vec(&json!({"version": IMPORT_VERSION, "files": files})).unwrap_or_default()
}

fn exact(value: &Value, keys: &[&str]) -> Option<Map<String, Value>> {
    let object = value.as_object()?;
    (object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)))
        .then(|| object.clone())
}

/// Decode and check one manifest: known version, table order without
/// duplicates, per-file caps (which bound the total), every required file,
/// the bridge pair complete and the one canonical spelling.
pub fn decode_manifest(bytes: &[u8]) -> Result<ImportManifest, &'static str> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err("import_manifest_oversized");
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "import_manifest_malformed")?;
    // The version is judged before the shape: a newer host gets a stable
    // refusal rather than a shape error.
    match value.get("version").and_then(Value::as_u64) {
        Some(IMPORT_VERSION) => {}
        _ if value.get("version").is_some() => return Err("import_version_unknown"),
        _ => return Err("import_manifest_malformed"),
    }
    let object = exact(&value, &["version", "files"]).ok_or("import_manifest_malformed")?;
    let files = object["files"]
        .as_array()
        .filter(|files| files.len() <= IMPORT_MEMBERS.len())
        .ok_or("import_manifest_malformed")?;
    let mut entries = Vec::with_capacity(files.len());
    for file in files {
        let file = exact(file, &["name", "length", "sha256"]).ok_or("import_manifest_malformed")?;
        let index = file["name"]
            .as_str()
            .and_then(member_index)
            .ok_or("import_file_unknown")?;
        if entries
            .last()
            .is_some_and(|last: &ManifestEntry| last.member >= index)
        {
            return Err("import_manifest_order");
        }
        let length = file["length"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or("import_manifest_malformed")?;
        if length > IMPORT_MEMBERS[index].cap {
            return Err("import_file_oversized");
        }
        if length == 0 {
            return Err("import_file_empty");
        }
        let sha256 = file["sha256"]
            .as_str()
            .filter(|text| is_sha256_hex(text))
            .ok_or("import_manifest_malformed")?;
        entries.push(ManifestEntry {
            member: index,
            length,
            sha256: sha256.to_owned(),
        });
    }
    let present = |index: usize| entries.iter().any(|entry| entry.member == index);
    if IMPORT_MEMBERS
        .iter()
        .enumerate()
        .any(|(index, m)| m.kind == Kind::Required && !present(index))
    {
        return Err("import_file_missing");
    }
    if present(SIDECAR_MEMBER) != present(CREDENTIAL_MEMBER) {
        return Err("import_bridge_incomplete");
    }
    if present(WEB_SIDECAR_MEMBER) != present(WEB_CREDENTIAL_MEMBER) {
        return Err("import_web_response_incomplete");
    }
    let sfu_present = [
        SFU_SIDECAR_MEMBER,
        SFU_KEY_MEMBER,
        SFU_BROKER_CA_MEMBER,
        SFU_MEDIA_CA_MEMBER,
    ]
    .into_iter()
    .filter(|index| present(*index))
    .count();
    if sfu_present != 0 && sfu_present != 4 {
        return Err("import_sfu_media_incomplete");
    }
    let manifest = ImportManifest { entries };
    // One spelling only: no duplicate keys, whitespace or escapes.
    if encode_manifest(&manifest) != bytes {
        return Err("import_manifest_noncanonical");
    }
    Ok(manifest)
}

/// Received or read file bytes, each in a zeroizing buffer, in table order.
pub struct ImportPayload {
    files: Vec<(usize, Zeroizing<Vec<u8>>)>,
}

impl ImportPayload {
    /// Bind `files` (in manifest order) to `manifest`: same count, exact
    /// lengths (a short file is truncated) and SHA-256 digests.
    pub fn verify(
        manifest: &ImportManifest,
        files: Vec<Zeroizing<Vec<u8>>>,
    ) -> Result<Self, &'static str> {
        if files.len() != manifest.entries.len() {
            return Err("import_file_missing");
        }
        let mut bound = Vec::with_capacity(files.len());
        for (entry, bytes) in manifest.entries.iter().zip(files) {
            if bytes.len() < entry.length {
                return Err("import_file_truncated");
            }
            if bytes.len() != entry.length {
                return Err("import_file_length_mismatch");
            }
            if sha256_hex(&bytes) != entry.sha256 {
                return Err("import_digest_mismatch");
            }
            bound.push((entry.member, bytes));
        }
        Ok(Self { files: bound })
    }

    /// Build from `(member name, bytes)` pairs in any order; the result
    /// passes the same manifest checks the provider applies. The host reads
    /// its source tree through `host_import::SourceTree` (S15).
    pub fn from_members(mut files: Vec<(&str, Zeroizing<Vec<u8>>)>) -> Result<Self, &'static str> {
        let mut indexed = Vec::with_capacity(files.len());
        for (name, bytes) in files.drain(..) {
            indexed.push((member_index(name).ok_or("import_file_unknown")?, bytes));
        }
        indexed.sort_by_key(|(index, _)| *index);
        let manifest = ImportManifest {
            entries: indexed
                .iter()
                .map(|(index, bytes)| ManifestEntry {
                    member: *index,
                    length: bytes.len(),
                    sha256: sha256_hex(bytes),
                })
                .collect(),
        };
        let manifest = decode_manifest(&encode_manifest(&manifest))?;
        Self::verify(&manifest, indexed.into_iter().map(|(_, b)| b).collect())
    }

    pub fn manifest(&self) -> ImportManifest {
        ImportManifest {
            entries: self
                .files
                .iter()
                .map(|(index, bytes)| ManifestEntry {
                    member: *index,
                    length: bytes.len(),
                    sha256: sha256_hex(bytes),
                })
                .collect(),
        }
    }

    pub fn files(&self) -> impl Iterator<Item = (&'static Member, &[u8])> {
        self.files
            .iter()
            .map(|(index, bytes)| (&IMPORT_MEMBERS[*index], bytes.as_slice()))
    }
}

// ---------------------------------------------------------------------------
// Reports returned to the host.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedFile {
    /// Path below `Aegis/`, e.g. `identity/device.pem`.
    pub path: String,
    pub length: u64,
    /// SHA-256 of the committed bytes, read back after the commit. A digest
    /// of a private file reveals nothing about it; no file byte is replied.
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportReport {
    pub files: Vec<CommittedFile>,
    /// The replaced tree (old key material included) was removed. False
    /// leaves it in a `.aegis-import-*` directory that the next import or
    /// forget sweeps first.
    pub retired_removed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgetReport {
    /// `Aegis/identity` existed and was moved away from the live path.
    pub identity_was_present: bool,
    /// Nothing of it, and no leftover of an earlier import or forget,
    /// remains in the container (removal verified).
    pub key_material_removed: bool,
}

/// Host check of a committed manifest against the one it sent: the exact
/// committed paths (every sent file and the provider's lock) with the sent
/// lengths and digests. The sidecar alone is rewritten by the provider (its
/// credential path names the provider's own container), so only its
/// presence is checked.
pub fn verify_import_report(
    manifest: &ImportManifest,
    report: &ImportReport,
) -> Result<(), &'static str> {
    if report.files.len() != manifest.entries.len() + 1 {
        return Err("import_reply_mismatch");
    }
    for (entry, file) in manifest.entries.iter().zip(&report.files) {
        let m = &IMPORT_MEMBERS[entry.member];
        if file.path != m.name()
            || !matches!(
                entry.member,
                SIDECAR_MEMBER | WEB_SIDECAR_MEMBER | SFU_SIDECAR_MEMBER
            ) && (file.length != entry.length as u64 || file.sha256 != entry.sha256)
        {
            return Err("import_reply_mismatch");
        }
    }
    let lock = report.files.last().ok_or("import_reply_mismatch")?;
    if lock.path != LOCK_PATH || lock.length != 0 || lock.sha256 != sha256_hex(b"") {
        return Err("import_reply_mismatch");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Authorization of the identity verbs, beyond the S10 signing requirement.

pub(crate) trait Principals {
    /// The uid logged in at the console; refused when nobody is.
    fn console_uid(&self) -> Result<u32, &'static str>;
    fn is_admin(&self, uid: u32) -> Result<bool, &'static str>;
    /// v30: a member of `_mbsetupuser` (Setup Assistant's group).
    fn is_setup_user(&self, uid: u32) -> Result<bool, &'static str>;
}

/// The peer euid (from the admitted libxpc connection) must be the console
/// user, never root, and an admin group member. v30: never a member of
/// `_mbsetupuser`, whose session satisfies a branch of the proof right
/// without an administrator's password.
pub(crate) fn authorize_identity_peer(
    peer_euid: u32,
    principals: &impl Principals,
) -> Result<(), &'static str> {
    let console = principals.console_uid()?;
    if console == 0 || peer_euid != console {
        return Err("peer_not_console_user");
    }
    if !principals.is_admin(peer_euid)? {
        return Err("peer_not_admin");
    }
    if principals.is_setup_user(peer_euid)? {
        return Err("peer_in_setup_group");
    }
    Ok(())
}

type CfRef = *const c_void;
#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCDynamicStoreCopyConsoleUser(
        store: CfRef,
        uid: *mut libc::uid_t,
        gid: *mut libc::gid_t,
    ) -> CfRef;
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: CfRef);
    fn CFStringGetCString(value: CfRef, buffer: *mut c_char, size: isize, encoding: u32) -> u8;
}
// <membership.h>, part of libSystem.
unsafe extern "C" {
    fn mbr_uid_to_uuid(uid: libc::uid_t, uu: *mut u8) -> c_int;
    fn mbr_gid_to_uuid(gid: libc::gid_t, uu: *mut u8) -> c_int;
    fn mbr_check_membership(user: *const u8, group: *const u8, ismember: *mut c_int) -> c_int;
}
/// The macOS `admin` group.
pub(crate) const ADMIN_GID: libc::gid_t = 80;
/// v30: the macOS `_mbsetupuser` group (Setup Assistant).
pub(crate) const SETUP_GID: libc::gid_t = 248;

/// Whether `uid` is a member of `gid` (directly or nested).
fn is_member(uid: u32, gid: libc::gid_t) -> Result<bool, &'static str> {
    let mut user = [0u8; 16];
    let mut group = [0u8; 16];
    let mut member: c_int = 0;
    unsafe {
        if mbr_uid_to_uuid(uid, user.as_mut_ptr()) != 0
            || mbr_gid_to_uuid(gid, group.as_mut_ptr()) != 0
            || mbr_check_membership(user.as_ptr(), group.as_ptr(), &mut member) != 0
        {
            return Err("admin_membership_unknown");
        }
    }
    Ok(member == 1)
}

pub(crate) struct NativePrincipals;
impl Principals for NativePrincipals {
    fn console_uid(&self) -> Result<u32, &'static str> {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let name = unsafe { SCDynamicStoreCopyConsoleUser(std::ptr::null(), &mut uid, &mut gid) };
        if name.is_null() {
            return Err("console_user_unknown");
        }
        let mut buffer = [0 as c_char; 256];
        let ok = unsafe {
            CFStringGetCString(
                name,
                buffer.as_mut_ptr(),
                buffer.len() as isize,
                0x0800_0100,
            )
        };
        unsafe { CFRelease(name) };
        let text = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        // At the login window the console "user" is loginwindow (uid 0).
        if ok == 0 || text.is_empty() || text == c"loginwindow" {
            return Err("console_user_absent");
        }
        Ok(uid)
    }
    fn is_admin(&self, uid: u32) -> Result<bool, &'static str> {
        is_member(uid, ADMIN_GID)
    }
    fn is_setup_user(&self, uid: u32) -> Result<bool, &'static str> {
        is_member(uid, SETUP_GID).map_err(|_| "setup_membership_unknown")
    }
}

// ---------------------------------------------------------------------------
// The tree gate: one provider capture lease versus import/forget.

/// How long an import or forget waits for transient readers (unauthenticated
/// `profile-terms` captures) to finish. New readers wait behind it, so a
/// flood of readers can delay it by at most this bound, never refuse it as
/// a live session.
pub(crate) const READER_DRAIN: Duration = Duration::from_secs(2);

#[derive(Default)]
pub(crate) struct GateState {
    /// Session and renewal captures: while any exists, import and forget
    /// are refused (`session_live`).
    holders: usize,
    /// Transient public-terms captures: import and forget wait for them.
    readers: usize,
    /// Imports or forgets waiting for readers to drain. New readers wait.
    writers_waiting: usize,
}

/// While any session lease exists (a provider capture), import and forget
/// are refused. An import or forget holds the gate's mutex from its check to
/// its end, so a capture that starts meanwhile waits and then sees the
/// result; no capture can observe a half-committed tree. Read leases (the
/// public terms) are writer-preferring: an import or forget waits at most
/// `READER_DRAIN` for those already held, and no new one starts meanwhile.
pub(crate) struct TreeGate {
    state: Mutex<GateState>,
    changed: Condvar,
}
impl TreeGate {
    pub(crate) const fn new() -> Self {
        Self {
            state: Mutex::new(GateState {
                holders: 0,
                readers: 0,
                writers_waiting: 0,
            }),
            changed: Condvar::new(),
        }
    }
    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// A session lease. Blocks while an import or forget holds the gate.
    pub(crate) fn lease(&'static self) -> TreeLease {
        self.lock().holders += 1;
        TreeLease {
            gate: self,
            reader: false,
        }
    }
    /// A transient read lease. Blocks while an import or forget holds the
    /// gate or waits for readers to drain.
    pub(crate) fn read_lease(&'static self) -> TreeLease {
        let mut state = self.lock();
        while state.writers_waiting != 0 {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        state.readers += 1;
        TreeLease {
            gate: self,
            reader: true,
        }
    }
    fn exclusive(&self) -> Result<ExclusiveTree<'_>, &'static str> {
        self.exclusive_within(READER_DRAIN)
    }
    fn exclusive_within(&self, drain: Duration) -> Result<ExclusiveTree<'_>, &'static str> {
        let mut state = self.lock();
        if state.holders != 0 {
            return Err("session_live");
        }
        let deadline = Instant::now() + drain;
        state.writers_waiting += 1;
        while state.readers != 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            state = self
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        state.writers_waiting -= 1;
        let refusal = if state.holders != 0 {
            Some("session_live")
        } else if state.readers != 0 {
            Some("tree_busy")
        } else {
            None
        };
        if let Some(code) = refusal {
            drop(state);
            self.changed.notify_all();
            return Err(code);
        }
        Ok(ExclusiveTree {
            state: Some(state),
            changed: &self.changed,
        })
    }
    #[cfg(test)]
    pub(crate) fn holders(&self) -> usize {
        self.lock().holders
    }
    #[cfg(test)]
    pub(crate) fn readers(&self) -> usize {
        self.lock().readers
    }
    #[cfg(test)]
    pub(crate) fn exclusive_for_test(
        &self,
        drain: Duration,
    ) -> Result<ExclusiveTree<'_>, &'static str> {
        self.exclusive_within(drain)
    }
}

/// The gate held exclusively by one import or forget; waiting readers are
/// woken when it ends.
pub(crate) struct ExclusiveTree<'a> {
    state: Option<MutexGuard<'a, GateState>>,
    changed: &'a Condvar,
}
impl Drop for ExclusiveTree<'_> {
    fn drop(&mut self) {
        drop(self.state.take());
        self.changed.notify_all();
    }
}

pub(crate) struct TreeLease {
    gate: &'static TreeGate,
    reader: bool,
}
impl Drop for TreeLease {
    fn drop(&mut self) {
        let mut state = self.gate.lock();
        if self.reader {
            state.readers = state.readers.saturating_sub(1);
        } else {
            state.holders = state.holders.saturating_sub(1);
        }
        drop(state);
        self.gate.changed.notify_all();
    }
}

/// The provider process's one gate: `CapturedAppGroupInputs::capture_claim`
/// leases it, the XPC identity verbs take it exclusively.
pub(crate) static PROVIDER_TREE_GATE: TreeGate = TreeGate::new();

/// B-06 S23: bumped by every committed import or forget. An expired
/// identity's renewal gate stands only while this is unchanged, so the
/// rebuild loop of an expired epoch captures nothing until a new identity
/// is committed (and holds no lease that would refuse that import).
pub(crate) static IDENTITY_GENERATION: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Descriptor-relative filesystem steps below the held container.

pub(crate) const DIRECTORY_FLAGS: c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
const STAGING_PREFIX: &str = ".aegis-import-";
const RETIRED_PREFIX: &str = ".aegis-retired-";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Sticky Time Machine exclusion (what `tmutil addexclusion` writes): a
/// binary plist of the string `com.apple.backupd`. It travels with the
/// directory through the commit rename.
pub(crate) const BACKUP_EXCLUDE_XATTR: &CStr = c"com.apple.metadata:com_apple_backup_excludeItem";
pub(crate) const BACKUP_EXCLUDE_VALUE: [u8; 61] = *b"bplist00_\x10\x11com.apple.backupd\x08\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c";

pub(crate) fn last_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

pub(crate) fn open_dir_at(parent: &File, name: &CStr) -> Result<File, i32> {
    let raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), DIRECTORY_FLAGS) };
    if raw < 0 {
        Err(last_errno())
    } else {
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}

pub(crate) fn stat_at(parent: &File, name: &CStr) -> Result<libc::stat, i32> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(last_errno());
    }
    Ok(unsafe { stat.assume_init() })
}

pub(crate) fn fstat(file: &File) -> Result<libc::stat, i32> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(last_errno());
    }
    Ok(unsafe { stat.assume_init() })
}

pub(crate) type Id = (u64, u64);
pub(crate) fn id(stat: &libc::stat) -> Id {
    (stat.st_dev as u64, stat.st_ino)
}

fn is_private_dir(stat: &libc::stat, uid: u32) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFDIR
        && stat.st_uid == uid
        && stat.st_mode & 0o7777 == 0o700
}

fn is_private_file(stat: &libc::stat, uid: u32) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFREG
        && stat.st_uid == uid
        && stat.st_mode & 0o7777 == 0o600
        && stat.st_nlink == 1
}

/// A fresh private directory `name` in `parent`, never an existing one.
fn mkdir_private(parent: &File, name: &CStr, uid: u32) -> Result<File, &'static str> {
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err("import_stage_failed");
    }
    let dir = open_dir_at(parent, name).map_err(|_| "import_stage_failed")?;
    if unsafe { libc::fchmod(dir.as_raw_fd(), 0o700) } != 0
        || !fstat(&dir).is_ok_and(|stat| is_private_dir(&stat, uid))
    {
        return Err("import_stage_failed");
    }
    Ok(dir)
}

/// A fresh private file `name` in `parent` holding exactly `bytes`.
fn write_private(parent: &File, name: &CStr, bytes: &[u8], uid: u32) -> Result<Id, &'static str> {
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err("import_stage_failed");
    }
    let mut file = unsafe { File::from_raw_fd(raw) };
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err("import_stage_failed");
    }
    let stat = fstat(&file).map_err(|_| "import_stage_failed")?;
    if !is_private_file(&stat, uid) {
        return Err("import_stage_failed");
    }
    file.write_all(bytes).map_err(|_| "import_stage_failed")?;
    file.sync_all().map_err(|_| "import_stage_failed")?;
    Ok(id(&stat))
}

fn exclude_from_backup(dir: &File) -> Result<(), &'static str> {
    if unsafe {
        libc::fsetxattr(
            dir.as_raw_fd(),
            BACKUP_EXCLUDE_XATTR.as_ptr(),
            BACKUP_EXCLUDE_VALUE.as_ptr().cast(),
            BACKUP_EXCLUDE_VALUE.len(),
            0,
            0,
        )
    } != 0
    {
        return Err("import_backup_exclusion_failed");
    }
    Ok(())
}

/// The directory carries exactly the sticky backup exclusion.
pub(crate) fn backup_excluded(dir: &File) -> bool {
    let mut value = [0u8; 128];
    let length = unsafe {
        libc::fgetxattr(
            dir.as_raw_fd(),
            BACKUP_EXCLUDE_XATTR.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
            0,
            0,
        )
    };
    usize::try_from(length).is_ok_and(|length| value[..length] == BACKUP_EXCLUDE_VALUE)
}

fn unique_name(prefix: &str) -> Result<CString, &'static str> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    CString::new(format!(
        "{prefix}{}-{nanos}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
    .map_err(|_| "import_stage_failed")
}

/// The names in `dir` (never `.` or `..`), read through a duplicate of the
/// held descriptor, so no path is resolved again.
pub(crate) fn list(dir: &File) -> Option<Vec<CString>> {
    let duplicate = unsafe { libc::dup(dir.as_raw_fd()) };
    if duplicate < 0 {
        return None;
    }
    // The duplicate shares the held descriptor's offset: start from 0.
    if unsafe { libc::lseek(duplicate, 0, libc::SEEK_SET) } != 0 {
        unsafe { libc::close(duplicate) };
        return None;
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return None;
    }
    unsafe { libc::rewinddir(stream) };
    let mut names = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name != c"." && name != c".." {
            names.push(name.to_owned());
        }
    }
    unsafe { libc::closedir(stream) };
    Some(names)
}

/// Remove `name` below `parent` without following any link: a directory's
/// entries first, at most `depth` levels down, each through its parent's
/// descriptor. True only once `name` is gone.
fn remove_entry_at(parent: &File, name: &CStr, depth: usize) -> bool {
    let stat = match stat_at(parent, name) {
        Err(libc::ENOENT) => return true,
        Err(_) => return false,
        Ok(stat) => stat,
    };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0;
    }
    let Some(depth) = depth.checked_sub(1) else {
        return false;
    };
    let Ok(dir) = open_dir_at(parent, name) else {
        return false;
    };
    // An entry that survives makes the final AT_REMOVEDIR fail (ENOTEMPTY).
    for child in list(&dir).unwrap_or_default() {
        remove_entry_at(&dir, &child, depth);
    }
    drop(dir);
    unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) == 0 }
}

/// Remove `name` (an entry under this module's own prefixes) below the held
/// container, only while it is still the entry `expected`. A non-directory
/// leftover (a link is never followed) is unlinked. Unlinking is the
/// guarantee; APFS copy-on-write and snapshots are outside it (README).
fn remove_tree(container: &HeldContainer, name: &CStr, expected: Option<Id>) -> bool {
    match stat_at(container.file(), name) {
        Err(libc::ENOENT) => return true,
        Err(_) => return false,
        Ok(stat) => {
            if expected.is_some_and(|expected| expected != id(&stat)) {
                return false;
            }
        }
    }
    let removed = remove_entry_at(container.file(), name, 8);
    let _ = container.file().sync_all();
    removed && matches!(stat_at(container.file(), name), Err(libc::ENOENT))
}

/// Remove every staging or retired entry a failed or interrupted
/// import/forget left in the container. True once none remains; false when
/// one could not be removed (it may hold old key material).
fn sweep(container: &HeldContainer) -> Result<bool, &'static str> {
    let mut swept = true;
    for name in list(container.file()).ok_or("import_sweep_failed")? {
        let Ok(text) = name.to_str() else { continue };
        if (text.starts_with(STAGING_PREFIX) || text.starts_with(RETIRED_PREFIX))
            && !remove_tree(container, &name, None)
        {
            swept = false;
        }
    }
    container
        .revalidate_identity()
        .map_err(|_| "import_container_changed")?;
    Ok(swept)
}

/// The current `Aegis` entry: absent, or a private directory of `uid`.
fn existing_tree(container: &HeldContainer, uid: u32) -> Result<Option<Id>, &'static str> {
    match stat_at(container.file(), c"Aegis") {
        Err(libc::ENOENT) => Ok(None),
        Err(_) => Err("aegis_tree_unsafe"),
        Ok(stat) if is_private_dir(&stat, uid) => Ok(Some(id(&stat))),
        Ok(_) => Err("aegis_tree_unsafe"),
    }
}

struct Written {
    dir: Dir,
    leaf: CString,
    id: Id,
    cap: usize,
    path: String,
}

/// The staged `Aegis` tree. Removed on drop unless committed; after a swap
/// the staging name holds the replaced tree, removed separately.
struct Staging<'a> {
    container: &'a HeldContainer,
    uid: u32,
    name: CString,
    root: File,
    root_id: Id,
    bundle: File,
    identity: File,
    written: Vec<Written>,
    armed: bool,
}

impl<'a> Staging<'a> {
    fn create(container: &'a HeldContainer, uid: u32) -> Result<Self, &'static str> {
        let name = unique_name(STAGING_PREFIX)?;
        let root = mkdir_private(container.file(), &name, uid)?;
        // From here on the drop guard removes whatever was staged.
        let root_id = id(&fstat(&root).map_err(|_| "import_stage_failed")?);
        let mut staging = Self {
            container,
            uid,
            name,
            bundle: root.try_clone().map_err(|_| "import_stage_failed")?,
            identity: root.try_clone().map_err(|_| "import_stage_failed")?,
            root,
            root_id,
            written: Vec::new(),
            armed: true,
        };
        staging.bundle = mkdir_private(&staging.root, Dir::Bundle.name(), uid)?;
        staging.identity = mkdir_private(&staging.root, Dir::Identity.name(), uid)?;
        // Excluded from backup before any secret is written into it, so no
        // backup snapshot can hold a staged key in an unexcluded directory.
        exclude_from_backup(&staging.identity)?;
        if !backup_excluded(&staging.identity) {
            return Err("import_backup_exclusion_failed");
        }
        Ok(staging)
    }

    fn path(&self) -> PathBuf {
        self.container
            .path()
            .join(self.name.to_str().unwrap_or_default())
    }

    fn dir(&self, dir: Dir) -> &File {
        match dir {
            Dir::Bundle => &self.bundle,
            Dir::Identity => &self.identity,
        }
    }

    fn write(
        &mut self,
        dir: Dir,
        leaf: &str,
        bytes: &[u8],
        cap: usize,
    ) -> Result<(), &'static str> {
        let name = CString::new(leaf).map_err(|_| "import_stage_failed")?;
        let id = write_private(self.dir(dir), &name, bytes, self.uid)?;
        self.written.push(Written {
            dir,
            path: format!("{}/{leaf}", dir.name().to_str().unwrap_or_default()),
            leaf: name,
            id,
            cap,
        });
        Ok(())
    }

    /// Exactly the staged entries: `bundle` and `identity` (the held
    /// directories) at the root, and in each only the files written there,
    /// still the written inodes, private, unlinked elsewhere, and `identity`
    /// still excluded from backup. A link, an extra entry, a replaced file
    /// or a dropped exclusion refuses the import.
    fn verify(&self) -> Result<(), &'static str> {
        let refused = "import_staging_tampered";
        let at_root = stat_at(self.container.file(), &self.name).map_err(|_| refused)?;
        if id(&at_root) != self.root_id || !is_private_dir(&at_root, self.uid) {
            return Err(refused);
        }
        let names = |dir: &File| -> Result<BTreeSet<CString>, &'static str> {
            Ok(list(dir).ok_or(refused)?.into_iter().collect())
        };
        let expected_root = BTreeSet::from([c"bundle".to_owned(), c"identity".to_owned()]);
        if names(&self.root)? != expected_root {
            return Err(refused);
        }
        for dir in [Dir::Bundle, Dir::Identity] {
            let held = fstat(self.dir(dir)).map_err(|_| refused)?;
            let named = stat_at(&self.root, dir.name()).map_err(|_| refused)?;
            if id(&held) != id(&named) || !is_private_dir(&named, self.uid) {
                return Err(refused);
            }
            let expected: BTreeSet<CString> = self
                .written
                .iter()
                .filter(|w| w.dir == dir)
                .map(|w| w.leaf.clone())
                .collect();
            if names(self.dir(dir))? != expected {
                return Err(refused);
            }
        }
        // The identity directory carries the backup exclusion it commits with.
        if !backup_excluded(&self.identity) {
            return Err(refused);
        }
        for written in &self.written {
            let stat = stat_at(self.dir(written.dir), &written.leaf).map_err(|_| refused)?;
            if id(&stat) != written.id || !is_private_file(&stat, self.uid) {
                return Err(refused);
            }
        }
        Ok(())
    }
}

impl Drop for Staging<'_> {
    fn drop(&mut self) {
        if self.armed {
            remove_tree(self.container, &self.name, Some(self.root_id));
        }
    }
}

/// The refusal for a read-back that failed after `renameatx_np` committed
/// the tree: the provider may hold the new tree, so the host reports the
/// commit state as unknown (`host_import::conclude_import`).
pub(crate) const IMPORT_COMMIT_UNVERIFIED: &str = "import_commit_unverified";

/// Read one committed file through the committed descriptors: still the
/// staged inode, private, within its cap; digest over the bytes read.
fn committed_file(dir: &File, written: &Written, uid: u32) -> Result<CommittedFile, &'static str> {
    let refused = IMPORT_COMMIT_UNVERIFIED;
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            written.leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(refused);
    }
    let file = unsafe { File::from_raw_fd(raw) };
    let stat = fstat(&file).map_err(|_| refused)?;
    if id(&stat) != written.id || !is_private_file(&stat, uid) {
        return Err(refused);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(written.cap + 1));
    (&file)
        .take(written.cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused)?;
    if bytes.len() > written.cap {
        return Err(refused);
    }
    Ok(CommittedFile {
        path: written.path.clone(),
        length: bytes.len() as u64,
        sha256: sha256_hex(&bytes),
    })
}

/// The 64-hex credential (optionally `\n`-terminated, never all zeros),
/// exactly as capture admits it.
fn bridge_secret(bytes: &[u8]) -> Result<Zeroizing<[u8; 64]>, &'static str> {
    let value = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if value.len() != 64
        || value
            .iter()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(b))
        || value.iter().all(|b| *b == b'0')
    {
        return Err("import_bridge_refused");
    }
    let mut secret = Zeroizing::new([0u8; 64]);
    secret.copy_from_slice(value);
    Ok(secret)
}

/// Import `payload` as the `Aegis` tree of `container_path` (owned by
/// `uid`). Refused while `gate` has a lease. `before_commit` runs on the
/// validated staging directory just before its final check and the rename;
/// production passes a no-op, tests use it to tamper or to race a capture.
pub(crate) fn import_tree(
    container_path: &Path,
    uid: u32,
    gate: &TreeGate,
    payload: &ImportPayload,
    before_commit: impl FnOnce(&Path),
) -> Result<ImportReport, &'static str> {
    let _exclusive = gate.exclusive()?;
    let container =
        HeldContainer::open(container_path, uid).map_err(|error| custody_refusal_code(&error))?;
    if !sweep(&container)? {
        return Err("import_sweep_failed");
    }
    let existing = existing_tree(&container, uid)?;
    let final_identity = container.path().join("Aegis/identity");
    let mut staging = Staging::create(&container, uid)?;
    let staged_bundle = staging.path().join("bundle");
    let staged_identity = staging.path().join("identity");

    let mut public: [Vec<u8>; BUNDLE_MEMBERS] = Default::default();
    let mut bridge_settings = None;
    let mut bridge_credential = None;
    let mut web_settings = None;
    let mut web_credential = None;
    let mut sfu_key = None;
    let mut sfu_broker_ca = None;
    let mut sfu_media_ca = None;
    for (member, bytes) in &payload.files {
        let (member, bytes, m) = (*member, bytes.as_slice(), &IMPORT_MEMBERS[*member]);
        if member < BUNDLE_MEMBERS {
            public[member] = bytes.to_vec();
        }
        if member == SIDECAR_MEMBER {
            // The committed sidecar names the credential in the provider's
            // own committed identity directory, whatever the host's said.
            let mut settings: BridgeSettings = std::str::from_utf8(bytes)
                .ok()
                .and_then(|text| toml::from_str(text).ok())
                .ok_or("import_bridge_refused")?;
            settings.credential_file = final_identity.join(BRIDGE_CREDENTIAL);
            settings.validate().map_err(|_| "import_bridge_refused")?;
            let text = toml::to_string(&settings).map_err(|_| "import_bridge_refused")?;
            if text.len() > m.cap {
                return Err("import_bridge_refused");
            }
            staging.write(m.dir, m.leaf, text.as_bytes(), m.cap)?;
            bridge_settings = Some(settings);
            continue;
        }
        if member == CREDENTIAL_MEMBER {
            bridge_credential = Some(bridge_secret(bytes)?);
        }
        if member == WEB_SIDECAR_MEMBER {
            let mut settings: WebResponseSettings = std::str::from_utf8(bytes)
                .ok()
                .and_then(|text| toml::from_str(text).ok())
                .ok_or("import_web_response_refused")?;
            if settings
                .credential_file
                .file_name()
                .and_then(|leaf| leaf.to_str())
                != Some(WEB_RESPONSE_CREDENTIAL)
            {
                return Err("import_web_response_refused");
            }
            settings.credential_file = final_identity.join(WEB_RESPONSE_CREDENTIAL);
            settings
                .validate()
                .map_err(|_| "import_web_response_refused")?;
            let text = toml::to_string(&settings).map_err(|_| "import_web_response_refused")?;
            if text.len() > m.cap {
                return Err("import_web_response_refused");
            }
            staging.write(m.dir, m.leaf, text.as_bytes(), m.cap)?;
            web_settings = Some(settings);
            continue;
        }
        if member == WEB_CREDENTIAL_MEMBER {
            web_credential = Some(
                crate::web_response_custody::admit_key(bytes)
                    .map_err(|_| "import_web_response_refused")?,
            );
        }
        if member == SFU_SIDECAR_MEMBER {
            crate::sfu_media_custody::admit_import_sidecar(bytes)
                .map_err(|_| "import_sfu_media_refused")?;
            let text = crate::sfu_media_custody::relocated_sidecar(&final_identity);
            staging.write(m.dir, m.leaf, text.as_bytes(), m.cap)?;
            continue;
        }
        if member == SFU_KEY_MEMBER {
            sfu_key = Some(
                crate::sfu_media_custody::admit_broker_key(bytes)
                    .map_err(|_| "import_sfu_media_refused")?,
            );
        }
        if member == SFU_BROKER_CA_MEMBER {
            sfu_broker_ca = Some(bytes.to_vec());
        }
        if member == SFU_MEDIA_CA_MEMBER {
            sfu_media_ca = Some(bytes.to_vec());
        }
        staging.write(m.dir, m.leaf, bytes, m.cap)?;
    }
    staging.write(Dir::Identity, LOCK, b"", 0)?;
    staging.verify()?;

    // The production validators, over the staged tree.
    let bridge = match (bridge_settings, bridge_credential) {
        (None, None) => None,
        (Some(mut settings), Some(secret)) => {
            settings.credential_file = staged_identity.join(BRIDGE_CREDENTIAL);
            Some(CapturedBridgeSnapshot { settings, secret })
        }
        _ => return Err("import_bridge_incomplete"),
    };
    let web = match (web_settings, web_credential) {
        (None, None) => None,
        (Some(mut settings), Some(secret)) => {
            settings.credential_file = staged_identity.join(WEB_RESPONSE_CREDENTIAL);
            Some(CapturedWebResponseSnapshot { settings, secret })
        }
        _ => return Err("import_web_response_incomplete"),
    };
    let sfu = match (sfu_key, sfu_broker_ca, sfu_media_ca) {
        (None, None, None) => None,
        (Some(broker_key), Some(broker_ca), Some(media_ca)) => Some(CapturedSfuSnapshot {
            broker_key,
            broker_ca,
            media_ca,
        }),
        _ => return Err("import_sfu_media_incomplete"),
    };
    BoundRelayPolicy::from_snapshot_with_web_sfu(
        public.clone(),
        bridge,
        web,
        sfu,
        &staged_bundle,
        &staged_identity,
    )
    .map_err(|_| "import_bundle_refused")?;
    let digest = profile_digest_bytes(&public);
    {
        let store = ProtectedOnlineExpectation::open_existing(&staged_identity, &digest)
            .map_err(|_| "import_identity_refused")?;
        let now = registry::unix_now().map_err(|_| "import_clock_unavailable")?;
        store
            .expectation_at(now)
            .map_err(|_| "import_identity_refused")?;
        // The Store lock is released here, before the commit.
    }
    // S22: the same held-byte custody the provider capture applies: the CSR
    // re-derived from the key and device id, and the completion receipt
    // bound to the record, CSR, profile and certificate bytes (and, S23, its
    // window to the certificate's signed validity under the pinned CA).
    let bytes = |member: usize| {
        payload
            .files
            .iter()
            .find(|(index, _)| *index == member)
            .map(|(_, bytes)| bytes.as_slice())
            .ok_or("import_file_missing")
    };
    crate::identity_custody::verify(
        &crate::identity_custody::HeldIdentityBytes {
            record: bytes(RECORD_MEMBER)?,
            key: bytes(KEY_MEMBER)?,
            csr: bytes(CSR_MEMBER)?,
            certificate: bytes(CERTIFICATE_MEMBER)?,
            device_ca: bytes(DEVICE_CA_MEMBER)?,
            completion: bytes(COMPLETION_MEMBER)?,
        },
        &digest,
    )
    .map_err(|_| "import_identity_refused")?;

    before_commit(&staging.path());
    container
        .revalidate_identity()
        .map_err(|_| "import_container_changed")?;
    staging.verify()?;
    if existing_tree(&container, uid)? != existing {
        return Err("import_tree_changed");
    }
    let flags = if existing.is_some() {
        libc::RENAME_SWAP
    } else {
        libc::RENAME_EXCL
    };
    if unsafe {
        libc::renameatx_np(
            container.file().as_raw_fd(),
            staging.name.as_ptr(),
            container.file().as_raw_fd(),
            c"Aegis".as_ptr(),
            flags,
        )
    } != 0
    {
        return Err("import_commit_failed");
    }
    // Committed: the staging name now holds the replaced tree, if any.
    staging.armed = false;
    IDENTITY_GENERATION.fetch_add(1, Ordering::AcqRel);
    let _ = container.file().sync_all();

    let refused = IMPORT_COMMIT_UNVERIFIED;
    let aegis = open_dir_at(container.file(), c"Aegis").map_err(|_| refused)?;
    if fstat(&aegis).map(|stat| id(&stat)) != Ok(staging.root_id) {
        return Err(refused);
    }
    let mut files = Vec::with_capacity(staging.written.len());
    for dir in [Dir::Bundle, Dir::Identity] {
        let committed = open_dir_at(&aegis, dir.name()).map_err(|_| refused)?;
        let held = fstat(staging.dir(dir)).map_err(|_| refused)?;
        if fstat(&committed).map(|stat| id(&stat)) != Ok(id(&held)) {
            return Err(refused);
        }
        for written in staging.written.iter().filter(|w| w.dir == dir) {
            files.push((
                written.path.clone(),
                committed_file(&committed, written, uid)?,
            ));
        }
    }
    // Reply in manifest order, the lock last.
    let order = |path: &str| member_index(path).unwrap_or(IMPORT_MEMBERS.len());
    files.sort_by_key(|(path, _)| order(path));
    let retired_removed = match existing {
        None => true,
        Some(old) => remove_tree(&container, &staging.name, Some(old)),
    };
    Ok(ImportReport {
        files: files.into_iter().map(|(_, file)| file).collect(),
        retired_removed,
    })
}

/// Move `Aegis/identity` (a private directory of `uid`) out of the live path
/// in one rename, then remove it. Refused while `gate` has a lease. The
/// bundle stays. A leftover the sweep cannot remove does not stop the live
/// identity's removal; it is reported as `key_material_removed: false`.
pub(crate) fn forget_identity(
    container_path: &Path,
    uid: u32,
    gate: &TreeGate,
) -> Result<ForgetReport, &'static str> {
    let _exclusive = gate.exclusive()?;
    let container =
        HeldContainer::open(container_path, uid).map_err(|error| custody_refusal_code(&error))?;
    let swept = sweep(&container)?;
    let absent = ForgetReport {
        identity_was_present: false,
        key_material_removed: swept,
    };
    let Some(tree) = existing_tree(&container, uid)? else {
        return Ok(absent);
    };
    let aegis = open_dir_at(container.file(), c"Aegis").map_err(|_| "aegis_tree_unsafe")?;
    if fstat(&aegis).map(|stat| id(&stat)) != Ok(tree) {
        return Err("aegis_tree_unsafe");
    }
    let identity = match stat_at(&aegis, c"identity") {
        Err(libc::ENOENT) => return Ok(absent),
        Err(_) => return Err("forget_failed"),
        // Only the private directory import commits is moved: anything else
        // could land in the sweep namespace as an entry of unknown shape.
        Ok(stat) if is_private_dir(&stat, uid) => id(&stat),
        Ok(_) => return Err("aegis_tree_unsafe"),
    };
    let retired = unique_name(RETIRED_PREFIX)?;
    if unsafe {
        libc::renameat(
            aegis.as_raw_fd(),
            c"identity".as_ptr(),
            container.file().as_raw_fd(),
            retired.as_ptr(),
        )
    } != 0
    {
        return Err("forget_failed");
    }
    IDENTITY_GENERATION.fetch_add(1, Ordering::AcqRel);
    let _ = aegis.sync_all();
    let _ = container.file().sync_all();
    Ok(ForgetReport {
        identity_was_present: true,
        key_material_removed: remove_tree(&container, &retired, Some(identity)) && swept,
    })
}

/// Provider: import into its own signed App Group container.
pub(crate) fn provider_import(payload: &ImportPayload) -> Result<ImportReport, &'static str> {
    let (container, uid) = crate::app_group::signed_provider_container()
        .map_err(|error| custody_refusal_code(&error))?;
    import_tree(&container, uid, &PROVIDER_TREE_GATE, payload, |_| {})
}

/// Provider: forget the identity in its own signed App Group container.
pub(crate) fn provider_forget() -> Result<ForgetReport, &'static str> {
    let (container, uid) = crate::app_group::signed_provider_container()
        .map_err(|error| custody_refusal_code(&error))?;
    forget_identity(&container, uid, &PROVIDER_TREE_GATE)
}

#[cfg(test)]
#[path = "identity_import_tests.rs"]
pub(crate) mod tests;
