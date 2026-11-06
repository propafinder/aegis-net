//! Provider diagnostics channel over hand-written libxpc FFI.
//!
//! The system extension listens on its `NEMachServiceName`; the containing
//! app connects through the privileged Mach bootstrap, so a same-UID
//! LaunchAgent cannot shadow the service. Each side pins the *other* role's
//! Developer ID requirement with `xpc_connection_set_peer_code_signing_requirement`
//! before the connection is resumed, so libxpc delivers no message of any verb
//! from another signer. Frames are size-bounded before parsing and unknown
//! verbs are refused.
//!
//! `ping` and `status` are read-only observations. Neither is a relay ACK,
//! packet permit, credential grant, Store claim or installed acceptance.
//!
//! `import` and `forget-identity` (S14) change the provider's identity tree.
//! Beyond the signing requirement libxpc enforces, each requires the peer
//! euid to be the console user, an admin member and outside Setup
//! Assistant's group (`identity_import`), then an administrator's fresh
//! approval: an `AuthorizationExternalForm` under `identity-approval` (v30)
//! whose reference holds a password the host's prompt just took, verified
//! without interaction for Apple's network-configuration right (the one
//! right the provider's sandbox lets it obtain) and spent by its first
//! presentation (`identity_import::authorization`). A form under the v26 to
//! v29 key `authorization` is refused first, as
//! `identity_authorization_host_outdated`, before any other check. All
//! checks run before any payload byte is copied; both verbs are refused
//! while a provider capture is live. `renew` is authorized the same way.
//!
//! `identity-gate` (v30) is read-only: whether the identity verbs could be
//! admitted now (the peer, the identity rule, the proof rule and the
//! provider's own sandbox probe), with no prompt, no form and no change.
//!
//! `profile-terms` (S16a) is read-only and needs only the signing
//! requirement: it returns the public terms of the held tree
//! (`profile_terms`), never key material, a certificate or a path. Its
//! capture takes a transient read lease, so it cannot make an import or
//! forget look like a live session.
//!
//! `filter-status` (S20b) is read-only: whether this process's packet
//! filter provider started, the leak guard's mode and arm token and
//! its per-reason counters. Never an address. v27 (S20f) adds one key,
//! `observability`: the arm accounting, the drops by interface class and
//! direction and the ring of the last drops, all bounded tokens and counts.
//! A reply without it (a v26 provider) still decodes.
use crate::{
    app_group::{
        container_admitted, container_ancestor_checks, open_container_anchor, AncestorFailure,
        ContainerAnchorFailure, PROVIDER_APP_GROUP,
    },
    identity_import::{
        self,
        authorization::{
            self as identity_authorization, IdentityApproval, AUTHORIZATION_KEY,
            EXTERNAL_FORM_LENGTH, LEGACY_AUTHORIZATION_KEYS,
        },
        committed_path_allowed, decode_manifest, encode_manifest, is_sha256_hex, CommittedFile,
        ForgetReport, ImportPayload, ImportReport, IMPORT_MEMBERS, MAX_MANIFEST_BYTES,
    },
    profile_terms::{self, ProfileTerms},
    provider_session::{SessionPhase, SessionPhaseReader},
};
use block2::{Block, RcBlock};
use serde_json::{json, Map, Value};
use std::{
    ffi::{c_char, c_int, c_void, CStr},
    fs::File,
    net::{IpAddr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Component, Path},
    ptr::NonNull,
    sync::{Mutex, OnceLock},
};
use zeroize::Zeroizing;

/// Wire schema of every request and reply frame.
pub const SCHEMA: &str = "aegis-ne-xpc-v1";
/// A request is `{"schema","verb"}` only; anything larger is refused unparsed.
pub const MAX_REQUEST_BYTES: usize = 256;
/// Upper bound for one reply frame, checked by both encoder and decoder.
pub const MAX_REPLY_BYTES: usize = 32 * 1024;
/// Bound for any one reported string (URL, realpath, path component).
const MAX_TEXT_BYTES: usize = 4096;
/// Bound for the custody walk: `/`, the realpath components and the tail.
const MAX_CUSTODY_STEPS: usize = 66;
const MAX_REFUSAL_BYTES: usize = 64;

/// The packaged `NEMachServiceName`: the provider App Group plus this suffix
/// (see `assemble-unsigned.py`). NetworkExtension requires the App Group
/// prefix for a system extension's Mach service.
#[cfg(test)]
pub(crate) const MACH_SERVICE_SUFFIX: &str = ".packet-tunnel";
pub(crate) const MACH_SERVICE_NAME: &CStr = c"group.TEAMID0000.dev.aegis.macos.packet-tunnel";

/// Required of the containing app when it connects to the provider.
pub(crate) const HOST_PEER_REQUIREMENT: &CStr = c"identifier \"dev.aegis.macos\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = \"TEAMID0000\"";
/// Required of the provider when the containing app connects to it.
pub(crate) const PROVIDER_PEER_REQUIREMENT: &CStr = c"identifier \"dev.aegis.macos.PacketTunnel\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = \"TEAMID0000\"";

/// Test-side builder that the committed constants must equal.
/// Developer ID Application, issued by Apple's Developer ID intermediate
/// (6.2.6) with the Developer ID leaf marker (6.1.13), for the approved Team.
#[cfg(test)]
fn developer_id_requirement(identifier: &str) -> String {
    use crate::app_group::APPROVED_TEAM_ID;
    format!(
        "identifier \"{identifier}\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = \"{APPROVED_TEAM_ID}\""
    )
}

const XPC_CONNECTION_MACH_SERVICE_LISTENER: u64 = 1 << 0;
const XPC_CONNECTION_MACH_SERVICE_PRIVILEGED: u64 = 1 << 1;
/// Provider: a listener in the system extension's own (system) bootstrap.
pub(crate) const LISTENER_FLAGS: u64 = XPC_CONNECTION_MACH_SERVICE_LISTENER;
/// Host: look the service up only in the privileged (system) bootstrap.
pub(crate) const CLIENT_FLAGS: u64 = XPC_CONNECTION_MACH_SERVICE_PRIVILEGED;

const FRAME_KEY: &CStr = c"frame";
/// The import manifest; each file travels under its member key.
const MANIFEST_KEY: &CStr = c"manifest";

type XpcObject = *mut c_void;
type Handler = Block<dyn Fn(XpcObject)>;
#[repr(C)]
struct XpcGlobal {
    _private: [u8; 0],
}

// libxpc and libsystem_sandbox are part of libSystem, which every macOS
// binary links. No crate provides these declarations.
unsafe extern "C" {
    fn xpc_connection_create_mach_service(
        name: *const c_char,
        targetq: *mut c_void,
        flags: u64,
    ) -> XpcObject;
    fn xpc_connection_set_event_handler(connection: XpcObject, handler: &Handler);
    fn xpc_connection_set_peer_code_signing_requirement(
        connection: XpcObject,
        requirement: *const c_char,
    ) -> c_int;
    fn xpc_connection_resume(connection: XpcObject);
    fn xpc_connection_cancel(connection: XpcObject);
    fn xpc_connection_send_message(connection: XpcObject, message: XpcObject);
    fn xpc_connection_send_message_with_reply_sync(
        connection: XpcObject,
        message: XpcObject,
    ) -> XpcObject;
    fn xpc_dictionary_create(
        keys: *const *const c_char,
        values: *const XpcObject,
        count: usize,
    ) -> XpcObject;
    fn xpc_dictionary_create_reply(original: XpcObject) -> XpcObject;
    fn xpc_dictionary_get_remote_connection(dictionary: XpcObject) -> XpcObject;
    fn xpc_connection_get_euid(connection: XpcObject) -> libc::uid_t;
    fn xpc_dictionary_get_count(dictionary: XpcObject) -> usize;
    fn xpc_dictionary_get_value(dictionary: XpcObject, key: *const c_char) -> XpcObject;
    fn xpc_dictionary_set_data(
        dictionary: XpcObject,
        key: *const c_char,
        bytes: *const c_void,
        length: usize,
    );
    fn xpc_data_get_length(data: XpcObject) -> usize;
    fn xpc_data_get_bytes_ptr(data: XpcObject) -> *const c_void;
    fn xpc_get_type(object: XpcObject) -> *const XpcGlobal;
    fn xpc_release(object: XpcObject);
    static _xpc_type_dictionary: XpcGlobal;
    static _xpc_type_connection: XpcGlobal;
    static _xpc_type_error: XpcGlobal;
    static _xpc_type_data: XpcGlobal;
    static _xpc_error_connection_invalid: XpcGlobal;
    static _xpc_error_connection_interrupted: XpcGlobal;
    static _xpc_error_peer_code_signing_requirement: XpcGlobal;
    // SPI: non-zero when the process runs under a sandbox profile. Diagnostic.
    fn sandbox_check(pid: libc::pid_t, operation: *const c_char, filter: c_int, ...) -> c_int;
}

fn is_type(object: XpcObject, kind: &XpcGlobal) -> bool {
    !object.is_null() && std::ptr::eq(unsafe { xpc_get_type(object) }, kind)
}

/// One owned (+1) libxpc object, released on drop.
struct XpcOwned(NonNull<c_void>);
impl XpcOwned {
    fn new(raw: XpcObject) -> Option<Self> {
        NonNull::new(raw).map(Self)
    }
    fn as_ptr(&self) -> XpcObject {
        self.0.as_ptr()
    }
}
impl Drop for XpcOwned {
    fn drop(&mut self) {
        unsafe { xpc_release(self.0.as_ptr()) }
    }
}

/// A fresh dictionary whose only key is `frame` = `bytes`.
fn framed(bytes: &[u8]) -> Option<XpcOwned> {
    let message =
        XpcOwned::new(unsafe { xpc_dictionary_create(std::ptr::null(), std::ptr::null(), 0) })?;
    set_frame(message.as_ptr(), bytes);
    Some(message)
}

fn set_frame(dictionary: XpcObject, bytes: &[u8]) {
    unsafe {
        xpc_dictionary_set_data(
            dictionary,
            FRAME_KEY.as_ptr(),
            bytes.as_ptr().cast(),
            bytes.len(),
        )
    }
}

/// A fresh dictionary holding each `(key, bytes)` as one data value.
fn framed_entries(entries: &[(&CStr, &[u8])]) -> Option<XpcOwned> {
    let message =
        XpcOwned::new(unsafe { xpc_dictionary_create(std::ptr::null(), std::ptr::null(), 0) })?;
    for (key, bytes) in entries {
        unsafe {
            xpc_dictionary_set_data(
                message.as_ptr(),
                key.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
            )
        }
    }
    Some(message)
}

/// The envelope is a dictionary with exactly one `frame` data value of at
/// most `limit` bytes. The length is checked before any byte is copied.
fn read_frame(message: XpcObject, limit: usize) -> Result<Vec<u8>, &'static str> {
    if !is_type(message, unsafe { &_xpc_type_dictionary }) {
        return Err("envelope_not_dictionary");
    }
    if unsafe { xpc_dictionary_get_count(message) } != 1 {
        return Err("envelope_shape");
    }
    read_request_frame(message, limit)
}

/// One data value of `message` under `key`, as libxpc holds it: its length
/// is known before any byte is copied. Absent or not data is `None`.
fn data_value(message: XpcObject, key: &CStr) -> Option<(*const u8, usize)> {
    let data = unsafe { xpc_dictionary_get_value(message, key.as_ptr()) };
    if !is_type(data, unsafe { &_xpc_type_data }) {
        return None;
    }
    let length = unsafe { xpc_data_get_length(data) };
    let bytes = unsafe { xpc_data_get_bytes_ptr(data) };
    if bytes.is_null() && length != 0 {
        return None;
    }
    Some((bytes.cast::<u8>(), length))
}

/// The `frame` of a request dictionary, whatever else it carries; the
/// caller judges the other keys once it knows the verb.
fn read_request_frame(message: XpcObject, limit: usize) -> Result<Vec<u8>, &'static str> {
    if !is_type(message, unsafe { &_xpc_type_dictionary }) {
        return Err("envelope_not_dictionary");
    }
    let (bytes, length) = data_value(message, FRAME_KEY).ok_or("envelope_shape")?;
    if length > limit {
        return Err("frame_oversized");
    }
    if length == 0 || bytes.is_null() {
        return Err("frame_empty");
    }
    Ok(unsafe { std::slice::from_raw_parts(bytes, length) }.to_vec())
}

/// Copy `length` bytes from libxpc into a buffer reserved in full first, so
/// no reallocation leaves an unzeroized copy behind.
fn zeroizing_copy(bytes: *const u8, length: usize) -> Zeroizing<Vec<u8>> {
    let mut copy = Zeroizing::new(Vec::with_capacity(length));
    if length != 0 {
        copy.extend_from_slice(unsafe { std::slice::from_raw_parts(bytes, length) });
    }
    copy
}

/// The import payload of an already authorized request: the manifest,
/// then exactly its files (no other key), each length checked against its
/// cap before any file byte is copied. The caps bound the total
/// (`MAX_IMPORT_BYTES`, asserted at compile time); `ImportPayload::verify`
/// then binds every copied file to its declared length and digest.
fn read_import_payload(message: XpcObject) -> Result<ImportPayload, &'static str> {
    let (bytes, length) = data_value(message, MANIFEST_KEY).ok_or("import_manifest_missing")?;
    if length > MAX_MANIFEST_BYTES {
        return Err("import_manifest_oversized");
    }
    let manifest = decode_manifest(&zeroizing_copy(bytes, length))?;
    // frame, identity-approval, manifest, then exactly the manifest's files.
    if unsafe { xpc_dictionary_get_count(message) } != 3 + manifest.entries().len() {
        return Err("import_envelope_shape");
    }
    let mut sources = Vec::with_capacity(manifest.entries().len());
    for entry in manifest.entries() {
        let member = &IMPORT_MEMBERS[entry.member];
        let (bytes, length) = data_value(message, member.key).ok_or("import_file_missing")?;
        if length > member.cap {
            return Err("import_file_oversized");
        }
        sources.push((bytes, length));
    }
    let files = sources
        .into_iter()
        .map(|(bytes, length)| zeroizing_copy(bytes, length))
        .collect();
    ImportPayload::verify(&manifest, files)
}

fn classify_error(error: XpcObject) -> &'static str {
    let is = |global: &XpcGlobal| std::ptr::eq(error.cast_const().cast::<XpcGlobal>(), global);
    unsafe {
        if is(&_xpc_error_peer_code_signing_requirement) {
            "peer_requirement_unsatisfied"
        } else if is(&_xpc_error_connection_invalid) {
            "service_unavailable"
        } else if is(&_xpc_error_connection_interrupted) {
            "service_interrupted"
        } else {
            "xpc_error"
        }
    }
}

// ---------------------------------------------------------------------------
// Message codec. Pure Rust; both binaries use the same encoder and decoder.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Ping,
    Status,
    /// S14: carries a payload; see `query_provider_import`.
    Import,
    ForgetIdentity,
    /// S16a: the held tree's public profile terms.
    ProfileTerms,
    /// S23: the epoch's certificate renewal state (read-only).
    CertStatus,
    /// S23: force the due renewal now (identity-verb authorization).
    Renew,
    /// S20b: the packet filter's attachment, gate and counters (read-only).
    /// No bare host flag: `--filter-status` also reads NEFilterManager.
    FilterStatus,
    /// v30: whether the identity verbs could be admitted now (read-only;
    /// no prompt, no form, no change).
    IdentityGate,
}

impl Verb {
    fn name(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Status => "status",
            Self::Import => "import",
            Self::ForgetIdentity => "forget-identity",
            Self::ProfileTerms => "profile-terms",
            Self::CertStatus => "cert-status",
            Self::Renew => "renew",
            Self::FilterStatus => "filter-status",
            Self::IdentityGate => "identity-gate",
        }
    }
    fn parse(name: &str) -> Option<Self> {
        match name {
            "ping" => Some(Self::Ping),
            "status" => Some(Self::Status),
            "import" => Some(Self::Import),
            "forget-identity" => Some(Self::ForgetIdentity),
            "profile-terms" => Some(Self::ProfileTerms),
            "cert-status" => Some(Self::CertStatus),
            "renew" => Some(Self::Renew),
            "filter-status" => Some(Self::FilterStatus),
            "identity-gate" => Some(Self::IdentityGate),
            _ => None,
        }
    }
    /// The verbs that change the identity the provider uses: each needs an
    /// administrator's approval (`authorization`) beyond the peer checks.
    pub fn requires_authorization(self) -> bool {
        matches!(self, Self::Import | Self::ForgetIdentity | Self::Renew)
    }
    /// The bare host CLI flag for this verb. `import` has none: the host
    /// verb `--import DIR [--remove-source]` takes a directory and is
    /// parsed by `host_lifecycle::parse_import`.
    pub fn from_flag(flag: &str) -> Option<Self> {
        match flag {
            "--ping" => Some(Self::Ping),
            "--status" => Some(Self::Status),
            "--forget-identity" => Some(Self::ForgetIdentity),
            "--profile-terms" => Some(Self::ProfileTerms),
            "--cert-status" => Some(Self::CertStatus),
            "--renew" => Some(Self::Renew),
            "--identity-gate" => Some(Self::IdentityGate),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyStep {
    pub component: String,
    /// 0 when the directory opened (O_DIRECTORY|O_NOFOLLOW), else its errno.
    pub errno: i32,
}

/// The production custody anchor: the canonical container opened once by
/// its absolute path (O_DIRECTORY|O_NOFOLLOW), then F_GETPATH on that
/// descriptor compared byte-for-byte with the canonical path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerOpenProbe {
    /// 0 when the container opened, else the open errno.
    pub errno: i32,
    /// 0 when F_GETPATH succeeded (or nothing opened), else its errno.
    pub getpath_errno: i32,
    /// The opened descriptor names exactly the canonical path.
    pub path_matched: bool,
    /// The matched descriptor passes capture's container owner/mode
    /// admission (directory, owner root or the euid, no group/other write).
    /// Never true without `path_matched`.
    pub admitted: bool,
}

/// One directory above the container, as capture checks it by path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AncestorStep {
    /// The ancestor's final name; `/` for the root.
    pub component: String,
    /// 0 when lstat(2) succeeded, else its errno.
    pub lstat_errno: i32,
    /// lstat succeeded and the owner/mode policy admitted it. Never true
    /// with a nonzero `lstat_errno`.
    pub policy_ok: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenProbe {
    /// `ok`, or the failing step: `socket`, `bind` or `listen`.
    pub stage: String,
    pub errno: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PingReport {
    pub euid: u32,
    pub sandboxed: bool,
    /// The raw `containerURLForSecurityApplicationGroupIdentifier` URL.
    pub container_url: Option<String>,
    pub container_realpath: Option<String>,
    /// realpath(3) errno for the container path; 0 when resolved or absent.
    pub realpath_errno: i32,
    /// The historical walk from `/`; the sandbox denies it at /private.
    pub custody: Vec<CustodyStep>,
    /// Capture's lstat owner/mode check of every directory above the
    /// container, `/` first; empty when nothing resolved.
    pub container_ancestors: Vec<AncestorStep>,
    /// The container anchor capture uses; `None` when nothing resolved.
    pub container_open: Option<ContainerOpenProbe>,
    pub loopback_listen: ListenProbe,
    pub session_phase: String,
    /// `Aegis/identity/identity.json` below the matched container anchor.
    /// Presence only: capture's ancestor and container admission gates are
    /// `container_ancestors` and `container_open.admitted`.
    pub identity_present: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusReport {
    pub session_phase: String,
    pub session_refusal: Option<String>,
}

/// S23 `cert-status`: the epoch's certificate window and renewal record.
/// Public facts and stable tokens only: no certificate, key or path. v31:
/// while no epoch runs, the provider process's last record of the identity
/// (its backoff and last outcome outlive the epoch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertStatusReport {
    /// `unknown`, `valid`, `due`, `in_progress`, `pending`,
    /// `renewed_pending_ack`, `not_yet_valid`, `expired`,
    /// `failed:<class>`, (v31) `deferred:guarded`, or (v32) `parked` (a
    /// request the authority rejected no longer blocks the capture) or
    /// `superseded` (the authority issued a successor this client refused).
    pub state: String,
    pub not_before: Option<u64>,
    pub not_after: Option<u64>,
    /// When renewal falls due: two thirds of the lifetime.
    pub renew_at: Option<u64>,
    /// Consecutive failed attempts.
    pub attempts: u32,
    pub last_attempt_at: Option<u64>,
    pub next_attempt_at: Option<u64>,
    /// The last failure class (`FAILURE_CLASSES`).
    pub last_failure: Option<String>,
    /// v31: the first failure of the current failing run (with
    /// `last_failure` only). Sent only when set, so a v26 to v30 host still
    /// decodes a report with no failure.
    pub failing_since: Option<u64>,
    /// v32: the local check that refused (`RENEWAL_CHECKS`), beside
    /// `last_failure` `local_refused`; v32 review: or, while a request stays
    /// journaled (`pending`, `superseded`, `expired`), beside another class:
    /// the receipt check that refused the authority's issued answer, or the
    /// refusal of a rejected request's park. Sent only when set.
    pub check: Option<String>,
}

/// v31: `seconds` since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ` (UTC).
pub fn utc_text(seconds: u64) -> String {
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    // Days to the civil date (Howard Hinnant's `civil_from_days`).
    let z = i64::try_from(days).unwrap_or(i64::MAX / 2) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

impl CertStatusReport {
    /// v31: the host's one renewal line for `--status` and `--ping` (on
    /// stderr), when renewal needs attention: deferred beside the armed
    /// guard, failing, or expired. Times are UTC; no address, path or
    /// material. `None` while renewal is healthy or not yet due.
    pub fn renewal_line(&self) -> Option<String> {
        let at = |value: Option<u64>| value.map_or_else(|| "unknown".to_owned(), utc_text);
        let attempts = |n: u32| format!("{n} attempt{}", if n == 1 { "" } else { "s" });
        if self.state == "expired" {
            return Some(format!(
                "renewal expired at {} ({}): import a new identity",
                at(self.not_after),
                attempts(self.attempts)
            ));
        }
        // v32: a superseded request: the authority's registry names a
        // successor this client refused, so the relay refuses the installed
        // certificate; only an import helps.
        if self.state == "superseded" {
            let detail = self
                .check
                .as_deref()
                .or(self.last_failure.as_deref())
                .unwrap_or("unknown");
            return Some(format!(
                "renewal superseded ({detail}) since {}: the authority issued a successor this client refused; the relay no longer admits the installed certificate; import a new identity",
                at(self.failing_since.or(self.last_attempt_at))
            ));
        }
        // v32: a parked request: the installed certificate keeps carrying
        // traffic; the request is retried at a later Connect.
        if self.state == "parked" {
            let class = self.last_failure.as_deref().unwrap_or("unknown");
            // v32 review: and the local check of a later attempt (for
            // example an unpark the journal could not write).
            let check = self
                .check
                .as_ref()
                .map_or_else(String::new, |check| format!(" ({check})"));
            return Some(format!(
                "renewal parked after {class}{check} since {}: the installed certificate is kept until {}, {}; it retries at the next Connect after {}; an import replaces the identity",
                at(self.failing_since.or(self.last_attempt_at)),
                at(self.not_after),
                attempts(self.attempts),
                at(self.next_attempt_at)
            ));
        }
        if self.state == "deferred:guarded" {
            let failing = self
                .last_failure
                .as_ref()
                .map_or_else(String::new, |class| {
                    format!(", last failure {class} since {}", at(self.failing_since))
                });
            return Some(format!(
                "renewal deferred:guarded (due since {}; runs at the next connect), expires at {}, {}{failing}",
                at(self.renew_at),
                at(self.not_after),
                attempts(self.attempts)
            ));
        }
        let class = self.last_failure.as_ref()?;
        // v32: a named local check is shown even before any attempt (a
        // parked request that cannot be read refuses every attempt).
        if self.attempts == 0 && self.check.is_none() {
            return None;
        }
        let check = self
            .check
            .as_ref()
            .map_or_else(String::new, |check| format!(" ({check})"));
        Some(format!(
            "renewal failing ({class}) since {}, expires at {}, {}{check}",
            at(self.failing_since.or(self.last_attempt_at)),
            at(self.not_after),
            attempts(self.attempts)
        ))
    }
}

/// S20b `filter-status`: the packet filter of the provider process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterStatusReport {
    /// `startFilter` ran in this process and `stopFilter` has not.
    pub attached: bool,
    /// The pid `startFilter` recorded is this (the XPC listener's) process.
    pub pid_match: bool,
    /// `open` or `guarding`.
    pub mode: String,
    /// The token of the arm the gate holds (process-unique, issued by the
    /// gate at each arm); `None` while Open.
    pub armed_token: Option<u64>,
    pub relay_armed: bool,
    /// v31: always false from a v31 provider (the S20b authority allowance
    /// is gone); kept so v26 to v30 hosts and providers still decode.
    pub authority_armed: bool,
    pub udp_relay_allowed: bool,
    /// Every counted reason (`leak_guard::COUNTED`), in that order.
    pub counters: Vec<(String, u64)>,
    /// v27: the `observability` key; `None` from a provider without it.
    pub observability: Option<FilterObservability>,
}

const FILTER_MODES: [&str; 2] = ["open", "guarding"];

/// v27 (S20f) `filter-status` `observability`: address-free by
/// construction (counts, bounded tokens and interface codes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterObservability {
    /// Arms in the provider process (the gate's last token).
    pub arm_seq: u64,
    /// Disarms that opened the gate.
    pub disarms: u64,
    /// Milliseconds guarded, every span (the current one included).
    pub armed_ms_total: u64,
    /// Milliseconds since the current arm; `None` while Open.
    pub armed_for_ms: Option<u64>,
    /// Open intervals that began while an epoch's settings may be applied.
    pub open_while_applied: u64,
    /// Epochs noted applied and not yet withdrawn.
    pub applied_epochs: u64,
    /// The pinned relay interface (`en7`, or `h:<hash>`); `None` unset.
    pub primary_iface: Option<String>,
    /// `(class, [in, out, any])` for every `leak_guard::DROP_CLASSES`.
    pub drops: Vec<(String, [u64; 3])>,
    pub ring_next: u64,
    pub ring_skipped: u64,
    pub ring_torn: u64,
    /// The last drops, oldest first, at most `leak_guard::RING_SLOTS`.
    pub recent_drops: Vec<DropEntry>,
    /// v29: the `outbound` key; `None` from a provider before v29.
    pub outbound: Option<Box<OutboundObservability>>,
}

/// v29 (S20h) `observability.outbound`: the outbound drops by interface
/// class and kind, the marked ones, and the ring of outbound drops only.
/// Address-free by construction, like the rest of the observability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundObservability {
    /// `leak_guard::MARK_SPORT_FIRST` and `MARK_SPORT_COUNT` of the
    /// provider: its marker, a range of TCP source ports.
    pub mark_sport_first: u16,
    pub mark_sport_count: u16,
    /// `(class, counts in leak_guard::OUT_KINDS order)` for every class.
    pub kinds: Vec<(String, [u64; 8])>,
    /// The same for the TCP drops from a source port of the marker range.
    pub marked: Vec<(String, [u64; 8])>,
    pub ring_next: u64,
    pub ring_skipped: u64,
    pub ring_torn: u64,
    /// The last outbound drops, oldest first, at most
    /// `leak_guard::RING_SLOTS`.
    pub recent: Vec<OutDropEntry>,
}

/// v29: one record of the outbound ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutDropEntry {
    /// Its fields, `dir` always `out`.
    pub entry: DropEntry,
    /// It came from a source port of the marker range.
    pub marked: bool,
}

/// v27: one ring record of `filter-status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropEntry {
    pub index: u64,
    pub arm_seq: u64,
    pub ms: u64,
    pub class: String,
    pub iface: String,
    pub dir: String,
    pub family: String,
    pub proto: u8,
    pub tcp: String,
    pub reason: String,
}

const DROP_FAMILIES: [&str; 3] = ["none", "v4", "v6"];
const OBSERVABILITY_KEYS: [&str; 9] = [
    "arm_seq",
    "disarms",
    "armed_ms_total",
    "armed_for_ms",
    "open_while_applied",
    "applied_epochs",
    "primary_iface",
    "drops",
    "ring",
];
const DROP_ENTRY_KEYS: [&str; 10] = [
    "index", "arm_seq", "ms", "class", "iface", "dir", "family", "proto", "tcp", "reason",
];
/// v29: the keys of `observability.outbound`, and of every ring.
const OUTBOUND_KEYS: [&str; 5] = [
    "mark_sport_first",
    "mark_sport_count",
    "kinds",
    "marked",
    "ring",
];
const RING_KEYS: [&str; 4] = ["next", "skipped", "torn", "entries"];

/// S23 `renew`: the request was accepted (`renew_scheduled`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenewReport {
    pub outcome: String,
}

pub const CERT_STATES: [&str; 11] = [
    "unknown",
    "valid",
    "due",
    "in_progress",
    "pending",
    "renewed_pending_ack",
    "not_yet_valid",
    "expired",
    // v31: due, and the armed leak guard forbids the dial.
    "deferred:guarded",
    // v32: a request the authority rejected, parked beside the installed
    // certificate (which is captured).
    "parked",
    // v32: the authority issued a successor this client refused.
    "superseded",
];
pub const FAILURE_CLASSES: [&str; 7] = [
    "unavailable",
    "timeout",
    "rejected",
    "recovery_required",
    "local_refused",
    "interface_unresolved",
    // v31: split from `timeout` (which is now only after the connect).
    "connect_timeout",
];
const RENEW_OUTCOMES: [&str; 1] = ["renew_scheduled"];
/// v32: every local check a renewal names in `cert-status` (`check`) and in
/// its log: `renewal_journal::CHECKS` and the step's own codes.
pub const RENEWAL_CHECKS: [&str; 22] = [
    "renewal_local_refused",
    "identity_renewal_busy",
    "renewal_not_due",
    "renewal_predecessor_expired",
    "renewal_journal_conflict",
    "renewal_successor_not_yet_valid",
    "renewal_journal_write",
    "renewal_parked_refused",
    "renewal_receipt_malformed",
    "renewal_receipt_binding",
    "renewal_receipt_identity",
    "renewal_successor_certificate",
    "renewal_receipt_metadata",
    "renewal_successor_expired",
    "renewal_successor_before_due",
    "renewal_successor_after_expiry",
    "renewal_successor_not_extending",
    "renewal_clock_skew",
    "renewal_authority_refused",
    "session_clock_failed",
    "renewal_runtime_failed",
    "renewal_expectation_refused",
];

/// v30 `identity-gate`: each check the identity verbs would run, as one
/// token, with no prompt and no form. `peer` is `admitted` or the peer
/// check's refusal code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityGateReport {
    pub peer: String,
    /// `admitted`, `unregistered` (the host registers it at its first
    /// prompt), `inadmissible` or `unavailable`.
    pub identity_rule: String,
    /// `admitted`, `unexpected` or `unavailable`.
    pub proof_rule: String,
    /// The provider's own sandbox probe for the proof right: `allowed`,
    /// `denied`, `failed` or `unavailable`.
    pub proof_probe: String,
}
pub const GATE_IDENTITY_RULES: [&str; 4] =
    ["admitted", "unregistered", "inadmissible", "unavailable"];
pub const GATE_PROOF_RULES: [&str; 3] = ["admitted", "unexpected", "unavailable"];
pub const GATE_PROBES: [&str; 4] = ["allowed", "denied", "failed", "unavailable"];
impl IdentityGateReport {
    /// The first check that would refuse an identity verb, as
    /// `<check>_<state>` (`peer_` and the peer code for the peer); `None`
    /// when the gate is open.
    pub fn blocker(&self) -> Option<String> {
        if self.peer != "admitted" {
            return Some(format!("peer_{}", self.peer.trim_start_matches("peer_")));
        }
        if !matches!(self.identity_rule.as_str(), "admitted" | "unregistered") {
            return Some(format!("identity_rule_{}", self.identity_rule));
        }
        if self.proof_rule != "admitted" {
            return Some(format!("proof_rule_{}", self.proof_rule));
        }
        if self.proof_probe != "allowed" {
            return Some(format!("proof_probe_{}", self.proof_probe));
        }
        None
    }
    /// The host's one summary line.
    pub fn line(&self) -> String {
        format!(
            "identity_gate={} peer={} identity_rule={} proof_rule={} proof_probe={}",
            self.blocker().map_or("open", |_| "closed"),
            self.peer,
            self.identity_rule,
            self.proof_rule,
            self.proof_probe
        )
    }
}

fn cert_state_allowed(state: &str) -> bool {
    CERT_STATES.contains(&state)
        || state
            .strip_prefix("failed:")
            .is_some_and(|class| FAILURE_CLASSES.contains(&class))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Ping(PingReport),
    Status(StatusReport),
    Import(ImportReport),
    Forget(ForgetReport),
    ProfileTerms(ProfileTerms),
    CertStatus(CertStatusReport),
    Renew(RenewReport),
    FilterStatus(FilterStatusReport),
    IdentityGate(IdentityGateReport),
    Refused(String),
}

const SESSION_PHASES: [&str; 5] = ["none", "constructing", "ready", "sealed", "joined"];
const LISTEN_STAGES: [&str; 4] = ["ok", "socket", "bind", "listen"];

fn phase_name(phase: Option<SessionPhase>) -> &'static str {
    match phase {
        None => "none",
        Some(SessionPhase::Constructing) => "constructing",
        Some(SessionPhase::Ready) => "ready",
        Some(SessionPhase::Sealed) => "sealed",
        Some(SessionPhase::Joined) => "joined",
    }
}

/// A refusal or session code token: `[a-z][a-z0-9_:.-]*`, bounded.
fn stable_code(text: &str) -> bool {
    text.len() <= MAX_REFUSAL_BYTES
        && text.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_:.-".contains(&b))
}

pub fn encode_request(verb: Verb) -> Vec<u8> {
    format!("{{\"schema\":\"{SCHEMA}\",\"verb\":\"{}\"}}", verb.name()).into_bytes()
}

/// Exact-shape object: every key in `keys`, and no other.
fn exact_object(value: Value, keys: &[&str]) -> Option<Map<String, Value>> {
    let Value::Object(object) = value else {
        return None;
    };
    (object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)))
        .then_some(object)
}

pub fn decode_request(bytes: &[u8]) -> Result<Verb, &'static str> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err("request_oversized");
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "request_malformed")?;
    let object = exact_object(value, &["schema", "verb"]).ok_or("request_malformed")?;
    if object.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
        return Err("schema_mismatch");
    }
    let verb = object
        .get("verb")
        .and_then(Value::as_str)
        .and_then(Verb::parse)
        .ok_or("unknown_verb")?;
    // Only the one canonical spelling is accepted: no duplicate keys,
    // whitespace or escapes that a different parser could read differently.
    if bytes != encode_request(verb).as_slice() {
        return Err("request_noncanonical");
    }
    Ok(verb)
}

fn report_value(reply: &Reply) -> Value {
    match reply {
        Reply::Ping(report) => json!({
            "schema": SCHEMA,
            "verb": "ping",
            "report": {
                "euid": report.euid,
                "sandboxed": report.sandboxed,
                "container_url": report.container_url,
                "container_realpath": report.container_realpath,
                "realpath_errno": report.realpath_errno,
                "custody": report.custody.iter().map(|step| json!({
                    "component": step.component,
                    "errno": step.errno,
                })).collect::<Vec<_>>(),
                "container_ancestors": report.container_ancestors.iter().map(|step| json!({
                    "component": step.component,
                    "lstat_errno": step.lstat_errno,
                    "policy_ok": step.policy_ok,
                })).collect::<Vec<_>>(),
                "container_open": report.container_open.as_ref().map(|open| json!({
                    "errno": open.errno,
                    "getpath_errno": open.getpath_errno,
                    "path_matched": open.path_matched,
                    "admitted": open.admitted,
                })),
                "loopback_listen": {
                    "stage": report.loopback_listen.stage,
                    "errno": report.loopback_listen.errno,
                },
                "session_phase": report.session_phase,
                "identity_present": report.identity_present,
            },
        }),
        Reply::Status(report) => json!({
            "schema": SCHEMA,
            "verb": "status",
            "report": {
                "session_phase": report.session_phase,
                "session_refusal": report.session_refusal,
            },
        }),
        Reply::Import(report) => json!({
            "schema": SCHEMA,
            "verb": "import",
            "report": {
                "files": report.files.iter().map(|file| json!({
                    "path": file.path,
                    "length": file.length,
                    "sha256": file.sha256,
                })).collect::<Vec<_>>(),
                "retired_removed": report.retired_removed,
            },
        }),
        Reply::Forget(report) => json!({
            "schema": SCHEMA,
            "verb": "forget-identity",
            "report": {
                "identity_was_present": report.identity_was_present,
                "key_material_removed": report.key_material_removed,
            },
        }),
        Reply::ProfileTerms(terms) => json!({
            "schema": SCHEMA,
            "verb": "profile-terms",
            "report": {
                "relay": terms.relay.to_string(),
                "dns": terms.dns.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "mtu": terms.mtu,
                "profile_sha256": terms.profile_sha256,
            },
        }),
        Reply::CertStatus(report) => {
            let mut value = json!({
                "state": report.state,
                "not_before": report.not_before,
                "not_after": report.not_after,
                "renew_at": report.renew_at,
                "attempts": report.attempts,
                "last_attempt_at": report.last_attempt_at,
                "next_attempt_at": report.next_attempt_at,
                "last_failure": report.last_failure,
            });
            // v31: only when set (a v26 to v30 host refuses an unknown key).
            if let (Some(since), Value::Object(object)) = (report.failing_since, &mut value) {
                object.insert("failing_since".into(), json!(since));
            }
            // v32: likewise (a v26 to v31 host refuses it).
            if let (Some(check), Value::Object(object)) = (&report.check, &mut value) {
                object.insert("check".into(), json!(check));
            }
            json!({"schema": SCHEMA, "verb": "cert-status", "report": value})
        }
        Reply::Renew(report) => json!({
            "schema": SCHEMA,
            "verb": "renew",
            "report": {"outcome": report.outcome},
        }),
        Reply::IdentityGate(report) => json!({
            "schema": SCHEMA,
            "verb": "identity-gate",
            "report": {
                "peer": report.peer,
                "identity_rule": report.identity_rule,
                "proof_rule": report.proof_rule,
                "proof_probe": report.proof_probe,
            },
        }),
        Reply::FilterStatus(report) => {
            let mut value = json!({
                "attached": report.attached,
                "pid_match": report.pid_match,
                "mode": report.mode,
                "armed_token": report.armed_token,
                "relay_armed": report.relay_armed,
                "authority_armed": report.authority_armed,
                "udp_relay_allowed": report.udp_relay_allowed,
                "counters": report.counters.iter()
                    .map(|(name, value)| (name.clone(), json!(value)))
                    .collect::<Map<String, Value>>(),
            });
            if let (Some(observed), Value::Object(object)) = (&report.observability, &mut value) {
                object.insert("observability".into(), observability_value(observed));
            }
            json!({"schema": SCHEMA, "verb": "filter-status", "report": value})
        }
        Reply::Refused(code) => json!({"schema": SCHEMA, "refused": code}),
    }
}

/// v27: one ring entry of `filter-status` as JSON.
fn drop_entry_value(entry: &DropEntry) -> Map<String, Value> {
    let value = json!({
        "index": entry.index,
        "arm_seq": entry.arm_seq,
        "ms": entry.ms,
        "class": entry.class,
        "iface": entry.iface,
        "dir": entry.dir,
        "family": entry.family,
        "proto": entry.proto,
        "tcp": entry.tcp,
        "reason": entry.reason,
    });
    match value {
        Value::Object(object) => object,
        _ => Map::new(),
    }
}

/// v29: a `[class][kind]` table as `{class: {kind: n}}`.
fn kinds_value(rows: &[(String, [u64; 8])]) -> Value {
    Value::Object(
        rows.iter()
            .map(|(class, row)| {
                (
                    class.clone(),
                    Value::Object(
                        crate::leak_guard::OUT_KINDS
                            .iter()
                            .zip(row.iter())
                            .map(|(kind, n)| (kind.name().to_owned(), json!(n)))
                            .collect(),
                    ),
                )
            })
            .collect(),
    )
}

/// v27: the `observability` object of a `filter-status` report. v29: with
/// `outbound` when the report has it (a v28-shaped report encodes as
/// before).
fn observability_value(observed: &FilterObservability) -> Value {
    let mut value = json!({
        "arm_seq": observed.arm_seq,
        "disarms": observed.disarms,
        "armed_ms_total": observed.armed_ms_total,
        "armed_for_ms": observed.armed_for_ms,
        "open_while_applied": observed.open_while_applied,
        "applied_epochs": observed.applied_epochs,
        "primary_iface": observed.primary_iface,
        "drops": observed.drops.iter()
            .map(|(class, [inbound, outbound, any])| {
                (class.clone(), json!({"in": inbound, "out": outbound, "any": any}))
            })
            .collect::<Map<String, Value>>(),
        "ring": {
            "next": observed.ring_next,
            "skipped": observed.ring_skipped,
            "torn": observed.ring_torn,
            "entries": observed.recent_drops.iter().map(drop_entry_value).collect::<Vec<_>>(),
        },
    });
    if let (Some(outbound), Value::Object(object)) = (&observed.outbound, &mut value) {
        object.insert(
            "outbound".into(),
            json!({
                "mark_sport_first": outbound.mark_sport_first,
                "mark_sport_count": outbound.mark_sport_count,
                "kinds": kinds_value(&outbound.kinds),
                "marked": kinds_value(&outbound.marked),
                "ring": {
                    "next": outbound.ring_next,
                    "skipped": outbound.ring_skipped,
                    "torn": outbound.ring_torn,
                    "entries": outbound.recent.iter().map(|out| {
                        let mut entry = drop_entry_value(&out.entry);
                        entry.insert("marked".into(), json!(out.marked));
                        Value::Object(entry)
                    }).collect::<Vec<_>>(),
                },
            }),
        );
    }
    value
}

pub fn encode_reply(reply: &Reply) -> Result<Vec<u8>, &'static str> {
    let bytes = serde_json::to_vec(&report_value(reply)).map_err(|_| "reply_unencodable")?;
    if bytes.len() > MAX_REPLY_BYTES {
        return Err("reply_oversized");
    }
    Ok(bytes)
}

fn text(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|text| text.len() <= MAX_TEXT_BYTES)
        .map(str::to_owned)
}
fn optional_text(value: &Value) -> Option<Option<String>> {
    if value.is_null() {
        Some(None)
    } else {
        text(value).map(Some)
    }
}
fn errno(value: &Value) -> Option<i32> {
    value
        .as_i64()
        .and_then(|n| i32::try_from(n).ok())
        .filter(|n| *n >= 0)
}
fn token(value: &Value, allowed: &[&str]) -> Option<String> {
    value
        .as_str()
        .filter(|name| allowed.contains(name))
        .map(str::to_owned)
}

fn decode_ping(report: Value) -> Option<PingReport> {
    let r = exact_object(
        report,
        &[
            "euid",
            "sandboxed",
            "container_url",
            "container_realpath",
            "realpath_errno",
            "custody",
            "container_ancestors",
            "container_open",
            "loopback_listen",
            "session_phase",
            "identity_present",
        ],
    )?;
    let container_open = match &r["container_open"] {
        Value::Null => None,
        value => {
            let open = exact_object(
                value.clone(),
                &["errno", "getpath_errno", "path_matched", "admitted"],
            )?;
            let probe = ContainerOpenProbe {
                errno: errno(&open["errno"])?,
                getpath_errno: errno(&open["getpath_errno"])?,
                path_matched: open["path_matched"].as_bool()?,
                admitted: open["admitted"].as_bool()?,
            };
            // Admission is only ever judged on a matched anchor.
            if probe.admitted && !probe.path_matched {
                return None;
            }
            Some(probe)
        }
    };
    let ancestors = r["container_ancestors"].as_array()?;
    if ancestors.len() > MAX_CUSTODY_STEPS {
        return None;
    }
    let container_ancestors = ancestors
        .iter()
        .map(|step| {
            let step = exact_object(step.clone(), &["component", "lstat_errno", "policy_ok"])?;
            let step = AncestorStep {
                component: text(&step["component"])?,
                lstat_errno: errno(&step["lstat_errno"])?,
                policy_ok: step["policy_ok"].as_bool()?,
            };
            (!step.policy_ok || step.lstat_errno == 0).then_some(step)
        })
        .collect::<Option<Vec<_>>>()?;
    let custody = r["custody"].as_array()?;
    if custody.len() > MAX_CUSTODY_STEPS {
        return None;
    }
    let custody = custody
        .iter()
        .map(|step| {
            let step = exact_object(step.clone(), &["component", "errno"])?;
            Some(CustodyStep {
                component: text(&step["component"])?,
                errno: errno(&step["errno"])?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let listen = exact_object(r["loopback_listen"].clone(), &["stage", "errno"])?;
    Some(PingReport {
        euid: r["euid"].as_u64().and_then(|n| u32::try_from(n).ok())?,
        sandboxed: r["sandboxed"].as_bool()?,
        container_url: optional_text(&r["container_url"])?,
        container_realpath: optional_text(&r["container_realpath"])?,
        realpath_errno: errno(&r["realpath_errno"])?,
        custody,
        container_ancestors,
        container_open,
        loopback_listen: ListenProbe {
            stage: token(&listen["stage"], &LISTEN_STAGES)?,
            errno: errno(&listen["errno"])?,
        },
        session_phase: token(&r["session_phase"], &SESSION_PHASES)?,
        identity_present: r["identity_present"].as_bool()?,
    })
}

fn decode_status(report: Value) -> Option<StatusReport> {
    let r = exact_object(report, &["session_phase", "session_refusal"])?;
    let refusal = match &r["session_refusal"] {
        Value::Null => None,
        value => Some(value.as_str().filter(|code| stable_code(code))?.to_owned()),
    };
    Some(StatusReport {
        session_phase: token(&r["session_phase"], &SESSION_PHASES)?,
        session_refusal: refusal,
    })
}

/// Every committed path once, each within its member cap, with a digest.
fn decode_import(report: Value) -> Option<ImportReport> {
    let r = exact_object(report, &["files", "retired_removed"])?;
    let files = r["files"].as_array()?;
    if files.len() > IMPORT_MEMBERS.len() + 1 {
        return None;
    }
    let mut seen = std::collections::BTreeSet::new();
    let files = files
        .iter()
        .map(|file| {
            let file = exact_object(file.clone(), &["path", "length", "sha256"])?;
            let path = file["path"].as_str()?;
            let cap = committed_path_allowed(path)?;
            let length = file["length"].as_u64().filter(|n| *n <= cap as u64)?;
            let sha256 = file["sha256"].as_str().filter(|t| is_sha256_hex(t))?;
            seen.insert(path.to_owned()).then(|| CommittedFile {
                path: path.to_owned(),
                length,
                sha256: sha256.to_owned(),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(ImportReport {
        files,
        retired_removed: r["retired_removed"].as_bool()?,
    })
}

fn decode_forget(report: Value) -> Option<ForgetReport> {
    let r = exact_object(report, &["identity_was_present", "key_material_removed"])?;
    Some(ForgetReport {
        identity_was_present: r["identity_was_present"].as_bool()?,
        key_material_removed: r["key_material_removed"].as_bool()?,
    })
}

/// Exactly the four public terms, each in its one canonical spelling, and
/// together a full-wide policy (`ProfileTerms::policy`).
fn decode_profile_terms(report: Value) -> Option<ProfileTerms> {
    let r = exact_object(report, &["relay", "dns", "mtu", "profile_sha256"])?;
    let relay_text = r["relay"].as_str()?;
    let relay: SocketAddr = relay_text.parse().ok()?;
    if relay.to_string() != relay_text {
        return None;
    }
    // At most two servers: `ProfileTerms::policy` (`FullWide::new`) below.
    let dns = r["dns"]
        .as_array()?
        .iter()
        .map(|value| {
            let text = value.as_str()?;
            let ip: IpAddr = text.parse().ok()?;
            (ip.to_string() == text).then_some(ip)
        })
        .collect::<Option<Vec<_>>>()?;
    let terms = ProfileTerms {
        relay,
        dns,
        mtu: r["mtu"].as_u64().and_then(|n| u16::try_from(n).ok())?,
        profile_sha256: r["profile_sha256"].as_str()?.to_owned(),
    };
    terms.policy().ok()?;
    Some(terms)
}

fn optional_u64(value: &Value) -> Option<Option<u64>> {
    if value.is_null() {
        Some(None)
    } else {
        value.as_u64().map(Some)
    }
}

/// Exactly the eight cert-status keys (v31: or nine, with a numeric
/// `failing_since` beside a failure class; v32: plus a `check` from
/// `RENEWAL_CHECKS` beside `last_failure` `local_refused`, v32 review: or
/// beside any failure class in `pending`, `superseded` or `expired`), a known state
/// token and failure class, and a window whose ends are both present or
/// both absent.
fn decode_cert_status(report: Value) -> Option<CertStatusReport> {
    const KEYS: [&str; 8] = [
        "state",
        "not_before",
        "not_after",
        "renew_at",
        "attempts",
        "last_attempt_at",
        "next_attempt_at",
        "last_failure",
    ];
    let mut keys = KEYS.to_vec();
    for optional in ["failing_since", "check"] {
        if report.get(optional).is_some() {
            keys.push(optional);
        }
    }
    let r = exact_object(report, &keys)?;
    let failing_since = match r.get("failing_since") {
        Some(value) => Some(value.as_u64()?),
        None => None,
    };
    let check = match r.get("check") {
        Some(value) => Some(token(value, &RENEWAL_CHECKS)?),
        None => None,
    };
    let state = r["state"]
        .as_str()
        .filter(|state| cert_state_allowed(state))?;
    let last_failure = match &r["last_failure"] {
        Value::Null => None,
        value => Some(token(value, &FAILURE_CLASSES)?),
    };
    let report = CertStatusReport {
        state: state.to_owned(),
        not_before: optional_u64(&r["not_before"])?,
        not_after: optional_u64(&r["not_after"])?,
        renew_at: optional_u64(&r["renew_at"])?,
        attempts: r["attempts"].as_u64().and_then(|n| u32::try_from(n).ok())?,
        last_attempt_at: optional_u64(&r["last_attempt_at"])?,
        next_attempt_at: optional_u64(&r["next_attempt_at"])?,
        last_failure,
        failing_since,
        check,
    };
    if report.failing_since.is_some() && report.last_failure.is_none() {
        return None;
    }
    // v32 review: beside another class only while a request stays journaled.
    let journaled = matches!(report.state.as_str(), "pending" | "superseded" | "expired");
    if report.check.is_some()
        && !(report.last_failure.as_deref() == Some("local_refused")
            || (report.last_failure.is_some() && journaled))
    {
        return None;
    }
    let windowed = report.not_before.is_some();
    if windowed != report.not_after.is_some() || windowed != report.renew_at.is_some() {
        return None;
    }
    Some(report)
}

fn decode_identity_gate(report: Value) -> Option<IdentityGateReport> {
    let r = exact_object(
        report,
        &["peer", "identity_rule", "proof_rule", "proof_probe"],
    )?;
    Some(IdentityGateReport {
        peer: r["peer"]
            .as_str()
            .filter(|code| stable_code(code))?
            .to_owned(),
        identity_rule: token(&r["identity_rule"], &GATE_IDENTITY_RULES)?,
        proof_rule: token(&r["proof_rule"], &GATE_PROOF_RULES)?,
        proof_probe: token(&r["proof_probe"], &GATE_PROBES)?,
    })
}

fn decode_renew(report: Value) -> Option<RenewReport> {
    let r = exact_object(report, &["outcome"])?;
    Some(RenewReport {
        outcome: token(&r["outcome"], &RENEW_OUTCOMES)?,
    })
}

/// Exactly the filter-status keys, a known mode, a token only while
/// guarding, no endpoint while Open, and exactly the counted reasons. v27:
/// with or without exactly one more key, `observability`.
fn decode_filter_status(report: Value) -> Option<FilterStatusReport> {
    const KEYS: [&str; 8] = [
        "attached",
        "pid_match",
        "mode",
        "armed_token",
        "relay_armed",
        "authority_armed",
        "udp_relay_allowed",
        "counters",
    ];
    let observed = report.get("observability").is_some();
    let mut r = if observed {
        let mut keys = KEYS.to_vec();
        keys.push("observability");
        exact_object(report, &keys)?
    } else {
        exact_object(report, &KEYS)?
    };
    let observability = match r.remove("observability") {
        Some(value) => Some(decode_observability(value)?),
        None => None,
    };
    let mode = token(&r["mode"], &FILTER_MODES)?;
    let armed_token = optional_u64(&r["armed_token"])?;
    let guarding = mode == "guarding";
    let relay_armed = r["relay_armed"].as_bool()?;
    let authority_armed = r["authority_armed"].as_bool()?;
    let udp_relay_allowed = r["udp_relay_allowed"].as_bool()?;
    if guarding != armed_token.is_some()
        || (!guarding && (relay_armed || authority_armed || udp_relay_allowed))
    {
        return None;
    }
    let attached = r["attached"].as_bool()?;
    let pid_match = r["pid_match"].as_bool()?;
    if pid_match && !attached {
        return None;
    }
    let Value::Object(counters) = &r["counters"] else {
        return None;
    };
    if counters.len() != crate::leak_guard::COUNTED.len() {
        return None;
    }
    let counters = crate::leak_guard::COUNTED
        .iter()
        .map(|reason| {
            let name = reason.name();
            Some((name.to_owned(), counters.get(name)?.as_u64()?))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(FilterStatusReport {
        attached,
        pid_match,
        mode,
        armed_token,
        relay_armed,
        authority_armed,
        udp_relay_allowed,
        counters,
        observability,
    })
}

/// v27: one ring entry with exactly `keys` (`DROP_ENTRY_KEYS`, v29: and
/// `marked` in the outbound ring) and only known tokens.
fn decode_drop_entry(entry: &Value, keys: &[&str]) -> Option<(DropEntry, Map<String, Value>)> {
    use crate::leak_guard::{iface_token_valid, DROP_CLASSES, TCP_CLASSES};
    let e = exact_object(entry.clone(), keys)?;
    let classes: Vec<&str> = DROP_CLASSES.iter().map(|class| class.name()).collect();
    let tcp: Vec<&str> = TCP_CLASSES.iter().map(|class| class.name()).collect();
    let reasons: Vec<&str> = crate::leak_guard::COUNTED
        .iter()
        .map(|reason| reason.name())
        .filter(|name| name.starts_with("drop_"))
        .collect();
    let iface = e["iface"].as_str().filter(|text| iface_token_valid(text))?;
    let decoded = DropEntry {
        index: e["index"].as_u64()?,
        arm_seq: e["arm_seq"].as_u64()?,
        ms: e["ms"].as_u64()?,
        class: token(&e["class"], &classes)?,
        iface: iface.to_owned(),
        dir: token(&e["dir"], &["in", "out", "any"])?,
        family: token(&e["family"], &DROP_FAMILIES)?,
        proto: u8::try_from(e["proto"].as_u64()?).ok()?,
        tcp: token(&e["tcp"], &tcp)?,
        reason: token(&e["reason"], &reasons)?,
    };
    Some((decoded, e))
}

/// v27: a ring object with exactly `next`, `skipped`, `torn` and at most
/// `RING_SLOTS` entries in increasing index order; `(next, skipped, torn,
/// entries)`.
fn decode_ring(value: &Value) -> Option<(u64, u64, u64, Vec<Value>)> {
    let ring = exact_object(value.clone(), &RING_KEYS)?;
    let Value::Array(entries) = &ring["entries"] else {
        return None;
    };
    if entries.len() > crate::leak_guard::RING_SLOTS {
        return None;
    }
    Some((
        ring["next"].as_u64()?,
        ring["skipped"].as_u64()?,
        ring["torn"].as_u64()?,
        entries.clone(),
    ))
}

/// Whether ring indices increase strictly.
fn increasing(indices: impl Iterator<Item = u64>) -> bool {
    let mut last = None;
    for index in indices {
        if last.is_some_and(|last| last >= index) {
            return false;
        }
        last = Some(index);
    }
    true
}

/// v29: a `{class: {kind: n}}` table with exactly every class and kind.
fn decode_kinds(value: &Value) -> Option<Vec<(String, [u64; 8])>> {
    use crate::leak_guard::{DROP_CLASSES, OUT_KINDS};
    let Value::Object(table) = value else {
        return None;
    };
    if table.len() != DROP_CLASSES.len() {
        return None;
    }
    let names: Vec<&str> = OUT_KINDS.iter().map(|kind| kind.name()).collect();
    DROP_CLASSES
        .iter()
        .map(|class| {
            let row = exact_object(table.get(class.name())?.clone(), &names)?;
            let mut counts = [0u64; 8];
            for (count, name) in counts.iter_mut().zip(names.iter()) {
                *count = row[*name].as_u64()?;
            }
            Some((class.name().to_owned(), counts))
        })
        .collect()
}

/// v29: exactly the outbound keys, both tables complete, and a ring of
/// outbound records only (`dir` `out`), each with a boolean `marked`.
fn decode_outbound(value: Value) -> Option<OutboundObservability> {
    let o = exact_object(value, &OUTBOUND_KEYS)?;
    let (ring_next, ring_skipped, ring_torn, entries) = decode_ring(&o["ring"])?;
    let mut keys = DROP_ENTRY_KEYS.to_vec();
    keys.push("marked");
    let recent = entries
        .iter()
        .map(|entry| {
            let (entry, raw) = decode_drop_entry(entry, &keys)?;
            (entry.dir == "out").then_some(())?;
            Some(OutDropEntry {
                entry,
                marked: raw["marked"].as_bool()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    if !increasing(recent.iter().map(|out| out.entry.index)) {
        return None;
    }
    Some(OutboundObservability {
        mark_sport_first: u16::try_from(o["mark_sport_first"].as_u64()?).ok()?,
        mark_sport_count: u16::try_from(o["mark_sport_count"].as_u64()?).ok()?,
        kinds: decode_kinds(&o["kinds"])?,
        marked: decode_kinds(&o["marked"])?,
        ring_next,
        ring_skipped,
        ring_torn,
        recent,
    })
}

/// v27: exactly the observability keys, every drop class with exactly
/// `in`, `out` and `any`, at most `RING_SLOTS` ring entries in increasing
/// index order, and only known tokens: nothing in it can carry an address.
/// v29: with or without exactly one more key, `outbound`.
fn decode_observability(value: Value) -> Option<FilterObservability> {
    use crate::leak_guard::{iface_token_valid, DROP_CLASSES};
    let with_outbound = value.get("outbound").is_some();
    let mut o = if with_outbound {
        let mut keys = OBSERVABILITY_KEYS.to_vec();
        keys.push("outbound");
        exact_object(value, &keys)?
    } else {
        exact_object(value, &OBSERVABILITY_KEYS)?
    };
    let outbound = match o.remove("outbound") {
        Some(value) => Some(Box::new(decode_outbound(value)?)),
        None => None,
    };
    let primary_iface = match &o["primary_iface"] {
        Value::Null => None,
        Value::String(text) if text != "none" && iface_token_valid(text) => Some(text.clone()),
        _ => return None,
    };
    let Value::Object(drops) = &o["drops"] else {
        return None;
    };
    if drops.len() != DROP_CLASSES.len() {
        return None;
    }
    let drops = DROP_CLASSES
        .iter()
        .map(|class| {
            let row = exact_object(drops.get(class.name())?.clone(), &["in", "out", "any"])?;
            Some((
                class.name().to_owned(),
                [
                    row["in"].as_u64()?,
                    row["out"].as_u64()?,
                    row["any"].as_u64()?,
                ],
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    let (ring_next, ring_skipped, ring_torn, entries) = decode_ring(&o["ring"])?;
    let recent_drops = entries
        .iter()
        .map(|entry| decode_drop_entry(entry, &DROP_ENTRY_KEYS).map(|(entry, _)| entry))
        .collect::<Option<Vec<_>>>()?;
    if !increasing(recent_drops.iter().map(|entry| entry.index)) {
        return None;
    }
    Some(FilterObservability {
        arm_seq: o["arm_seq"].as_u64()?,
        disarms: o["disarms"].as_u64()?,
        armed_ms_total: o["armed_ms_total"].as_u64()?,
        armed_for_ms: optional_u64(&o["armed_for_ms"])?,
        open_while_applied: o["open_while_applied"].as_u64()?,
        applied_epochs: o["applied_epochs"].as_u64()?,
        primary_iface,
        drops,
        ring_next,
        ring_skipped,
        ring_torn,
        recent_drops,
        outbound,
    })
}

/// v27: the `filter-status` entry of one ring record.
fn drop_entry_of(index: u64, record: &crate::leak_guard::DropRecord) -> DropEntry {
    DropEntry {
        index,
        arm_seq: u64::from(record.arm_seq),
        ms: u64::from(record.ms),
        class: record.class.name().to_owned(),
        iface: crate::leak_guard::iface_token(record.iface),
        dir: record.direction.name().to_owned(),
        family: match record.family {
            4 => "v4",
            6 => "v6",
            _ => "none",
        }
        .to_owned(),
        proto: record.protocol,
        tcp: record.tcp.name().to_owned(),
        reason: record.reason.name().to_owned(),
    }
}

/// v29: the outbound observability of this process's counters.
pub(crate) fn outbound_of(counters: &crate::leak_guard::Counters) -> OutboundObservability {
    use crate::leak_guard::{DROP_CLASSES, MARK_SPORT_COUNT, MARK_SPORT_FIRST};
    let (kinds, marked) = counters.out_snapshot();
    let rows = |table: crate::leak_guard::OutCounts| {
        DROP_CLASSES
            .iter()
            .zip(table)
            .map(|(class, row)| (class.name().to_owned(), row))
            .collect()
    };
    let ring = counters.out_ring().snapshot_marked();
    OutboundObservability {
        mark_sport_first: MARK_SPORT_FIRST,
        mark_sport_count: MARK_SPORT_COUNT,
        kinds: rows(kinds),
        marked: rows(marked),
        ring_next: ring.next,
        ring_skipped: ring.skipped,
        ring_torn: ring.torn,
        recent: ring
            .entries
            .iter()
            .map(|(index, record, marked)| OutDropEntry {
                entry: drop_entry_of(*index, record),
                marked: *marked,
            })
            .collect(),
    }
}

/// v27: the observability of this process's gate and counters (v29: with
/// its outbound part).
pub(crate) fn observability_of(
    gate: &crate::leak_guard::Gate,
    counters: &crate::leak_guard::Counters,
) -> FilterObservability {
    use crate::leak_guard::{iface_token, DROP_CLASSES};
    let stats = gate.arm_stats();
    let ring = counters.ring().snapshot();
    FilterObservability {
        arm_seq: stats.arm_seq,
        disarms: stats.disarms,
        armed_ms_total: stats.armed_ms_total,
        armed_for_ms: stats.armed_for_ms,
        open_while_applied: stats.open_while_applied,
        applied_epochs: stats.applied_epochs,
        primary_iface: (stats.primary != 0).then(|| iface_token(stats.primary)),
        drops: DROP_CLASSES
            .iter()
            .zip(counters.drop_snapshot())
            .map(|(class, row)| (class.name().to_owned(), row))
            .collect(),
        ring_next: ring.next,
        ring_skipped: ring.skipped,
        ring_torn: ring.torn,
        recent_drops: ring
            .entries
            .iter()
            .map(|(index, record)| drop_entry_of(*index, record))
            .collect(),
        outbound: Some(Box::new(outbound_of(counters))),
    }
}

/// The filter-status report of this process's gate, counters and filter.
pub(crate) fn filter_status_of(
    gate: &crate::leak_guard::Gate,
    counters: &crate::leak_guard::Counters,
    attachment: &crate::leak_guard::Attachment,
    pid: i32,
) -> FilterStatusReport {
    use crate::leak_guard::{Mode, COUNTED};
    let (snapshot, _) = gate.snapshot();
    let guarding = snapshot.mode == Mode::Guarding;
    let attached = attachment.attached();
    FilterStatusReport {
        attached,
        pid_match: attached && attachment.pid() == pid,
        mode: if guarding { "guarding" } else { "open" }.into(),
        armed_token: guarding.then_some(snapshot.token),
        relay_armed: guarding && !snapshot.relays.is_empty(),
        // v31: the gate holds no authority any more; kept on the wire.
        authority_armed: false,
        udp_relay_allowed: guarding && snapshot.udp_relay,
        counters: COUNTED
            .iter()
            .zip(counters.snapshot())
            .map(|(reason, value)| (reason.name().to_owned(), value))
            .collect(),
        observability: Some(observability_of(gate, counters)),
    }
}

/// Decode one reply to `expected`. A refusal frame decodes to `Refused`;
/// a reply for another verb, an unknown key or an oversized frame does not.
pub fn decode_reply(bytes: &[u8], expected: Verb) -> Result<Reply, &'static str> {
    if bytes.len() > MAX_REPLY_BYTES {
        return Err("reply_oversized");
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "reply_malformed")?;
    if value.get("refused").is_some() {
        let object = exact_object(value, &["schema", "refused"]).ok_or("reply_malformed")?;
        if object["schema"].as_str() != Some(SCHEMA) {
            return Err("schema_mismatch");
        }
        let code = object["refused"]
            .as_str()
            .filter(|code| stable_code(code))
            .ok_or("reply_malformed")?;
        return Ok(Reply::Refused(code.into()));
    }
    let mut object = exact_object(value, &["schema", "verb", "report"]).ok_or("reply_malformed")?;
    if object["schema"].as_str() != Some(SCHEMA) {
        return Err("schema_mismatch");
    }
    if object["verb"].as_str() != Some(expected.name()) {
        return Err("reply_verb_mismatch");
    }
    let report = object.remove("report").ok_or("reply_malformed")?;
    match expected {
        Verb::Ping => decode_ping(report).map(Reply::Ping),
        Verb::Status => decode_status(report).map(Reply::Status),
        Verb::Import => decode_import(report).map(Reply::Import),
        Verb::ForgetIdentity => decode_forget(report).map(Reply::Forget),
        Verb::ProfileTerms => decode_profile_terms(report).map(Reply::ProfileTerms),
        Verb::CertStatus => decode_cert_status(report).map(Reply::CertStatus),
        Verb::Renew => decode_renew(report).map(Reply::Renew),
        Verb::FilterStatus => decode_filter_status(report).map(Reply::FilterStatus),
        Verb::IdentityGate => decode_identity_gate(report).map(Reply::IdentityGate),
    }
    .ok_or("reply_malformed")
}

// ---------------------------------------------------------------------------
// Provider responder and its native observations.

pub(crate) trait Observer {
    fn ping(&self) -> PingReport;
    fn status(&self) -> StatusReport;
    /// The identity verbs' peer check (console user, admin). Refuses unless
    /// an observer implements it.
    fn authorize(&self, _peer_euid: u32) -> Result<(), &'static str> {
        Err("identity_verbs_unavailable")
    }
    /// The identity verbs' proof of administrator presence: the request's
    /// external form (`None` when absent), admitted at most once.
    fn admit_authorization(&self, _form: Option<&[u8]>) -> Result<(), &'static str> {
        Err("identity_verbs_unavailable")
    }
    fn import(&self, _payload: &ImportPayload) -> Result<ImportReport, &'static str> {
        Err("identity_verbs_unavailable")
    }
    fn forget(&self) -> Result<ForgetReport, &'static str> {
        Err("identity_verbs_unavailable")
    }
    /// Public terms of the held tree. Needs no identity-verb authorization.
    fn profile_terms(&self) -> Result<ProfileTerms, &'static str> {
        Err("profile_terms_unavailable")
    }
    /// S23: the epoch's renewal state. Read-only, no authorization.
    fn cert_status(&self) -> Result<CertStatusReport, &'static str> {
        Err("cert_status_unavailable")
    }
    /// S23: force the due renewal. Authorized like the identity verbs.
    fn renew(&self) -> Result<RenewReport, &'static str> {
        Err("renew_unavailable")
    }
    /// S20b: the packet filter's state. Read-only, no authorization.
    fn filter_status(&self) -> Result<FilterStatusReport, &'static str> {
        Err("filter_status_unavailable")
    }
    /// v30: the identity verbs' checks for a peer whose own check gave
    /// `peer`, read-only.
    fn identity_gate(
        &self,
        _peer: Result<(), &'static str>,
    ) -> Result<IdentityGateReport, &'static str> {
        Err("identity_gate_unavailable")
    }
}

/// A reply frame within the bound; an unencodable reply becomes a refusal.
fn bounded(reply: &Reply) -> Vec<u8> {
    encode_reply(reply).unwrap_or_else(|code| {
        encode_reply(&Reply::Refused(code.into())).unwrap_or_else(|_| b"{}".to_vec())
    })
}

/// The reply to `verb`. An identity verb is authorized for `peer_euid`,
/// then its administrator approval (`authorization`) is admitted, before
/// its payload is read or anything changes; with no message, no peer or no
/// approval it is refused.
fn answer(
    verb: Verb,
    message: Option<XpcObject>,
    peer_euid: Option<u32>,
    authorization: Option<&[u8]>,
    observer: &impl Observer,
) -> Reply {
    let authorized = || {
        peer_euid
            .ok_or("peer_unidentified")
            .and_then(|euid| observer.authorize(euid))
            .and_then(|()| observer.admit_authorization(authorization))
    };
    let result = match verb {
        Verb::Ping => Ok(Reply::Ping(observer.ping())),
        Verb::Status => Ok(Reply::Status(observer.status())),
        Verb::ForgetIdentity => authorized().and_then(|()| observer.forget().map(Reply::Forget)),
        Verb::Import => authorized()
            .and_then(|()| read_import_payload(message.ok_or("import_payload_missing")?))
            .and_then(|payload| observer.import(&payload).map(Reply::Import)),
        Verb::CertStatus => observer.cert_status().map(Reply::CertStatus),
        Verb::FilterStatus => observer.filter_status().map(Reply::FilterStatus),
        Verb::Renew => authorized().and_then(|()| observer.renew().map(Reply::Renew)),
        Verb::IdentityGate => observer
            .identity_gate(
                peer_euid
                    .ok_or("peer_unidentified")
                    .and_then(|euid| observer.authorize(euid)),
            )
            .map(Reply::IdentityGate),
        // A code a host could not decode becomes one opaque refusal.
        Verb::ProfileTerms => observer
            .profile_terms()
            .map(Reply::ProfileTerms)
            .map_err(|code| {
                if stable_code(code) {
                    code
                } else {
                    profile_terms::TERMS_REFUSED
                }
            }),
    };
    result.unwrap_or_else(|code| Reply::Refused(code.into()))
}

/// One reply frame for one request frame, with no envelope or peer: the
/// identity verbs are refused. Refusals are replies, so the host sees a
/// stable code; the reply itself is bounded like any other.
#[cfg(test)]
pub(crate) fn respond(request: Result<Vec<u8>, &'static str>, observer: &impl Observer) -> Vec<u8> {
    bounded(&match request.and_then(|bytes| decode_request(&bytes)) {
        Ok(verb) => answer(verb, None, None, None, observer),
        Err(code) => Reply::Refused(code.into()),
    })
}

/// Test seam (S15): the provider's real envelope parser and responder over
/// the libxpc dictionary built from exactly the entries a host sends.
#[cfg(test)]
pub(crate) fn respond_entries(
    entries: &[(&CStr, &[u8])],
    peer_euid: Option<u32>,
    observer: &impl Observer,
) -> Vec<u8> {
    let message = framed_entries(entries).expect("xpc dictionary");
    respond_message(message.as_ptr(), peer_euid, observer)
}

/// The `identity-approval` data value, copied only up to one byte past a
/// form (a longer value stays malformed without being copied). Absent, or
/// not data, is `None`.
fn read_authorization(message: XpcObject) -> Option<Zeroizing<Vec<u8>>> {
    let (bytes, length) = data_value(message, AUTHORIZATION_KEY)?;
    Some(zeroizing_copy(bytes, length.min(EXTERNAL_FORM_LENGTH + 1)))
}

/// v30: the identity verbs' host floor, before any other check. A message
/// with a key an earlier host sent its form under (v26 to v29) comes from a
/// host whose approval this provider cannot check: refused as
/// `identity_authorization_host_outdated` (with the current key as well, as
/// a shape). Signed, hardened host code cannot be made to send another key.
fn approval_floor(message: XpcObject) -> Result<(), &'static str> {
    let legacy = LEGACY_AUTHORIZATION_KEYS
        .iter()
        .any(|key| !unsafe { xpc_dictionary_get_value(message, key.as_ptr()) }.is_null());
    let current =
        !unsafe { xpc_dictionary_get_value(message, AUTHORIZATION_KEY.as_ptr()) }.is_null();
    match (legacy, current) {
        (false, _) => Ok(()),
        (true, false) => Err("identity_authorization_host_outdated"),
        (true, true) => Err("envelope_shape"),
    }
}

/// One reply frame for one request dictionary from `peer_euid`. Only the
/// identity verbs may carry `identity-approval`, and only `import` a
/// payload beyond it.
pub(crate) fn respond_message(
    message: XpcObject,
    peer_euid: Option<u32>,
    observer: &impl Observer,
) -> Vec<u8> {
    let count = unsafe { xpc_dictionary_get_count(message) };
    let reply = match read_request_frame(message, MAX_REQUEST_BYTES)
        .and_then(|bytes| decode_request(&bytes))
    {
        Ok(verb) if verb.requires_authorization() => match approval_floor(message) {
            Err(code) => Reply::Refused(code.into()),
            Ok(()) => {
                let authorization = read_authorization(message);
                let form = authorization.as_deref().map(Vec::as_slice);
                if verb == Verb::Import {
                    answer(verb, Some(message), peer_euid, form, observer)
                } else if count == 1 + usize::from(form.is_some()) {
                    answer(verb, None, peer_euid, form, observer)
                } else {
                    Reply::Refused("envelope_shape".into())
                }
            }
        },
        Ok(verb) if count == 1 => answer(verb, None, peer_euid, None, observer),
        Ok(_) => Reply::Refused("envelope_shape".into()),
        Err(code) => Reply::Refused(code.into()),
    };
    bounded(&reply)
}

/// The newest start attempt, as `status`/`ping` report it.
#[derive(Clone)]
enum Observed {
    /// A session exists or existed: its phase record, held after it ends.
    Session(SessionPhaseReader),
    /// The start was refused before any session was constructed.
    StartRefused(&'static str),
}

static OBSERVED: Mutex<Option<Observed>> = Mutex::new(None);

fn observe(observed: Observed) {
    *OBSERVED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(observed);
}

/// Record the newest session for `status`/`ping`. The reader holds only that
/// session's phase record, never the session, its bridge or its Store claim,
/// so its last phase and first refusal stay observable after it is joined.
pub(crate) fn publish_session(reader: SessionPhaseReader) {
    observe(Observed::Session(reader));
}

/// Record a start refused before any session existed (custody, protocol,
/// factory). It replaces the previous session's record: that session is gone.
pub(crate) fn publish_start_refusal(code: &'static str) {
    observe(Observed::StartRefused(code));
}

fn session_observation() -> (Option<SessionPhase>, Option<&'static str>) {
    let observed = OBSERVED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    match observed {
        None => (None, None),
        Some(Observed::StartRefused(code)) => (None, Some(code)),
        Some(Observed::Session(reader)) => {
            let (phase, refusal) = reader.snapshot();
            (Some(phase), refusal)
        }
    }
}

const DIRECTORY_FLAGS: c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Open `/`, every component of `realpath`, then `tail`, one at a time with
/// O_DIRECTORY|O_NOFOLLOW, and record each errno. Stops at the first failure;
/// returns the last directory only when every step opened.
pub(crate) fn custody_walk(realpath: &Path, tail: &[&str]) -> (Vec<CustodyStep>, Option<File>) {
    let mut steps = Vec::new();
    let root = unsafe { libc::open(c"/".as_ptr(), DIRECTORY_FLAGS) };
    if root < 0 {
        steps.push(CustodyStep {
            component: "/".into(),
            errno: last_errno(),
        });
        return (steps, None);
    }
    let mut parent = unsafe { File::from_raw_fd(root) };
    steps.push(CustodyStep {
        component: "/".into(),
        errno: 0,
    });
    let mut names = Vec::new();
    for part in realpath.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => names.push(name.as_encoded_bytes().to_vec()),
            _ => {
                steps.push(CustodyStep {
                    component: "non_canonical".into(),
                    errno: libc::EINVAL,
                });
                return (steps, None);
            }
        }
    }
    names.extend(tail.iter().map(|name| name.as_bytes().to_vec()));
    for name in names {
        let component = String::from_utf8_lossy(&name).into_owned();
        // The marker itself is the last of at most MAX_CUSTODY_STEPS steps,
        // the bound the decoder enforces.
        if steps.len() + 1 >= MAX_CUSTODY_STEPS {
            steps.push(CustodyStep {
                component: "too_deep".into(),
                errno: libc::ENAMETOOLONG,
            });
            return (steps, None);
        }
        let Ok(cname) = std::ffi::CString::new(name) else {
            steps.push(CustodyStep {
                component,
                errno: libc::EINVAL,
            });
            return (steps, None);
        };
        let raw = unsafe { libc::openat(parent.as_raw_fd(), cname.as_ptr(), DIRECTORY_FLAGS) };
        if raw < 0 {
            steps.push(CustodyStep {
                component,
                errno: last_errno(),
            });
            return (steps, None);
        }
        parent = unsafe { File::from_raw_fd(raw) };
        steps.push(CustodyStep {
            component,
            errno: 0,
        });
    }
    (steps, Some(parent))
}

/// Capture's ancestor precondition (`container_ancestor_checks`), one step
/// per directory above `canonical`, `/` first, bounded like the custody walk.
pub(crate) fn container_ancestor_probe(canonical: &Path, uid: u32) -> Vec<AncestorStep> {
    let checks = container_ancestor_checks(canonical, uid);
    // Past the decoder's bound the last slot is the `too_deep` marker.
    let fits = checks.len() <= MAX_CUSTODY_STEPS;
    let mut steps: Vec<_> = checks
        .iter()
        .take(if fits {
            checks.len()
        } else {
            MAX_CUSTODY_STEPS - 1
        })
        .map(|(ancestor, outcome)| AncestorStep {
            component: ancestor
                .file_name()
                .map_or_else(|| "/".into(), |name| name.to_string_lossy().into_owned()),
            lstat_errno: match outcome {
                Err(AncestorFailure::Lstat(errno)) => *errno,
                _ => 0,
            },
            policy_ok: outcome.is_ok(),
        })
        .collect();
    if !fits {
        steps.push(AncestorStep {
            component: "too_deep".into(),
            lstat_errno: libc::ENAMETOOLONG,
            policy_ok: false,
        });
    }
    steps
}

/// Open the canonical container the way capture anchors it and report the
/// open errno, whether F_GETPATH matched and whether capture's owner/mode
/// admission (for `uid`) accepts it. The descriptor is returned only when it
/// matched; it is a diagnostic, never a capture or Store claim.
pub(crate) fn container_open_probe(
    canonical: &Path,
    uid: u32,
) -> (ContainerOpenProbe, Option<File>) {
    let probe = |errno, getpath_errno, path_matched, admitted| ContainerOpenProbe {
        errno,
        getpath_errno,
        path_matched,
        admitted,
    };
    match open_container_anchor(canonical) {
        Ok(file) => (
            probe(0, 0, true, container_admitted(&file, uid)),
            Some(file),
        ),
        Err(ContainerAnchorFailure::Open(errno)) => (probe(errno, 0, false, false), None),
        Err(ContainerAnchorFailure::GetPath(errno)) => (probe(0, errno, false, false), None),
        Err(ContainerAnchorFailure::Mismatch) => (probe(0, 0, false, false), None),
    }
}

/// `names`, one directory at a time below `parent`, O_DIRECTORY|O_NOFOLLOW.
fn open_below(parent: &File, names: &[&CStr]) -> Option<File> {
    let mut current = parent.try_clone().ok()?;
    for name in names {
        let raw = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), DIRECTORY_FLAGS) };
        if raw < 0 {
            return None;
        }
        current = unsafe { File::from_raw_fd(raw) };
    }
    Some(current)
}

/// `identity.json` exists in `identity` as a regular file, not via a link.
/// Presence only: the file is never opened or read.
pub(crate) fn identity_present(identity: &File) -> bool {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let found = unsafe {
        libc::fstatat(
            identity.as_raw_fd(),
            c"identity.json".as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0;
    found && unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFREG
}

/// Bind and listen on 127.0.0.1, ephemeral port, then close.
pub(crate) fn loopback_listen_probe() -> ListenProbe {
    let failed = |stage: &str| ListenProbe {
        stage: stage.into(),
        errno: last_errno(),
    };
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if raw < 0 {
        return failed("socket");
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let address = libc::sockaddr_in {
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
        },
        sin_zero: [0; 8],
    };
    if unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    } != 0
    {
        return failed("bind");
    }
    if unsafe { libc::listen(socket.as_raw_fd(), 1) } != 0 {
        return failed("listen");
    }
    ListenProbe {
        stage: "ok".into(),
        errno: 0,
    }
}

pub(crate) fn sandboxed() -> bool {
    unsafe { sandbox_check(libc::getpid(), std::ptr::null(), 0) != 0 }
}

/// Raw container URL and its path, from NSFileManager, for the provider group.
fn container_url() -> Option<(String, String)> {
    use objc2::{class, msg_send, rc::Retained, runtime::AnyObject};
    use objc2_foundation::NSString;
    let identifier = NSString::from_str(PROVIDER_APP_GROUP);
    let manager: Retained<AnyObject> = unsafe { msg_send![class!(NSFileManager), defaultManager] };
    let url: Option<Retained<AnyObject>> = unsafe {
        msg_send![&*manager, containerURLForSecurityApplicationGroupIdentifier: &*identifier]
    };
    let url = url?;
    let raw: Option<Retained<NSString>> = unsafe { msg_send![&*url, absoluteString] };
    let path: Option<Retained<NSString>> = unsafe { msg_send![&*url, path] };
    Some((raw?.to_string(), path?.to_string()))
}

/// Ping fields after the container lookup. Separate from NSFileManager so
/// lib tests can drive it with a temporary directory.
pub(crate) fn ping_from_container(
    container: Option<(String, String)>,
    phase: Option<SessionPhase>,
) -> PingReport {
    let mut report = PingReport {
        euid: unsafe { libc::geteuid() },
        sandboxed: sandboxed(),
        container_url: None,
        container_realpath: None,
        realpath_errno: 0,
        custody: Vec::new(),
        container_ancestors: Vec::new(),
        container_open: None,
        loopback_listen: loopback_listen_probe(),
        session_phase: phase_name(phase).into(),
        identity_present: false,
    };
    let Some((url, path)) = container else {
        return report;
    };
    report.container_url = Some(url);
    match std::fs::canonicalize(&path) {
        Ok(resolved) => {
            let (custody, _) = custody_walk(&resolved, &["Aegis", "identity"]);
            report.custody = custody;
            report.container_ancestors = container_ancestor_probe(&resolved, report.euid);
            let (open, anchor) = container_open_probe(&resolved, report.euid);
            report.container_open = Some(open);
            report.identity_present = anchor
                .and_then(|container| open_below(&container, &[c"Aegis", c"identity"]))
                .is_some_and(|identity| identity_present(&identity));
            report.container_realpath = Some(resolved.to_string_lossy().into_owned());
        }
        Err(error) => report.realpath_errno = error.raw_os_error().unwrap_or(libc::EIO),
    }
    report
}

struct NativeObserver;
impl Observer for NativeObserver {
    fn ping(&self) -> PingReport {
        let container = objc2::rc::autoreleasepool(|_| container_url());
        ping_from_container(container, session_observation().0)
    }
    fn status(&self) -> StatusReport {
        let (phase, refusal) = session_observation();
        StatusReport {
            session_phase: phase_name(phase).into(),
            session_refusal: refusal.filter(|code| stable_code(code)).map(str::to_owned),
        }
    }
    fn authorize(&self, peer_euid: u32) -> Result<(), &'static str> {
        identity_import::authorize_identity_peer(peer_euid, &identity_import::NativePrincipals)
    }
    fn admit_authorization(&self, form: Option<&[u8]>) -> Result<(), &'static str> {
        identity_authorization::PROVIDER_AUTHORIZATIONS
            .admit(form, &identity_authorization::native_verifier())
    }
    fn import(&self, payload: &ImportPayload) -> Result<ImportReport, &'static str> {
        identity_import::provider_import(payload)
    }
    fn forget(&self) -> Result<ForgetReport, &'static str> {
        identity_import::provider_forget()
    }
    fn profile_terms(&self) -> Result<ProfileTerms, &'static str> {
        profile_terms::provider_terms(|| {
            crate::app_group::CapturedAppGroupInputs::capture_terms_claim(PROVIDER_APP_GROUP)
        })
    }
    fn cert_status(&self) -> Result<CertStatusReport, &'static str> {
        crate::identity_renewal::cert_status()
    }
    fn renew(&self) -> Result<RenewReport, &'static str> {
        crate::identity_renewal::request_renewal().map(|outcome| RenewReport {
            outcome: outcome.into(),
        })
    }
    fn filter_status(&self) -> Result<FilterStatusReport, &'static str> {
        use crate::leak_guard::{ATTACHMENT, COUNTERS, LEAK_GUARD};
        Ok(filter_status_of(
            &LEAK_GUARD,
            &COUNTERS,
            &ATTACHMENT,
            std::process::id() as i32,
        ))
    }
    fn identity_gate(
        &self,
        peer: Result<(), &'static str>,
    ) -> Result<IdentityGateReport, &'static str> {
        Ok(IdentityGateReport {
            peer: peer.err().unwrap_or("admitted").into(),
            identity_rule: identity_authorization::identity_rule_state(
                identity_authorization::read_right,
            )
            .into(),
            proof_rule: identity_authorization::proof_rule_state(
                identity_authorization::read_right,
            )
            .into(),
            proof_probe: identity_authorization::proof_probe().token().into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Connection admission: one ordering for both sides, driven through a trait
// so the requirement-before-resume order is a tested property.

pub(crate) trait Endpoint {
    /// `xpc_connection_set_peer_code_signing_requirement`; 0 on success.
    fn require_peer(&self, requirement: &CStr) -> c_int;
    /// Install the message handler (`serve`) or an inert one.
    fn set_handler(&self, serve: bool);
    fn resume(&self);
    fn cancel(&self);
}

pub(crate) trait ClientEndpoint: Endpoint {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, &'static str>;
    /// One dictionary of several data values (an import) and its reply.
    fn exchange_entries(&self, entries: &[(&CStr, &[u8])]) -> Result<Vec<u8>, &'static str>;
}

/// A connection that could not pin its peer requirement is never served:
/// it gets an inert handler and is cancelled before libxpc may resume it.
fn refuse(endpoint: &impl Endpoint) -> &'static str {
    endpoint.set_handler(false);
    endpoint.cancel();
    endpoint.resume();
    "peer_requirement_not_set"
}

/// Provider side: pin the host requirement, then serve. libxpc enforces it
/// for every message on this connection, so it covers every verb.
pub(crate) fn admit_peer(peer: &impl Endpoint) -> Result<(), &'static str> {
    admit_peer_with(peer, HOST_PEER_REQUIREMENT)
}

/// `admit_peer` for `requirement` (tests pin others on an anonymous
/// listener: the test binary's own and wrong-team/identifier variants).
fn admit_peer_with(peer: &impl Endpoint, requirement: &CStr) -> Result<(), &'static str> {
    if peer.require_peer(requirement) != 0 {
        return Err(refuse(peer));
    }
    peer.set_handler(true);
    peer.resume();
    Ok(())
}

/// Host side: pin the provider requirement before resume, exchange one
/// bounded frame, decode it for `verb`, then cancel.
pub(crate) fn query(connection: &impl ClientEndpoint, verb: Verb) -> Result<Reply, &'static str> {
    if connection.require_peer(PROVIDER_PEER_REQUIREMENT) != 0 {
        return Err(refuse(connection));
    }
    connection.set_handler(false);
    connection.resume();
    let reply = connection
        .exchange(&encode_request(verb))
        .and_then(|bytes| decode_reply(&bytes, verb));
    connection.cancel();
    reply
}

/// Host side `forget-identity` / `renew`: the same pinning order as
/// `query`, the frame and the administrator's `authorization` in one
/// dictionary.
pub(crate) fn query_authorized(
    connection: &impl ClientEndpoint,
    verb: Verb,
    authorization: &[u8],
) -> Result<Reply, &'static str> {
    if verb == Verb::Import || !verb.requires_authorization() {
        return Err("verb_not_authorized_separately");
    }
    if connection.require_peer(PROVIDER_PEER_REQUIREMENT) != 0 {
        return Err(refuse(connection));
    }
    connection.set_handler(false);
    connection.resume();
    let frame = encode_request(verb);
    let reply = connection
        .exchange_entries(&[(FRAME_KEY, &frame), (AUTHORIZATION_KEY, authorization)])
        .and_then(|bytes| decode_reply(&bytes, verb));
    connection.cancel();
    reply
}

/// The import request: `frame`, `authorization`, `manifest` and one data
/// value per file.
fn import_entries<'a>(
    frame: &'a [u8],
    authorization: &'a [u8],
    manifest: &'a [u8],
    payload: &'a ImportPayload,
) -> Vec<(&'static CStr, &'a [u8])> {
    let mut entries = vec![
        (FRAME_KEY, frame),
        (AUTHORIZATION_KEY, authorization),
        (MANIFEST_KEY, manifest),
    ];
    entries.extend(payload.files().map(|(member, bytes)| (member.key, bytes)));
    entries
}

/// Host side `import`: the same pinning order as `query`, one dictionary
/// with the administrator's `authorization` and the payload, the reply
/// decoded and checked against what was sent.
pub(crate) fn query_import(
    connection: &impl ClientEndpoint,
    payload: &ImportPayload,
    authorization: &[u8],
) -> Result<Reply, &'static str> {
    if connection.require_peer(PROVIDER_PEER_REQUIREMENT) != 0 {
        return Err(refuse(connection));
    }
    connection.set_handler(false);
    connection.resume();
    let frame = encode_request(Verb::Import);
    let manifest = payload.manifest();
    let manifest_bytes = encode_manifest(&manifest);
    let reply = connection
        .exchange_entries(&import_entries(
            &frame,
            authorization,
            &manifest_bytes,
            payload,
        ))
        .and_then(|bytes| decode_reply(&bytes, Verb::Import))
        .and_then(|reply| match &reply {
            Reply::Import(report) => {
                identity_import::verify_import_report(&manifest, report).map(|()| reply)
            }
            _ => Ok(reply),
        });
    connection.cancel();
    reply
}

/// A libxpc connection the caller keeps alive for the duration of the call.
struct NativeConnection(XpcObject);

fn on_peer_event(event: XpcObject) {
    // Errors (invalid, interrupted, peer requirement) end the peer; only a
    // dictionary that libxpc admitted under the requirement is answered.
    if !is_type(event, unsafe { &_xpc_type_dictionary }) {
        return;
    }
    let remote = unsafe { xpc_dictionary_get_remote_connection(event) };
    // The euid of the connection libxpc admitted under the requirement.
    let peer_euid = (!remote.is_null()).then(|| unsafe { xpc_connection_get_euid(remote) });
    let reply_bytes = respond_message(event, peer_euid, &NativeObserver);
    log_identity_outcome(event, &reply_bytes);
    let Some(reply) = XpcOwned::new(unsafe { xpc_dictionary_create_reply(event) }) else {
        return;
    };
    set_frame(reply.as_ptr(), &reply_bytes);
    if !remote.is_null() {
        unsafe { xpc_connection_send_message(remote, reply.as_ptr()) };
    }
}

/// One stable code line for each identity verb: `committed`/`forgotten` or
/// the refusal. Never a path, digest or byte of the payload.
fn log_identity_outcome(event: XpcObject, reply: &[u8]) {
    let verb = read_request_frame(event, MAX_REQUEST_BYTES)
        .ok()
        .and_then(|bytes| decode_request(&bytes).ok());
    let event = match verb {
        Some(Verb::Import) => "xpc_import",
        Some(Verb::ForgetIdentity) => "xpc_forget_identity",
        _ => return,
    };
    let code = match verb.map(|verb| decode_reply(reply, verb)) {
        Some(Ok(Reply::Refused(code))) => {
            crate::apple::log_code(event, &code);
            return;
        }
        Some(Ok(Reply::Import(report))) if report.retired_removed => "committed",
        Some(Ok(Reply::Import(_))) => "committed_retired_tree_kept",
        Some(Ok(Reply::Forget(report))) if report.key_material_removed => "forgotten",
        Some(Ok(Reply::Forget(_))) => "forgotten_removal_incomplete",
        _ => "reply_unencodable",
    };
    crate::apple::log_code(event, code);
}

impl Endpoint for NativeConnection {
    fn require_peer(&self, requirement: &CStr) -> c_int {
        unsafe { xpc_connection_set_peer_code_signing_requirement(self.0, requirement.as_ptr()) }
    }
    fn set_handler(&self, serve: bool) {
        let handler: RcBlock<dyn Fn(XpcObject)> = if serve {
            RcBlock::new(|event: XpcObject| {
                let _ = std::panic::catch_unwind(|| {
                    objc2::rc::autoreleasepool(|_| on_peer_event(event))
                });
            })
        } else {
            RcBlock::new(|_: XpcObject| {})
        };
        // libxpc copies the handler block; this reference may drop after.
        unsafe { xpc_connection_set_event_handler(self.0, &handler) };
    }
    fn resume(&self) {
        unsafe { xpc_connection_resume(self.0) }
    }
    fn cancel(&self) {
        unsafe { xpc_connection_cancel(self.0) }
    }
}

impl NativeConnection {
    fn send(&self, message: XpcOwned) -> Result<Vec<u8>, &'static str> {
        let reply = XpcOwned::new(unsafe {
            xpc_connection_send_message_with_reply_sync(self.0, message.as_ptr())
        })
        .ok_or("xpc_no_reply")?;
        if is_type(reply.as_ptr(), unsafe { &_xpc_type_error }) {
            return Err(classify_error(reply.as_ptr()));
        }
        read_frame(reply.as_ptr(), MAX_REPLY_BYTES)
    }
}

impl ClientEndpoint for NativeConnection {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.send(framed(request).ok_or("xpc_message_create_failed")?)
    }
    fn exchange_entries(&self, entries: &[(&CStr, &[u8])]) -> Result<Vec<u8>, &'static str> {
        self.send(framed_entries(entries).ok_or("xpc_message_create_failed")?)
    }
}

fn on_listener_event(event: XpcObject) {
    // A listener delivers new peers as connections; its own errors carry no
    // peer and are only logged.
    if !is_type(event, unsafe { &_xpc_type_connection }) {
        crate::apple::log_code("xpc_listener_event", classify_error(event));
        return;
    }
    // The peer is owned by libxpc while active; it is never released here.
    if let Err(code) = admit_peer(&NativeConnection(event)) {
        crate::apple::log_code("xpc_refused", code);
    }
}

/// Provider: create and resume the one `NEMachServiceName` listener. The
/// listener lives for the process; a second call is refused.
pub(crate) fn start_listener() -> Result<(), &'static str> {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return Err("xpc_listener_already_started");
    }
    let listener = unsafe {
        xpc_connection_create_mach_service(
            MACH_SERVICE_NAME.as_ptr(),
            std::ptr::null_mut(),
            LISTENER_FLAGS,
        )
    };
    if listener.is_null() {
        return Err("xpc_listener_create_failed");
    }
    let handler: RcBlock<dyn Fn(XpcObject)> = RcBlock::new(|event: XpcObject| {
        let _ = std::panic::catch_unwind(|| on_listener_event(event));
    });
    unsafe {
        xpc_connection_set_event_handler(listener, &handler);
        xpc_connection_resume(listener);
    }
    // Intentionally never released: the listener is process-lifetime.
    // v30: whether this sandbox lets the provider obtain the proof right,
    // logged once (never a proof of anything a host sent).
    std::thread::spawn(|| {
        let probe = identity_authorization::proof_probe();
        let status = probe.status().map_or_else(
            || "status:none".to_owned(),
            |status| format!("status:{status}"),
        );
        crate::apple::log_fields("identity_proof_probe", &[probe.token(), &status]);
    });
    Ok(())
}

/// Host: one bounded request to the provider through the privileged
/// bootstrap, with the provider's Developer ID requirement pinned first.
pub fn query_provider(verb: Verb) -> Result<Reply, &'static str> {
    if verb == Verb::Import {
        return Err("import_requires_payload");
    }
    if verb.requires_authorization() {
        return Err("identity_authorization_required");
    }
    let connection = client_connection()?;
    // Cancelled inside `query` on every path before `connection` is released.
    query(&NativeConnection(connection.as_ptr()), verb)
}

fn client_connection() -> Result<XpcOwned, &'static str> {
    XpcOwned::new(unsafe {
        xpc_connection_create_mach_service(
            MACH_SERVICE_NAME.as_ptr(),
            std::ptr::null_mut(),
            CLIENT_FLAGS,
        )
    })
    .ok_or("xpc_connection_create_failed")
}

/// Host: one bounded `forget-identity` or `renew` carrying the
/// administrator's `approval` (only the host's password prompt makes one),
/// pinned like `query_provider`. The approval's rights are destroyed once
/// the provider has answered (or on any refusal).
pub fn query_provider_authorized(
    verb: Verb,
    approval: IdentityApproval,
) -> Result<Reply, &'static str> {
    if verb == Verb::Import || !verb.requires_authorization() {
        return Err("verb_not_authorized_separately");
    }
    let connection = client_connection()?;
    let reply = query_authorized(
        &NativeConnection(connection.as_ptr()),
        verb,
        approval.external_form(),
    );
    approval.spend();
    reply
}

/// Host: one bounded `import` of `payload` with the administrator's
/// `approval`, pinned like `query_provider`. The reply is checked against
/// the sent manifest; the approval is spent once the provider has answered.
pub fn query_provider_import(
    payload: &ImportPayload,
    approval: IdentityApproval,
) -> Result<Reply, &'static str> {
    let connection = client_connection()?;
    let reply = query_import(
        &NativeConnection(connection.as_ptr()),
        payload,
        approval.external_form(),
    );
    approval.spend();
    reply
}

#[cfg(test)]
#[path = "provider_xpc_tests.rs"]
mod tests;
