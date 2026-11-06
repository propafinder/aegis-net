//! B-06 audit, v30 (S21j): proof of administrator presence for the
//! identity verbs, checked by the sandboxed provider itself.
//!
//! The XPC peer requirement proves only that a signed host sent a request,
//! and the console/admin euid check proves only who runs it. Any process of
//! the console admin can exec the signed host, so neither shows that a
//! person approved replacing or removing the identity. `import`,
//! `forget-identity` and `renew` therefore also carry an
//! `AuthorizationExternalForm` under [`AUTHORIZATION_KEY`]:
//!
//! - The host creates a fresh `AuthorizationRef`, registers
//!   [`IDENTITY_RIGHT`] when it is absent (`config.add.` lets anyone add a
//!   missing right) and admits its rule (`host_right_admitted`: a
//!   non-shared, **password-only** administrator authentication with
//!   AEGIS's own prompt; Touch ID is not offered, so a finger still resting
//!   from an earlier prompt cannot approve this one). It admits the shape
//!   of Apple's [`PROOF_RIGHT`] read-only (`proof_rule_admitted`), asks for
//!   the identity right with interaction allowed and a prompt naming the
//!   change (`IdentityChange::prompt`), then copies [`PROOF_RIGHT`] on the
//!   same reference without interaction and sends nothing unless that
//!   succeeds (`IdentityApproval` exists only after both).
//! - The provider runs in the App Sandbox. authd checks the caller's
//!   sandbox for every right before its rule, so the provider can never
//!   obtain an AEGIS right (v26 to v29 asked for one and were always
//!   refused: `Sandbox denied authorizing right`). The profile lets
//!   network-extension holders obtain [`PROOF_RIGHT`]
//!   (`system.services.systemconfiguration.network`), a k-of-n 1 rule
//!   whose only branch a non-root, unentitled creator outside Setup
//!   Assistant can satisfy is `authenticate-admin-nonshared`: a non-shared
//!   administrator credential at most 30 s old held by this very
//!   reference. authd keeps credentials per user, not per right, so the
//!   one the identity prompt stored satisfies it. The provider admits the
//!   identity rule and the proof rule read-only (`AuthorizationRightGet`
//!   has no sandbox check), re-creates the reference from the form and
//!   copies [`PROOF_RIGHT`] without interaction (`PROVIDER_COPY_RIGHTS` is
//!   the only right it ever copies), then destroys the rights. Every form is
//!   spent by its first presentation (`AuthorizationGate`, which remembers
//!   digests, never forms), admitted or not. The provider never writes the
//!   authorization database.
//! - Hosts v26 to v29 send their form under the legacy key and are refused
//!   `identity_authorization_host_outdated`; earlier hosts send none and are
//!   refused `identity_authorization_missing` (`provider_xpc`). Signed,
//!   hardened host code cannot be made to send the current key.
//!
//! `--disable-filter` and `--remove-filter` weaken the S20b leak guard and
//! are refused without an administrator at the prompt as well, under their
//! own right [`FILTER_RIGHT`] (its prompt names the leak guard, not the
//! identity; v30 makes it password-only under a new name too). They change
//! NEFilterManager from the host itself, with no provider to re-check, so
//! the host refuses a rule that is not admissible instead of repairing it:
//! a weak rule someone added first can only refuse the change, never let it
//! through without a prompt.
//!
//! The rules' credential timeout is bounded (`RIGHT_TIMEOUT_SECS`) rather
//! than 0: authd judges a credential's age against the rule on every
//! evaluation, so a timeout of 0 would expire the host's fresh credential
//! before the provider's non-interactive check. Re-prompting comes from the
//! non-shared rule and a fresh reference per host run, not from the timeout.
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    ffi::{c_char, c_void, CStr, CString},
    sync::{Mutex, PoisonError},
};

/// v30: the authorization right every identity-changing verb requires
/// (password-only; it replaces `LEGACY_IDENTITY_RIGHT`, whose rule an
/// earlier host registered with Touch ID allowed and which only an
/// administrator could change).
pub const IDENTITY_RIGHT: &CStr = c"dev.aegis.macos.identity-change";
/// The v26 to v29 identity right, left in place. No v30 host asks for it;
/// a kept v26 to v29 host still does, and the provider refuses what it then
/// sends (`identity_authorization_host_outdated`).
pub const LEGACY_IDENTITY_RIGHT: &CStr = c"dev.aegis.macos.identity-import";
/// v30: the right `--disable-filter` and `--remove-filter` require
/// (password-only, like `IDENTITY_RIGHT`).
pub const FILTER_RIGHT: &CStr = c"dev.aegis.macos.leak-guard-change";
/// The v26 to v29 leak-guard right, left in place. No v30 host asks for it,
/// but a kept v26 to v29 host still does, with Touch ID offered, and its
/// filter verbs need no provider: the packaging scripts remove the host
/// executable of every kept v25 to v29 copy (`pipeline.py
/// disarm-weak-host`, `LEAK_GUARD_PASSWORD_MIN`).
pub const LEGACY_FILTER_RIGHT: &CStr = c"dev.aegis.macos.leak-guard-weaken";
/// Apple's right that the provider's sandbox profile lets it obtain and
/// whose rule only a fresh, non-shared administrator credential satisfies
/// for the host's reference.
pub const PROOF_RIGHT: &CStr = c"system.services.systemconfiguration.network";
/// Every right the provider passes to `AuthorizationCopyRights`.
pub(crate) const PROVIDER_COPY_RIGHTS: [&CStr; 1] = [PROOF_RIGHT];
/// `kAuthorizationExternalFormLength`.
pub const EXTERNAL_FORM_LENGTH: usize = 32;
/// v30: the XPC key that carries the external form of an identity verb. A
/// provider that must refuse the hosts sending it renames it and moves
/// this one to `LEGACY_AUTHORIZATION_KEYS`.
pub(crate) const AUTHORIZATION_KEY: &CStr = c"identity-approval";
/// Keys earlier hosts sent their form under (v26 to v29).
pub(crate) const LEGACY_AUTHORIZATION_KEYS: [&CStr; 1] = [c"authorization"];
/// The registered rule's credential lifetime: long enough for the
/// provider's check after the host's prompt, never shared or cached across
/// host runs.
pub(crate) const RIGHT_TIMEOUT_SECS: i64 = 30;
/// Seconds the host waits for the administrator to answer the prompt.
pub const PROMPT_TIMEOUT_SECS: u64 = 120;
/// Spent-form digests the provider remembers. The destroyed rights already
/// refuse an older form; this bound only caps memory.
pub(crate) const MAX_SPENT_FORMS: usize = 1024;
/// Keys that delegate or bypass the user authentication of a rule.
const ESCALATING_KEYS: [&CStr; 6] = [
    c"rule",
    c"k-of-n",
    c"mechanisms",
    c"entitled",
    c"entitled-group",
    c"vpn-entitled-group",
];
/// Keys that grant a rule on an entitlement of the creator.
const ENTITLEMENT_KEYS: [&CStr; 3] = [c"entitled", c"entitled-group", c"vpn-entitled-group"];
/// The delegates `PROOF_RIGHT` may name (macOS 26.5: all four, in this
/// order); `PROOF_ADMIN_DELEGATE` must be one of them.
pub(crate) const PROOF_DELEGATES: [&str; 4] = [
    "is-root",
    "entitled",
    "_mbsetupuser-nonshared",
    "authenticate-admin-nonshared",
];
pub(crate) const PROOF_ADMIN_DELEGATE: &str = "authenticate-admin-nonshared";
/// The one mechanism of `entitled`: it checks the creator for an
/// Apple-private entitlement no third-party code can hold.
pub(crate) const ENTITLED_MECHANISM: &str = "builtin:entitled,privileged";
/// Bound for any string read from a rule (class, group, prompt, delegate).
const MAX_RULE_STRING: usize = 256;
/// Bound for a delegate or mechanism list.
const MAX_RULE_LIST: isize = 16;

// ---------------------------------------------------------------------------
// Right definition: what host and provider require of a rule.

/// The fields of a right definition that decide who may obtain it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RightDefinition {
    pub(crate) class: Option<String>,
    pub(crate) group: Option<String>,
    pub(crate) shared: Option<bool>,
    pub(crate) timeout: Option<i64>,
    pub(crate) authenticate_user: Option<bool>,
    pub(crate) allow_root: Option<bool>,
    pub(crate) session_owner: Option<bool>,
    /// v30: `password-only` (no Touch ID or smart card in the dialog).
    pub(crate) password_only: Option<bool>,
    /// v30: the `""` entry of `default-prompt` (the description the right
    /// was registered with).
    pub(crate) default_prompt: Option<String>,
    /// v30: `default-prompt` holds an entry besides `""` (a localization
    /// the host never registers).
    pub(crate) prompt_localized: bool,
    /// v30: `k-of-n`, `rule` (one name or a list) and `mechanisms`.
    pub(crate) k_of_n: Option<i64>,
    pub(crate) rules: Option<Vec<String>>,
    pub(crate) mechanisms: Option<Vec<String>>,
    /// v30: one of `ENTITLEMENT_KEYS` is present.
    pub(crate) entitlement_keys: bool,
    /// One of `ESCALATING_KEYS` is present.
    pub(crate) escalating: bool,
    /// A judged key is present with an unexpected type.
    pub(crate) malformed: bool,
}

/// The rule the host registers for `right` (`IDENTITY_RIGHT` or
/// `FILTER_RIGHT`).
pub(crate) fn registered_definition(right: &CStr) -> RightDefinition {
    RightDefinition {
        class: Some("user".into()),
        group: Some("admin".into()),
        shared: Some(false),
        timeout: Some(RIGHT_TIMEOUT_SECS),
        authenticate_user: Some(true),
        allow_root: Some(false),
        session_owner: Some(false),
        password_only: Some(true),
        default_prompt: Some(right_text(right).0.to_string_lossy().into_owned()),
        ..RightDefinition::default()
    }
}

/// An administrator must authenticate into this reference alone, and the
/// credential must expire within `RIGHT_TIMEOUT_SECS`. A rule that is
/// shared, allows root, accepts the session owner, delegates to another
/// rule or entitlement, or is not a `user` rule of `admin`, is refused.
pub(crate) fn right_admissible(definition: &RightDefinition) -> bool {
    definition.class.as_deref() == Some("user")
        && definition.group.as_deref() == Some("admin")
        && definition.shared == Some(false)
        && definition
            .timeout
            .is_some_and(|timeout| (0..=RIGHT_TIMEOUT_SECS).contains(&timeout))
        && definition.authenticate_user != Some(false)
        && definition.allow_root != Some(true)
        && definition.session_owner != Some(true)
        && !definition.escalating
        && !definition.malformed
}

/// v30: an AEGIS right's rule: admissible, password-only and with exactly
/// the prompt the host registers for it (no localization beside it).
pub(crate) fn aegis_right_admissible(right: &CStr, definition: &RightDefinition) -> bool {
    right_admissible(definition)
        && definition.password_only == Some(true)
        && definition.default_prompt.as_deref() == right_text(right).0.to_str().ok()
        && !definition.prompt_localized
}

/// The refusal codes of one AEGIS right.
struct Codes {
    unavailable: &'static str,
    unregistered: &'static str,
    inadmissible: &'static str,
    cancelled: &'static str,
    denied: &'static str,
}
const IDENTITY_CODES: Codes = Codes {
    unavailable: "identity_authorization_unavailable",
    unregistered: "identity_authorization_right_unregistered",
    inadmissible: "identity_authorization_right_inadmissible",
    cancelled: "identity_authorization_cancelled",
    denied: "identity_authorization_denied",
};
const FILTER_CODES: Codes = Codes {
    unavailable: "filter_authorization_unavailable",
    unregistered: "filter_authorization_right_unregistered",
    inadmissible: "filter_authorization_right_inadmissible",
    cancelled: "filter_authorization_cancelled",
    denied: "filter_authorization_denied",
};
fn codes(right: &CStr) -> &'static Codes {
    if right == FILTER_RIGHT {
        &FILTER_CODES
    } else {
        &IDENTITY_CODES
    }
}

/// The admission of an AEGIS right's rule by the host (before it prompts)
/// and, for `IDENTITY_RIGHT`, by the provider (before it checks a form):
/// registered and `aegis_right_admissible`. Nothing repairs it; an
/// inadmissible rule refuses.
pub(crate) fn host_right_admitted(
    right: &CStr,
    definition: Option<&RightDefinition>,
) -> Result<(), &'static str> {
    let codes = codes(right);
    match definition {
        None => Err(codes.unregistered),
        Some(definition) if aegis_right_admissible(right, definition) => Ok(()),
        Some(_) => Err(codes.inadmissible),
    }
}

/// One delegate of `PROOF_RIGHT`, judged by its name. Each branch a host
/// reference could take must need what it needs on this Mac today.
fn proof_delegate_admitted(name: &str, definition: &RightDefinition) -> bool {
    let plain = !definition.escalating && !definition.malformed;
    let user = definition.class.as_deref() == Some("user");
    match name {
        // A non-shared administrator credential, at most 30 s old.
        PROOF_ADMIN_DELEGATE => right_admissible(definition),
        // The creator's uid 0 only (a root session credential aside).
        "is-root" => {
            user && plain
                && definition.allow_root == Some(true)
                && definition.authenticate_user == Some(false)
                && definition.group.is_none()
                && definition.session_owner != Some(true)
        }
        // The session's user in `_mbsetupuser` (Setup Assistant) only.
        "_mbsetupuser-nonshared" => {
            user && plain
                && definition.group.as_deref() == Some("_mbsetupuser")
                && definition.authenticate_user == Some(false)
                && definition.allow_root != Some(true)
                && definition.session_owner != Some(true)
        }
        // Apple's private entitlement of the creator only.
        "entitled" => {
            definition.class.as_deref() == Some("evaluate-mechanisms")
                && definition.mechanisms.as_deref() == Some(&[ENTITLED_MECHANISM.to_owned()][..])
                && definition.rules.is_none()
                && definition.k_of_n.is_none()
                && definition.group.is_none()
                && !definition.entitlement_keys
                && !definition.malformed
        }
        _ => false,
    }
}

/// v30: `PROOF_RIGHT` still has the shape this design rests on: class
/// `rule`, k-of-n 1, only known delegates and among them
/// `authenticate-admin-nonshared`, each delegate as `proof_delegate_admitted`
/// requires, and nothing that grants it otherwise. Read-only; anything else
/// (an administrator's edit, a macOS update) refuses with a distinct code.
pub(crate) fn proof_rule_admitted(
    read: impl Fn(&CStr) -> Result<Option<RightDefinition>, &'static str>,
) -> Result<(), &'static str> {
    const UNEXPECTED: &str = "identity_authorization_proof_rule_unexpected";
    let unavailable = |_| IDENTITY_CODES.unavailable;
    let proof = read(PROOF_RIGHT).map_err(unavailable)?.ok_or(UNEXPECTED)?;
    let delegates = proof.rules.as_deref().ok_or(UNEXPECTED)?;
    if proof.malformed
        || proof.class.as_deref() != Some("rule")
        || proof.k_of_n != Some(1)
        || proof.mechanisms.is_some()
        || proof.entitlement_keys
        || !delegates.iter().any(|name| name == PROOF_ADMIN_DELEGATE)
        || !delegates
            .iter()
            .all(|name| PROOF_DELEGATES.contains(&name.as_str()))
    {
        return Err(UNEXPECTED);
    }
    for name in delegates {
        let right = CString::new(name.as_str()).map_err(|_| UNEXPECTED)?;
        let definition = read(&right).map_err(unavailable)?.ok_or(UNEXPECTED)?;
        if !proof_delegate_admitted(name, &definition) {
            return Err(UNEXPECTED);
        }
    }
    Ok(())
}

/// The provider's reading of an `AuthorizationCopyRights` status for
/// `PROOF_RIGHT`: `interaction not allowed` means no live credential (never
/// granted, older than the rule allows, or destroyed); `denied` is a rule
/// or sandbox refusal; anything else an unusable reference.
pub(crate) fn proof_status(status: i32) -> Result<(), &'static str> {
    match status {
        0 => Ok(()),
        ERR_AUTHORIZATION_INTERACTION_NOT_ALLOWED => Err("identity_authorization_expired"),
        ERR_AUTHORIZATION_DENIED => Err("identity_authorization_denied"),
        _ => Err("identity_authorization_invalid"),
    }
}

// ---------------------------------------------------------------------------
// Provider gate: each form is presented once.

/// Evaluates one external form without interaction and destroys its
/// rights, whatever the outcome.
pub(crate) trait FormVerifier {
    fn verify(&self, form: &[u8; EXTERNAL_FORM_LENGTH]) -> Result<(), &'static str>;
}

/// The provider's spent forms, as SHA-256 digests (a form is a bearer
/// token; its bytes are never retained).
pub(crate) struct AuthorizationGate {
    spent: Mutex<VecDeque<[u8; 32]>>,
}
impl AuthorizationGate {
    pub(crate) const fn new() -> Self {
        Self {
            spent: Mutex::new(VecDeque::new()),
        }
    }

    /// Admit one identity request's authorization. A missing or malformed
    /// form is refused before the verifier runs; a form already presented
    /// is refused as a replay. A form is spent before it is verified, so
    /// one that was refused (expired, denied) cannot be presented again.
    pub(crate) fn admit(
        &self,
        form: Option<&[u8]>,
        verifier: &impl FormVerifier,
    ) -> Result<(), &'static str> {
        let bytes = form.ok_or("identity_authorization_missing")?;
        let form: &[u8; EXTERNAL_FORM_LENGTH] = bytes
            .try_into()
            .map_err(|_| "identity_authorization_malformed")?;
        if form.iter().all(|byte| *byte == 0) {
            return Err("identity_authorization_malformed");
        }
        let digest: [u8; 32] = Sha256::digest(form).into();
        {
            let mut spent = self.spent.lock().unwrap_or_else(PoisonError::into_inner);
            if spent.contains(&digest) {
                return Err("identity_authorization_replayed");
            }
            if spent.len() == MAX_SPENT_FORMS {
                spent.pop_front();
            }
            spent.push_back(digest);
        }
        verifier.verify(form)
    }

    #[cfg(test)]
    pub(crate) fn spent(&self) -> usize {
        self.spent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// The provider process's one gate.
pub(crate) static PROVIDER_AUTHORIZATIONS: AuthorizationGate = AuthorizationGate::new();

/// v30: the provider's verifier, over a rule reader and a form copier so
/// its order is tested: the identity rule and the proof rule (read-only),
/// then each of `PROVIDER_COPY_RIGHTS` for the form, without interaction.
pub(crate) struct ProofVerifier<R, C> {
    pub(crate) read: R,
    pub(crate) copy: C,
}
impl<R, C> FormVerifier for ProofVerifier<R, C>
where
    R: Fn(&CStr) -> Result<Option<RightDefinition>, &'static str>,
    C: Fn(&[u8; EXTERNAL_FORM_LENGTH], &CStr) -> Result<i32, &'static str>,
{
    fn verify(&self, form: &[u8; EXTERNAL_FORM_LENGTH]) -> Result<(), &'static str> {
        let read = |right: &CStr| (self.read)(right).map_err(|_| IDENTITY_CODES.unavailable);
        host_right_admitted(IDENTITY_RIGHT, read(IDENTITY_RIGHT)?.as_ref())?;
        proof_rule_admitted(read)?;
        for right in PROVIDER_COPY_RIGHTS {
            proof_status((self.copy)(form, right)?)?;
        }
        Ok(())
    }
}

/// The provider's native verifier.
pub(crate) fn native_verifier() -> impl FormVerifier {
    ProofVerifier {
        read: read_right,
        copy: copy_external,
    }
}

/// The identity gate's view of `IDENTITY_RIGHT`: `admitted`, `unregistered`
/// (the host registers it at its first prompt), `inadmissible` or
/// `unavailable`.
pub(crate) fn identity_rule_state(
    read: impl Fn(&CStr) -> Result<Option<RightDefinition>, &'static str>,
) -> &'static str {
    match read(IDENTITY_RIGHT) {
        Err(_) => "unavailable",
        Ok(None) => "unregistered",
        Ok(Some(definition)) if aegis_right_admissible(IDENTITY_RIGHT, &definition) => "admitted",
        Ok(Some(_)) => "inadmissible",
    }
}

/// The identity gate's view of `PROOF_RIGHT`: `admitted`, `unexpected` or
/// `unavailable`.
pub(crate) fn proof_rule_state(
    read: impl Fn(&CStr) -> Result<Option<RightDefinition>, &'static str>,
) -> &'static str {
    match proof_rule_admitted(read) {
        Ok(()) => "admitted",
        Err(code) if code == IDENTITY_CODES.unavailable => "unavailable",
        Err(_) => "unexpected",
    }
}

/// v30: whether this process's sandbox lets it obtain `PROOF_RIGHT`, from
/// its own root reference (`is-root` grants it without a credential or a
/// prompt). A diagnostic only, never a proof of anything a host sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofProbe {
    Allowed,
    /// `errAuthorizationDenied`: the sandbox (or the rule) refuses it.
    Denied,
    /// Any other status (not root, authd error).
    Failed(i32),
    /// No reference could be created.
    Unavailable,
}
impl ProofProbe {
    pub(crate) fn of_status(status: i32) -> Self {
        match status {
            0 => Self::Allowed,
            ERR_AUTHORIZATION_DENIED => Self::Denied,
            other => Self::Failed(other),
        }
    }
    pub(crate) fn token(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Failed(_) => "failed",
            Self::Unavailable => "unavailable",
        }
    }
    pub(crate) fn status(self) -> Option<i32> {
        match self {
            Self::Allowed => Some(0),
            Self::Denied => Some(ERR_AUTHORIZATION_DENIED),
            Self::Failed(status) => Some(status),
            Self::Unavailable => None,
        }
    }
    /// v30 review: only `Allowed` and `Denied` answer whether this sandbox
    /// allows the right; `Failed` (an authd error) and `Unavailable` (no
    /// reference) say nothing about it and may pass.
    pub(crate) fn is_answer(self) -> bool {
        matches!(self, Self::Allowed | Self::Denied)
    }
}

/// v30 review: the provider keeps the probe's first answer
/// (`ProofProbe::is_answer`) for the life of its process. A failed or
/// unavailable probe is not kept, so an authd error while the extension
/// starts (early at boot, a dark wake) cannot close the identity gate until
/// the provider restarts: the next caller probes again. The lock is held
/// while one probe runs, so concurrent callers never probe twice at once.
pub(crate) struct ProbeCache(Mutex<Option<ProofProbe>>);
impl ProbeCache {
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(None))
    }
    pub(crate) fn get_or_probe(&self, probe: impl FnOnce() -> ProofProbe) -> ProofProbe {
        let mut kept = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(answer) = *kept {
            return answer;
        }
        let result = probe();
        if result.is_answer() {
            *kept = Some(result);
        }
        result
    }
}

/// The provider's probe: the listener runs it once at start, and the
/// identity gate reads it (again after a failure, `ProbeCache`).
pub(crate) fn proof_probe() -> ProofProbe {
    static PROBE: ProbeCache = ProbeCache::new();
    PROBE.get_or_probe(|| match Authorization::create_kept() {
        Ok(authorization) => {
            ProofProbe::of_status(authorization.copy_right(PROOF_RIGHT, FLAG_EXTEND_RIGHTS, None))
        }
        Err(_) => ProofProbe::Unavailable,
    })
}

// ---------------------------------------------------------------------------
// Authorization Services and CoreFoundation, hand-declared.

type CfRef = *const c_void;
type AuthorizationRef = *mut c_void;

#[repr(C)]
struct AuthorizationItem {
    name: *const c_char,
    value_length: usize,
    value: *mut c_void,
    flags: u32,
}
#[repr(C)]
struct AuthorizationItemSet {
    count: u32,
    items: *mut AuthorizationItem,
}
#[repr(C)]
struct ExternalForm {
    bytes: [u8; EXTERNAL_FORM_LENGTH],
}
#[repr(C)]
struct CfOpaque {
    _private: [u8; 0],
}

const FLAG_DEFAULTS: u32 = 0;
const FLAG_INTERACTION_ALLOWED: u32 = 1 << 0;
const FLAG_EXTEND_RIGHTS: u32 = 1 << 1;
const FLAG_DESTROY_RIGHTS: u32 = 1 << 3;
const ERR_AUTHORIZATION_DENIED: i32 = -60005;
const ERR_AUTHORIZATION_CANCELED: i32 = -60006;
const ERR_AUTHORIZATION_INTERACTION_NOT_ALLOWED: i32 = -60007;
/// `kAuthorizationEnvironmentPrompt`.
const ENVIRONMENT_PROMPT: &CStr = c"prompt";
const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const CF_NUMBER_SINT64: isize = 4;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn AuthorizationCreate(
        rights: *const AuthorizationItemSet,
        environment: *const AuthorizationItemSet,
        flags: u32,
        authorization: *mut AuthorizationRef,
    ) -> i32;
    fn AuthorizationFree(authorization: AuthorizationRef, flags: u32) -> i32;
    fn AuthorizationCopyRights(
        authorization: AuthorizationRef,
        rights: *const AuthorizationItemSet,
        environment: *const AuthorizationItemSet,
        flags: u32,
        authorized_rights: *mut *mut AuthorizationItemSet,
    ) -> i32;
    fn AuthorizationMakeExternalForm(
        authorization: AuthorizationRef,
        external_form: *mut ExternalForm,
    ) -> i32;
    fn AuthorizationCreateFromExternalForm(
        external_form: *const ExternalForm,
        authorization: *mut AuthorizationRef,
    ) -> i32;
    fn AuthorizationRightGet(right_name: *const c_char, right_definition: *mut CfRef) -> i32;
    fn AuthorizationRightSet(
        authorization: AuthorizationRef,
        right_name: *const c_char,
        right_definition: CfRef,
        description_key: CfRef,
        bundle: CfRef,
        locale_table_name: CfRef,
    ) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: CfRef);
    fn CFGetTypeID(value: CfRef) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFBooleanGetTypeID() -> usize;
    fn CFNumberGetTypeID() -> usize;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFArrayGetTypeID() -> usize;
    fn CFArrayGetCount(array: CfRef) -> isize;
    fn CFArrayGetValueAtIndex(array: CfRef, index: isize) -> CfRef;
    fn CFStringCreateWithCString(allocator: CfRef, text: *const c_char, encoding: u32) -> CfRef;
    fn CFStringGetCString(value: CfRef, buffer: *mut c_char, size: isize, encoding: u32) -> u8;
    fn CFBooleanGetValue(value: CfRef) -> u8;
    fn CFNumberCreate(allocator: CfRef, kind: isize, value: *const c_void) -> CfRef;
    fn CFNumberGetValue(value: CfRef, kind: isize, out: *mut c_void) -> u8;
    fn CFDictionaryGetValue(dictionary: CfRef, key: CfRef) -> CfRef;
    fn CFDictionaryGetCount(dictionary: CfRef) -> isize;
    fn CFDictionaryCreateMutable(
        allocator: CfRef,
        capacity: isize,
        key_callbacks: *const CfOpaque,
        value_callbacks: *const CfOpaque,
    ) -> CfRef;
    fn CFDictionarySetValue(dictionary: CfRef, key: CfRef, value: CfRef);
    static kCFTypeDictionaryKeyCallBacks: CfOpaque;
    static kCFTypeDictionaryValueCallBacks: CfOpaque;
    static kCFBooleanTrue: CfRef;
    static kCFBooleanFalse: CfRef;
}

/// One owned (+1) CoreFoundation object, released on drop.
struct Cf(CfRef);
impl Cf {
    fn new(value: CfRef) -> Option<Self> {
        (!value.is_null()).then_some(Self(value))
    }
    fn string(text: &CStr) -> Option<Self> {
        Self::new(unsafe {
            CFStringCreateWithCString(std::ptr::null(), text.as_ptr(), CF_STRING_ENCODING_UTF8)
        })
    }
    fn number(value: i64) -> Option<Self> {
        Self::new(unsafe {
            CFNumberCreate(
                std::ptr::null(),
                CF_NUMBER_SINT64,
                (&value as *const i64).cast(),
            )
        })
    }
    fn dictionary() -> Option<Self> {
        Self::new(unsafe {
            CFDictionaryCreateMutable(
                std::ptr::null(),
                0,
                &raw const kCFTypeDictionaryKeyCallBacks,
                &raw const kCFTypeDictionaryValueCallBacks,
            )
        })
    }
}
impl Drop for Cf {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) }
    }
}

/// One owned `AuthorizationRef`. Its rights are destroyed on drop (so a
/// form made from it is spent once its holder is done), except for the
/// provider's own probe reference, which holds none.
struct Authorization {
    reference: AuthorizationRef,
    destroy: bool,
}
impl Authorization {
    fn create_with(destroy: bool) -> Result<Self, &'static str> {
        let mut reference: AuthorizationRef = std::ptr::null_mut();
        let status = unsafe {
            AuthorizationCreate(
                std::ptr::null(),
                std::ptr::null(),
                FLAG_DEFAULTS,
                &mut reference,
            )
        };
        if status != 0 || reference.is_null() {
            return Err("identity_authorization_unavailable");
        }
        Ok(Self { reference, destroy })
    }
    fn create() -> Result<Self, &'static str> {
        Self::create_with(true)
    }
    /// Freed without destroying rights: destroying also purges the
    /// session's shared credentials, which a probe must not touch.
    fn create_kept() -> Result<Self, &'static str> {
        Self::create_with(false)
    }
    fn from_external(form: &[u8; EXTERNAL_FORM_LENGTH]) -> Result<Self, &'static str> {
        let external = ExternalForm { bytes: *form };
        let mut reference: AuthorizationRef = std::ptr::null_mut();
        let status = unsafe { AuthorizationCreateFromExternalForm(&external, &mut reference) };
        if status != 0 || reference.is_null() {
            return Err("identity_authorization_invalid");
        }
        Ok(Self {
            reference,
            destroy: true,
        })
    }
    /// `AuthorizationCopyRights` for `right` alone, with an optional
    /// `kAuthorizationEnvironmentPrompt`; the authorized set is not
    /// requested.
    fn copy_right(&self, right: &CStr, flags: u32, prompt: Option<&CStr>) -> i32 {
        let mut item = AuthorizationItem {
            name: right.as_ptr(),
            value_length: 0,
            value: std::ptr::null_mut(),
            flags: 0,
        };
        let rights = AuthorizationItemSet {
            count: 1,
            items: &mut item,
        };
        let mut prompt_item = prompt.map(|text| AuthorizationItem {
            name: ENVIRONMENT_PROMPT.as_ptr(),
            value_length: text.to_bytes().len(),
            value: text.as_ptr().cast_mut().cast(),
            flags: 0,
        });
        let environment = prompt_item.as_mut().map(|item| AuthorizationItemSet {
            count: 1,
            items: item,
        });
        let environment = environment
            .as_ref()
            .map_or(std::ptr::null(), |set| set as *const AuthorizationItemSet);
        unsafe {
            AuthorizationCopyRights(
                self.reference,
                &rights,
                environment,
                flags,
                std::ptr::null_mut(),
            )
        }
    }
    fn external_form(&self) -> Result<[u8; EXTERNAL_FORM_LENGTH], &'static str> {
        let mut external = ExternalForm {
            bytes: [0; EXTERNAL_FORM_LENGTH],
        };
        if unsafe { AuthorizationMakeExternalForm(self.reference, &mut external) } != 0 {
            return Err("identity_authorization_unavailable");
        }
        Ok(external.bytes)
    }
}
impl Drop for Authorization {
    fn drop(&mut self) {
        let flags = if self.destroy {
            FLAG_DESTROY_RIGHTS
        } else {
            FLAG_DEFAULTS
        };
        unsafe { AuthorizationFree(self.reference, flags) };
    }
}

fn dictionary_value(dictionary: CfRef, key: &CStr) -> Result<CfRef, &'static str> {
    let key = Cf::string(key).ok_or("identity_authorization_unavailable")?;
    Ok(unsafe { CFDictionaryGetValue(dictionary, key.0) })
}

fn is_cf(value: CfRef, type_id: usize) -> bool {
    !value.is_null() && unsafe { CFGetTypeID(value) } == type_id
}

/// A CFString of at most `MAX_RULE_STRING - 1` UTF-8 bytes.
fn cf_string(value: CfRef) -> Option<String> {
    if !is_cf(value, unsafe { CFStringGetTypeID() }) {
        return None;
    }
    let mut buffer = [0 as c_char; MAX_RULE_STRING];
    if unsafe {
        CFStringGetCString(
            value,
            buffer.as_mut_ptr(),
            buffer.len() as isize,
            CF_STRING_ENCODING_UTF8,
        )
    } == 0
    {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// One CFString, or a CFArray of at most `MAX_RULE_LIST` CFStrings.
fn cf_strings(value: CfRef) -> Option<Vec<String>> {
    if is_cf(value, unsafe { CFStringGetTypeID() }) {
        return cf_string(value).map(|text| vec![text]);
    }
    if !is_cf(value, unsafe { CFArrayGetTypeID() }) {
        return None;
    }
    let count = unsafe { CFArrayGetCount(value) };
    if !(0..=MAX_RULE_LIST).contains(&count) {
        return None;
    }
    (0..count)
        .map(|index| cf_string(unsafe { CFArrayGetValueAtIndex(value, index) }))
        .collect()
}

/// The parser's view of one definition dictionary: each judged key read
/// once, a present key of an unexpected type marking it malformed.
struct Fields {
    dictionary: CfRef,
    malformed: bool,
}
impl Fields {
    fn read<T>(
        &mut self,
        key: &CStr,
        convert: impl Fn(CfRef) -> Option<T>,
    ) -> Result<Option<T>, &'static str> {
        let value = dictionary_value(self.dictionary, key)?;
        if value.is_null() {
            return Ok(None);
        }
        let converted = convert(value);
        if converted.is_none() {
            self.malformed = true;
        }
        Ok(converted)
    }
    fn string(&mut self, key: &CStr) -> Result<Option<String>, &'static str> {
        self.read(key, cf_string)
    }
    fn flag(&mut self, key: &CStr) -> Result<Option<bool>, &'static str> {
        self.read(key, |value| {
            is_cf(value, unsafe { CFBooleanGetTypeID() })
                .then(|| unsafe { CFBooleanGetValue(value) } != 0)
        })
    }
    fn number(&mut self, key: &CStr) -> Result<Option<i64>, &'static str> {
        self.read(key, |value| {
            let mut number: i64 = 0;
            (is_cf(value, unsafe { CFNumberGetTypeID() })
                && unsafe {
                    CFNumberGetValue(value, CF_NUMBER_SINT64, (&mut number as *mut i64).cast())
                } != 0)
                .then_some(number)
        })
    }
    fn present(&self, key: &CStr) -> Result<bool, &'static str> {
        Ok(!dictionary_value(self.dictionary, key)?.is_null())
    }
}

/// The judged fields of one CF right definition.
fn parse_definition(dictionary: CfRef) -> Result<RightDefinition, &'static str> {
    if !is_cf(dictionary, unsafe { CFDictionaryGetTypeID() }) {
        return Ok(RightDefinition {
            malformed: true,
            ..RightDefinition::default()
        });
    }
    let mut fields = Fields {
        dictionary,
        malformed: false,
    };
    let mut definition = RightDefinition {
        class: fields.string(c"class")?,
        group: fields.string(c"group")?,
        shared: fields.flag(c"shared")?,
        timeout: fields.number(c"timeout")?,
        authenticate_user: fields.flag(c"authenticate-user")?,
        allow_root: fields.flag(c"allow-root")?,
        session_owner: fields.flag(c"session-owner")?,
        password_only: fields.flag(c"password-only")?,
        k_of_n: fields.number(c"k-of-n")?,
        rules: fields.read(c"rule", cf_strings)?,
        mechanisms: fields.read(c"mechanisms", |value| {
            is_cf(value, unsafe { CFArrayGetTypeID() })
                .then(|| cf_strings(value))
                .flatten()
        })?,
        ..RightDefinition::default()
    };
    let prompts = dictionary_value(dictionary, c"default-prompt")?;
    if !prompts.is_null() {
        if is_cf(prompts, unsafe { CFDictionaryGetTypeID() }) {
            let entry = dictionary_value(prompts, c"")?;
            definition.default_prompt = cf_string(entry);
            let count = unsafe { CFDictionaryGetCount(prompts) };
            definition.prompt_localized = count != isize::from(!entry.is_null());
            if !entry.is_null() && definition.default_prompt.is_none() {
                fields.malformed = true;
            }
        } else {
            fields.malformed = true;
        }
    }
    for key in ENTITLEMENT_KEYS {
        definition.entitlement_keys |= fields.present(key)?;
    }
    for key in ESCALATING_KEYS {
        definition.escalating |= fields.present(key)?;
    }
    definition.malformed = fields.malformed;
    Ok(definition)
}

/// The authorization database's definition of `right`; `None` when it is
/// not defined. Read-only (no sandbox check in authd).
pub(crate) fn read_right(right: &CStr) -> Result<Option<RightDefinition>, &'static str> {
    let mut raw: CfRef = std::ptr::null();
    let status = unsafe { AuthorizationRightGet(right.as_ptr(), &mut raw) };
    if status == ERR_AUTHORIZATION_DENIED {
        return Ok(None);
    }
    if status != 0 {
        return Err("identity_authorization_unavailable");
    }
    let owned = Cf::new(raw).ok_or("identity_authorization_unavailable")?;
    parse_definition(owned.0).map(Some)
}

/// What the prompt (`description`, shown as "<host> is trying to ...") and
/// the authorization database (`comment`) say about `right`.
pub(crate) fn right_text(right: &CStr) -> (&'static CStr, &'static CStr) {
    if right == FILTER_RIGHT {
        (
            c"turn off or remove the AEGIS leak guard",
            c"AEGIS: an administrator types a password to approve each change that turns off or removes the leak guard.",
        )
    } else {
        (
            c"change the AEGIS VPN device identity",
            c"AEGIS: an administrator types a password to approve each identity change.",
        )
    }
}

/// `registered_definition(right)` as the CF dictionary `AuthorizationRightSet`
/// takes, with its `comment` (the description goes separately and comes
/// back as `default-prompt`).
fn registered_cf_definition(right: &CStr) -> Result<Cf, &'static str> {
    let unavailable = codes(right).unavailable;
    let dictionary = Cf::dictionary().ok_or(unavailable)?;
    let set = |key: &CStr, value: CfRef| -> Result<(), &'static str> {
        let key = Cf::string(key).ok_or(unavailable)?;
        unsafe { CFDictionarySetValue(dictionary.0, key.0, value) };
        Ok(())
    };
    let definition = registered_definition(right);
    let class = Cf::string(c"user").ok_or(unavailable)?;
    let group = Cf::string(c"admin").ok_or(unavailable)?;
    let comment = Cf::string(right_text(right).1).ok_or(unavailable)?;
    let timeout = Cf::number(definition.timeout.ok_or(unavailable)?).ok_or(unavailable)?;
    let tries = Cf::number(10_000).ok_or(unavailable)?;
    let boolean = |value: Option<bool>| -> Result<CfRef, &'static str> {
        let value = value.ok_or(unavailable)?;
        Ok(unsafe {
            if value {
                kCFBooleanTrue
            } else {
                kCFBooleanFalse
            }
        })
    };
    set(c"class", class.0)?;
    set(c"group", group.0)?;
    set(c"shared", boolean(definition.shared)?)?;
    set(c"timeout", timeout.0)?;
    set(c"tries", tries.0)?;
    set(c"authenticate-user", boolean(definition.authenticate_user)?)?;
    set(c"allow-root", boolean(definition.allow_root)?)?;
    set(c"session-owner", boolean(definition.session_owner)?)?;
    set(c"password-only", boolean(definition.password_only)?)?;
    set(c"comment", comment.0)?;
    Ok(dictionary)
}

/// Host only: register `right` with its rule and description.
fn write_right(authorization: &Authorization, right: &CStr) -> Result<(), &'static str> {
    let codes = codes(right);
    let definition = registered_cf_definition(right)?;
    let description = Cf::string(right_text(right).0).ok_or(codes.unavailable)?;
    let status = unsafe {
        AuthorizationRightSet(
            authorization.reference,
            right.as_ptr(),
            definition.0,
            description.0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(codes.unregistered)
    }
}

// ---------------------------------------------------------------------------
// Provider side.

/// Re-create the host's reference from `form` and copy `right` without
/// interaction; the rights are destroyed on return. A refusal's raw status
/// is logged (a stable code line, never the form).
fn copy_external(form: &[u8; EXTERNAL_FORM_LENGTH], right: &CStr) -> Result<i32, &'static str> {
    let authorization = Authorization::from_external(form)?;
    let status = authorization.copy_right(right, FLAG_EXTEND_RIGHTS, None);
    if status != 0 {
        crate::apple::log_fields("identity_proof_refused", &[&format!("status:{status}")]);
    }
    Ok(status)
}

// ---------------------------------------------------------------------------
// Host side.

/// What an identity approval is for; its prompt names the change, so a
/// dialog an unexpected process raised says what it would do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityChange {
    Forget,
    Renew,
    /// `--import DIR`: the source directory's own name, when it is short
    /// and plain enough to show.
    Import {
        source: Option<String>,
    },
    /// v45 `--enroll`: the import of a just-issued identity for `device`
    /// (a valid device id, shown in the prompt), worded in Russian when
    /// `russian` (the system language); `replacing` when the provider holds
    /// an identity the import replaces.
    Join {
        device: Option<String>,
        russian: bool,
        replacing: bool,
    },
}
impl IdentityChange {
    /// v45: the join of `device` (shown only when it is a valid device id).
    pub fn join_of(device: &str, russian: bool, replacing: bool) -> Self {
        let device = aegis_core::secure_channel::registry::validate_device_id(device)
            .ok()
            .map(|()| device.to_owned());
        Self::Join {
            device,
            russian,
            replacing,
        }
    }

    /// The import of `dir`, naming its last component when it is at most 64
    /// ASCII letters, digits, `.`, `_`, `-` or spaces (never a path).
    pub fn import_of(dir: &std::path::Path) -> Self {
        let source = dir
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| {
                !name.is_empty()
                    && name.len() <= 64
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._- ".contains(&b))
            })
            .map(str::to_owned);
        Self::Import { source }
    }

    /// `kAuthorizationEnvironmentPrompt` for this change.
    pub(crate) fn prompt(&self) -> CString {
        let what = match self {
            Self::Forget => {
                "remove this Mac's VPN device identity (forget-identity)".to_owned()
            }
            Self::Renew => "renew this Mac's VPN device certificate now (renew)".to_owned(),
            Self::Import { source: Some(name) } => format!(
                "replace this Mac's VPN device identity with the one in the folder \"{name}\" (import)"
            ),
            Self::Import { source: None } => {
                "replace this Mac's VPN device identity (import)".to_owned()
            }
            Self::Join {
                device,
                russian: true,
                replacing,
            } => {
                let named = device
                    .as_deref()
                    .map(|device| format!(" «{device}»"))
                    .unwrap_or_default();
                let what = if *replacing {
                    format!("заменит VPN-удостоверение этого Mac на удостоверение{named} из вашего приглашения (join)")
                } else {
                    format!("установит на этот Mac VPN-удостоверение{named} из вашего приглашения (join)")
                };
                return CString::new(format!(
                    "AEGIS {what}. Вводите пароль администратора, только если вы сами начали это."
                ))
                .unwrap_or_default();
            }
            Self::Join {
                device, replacing, ..
            } => {
                let verb = if *replacing {
                    "replace this Mac's VPN device identity with"
                } else {
                    "install this Mac's VPN device identity"
                };
                match device {
                    Some(device) => format!("{verb} \"{device}\" from your invitation (join)"),
                    None if *replacing => format!("{verb} the one from your invitation (join)"),
                    None => format!("{verb} from your invitation (join)"),
                }
            }
        };
        CString::new(format!(
            "AEGIS will {what}. Type an administrator password only if you started this."
        ))
        .unwrap_or_default()
    }
}

/// The host's view of Authorization Services, so the approval order is
/// tested without authd.
pub(crate) trait HostAuthority {
    type Reference;
    fn create(&self) -> Result<Self::Reference, &'static str>;
    fn read(&self, right: &CStr) -> Result<Option<RightDefinition>, &'static str>;
    fn register(&self, reference: &Self::Reference, right: &CStr) -> Result<(), &'static str>;
    /// `AuthorizationCopyRights` with extend rights, and interaction when
    /// `interactive`; the status.
    fn copy(
        &self,
        reference: &Self::Reference,
        right: &CStr,
        interactive: bool,
        prompt: Option<&CStr>,
    ) -> i32;
    fn external_form(
        &self,
        reference: &Self::Reference,
    ) -> Result<[u8; EXTERNAL_FORM_LENGTH], &'static str>;
}

/// One approval of `right` (`IDENTITY_RIGHT` or `FILTER_RIGHT`) in a fresh
/// reference: register the right when absent, admit its rule, (identity)
/// admit the proof rule, ask for the right with interaction (the only
/// interactive call), then (identity) copy `PROOF_RIGHT` without
/// interaction and make the form. Every refusal comes before anything is
/// sent; the reference is dropped (its rights destroyed) with it.
pub(crate) fn host_approve<A: HostAuthority>(
    authority: &A,
    right: &CStr,
    prompt: Option<&CStr>,
) -> Result<(A::Reference, Option<[u8; EXTERNAL_FORM_LENGTH]>), &'static str> {
    let codes = codes(right);
    let proved = right == IDENTITY_RIGHT;
    let unavailable = |_| codes.unavailable;
    let reference = authority.create().map_err(unavailable)?;
    if authority.read(right).map_err(unavailable)?.is_none() {
        authority
            .register(&reference, right)
            .map_err(|_| codes.unregistered)?;
    }
    host_right_admitted(right, authority.read(right).map_err(unavailable)?.as_ref())?;
    if proved {
        proof_rule_admitted(|name| authority.read(name))?;
    }
    match authority.copy(&reference, right, true, prompt) {
        0 => {}
        ERR_AUTHORIZATION_CANCELED => return Err(codes.cancelled),
        _ => return Err(codes.denied),
    }
    if !proved {
        return Ok((reference, None));
    }
    if authority.copy(&reference, PROOF_RIGHT, false, None) != 0 {
        return Err("identity_authorization_unprovable");
    }
    let form = authority.external_form(&reference).map_err(unavailable)?;
    Ok((reference, Some(form)))
}

/// The host's native authority.
struct NativeAuthority;
impl HostAuthority for NativeAuthority {
    type Reference = Authorization;
    fn create(&self) -> Result<Authorization, &'static str> {
        Authorization::create()
    }
    fn read(&self, right: &CStr) -> Result<Option<RightDefinition>, &'static str> {
        read_right(right)
    }
    fn register(&self, reference: &Authorization, right: &CStr) -> Result<(), &'static str> {
        write_right(reference, right)
    }
    fn copy(
        &self,
        reference: &Authorization,
        right: &CStr,
        interactive: bool,
        prompt: Option<&CStr>,
    ) -> i32 {
        let flags = if interactive {
            FLAG_INTERACTION_ALLOWED | FLAG_EXTEND_RIGHTS
        } else {
            FLAG_EXTEND_RIGHTS
        };
        reference.copy_right(right, flags, prompt)
    }
    fn external_form(
        &self,
        reference: &Authorization,
    ) -> Result<[u8; EXTERNAL_FORM_LENGTH], &'static str> {
        reference.external_form()
    }
}

/// An administrator's approval of one identity change, proved for
/// `PROOF_RIGHT`. Only `approve_identity_change` makes one (and a test
/// constructor); the host's identity requests take it by value, so none is
/// sent without the prompt. The reference stays alive until the provider
/// has answered (freeing it first would invalidate the form) and its
/// rights are destroyed when it is spent or dropped.
pub struct IdentityApproval {
    authorization: Option<Authorization>,
    form: [u8; EXTERNAL_FORM_LENGTH],
}
impl IdentityApproval {
    /// The form to send; valid while `self` lives.
    pub(crate) fn external_form(&self) -> &[u8] {
        &self.form
    }

    /// Destroy the rights now (also done on drop).
    pub(crate) fn spend(self) {
        drop(self.authorization);
    }

    #[cfg(test)]
    pub(crate) fn for_tests(form: [u8; EXTERNAL_FORM_LENGTH]) -> Self {
        Self {
            authorization: None,
            form,
        }
    }
}

/// v30: an administrator types a password to approve one identity change
/// (`host_approve` for `IDENTITY_RIGHT` with `change`'s prompt). Blocks
/// until the prompt is answered; the caller bounds the wait.
pub fn approve_identity_change(change: &IdentityChange) -> Result<IdentityApproval, &'static str> {
    let prompt = change.prompt();
    let (authorization, form) = host_approve(&NativeAuthority, IDENTITY_RIGHT, Some(&prompt))?;
    Ok(IdentityApproval {
        authorization: Some(authorization),
        form: form.ok_or(IDENTITY_CODES.unavailable)?,
    })
}

/// v26/v30: an administrator approves one `--disable-filter` or
/// `--remove-filter` at the password-only system prompt (`host_approve` for
/// `FILTER_RIGHT`), in a fresh reference whose rights are destroyed on
/// return. Blocks until the prompt is answered; the caller bounds the wait.
pub fn approve_filter_weakening() -> Result<(), &'static str> {
    host_approve(&NativeAuthority, FILTER_RIGHT, None).map(drop)
}

#[cfg(test)]
pub(crate) mod native_test {
    //! Non-interactive handles for lib tests: never a prompt, never a write
    //! to the authorization database.
    use super::*;

    /// The external form of a fresh reference that holds no credential;
    /// `None` when authd refuses this test binary (below).
    pub(crate) fn uncredentialed_form() -> Option<([u8; EXTERNAL_FORM_LENGTH], impl Drop)> {
        let authorization = authd_reachable(Authorization::create())?;
        let form = authorization.external_form().expect("external form");
        Some((form, authorization))
    }

    /// authd answers `errAuthorizationInternal` to a client whose
    /// executable it cannot read, such as a test binary below a
    /// TCC-protected folder (`~/Documents`). Only that refusal is tolerated,
    /// loudly; the production host and provider are installed elsewhere.
    pub(crate) fn authd_reachable<T>(result: Result<T, &'static str>) -> Option<T> {
        match result {
            Err("identity_authorization_unavailable") => {
                eprintln!(
                    "authd refused this test binary (errAuthorizationInternal): native authorization checks not run here; run the test binary from outside a protected folder"
                );
                None
            }
            other => Some(other.expect("authorization services")),
        }
    }

    /// `registered_cf_definition(right)` parsed back by the parser.
    pub(crate) fn registered_round_trip(right: &CStr) -> RightDefinition {
        let definition = registered_cf_definition(right).expect("definition");
        let parsed = parse_definition(definition.0).expect("parse");
        // AuthorizationRightSet takes the description separately; authd
        // stores it as `default-prompt` {"": description}.
        RightDefinition {
            default_prompt: Some(right_text(right).0.to_string_lossy().into_owned()),
            ..parsed
        }
    }

    /// The parser over a CF dictionary built from `entries` (strings,
    /// booleans, numbers, string arrays and a `default-prompt` map), as
    /// authd would return it.
    pub(crate) enum Value<'a> {
        Text(&'a str),
        Flag(bool),
        Number(i64),
        List(&'a [&'a str]),
        Prompts(&'a [(&'a str, &'a str)]),
    }
    pub(crate) fn parse_entries(entries: &[(&str, Value)]) -> RightDefinition {
        let dictionary = Cf::dictionary().unwrap();
        let mut kept = Vec::new();
        let text = |text: &str| Cf::string(&CString::new(text).unwrap()).unwrap();
        for (key, value) in entries {
            let value = match value {
                Value::Text(t) => text(t),
                Value::Flag(f) => {
                    let key = text(key);
                    unsafe {
                        CFDictionarySetValue(
                            dictionary.0,
                            key.0,
                            if *f { kCFBooleanTrue } else { kCFBooleanFalse },
                        )
                    };
                    kept.push(key);
                    continue;
                }
                Value::Number(n) => Cf::number(*n).unwrap(),
                Value::List(items) => {
                    let items: Vec<Cf> = items.iter().map(|item| text(item)).collect();
                    let raw: Vec<CfRef> = items.iter().map(|item| item.0).collect();
                    let array = Cf::new(unsafe {
                        CFArrayCreate(
                            std::ptr::null(),
                            raw.as_ptr(),
                            raw.len() as isize,
                            &raw const kCFTypeArrayCallBacks,
                        )
                    })
                    .unwrap();
                    kept.extend(items);
                    array
                }
                Value::Prompts(prompts) => {
                    let map = Cf::dictionary().unwrap();
                    for (lang, prompt) in prompts.iter() {
                        let (lang, prompt) = (text(lang), text(prompt));
                        unsafe { CFDictionarySetValue(map.0, lang.0, prompt.0) };
                        kept.push(lang);
                        kept.push(prompt);
                    }
                    map
                }
            };
            let key = text(key);
            unsafe { CFDictionarySetValue(dictionary.0, key.0, value.0) };
            kept.push(key);
            kept.push(value);
        }
        parse_definition(dictionary.0).expect("parse")
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFArrayCreate(
            allocator: CfRef,
            values: *const CfRef,
            count: isize,
            callbacks: *const CfOpaque,
        ) -> CfRef;
        static kCFTypeArrayCallBacks: CfOpaque;
    }
}

/// Lib-test stand-ins for the provider's verifier and the host's forms.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Admits every well-formed form: only the gate can refuse a replay.
    pub(crate) struct AdmitEveryForm;
    impl FormVerifier for AdmitEveryForm {
        fn verify(&self, _: &[u8; EXTERNAL_FORM_LENGTH]) -> Result<(), &'static str> {
            Ok(())
        }
    }

    /// A form no earlier call returned (in this test process).
    pub(crate) fn fresh_form() -> [u8; EXTERNAL_FORM_LENGTH] {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let mut form = [0x3C; EXTERNAL_FORM_LENGTH];
        form[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        form
    }
}

#[cfg(test)]
#[path = "identity_authorization_tests.rs"]
mod tests;
