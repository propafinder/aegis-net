//! B-06 S11 host-side lifecycle decisions that need no Apple call: argument
//! parsing for the containing app, the system-extension replacement rule and
//! the bounded activation outcome with its exit codes. The native calls stay
//! in `bin/host.rs` and `manager.rs`; nothing here proves an installed
//! activation, profile or tunnel state.

use crate::{
    configuration::{WindowMode, PROVIDER_ID},
    provider_xpc::{Reply, Verb},
};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

/// The host stops waiting for an activation request after this long. Apple
/// withdraws a request that still awaits approval when the app exits; the
/// user approves in System Settings and runs the request again.
pub const ACTIVATION_TIMEOUT_SECS: u64 = 120;

/// `--request-activation` exit codes. `0` is the only completed result.
pub const EXIT_ACTIVATION_COMPLETED: i32 = 0;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_ACTIVATION_WILL_COMPLETE_AFTER_REBOOT: i32 = 10;
pub const EXIT_ACTIVATION_FAILED: i32 = 11;
pub const EXIT_ACTIVATION_CANCELLED: i32 = 12;
pub const EXIT_ACTIVATION_REPLACEMENT_DECLINED: i32 = 13;
pub const EXIT_ACTIVATION_TIMEOUT_AWAITING_APPROVAL: i32 = 14;
pub const EXIT_ACTIVATION_TIMEOUT: i32 = 75;

/// The host stops waiting for a deactivation request (S21) after this long.
pub const DEACTIVATION_TIMEOUT_SECS: u64 = 120;

/// `--deactivate` exit codes (S21). `0` is the only completed result; every
/// other code differs from each activation and XPC code, so a log or wrapper
/// never reads one request's outcome as another's.
pub const EXIT_DEACTIVATION_COMPLETED: i32 = 0;
pub const EXIT_DEACTIVATION_WILL_COMPLETE_AFTER_REBOOT: i32 = 20;
pub const EXIT_DEACTIVATION_FAILED: i32 = 21;
pub const EXIT_DEACTIVATION_CANCELLED: i32 = 22;
pub const EXIT_DEACTIVATION_NOT_FOUND: i32 = 23;
pub const EXIT_DEACTIVATION_TIMEOUT_AWAITING_APPROVAL: i32 = 24;
pub const EXIT_DEACTIVATION_TIMEOUT: i32 = 25;

/// `OSSystemExtensionRequestResult` raw values.
const RESULT_COMPLETED: isize = 0;
const RESULT_WILL_COMPLETE_AFTER_REBOOT: isize = 1;
/// `OSSystemExtensionErrorExtensionNotFound`.
const ERROR_EXTENSION_NOT_FOUND: isize = 4;
/// `OSSystemExtensionErrorRequestCanceled`.
const ERROR_REQUEST_CANCELED: isize = 11;

pub const USAGE: &str =
    "usage: aegis-ne-host --ping | --status | --profile-terms | --list | --remove-profile | --emergency-stop \
| --filter-status | --enable-filter | --disable-filter | --remove-filter \
| --forget-identity | --import ABSOLUTE_PRIVATE_AEGIS_DIR [--remove-source] \
| --enroll ABSOLUTE_FILE.aegis-invite [--remove-source] [--replace-identity] | --identity-gate | --request-activation PROVIDER_ID \
| --deactivate [PROVIDER_ID] | --save-profile PROVIDER_ID RELAY_IP [--replace-existing] \
| --connect/--disconnect/--status/--repair-runtime PROVIDER_ID OWNER_GENERATION RELAY_IP \
| --connect PROVIDER_ID OWNER_GENERATION RELAY_IP --window-policy adaptive|fixed";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedVerb {
    Connect,
    Disconnect,
    Status,
    RepairRuntime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostCommand {
    /// Bare `--ping`/`--status`/`--profile-terms`/`--forget-identity`: one
    /// bounded XPC exchange with the provider.
    Xpc(Verb),
    /// `--import DIR [--remove-source]` (S15): send `DIR/bundle` and
    /// `DIR/identity` to the provider's own container (S14) and, only with
    /// `remove_source` and an exact manifest echo, remove `DIR`.
    Import {
        dir: PathBuf,
        remove_source: bool,
    },
    /// v45 `--enroll FILE [--remove-source] [--replace-identity]`: admit
    /// one `.aegis-invite` package, stage and redeem it (`host_enroll`),
    /// then import the issued identity as `--import --remove-source` does.
    /// `remove_source` removes the package file after a commit;
    /// `replace_identity` allows replacing a currently valid identity.
    Enroll {
        path: PathBuf,
        remove_source: bool,
        replace_identity: bool,
    },
    RequestActivation,
    /// `--deactivate [PROVIDER_ID]` (S21): one bounded deactivation request
    /// for this provider only.
    Deactivate,
    /// `--save-profile PROVIDER_ID RELAY_IP [--replace-existing]`. Without
    /// the flag an existing profile of this provider refuses the save; with
    /// it (S16d) the one existing profile is modified in place.
    SaveProfile {
        relay: IpAddr,
        replace_existing: bool,
    },
    /// v35: `window` is the one tunnel start's stream-window mode. v36:
    /// Fixed (the product default) unless `--connect ... --window-policy
    /// adaptive` (a diagnostics flag of the owner CLI for a QA arm; never
    /// saved); `--window-policy fixed` stays accepted.
    Owned {
        verb: OwnedVerb,
        owner_generation: String,
        relay: IpAddr,
        window: WindowMode,
    },
    /// Every saved profile of this provider, regardless of owner generation.
    List,
    /// removeFromPreferences on every saved profile of this provider.
    RemoveProfile,
    /// stopVPNTunnel on every manager of this provider, not gated on an
    /// exact owner-generation/intent match.
    EmergencyStop,
    /// S20b `--filter-status`: NEFilterManager readback and the provider's
    /// `filter-status` (attached, gate, counters).
    FilterStatus,
    /// S20b `--enable-filter`: save the packet-filter configuration for this
    /// provider (the first save asks the user to allow it) and read it back.
    EnableFilter,
    /// S20b `--disable-filter`: keep the configuration, enabled=false.
    DisableFilter,
    /// S20b `--remove-filter`: removeFromPreferences, verified absent.
    RemoveFilter,
}

/// The S20b filter verbs. Each takes no operand: any operand is refused as
/// `filter_operand_refused` (uninstall-app.sh's capability probe relies on
/// that code; an older host answers `unknown_command`).
pub const FILTER_FLAGS: [&str; 4] = [
    "--filter-status",
    "--enable-filter",
    "--disable-filter",
    "--remove-filter",
];
pub const FILTER_OPERAND_REFUSED: &str = "filter_operand_refused";

/// v26 audit merge: the filter verbs that weaken the leak guard need an
/// administrator at the system prompt (`identity_authorization::FILTER_RIGHT`)
/// before NEFilterManager is touched, like the identity verbs: any process
/// of the console user can exec the signed host. Reading and enabling the
/// filter do not.
pub fn filter_requires_authorization(command: &HostCommand) -> bool {
    matches!(
        command,
        HostCommand::DisableFilter | HostCommand::RemoveFilter
    )
}

fn filter_command(flag: &str) -> Option<HostCommand> {
    match flag {
        "--filter-status" => Some(HostCommand::FilterStatus),
        "--enable-filter" => Some(HostCommand::EnableFilter),
        "--disable-filter" => Some(HostCommand::DisableFilter),
        "--remove-filter" => Some(HostCommand::RemoveFilter),
        _ => None,
    }
}

fn provider(id: &str) -> Result<(), &'static str> {
    if id == PROVIDER_ID {
        Ok(())
    } else {
        Err("provider_id_mismatch")
    }
}

fn relay(text: &str) -> Result<IpAddr, &'static str> {
    text.parse().map_err(|_| "numeric_relay_required")
}

/// Same shape the provider accepts from a saved profile.
fn owner_generation(text: &str) -> Result<String, &'static str> {
    if text.is_empty() || text.len() > 128 || text.chars().any(char::is_control) {
        return Err("owner_generation_invalid");
    }
    Ok(text.to_owned())
}

/// `--import` operands: exactly one directory and at most one
/// `--remove-source`, in either order. Any other flag, a repeated flag or a
/// second directory is refused. The directory's safety (canonical, 0700,
/// owned by the caller, no link) is checked when it is opened
/// (`host_import::SourceTree`).
fn parse_import(rest: &[&str]) -> Result<HostCommand, &'static str> {
    let mut dir = None;
    let mut remove_source = false;
    for arg in rest {
        match *arg {
            "--remove-source" if remove_source => return Err("duplicate_flag"),
            "--remove-source" => remove_source = true,
            "--import" => return Err("duplicate_flag"),
            flag if flag.starts_with('-') => return Err("unknown_flag"),
            _ if dir.is_some() => return Err("import_dir_repeated"),
            path => dir = Some(PathBuf::from(path)),
        }
    }
    let dir = dir.ok_or("import_dir_required")?;
    if !dir.is_absolute() {
        return Err("import_dir_must_be_absolute");
    }
    Ok(HostCommand::Import { dir, remove_source })
}

/// v45 `--enroll` operands: exactly one absolute package path and at most
/// one each of `--remove-source` and `--replace-identity`, in any order.
/// The file's safety (canonical, regular, the caller's, one link, the
/// extension, the cap) is checked when it is read (`invite_package`).
fn parse_enroll(rest: &[&str]) -> Result<HostCommand, &'static str> {
    let mut path = None;
    let (mut remove_source, mut replace_identity) = (false, false);
    for arg in rest {
        match *arg {
            "--remove-source" if remove_source => return Err("duplicate_flag"),
            "--remove-source" => remove_source = true,
            "--replace-identity" if replace_identity => return Err("duplicate_flag"),
            "--replace-identity" => replace_identity = true,
            "--enroll" => return Err("duplicate_flag"),
            flag if flag.starts_with('-') => return Err("unknown_flag"),
            _ if path.is_some() => return Err("enroll_path_repeated"),
            operand => path = Some(PathBuf::from(operand)),
        }
    }
    let path = path.ok_or("enroll_path_required")?;
    if !path.is_absolute() {
        return Err("enroll_path_must_be_absolute");
    }
    Ok(HostCommand::Enroll {
        path,
        remove_source,
        replace_identity,
    })
}

/// `--save-profile` operands: the provider id then the relay, and at most
/// one `--replace-existing` anywhere among them. Any other flag, a repeated
/// flag, or a missing or extra operand is refused.
fn parse_save(rest: &[&str]) -> Result<HostCommand, &'static str> {
    let mut operands = Vec::with_capacity(2);
    let mut replace_existing = false;
    for arg in rest {
        match *arg {
            "--replace-existing" if replace_existing => return Err("duplicate_flag"),
            "--replace-existing" => replace_existing = true,
            "--save-profile" => return Err("duplicate_flag"),
            flag if flag.starts_with('-') => return Err("unknown_flag"),
            operand => operands.push(operand),
        }
    }
    let [id, relay_ip] = operands.as_slice() else {
        return Err("save_operands_required");
    };
    provider(id)?;
    Ok(HostCommand::SaveProfile {
        relay: relay(relay_ip)?,
        replace_existing,
    })
}

/// Parse `argv` (including the program name). Every refusal is a usage error.
pub fn parse_host_args(args: &[String]) -> Result<HostCommand, &'static str> {
    let args: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    match args.as_slice() {
        ["--import", rest @ ..] => parse_import(rest),
        ["--enroll", rest @ ..] => parse_enroll(rest),
        ["--save-profile", rest @ ..] => parse_save(rest),
        [flag] if filter_command(flag).is_some() => filter_command(flag).ok_or("unknown_command"),
        [flag, _, ..] if FILTER_FLAGS.contains(flag) => Err(FILTER_OPERAND_REFUSED),
        [flag] => match *flag {
            "--list" => Ok(HostCommand::List),
            "--remove-profile" => Ok(HostCommand::RemoveProfile),
            "--emergency-stop" => Ok(HostCommand::EmergencyStop),
            "--deactivate" => Ok(HostCommand::Deactivate),
            other => Verb::from_flag(other)
                .map(HostCommand::Xpc)
                .ok_or("unknown_command"),
        },
        ["--request-activation", id] => {
            provider(id)?;
            Ok(HostCommand::RequestActivation)
        }
        ["--deactivate", id] => {
            provider(id)?;
            Ok(HostCommand::Deactivate)
        }
        // v35: a start's window policy, for --connect only, with exactly
        // one value after the positional operands. v36: `adaptive` (the v35
        // window, a QA arm) or `fixed` (the default anyway).
        ["--connect", id, generation, relay_ip, "--window-policy", value] => {
            let window = WindowMode::from_value(value).ok_or("unknown_command")?;
            provider(id)?;
            Ok(HostCommand::Owned {
                verb: OwnedVerb::Connect,
                owner_generation: owner_generation(generation)?,
                relay: relay(relay_ip)?,
                window,
            })
        }
        [flag, id, generation, relay_ip] => {
            let verb = match *flag {
                "--connect" => OwnedVerb::Connect,
                "--disconnect" => OwnedVerb::Disconnect,
                "--status" => OwnedVerb::Status,
                "--repair-runtime" => OwnedVerb::RepairRuntime,
                _ => return Err("unknown_command"),
            };
            provider(id)?;
            Ok(HostCommand::Owned {
                verb,
                owner_generation: owner_generation(generation)?,
                relay: relay(relay_ip)?,
                window: WindowMode::default(),
            })
        }
        _ => Err("unknown_command"),
    }
}

/// v45 `--enroll`: the package was refused before anything was staged.
pub const EXIT_ENROLL_PACKAGE_REFUSED: i32 = 40;
/// v45 `--enroll`: a currently valid identity is installed and
/// `--replace-identity` was not given. Nothing changed.
pub const EXIT_ENROLL_IDENTITY_PRESENT: i32 = 41;
/// v45 `--enroll`: a tunnel session is live. Nothing changed.
pub const EXIT_ENROLL_SESSION_LIVE: i32 = 42;
/// v45 `--enroll`: the authority rejected the invitation (expired, used,
/// revoked or not for this device). The staged request is kept.
pub const EXIT_ENROLL_REJECTED: i32 = 43;
/// v45 `--enroll`: the authority was not reached or was busy. The staged
/// request is kept; a rerun with the same package resumes it.
pub const EXIT_ENROLL_UNREACHABLE: i32 = 44;
/// v45 `--enroll`: a local staging, Store or journal check refused.
pub const EXIT_ENROLL_LOCAL_FAILED: i32 = 45;
/// v45 `--enroll`: the authority requires operator recovery.
pub const EXIT_ENROLL_RECOVERY_REQUIRED: i32 = 46;

/// Provider refused the request, or its reply was malformed.
pub const EXIT_XPC_REFUSED: i32 = 65;
/// `--import`: the source directory was refused before anything was sent.
pub const EXIT_IMPORT_SOURCE_REFUSED: i32 = 66;
/// `--import`, `--forget-identity`, `--renew`, and (v26) `--disable-filter`
/// and `--remove-filter`: no administrator approved the change (prompt
/// cancelled, denied or unanswered, or Authorization Services unavailable).
/// Nothing was sent or changed; an import source is kept.
pub const EXIT_AUTHORIZATION_REFUSED: i32 = 67;
/// The service is unavailable or its signer was refused.
pub const EXIT_XPC_UNAVAILABLE: i32 = 69;
/// `--import --remove-source`: the provider committed exactly what was sent,
/// but the source was not (completely) removed.
pub const EXIT_IMPORT_SOURCE_NOT_REMOVED: i32 = 73;
/// The provider committed, but left key material it was asked to remove:
/// an import kept the replaced tree, or a forget could not delete it.
pub const EXIT_XPC_REMOVAL_INCOMPLETE: i32 = 74;
/// No reply within the XPC budget; an import's commit state is unknown.
pub const EXIT_XPC_TIMEOUT: i32 = 75;
/// `--import`: the provider's committed manifest differs from what was
/// sent. The source is always kept.
pub const EXIT_IMPORT_MANIFEST_MISMATCH: i32 = 76;
/// `--import`: the request may have reached the provider, but no decoded
/// answer says whether it committed (interrupted connection, malformed
/// reply, or a refusal the provider can only make after its commit). The
/// source is always kept.
pub const EXIT_IMPORT_COMMIT_UNKNOWN: i32 = 77;

/// Exit code for a host-side XPC failure code (no decoded reply).
pub fn xpc_error_exit(code: &str) -> i32 {
    if code == "import_reply_mismatch" {
        return EXIT_IMPORT_MANIFEST_MISMATCH;
    }
    let malformed = code.starts_with("reply_")
        || code.starts_with("frame_")
        || code.starts_with("envelope_")
        || code == "schema_mismatch";
    if malformed {
        EXIT_XPC_REFUSED
    } else {
        EXIT_XPC_UNAVAILABLE
    }
}

/// v31: the verbs after whose answer the host also asks `cert-status` and
/// prints the renewal line (stderr) when renewal needs attention; stdout
/// keeps exactly the verb's one JSON line.
pub fn shows_renewal_line(verb: Verb) -> bool {
    matches!(verb, Verb::Ping | Verb::Status)
}

/// v31: whether `reply` (to a `shows_renewal_line` verb) was answered, so
/// the renewal line is asked for: never after a refusal or a failure.
pub fn renewal_line_wanted(verb: Verb, reply: &Result<Reply, &'static str>) -> bool {
    shows_renewal_line(verb) && matches!(reply, Ok(reply) if !matches!(reply, Reply::Refused(_)))
}

/// v31: the renewal line of one `cert-status` answer, `None` for anything
/// else (an older provider's refusal, `no_epoch`, a malformed reply).
pub fn renewal_line(reply: &Result<Reply, &'static str>) -> Option<String> {
    match reply {
        Ok(Reply::CertStatus(report)) => report.renewal_line(),
        _ => None,
    }
}

/// Exit code for one decoded provider reply. v30: a closed identity gate
/// is a refusal (65) as well, so uninstall-app.sh stops before it changes
/// anything.
pub fn xpc_reply_exit(reply: &Reply) -> i32 {
    match reply {
        Reply::Refused(_) => EXIT_XPC_REFUSED,
        Reply::IdentityGate(report) if report.blocker().is_some() => EXIT_XPC_REFUSED,
        Reply::Import(report) if !report.retired_removed => EXIT_XPC_REMOVAL_INCOMPLETE,
        Reply::Forget(report) if !report.key_material_removed => EXIT_XPC_REMOVAL_INCOMPLETE,
        _ => 0,
    }
}

/// S20b filter verb exit codes. `0` is the only accepted result; each other
/// code differs from every activation, deactivation and import code, and
/// `EXIT_XPC_UNAVAILABLE` (69) keeps its meaning for `--filter-status`.
pub const EXIT_FILTER_NOT_CONFIGURED: i32 = 30;
pub const EXIT_FILTER_DISABLED: i32 = 31;
pub const EXIT_FILTER_FIELD_MISMATCH: i32 = 32;
pub const EXIT_FILTER_NOT_ATTACHED: i32 = 33;
pub const EXIT_FILTER_FAILED: i32 = 34;
pub const EXIT_FILTER_PERMISSION_DENIED: i32 = 35;
pub const EXIT_FILTER_TIMEOUT: i32 = 36;
pub const EXIT_FILTER_REMOVAL_INCOMPLETE: i32 = 37;

/// The bound of `--filter-status`, `--disable-filter` and `--remove-filter`.
pub const FILTER_VERB_SECS: u64 = 30;
/// `--enable-filter` waits for the user's answer to the first save's
/// "would like to filter network content" alert.
pub const FILTER_ENABLE_SECS: u64 = 120;

/// The reviewed packet-filter configuration (Quinn, forum 127991):
/// filterPackets and the packet provider's bundle id, every other filter
/// property unset, grade Firewall.
pub const FILTER_DESCRIPTION: &str = "AEGIS leak guard";
/// `NEFilterManagerGradeFirewall`.
pub const FILTER_GRADE_FIREWALL: isize = 1;

/// What one NEFilterManager load returned, without any address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FilterReadback {
    /// A provider configuration exists.
    pub configured: bool,
    pub enabled: bool,
    pub filter_packets: bool,
    pub filter_sockets: bool,
    pub packet_bundle_id: Option<String>,
    /// Set means another provider kind was configured: never reviewed.
    pub data_bundle_id: Option<String>,
    pub server_address_set: bool,
    pub organization_set: bool,
    pub grade: isize,
    pub description: Option<String>,
}

impl FilterReadback {
    /// The first field of a configured readback that differs from the
    /// reviewed configuration, ignoring `enabled`.
    pub fn mismatch(&self) -> Option<&'static str> {
        if !self.filter_packets {
            Some("filter_packets")
        } else if self.filter_sockets {
            Some("filter_sockets")
        } else if self.packet_bundle_id.as_deref() != Some(PROVIDER_ID) {
            Some("packet_bundle_id")
        } else if self.data_bundle_id.is_some() {
            Some("data_bundle_id")
        } else if self.server_address_set {
            Some("server_address")
        } else if self.organization_set {
            Some("organization")
        } else if self.grade != FILTER_GRADE_FIREWALL {
            Some("grade")
        } else if self.description.as_deref() != Some(FILTER_DESCRIPTION) {
            Some("description")
        } else {
            None
        }
    }

    /// The readback fields of one result line (stable tokens only).
    pub fn fields(&self) -> String {
        let id = match self.packet_bundle_id.as_deref() {
            None => "none",
            Some(PROVIDER_ID) => "match",
            Some(_) => "mismatch",
        };
        let grade = match self.grade {
            1 => "firewall",
            2 => "inspector",
            _ => "other",
        };
        format!(
            "configured={} enabled={} filter_packets={} filter_sockets={} packet_bundle_id={id} grade={grade}",
            self.configured, self.enabled, self.filter_packets, self.filter_sockets
        )
    }
}

/// The outcome of one filter verb: its `filter_result=` name and exit code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterOutcome {
    Ok,
    NotConfigured,
    Disabled,
    FieldMismatch(&'static str),
    NotAttached,
    ProviderUnavailable,
    PermissionDenied,
    Failed(&'static str),
    Timeout,
    RemovalIncomplete,
    /// v26: no administrator approved `--disable-filter`/`--remove-filter`;
    /// NEFilterManager was not touched.
    AuthorizationRefused(&'static str),
}

impl FilterOutcome {
    pub fn name(self) -> &'static str {
        match self {
            FilterOutcome::Ok => "ok",
            FilterOutcome::NotConfigured => "not_configured",
            FilterOutcome::Disabled => "disabled",
            FilterOutcome::FieldMismatch(_) => "field_mismatch",
            FilterOutcome::NotAttached => "not_attached",
            FilterOutcome::ProviderUnavailable => "provider_unavailable",
            FilterOutcome::PermissionDenied => "permission_denied",
            FilterOutcome::Failed(_) => "failed",
            FilterOutcome::Timeout => "timeout",
            FilterOutcome::RemovalIncomplete => "removal_incomplete",
            FilterOutcome::AuthorizationRefused(_) => "authorization_refused",
        }
    }

    pub fn exit(self) -> i32 {
        match self {
            FilterOutcome::Ok => 0,
            FilterOutcome::NotConfigured => EXIT_FILTER_NOT_CONFIGURED,
            FilterOutcome::Disabled => EXIT_FILTER_DISABLED,
            FilterOutcome::FieldMismatch(_) => EXIT_FILTER_FIELD_MISMATCH,
            FilterOutcome::NotAttached => EXIT_FILTER_NOT_ATTACHED,
            FilterOutcome::ProviderUnavailable => EXIT_XPC_UNAVAILABLE,
            FilterOutcome::PermissionDenied => EXIT_FILTER_PERMISSION_DENIED,
            FilterOutcome::Failed(_) => EXIT_FILTER_FAILED,
            FilterOutcome::Timeout => EXIT_FILTER_TIMEOUT,
            FilterOutcome::RemovalIncomplete => EXIT_FILTER_REMOVAL_INCOMPLETE,
            FilterOutcome::AuthorizationRefused(_) => EXIT_AUTHORIZATION_REFUSED,
        }
    }

    /// `filter_result=NAME exit_code=N`, the prefix of every result line.
    pub fn prefix(self) -> String {
        format!("filter_result={} exit_code={}", self.name(), self.exit())
    }

    /// The stderr detail: the mismatching field or the failure code.
    pub fn detail(self) -> Option<&'static str> {
        match self {
            FilterOutcome::FieldMismatch(field) => Some(field),
            FilterOutcome::Failed(code) => Some(code),
            FilterOutcome::AuthorizationRefused(code) => Some(code),
            _ => None,
        }
    }
}

/// `NEFilterManagerError` raw values as stable codes; another domain's
/// error is never read as one of them.
pub fn filter_error_code(filter_domain: bool, code: isize) -> &'static str {
    if !filter_domain {
        return "filter_error_foreign_domain";
    }
    match code {
        1 => "filter_configuration_invalid",
        2 => "filter_configuration_disabled",
        3 => "filter_configuration_stale",
        4 => "filter_configuration_cannot_be_removed",
        5 => "filter_permission_denied",
        6 => "filter_internal_error",
        _ => "filter_error_unknown",
    }
}

/// A NEFilterManager call that failed with `code`.
pub fn filter_failure(code: &'static str) -> FilterOutcome {
    match code {
        "filter_permission_denied" => FilterOutcome::PermissionDenied,
        "operation_expired" => FilterOutcome::Timeout,
        other => FilterOutcome::Failed(other),
    }
}

/// A configured, exact readback: `want_enabled` decides Ok or Disabled.
fn configured_outcome(readback: &FilterReadback, want_enabled: bool) -> FilterOutcome {
    if !readback.configured {
        return FilterOutcome::NotConfigured;
    }
    if let Some(field) = readback.mismatch() {
        return FilterOutcome::FieldMismatch(field);
    }
    match (want_enabled, readback.enabled) {
        (true, true) | (false, false) => FilterOutcome::Ok,
        (true, false) => FilterOutcome::Disabled,
        (false, true) => FilterOutcome::FieldMismatch("enabled"),
    }
}

/// `--enable-filter`: the reloaded configuration is exact and enabled.
pub fn enable_outcome(readback: &FilterReadback) -> FilterOutcome {
    configured_outcome(readback, true)
}

/// `--disable-filter`: the reloaded configuration is exact and disabled.
pub fn disable_outcome(readback: &FilterReadback) -> FilterOutcome {
    configured_outcome(readback, false)
}

/// `--remove-filter`: nothing is configured after the removal.
pub fn remove_outcome(after: &FilterReadback) -> FilterOutcome {
    if after.configured {
        FilterOutcome::RemovalIncomplete
    } else {
        FilterOutcome::Ok
    }
}

/// What the provider's `filter-status` said, for `--filter-status`.
///
/// v29: the report's boxed `outbound` part took it 8 bytes past Clippy's
/// variant-size threshold; one value exists per `--filter-status` call, so
/// boxing the report (and every caller) would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterAttachment {
    /// The decoded report.
    Report(crate::provider_xpc::FilterStatusReport),
    /// The provider refused or its reply was malformed.
    Refused(String),
    /// No reply: the service is unavailable, its signer refused, or the
    /// bound passed.
    Unavailable(&'static str),
}

/// `--filter-status`: configured, exact, enabled, and the provider's filter
/// started in the provider process.
pub fn status_outcome(readback: &FilterReadback, attachment: &FilterAttachment) -> FilterOutcome {
    let configured = enable_outcome(readback);
    if configured != FilterOutcome::Ok {
        return configured;
    }
    match attachment {
        FilterAttachment::Report(report) if report.attached && report.pid_match => {
            FilterOutcome::Ok
        }
        FilterAttachment::Report(_) => FilterOutcome::NotAttached,
        FilterAttachment::Refused(_) => FilterOutcome::NotAttached,
        FilterAttachment::Unavailable(_) => FilterOutcome::ProviderUnavailable,
    }
}

/// The attachment fields of a `--filter-status` line.
pub fn attachment_fields(attachment: Option<&FilterAttachment>) -> String {
    match attachment {
        Some(FilterAttachment::Report(report)) => {
            let dropped: u64 = report
                .counters
                .iter()
                .filter(|(name, _)| name.starts_with("drop_"))
                .map(|(_, value)| *value)
                .sum();
            let allowed: u64 = report
                .counters
                .iter()
                .filter(|(name, _)| name.starts_with("allow_"))
                .map(|(_, value)| *value)
                .sum();
            let line = format!(
                "attached={} pid_match={} mode={} armed_token={} dropped={dropped} allowed={allowed}",
                report.attached,
                report.pid_match,
                report.mode,
                report
                    .armed_token
                    .map_or_else(|| "none".to_string(), |g| g.to_string()),
            );
            match &report.observability {
                Some(observed) => format!("{line} {}", observability_fields(observed)),
                None => line,
            }
        }
        Some(FilterAttachment::Refused(_)) => "attached=refused".into(),
        Some(FilterAttachment::Unavailable(_)) => "attached=unavailable".into(),
        None => "attached=unknown".into(),
    }
}

/// v27: the compact, address-free summary of the provider's
/// `observability` on the `--filter-status` line: arm accounting, drops by
/// interface class per direction, the ring's counts and its last four
/// records (`iface:dir:tcp:reason@ms`).
pub fn observability_fields(observed: &crate::provider_xpc::FilterObservability) -> String {
    let drops = |slot: usize| {
        observed
            .drops
            .iter()
            .map(|(class, row)| format!("{class}:{}", row[slot]))
            .collect::<Vec<_>>()
            .join(",")
    };
    let recent = observed
        .recent_drops
        .iter()
        .rev()
        .take(4)
        .map(|entry| {
            format!(
                "{}:{}:{}:{}@{}",
                entry.iface,
                entry.dir,
                entry.tcp,
                entry.reason.trim_start_matches("drop_"),
                entry.ms
            )
        })
        .collect::<Vec<_>>();
    let line = format!(
        "arm_seq={} disarms={} open_while_applied={} applied_epochs={} armed_ms_total={} armed_for_ms={} \
         primary_if={} in_drops={} out_drops={} any_drops={} ring=next:{},skipped:{},torn:{} recent={}",
        observed.arm_seq,
        observed.disarms,
        observed.open_while_applied,
        observed.applied_epochs,
        observed.armed_ms_total,
        observed
            .armed_for_ms
            .map_or_else(|| "none".to_string(), |ms| ms.to_string()),
        observed.primary_iface.as_deref().unwrap_or("none"),
        drops(0),
        drops(1),
        drops(2),
        observed.ring_next,
        observed.ring_skipped,
        observed.ring_torn,
        if recent.is_empty() {
            "none".to_string()
        } else {
            recent.join(";")
        },
    );
    match &observed.outbound {
        Some(outbound) => format!("{line} {}", outbound_fields(outbound)),
        None => line,
    }
}

/// v29 (S20h): the outbound part of the `--filter-status` line, after the
/// v27 fields: the non-zero outbound drops by `class:kind`, the marked ones
/// (`mark=sport`: the provider marks by TCP source port; the line never
/// names a port), the outbound ring's counts and its last four records
/// (`iface:tcp:reason@ms`, `:m` when marked).
pub fn outbound_fields(outbound: &crate::provider_xpc::OutboundObservability) -> String {
    let table = |rows: &[(String, [u64; 8])]| {
        let cells: Vec<String> = rows
            .iter()
            .flat_map(|(class, row)| {
                crate::leak_guard::OUT_KINDS
                    .iter()
                    .zip(row.iter())
                    .filter(|(_, n)| **n != 0)
                    .map(move |(kind, n)| format!("{class}:{}:{n}", kind.name()))
            })
            .collect();
        if cells.is_empty() {
            "none".to_string()
        } else {
            cells.join(",")
        }
    };
    let recent: Vec<String> = outbound
        .recent
        .iter()
        .rev()
        .take(4)
        .map(|out| {
            format!(
                "{}:{}:{}@{}{}",
                out.entry.iface,
                out.entry.tcp,
                out.entry.reason.trim_start_matches("drop_"),
                out.entry.ms,
                if out.marked { ":m" } else { "" }
            )
        })
        .collect();
    format!(
        "out_kinds={} out_marked={} mark=sport out_ring=next:{},skipped:{},torn:{} out_recent={}",
        table(&outbound.kinds),
        table(&outbound.marked),
        outbound.ring_next,
        outbound.ring_skipped,
        outbound.ring_torn,
        if recent.is_empty() {
            "none".to_string()
        } else {
            recent.join(";")
        },
    )
}

/// A `CFBundleVersion` under the packaging grammar
/// `[1-9][0-9]{0,8}(\.(0|[1-9][0-9]{0,8})){0,2}`, padded to three parts.
pub fn parse_bundle_version(text: &str) -> Option<[u32; 3]> {
    let mut parts = [0u32; 3];
    let mut count = 0;
    for (index, part) in text.split('.').enumerate() {
        if index >= 3
            || part.is_empty()
            || part.len() > 9
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
            || (index == 0 && part == "0")
        {
            return None;
        }
        parts[index] = part.parse().ok()?;
        count += 1;
    }
    (count > 0).then_some(parts)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplacementDecision {
    Replace,
    Cancel(&'static str),
}

impl ReplacementDecision {
    /// The `replacement_decision=` token: what the delegate answered, never
    /// whether Apple then replaced the active extension.
    fn token(self) -> &'static str {
        match self {
            ReplacementDecision::Replace => "replace",
            ReplacementDecision::Cancel(_) => "cancel",
        }
    }
}

/// Replace only this provider, only with a numerically newer CFBundleVersion.
/// Equal (Apple also asks for a CFBundleShortVersionString-only difference
/// and, in developer mode, always), lower, malformed or foreign: Cancel.
pub fn replacement_decision(
    existing_id: &str,
    existing_version: &str,
    incoming_id: &str,
    incoming_version: &str,
) -> ReplacementDecision {
    if existing_id != PROVIDER_ID || incoming_id != PROVIDER_ID {
        return ReplacementDecision::Cancel("replacement_identifier_mismatch");
    }
    let (Some(existing), Some(incoming)) = (
        parse_bundle_version(existing_version),
        parse_bundle_version(incoming_version),
    ) else {
        return ReplacementDecision::Cancel("replacement_version_invalid");
    };
    if incoming > existing {
        ReplacementDecision::Replace
    } else {
        ReplacementDecision::Cancel("replacement_version_not_newer")
    }
}

/// A value that can be printed as one `key=value` token, else `None`.
pub fn printable_token(text: &str) -> Option<&str> {
    (!text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
    .then_some(text)
}

fn token(text: &str) -> &str {
    printable_token(text).unwrap_or("unprintable")
}

/// The `--list` placeholder for a value that is absent or not printable.
pub const UNAVAILABLE: &str = "unavailable";

/// An NSUUID string (`8-4-4-4-12` uppercase hex), the scutil service id.
fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups.iter().all(|g| {
            g.bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
        })
}

/// One `--list` stdout line: a saved profile of this provider. A value that
/// is not printable (or is the placeholder itself) prints `unavailable`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileLine {
    pub index: usize,
    pub owner_generation: Option<String>,
    /// The scutil (`scutil --nc list`) service id; only an NSUUID string.
    pub scutil_service_id: Option<String>,
    pub intent_valid: bool,
    pub enabled: bool,
    pub on_demand_enabled: bool,
    pub native_vpn_status: isize,
}

impl ProfileLine {
    const KEYS: [&'static str; 7] = [
        "index",
        "owner_generation",
        "scutil_service_id",
        "intent_valid",
        "enabled",
        "on_demand_enabled",
        "native_vpn_status",
    ];

    pub fn format(&self) -> String {
        let shown = |value: Option<&str>, admit: fn(&str) -> bool| {
            value
                .filter(|v| *v != UNAVAILABLE && admit(v))
                .unwrap_or(UNAVAILABLE)
                .to_owned()
        };
        format!(
            "profile index={} owner_generation={} scutil_service_id={} intent_valid={} enabled={} on_demand_enabled={} native_vpn_status={}",
            self.index,
            shown(self.owner_generation.as_deref(), |v| printable_token(v).is_some()),
            shown(self.scutil_service_id.as_deref(), is_uuid),
            self.intent_valid,
            self.enabled,
            self.on_demand_enabled,
            self.native_vpn_status
        )
    }

    /// Parse one line exactly as `format` prints it: the `profile` word,
    /// then every key once, in order, nothing else.
    pub fn parse(line: &str) -> Result<Self, &'static str> {
        let mut words = line.split(' ');
        if words.next() != Some("profile") {
            return Err("profile_line_prefix");
        }
        let mut values = Vec::with_capacity(Self::KEYS.len());
        for key in Self::KEYS {
            let word = words.next().ok_or("profile_line_shape")?;
            let value = word
                .strip_prefix(key)
                .and_then(|rest| rest.strip_prefix('='))
                .ok_or("profile_line_shape")?;
            values.push(value);
        }
        if words.next().is_some() {
            return Err("profile_line_shape");
        }
        let flag = |text: &str| match text {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err("profile_line_value"),
        };
        let optional = |text: &str, admit: fn(&str) -> bool| match text {
            UNAVAILABLE => Ok(None),
            value if admit(value) => Ok(Some(value.to_owned())),
            _ => Err("profile_line_value"),
        };
        let number = |text: &str| -> Result<u64, &'static str> {
            if text.is_empty()
                || !text.bytes().all(|b| b.is_ascii_digit())
                || (text.len() > 1 && text.starts_with('0'))
            {
                return Err("profile_line_value");
            }
            text.parse().map_err(|_| "profile_line_value")
        };
        Ok(Self {
            index: usize::try_from(number(values[0])?).map_err(|_| "profile_line_value")?,
            owner_generation: optional(values[1], |v| printable_token(v).is_some())?,
            scutil_service_id: optional(values[2], is_uuid)?,
            intent_valid: flag(values[3])?,
            enabled: flag(values[4])?,
            on_demand_enabled: flag(values[5])?,
            native_vpn_status: isize::try_from(number(values[6])?)
                .map_err(|_| "profile_line_value")?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationOutcome {
    Completed,
    WillCompleteAfterReboot,
    /// Unknown finish result raw value or any non-cancel failure.
    Failed {
        domain: String,
        code: isize,
    },
    Cancelled {
        code: isize,
    },
    ReplacementDeclined {
        reason: &'static str,
        existing_version: String,
        incoming_version: String,
    },
    Timeout,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Declined {
    reason: &'static str,
    existing_version: String,
    incoming_version: String,
}

/// Delegate callbacks fold into one terminal outcome; the first terminal
/// callback wins and later ones are ignored.
#[derive(Debug, Default)]
pub struct ActivationTracker {
    needs_user_approval: bool,
    declined: Option<Declined>,
    /// The delegate's last answer; a decision, not an outcome.
    decision: Option<ReplacementDecision>,
    outcome: Option<ActivationOutcome>,
}

impl ActivationTracker {
    pub fn needs_user_approval(&mut self) {
        self.needs_user_approval = true;
    }

    /// Records and returns the replacement decision for Apple's delegate.
    pub fn replacement(
        &mut self,
        existing_id: &str,
        existing_version: &str,
        incoming_id: &str,
        incoming_version: &str,
    ) -> ReplacementDecision {
        let decision =
            replacement_decision(existing_id, existing_version, incoming_id, incoming_version);
        self.decision = Some(decision);
        match decision {
            ReplacementDecision::Replace => {
                self.declined = None;
            }
            ReplacementDecision::Cancel(reason) => {
                self.declined = Some(Declined {
                    reason,
                    existing_version: existing_version.to_owned(),
                    incoming_version: incoming_version.to_owned(),
                });
            }
        }
        decision
    }

    fn settle(&mut self, outcome: ActivationOutcome) -> bool {
        if self.outcome.is_some() {
            return false;
        }
        self.outcome = Some(outcome);
        true
    }

    /// `request:didFinishWithResult:`; true when this settled the request.
    pub fn finished(&mut self, raw_result: isize) -> bool {
        self.settle(match raw_result {
            RESULT_COMPLETED => ActivationOutcome::Completed,
            RESULT_WILL_COMPLETE_AFTER_REBOOT => ActivationOutcome::WillCompleteAfterReboot,
            other => ActivationOutcome::Failed {
                domain: "unknown_request_result".into(),
                code: other,
            },
        })
    }

    /// `request:didFailWithError:`; `system_extension_domain` is whether the
    /// error domain is `OSSystemExtensionErrorDomain`.
    pub fn failed(&mut self, system_extension_domain: bool, domain: &str, code: isize) -> bool {
        let outcome = if system_extension_domain && code == ERROR_REQUEST_CANCELED {
            match self.declined.clone() {
                Some(declined) => ActivationOutcome::ReplacementDeclined {
                    reason: declined.reason,
                    existing_version: declined.existing_version,
                    incoming_version: declined.incoming_version,
                },
                None => ActivationOutcome::Cancelled { code },
            }
        } else {
            ActivationOutcome::Failed {
                domain: domain.to_owned(),
                code,
            }
        };
        self.settle(outcome)
    }

    pub fn timed_out(&mut self) -> bool {
        self.settle(ActivationOutcome::Timeout)
    }

    pub fn outcome(&self) -> Option<&ActivationOutcome> {
        self.outcome.as_ref()
    }

    /// Exit code for the settled outcome; an unsettled request is a timeout.
    pub fn exit_code(&self) -> i32 {
        match self.outcome.as_ref().unwrap_or(&ActivationOutcome::Timeout) {
            ActivationOutcome::Completed => EXIT_ACTIVATION_COMPLETED,
            ActivationOutcome::WillCompleteAfterReboot => {
                EXIT_ACTIVATION_WILL_COMPLETE_AFTER_REBOOT
            }
            ActivationOutcome::Failed { .. } => EXIT_ACTIVATION_FAILED,
            ActivationOutcome::Cancelled { .. } => EXIT_ACTIVATION_CANCELLED,
            ActivationOutcome::ReplacementDeclined { .. } => EXIT_ACTIVATION_REPLACEMENT_DECLINED,
            ActivationOutcome::Timeout if self.needs_user_approval => {
                EXIT_ACTIVATION_TIMEOUT_AWAITING_APPROVAL
            }
            ActivationOutcome::Timeout => EXIT_ACTIVATION_TIMEOUT,
        }
    }

    /// One stdout line; a request result is not tunnel readiness.
    /// `replacement_decision` is the delegate's answer (`none` when Apple did
    /// not ask); only `activation_result=completed` (or
    /// `will_complete_after_reboot`) says Apple acted on a `replace`.
    pub fn report_line(&self) -> String {
        let outcome = self.outcome.as_ref().unwrap_or(&ActivationOutcome::Timeout);
        let (name, detail) = match outcome {
            ActivationOutcome::Completed => ("completed", String::new()),
            ActivationOutcome::WillCompleteAfterReboot => {
                ("will_complete_after_reboot", String::new())
            }
            ActivationOutcome::Failed { domain, code } => (
                "failed",
                format!(" error_domain={} error_code={code}", token(domain)),
            ),
            ActivationOutcome::Cancelled { code } => ("cancelled", format!(" error_code={code}")),
            ActivationOutcome::ReplacementDeclined {
                reason,
                existing_version,
                incoming_version,
            } => (
                "replacement_declined",
                format!(
                    " reason={reason} existing_version={} incoming_version={}",
                    token(existing_version),
                    token(incoming_version)
                ),
            ),
            ActivationOutcome::Timeout if self.needs_user_approval => {
                ("timeout_awaiting_approval", String::new())
            }
            ActivationOutcome::Timeout => ("timeout", String::new()),
        };
        format!(
            "activation_result={name} exit_code={} will_complete_after_reboot={} needs_user_approval={} replacement_decision={}{detail} tunnel_ready=unknown",
            self.exit_code(),
            matches!(outcome, ActivationOutcome::WillCompleteAfterReboot),
            self.needs_user_approval,
            self.decision.map_or("none", ReplacementDecision::token),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeactivationOutcome {
    Completed,
    WillCompleteAfterReboot,
    /// Unknown finish result raw value or any failure that is neither a
    /// cancel nor `ExtensionNotFound` in the system-extension domain.
    Failed {
        domain: String,
        code: isize,
    },
    Cancelled {
        code: isize,
    },
    /// Apple knows no such extension for this app. Never a completed
    /// deactivation: it does not say that nothing of this provider is active.
    NotFound {
        code: isize,
    },
    Timeout,
}

/// S21: the delegate callbacks of one `--deactivate` request fold into one
/// terminal outcome; the first terminal callback wins and later ones are
/// ignored. A deactivation has no replacement decision.
#[derive(Debug, Default)]
pub struct DeactivationTracker {
    needs_user_approval: bool,
    outcome: Option<DeactivationOutcome>,
}

impl DeactivationTracker {
    pub fn needs_user_approval(&mut self) {
        self.needs_user_approval = true;
    }

    fn settle(&mut self, outcome: DeactivationOutcome) -> bool {
        if self.outcome.is_some() {
            return false;
        }
        self.outcome = Some(outcome);
        true
    }

    /// `request:didFinishWithResult:`; true when this settled the request.
    pub fn finished(&mut self, raw_result: isize) -> bool {
        self.settle(match raw_result {
            RESULT_COMPLETED => DeactivationOutcome::Completed,
            RESULT_WILL_COMPLETE_AFTER_REBOOT => DeactivationOutcome::WillCompleteAfterReboot,
            other => DeactivationOutcome::Failed {
                domain: "unknown_request_result".into(),
                code: other,
            },
        })
    }

    /// `request:didFailWithError:`; `system_extension_domain` is whether the
    /// error domain is `OSSystemExtensionErrorDomain`.
    pub fn failed(&mut self, system_extension_domain: bool, domain: &str, code: isize) -> bool {
        self.settle(match (system_extension_domain, code) {
            (true, ERROR_REQUEST_CANCELED) => DeactivationOutcome::Cancelled { code },
            (true, ERROR_EXTENSION_NOT_FOUND) => DeactivationOutcome::NotFound { code },
            _ => DeactivationOutcome::Failed {
                domain: domain.to_owned(),
                code,
            },
        })
    }

    pub fn timed_out(&mut self) -> bool {
        self.settle(DeactivationOutcome::Timeout)
    }

    pub fn outcome(&self) -> Option<&DeactivationOutcome> {
        self.outcome.as_ref()
    }

    /// Exit code for the settled outcome; an unsettled request is a timeout.
    pub fn exit_code(&self) -> i32 {
        match self
            .outcome
            .as_ref()
            .unwrap_or(&DeactivationOutcome::Timeout)
        {
            DeactivationOutcome::Completed => EXIT_DEACTIVATION_COMPLETED,
            DeactivationOutcome::WillCompleteAfterReboot => {
                EXIT_DEACTIVATION_WILL_COMPLETE_AFTER_REBOOT
            }
            DeactivationOutcome::Failed { .. } => EXIT_DEACTIVATION_FAILED,
            DeactivationOutcome::Cancelled { .. } => EXIT_DEACTIVATION_CANCELLED,
            DeactivationOutcome::NotFound { .. } => EXIT_DEACTIVATION_NOT_FOUND,
            DeactivationOutcome::Timeout if self.needs_user_approval => {
                EXIT_DEACTIVATION_TIMEOUT_AWAITING_APPROVAL
            }
            DeactivationOutcome::Timeout => EXIT_DEACTIVATION_TIMEOUT,
        }
    }

    /// One stdout line. Only `deactivation_result=completed` says Apple
    /// deactivated the extension; `will_complete_after_reboot` leaves it
    /// running until the next boot.
    pub fn report_line(&self) -> String {
        let outcome = self
            .outcome
            .as_ref()
            .unwrap_or(&DeactivationOutcome::Timeout);
        let (name, detail) = match outcome {
            DeactivationOutcome::Completed => ("completed", String::new()),
            DeactivationOutcome::WillCompleteAfterReboot => {
                ("will_complete_after_reboot", String::new())
            }
            DeactivationOutcome::Failed { domain, code } => (
                "failed",
                format!(" error_domain={} error_code={code}", token(domain)),
            ),
            DeactivationOutcome::Cancelled { code } => ("cancelled", format!(" error_code={code}")),
            DeactivationOutcome::NotFound { code } => ("not_found", format!(" error_code={code}")),
            DeactivationOutcome::Timeout if self.needs_user_approval => {
                ("timeout_awaiting_approval", String::new())
            }
            DeactivationOutcome::Timeout => ("timeout", String::new()),
        };
        format!(
            "deactivation_result={name} exit_code={} will_complete_after_reboot={} needs_user_approval={}{detail}",
            self.exit_code(),
            matches!(outcome, DeactivationOutcome::WillCompleteAfterReboot),
            self.needs_user_approval,
        )
    }
}

/// The single stdout result of one bounded host verb. The completion and its
/// watchdog both claim it before printing and exiting; only the first claim
/// wins, so one run never prints two contradictory result lines.
#[derive(Debug, Default)]
pub struct ResultClaim(AtomicBool);

impl ResultClaim {
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// True exactly once; every later or concurrent caller gets false and
    /// must print nothing.
    pub fn claim(&self) -> bool {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

/// Whether a `--save-profile` refusal may leave a durable native profile.
/// Only refusals before `saveToPreferences` is dispatched are known unsaved.
pub fn save_refusal_may_be_durable(code: &str) -> bool {
    !matches!(
        code,
        "main_thread_required"
            | "profile_load_failed"
            | "profile_inventory_absent"
            | "existing_provider_profile_refused"
            | "multiple_provider_profiles_refused"
            | "existing_profile_not_idle"
            | "invalid_provider_identifier"
            | "wrong_provider_protocol"
    )
}

/// The stderr diagnostic of the six protocol flags a reload returned (S16d)
/// or `--list` read, in `configuration::FULLWIDE_FLAGS` order. Not a stdout
/// result line; `unavailable` when no provider protocol was read.
pub fn protocol_flags_text(flags: Option<[bool; 6]>) -> String {
    flags.map_or_else(
        || "flags=unavailable".to_string(),
        |f| {
            format!(
                "include_all={} exclude_local={} exclude_apns={} exclude_cellular={} exclude_device={} enforce_routes={}",
                f[0], f[1], f[2], f[3], f[4], f[5]
            )
        },
    )
}

/// The stderr line a save prints when the reloaded profile failed
/// verification after a reload that returned no error (`manager::
/// SaveFailure::reloaded_line`), so the installed run shows what macOS kept;
/// `flags=unavailable` when the reload returned no provider protocol.
pub fn reloaded_flags_line(owner_generation: &str, flags: Option<[bool; 6]>) -> String {
    format!(
        "reloaded_profile owner_generation={} {}",
        printable_token(owner_generation).unwrap_or(UNAVAILABLE),
        protocol_flags_text(flags)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        std::iter::once("aegis-ne-host")
            .chain(items.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn host_bundle_version_grammar_matches_packaging() {
        assert_eq!(parse_bundle_version("7"), Some([7, 0, 0]));
        assert_eq!(parse_bundle_version("1.2"), Some([1, 2, 0]));
        assert_eq!(parse_bundle_version("1.0.3"), Some([1, 0, 3]));
        assert_eq!(
            parse_bundle_version("999999999.999999999.999999999"),
            Some([999_999_999; 3])
        );
        for bad in [
            "",
            "0",
            "0.1",
            "01",
            "1.01",
            "1.",
            ".1",
            "1..2",
            "1.2.3.4",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1a",
            "1e3",
            "1000000000",
            "１",
            "1.2.x",
        ] {
            assert_eq!(parse_bundle_version(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn host_replacement_requires_numerically_newer_bundle_version() {
        let p = PROVIDER_ID;
        for (existing, incoming) in [("7", "8"), ("7", "7.0.1"), ("9", "10"), ("1.9", "1.10")] {
            assert_eq!(
                replacement_decision(p, existing, p, incoming),
                ReplacementDecision::Replace,
                "{existing} -> {incoming}"
            );
        }
        for (existing, incoming) in [("7", "7"), ("7", "7.0"), ("7.0.0", "7"), ("8", "7")] {
            assert_eq!(
                replacement_decision(p, existing, p, incoming),
                ReplacementDecision::Cancel("replacement_version_not_newer"),
                "{existing} -> {incoming}"
            );
        }
        // Numeric, not lexical: "10" > "9" and "1.10" > "1.9".
        assert_eq!(
            replacement_decision(p, "10", p, "9"),
            ReplacementDecision::Cancel("replacement_version_not_newer")
        );
        for (existing, incoming) in [("7", "8a"), ("x", "8"), ("7", ""), ("7", "08")] {
            assert_eq!(
                replacement_decision(p, existing, p, incoming),
                ReplacementDecision::Cancel("replacement_version_invalid")
            );
        }
        assert_eq!(
            replacement_decision("dev.aegis.macos.Other", "7", p, "8"),
            ReplacementDecision::Cancel("replacement_identifier_mismatch")
        );
        assert_eq!(
            replacement_decision(p, "7", "dev.aegis.macos.Other", "8"),
            ReplacementDecision::Cancel("replacement_identifier_mismatch")
        );
    }

    #[test]
    fn host_identity_replies_exit_nonzero_unless_key_material_is_gone() {
        use crate::identity_import::{ForgetReport, ImportReport};
        let import = |retired_removed| {
            Reply::Import(ImportReport {
                files: Vec::new(),
                retired_removed,
            })
        };
        let forget = |key_material_removed| {
            Reply::Forget(ForgetReport {
                identity_was_present: true,
                key_material_removed,
            })
        };
        assert_eq!(xpc_reply_exit(&import(true)), 0);
        assert_eq!(xpc_reply_exit(&forget(true)), 0);
        assert_eq!(xpc_reply_exit(&import(false)), EXIT_XPC_REMOVAL_INCOMPLETE);
        assert_eq!(xpc_reply_exit(&forget(false)), EXIT_XPC_REMOVAL_INCOMPLETE);
        assert_eq!(
            xpc_reply_exit(&Reply::Refused("session_live".into())),
            EXIT_XPC_REFUSED
        );
        // v30: the identity gate exits 0 only while open.
        let gate = |peer: &str, identity_rule: &str, proof_rule: &str, proof_probe: &str| {
            Reply::IdentityGate(crate::provider_xpc::IdentityGateReport {
                peer: peer.into(),
                identity_rule: identity_rule.into(),
                proof_rule: proof_rule.into(),
                proof_probe: proof_probe.into(),
            })
        };
        for identity_rule in ["admitted", "unregistered"] {
            assert_eq!(
                xpc_reply_exit(&gate("admitted", identity_rule, "admitted", "allowed")),
                0
            );
        }
        for closed in [
            gate("peer_not_admin", "admitted", "admitted", "allowed"),
            gate("admitted", "inadmissible", "admitted", "allowed"),
            gate("admitted", "unavailable", "admitted", "allowed"),
            gate("admitted", "admitted", "unexpected", "allowed"),
            gate("admitted", "admitted", "admitted", "denied"),
            gate("admitted", "admitted", "admitted", "failed"),
        ] {
            assert_eq!(xpc_reply_exit(&closed), EXIT_XPC_REFUSED, "{closed:?}");
        }
    }

    #[test]
    fn host_parses_lifecycle_verbs_and_refuses_variants() {
        let p = PROVIDER_ID;
        assert_eq!(parse_host_args(&argv(&["--list"])), Ok(HostCommand::List));
        assert_eq!(
            parse_host_args(&argv(&["--remove-profile"])),
            Ok(HostCommand::RemoveProfile)
        );
        assert_eq!(
            parse_host_args(&argv(&["--emergency-stop"])),
            Ok(HostCommand::EmergencyStop)
        );
        assert_eq!(
            parse_host_args(&argv(&["--ping"])),
            Ok(HostCommand::Xpc(Verb::Ping))
        );
        assert_eq!(
            parse_host_args(&argv(&["--status"])),
            Ok(HostCommand::Xpc(Verb::Status))
        );
        assert_eq!(
            parse_host_args(&argv(&["--forget-identity"])),
            Ok(HostCommand::Xpc(Verb::ForgetIdentity))
        );
        assert_eq!(
            parse_host_args(&argv(&["--profile-terms"])),
            Ok(HostCommand::Xpc(Verb::ProfileTerms))
        );
        assert_eq!(
            parse_host_args(&argv(&["--identity-gate"])),
            Ok(HostCommand::Xpc(Verb::IdentityGate))
        );
        assert!(USAGE.contains("--identity-gate"));
        assert_eq!(
            parse_host_args(&argv(&["--request-activation", p])),
            Ok(HostCommand::RequestActivation)
        );
        assert_eq!(
            parse_host_args(&argv(&["--save-profile", p, "192.0.2.1"])),
            Ok(HostCommand::SaveProfile {
                relay: "192.0.2.1".parse().unwrap(),
                replace_existing: false,
            })
        );
        for (flag, verb) in [
            ("--connect", OwnedVerb::Connect),
            ("--disconnect", OwnedVerb::Disconnect),
            ("--status", OwnedVerb::Status),
            ("--repair-runtime", OwnedVerb::RepairRuntime),
        ] {
            assert_eq!(
                parse_host_args(&argv(&[flag, p, "GEN-1", "2001:db8::1"])),
                Ok(HostCommand::Owned {
                    verb,
                    owner_generation: "GEN-1".into(),
                    relay: "2001:db8::1".parse().unwrap(),
                    window: WindowMode::Fixed,
                })
            );
        }
        let refused: &[&[&str]] = &[
            &[],
            &["--bogus"],
            &["--list", p],
            &["--remove-profile", p],
            &["--emergency-stop", p],
            &["--emergency-stop", p, "GEN-1", "192.0.2.1"],
            &["--request-activation"],
            &["--import-identity", "/Users/a/Aegis"],
            &["--forget-identity", "/a"],
            &["--profile-terms", p],
            &["--profile-terms", p, "GEN-1", "192.0.2.1"],
            &["--profile-terms", p, "192.0.2.1"],
            &["--forget-identity", "--remove-source"],
            &["--import"],
            &["--remove-source", "--import", "/a"],
            &["--request-activation", "dev.aegis.macos.Other"],
            &["--request-activation", p, "extra"],
            &["--save-profile", p],
            &["--save-profile", "dev.aegis.macos.Other", "192.0.2.1"],
            &["--save-profile", p, "relay.example"],
            &["--connect", p, "GEN-1"],
            &["--connect", "dev.aegis.macos.Other", "GEN-1", "192.0.2.1"],
            &["--connect", p, "", "192.0.2.1"],
            &["--connect", p, "GEN\n1", "192.0.2.1"],
            &["--connect", p, "GEN-1", "not-an-ip"],
            &["--remove-profile", p, "GEN-1", "192.0.2.1"],
            &["--list", p, "GEN-1", "192.0.2.1"],
        ];
        for args in refused {
            assert!(parse_host_args(&argv(args)).is_err(), "{args:?}");
        }
        let long = "G".repeat(129);
        assert!(parse_host_args(&argv(&["--status", p, &long, "192.0.2.1"])).is_err());
        let max = "G".repeat(128);
        assert!(parse_host_args(&argv(&["--status", p, &max, "192.0.2.1"])).is_ok());
    }

    /// S16d: `--replace-existing` only with `--save-profile`, at most once.
    #[test]
    fn host_save_profile_parses_an_optional_replace_existing() {
        let p = PROVIDER_ID;
        let save = |relay: &str, replace_existing| {
            Ok(HostCommand::SaveProfile {
                relay: relay.parse().unwrap(),
                replace_existing,
            })
        };
        assert_eq!(
            parse_host_args(&argv(&["--save-profile", p, "192.0.2.1"])),
            save("192.0.2.1", false)
        );
        for args in [
            &["--save-profile", p, "192.0.2.1", "--replace-existing"][..],
            &["--save-profile", p, "--replace-existing", "192.0.2.1"],
            &["--save-profile", "--replace-existing", p, "192.0.2.1"],
        ] {
            assert_eq!(
                parse_host_args(&argv(args)),
                save("192.0.2.1", true),
                "{args:?}"
            );
        }
        assert_eq!(
            parse_host_args(&argv(&["--save-profile", p, "::1", "--replace-existing"])),
            save("::1", true)
        );
        let x = "--replace-existing";
        for (args, code) in [
            (
                &["--save-profile", p, "192.0.2.1", x, x][..],
                "duplicate_flag",
            ),
            (&["--save-profile", x, p, x, "192.0.2.1"], "duplicate_flag"),
            (
                &["--save-profile", p, "192.0.2.1", "--save-profile"],
                "duplicate_flag",
            ),
            (
                &["--save-profile", p, "192.0.2.1", "--replace"],
                "unknown_flag",
            ),
            (
                &["--save-profile", p, "192.0.2.1", "--replace-existing=yes"],
                "unknown_flag",
            ),
            (
                &["--save-profile", p, "192.0.2.1", "--remove-source"],
                "unknown_flag",
            ),
            (&["--save-profile", p, x], "save_operands_required"),
            (&["--save-profile", x], "save_operands_required"),
            (&["--save-profile"], "save_operands_required"),
            (
                &["--save-profile", p, "192.0.2.1", "192.0.2.2"],
                "save_operands_required",
            ),
            (
                &["--save-profile", "dev.aegis.macos.Other", "192.0.2.1", x],
                "provider_id_mismatch",
            ),
            (
                &["--save-profile", p, "relay.example", x],
                "numeric_relay_required",
            ),
            (
                &["--save-profile", "192.0.2.1", p, x],
                "provider_id_mismatch",
            ),
        ] {
            assert_eq!(parse_host_args(&argv(args)), Err(code), "{args:?}");
        }
        // The flag belongs to no other verb.
        for args in [
            &[x][..],
            &[x, "--save-profile", p, "192.0.2.1"],
            &["--list", x],
            &["--remove-profile", x],
            &["--emergency-stop", x],
            &["--ping", x],
            &["--request-activation", p, x],
            &["--connect", p, "GEN-1", "192.0.2.1", x],
            &["--connect", p, x, "192.0.2.1"],
            &["--status", p, "GEN-1", x],
        ] {
            let parsed = parse_host_args(&argv(args));
            assert!(
                !matches!(parsed, Ok(HostCommand::SaveProfile { .. })),
                "{args:?}"
            );
            if !matches!(args, ["--connect", _, "--replace-existing", _]) {
                assert!(parsed.is_err(), "{args:?}");
            }
        }
    }

    /// S16d: the stderr flag diagnostics have one stable shape, shared by
    /// `--list` and a save whose reload failed verification.
    #[test]
    fn host_protocol_flag_diagnostics_format() {
        assert_eq!(
            protocol_flags_text(Some([false, false, true, true, true, false])),
            "include_all=false exclude_local=false exclude_apns=true exclude_cellular=true \
exclude_device=true enforce_routes=false"
        );
        assert_eq!(
            protocol_flags_text(Some(crate::configuration::FULLWIDE_FLAGS)),
            "include_all=true exclude_local=false exclude_apns=false exclude_cellular=false \
exclude_device=false enforce_routes=false"
        );
        assert_eq!(protocol_flags_text(None), "flags=unavailable");
        let line = reloaded_flags_line(
            "C21E2D4A-0000-4000-8000-000000000000",
            Some([false, false, true, true, true, false]),
        );
        assert_eq!(
            line,
            "reloaded_profile owner_generation=C21E2D4A-0000-4000-8000-000000000000 \
include_all=false exclude_local=false exclude_apns=true exclude_cellular=true \
exclude_device=true enforce_routes=false"
        );
        for (index, name) in [
            "include_all",
            "exclude_local",
            "exclude_apns",
            "exclude_cellular",
            "exclude_device",
            "enforce_routes",
        ]
        .into_iter()
        .enumerate()
        {
            let mut flags = [false; 6];
            flags[index] = true;
            let text = protocol_flags_text(Some(flags));
            assert!(text.contains(&format!("{name}=true")), "{text}");
            assert_eq!(text.matches("=true").count(), 1, "{text}");
        }
        // An unprintable generation is withheld, and the line stays one line.
        let hostile = reloaded_flags_line("gen\nwith space", None);
        assert_eq!(
            hostile,
            "reloaded_profile owner_generation=unavailable flags=unavailable"
        );
    }

    #[test]
    fn host_import_parses_one_dir_and_an_optional_remove_source() {
        let import = |dir: &str, remove_source| {
            Ok(HostCommand::Import {
                dir: dir.into(),
                remove_source,
            })
        };
        assert_eq!(
            parse_host_args(&argv(&["--import", "/Users/a/Aegis"])),
            import("/Users/a/Aegis", false)
        );
        assert_eq!(
            parse_host_args(&argv(&["--import", "/Users/a/Aegis", "--remove-source"])),
            import("/Users/a/Aegis", true)
        );
        assert_eq!(
            parse_host_args(&argv(&["--import", "--remove-source", "/Users/a/Aegis"])),
            import("/Users/a/Aegis", true)
        );
        for (args, code) in [
            (&["--import"][..], "import_dir_required"),
            (&["--import", "--remove-source"], "import_dir_required"),
            (
                &["--import", "relative/Aegis"],
                "import_dir_must_be_absolute",
            ),
            (&["--import", ""], "import_dir_must_be_absolute"),
            (&["--import", "/a", "/b"], "import_dir_repeated"),
            (
                &["--import", "/a", "--remove-source", "--remove-source"],
                "duplicate_flag",
            ),
            (&["--import", "/a", "--import", "/b"], "duplicate_flag"),
            (&["--import", "/a", "--remove"], "unknown_flag"),
            (&["--import", "/a", "--remove-source=yes"], "unknown_flag"),
            (&["--import", "/a", "-r"], "unknown_flag"),
            (&["--import", "/a", "--ping"], "unknown_flag"),
            (&["--import", "-/a"], "unknown_flag"),
            (&["--import-identity", "/a"], "unknown_command"),
            (&["--remove-source", "/a"], "unknown_command"),
        ] {
            assert_eq!(parse_host_args(&argv(args)), Err(code), "{args:?}");
        }
    }

    #[test]
    fn host_import_and_xpc_failures_have_distinct_exit_codes() {
        let codes = [
            0,
            EXIT_USAGE,
            EXIT_XPC_REFUSED,
            EXIT_IMPORT_SOURCE_REFUSED,
            EXIT_XPC_UNAVAILABLE,
            EXIT_IMPORT_SOURCE_NOT_REMOVED,
            EXIT_XPC_REMOVAL_INCOMPLETE,
            EXIT_XPC_TIMEOUT,
            EXIT_IMPORT_MANIFEST_MISMATCH,
            EXIT_IMPORT_COMMIT_UNKNOWN,
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
        assert_eq!(
            xpc_error_exit("import_reply_mismatch"),
            EXIT_IMPORT_MANIFEST_MISMATCH
        );
        for malformed in [
            "reply_malformed",
            "reply_verb_mismatch",
            "frame_oversized",
            "envelope_shape",
            "schema_mismatch",
        ] {
            assert_eq!(xpc_error_exit(malformed), EXIT_XPC_REFUSED, "{malformed}");
        }
        for unavailable in [
            "xpc_connection_invalid",
            "peer_requirement_not_set",
            "xpc_no_reply",
        ] {
            assert_eq!(
                xpc_error_exit(unavailable),
                EXIT_XPC_UNAVAILABLE,
                "{unavailable}"
            );
        }
    }

    #[test]
    fn host_activation_outcomes_have_distinct_exit_codes() {
        let codes = [
            EXIT_ACTIVATION_COMPLETED,
            EXIT_USAGE,
            EXIT_ACTIVATION_WILL_COMPLETE_AFTER_REBOOT,
            EXIT_ACTIVATION_FAILED,
            EXIT_ACTIVATION_CANCELLED,
            EXIT_ACTIVATION_REPLACEMENT_DECLINED,
            EXIT_ACTIVATION_TIMEOUT_AWAITING_APPROVAL,
            EXIT_ACTIVATION_TIMEOUT,
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
        assert_eq!(ACTIVATION_TIMEOUT_SECS, 120);

        let mut t = ActivationTracker::default();
        assert!(t.finished(0));
        assert_eq!(t.exit_code(), 0);
        assert!(t
            .report_line()
            .starts_with("activation_result=completed exit_code=0 "));
        // First terminal callback wins.
        assert!(!t.failed(true, "OSSystemExtensionErrorDomain", 1));
        assert!(!t.timed_out());
        assert_eq!(t.outcome(), Some(&ActivationOutcome::Completed));

        let mut t = ActivationTracker::default();
        t.finished(1);
        assert_eq!(t.exit_code(), EXIT_ACTIVATION_WILL_COMPLETE_AFTER_REBOOT);
        assert!(t.report_line().contains("will_complete_after_reboot=true"));

        let mut t = ActivationTracker::default();
        t.finished(7);
        assert_eq!(t.exit_code(), EXIT_ACTIVATION_FAILED);
        assert!(t
            .report_line()
            .contains("error_domain=unknown_request_result"));

        let mut t = ActivationTracker::default();
        t.failed(true, "OSSystemExtensionErrorDomain", 8);
        assert_eq!(t.exit_code(), EXIT_ACTIVATION_FAILED);
        assert!(t
            .report_line()
            .contains("error_domain=OSSystemExtensionErrorDomain error_code=8"));

        // Code 11 is a cancel only in the system-extension domain.
        let mut t = ActivationTracker::default();
        t.failed(false, "NSCocoaErrorDomain", 11);
        assert_eq!(t.exit_code(), EXIT_ACTIVATION_FAILED);
        let mut t = ActivationTracker::default();
        t.failed(true, "OSSystemExtensionErrorDomain", 11);
        assert_eq!(t.exit_code(), EXIT_ACTIVATION_CANCELLED);

        let mut t = ActivationTracker::default();
        assert_eq!(
            t.replacement(PROVIDER_ID, "8", PROVIDER_ID, "8"),
            ReplacementDecision::Cancel("replacement_version_not_newer")
        );
        t.failed(true, "OSSystemExtensionErrorDomain", 11);
        assert_eq!(t.exit_code(), EXIT_ACTIVATION_REPLACEMENT_DECLINED);
        assert!(t.report_line().contains(
            "reason=replacement_version_not_newer existing_version=8 incoming_version=8"
        ));

        let mut t = ActivationTracker::default();
        assert_eq!(
            t.replacement(PROVIDER_ID, "8", PROVIDER_ID, "9"),
            ReplacementDecision::Replace
        );
        t.finished(0);
        assert_eq!(t.exit_code(), 0);
        assert!(t.report_line().contains("replacement_decision=replace"));

        let mut t = ActivationTracker::default();
        assert!(t.timed_out());
        assert_eq!(t.exit_code(), EXIT_ACTIVATION_TIMEOUT);
        let mut t = ActivationTracker::default();
        t.needs_user_approval();
        // Unsettled reads as a timeout; approval selects its own code.
        assert_eq!(t.outcome(), None);
        assert_eq!(t.exit_code(), EXIT_ACTIVATION_TIMEOUT_AWAITING_APPROVAL);
        assert!(t.timed_out());
        assert_eq!(t.exit_code(), EXIT_ACTIVATION_TIMEOUT_AWAITING_APPROVAL);
        assert!(t
            .report_line()
            .contains("activation_result=timeout_awaiting_approval"));
        // Approval then completion is still completed.
        let mut t = ActivationTracker::default();
        t.needs_user_approval();
        t.finished(0);
        assert_eq!(t.exit_code(), 0);
        assert!(t.report_line().contains("needs_user_approval=true"));

        let mut t = ActivationTracker::default();
        t.failed(true, "bad domain\nline", 3);
        assert!(t.report_line().contains("error_domain=unprintable"));
        assert!(!t.report_line().contains('\n'));
    }

    /// S21: `--deactivate` alone or with this provider's id, nothing else.
    #[test]
    fn host_parses_deactivate_for_this_provider_only() {
        let p = PROVIDER_ID;
        assert_eq!(
            parse_host_args(&argv(&["--deactivate"])),
            Ok(HostCommand::Deactivate)
        );
        assert_eq!(
            parse_host_args(&argv(&["--deactivate", p])),
            Ok(HostCommand::Deactivate)
        );
        for (args, code) in [
            (
                &["--deactivate", "dev.aegis.macos.Other"][..],
                "provider_id_mismatch",
            ),
            (&["--deactivate", "dev.aegis.macos"], "provider_id_mismatch"),
            (&["--deactivate", ""], "provider_id_mismatch"),
            // uninstall-app.sh's parse-only capability probe (CAPABILITY_PROBE).
            (
                &["--deactivate", "capability-probe"],
                "provider_id_mismatch",
            ),
            (&["--deactivate", "--remove-source"], "provider_id_mismatch"),
            (&["--deactivate", p, "extra"], "unknown_command"),
            (&["--deactivate", p, p], "unknown_command"),
            (
                &["--deactivate", p, "GEN-1", "192.0.2.1"],
                "unknown_command",
            ),
            (&["--deactivation"], "unknown_command"),
            (&["--deactivate=yes"], "unknown_command"),
            (&[p, "--deactivate"], "unknown_command"),
        ] {
            assert_eq!(parse_host_args(&argv(args)), Err(code), "{args:?}");
        }
        // Activation never parses as a deactivation, nor the reverse.
        assert_eq!(
            parse_host_args(&argv(&["--request-activation", p])),
            Ok(HostCommand::RequestActivation)
        );
        assert!(parse_host_args(&argv(&["--request-activation"])).is_err());
        assert!(USAGE.contains("--deactivate [PROVIDER_ID]"));
    }

    #[test]
    fn host_deactivation_outcomes_have_distinct_exit_codes() {
        let deactivation = [
            EXIT_DEACTIVATION_COMPLETED,
            EXIT_DEACTIVATION_WILL_COMPLETE_AFTER_REBOOT,
            EXIT_DEACTIVATION_FAILED,
            EXIT_DEACTIVATION_CANCELLED,
            EXIT_DEACTIVATION_NOT_FOUND,
            EXIT_DEACTIVATION_TIMEOUT_AWAITING_APPROVAL,
            EXIT_DEACTIVATION_TIMEOUT,
        ];
        let others = [
            EXIT_USAGE,
            EXIT_ACTIVATION_WILL_COMPLETE_AFTER_REBOOT,
            EXIT_ACTIVATION_FAILED,
            EXIT_ACTIVATION_CANCELLED,
            EXIT_ACTIVATION_REPLACEMENT_DECLINED,
            EXIT_ACTIVATION_TIMEOUT_AWAITING_APPROVAL,
            EXIT_ACTIVATION_TIMEOUT,
            EXIT_XPC_REFUSED,
            EXIT_IMPORT_SOURCE_REFUSED,
            EXIT_XPC_UNAVAILABLE,
            EXIT_IMPORT_SOURCE_NOT_REMOVED,
            EXIT_XPC_REMOVAL_INCOMPLETE,
            EXIT_XPC_TIMEOUT,
            EXIT_IMPORT_MANIFEST_MISMATCH,
            EXIT_IMPORT_COMMIT_UNKNOWN,
        ];
        // Unique among themselves and disjoint from every other host code
        // (activation and XPC timeouts already share 75).
        let unique: std::collections::BTreeSet<_> = deactivation.iter().collect();
        assert_eq!(unique.len(), deactivation.len());
        let others: std::collections::BTreeSet<_> = others.iter().collect();
        for code in &deactivation[1..] {
            assert!(!others.contains(code), "{code}");
        }
        assert_eq!(EXIT_DEACTIVATION_COMPLETED, 0);
        assert_eq!(DEACTIVATION_TIMEOUT_SECS, 120);

        let settle = |f: &dyn Fn(&mut DeactivationTracker) -> bool| {
            let mut t = DeactivationTracker::default();
            assert!(f(&mut t));
            t
        };
        let t = settle(&|t| t.finished(0));
        assert_eq!(t.exit_code(), 0);
        assert_eq!(
            t.report_line(),
            "deactivation_result=completed exit_code=0 will_complete_after_reboot=false \
needs_user_approval=false"
        );
        let t = settle(&|t| t.finished(1));
        assert_eq!(t.exit_code(), EXIT_DEACTIVATION_WILL_COMPLETE_AFTER_REBOOT);
        assert!(t.report_line().starts_with(
            "deactivation_result=will_complete_after_reboot exit_code=20 will_complete_after_reboot=true "
        ));
        let t = settle(&|t| t.finished(7));
        assert_eq!(t.exit_code(), EXIT_DEACTIVATION_FAILED);
        assert!(t
            .report_line()
            .ends_with(" error_domain=unknown_request_result error_code=7"));
        // Cancel and not-found only in the system-extension domain.
        let t = settle(&|t| t.failed(true, "OSSystemExtensionErrorDomain", 11));
        assert_eq!(t.exit_code(), EXIT_DEACTIVATION_CANCELLED);
        assert!(t
            .report_line()
            .starts_with("deactivation_result=cancelled exit_code=22 "));
        let t = settle(&|t| t.failed(true, "OSSystemExtensionErrorDomain", 4));
        assert_eq!(t.exit_code(), EXIT_DEACTIVATION_NOT_FOUND);
        assert!(t
            .report_line()
            .starts_with("deactivation_result=not_found exit_code=23 "));
        for (domain, code) in [("NSCocoaErrorDomain", 11), ("NSCocoaErrorDomain", 4)] {
            let t = settle(&|t| t.failed(false, domain, code));
            assert_eq!(t.exit_code(), EXIT_DEACTIVATION_FAILED, "{domain} {code}");
            assert!(t
                .report_line()
                .contains(&format!("error_domain={domain} error_code={code}")));
        }
        for code in [1, 3, 8, 9, 10, 12, 13] {
            let t = settle(&|t| t.failed(true, "OSSystemExtensionErrorDomain", code));
            assert_eq!(t.exit_code(), EXIT_DEACTIVATION_FAILED, "{code}");
        }
        let t = settle(&|t| t.timed_out());
        assert_eq!(t.exit_code(), EXIT_DEACTIVATION_TIMEOUT);
        assert!(t
            .report_line()
            .starts_with("deactivation_result=timeout exit_code=25 "));

        // Approval pending: unsettled and timed out both read as awaiting.
        let mut t = DeactivationTracker::default();
        t.needs_user_approval();
        assert_eq!(t.outcome(), None);
        assert_eq!(t.exit_code(), EXIT_DEACTIVATION_TIMEOUT_AWAITING_APPROVAL);
        assert!(t.timed_out());
        assert_eq!(t.exit_code(), EXIT_DEACTIVATION_TIMEOUT_AWAITING_APPROVAL);
        assert!(t
            .report_line()
            .starts_with("deactivation_result=timeout_awaiting_approval exit_code=24 "));
        assert!(t.report_line().contains(" needs_user_approval=true"));
        // Approval, then completion, is completed.
        let mut t = DeactivationTracker::default();
        t.needs_user_approval();
        assert!(t.finished(0));
        assert_eq!(t.exit_code(), 0);
        assert!(t.report_line().contains(" needs_user_approval=true"));

        // The first terminal callback wins.
        let mut t = DeactivationTracker::default();
        assert!(t.failed(true, "OSSystemExtensionErrorDomain", 9));
        assert!(!t.finished(0));
        assert!(!t.timed_out());
        assert_eq!(t.exit_code(), EXIT_DEACTIVATION_FAILED);
        let mut t = DeactivationTracker::default();
        assert!(t.timed_out());
        assert!(!t.finished(0));
        assert_eq!(t.exit_code(), EXIT_DEACTIVATION_TIMEOUT);

        // A hostile domain stays one token on one line; never an activation line.
        let t = settle(&|t| t.failed(false, "bad domain\nline", 3));
        let line = t.report_line();
        assert!(line.contains("error_domain=unprintable"), "{line}");
        assert!(!line.contains('\n'));
        assert!(line.starts_with("deactivation_result=failed "), "{line}");
        assert!(!line.contains(" activation_result="), "{line}");
        assert!(!line.contains("replacement_decision="));
    }

    #[test]
    fn host_replacement_decision_is_never_reported_as_an_outcome() {
        let line = ActivationTracker::default().report_line();
        assert!(line.contains(" replacement_decision=none "), "{line}");

        // Replace, then Apple fails, cancels or never answers: the line keeps
        // the non-completed result and only names the delegate's decision.
        for (settle, result, exit) in [
            (0u8, "activation_result=failed ", EXIT_ACTIVATION_FAILED),
            (1, "activation_result=cancelled ", EXIT_ACTIVATION_CANCELLED),
            (2, "activation_result=timeout ", EXIT_ACTIVATION_TIMEOUT),
        ] {
            let mut t = ActivationTracker::default();
            assert_eq!(
                t.replacement(PROVIDER_ID, "8", PROVIDER_ID, "9"),
                ReplacementDecision::Replace
            );
            match settle {
                0 => assert!(t.failed(true, "OSSystemExtensionErrorDomain", 9)),
                1 => assert!(t.failed(true, "OSSystemExtensionErrorDomain", 11)),
                _ => assert!(t.timed_out()),
            }
            let line = t.report_line();
            assert_eq!(t.exit_code(), exit, "{line}");
            assert!(line.starts_with(result), "{line}");
            assert!(line.contains(" replacement_decision=replace "), "{line}");
            assert!(!line.contains("replaced="), "{line}");
        }

        let mut t = ActivationTracker::default();
        t.replacement(PROVIDER_ID, "9", PROVIDER_ID, "8");
        t.failed(true, "OSSystemExtensionErrorDomain", 11);
        assert!(t
            .report_line()
            .contains(" replacement_decision=cancel reason=replacement_version_not_newer "));
    }

    #[test]
    fn host_result_claim_admits_exactly_one_printer() {
        let claim = ResultClaim::new();
        assert!(claim.claim());
        assert!(!claim.claim());
        assert!(!claim.claim());

        // A completion and its watchdog racing: exactly one wins.
        for _ in 0..64 {
            let claim = std::sync::Arc::new(ResultClaim::new());
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
            let winners: usize = (0..8)
                .map(|_| {
                    let (claim, barrier) = (claim.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        usize::from(claim.claim())
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .sum();
            assert_eq!(winners, 1);
        }
    }

    #[test]
    fn host_printable_tokens_and_save_durability() {
        assert_eq!(
            printable_token("6B29FC40-CA47-1067-B31D-00DD010662DA"),
            Some("6B29FC40-CA47-1067-B31D-00DD010662DA")
        );
        for bad in ["", "a b", "a=b", "a\n", "é", &"a".repeat(129)] {
            assert_eq!(printable_token(bad), None, "{bad:?}");
        }
        for unsaved in [
            "main_thread_required",
            "profile_load_failed",
            "existing_provider_profile_refused",
            "multiple_provider_profiles_refused",
            "existing_profile_not_idle",
        ] {
            assert!(!save_refusal_may_be_durable(unsaved));
        }
        for unknown in [
            "operation_expired",
            "profile_save_failed",
            "saved_profile_generation_mismatch",
            "runtime_publication_failed",
            "profile_flags_not_persisted",
            "profile_reload_failed",
            "saved_profile_typed_intent_mismatch",
        ] {
            assert!(save_refusal_may_be_durable(unknown));
        }
    }

    #[test]
    fn host_list_lines_round_trip_and_refuse_variants() {
        let line = ProfileLine {
            index: 0,
            owner_generation: Some("6B29FC40-CA47-1067-B31D-00DD010662DA".into()),
            scutil_service_id: Some("0F5C4B6E-2D2A-4C1E-9B59-3A8E1D2C4B7F".into()),
            intent_valid: true,
            enabled: true,
            on_demand_enabled: false,
            native_vpn_status: 1,
        };
        let text = line.format();
        assert_eq!(
            text,
            "profile index=0 owner_generation=6B29FC40-CA47-1067-B31D-00DD010662DA \
scutil_service_id=0F5C4B6E-2D2A-4C1E-9B59-3A8E1D2C4B7F intent_valid=true enabled=true \
on_demand_enabled=false native_vpn_status=1"
        );
        assert_eq!(ProfileLine::parse(&text), Ok(line.clone()));
        let absent = ProfileLine {
            index: 12,
            owner_generation: None,
            scutil_service_id: None,
            intent_valid: false,
            enabled: false,
            on_demand_enabled: true,
            native_vpn_status: 0,
        };
        assert_eq!(ProfileLine::parse(&absent.format()), Ok(absent.clone()));
        assert!(absent.format().contains("owner_generation=unavailable"));
        // Unprintable values, a non-UUID service id or the placeholder
        // itself print as unavailable, never echoed.
        for (generation, service) in [
            ("gen with space", "not-a-uuid"),
            ("gen=x", "0f5c4b6e-2d2a-4c1e-9b59-3a8e1d2c4b7f"),
            (UNAVAILABLE, "0F5C4B6E-2D2A-4C1E-9B59-3A8E1D2C4B7"),
        ] {
            let hostile = ProfileLine {
                owner_generation: Some(generation.into()),
                scutil_service_id: Some(service.into()),
                ..line.clone()
            };
            let parsed = ProfileLine::parse(&hostile.format()).unwrap();
            assert_eq!(parsed.owner_generation, None, "{generation:?}");
            assert_eq!(parsed.scutil_service_id, None, "{service:?}");
        }
        let refused = [
            String::new(),
            text.replacen("profile ", "profiles ", 1),
            text.replacen("index=0", "index=00", 1),
            text.replacen("index=0", "index=-1", 1),
            text.replacen(" enabled=true", " enabled=yes", 1),
            text.replacen("intent_valid=true ", "", 1),
            format!("{text} extra=1"),
            text.replacen("native_vpn_status=1", "native_vpn_status=", 1),
            text.replacen("scutil_service_id=0F5C", "scutil_service_id=0f5c", 1),
            text.replacen("owner_generation=", "generation=", 1),
            text.replace(' ', "  "),
            {
                let mut swapped: Vec<&str> = text.split(' ').collect();
                swapped.swap(4, 5);
                swapped.join(" ")
            },
        ];
        for bad in &refused {
            assert!(ProfileLine::parse(bad).is_err(), "{bad:?}");
        }
    }

    /// S20b: the four filter verbs parse bare; any operand is
    /// `filter_operand_refused`, the code uninstall-app.sh probes for.
    #[test]
    fn host_parses_filter_verbs_bare_and_refuses_any_operand() {
        for (flag, command) in [
            ("--filter-status", HostCommand::FilterStatus),
            ("--enable-filter", HostCommand::EnableFilter),
            ("--disable-filter", HostCommand::DisableFilter),
            ("--remove-filter", HostCommand::RemoveFilter),
        ] {
            assert_eq!(parse_host_args(&argv(&[flag])), Ok(command), "{flag}");
            assert!(FILTER_FLAGS.contains(&flag));
            assert!(USAGE.contains(flag), "{flag}");
            for extra in [
                &["capability-probe"][..],
                &[PROVIDER_ID],
                &[flag],
                &["--remove-source"],
                &[PROVIDER_ID, "GEN-1", "192.0.2.1"],
            ] {
                let mut args = vec![flag];
                args.extend_from_slice(extra);
                assert_eq!(
                    parse_host_args(&argv(&args)),
                    Err(FILTER_OPERAND_REFUSED),
                    "{args:?}"
                );
            }
            // The flag is not a bare XPC verb: `--filter-status` also reads
            // NEFilterManager, so it never reaches the plain XPC dispatch.
            assert_eq!(Verb::from_flag(flag), None, "{flag}");
        }
        for args in [
            &["--filter-statuses"][..],
            &["--filter"],
            &["--enable-filter=yes"],
            &["--remove-filters"],
            &[PROVIDER_ID, "--remove-filter"],
        ] {
            assert_eq!(
                parse_host_args(&argv(args)),
                Err("unknown_command"),
                "{args:?}"
            );
        }
        // The deactivate probe keeps its own code.
        assert_eq!(
            parse_host_args(&argv(&["--deactivate", "capability-probe"])),
            Err("provider_id_mismatch")
        );
        assert_eq!(FILTER_OPERAND_REFUSED, "filter_operand_refused");
    }

    #[test]
    fn host_filter_exit_codes_differ_from_every_other_host_code() {
        let filter = [
            EXIT_FILTER_NOT_CONFIGURED,
            EXIT_FILTER_DISABLED,
            EXIT_FILTER_FIELD_MISMATCH,
            EXIT_FILTER_NOT_ATTACHED,
            EXIT_FILTER_FAILED,
            EXIT_FILTER_PERMISSION_DENIED,
            EXIT_FILTER_TIMEOUT,
            EXIT_FILTER_REMOVAL_INCOMPLETE,
        ];
        assert_eq!(filter, [30, 31, 32, 33, 34, 35, 36, 37]);
        let others = [
            0,
            EXIT_USAGE,
            EXIT_ACTIVATION_WILL_COMPLETE_AFTER_REBOOT,
            EXIT_ACTIVATION_FAILED,
            EXIT_ACTIVATION_CANCELLED,
            EXIT_ACTIVATION_REPLACEMENT_DECLINED,
            EXIT_ACTIVATION_TIMEOUT_AWAITING_APPROVAL,
            EXIT_ACTIVATION_TIMEOUT,
            EXIT_DEACTIVATION_WILL_COMPLETE_AFTER_REBOOT,
            EXIT_DEACTIVATION_FAILED,
            EXIT_DEACTIVATION_CANCELLED,
            EXIT_DEACTIVATION_NOT_FOUND,
            EXIT_DEACTIVATION_TIMEOUT_AWAITING_APPROVAL,
            EXIT_DEACTIVATION_TIMEOUT,
            EXIT_XPC_REFUSED,
            EXIT_IMPORT_SOURCE_REFUSED,
            EXIT_XPC_UNAVAILABLE,
            EXIT_IMPORT_SOURCE_NOT_REMOVED,
            EXIT_XPC_REMOVAL_INCOMPLETE,
            EXIT_XPC_TIMEOUT,
            EXIT_IMPORT_MANIFEST_MISMATCH,
            EXIT_IMPORT_COMMIT_UNKNOWN,
        ];
        let unique: std::collections::BTreeSet<_> = filter.iter().collect();
        assert_eq!(unique.len(), filter.len());
        for code in filter {
            assert!(!others.contains(&code), "{code}");
        }
        // Each outcome maps to its own code; only Ok is 0, and the provider
        // being unavailable keeps the XPC code.
        let outcomes = [
            FilterOutcome::Ok,
            FilterOutcome::NotConfigured,
            FilterOutcome::Disabled,
            FilterOutcome::FieldMismatch("grade"),
            FilterOutcome::NotAttached,
            FilterOutcome::ProviderUnavailable,
            FilterOutcome::PermissionDenied,
            FilterOutcome::Failed("filter_internal_error"),
            FilterOutcome::Timeout,
            FilterOutcome::RemovalIncomplete,
            FilterOutcome::AuthorizationRefused("filter_authorization_denied"),
        ];
        let exits: std::collections::BTreeSet<_> = outcomes.iter().map(|o| o.exit()).collect();
        assert_eq!(exits.len(), outcomes.len());
        let names: std::collections::BTreeSet<_> = outcomes.iter().map(|o| o.name()).collect();
        assert_eq!(names.len(), outcomes.len());
        assert_eq!(FilterOutcome::Ok.exit(), 0);
        assert_eq!(
            FilterOutcome::ProviderUnavailable.exit(),
            EXIT_XPC_UNAVAILABLE
        );
        assert_eq!(FilterOutcome::Ok.prefix(), "filter_result=ok exit_code=0");
        assert_eq!(
            FilterOutcome::NotConfigured.prefix(),
            "filter_result=not_configured exit_code=30"
        );
        assert_eq!(
            FilterOutcome::FieldMismatch("grade").detail(),
            Some("grade")
        );
        assert_eq!(FilterOutcome::Failed("x").detail(), Some("x"));
        assert_eq!(FilterOutcome::Disabled.detail(), None);
        assert_eq!((FILTER_VERB_SECS, FILTER_ENABLE_SECS), (30, 120));
        // v26: a refused administrator approval keeps the identity verbs'
        // code, names its refusal and never reads as a filter state.
        let refused = FilterOutcome::AuthorizationRefused("filter_authorization_cancelled");
        assert_eq!(refused.exit(), EXIT_AUTHORIZATION_REFUSED);
        assert_eq!(
            refused.prefix(),
            "filter_result=authorization_refused exit_code=67"
        );
        assert_eq!(refused.detail(), Some("filter_authorization_cancelled"));
    }

    /// v26 audit merge: only the verbs that weaken the leak guard need the
    /// administrator; reading and enabling it never prompt.
    #[test]
    fn filter_verbs_that_weaken_the_guard_need_an_administrator() {
        for (flag, required) in [
            ("--filter-status", false),
            ("--enable-filter", false),
            ("--disable-filter", true),
            ("--remove-filter", true),
        ] {
            let command = parse_host_args(&argv(&[flag])).expect(flag);
            assert_eq!(filter_requires_authorization(&command), required, "{flag}");
        }
        for command in [
            HostCommand::Xpc(Verb::Ping),
            HostCommand::RemoveProfile,
            HostCommand::EmergencyStop,
        ] {
            assert!(!filter_requires_authorization(&command), "{command:?}");
        }
    }

    fn reviewed() -> FilterReadback {
        FilterReadback {
            configured: true,
            enabled: true,
            filter_packets: true,
            filter_sockets: false,
            packet_bundle_id: Some(PROVIDER_ID.into()),
            data_bundle_id: None,
            server_address_set: false,
            organization_set: false,
            grade: FILTER_GRADE_FIREWALL,
            description: Some(FILTER_DESCRIPTION.into()),
        }
    }

    #[test]
    fn host_filter_readback_must_be_the_reviewed_configuration() {
        let exact = reviewed();
        assert_eq!(exact.mismatch(), None);
        assert_eq!(enable_outcome(&exact), FilterOutcome::Ok);
        assert_eq!(
            exact.fields(),
            "configured=true enabled=true filter_packets=true filter_sockets=false packet_bundle_id=match grade=firewall"
        );
        let cases: [(FilterReadback, &str); 9] = [
            (
                FilterReadback {
                    filter_packets: false,
                    ..reviewed()
                },
                "filter_packets",
            ),
            (
                FilterReadback {
                    filter_sockets: true,
                    ..reviewed()
                },
                "filter_sockets",
            ),
            (
                FilterReadback {
                    packet_bundle_id: None,
                    ..reviewed()
                },
                "packet_bundle_id",
            ),
            (
                FilterReadback {
                    packet_bundle_id: Some("dev.aegis.macos".into()),
                    ..reviewed()
                },
                "packet_bundle_id",
            ),
            (
                FilterReadback {
                    data_bundle_id: Some(PROVIDER_ID.into()),
                    ..reviewed()
                },
                "data_bundle_id",
            ),
            (
                FilterReadback {
                    server_address_set: true,
                    ..reviewed()
                },
                "server_address",
            ),
            (
                FilterReadback {
                    organization_set: true,
                    ..reviewed()
                },
                "organization",
            ),
            (
                FilterReadback {
                    grade: 2,
                    ..reviewed()
                },
                "grade",
            ),
            (
                FilterReadback {
                    description: None,
                    ..reviewed()
                },
                "description",
            ),
        ];
        for (readback, field) in &cases {
            assert_eq!(readback.mismatch(), Some(*field));
            assert_eq!(
                enable_outcome(readback),
                FilterOutcome::FieldMismatch(field)
            );
            assert_eq!(
                disable_outcome(readback),
                FilterOutcome::FieldMismatch(field)
            );
        }
        assert!(FilterReadback {
            grade: 2,
            ..reviewed()
        }
        .fields()
        .ends_with("grade=inspector"));
        assert!(FilterReadback {
            grade: 0,
            ..reviewed()
        }
        .fields()
        .ends_with("grade=other"));
        assert!(FilterReadback {
            packet_bundle_id: Some("x".into()),
            ..reviewed()
        }
        .fields()
        .contains("packet_bundle_id=mismatch"));
        let disabled = FilterReadback {
            enabled: false,
            ..reviewed()
        };
        assert_eq!(enable_outcome(&disabled), FilterOutcome::Disabled);
        assert_eq!(disable_outcome(&disabled), FilterOutcome::Ok);
        assert_eq!(
            disable_outcome(&exact),
            FilterOutcome::FieldMismatch("enabled")
        );
        let absent = FilterReadback::default();
        assert_eq!(enable_outcome(&absent), FilterOutcome::NotConfigured);
        assert_eq!(disable_outcome(&absent), FilterOutcome::NotConfigured);
        assert_eq!(remove_outcome(&absent), FilterOutcome::Ok);
        assert_eq!(remove_outcome(&exact), FilterOutcome::RemovalIncomplete);
        assert_eq!(remove_outcome(&disabled), FilterOutcome::RemovalIncomplete);
        assert!(absent
            .fields()
            .starts_with("configured=false enabled=false"));
        assert!(absent.fields().contains("packet_bundle_id=none"));
    }

    fn report(attached: bool, pid_match: bool) -> crate::provider_xpc::FilterStatusReport {
        crate::provider_xpc::FilterStatusReport {
            attached,
            pid_match,
            mode: "guarding".into(),
            armed_token: Some(3),
            relay_armed: true,
            authority_armed: true,
            udp_relay_allowed: false,
            counters: crate::leak_guard::COUNTED
                .iter()
                .enumerate()
                .map(|(i, r)| (r.name().to_string(), i as u64))
                .collect(),
            observability: None,
        }
    }

    #[test]
    fn host_filter_status_needs_an_exact_enabled_configuration_and_an_attached_filter() {
        let attached = FilterAttachment::Report(report(true, true));
        assert_eq!(status_outcome(&reviewed(), &attached), FilterOutcome::Ok);
        for attachment in [
            FilterAttachment::Report(report(false, false)),
            FilterAttachment::Report(report(true, false)),
            FilterAttachment::Refused("filter_status_unavailable".into()),
        ] {
            assert_eq!(
                status_outcome(&reviewed(), &attachment),
                FilterOutcome::NotAttached
            );
        }
        assert_eq!(
            status_outcome(
                &reviewed(),
                &FilterAttachment::Unavailable("xpc_connection_invalid")
            ),
            FilterOutcome::ProviderUnavailable
        );
        // The configuration is judged first.
        assert_eq!(
            status_outcome(&FilterReadback::default(), &attached),
            FilterOutcome::NotConfigured
        );
        assert_eq!(
            status_outcome(
                &FilterReadback {
                    enabled: false,
                    ..reviewed()
                },
                &attached
            ),
            FilterOutcome::Disabled
        );
        assert_eq!(
            status_outcome(
                &FilterReadback {
                    grade: 2,
                    ..reviewed()
                },
                &attached
            ),
            FilterOutcome::FieldMismatch("grade")
        );
        // The line: counters summed by verdict, never an address.
        let allowed: u64 = (0..11).sum();
        let dropped: u64 = (11..25).sum();
        assert_eq!(
            attachment_fields(Some(&attached)),
            format!("attached=true pid_match=true mode=guarding armed_token=3 dropped={dropped} allowed={allowed}")
        );
        assert_eq!(attachment_fields(None), "attached=unknown");
        assert_eq!(
            attachment_fields(Some(&FilterAttachment::Unavailable("x"))),
            "attached=unavailable"
        );
        assert_eq!(
            attachment_fields(Some(&FilterAttachment::Refused("x".into()))),
            "attached=refused"
        );
        let mut open = report(false, false);
        open.mode = "open".into();
        open.armed_token = None;
        assert!(
            attachment_fields(Some(&FilterAttachment::Report(open))).contains("armed_token=none")
        );
    }

    fn observed() -> crate::provider_xpc::FilterObservability {
        let entry = |index: u64, iface: &str, dir: &str, tcp: &str, reason: &str, ms: u64| {
            crate::provider_xpc::DropEntry {
                index,
                arm_seq: 2,
                ms,
                class: "primary".into(),
                iface: iface.into(),
                dir: dir.into(),
                family: "v4".into(),
                proto: 6,
                tcp: tcp.into(),
                reason: reason.into(),
            }
        };
        crate::provider_xpc::FilterObservability {
            arm_seq: 2,
            disarms: 1,
            armed_ms_total: 90_500,
            armed_for_ms: Some(4_000),
            open_while_applied: 0,
            applied_epochs: 1,
            primary_iface: Some("en7".into()),
            drops: crate::leak_guard::DROP_CLASSES
                .iter()
                .enumerate()
                .map(|(i, class)| (class.name().to_string(), [i as u64, 10 + i as u64, 0]))
                .collect(),
            ring_next: 15,
            ring_skipped: 0,
            ring_torn: 0,
            recent_drops: vec![
                entry(10, "en7", "out", "syn", "drop_tcp_out", 100),
                entry(11, "en0", "in", "ack_only", "drop_tcp_in", 110),
                entry(12, "awdl0", "out", "none", "drop_udp", 120),
                entry(13, "h:0badf00d", "any", "none", "drop_mdns", 130),
                entry(14, "en7", "out", "rst", "drop_tcp_out", 140),
            ],
            outbound: None,
        }
    }

    /// v27 (S20f): `--filter-status` appends the provider's observability as
    /// a compact, address-free summary; without it the line is unchanged.
    #[test]
    fn host_filter_status_line_summarizes_the_observability() {
        let fields = observability_fields(&observed());
        assert_eq!(
            fields,
            "arm_seq=2 disarms=1 open_while_applied=0 applied_epochs=1 armed_ms_total=90500 \
             armed_for_ms=4000 primary_if=en7 \
             in_drops=primary:0,en_other:1,awdl_llw:2,bridge_ap_anpi:3,other:4 \
             out_drops=primary:10,en_other:11,awdl_llw:12,bridge_ap_anpi:13,other:14 \
             any_drops=primary:0,en_other:0,awdl_llw:0,bridge_ap_anpi:0,other:0 \
             ring=next:15,skipped:0,torn:0 \
             recent=en7:out:rst:tcp_out@140;h:0badf00d:any:none:mdns@130;\
             awdl0:out:none:udp@120;en0:in:ack_only:tcp_in@110"
        );
        let mut open = observed();
        open.armed_for_ms = None;
        open.primary_iface = None;
        open.recent_drops.clear();
        let fields = observability_fields(&open);
        assert!(
            fields.contains(" armed_for_ms=none primary_if=none "),
            "{fields}"
        );
        assert!(fields.ends_with(" recent=none"), "{fields}");
        let plain = report(true, true);
        let mut with = plain.clone();
        with.observability = Some(observed());
        let base = attachment_fields(Some(&FilterAttachment::Report(plain)));
        assert_eq!(
            attachment_fields(Some(&FilterAttachment::Report(with))),
            format!("{base} {}", observability_fields(&observed()))
        );
        // Only stable tokens: no address can reach the line.
        assert!(fields
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" _:,;=@".contains(&b)));
    }

    /// v27: the install guide names every key of the observability reply.
    #[test]
    fn filter_docs_name_every_observability_key() {
        fn flat(text: &str) -> String {
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        }
        let install = flat(include_str!(
            "../../../../docs/platforms/macos/install-and-enable.md"
        ));
        let from = install
            .find("v27 (S20f) observability")
            .expect("observability section");
        let section = &install[from..];
        let mut with = report(true, true);
        with.observability = Some(observed());
        let bytes =
            crate::provider_xpc::encode_reply(&crate::provider_xpc::Reply::FilterStatus(with))
                .expect("encode");
        let reply: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let observability = reply["report"]["observability"]
            .as_object()
            .expect("observability");
        let ring = observability["ring"].as_object().expect("ring");
        let entry = ring["entries"][0].as_object().expect("entry");
        let keys: Vec<String> = observability
            .keys()
            .chain(ring.keys())
            .chain(entry.keys())
            .cloned()
            .chain(["in", "out", "any"].map(String::from))
            .collect();
        for key in keys {
            let named = format!("`{key}`");
            assert!(section.contains(&named), "{named}");
        }
        for class in crate::leak_guard::DROP_CLASSES {
            assert!(
                section.contains(&format!("`{}`", class.name())),
                "{class:?}"
            );
        }
    }

    /// v29 (S20h): a sample of the outbound observability.
    fn outbound() -> crate::provider_xpc::OutboundObservability {
        let mut kinds: Vec<(String, [u64; 8])> = crate::leak_guard::DROP_CLASSES
            .iter()
            .map(|class| (class.name().to_string(), [0; 8]))
            .collect();
        let mut marked = kinds.clone();
        kinds[0].1[2] = 64; // primary ack_only
        kinds[0].1[3] = 2; // primary data
        kinds[1].1[7] = 3; // en_other non_tcp
        marked[0].1[2] = 24;
        marked[0].1[3] = 2;
        let out = |index: u64, iface: &str, tcp: &str, reason: &str, ms: u64, marked: bool| {
            crate::provider_xpc::OutDropEntry {
                entry: crate::provider_xpc::DropEntry {
                    index,
                    arm_seq: 1,
                    ms,
                    class: "primary".into(),
                    iface: iface.into(),
                    dir: "out".into(),
                    family: "v4".into(),
                    proto: 6,
                    tcp: tcp.into(),
                    reason: reason.into(),
                },
                marked,
            }
        };
        crate::provider_xpc::OutboundObservability {
            mark_sport_first: crate::leak_guard::MARK_SPORT_FIRST,
            mark_sport_count: crate::leak_guard::MARK_SPORT_COUNT,
            kinds,
            marked,
            ring_next: 69,
            ring_skipped: 1,
            ring_torn: 0,
            recent: vec![
                out(64, "en0", "ack_only", "drop_tcp_out", 41_040, true),
                out(65, "en0", "ack_only", "drop_tcp_out", 42_580, false),
                out(66, "en0", "data", "drop_tcp_out", 42_661, true),
                out(67, "en5", "none", "drop_udp", 43_000, false),
                out(68, "en0", "ack_only", "drop_tcp_out", 45_040, true),
            ],
        }
    }

    /// v29 (S20h): the outbound drops follow the v27 fields on the line;
    /// a report without them prints the v27 line unchanged.
    #[test]
    fn host_filter_status_line_summarizes_the_outbound_drops() {
        assert_eq!(
            outbound_fields(&outbound()),
            "out_kinds=primary:ack_only:64,primary:data:2,en_other:non_tcp:3 \
             out_marked=primary:ack_only:24,primary:data:2 mark=sport \
             out_ring=next:69,skipped:1,torn:0 \
             out_recent=en0:ack_only:tcp_out@45040:m;en5:none:udp@43000;\
             en0:data:tcp_out@42661:m;en0:ack_only:tcp_out@42580"
        );
        let mut with = observed();
        with.outbound = Some(Box::new(outbound()));
        let fields = observability_fields(&with);
        assert_eq!(
            fields,
            format!(
                "{} {}",
                observability_fields(&observed()),
                outbound_fields(&outbound())
            )
        );
        assert!(fields
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" _:,;=@".contains(&b)));
        let mut quiet = outbound();
        for (_, row) in quiet.kinds.iter_mut().chain(quiet.marked.iter_mut()) {
            *row = [0; 8];
        }
        quiet.recent.clear();
        let quiet = outbound_fields(&quiet);
        assert!(quiet.starts_with("out_kinds=none out_marked=none mark=sport "));
        // The marker's ports stay out of the line.
        for port in [
            crate::leak_guard::MARK_SPORT_FIRST,
            crate::leak_guard::MARK_SPORT_FIRST + crate::leak_guard::MARK_SPORT_COUNT - 1,
        ] {
            assert!(!outbound_fields(&outbound()).contains(&port.to_string()));
        }
        assert!(quiet.ends_with(" out_recent=none"), "{quiet}");
    }

    /// v29: the install guide names every key of the outbound reply.
    #[test]
    fn filter_docs_name_every_outbound_key() {
        fn flat(text: &str) -> String {
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        }
        let install = flat(include_str!(
            "../../../../docs/platforms/macos/install-and-enable.md"
        ));
        let from = install
            .find("v29 (S20h) outbound observability")
            .expect("outbound section");
        let section = &install[from..];
        let mut observed = observed();
        observed.outbound = Some(Box::new(outbound()));
        let mut with = report(true, true);
        with.observability = Some(observed);
        let bytes =
            crate::provider_xpc::encode_reply(&crate::provider_xpc::Reply::FilterStatus(with))
                .expect("encode");
        let reply: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let outbound = reply["report"]["observability"]["outbound"]
            .as_object()
            .expect("outbound");
        let ring = outbound["ring"].as_object().expect("ring");
        let entry = ring["entries"][0].as_object().expect("entry");
        let keys: Vec<String> = ["outbound".to_string()]
            .into_iter()
            .chain(outbound.keys().cloned())
            .chain(ring.keys().cloned())
            .chain(entry.keys().cloned())
            .chain(
                crate::leak_guard::OUT_KINDS
                    .iter()
                    .map(|kind| kind.name().to_string()),
            )
            .collect();
        for key in keys {
            let named = format!("`{key}`");
            assert!(section.contains(&named), "{named}");
        }
        assert!(section.contains(&format!("`{}`", crate::leak_guard::MARK_SPORT_FIRST)));
        assert!(section.contains(&format!("`{}`", crate::leak_guard::MARK_SPORT_COUNT)));
        assert!(section.contains("`mark=sport`"));
    }

    #[test]
    fn host_filter_errors_map_to_stable_codes_and_outcomes() {
        for (code, name) in [
            (1, "filter_configuration_invalid"),
            (2, "filter_configuration_disabled"),
            (3, "filter_configuration_stale"),
            (4, "filter_configuration_cannot_be_removed"),
            (5, "filter_permission_denied"),
            (6, "filter_internal_error"),
            (0, "filter_error_unknown"),
            (7, "filter_error_unknown"),
        ] {
            assert_eq!(filter_error_code(true, code), name, "{code}");
            assert_eq!(
                filter_error_code(false, code),
                "filter_error_foreign_domain"
            );
        }
        assert_eq!(
            filter_failure("filter_permission_denied"),
            FilterOutcome::PermissionDenied
        );
        assert_eq!(filter_failure("operation_expired"), FilterOutcome::Timeout);
        assert_eq!(
            filter_failure("main_thread_required"),
            FilterOutcome::Failed("main_thread_required")
        );
        assert_eq!(
            filter_failure("filter_configuration_stale"),
            FilterOutcome::Failed("filter_configuration_stale")
        );
        // A foreign domain's code 5 is never a permission denial.
        assert_eq!(
            filter_failure(filter_error_code(false, 5)),
            FilterOutcome::Failed("filter_error_foreign_domain")
        );
    }

    /// v25 review: the macOS docs and the entrypoint notes state what
    /// `--filter-status` really exits with per filter state, its second
    /// stdout line and every filter verb's code, all derived from the
    /// host's own outcomes.
    #[test]
    fn filter_docs_match_the_host_filter_outcomes_per_state() {
        fn flat(text: &str) -> String {
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        }
        fn section<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
            let from = text.find(start).expect("section start");
            let rest = &text[from..];
            rest[start.len()..]
                .find(end)
                .map_or(rest, |to| &rest[..start.len() + to])
        }
        let code = |o: FilterOutcome| format!("{} `{}`", o.exit(), o.name());
        let limits = flat(include_str!(
            "../../../../docs/platforms/macos/known-limits.md"
        ));
        let install = flat(include_str!(
            "../../../../docs/platforms/macos/install-and-enable.md"
        ));
        let entry = flat(include_str!("bin/README.md"));

        let attachments = [
            FilterAttachment::Report(report(true, true)),
            FilterAttachment::Report(report(true, false)),
            FilterAttachment::Refused("filter_status_unavailable".into()),
            FilterAttachment::Unavailable("xpc_timeout"),
        ];
        let removed = FilterReadback::default();
        let disabled = FilterReadback {
            enabled: false,
            ..reviewed()
        };
        // A removed or disabled filter gives one outcome whatever the
        // provider would say (host.rs does not even ask it).
        let removed_exit = enable_outcome(&removed);
        let disabled_exit = enable_outcome(&disabled);
        for attachment in &attachments {
            assert_eq!(status_outcome(&removed, attachment), removed_exit);
            assert_eq!(status_outcome(&disabled, attachment), disabled_exit);
        }
        let not_attached = status_outcome(&reviewed(), &attachments[1]);
        assert_eq!(status_outcome(&reviewed(), &attachments[2]), not_attached);
        let unreachable = status_outcome(&reviewed(), &attachments[3]);
        let ok = status_outcome(&reviewed(), &attachments[0]);

        let tunnel = section(&limits, "**The tunnel does not require it.**", " - **");
        assert!(
            tunnel.contains(&format!(
                "`--filter-status` then exits {} (disabled) or {} (removed).",
                code(disabled_exit),
                code(removed_exit)
            )),
            "{tunnel}"
        );
        assert!(
            tunnel.contains(&format!(
                "Exit {} and {} arise only with an enabled filter.",
                code(not_attached),
                code(unreachable)
            )),
            "{tunnel}"
        );
        for (state, outcome) in [
            ("Removed or never saved", removed_exit),
            ("Saved but disabled", disabled_exit),
            (
                "Saved and enabled, filter not attached in the provider (or the provider refused)",
                not_attached,
            ),
            (
                "Saved and enabled, provider unreachable (no XPC reply)",
                unreachable,
            ),
            ("Saved, enabled and attached", ok),
        ] {
            let row = format!("| {state} | {} |", code(outcome));
            assert!(install.contains(&row), "{row}");
        }
        assert!(!install.contains("reports 31 (or 33"));
        assert!(!limits.contains("exits 31 or 33"));

        // The second stdout line: every key of the provider's reply.
        let filter = section(
            &install,
            "Each verb takes no operand",
            "The tunnel does not depend on the filter",
        );
        assert!(filter.contains(
            "When the provider answers, `--filter-status` prints a second line: the provider's JSON `filter-status` reply"
        ));
        assert!(filter.contains(
            "`dropped=` and `allowed=` on the first line are the sums of those `drop_*` and `allow_*` counters."
        ));
        let bytes = crate::provider_xpc::encode_reply(&crate::provider_xpc::Reply::FilterStatus(
            report(true, true),
        ))
        .expect("encode");
        let reply: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let keys = reply["report"].as_object().expect("report");
        assert!(keys.contains_key("counters"));
        for key in keys.keys().filter(|key| *key != "counters") {
            assert!(filter.contains(&format!("`{key}`")), "{key}");
        }
        for (name, _) in &report(true, true).counters {
            let named = if name.starts_with("drop_") {
                "`drop_*`".to_string()
            } else if name.starts_with("allow_") {
                "`allow_*`".to_string()
            } else {
                format!("`{name}`, which is not a verdict")
            };
            assert!(filter.contains(&named), "{name}");
        }

        // The entrypoint notes the page links to carry every filter verb,
        // bound and code.
        let s20b = section(&entry, "Since B-06 S20b", "Since B-06 S2");
        for flag in FILTER_FLAGS {
            assert!(filter_command(flag).is_some());
            assert!(s20b.contains(&format!("`{flag}`")), "{flag}");
        }
        assert!(s20b.contains(&format!("bounded at {FILTER_ENABLE_SECS} s")));
        assert!(s20b.contains(&format!("bounded at {FILTER_VERB_SECS} s")));
        assert!(s20b.contains("as a second line"));
        for outcome in [
            FilterOutcome::Ok,
            FilterOutcome::NotConfigured,
            FilterOutcome::Disabled,
            FilterOutcome::FieldMismatch("grade"),
            FilterOutcome::NotAttached,
            FilterOutcome::Failed("filter_internal_error"),
            FilterOutcome::PermissionDenied,
            FilterOutcome::Timeout,
            FilterOutcome::RemovalIncomplete,
            FilterOutcome::ProviderUnavailable,
            FilterOutcome::AuthorizationRefused("filter_authorization_denied"),
        ] {
            assert!(s20b.contains(&code(outcome)), "{}", code(outcome));
        }
        assert!(s20b.contains("A disabled or removed filter never gives 33 or 69"));
    }

    /// T23 (v35; v36, outcome `fixed`): the bare `--connect` is the
    /// product default, v33's fixed window; `--connect ... --window-policy
    /// adaptive` asks for the v35 window (a QA arm) and `--window-policy
    /// fixed` stays accepted. Every other spelling, value or place of the
    /// flag is refused, and no other verb takes it.
    #[test]
    fn host_connect_takes_the_window_policy_flag_only_as_its_declared_forms() {
        let p = PROVIDER_ID;
        for (value, window) in [
            ("fixed", WindowMode::Fixed),
            ("adaptive", WindowMode::Adaptive),
        ] {
            assert_eq!(
                parse_host_args(&argv(&[
                    "--connect",
                    p,
                    "GEN-1",
                    "192.0.2.1",
                    "--window-policy",
                    value
                ])),
                Ok(HostCommand::Owned {
                    verb: OwnedVerb::Connect,
                    owner_generation: "GEN-1".into(),
                    relay: "192.0.2.1".parse().unwrap(),
                    window,
                }),
                "{value}"
            );
        }
        assert_eq!(
            parse_host_args(&argv(&["--connect", p, "GEN-1", "192.0.2.1"])),
            Ok(HostCommand::Owned {
                verb: OwnedVerb::Connect,
                owner_generation: "GEN-1".into(),
                relay: "192.0.2.1".parse().unwrap(),
                window: WindowMode::Fixed,
            })
        );
        let refused: &[&[&str]] = &[
            &[
                "--connect",
                p,
                "GEN-1",
                "192.0.2.1",
                "--window-policy",
                "ADAPTIVE",
            ],
            &[
                "--connect",
                p,
                "GEN-1",
                "192.0.2.1",
                "--window-policy",
                "v35",
            ],
            &[
                "--connect",
                p,
                "GEN-1",
                "192.0.2.1",
                "--window-policy",
                "adaptive",
                "x",
            ],
            &[
                "--disconnect",
                p,
                "GEN-1",
                "192.0.2.1",
                "--window-policy",
                "adaptive",
            ],
            &[
                "--connect",
                p,
                "GEN-1",
                "192.0.2.1",
                "--window-policy",
                "FIXED",
            ],
            &["--connect", p, "GEN-1", "192.0.2.1", "--window-policy", ""],
            &["--connect", p, "GEN-1", "192.0.2.1", "--window-policy"],
            &[
                "--connect",
                p,
                "GEN-1",
                "192.0.2.1",
                "--window-policy",
                "fixed",
                "x",
            ],
            &[
                "--connect",
                p,
                "GEN-1",
                "192.0.2.1",
                "--window-policy=fixed",
            ],
            &[
                "--connect",
                "--window-policy",
                "fixed",
                p,
                "GEN-1",
                "192.0.2.1",
            ],
            &[
                "--connect",
                p,
                "GEN-1",
                "--window-policy",
                "fixed",
                "192.0.2.1",
            ],
            &[
                "--disconnect",
                p,
                "GEN-1",
                "192.0.2.1",
                "--window-policy",
                "fixed",
            ],
            &[
                "--status",
                p,
                "GEN-1",
                "192.0.2.1",
                "--window-policy",
                "fixed",
            ],
            &[
                "--repair-runtime",
                p,
                "GEN-1",
                "192.0.2.1",
                "--window-policy",
                "fixed",
            ],
            &["--save-profile", p, "192.0.2.1", "--window-policy", "fixed"],
            &["--window-policy", "fixed"],
        ];
        for args in refused {
            assert!(parse_host_args(&argv(args)).is_err(), "{args:?}");
        }
        // The operands are still checked in the long form.
        assert_eq!(
            parse_host_args(&argv(&[
                "--connect",
                "dev.aegis.macos.Other",
                "GEN-1",
                "192.0.2.1",
                "--window-policy",
                "fixed"
            ])),
            Err("provider_id_mismatch")
        );
        assert_eq!(
            parse_host_args(&argv(&[
                "--connect",
                p,
                "GEN-1",
                "not-an-ip",
                "--window-policy",
                "fixed"
            ])),
            Err("numeric_relay_required")
        );
        assert!(USAGE.contains("--window-policy adaptive|fixed"));
    }
}
