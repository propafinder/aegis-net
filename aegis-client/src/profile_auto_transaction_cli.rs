//! PRIVATE UNAPPLIED strict administrative AUTO transaction argument protocol.
//! No dynamic command/UID/hash/reference flag admission. Standalone `profile
//! auto` is unchanged; `profile auto-config` has a separate hidden dispatch.
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
const PROTOCOL: &str = "auto-config-snapshot-v2";
const REFUSED: &str = "Administrative AUTO transaction arguments refused";
type Result<T> = std::result::Result<T, String>;
fn refusal() -> String {
    REFUSED.into()
}
#[derive(clap::Args, Clone, Debug)]
pub(crate) struct Args {
    #[arg(trailing_var_arg=true,allow_hyphen_values=true,num_args=0..)]
    pub(crate) words: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExistingChoice {
    None,
    Upgrade,
    Reinstall,
}
pub(crate) use crate::profile_auto_runtime_identity::ServiceUser;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InspectField {
    ProductMode,
    UdpPolicy,
    DnsPolicy,
    Ipv6Policy,
    LeakRisk,
    PlanPath,
    RuntimeServicePolicy,
    RuntimeEventsPath,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerifyPhase {
    BeforeCustody,
    PublishedConfig,
    BeforeActivation,
}
#[derive(Clone, Debug)]
pub(crate) struct PrepareArgs {
    pub config_root: PathBuf,
    pub state_dir: PathBuf,
    pub metadata_dir: PathBuf,
    pub staging_parent: PathBuf,
    pub existing_choice: ExistingChoice,
    pub udp_carry: bool,
    pub bundle_dir: Option<PathBuf>,
    pub masque_server: Option<String>,
    pub masque_ca: Option<PathBuf>,
    pub wide_interface: Option<String>,
    pub public_payload_root: PathBuf,
    pub candidate_binary: PathBuf,
    pub installed_binary: PathBuf,
    pub runtime_events: PathBuf,
    pub source_manifest_url: Option<String>,
    pub source_release_channel: Option<String>,
    /// Production V2 only: fixed, root-owned pre-mutation stage handoff.
    pub prepare_handoff: Option<PathBuf>,
    /// Set by the closed boot-specific verb, never by a caller supplied flag.
    pub boot_successor: bool,
    /// Closed explicit product selector, bound into the private stage plan.
    pub requested_mode: Option<String>,
}
#[derive(Clone, Debug)]
pub(crate) enum CommandArgs {
    Inspect {
        stage: PathBuf,
        field: InspectField,
    },
    Verify {
        stage: PathBuf,
        phase: VerifyPhase,
    },
    BindRuntimeService {
        stage: PathBuf,
        service_user: ServiceUser,
    },
    CommitCustody {
        stage: PathBuf,
        service_user: ServiceUser,
        was_active: bool,
    },
    CommitState {
        stage: PathBuf,
    },
    CommitConfig {
        stage: PathBuf,
    },
    SealInstallReceipt {
        stage: PathBuf,
    },
    PublishServicePolicy {
        stage: PathBuf,
    },
    ReloadServicePolicy {
        stage: PathBuf,
    },
    PublishMetadata {
        stage: PathBuf,
    },
    BeginCapture {
        stage: PathBuf,
    },
    Finalize {
        stage: PathBuf,
    },
    Rollback {
        stage: PathBuf,
        capture_started: bool,
    },
}
#[derive(Clone, Debug)]
pub(crate) enum Parsed {
    Protocol,
    BeginBootSuccessor,
    CompleteBootPrepare,
    Worker {
        stage: PathBuf,
    },
    BeginStoppedSuccessor {
        candidate_binary: PathBuf,
        public_payload_root: PathBuf,
    },
    Prepare(Box<PrepareArgs>),
    Command(CommandArgs),
}
fn bounded_optional(
    map: &mut BTreeMap<String, String>,
    key: &str,
    max: usize,
) -> Result<Option<String>> {
    map.remove(key)
        .map(|v| {
            if scalar(&v, max) {
                Ok(v)
            } else {
                Err(refusal())
            }
        })
        .transpose()
}
fn scalar(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
fn path(s: String) -> Result<PathBuf> {
    if !scalar(&s, 4096) {
        return Err(refusal());
    }
    let p = PathBuf::from(s);
    if !p.is_absolute()
        || p == Path::new("/")
        || p.components()
            .any(|x| !matches!(x, Component::RootDir | Component::Normal(_)))
        || p.components().collect::<PathBuf>().as_os_str() != p.as_os_str()
    {
        return Err(refusal());
    }
    Ok(p)
}
fn flagmap(words: &[String]) -> Result<BTreeMap<String, String>> {
    if !words.len().is_multiple_of(2) {
        return Err(refusal());
    }
    let mut map = BTreeMap::new();
    for pair in words.chunks_exact(2) {
        if !pair[0].starts_with("--")
            || pair[0].len() > 32
            || pair[1].starts_with("--")
            || !scalar(&pair[1], 4096)
            || map.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(refusal());
        }
    }
    Ok(map)
}
fn take(map: &mut BTreeMap<String, String>, name: &str) -> Result<String> {
    map.remove(name).ok_or_else(refusal)
}
fn bit(value: String) -> Result<bool> {
    match value.as_str() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(refusal()),
    }
}
fn optional_path(map: &mut BTreeMap<String, String>, name: &str) -> Result<Option<PathBuf>> {
    map.remove(name).map(path).transpose()
}
fn endpoint(value: String) -> Result<String> {
    // Only lexical endpoint admission. Resolver observations belong to the
    // coordinator; parser neither resolves nor interprets this as an IP proof.
    if !scalar(&value, 255)
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'/' | b'\\' | b'@' | b'#' | b'?'))
    {
        return Err(refusal());
    }
    let (host, port) = value.rsplit_once(':').ok_or_else(refusal)?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refusal());
    }
    let port = port.parse::<u16>().map_err(|_| refusal())?;
    let valid_host = if host.starts_with('[') && host.ends_with(']') {
        host[1..host.len() - 1]
            .parse::<std::net::Ipv6Addr>()
            .is_ok()
    } else {
        !host.is_empty()
            && !host.contains(':')
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    };
    if !valid_host || port == 0 {
        return Err(refusal());
    }
    Ok(value)
}
fn interface(value: String) -> Result<String> {
    if value.len() > 15
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        Err(refusal())
    } else {
        Ok(value)
    }
}
pub(crate) fn parse(words: &[String]) -> Result<Parsed> {
    if words.is_empty()
        || words.len() > 40
        || words
            .iter()
            .try_fold(0usize, |n, s| n.checked_add(s.len()))
            .filter(|n| *n <= 32768)
            .is_none()
    {
        return Err(refusal());
    }
    let action = words[0].as_str();
    if action == "protocol" {
        return if words.len() == 1 {
            Ok(Parsed::Protocol)
        } else {
            Err(refusal())
        };
    }
    let mut map = flagmap(&words[1..])?;
    let parsed = if action == "begin-boot-successor" {
        Parsed::BeginBootSuccessor
    } else if action == "complete-boot-prepare" {
        Parsed::CompleteBootPrepare
    } else if action == "worker" {
        Parsed::Worker {
            stage: path(take(&mut map, "--stage")?)?,
        }
    } else if action == "begin-stopped-successor" {
        Parsed::BeginStoppedSuccessor {
            candidate_binary: path(take(&mut map, "--candidate-binary")?)?,
            public_payload_root: path(take(&mut map, "--public-payload-root")?)?,
        }
    } else if action == "prepare" || action == "prepare-boot-successor" {
        let args = PrepareArgs {
            config_root: path(take(&mut map, "--config-root")?)?,
            state_dir: path(take(&mut map, "--state-dir")?)?,
            metadata_dir: path(take(&mut map, "--metadata-dir")?)?,
            staging_parent: path(take(&mut map, "--staging-parent")?)?,
            existing_choice: match take(&mut map, "--existing-choice")?.as_str() {
                "none" => ExistingChoice::None,
                "upgrade" => ExistingChoice::Upgrade,
                "reinstall" => ExistingChoice::Reinstall,
                _ => return Err(refusal()),
            },
            udp_carry: bit(take(&mut map, "--udp-carry")?)?,
            bundle_dir: optional_path(&mut map, "--bundle-dir")?,
            masque_server: map.remove("--masque-server").map(endpoint).transpose()?,
            masque_ca: optional_path(&mut map, "--masque-ca")?,
            wide_interface: map.remove("--wide-interface").map(interface).transpose()?,
            public_payload_root: path(take(&mut map, "--public-payload-root")?)?,
            candidate_binary: path(take(&mut map, "--candidate-binary")?)?,
            installed_binary: path(take(&mut map, "--installed-binary")?)?,
            runtime_events: path(take(&mut map, "--runtime-events")?)?,
            source_manifest_url: bounded_optional(&mut map, "--source-manifest-url", 2048)?,
            source_release_channel: bounded_optional(&mut map, "--source-release-channel", 128)?,
            prepare_handoff: match optional_path(&mut map, "--prepare-handoff")? {
                Some(path)
                    if path == Path::new("/var/lib/aegis-auto/control/prepare-current.json") =>
                {
                    Some(path)
                }
                Some(_) => return Err(refusal()),
                None => None,
            },
            boot_successor: action == "prepare-boot-successor",
            requested_mode: match map.remove("--requested-mode") {
                Some(value) if value == "socks-only" => Some(value),
                Some(_) => return Err(refusal()),
                None => None,
            },
        };
        Parsed::Prepare(Box::new(args))
    } else {
        let stage = path(take(&mut map, "--stage")?)?;
        let args = match action {
            "inspect" => CommandArgs::Inspect {
                stage,
                field: match take(&mut map, "--field")?.as_str() {
                    "runtime-service-policy" => InspectField::RuntimeServicePolicy,
                    "runtime-events-path" => InspectField::RuntimeEventsPath,
                    "product-mode" => InspectField::ProductMode,
                    "udp-policy" => InspectField::UdpPolicy,
                    "dns-policy" => InspectField::DnsPolicy,
                    "ipv6-policy" => InspectField::Ipv6Policy,
                    "leak-risk" => InspectField::LeakRisk,
                    "plan-path" => InspectField::PlanPath,
                    _ => return Err(refusal()),
                },
            },
            "verify" => CommandArgs::Verify {
                stage,
                phase: match take(&mut map, "--phase")?.as_str() {
                    "before-custody" => VerifyPhase::BeforeCustody,
                    "published-config" => VerifyPhase::PublishedConfig,
                    "before-activation" => VerifyPhase::BeforeActivation,
                    _ => return Err(refusal()),
                },
            },
            "bind-runtime-service" => CommandArgs::BindRuntimeService {
                stage,
                service_user: match take(&mut map, "--service-user")?.as_str() {
                    "root" => ServiceUser::Root,
                    "aegis" => ServiceUser::Aegis,
                    "aegis-svc" => ServiceUser::AegisSvc,
                    _ => return Err(refusal()),
                },
            },
            "commit-custody" => CommandArgs::CommitCustody {
                stage,
                service_user: match take(&mut map, "--service-user")?.as_str() {
                    "root" => ServiceUser::Root,
                    "aegis" => ServiceUser::Aegis,
                    "aegis-svc" => ServiceUser::AegisSvc,
                    _ => return Err(refusal()),
                },
                was_active: bit(take(&mut map, "--was-active")?)?,
            },
            "commit-state" => CommandArgs::CommitState { stage },
            "commit-config" => CommandArgs::CommitConfig { stage },
            "seal-install-receipt" => CommandArgs::SealInstallReceipt { stage },
            "publish-service-policy" => CommandArgs::PublishServicePolicy { stage },
            "reload-service-policy" => CommandArgs::ReloadServicePolicy { stage },
            "publish-metadata" => CommandArgs::PublishMetadata { stage },
            "begin-capture" => CommandArgs::BeginCapture { stage },
            "finalize" => CommandArgs::Finalize { stage },
            "rollback" => CommandArgs::Rollback {
                stage,
                capture_started: bit(take(&mut map, "--capture-started")?)?,
            },
            _ => return Err(refusal()),
        };
        Parsed::Command(args)
    };
    if !map.is_empty() {
        return Err(refusal());
    }
    Ok(parsed)
}
#[cfg(target_os = "linux")]
fn administrator() -> bool {
    unsafe { libc::geteuid() == 0 }
}
#[cfg(not(target_os = "linux"))]
fn administrator() -> bool {
    false
}
pub(crate) fn inspect_scalar(field: InspectField, stage: &Path, value: &str) -> Result<()> {
    if !scalar(value, 4096) {
        return Err(refusal());
    }
    let accepted = match field {
        InspectField::RuntimeServicePolicy => {
            matches!(value, "root" | "dedicated-none" | "dedicated-bind")
        }
        InspectField::RuntimeEventsPath => fixed_runtime_events(value),
        InspectField::ProductMode => {
            matches!(value, "socks-only" | "wide-redirect-safe" | "full-wide-tun")
        }
        InspectField::UdpPolicy => matches!(
            value,
            "native" | "block" | "masque_direct" | "preview_allowlist"
        ),
        InspectField::DnsPolicy => matches!(value, "native" | "preview" | "block"),
        InspectField::Ipv6Policy => matches!(value, "native" | "block" | "capture" | "tun_carried"),
        InspectField::LeakRisk => matches!(value, "not_wide" | "low" | "high"),
        InspectField::PlanPath => {
            let p = path(value.to_owned())?;
            p.starts_with(stage)
                && p.file_name() == Some(std::ffi::OsStr::new("auto-install-plan.json"))
        }
    };
    if accepted {
        Ok(())
    } else {
        Err(refusal())
    }
}
pub(crate) fn fixed_runtime_events(value: &str) -> bool {
    matches!(
        value,
        "/dev/null"
            | "/var/lib/aegis-client-logs/root/runtime-events.jsonl"
            | "/var/lib/aegis-client-logs/service/runtime-events.jsonl"
            | "/var/log/aegis-client/runtime/runtime-events.jsonl"
    )
}
pub(crate) fn run(words: &[String]) -> Result<()> {
    let args = parse(words)?;
    if matches!(args, Parsed::Protocol) {
        println!("{PROTOCOL}");
        return Ok(());
    }
    if !administrator() {
        return Err("Administrative AUTO transaction requires Linux root authority".into());
    }
    match args {
        Parsed::Protocol => unreachable!("handled protocol"),
        Parsed::BeginBootSuccessor => {
            use std::io::Write;
            let bytes = crate::profile_auto_transaction::begin_boot_successor()
                .map_err(|_| "Administrative AUTO boot successor refused".to_string())?;
            std::io::stdout().write_all(&bytes).map_err(|_| refusal())
        }
        Parsed::CompleteBootPrepare => {
            let stage = crate::profile_auto_transaction::complete_boot_prepare_after_crash()
                .map_err(|_| "Administrative AUTO boot Prepare recovery refused".to_string())?;
            let text = stage.to_str().ok_or_else(refusal)?;
            path(text.to_owned())?;
            println!("{text}");
            Ok(())
        }
        Parsed::Worker { stage } => crate::profile_auto_transaction::worker(&stage),
        Parsed::BeginStoppedSuccessor {
            candidate_binary,
            public_payload_root,
        } => {
            use std::io::Write;
            let bytes = crate::profile_auto_transaction::begin_stopped_successor(
                &candidate_binary,
                &public_payload_root,
            )
            .map_err(|_| "Administrative AUTO successor refused".to_string())?;
            std::io::stdout().write_all(&bytes).map_err(|_| refusal())
        }
        Parsed::Prepare(args) => {
            let parent = args.staging_parent.clone();
            let held_lock = if args.prepare_handoff.is_some() {
                Some(
                    crate::profile_auto_stopped_service::InstallLock::acquire()
                        .map_err(|_| refusal())?,
                )
            } else {
                None
            };
            let staged = crate::profile_auto_transaction::prepare(*args, held_lock.as_ref())
                .map_err(|_| "Administrative AUTO transaction preparation refused".to_string())?;
            if staged.parent() != Some(parent.as_path()) {
                return Err(refusal());
            }
            let text = staged.to_str().ok_or_else(refusal)?;
            path(text.to_owned())?;
            if let Some(lock) = held_lock.as_ref() {
                lock.revalidate().map_err(|_| refusal())?;
            }
            println!("{text}");
            Ok(())
        }
        Parsed::Command(args) => {
            let getter = match &args {
                CommandArgs::Inspect { stage, field } => Some((stage.clone(), *field)),
                _ => None,
            };
            let result = crate::profile_auto_transaction::command(args)
                .map_err(|_| "Administrative AUTO transaction phase refused".to_string())?;
            match (getter, result) {
                (Some((stage, field)), Some(value)) => {
                    inspect_scalar(field, &stage, &value)?;
                    println!("{value}");
                    Ok(())
                }
                (None, None) => Ok(()),
                _ => Err(refusal()),
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }
    fn fresh() -> Vec<String> {
        words("prepare --config-root /etc/aegis --state-dir /var/lib/aegis --metadata-dir /var/lib/aegis-admin --staging-parent /run/aegis-installer-config-snapshots --existing-choice none --udp-carry 0 --bundle-dir /opt/private-bundle --public-payload-root /opt/public-release --candidate-binary /opt/public-release/aegis-client --installed-binary /usr/local/bin/aegis-client --runtime-events /var/log/aegis-client/runtime-events.jsonl")
    }
    #[test]
    fn inspect_prepared_runtime_path_accepts_only_one_scalar_field() {
        assert!(matches!(
            parse(&words(
                "inspect --stage /run/private-stage --field runtime-events-path"
            ))
            .unwrap(),
            Parsed::Command(CommandArgs::Inspect {
                field: InspectField::RuntimeEventsPath,
                ..
            })
        ));
        assert!(parse(&words("inspect --stage /run/private-stage --field runtime-events-path --runtime-events /tmp/foreign")).is_err());
        for accepted in [
            "/dev/null",
            "/var/lib/aegis-client-logs/root/runtime-events.jsonl",
            "/var/lib/aegis-client-logs/service/runtime-events.jsonl",
        ] {
            assert!(inspect_scalar(
                InspectField::RuntimeEventsPath,
                Path::new("/run/private-stage"),
                accepted
            )
            .is_ok());
        }
        for refused in [
            "/tmp/events",
            "/var/lib/aegis-client-logs/runtime/runtime-events.jsonl",
            "relative",
            "/dev/null\n",
        ] {
            assert!(inspect_scalar(
                InspectField::RuntimeEventsPath,
                Path::new("/run/private-stage"),
                refused
            )
            .is_err());
        }
    }
    #[test]
    fn shell_prepare_flags_parse_and_three_existing_choices() {
        for choice in ["none", "upgrade", "reinstall"] {
            let mut v = fresh();
            v[10] = choice.into();
            assert!(matches!(parse(&v).unwrap(), Parsed::Prepare(_)));
        }
    }
    #[test]
    fn prepare_requires_runtime_events_path() {
        let mut v = fresh();
        let flag = v
            .iter()
            .position(|word| word == "--runtime-events")
            .unwrap();
        v.drain(flag..flag + 2);
        assert_eq!(parse(&v).unwrap_err(), REFUSED);
    }
    #[test]
    fn successor_parser_never_accepts_stage_hash_or_force_authority() {
        let good = words("begin-stopped-successor --candidate-binary /var/lib/aegis-auto/releases/next/bin/aegis-client --public-payload-root /var/lib/aegis-auto/releases/next");
        assert!(matches!(
            parse(&good).unwrap(),
            Parsed::BeginStoppedSuccessor { .. }
        ));
        for tail in [
            "--stage /run/foreign",
            "--force 1",
            "--stopped-sha deadbeef",
            "--candidate-binary /other/bin/aegis-client",
        ] {
            let mut altered = good.clone();
            altered.extend(words(tail));
            assert!(parse(&altered).is_err());
        }
    }
    #[test]
    fn boot_successor_has_no_caller_path_hash_or_boot_authority() {
        assert!(matches!(
            parse(&words("begin-boot-successor")).unwrap(),
            Parsed::BeginBootSuccessor
        ));
        assert!(matches!(
            parse(&words("complete-boot-prepare")).unwrap(),
            Parsed::CompleteBootPrepare
        ));
        for tail in [
            "--stage /run/old",
            "--boot-id old",
            "--force 1",
            "--candidate-binary /old",
        ] {
            assert!(parse(&words(&format!("begin-boot-successor {tail}"))).is_err());
            assert!(parse(&words(&format!("complete-boot-prepare {tail}"))).is_err());
        }
    }
    #[test]
    fn production_prepare_handoff_has_one_fixed_control_leaf() {
        let mut accepted = fresh();
        accepted.extend(words(
            "--prepare-handoff /var/lib/aegis-auto/control/prepare-current.json",
        ));
        let Parsed::Prepare(args) = parse(&accepted).unwrap() else {
            panic!("expected prepare");
        };
        assert_eq!(
            args.prepare_handoff.as_deref(),
            Some(Path::new(
                "/var/lib/aegis-auto/control/prepare-current.json"
            ))
        );
        assert!(!args.boot_successor);
        let mut boot = accepted.clone();
        boot[0] = "prepare-boot-successor".into();
        let Parsed::Prepare(boot_args) = parse(&boot).unwrap() else {
            panic!("expected boot prepare");
        };
        assert!(boot_args.boot_successor);
        assert_eq!(boot_args.prepare_handoff, args.prepare_handoff);
        let mut caller_flag = accepted.clone();
        caller_flag.extend(words("--boot-successor 1"));
        assert!(parse(&caller_flag).is_err());
        for leaf in [
            "/tmp/prepare-current.json",
            "/var/lib/aegis-auto/control/prepare-completed.json",
            "/var/lib/aegis-auto/control/../control/prepare-current.json",
        ] {
            let mut refused = fresh();
            refused.extend(words(&format!("--prepare-handoff {leaf}")));
            assert!(parse(&refused).is_err());
        }
    }
    #[test]
    fn prepare_explicit_socks_selector_is_closed() {
        let mut accepted = fresh();
        accepted.extend(words("--requested-mode socks-only"));
        let Parsed::Prepare(args) = parse(&accepted).unwrap() else {
            panic!("expected prepare");
        };
        assert_eq!(args.requested_mode.as_deref(), Some("socks-only"));
        for bad in [
            "full-wide-tun",
            "wide-redirect-safe",
            "legacy-socks",
            "auto",
        ] {
            let mut rejected = fresh();
            rejected.extend(words(&format!("--requested-mode {bad}")));
            assert!(parse(&rejected).is_err());
        }
    }
    #[test]
    fn runtime_binding_names_are_closed_and_uid_claims_refused() {
        for user in ["root", "aegis", "aegis-svc"] {
            assert!(matches!(
                parse(&words(&format!(
                    "bind-runtime-service --stage /run/private --service-user {user}"
                )))
                .unwrap(),
                Parsed::Command(CommandArgs::BindRuntimeService { .. })
            ));
        }
        for args in [
            "--service-user arbitrary",
            "--service-user 997",
            "--service-user aegis --uid 997",
            "--service-user aegis --gid 997",
        ] {
            assert!(parse(&words(&format!(
                "bind-runtime-service --stage /run/private {args}"
            )))
            .is_err());
        }
    }
    #[test]
    fn protocol_has_no_flags_or_nonroot_mutation() {
        assert!(matches!(
            parse(&words("protocol")).unwrap(),
            Parsed::Protocol
        ));
        assert!(parse(&words("protocol --stage /tmp/x")).is_err());
    }
    #[test]
    fn all_phase_commands_have_closed_required_fields() {
        for s in [
            "inspect --stage /run/private --field product-mode",
            "verify --stage /run/private --phase before-custody",
            "verify --stage /run/private --phase published-config",
            "commit-custody --stage /run/private --service-user root --was-active 0",
            "commit-state --stage /run/private",
            "commit-config --stage /run/private",
            "publish-metadata --stage /run/private",
            "begin-capture --stage /run/private",
            "finalize --stage /run/private",
            "rollback --stage /run/private --capture-started 1",
        ] {
            assert!(matches!(parse(&words(s)).unwrap(), Parsed::Command(_)));
        }
    }
    #[test]
    fn duplicate_unknown_missing_flags_and_paths_refuse() {
        let mut v = fresh();
        v.extend(words("--state-dir /var/lib/other"));
        assert!(parse(&v).is_err());
        for extra in [
            "--uid 0",
            "--hash abc",
            "--reference /etc/secret",
            "--json 1",
        ] {
            let mut v = fresh();
            v.extend(words(extra));
            assert!(parse(&v).is_err());
        }
        assert!(parse(&words("commit-config --stage")).is_err());
        assert!(parse(&words("commit-config --stage relative")).is_err());
        assert!(parse(&words("commit-config --stage /run/../tmp/private")).is_err());
    }
    #[test]
    fn unsupported_getters_users_modes_and_bit_values_refuse() {
        for s in [
            "inspect --stage /run/private --field token",
            "verify --stage /run/private --phase any",
            "commit-custody --stage /run/private --service-user daemon --was-active 1",
            "commit-custody --stage /run/private --service-user aegis --was-active true",
            "rollback --stage /run/private --capture-started 2",
        ] {
            assert!(parse(&words(s)).is_err());
        }
        let mut v = fresh();
        v[10] = "purge".into();
        assert!(parse(&v).is_err());
    }
    #[test]
    fn scalar_output_never_accepts_secret_or_multiline_dump() {
        assert!(inspect_scalar(
            InspectField::ProductMode,
            Path::new("/run/private"),
            "full-wide-tun"
        )
        .is_ok());
        assert!(inspect_scalar(
            InspectField::ProductMode,
            Path::new("/run/private"),
            "token=secret"
        )
        .is_err());
        assert!(inspect_scalar(
            InspectField::LeakRisk,
            Path::new("/run/private"),
            "low\nsecret"
        )
        .is_err());
        assert!(inspect_scalar(
            InspectField::PlanPath,
            Path::new("/run/private"),
            "/etc/auto-install-plan.json"
        )
        .is_err());
    }
    #[test]
    fn endpoint_admission_is_lexical_and_keeps_ipv6_masque() {
        assert!(endpoint("[2001:db8::1]:443".into()).is_ok());
        assert!(endpoint("relay.example:443".into()).is_ok());
        assert!(endpoint("relay.example:+443".into()).is_err());
        assert!(endpoint("https://relay.example:443".into()).is_err());
    }
    #[test]
    fn bounded_arguments_refuse_unbounded_or_control_input() {
        let mut v = fresh();
        v.push("x".repeat(32769));
        assert!(parse(&v).is_err());
        assert!(parse(&[
            "commit-config".into(),
            "--stage".into(),
            "/run/secret\nother".into()
        ])
        .is_err());
        let mut v = vec!["commit-config".to_owned()];
        for _ in 0..21 {
            v.extend(words("--stage /run/private"));
        }
        assert!(parse(&v).is_err());
    }
}
