use super::*;
use crate::{
    configuration::WindowMode,
    host_lifecycle::{parse_host_args, HostCommand, OwnedVerb, ProfileLine},
    menu_model::{ExtensionState, Observation, Probe},
    profile_terms::ProfileTerms,
    provider_xpc::{
        encode_reply, CertStatusReport, ListenProbe, PingReport, Reply, StatusReport, Verb,
    },
};
use std::collections::VecDeque;

const GENERATION: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
const NEW_GENERATION: &str = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";
const RELAY: &str = "192.168.1.107";

fn relay() -> IpAddr {
    RELAY.parse().unwrap()
}

fn argv(verb: &HostVerb) -> Vec<String> {
    std::iter::once("aegis-ne-host".to_owned())
        .chain(verb.args())
        .collect()
}

#[test]
fn every_menu_verb_is_an_existing_cli_command() {
    let dir = PathBuf::from("/Users/someone/aegis-enroll");
    let cases = [
        (HostVerb::List, HostCommand::List),
        (HostVerb::ProviderStatus, HostCommand::Xpc(Verb::Status)),
        (HostVerb::Ping, HostCommand::Xpc(Verb::Ping)),
        (HostVerb::CertStatus, HostCommand::Xpc(Verb::CertStatus)),
        (HostVerb::ProfileTerms, HostCommand::Xpc(Verb::ProfileTerms)),
        (HostVerb::FilterStatus, HostCommand::FilterStatus),
        (HostVerb::EnableFilter, HostCommand::EnableFilter),
        (HostVerb::RequestActivation, HostCommand::RequestActivation),
        (
            HostVerb::Import {
                dir: dir.clone(),
                remove_source: false,
            },
            HostCommand::Import {
                dir: dir.clone(),
                remove_source: false,
            },
        ),
        (
            HostVerb::Import {
                dir: dir.clone(),
                remove_source: true,
            },
            HostCommand::Import {
                dir,
                remove_source: true,
            },
        ),
        (
            HostVerb::SaveProfile {
                relay: relay(),
                replace_existing: false,
            },
            HostCommand::SaveProfile {
                relay: relay(),
                replace_existing: false,
            },
        ),
        (
            HostVerb::SaveProfile {
                relay: relay(),
                replace_existing: true,
            },
            HostCommand::SaveProfile {
                relay: relay(),
                replace_existing: true,
            },
        ),
        (
            HostVerb::Connect {
                owner_generation: GENERATION.into(),
                relay: relay(),
            },
            HostCommand::Owned {
                verb: OwnedVerb::Connect,
                owner_generation: GENERATION.into(),
                relay: relay(),
                // Never the QA window flag: the product default.
                window: WindowMode::default(),
            },
        ),
        (
            HostVerb::Disconnect {
                owner_generation: GENERATION.into(),
                relay: relay(),
            },
            HostCommand::Owned {
                verb: OwnedVerb::Disconnect,
                owner_generation: GENERATION.into(),
                relay: relay(),
                window: WindowMode::default(),
            },
        ),
        (HostVerb::EmergencyStop, HostCommand::EmergencyStop),
    ];
    for (verb, expected) in cases {
        let parsed = parse_host_args(&argv(&verb));
        assert_eq!(parsed, Ok(expected.clone()), "{}", verb.name());
        // None weakens the leak guard or removes an identity or a profile.
        assert!(!matches!(
            expected,
            HostCommand::DisableFilter
                | HostCommand::RemoveFilter
                | HostCommand::RemoveProfile
                | HostCommand::Deactivate
                | HostCommand::Xpc(Verb::ForgetIdentity | Verb::Renew)
        ));
    }
}

#[test]
fn outer_bounds_exceed_the_hosts_own_bounds() {
    let secs = |verb: HostVerb| verb.bound().as_secs();
    // XPC verbs: 10 s; profile and filter-status verbs: 30 s.
    assert!(secs(HostVerb::ProviderStatus) > 10);
    assert!(secs(HostVerb::List) > 30);
    assert!(secs(HostVerb::FilterStatus) > 30);
    assert!(secs(HostVerb::EmergencyStop) > 30);
    // Activation and filter enable: 120 s; import: a 120 s prompt + 10 s.
    assert!(secs(HostVerb::RequestActivation) > 120);
    assert!(secs(HostVerb::EnableFilter) > 120);
    assert!(
        secs(HostVerb::Import {
            dir: PathBuf::from("/x"),
            remove_source: false
        }) > 130
    );
}

#[test]
fn verb_names_never_carry_an_operand() {
    let verb = HostVerb::Import {
        dir: PathBuf::from("/Users/someone/secret-folder"),
        remove_source: true,
    };
    assert_eq!(verb.name(), "import --remove-source");
    let verb = HostVerb::Connect {
        owner_generation: GENERATION.into(),
        relay: relay(),
    };
    assert_eq!(verb.name(), "connect");
}

#[test]
fn a_bounded_child_reports_exit_stdout_and_streamed_stderr() {
    let mut seen = Vec::new();
    let run = run_bounded(
        Path::new("/bin/sh"),
        &[
            "-c".into(),
            "echo out; echo first >&2; echo second >&2; exit 3".into(),
        ],
        Duration::from_secs(10),
        &mut |line| seen.push(line.to_owned()),
    );
    assert_eq!(run.exit, Some(3));
    assert_eq!(run.stdout, "out\n");
    assert_eq!(run.stderr, "first\nsecond\n");
    assert_eq!(seen, vec!["first", "second"]);
    assert!(!run.timed_out);
    assert_eq!(run.code(), Some("second".into()));
}

#[test]
fn a_child_past_its_outer_bound_is_killed() {
    let started = Instant::now();
    let run = run_bounded(
        Path::new("/bin/sleep"),
        &["5".into()],
        Duration::from_millis(300),
        &mut |_| {},
    );
    assert!(run.timed_out);
    assert_eq!(run.exit, None);
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(run.summary("x").ends_with("outer_bound_expired"));
}

#[test]
fn a_child_that_cannot_start_is_a_failed_run() {
    let run = run_bounded(
        Path::new("/nonexistent/aegis-ne-host"),
        &[],
        Duration::from_secs(1),
        &mut |_| {},
    );
    assert_eq!(run.exit, None);
    assert!(!run.ok());
}

/// Scripted runner: each host call must be the next scripted verb.
struct Fake {
    script: VecDeque<(&'static str, Run)>,
    calls: Vec<Vec<String>>,
    extension: Run,
}

impl Fake {
    fn new(script: Vec<(&'static str, Run)>) -> Self {
        Self {
            script: script.into(),
            calls: Vec::new(),
            extension: ok_run(""),
        }
    }

    fn names(&self) -> Vec<String> {
        self.calls.iter().map(|args| args[0].clone()).collect()
    }
}

impl Runner for Fake {
    fn host(&mut self, verb: &HostVerb, on_stderr: &mut dyn FnMut(&str)) -> Run {
        self.calls.push(verb.args());
        let (name, run) = self
            .script
            .pop_front()
            .unwrap_or_else(|| panic!("unscripted verb {}", verb.name()));
        assert_eq!(name, verb.name(), "verb order");
        for line in run.stderr.lines() {
            on_stderr(line);
        }
        run
    }

    fn extension_list(&mut self) -> Run {
        self.calls.push(vec!["systemextensionsctl".into()]);
        self.extension.clone()
    }
}

fn ok_run(stdout: &str) -> Run {
    Run {
        exit: Some(0),
        stdout: stdout.into(),
        ..Run::default()
    }
}

fn failed_run(exit: i32, stdout: &str, stderr: &str) -> Run {
    Run {
        exit: Some(exit),
        stdout: stdout.into(),
        stderr: stderr.into(),
        timed_out: false,
    }
}

fn json(reply: &Reply) -> String {
    String::from_utf8(encode_reply(reply).unwrap()).unwrap() + "\n"
}

fn terms() -> Run {
    ok_run(&json(&Reply::ProfileTerms(ProfileTerms {
        relay: format!("{RELAY}:443").parse().unwrap(),
        dns: vec!["198.19.255.2".parse().unwrap()],
        mtu: 1280,
        profile_sha256: "c".repeat(64),
    })))
}

fn list(profiles: &[ProfileLine]) -> Run {
    let mut out = String::new();
    for profile in profiles {
        out.push_str(&profile.format());
        out.push('\n');
    }
    out.push_str(&format!(
        "profiles={} native_acceptance=false\n",
        profiles.len()
    ));
    ok_run(&out)
}

fn profile(intent_valid: bool, status: isize) -> ProfileLine {
    ProfileLine {
        index: 0,
        owner_generation: Some(GENERATION.into()),
        scutil_service_id: None,
        intent_valid,
        enabled: true,
        on_demand_enabled: false,
        native_vpn_status: status,
    }
}

fn filter(outcome: &str, exit: i32, mode: &str) -> Run {
    Run {
        exit: Some(exit),
        stdout: format!(
            "filter_result={outcome} exit_code={exit} configured=true enabled=true filter_packets=true filter_sockets=false packet_bundle_id=match grade=firewall attached=true pid_match=true mode={mode} armed_token=none dropped=0 allowed=0\n"
        ),
        ..Run::default()
    }
}

fn saved(generation: &str) -> Run {
    ok_run(&format!(
        "owner_generation={generation} saved=true profile_sha256={} native_vpn_status=1 native_acceptance=false\n",
        "c".repeat(64)
    ))
}

fn started(generation: &str) -> Run {
    ok_run(&format!(
        "owner_generation={generation} profile_sha256={} native_vpn_status=2 native_acceptance=false\n",
        "c".repeat(64)
    ))
}

#[test]
fn connect_checks_the_guard_reads_the_terms_and_starts_the_profile() {
    let mut fake = Fake::new(vec![
        ("filter-status", filter("ok", 0, "open")),
        ("profile-terms", terms()),
        ("list", list(&[profile(true, 1)])),
        ("connect", started(GENERATION)),
    ]);
    let outcome = connect(&mut fake);
    assert!(outcome.ok, "{outcome:?}");
    assert_eq!(
        fake.calls.last().unwrap(),
        &vec![
            "--connect".to_owned(),
            PROVIDER_ID.into(),
            GENERATION.into(),
            RELAY.into()
        ]
    );
    assert_eq!(outcome.events.len(), 4);
}

#[test]
fn connect_turns_the_guard_on_and_saves_a_first_profile() {
    let mut fake = Fake::new(vec![
        ("filter-status", filter("not_configured", 30, "open")),
        ("enable-filter", filter("ok", 0, "open")),
        ("filter-status", filter("ok", 0, "open")),
        ("profile-terms", terms()),
        ("list", list(&[])),
        ("save-profile", saved(NEW_GENERATION)),
        ("connect", started(NEW_GENERATION)),
    ]);
    let outcome = connect(&mut fake);
    assert!(outcome.ok, "{outcome:?}");
    assert_eq!(fake.calls.last().unwrap()[2], NEW_GENERATION);
}

#[test]
fn connect_never_starts_without_a_running_guard() {
    for script in [
        vec![
            ("filter-status", filter("disabled", 31, "open")),
            (
                "enable-filter",
                failed_run(
                    35,
                    "filter_result=permission_denied exit_code=35 filter_saved=unknown\n",
                    "",
                ),
            ),
        ],
        vec![("filter-status", filter("not_attached", 33, "open"))],
        vec![(
            "filter-status",
            failed_run(
                34,
                "filter_result=failed exit_code=34 configured=unknown\n",
                "filter_internal_error\n",
            ),
        )],
    ] {
        let mut fake = Fake::new(script);
        let outcome = connect(&mut fake);
        assert!(!outcome.ok);
        assert!(
            !fake
                .names()
                .iter()
                .any(|n| n == "--connect" || n == "--profile-terms"),
            "{:?}",
            fake.names()
        );
    }
}

#[test]
fn connect_rewrites_a_stale_profile_once() {
    let mut fake = Fake::new(vec![
        ("filter-status", filter("ok", 0, "open")),
        ("profile-terms", terms()),
        ("list", list(&[profile(true, 1)])),
        (
            "connect",
            failed_run(
                2,
                "",
                &format!("owner_generation={GENERATION} saved_profile_typed_intent_mismatch\n"),
            ),
        ),
        ("save-profile --replace-existing", saved(NEW_GENERATION)),
        ("connect", started(NEW_GENERATION)),
    ]);
    let outcome = connect(&mut fake);
    assert!(outcome.ok, "{outcome:?}");
    assert!(fake.calls.contains(&vec![
        "--save-profile".into(),
        PROVIDER_ID.into(),
        RELAY.into(),
        "--replace-existing".into()
    ]));
}

#[test]
fn connect_rewrites_an_invalid_idle_profile_before_starting() {
    let mut fake = Fake::new(vec![
        ("filter-status", filter("ok", 0, "open")),
        ("profile-terms", terms()),
        ("list", list(&[profile(false, 1)])),
        ("save-profile --replace-existing", saved(NEW_GENERATION)),
        ("connect", started(NEW_GENERATION)),
    ]);
    assert!(connect(&mut fake).ok);
}

#[test]
fn connect_without_terms_asks_for_the_invitation() {
    let mut fake = Fake::new(vec![
        ("filter-status", filter("ok", 0, "open")),
        (
            "profile-terms",
            failed_run(65, "", "provider_refused provider_identity_missing\n"),
        ),
    ]);
    let outcome = connect(&mut fake);
    assert!(!outcome.ok);
    assert!(
        // v45: the invitation is now a file the user joins with.
        outcome
            .message
            .contains("joined with your invitation yet, do that first"),
        "{}",
        outcome.message
    );
    assert!(outcome
        .message
        .ends_with("(code: provider_identity_missing)"));
}

#[test]
fn connect_refuses_several_profiles() {
    let mut second = profile(true, 1);
    second.index = 1;
    let mut fake = Fake::new(vec![
        ("filter-status", filter("ok", 0, "open")),
        ("profile-terms", terms()),
        ("list", list(&[profile(true, 1), second])),
    ]);
    let outcome = connect(&mut fake);
    assert!(!outcome.ok);
    assert!(outcome.message.contains("More than one"));
}

#[test]
fn disconnect_names_the_exact_profile() {
    let mut fake = Fake::new(vec![
        ("list", list(&[profile(true, 3)])),
        ("profile-terms", terms()),
        ("disconnect", started(GENERATION)),
    ]);
    let outcome = disconnect(&mut fake);
    assert!(outcome.ok);
    assert_eq!(
        fake.calls.last().unwrap(),
        &vec![
            "--disconnect".to_owned(),
            PROVIDER_ID.into(),
            GENERATION.into(),
            RELAY.into()
        ]
    );
}

#[test]
fn disconnect_falls_back_to_the_emergency_stop() {
    let mut fake = Fake::new(vec![
        ("list", list(&[profile(true, 4)])),
        ("profile-terms", failed_run(69, "", "xpc_connection_invalid\n")),
        (
            "emergency-stop",
            ok_run("stop_requested index=0 owner_generation=x native_vpn_status_before=4 on_demand_enabled=false\nemergency_stop_requested=1 disconnected=unknown\n"),
        ),
    ]);
    let outcome = disconnect(&mut fake);
    assert!(outcome.ok);
    assert_eq!(outcome.events.len(), 3);
    let mut fake = Fake::new(vec![
        ("list", list(&[profile(true, 3)])),
        ("profile-terms", terms()),
        (
            "disconnect",
            failed_run(
                2,
                "",
                "owner_generation=x saved_profile_typed_intent_mismatch\n",
            ),
        ),
        (
            "emergency-stop",
            ok_run("emergency_stop_requested=1 disconnected=unknown\n"),
        ),
    ]);
    assert!(disconnect(&mut fake).ok);
}

#[test]
fn activation_reports_the_system_settings_wait_as_it_happens() {
    let mut fake = Fake::new(vec![(
        "request-activation",
        failed_run(
            14,
            "activation_result=timeout_awaiting_approval exit_code=14 will_complete_after_reboot=false needs_user_approval=true replacement_decision=none tunnel_ready=unknown\n",
            "System Settings approval required; no automatic approval. Waiting at most 120s.\n",
        ),
    )]);
    let mut prompted = 0;
    let outcome = activate(&mut fake, &mut || prompted += 1);
    assert_eq!(prompted, 1);
    assert!(!outcome.ok && outcome.approval_needed);
    assert!(outcome.message.contains("System Settings"));
    let mut fake = Fake::new(vec![(
        "request-activation",
        ok_run("activation_result=completed exit_code=0 will_complete_after_reboot=false needs_user_approval=false replacement_decision=none tunnel_ready=unknown\n"),
    )]);
    let outcome = activate(&mut fake, &mut || panic!("no approval asked"));
    assert!(outcome.ok && !outcome.approval_needed);
}

#[test]
fn import_results_follow_the_host_exit_codes() {
    let dir = Path::new("/Users/someone/aegis-enroll");
    let mut fake = Fake::new(vec![(
        "import",
        ok_run("import_result=committed manifest_match=true committed_files=11\n"),
    )]);
    assert!(import(&mut fake, dir, false).ok);
    assert_eq!(
        fake.calls[0],
        vec!["--import".to_owned(), dir.to_string_lossy().into_owned()]
    );
    let mut fake = Fake::new(vec![(
        "import --remove-source",
        failed_run(
            66,
            "import_result=not_sent\n",
            "import_source_not_private\n",
        ),
    )]);
    let outcome = import(&mut fake, dir, true);
    assert!(!outcome.ok);
    assert!(outcome.message.contains("Get Info"));
    let mut fake = Fake::new(vec![(
        "import",
        failed_run(
            73,
            "import_result=committed\n",
            "import_source_not_removed\n",
        ),
    )]);
    assert!(import(&mut fake, dir, false).ok);
}

fn ping(identity_present: bool) -> Run {
    ok_run(&json(&Reply::Ping(PingReport {
        euid: 0,
        sandboxed: true,
        container_url: None,
        container_realpath: None,
        realpath_errno: 0,
        custody: Vec::new(),
        container_ancestors: Vec::new(),
        container_open: None,
        loopback_listen: ListenProbe {
            stage: "ok".into(),
            errno: 0,
        },
        session_phase: "none".into(),
        identity_present,
    })))
}

#[test]
fn a_full_refresh_reads_every_fact_read_only() {
    let mut fake = Fake::new(vec![
        ("list", list(&[profile(true, 3)])),
        (
            "status",
            ok_run(&json(&Reply::Status(StatusReport {
                session_phase: "ready".into(),
                session_refusal: None,
            }))),
        ),
        ("ping", ping(true)),
        (
            "cert-status",
            ok_run(&json(&Reply::CertStatus(CertStatusReport {
                state: "valid".into(),
                not_before: Some(1),
                not_after: Some(2_000_000_000),
                renew_at: Some(1_900_000_000),
                attempts: 0,
                last_attempt_at: None,
                next_attempt_at: None,
                last_failure: None,
                failing_since: None,
                check: None,
            }))),
        ),
        ("filter-status", filter("ok", 0, "guarding")),
    ]);
    fake.extension = ok_run(
        "*\t*\tTEAMID0000\tdev.aegis.macos.PacketTunnel (0.1.0/39)\tAEGIS\t[activated enabled]\n",
    );
    let mut obs = Observation {
        approval_requested: true,
        ..Observation::default()
    };
    let events = refresh(&mut fake, &mut obs, true, 1_800_000_000);
    assert!(events.is_empty(), "{events:?}");
    assert!(obs.refreshed && !obs.approval_requested);
    assert_eq!(
        obs.extension,
        ExtensionState::Enabled {
            build: Some("39".into())
        }
    );
    assert_eq!(obs.identity_present, Some(true));
    assert_eq!(obs.cert.as_ref().map(|c| c.state.as_str()), Some("valid"));
    assert_eq!(obs.status_since, Some((3, 1_800_000_000)));
    assert!(matches!(obs.filter, Probe::Ok(ref f) if f.mode.as_deref() == Some("guarding")));
    // Only read-only verbs ran.
    for args in &fake.calls {
        assert!(
            [
                "systemextensionsctl",
                "--list",
                "--status",
                "--ping",
                "--cert-status",
                "--filter-status"
            ]
            .contains(&args[0].as_str()),
            "{args:?}"
        );
        assert_eq!(args.len(), 1, "{args:?}");
    }
}

#[test]
fn without_the_extension_no_provider_query_runs() {
    let mut fake = Fake::new(vec![("list", list(&[]))]);
    fake.extension = ok_run("");
    let mut obs = Observation {
        identity_present: Some(true),
        ..Observation::default()
    };
    refresh(&mut fake, &mut obs, false, 1);
    assert_eq!(obs.extension, ExtensionState::NotFound);
    assert_eq!(obs.identity_present, None);
    assert!(matches!(obs.provider, Probe::Unknown));
    assert_eq!(fake.names(), vec!["systemextensionsctl", "--list"]);
}

#[test]
fn an_unreachable_provider_is_not_asked_again_in_the_same_refresh() {
    let mut fake = Fake::new(vec![
        ("list", list(&[profile(true, 1)])),
        ("status", failed_run(69, "", "xpc_connection_invalid\n")),
        ("filter-status", filter("provider_unavailable", 69, "open")),
    ]);
    fake.extension = ok_run(
        "*\t*\tTEAMID0000\tdev.aegis.macos.PacketTunnel (0.1.0/39)\tAEGIS\t[activated enabled]\n",
    );
    let mut obs = Observation::default();
    let events = refresh(&mut fake, &mut obs, true, 1);
    assert!(obs.provider.provider_unreachable());
    assert_eq!(events, vec!["status exit=69 code=xpc_connection_invalid"]);
    assert!(!fake
        .names()
        .iter()
        .any(|n| n == "--ping" || n == "--cert-status"));
}

#[test]
fn import_waits_for_a_down_tunnel() {
    let mut obs = Observation {
        profiles: Probe::Ok(vec![profile(true, 3)]),
        ..Observation::default()
    };
    assert!(!import_allowed(&obs));
    obs.profiles = Probe::Ok(vec![profile(true, 1)]);
    assert!(import_allowed(&obs));
}

// ---------------------------------------------------------------------------
// v45: joining with an invitation file (`--enroll`).

fn enrolled(exit: i32, result: &str, stderr: &str) -> Run {
    failed_run(
        exit,
        &format!(
            "enroll_result={result} stage=done redeem=issued import=committed staging=removed invite=removed\n"
        ),
        stderr,
    )
}

#[test]
fn the_join_verb_is_the_cli_enroll_of_the_inbox_copy() {
    let copy = PathBuf::from("/Users/someone/Library/Application Support/dev.aegis.macos/join/join-0123456789abcdef.aegis-invite");
    for replace_identity in [false, true] {
        let verb = HostVerb::Enroll {
            path: copy.clone(),
            replace_identity,
        };
        assert_eq!(
            parse_host_args(&argv(&verb)),
            Ok(HostCommand::Enroll {
                path: copy.clone(),
                // The host removes the menu's own copy after a commit.
                remove_source: true,
                replace_identity,
            })
        );
        assert!(!verb.name().contains('/'), "{}", verb.name());
        // Precheck (3 x 10 s), redeem (60 s), prompt (120 s), import (10 s).
        assert!(verb.bound().as_secs() > 30 + 60 + 120 + 10);
    }
    assert_eq!(
        HostVerb::Enroll {
            path: copy,
            replace_identity: true
        }
        .name(),
        "enroll --replace-identity"
    );
}

#[test]
fn join_reports_every_progress_step_and_succeeds_only_when_joined() {
    let progress = "enroll_progress=checking\nenroll_progress=preparing\nenroll_progress=contacting\nenroll_progress=approving\nadministrator approval required for this identity change; answer the system prompt (at most 120s)\nenroll_progress=importing\n";
    let mut fake = Fake::new(vec![("enroll", enrolled(0, "joined", progress))]);
    let mut steps = Vec::new();
    let outcome = join(
        &mut fake,
        Path::new("/x/join-1.aegis-invite"),
        false,
        &mut |step| steps.push(step),
    );
    assert!(outcome.ok, "{outcome:?}");
    assert!(outcome.message.starts_with("You joined AEGIS"));
    assert_eq!(
        steps,
        [
            JoinStep::Checking,
            JoinStep::Preparing,
            JoinStep::Contacting,
            JoinStep::Approving,
            JoinStep::Importing,
        ]
    );
    assert_eq!(outcome.events, ["enroll exit=0 code=none"]);
    assert_eq!(fake.calls[0][0], "--enroll");
    assert!(fake.calls[0].contains(&"--remove-source".to_owned()));

    // An exit 0 without the joined line is never a success.
    let mut fake = Fake::new(vec![("enroll", ok_run("something else\n"))]);
    assert!(
        !join(
            &mut fake,
            Path::new("/x/a.aegis-invite"),
            false,
            &mut |_| {}
        )
        .ok
    );
    // 73: joined, a temporary file left behind.
    let mut fake = Fake::new(vec![(
        "enroll",
        enrolled(73, "joined", "import_source_removal_incomplete\n"),
    )]);
    assert!(
        join(
            &mut fake,
            Path::new("/x/a.aegis-invite"),
            false,
            &mut |_| {}
        )
        .ok
    );
}

#[test]
fn join_failures_say_what_to_do_and_name_their_code() {
    let cases = [
        (
            43,
            "enroll_invitation_rejected",
            "expired or was already used",
        ),
        (
            44,
            "enroll_authority_unreachable",
            "could not reach its server",
        ),
        (42, "enroll_session_live", "Disconnect first"),
        (
            41,
            "enroll_identity_present",
            "already has a working AEGIS identity",
        ),
        (40, "invite_not_canonical", "not a valid AEGIS invitation"),
        (45, "enroll_certificate_not_yet_valid", "date and time"),
        (45, "enroll_staging_conflict", "could not prepare this Mac"),
        (
            67,
            "identity_authorization_refused",
            "No administrator password",
        ),
        (69, "service_unavailable", "not running"),
        (65, "provider_refused session_live", "Disconnect first"),
    ];
    for (exit, code, text) in cases {
        let line = "enroll_result=failed stage=redeem redeem=rejected import=not_sent staging=kept invite=kept\n";
        let mut fake = Fake::new(vec![(
            "enroll",
            failed_run(exit, line, &format!("{code}\n")),
        )]);
        let outcome = join(
            &mut fake,
            Path::new("/x/a.aegis-invite"),
            false,
            &mut |_| {},
        );
        assert!(!outcome.ok, "{exit}");
        assert!(
            outcome.message.contains(text),
            "{exit}: {}",
            outcome.message
        );
        let last = code.split(' ').next_back().unwrap();
        assert!(
            outcome.message.ends_with(&format!("(code: {last})")),
            "{}",
            outcome.message
        );
    }
    // Killed at the outer bound: the result is unknown.
    let mut fake = Fake::new(vec![(
        "enroll",
        Run {
            exit: None,
            timed_out: true,
            ..Run::default()
        },
    )]);
    let outcome = join(
        &mut fake,
        Path::new("/x/a.aegis-invite"),
        false,
        &mut |_| {},
    );
    assert!(!outcome.ok && outcome.message.contains("could not confirm"));
    // The same in Russian.
    crate::menu_l10n::with(crate::menu_l10n::Lang::Ru, || {
        let mut fake = Fake::new(vec![(
            "enroll",
            failed_run(43, "", "enroll_invitation_rejected\n"),
        )]);
        let outcome = join(
            &mut fake,
            Path::new("/x/a.aegis-invite"),
            false,
            &mut |_| {},
        );
        assert!(
            outcome.message.contains("приглашения истёк"),
            "{}",
            outcome.message
        );
        assert!(outcome
            .message
            .ends_with("(код: enroll_invitation_rejected)"));
    });
}

#[test]
fn join_waits_for_a_disconnect_like_an_import() {
    let mut obs = Observation {
        profiles: Probe::Ok(vec![profile(true, 3)]),
        ..Observation::default()
    };
    assert!(!join_allowed(&obs));
    obs.profiles = Probe::Ok(vec![profile(true, 1)]);
    assert!(join_allowed(&obs));
}
