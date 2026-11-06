use super::*;
use crate::host_lifecycle::ProfileLine;
use crate::provider_xpc::{CertStatusReport, StatusReport};

const NOW: u64 = 1_793_000_000;
const GENERATION: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";

fn args(items: &[&str]) -> Vec<String> {
    std::iter::once("aegis-ne-host")
        .chain(items.iter().copied())
        .map(String::from)
        .collect()
}

fn profile(status: isize) -> ProfileLine {
    ProfileLine {
        index: 0,
        owner_generation: Some(GENERATION.into()),
        scutil_service_id: None,
        intent_valid: true,
        enabled: true,
        on_demand_enabled: false,
        native_vpn_status: status,
    }
}

fn cert(state: &str, not_after: u64) -> CertStatusReport {
    CertStatusReport {
        state: state.into(),
        not_before: Some(not_after - 3 * 86_400),
        not_after: Some(not_after),
        renew_at: Some(not_after - 86_400),
        attempts: 0,
        last_attempt_at: None,
        next_attempt_at: None,
        last_failure: None,
        failing_since: None,
        check: None,
    }
}

fn filter(outcome: &str, mode: Option<&str>) -> Probe<FilterView> {
    Probe::Ok(FilterView {
        outcome: outcome.into(),
        mode: mode.map(str::to_owned),
    })
}

/// Set up and disconnected.
fn ready() -> Observation {
    Observation {
        refreshed: true,
        in_applications: true,
        app_build: Some("39".into()),
        extension: ExtensionState::Enabled {
            build: Some("39".into()),
        },
        profiles: Probe::Ok(vec![profile(1)]),
        provider: Probe::Ok(StatusReport {
            session_phase: "none".into(),
            session_refusal: None,
        }),
        identity_present: Some(true),
        cert: Some(cert("valid", NOW + 2 * 86_400)),
        filter: filter("ok", Some("open")),
        status_since: Some((1, NOW - 100)),
        ..Observation::default()
    }
}

fn with_status(status: isize, since: u64) -> Observation {
    Observation {
        profiles: Probe::Ok(vec![profile(status)]),
        status_since: Some((status, since)),
        ..ready()
    }
}

#[test]
fn only_a_launchservices_start_without_a_verb_is_the_menu_app() {
    assert!(launched_as_app(&args(&[]), false));
    assert!(launched_as_app(&args(&["-psn_0_123456"]), false));
    // A terminal start without arguments keeps the CLI's usage error.
    assert!(!launched_as_app(&args(&[]), true));
    assert!(!launched_as_app(&args(&["--status"]), false));
    assert!(!launched_as_app(&args(&["--status", "x"]), false));
    assert!(!launched_as_app(&args(&["-psn_0_1", "--list"]), false));
}

#[test]
fn only_the_installed_executable_is_in_applications() {
    assert!(in_applications(INSTALLED_EXECUTABLE));
    assert!(!in_applications(
        "/Users/someone/Downloads/AEGIS.app/Contents/MacOS/aegis-ne-host"
    ));
    assert!(!in_applications(
        "/private/var/folders/ab/cd/T/AppTranslocation/X/d/AEGIS.app/Contents/MacOS/aegis-ne-host"
    ));
}

const LISTING: &str = "35 extension(s)\n\
--- com.apple.system_extension.network_extension (Go to 'System Settings > General > Login Items & Extensions > Network Extensions' to modify these system extension(s))\n\
enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n\
\t\tTEAMID0000\tdev.aegis.macos.PacketTunnel (0.1.0/36)\tAEGIS\t[terminated waiting to uninstall on reboot]\n\
*\t*\tTEAMID0000\tdev.aegis.macos.PacketTunnel (0.1.0/38)\tAEGIS\t[activated enabled]\n\
\t\tTEAMID0000\tdev.aegis.macos.PacketTunnel (0.1.0/8)\tAEGIS\t[terminated waiting to uninstall on reboot]\n";

fn listing(rows: &[(&str, &str, &str)]) -> String {
    let mut text = String::from("enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n");
    for (team, id, state) in rows {
        text.push_str(&format!("*\t*\t{team}\t{id}\tAEGIS\t[{state}]\n"));
    }
    text
}

#[test]
fn the_extension_list_is_read_for_this_provider_and_team_only() {
    assert_eq!(
        parse_extension_list(LISTING),
        ExtensionState::Enabled {
            build: Some("38".into())
        }
    );
    let id = "dev.aegis.macos.PacketTunnel (0.1.0/39)";
    for (state, expected) in [
        (
            "activated waiting for user",
            ExtensionState::AwaitingApproval,
        ),
        ("activated disabled", ExtensionState::Disabled),
        ("validating by category", ExtensionState::Validating),
        (
            "terminated waiting to uninstall on reboot",
            ExtensionState::Inactive,
        ),
    ] {
        assert_eq!(
            parse_extension_list(&listing(&[("TEAMID0000", id, state)])),
            expected,
            "{state}"
        );
    }
    // Another team's or a look-alike identifier never counts.
    assert_eq!(
        parse_extension_list(&listing(&[("ABCDE12345", id, "activated enabled")])),
        ExtensionState::NotFound
    );
    assert_eq!(
        parse_extension_list(&listing(&[(
            "TEAMID0000",
            "dev.aegis.macos.PacketTunnelX (0.1.0/39)",
            "activated enabled"
        )])),
        ExtensionState::NotFound
    );
    assert_eq!(parse_extension_list(""), ExtensionState::NotFound);
}

#[test]
fn the_newest_enabled_build_wins_over_approval_and_older_builds() {
    let text = listing(&[
        (
            "TEAMID0000",
            "dev.aegis.macos.PacketTunnel (0.1.0/38)",
            "activated enabled",
        ),
        (
            "TEAMID0000",
            "dev.aegis.macos.PacketTunnel (0.1.0/40)",
            "activated enabled",
        ),
        (
            "TEAMID0000",
            "dev.aegis.macos.PacketTunnel (0.1.0/39)",
            "activated waiting for user",
        ),
    ]);
    assert_eq!(
        parse_extension_list(&text),
        ExtensionState::Enabled {
            build: Some("40".into())
        }
    );
}

#[test]
fn an_update_is_pending_only_for_a_numerically_newer_app() {
    assert!(update_pending(Some("39"), Some("38")));
    assert!(!update_pending(Some("39"), Some("39")));
    assert!(!update_pending(Some("38"), Some("39")));
    assert!(!update_pending(Some("39"), None));
    assert!(!update_pending(Some("039"), Some("38")));
}

#[test]
fn list_output_is_parsed_with_the_hosts_own_line_parser() {
    let line = profile(3).format();
    let out = format!("{line}\nprofiles=1 native_acceptance=false\n");
    assert_eq!(parse_list(&out), Ok(vec![profile(3)]));
    assert_eq!(
        parse_list("profiles=0 native_acceptance=false\n"),
        Ok(Vec::new())
    );
    assert_eq!(
        parse_list(&format!("{line}\nprofiles=2 native_acceptance=false\n")),
        Err("list_count_mismatch")
    );
    assert_eq!(parse_list(&line), Err("list_total_missing"));
    assert_eq!(
        parse_list("profile index=0 garbage\nprofiles=1\n"),
        Err("profile_line_shape")
    );
}

#[test]
fn the_stderr_code_is_the_last_code_word() {
    assert_eq!(
        stderr_code(&format!(
            "owner_generation={GENERATION} existing_profile_not_idle\n"
        )),
        Some("existing_profile_not_idle".into())
    );
    assert_eq!(
        stderr_code("provider_refused session_live\n"),
        Some("session_live".into())
    );
    assert_eq!(
        stderr_code(
            "administrator approval required for this identity change; answer the system prompt (at most 120s)\nimport_source_not_private\n"
        ),
        Some("import_source_not_private".into())
    );
    assert_eq!(
        stderr_code("administrator approval required for this identity change; answer the system prompt (at most 120s)\n"),
        None
    );
    assert_eq!(stderr_code("filter_result=failed exit_code=34\n"), None);
    assert_eq!(stderr_code(""), None);
}

#[test]
fn fields_and_result_lines_are_read_by_key() {
    let out = "filter_result=ok exit_code=0 configured=true enabled=true attached=true pid_match=true mode=guarding armed_token=4\n{\"schema\":\"x\"}\n";
    let line = result_line(out, "filter_result=").unwrap();
    assert_eq!(field(line, "mode"), Some("guarding"));
    assert_eq!(field(line, "exit_code"), Some("0"));
    assert_eq!(field(line, "absent"), None);
    assert_eq!(
        parse_filter_status(out),
        Some(FilterView {
            outcome: "ok".into(),
            mode: Some("guarding".into())
        })
    );
    assert_eq!(parse_filter_status("nothing\n"), None);
}

#[test]
fn the_guard_state_follows_the_filter_outcome() {
    let view = |outcome: &str, mode: Option<&str>| FilterView {
        outcome: outcome.into(),
        mode: mode.map(str::to_owned),
    };
    assert_eq!(
        view("ok", Some("guarding")).guard(),
        GuardState::On { guarding: true }
    );
    assert_eq!(
        view("ok", Some("open")).guard(),
        GuardState::On { guarding: false }
    );
    for off in ["not_configured", "disabled", "field_mismatch"] {
        assert_eq!(view(off, None).guard(), GuardState::Off, "{off}");
    }
    for not_running in ["not_attached", "provider_unavailable"] {
        assert_eq!(view(not_running, None).guard(), GuardState::NotRunning);
    }
    assert_eq!(view("timeout", None).guard(), GuardState::Failed);
}

#[test]
fn certificate_states_map_to_what_the_user_must_do() {
    let end = NOW + 86_400 * 2;
    assert_eq!(
        cert_facet(&cert("valid", end), NOW),
        CertFacet::Valid {
            not_after: Some(end)
        }
    );
    // The clock wins over a stale "valid".
    assert_eq!(
        cert_facet(&cert("valid", NOW - 1), NOW),
        CertFacet::Expired {
            not_after: Some(NOW - 1)
        }
    );
    assert!(cert_facet(&cert("expired", end), NOW).needs_new_identity());
    assert!(cert_facet(&cert("superseded", end), NOW).needs_new_identity());
    assert_eq!(cert_facet(&cert("pending", end), NOW), CertFacet::Pending);
    assert_eq!(
        cert_facet(&cert("failed:connect_timeout", end), NOW),
        CertFacet::Failing {
            class: "connect_timeout".into(),
            not_after: Some(end)
        }
    );
    assert_eq!(
        cert_facet(&cert("deferred:guarded", end), NOW),
        CertFacet::Deferred {
            not_after: Some(end)
        }
    );
    assert_eq!(
        cert_facet(&cert("renewed_pending_ack", end), NOW),
        CertFacet::Renewing {
            not_after: Some(end)
        }
    );
    assert_eq!(cert_facet(&cert("strange", end), NOW), CertFacet::Unknown);
    assert!(CertFacet::Valid {
        not_after: Some(NOW + 3600)
    }
    .text(NOW)
    .contains("renews at the next connect"));
}

#[test]
fn utc_times_are_shown_to_the_minute() {
    assert_eq!(friendly_utc(0), "1970-01-01 00:00 UTC");
    assert_eq!(friendly_utc(1_793_094_414), "2026-10-27 09:46 UTC");
}

#[test]
fn before_the_first_refresh_the_menu_is_checking() {
    let view = derive(&Observation::default(), NOW);
    assert_eq!(view.primary, Primary::Checking);
    assert_eq!(view.actions, Actions::default());
}

#[test]
fn outside_applications_nothing_else_is_offered() {
    let obs = Observation {
        in_applications: false,
        ..ready()
    };
    let view = derive(&obs, NOW);
    assert_eq!(view.primary, Primary::MoveToApplications);
    assert!(!view.actions.connect && view.actions.setup.is_none());
}

#[test]
fn approval_states_point_to_system_settings() {
    for obs in [
        Observation {
            extension: ExtensionState::AwaitingApproval,
            ..ready()
        },
        Observation {
            extension: ExtensionState::NotFound,
            approval_requested: true,
            ..ready()
        },
        Observation {
            extension: ExtensionState::Disabled,
            ..ready()
        },
    ] {
        let view = derive(&obs, NOW);
        assert_eq!(view.primary, Primary::NeedsApproval);
        assert_eq!(view.title, "Needs approval in System Settings");
        assert!(view.actions.open_settings);
        assert_eq!(view.actions.setup, Some(SetupStep::ActivateExtension));
        assert!(!view.actions.connect);
    }
}

#[test]
fn a_missing_extension_starts_setup() {
    let obs = Observation {
        extension: ExtensionState::NotFound,
        ..ready()
    };
    let view = derive(&obs, NOW);
    assert_eq!(view.primary, Primary::Setup(SetupStep::ActivateExtension));
    assert_eq!(next_setup_step(&view), Some(SetupStep::ActivateExtension));
    assert!(!view.actions.import && !view.actions.connect);
}

#[test]
fn a_ready_mac_is_disconnected_and_can_connect_or_import() {
    let view = derive(&ready(), NOW);
    assert_eq!(view.primary, Primary::Disconnected);
    assert_eq!(view.symbol, "shield");
    assert!(view.actions.connect && view.actions.import);
    assert!(!view.actions.disconnect && !view.actions.force_stop);
    assert!(view.details.iter().any(|d| d == "Leak guard: on"));
    assert!(view
        .details
        .iter()
        .any(|d| d.starts_with("Certificate: valid until")));
}

#[test]
fn connecting_turns_into_blocked_after_the_grace() {
    let fresh = derive(&with_status(2, NOW - 5), NOW);
    assert_eq!(fresh.primary, Primary::Connecting);
    assert!(fresh.actions.disconnect && !fresh.actions.connect && !fresh.actions.import);
    let stuck = derive(&with_status(2, NOW - CONNECTING_GRACE_SECS - 1), NOW);
    assert_eq!(
        stuck.primary,
        Primary::Blocked(BlockReason::StillConnecting)
    );
    assert!(stuck.actions.force_stop && stuck.actions.disconnect);
}

#[test]
fn connected_and_reasserting_tunnels() {
    let connected = Observation {
        filter: filter("ok", Some("guarding")),
        ..with_status(3, NOW - 600)
    };
    let view = derive(&connected, NOW);
    assert_eq!(view.primary, Primary::Connected);
    assert_eq!(view.symbol, "lock.shield.fill");
    assert!(view.actions.disconnect && !view.actions.connect && !view.actions.import);
    assert!(view
        .details
        .iter()
        .any(|d| d == "Leak guard: on, guarding traffic"));
    let blocked = derive(&with_status(4, NOW - 3), NOW);
    assert_eq!(blocked.primary, Primary::Blocked(BlockReason::Reconnecting));
    assert_eq!(blocked.title, "Blocked by leak guard (reconnecting)");
    assert!(blocked.actions.force_stop);
}

#[test]
fn an_expired_certificate_blocks_or_asks_for_a_new_invitation() {
    let up = Observation {
        cert: Some(cert("expired", NOW - 10)),
        ..with_status(4, NOW - 300)
    };
    let view = derive(&up, NOW);
    assert_eq!(view.primary, Primary::CertificateExpired { blocked: true });
    assert!(view.actions.force_stop && view.actions.disconnect);
    let down = Observation {
        cert: Some(cert("superseded", NOW + 10)),
        ..ready()
    };
    let view = derive(&down, NOW);
    assert_eq!(view.primary, Primary::CertificateExpired { blocked: false });
    assert!(!view.actions.connect && view.actions.import);
    // The provider's refusal says so even without a certificate record.
    let refused = Observation {
        cert: None,
        provider: Probe::Ok(StatusReport {
            session_phase: "none".into(),
            session_refusal: Some("session_identity_expired".into()),
        }),
        ..ready()
    };
    assert_eq!(
        derive(&refused, NOW).primary,
        Primary::CertificateExpired { blocked: false }
    );
}

#[test]
fn setup_steps_follow_their_order() {
    let guard_off = Observation {
        filter: filter("not_configured", None),
        identity_present: Some(false),
        profiles: Probe::Ok(Vec::new()),
        ..ready()
    };
    let view = derive(&guard_off, NOW);
    assert_eq!(view.primary, Primary::Setup(SetupStep::TurnOnLeakGuard));
    assert!(view.actions.enable_guard);
    let no_identity = Observation {
        identity_present: Some(false),
        profiles: Probe::Ok(Vec::new()),
        ..ready()
    };
    let view = derive(&no_identity, NOW);
    assert_eq!(view.primary, Primary::Setup(SetupStep::ImportIdentity));
    assert!(!view.actions.connect && view.actions.import);
    let no_profile = Observation {
        profiles: Probe::Ok(Vec::new()),
        ..ready()
    };
    let view = derive(&no_profile, NOW);
    assert_eq!(view.primary, Primary::Setup(SetupStep::AddVpnConfiguration));
    // Connect saves the profile itself (the same `--save-profile`).
    assert!(view.actions.connect);
}

#[test]
fn a_newer_app_asks_to_finish_its_update_only_when_disconnected() {
    let obs = Observation {
        extension: ExtensionState::Enabled {
            build: Some("38".into()),
        },
        ..ready()
    };
    assert_eq!(
        derive(&obs, NOW).primary,
        Primary::Setup(SetupStep::UpdateExtension)
    );
    let up = Observation {
        extension: ExtensionState::Enabled {
            build: Some("38".into()),
        },
        ..with_status(3, NOW - 60)
    };
    let view = derive(&up, NOW);
    assert_eq!(view.primary, Primary::Connected);
    assert!(view.details.iter().any(|d| d.starts_with("Update ready")));
}

#[test]
fn an_unreachable_provider_is_reported() {
    let obs = Observation {
        provider: Probe::Failed {
            exit: Some(69),
            code: Some("xpc_connection_invalid".into()),
        },
        ..ready()
    };
    let view = derive(&obs, NOW);
    assert_eq!(view.primary, Primary::ExtensionNotResponding);
    assert!(!view.actions.connect);
}

#[test]
fn a_running_action_disables_every_other_action() {
    let obs = Observation {
        activity: Some(Activity::Connecting),
        ..ready()
    };
    let view = derive(&obs, NOW);
    assert_eq!(view.primary, Primary::Busy(Activity::Connecting));
    assert_eq!(view.title, "Connecting…");
    assert!(!view.actions.connect && !view.actions.disconnect && !view.actions.import);
    assert!(view.actions.setup.is_none() && !view.actions.force_stop);
}

#[test]
fn a_pending_renewal_is_shown_and_connect_retries_it() {
    let obs = Observation {
        cert: Some(cert("pending", NOW + 86_400)),
        ..ready()
    };
    let view = derive(&obs, NOW);
    assert_eq!(view.primary, Primary::CertificateRenewing);
    assert!(view.actions.connect);
}

#[test]
fn a_stuck_disconnect_offers_the_forced_stop() {
    let fresh = derive(&with_status(5, NOW - 2), NOW);
    assert_eq!(fresh.primary, Primary::Disconnecting);
    assert!(!fresh.actions.force_stop);
    let stuck = derive(&with_status(5, NOW - DISCONNECTING_GRACE_SECS - 1), NOW);
    assert!(stuck.actions.force_stop);
}

#[test]
fn the_status_age_restarts_when_the_status_changes() {
    let mut obs = with_status(2, NOW - 300);
    obs.note_status(NOW);
    assert_eq!(obs.status_since, Some((2, NOW - 300)));
    obs.profiles = Probe::Ok(vec![profile(3)]);
    obs.note_status(NOW);
    assert_eq!(obs.status_since, Some((3, NOW)));
    obs.profiles = Probe::Ok(Vec::new());
    obs.note_status(NOW);
    assert_eq!(obs.status_since, None);
}

#[test]
fn import_refusals_are_explained() {
    assert!(
        explain::import(Some(66), Some("import_source_unexpected_entry")).contains(".DS_Store")
    );
    assert!(explain::import(Some(66), Some("import_source_not_private")).contains("Get Info"));
    assert!(explain::import(Some(67), None).contains("Nothing was changed"));
    assert!(explain::import(Some(65), Some("session_live")).starts_with("Disconnect first"));
    assert!(explain::import(None, None).contains("folder was kept"));
    assert_eq!(
        explain::with_code("Failed.", Some("x_code")),
        "Failed. (code: x_code)"
    );
}

// ---------------------------------------------------------------------------
// v45: joining with an invitation file, and the Russian menu.

#[test]
fn join_is_prominent_without_an_identity_or_with_a_dead_certificate() {
    let no_identity = Observation {
        identity_present: Some(false),
        profiles: Probe::Ok(Vec::new()),
        ..ready()
    };
    let view = derive(&no_identity, NOW);
    assert_eq!(view.primary, Primary::Setup(SetupStep::ImportIdentity));
    assert_eq!(view.title, "Setup needed: join with your invitation");
    assert!(view.actions.join && view.actions.join_prominent);
    assert!(no_identity.identity_replaceable(NOW));

    let expired = Observation {
        cert: Some(cert("expired", NOW - 10)),
        ..ready()
    };
    let view = derive(&expired, NOW);
    assert_eq!(view.primary, Primary::CertificateExpired { blocked: false });
    assert_eq!(view.title, "Certificate expired: ask for a new invitation");
    assert!(view.actions.join && view.actions.join_prominent);
    assert!(expired.identity_replaceable(NOW));
    assert!(view
        .details
        .iter()
        .any(|d| d.contains("ask for a new invitation")));

    // A working identity: Join stays in the More submenu and asks first.
    let view = derive(&ready(), NOW);
    assert!(view.actions.join && !view.actions.join_prominent);
    assert!(!ready().identity_replaceable(NOW));
    let unknown = Observation {
        identity_present: None,
        cert: None,
        ..ready()
    };
    assert!(!unknown.identity_replaceable(NOW));

    // Never while a tunnel is up or an action runs.
    let up = derive(&with_status(3, NOW - 60), NOW);
    assert!(!up.actions.join);
    let busy = Observation {
        activity: Some(Activity::Joining(JoinStep::Contacting)),
        ..ready()
    };
    let view = derive(&busy, NOW);
    assert_eq!(view.title, "Joining: contacting the AEGIS server…");
    assert!(!view.actions.join && !view.actions.connect);
}

#[test]
fn a_progress_line_names_one_join_step() {
    use crate::host_enroll::{PROGRESS, STEPS};
    let steps: Vec<_> = STEPS
        .iter()
        .map(|step| JoinStep::from_progress(&format!("{PROGRESS}{step}")))
        .collect();
    assert!(steps.iter().all(Option::is_some), "{steps:?}");
    assert_eq!(JoinStep::from_progress("enroll_progress=other"), None);
    assert_eq!(JoinStep::from_progress("contacting"), None);
}

fn cyrillic(text: &str) -> bool {
    text.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c))
}

#[test]
fn every_menu_string_has_a_russian_text() {
    use crate::menu_l10n::{with, Lang};
    let primaries = [
        Primary::Checking,
        Primary::MoveToApplications,
        Primary::NeedsApproval,
        Primary::Setup(SetupStep::ActivateExtension),
        Primary::Setup(SetupStep::UpdateExtension),
        Primary::Setup(SetupStep::TurnOnLeakGuard),
        Primary::Setup(SetupStep::ImportIdentity),
        Primary::Setup(SetupStep::AddVpnConfiguration),
        Primary::Busy(Activity::Importing),
        Primary::Disconnected,
        Primary::Connecting,
        Primary::Connected,
        Primary::Disconnecting,
        Primary::Blocked(BlockReason::Reconnecting),
        Primary::Blocked(BlockReason::StillConnecting),
        Primary::CertificateExpired { blocked: true },
        Primary::CertificateExpired { blocked: false },
        Primary::CertificateRenewing,
        Primary::ExtensionNotResponding,
    ];
    let activities = [
        Activity::Checking,
        Activity::Activating,
        Activity::EnablingGuard,
        Activity::Importing,
        Activity::Joining(JoinStep::Checking),
        Activity::Joining(JoinStep::Preparing),
        Activity::Joining(JoinStep::Contacting),
        Activity::Joining(JoinStep::Approving),
        Activity::Joining(JoinStep::Importing),
        Activity::SavingProfile,
        Activity::Connecting,
        Activity::Disconnecting,
        Activity::Stopping,
    ];
    let facets = [
        CertFacet::Unknown,
        CertFacet::Valid {
            not_after: Some(NOW + 3600),
        },
        CertFacet::Valid {
            not_after: Some(NOW + 30 * 86400),
        },
        CertFacet::Renewing { not_after: None },
        CertFacet::Deferred {
            not_after: Some(NOW),
        },
        CertFacet::Failing {
            class: "timeout".into(),
            not_after: None,
        },
        CertFacet::Pending,
        CertFacet::Parked { not_after: None },
        CertFacet::Superseded,
        CertFacet::Expired {
            not_after: Some(NOW - 1),
        },
        CertFacet::NotYetValid,
    ];
    let mut explanations: Vec<Box<dyn Fn() -> String>> = Vec::new();
    for exit in [
        Some(0),
        Some(10),
        Some(11),
        Some(12),
        Some(13),
        Some(14),
        Some(75),
        Some(99),
        None,
    ] {
        explanations.push(Box::new(move || explain::activation(exit)));
    }
    for outcome in [Some("ok"), Some("permission_denied"), Some("timeout"), None] {
        explanations.push(Box::new(move || explain::enable_filter(outcome)));
    }
    for (exit, code) in [
        (Some(0), None),
        (Some(66), Some("import_source_missing")),
        (Some(66), Some("import_source_not_private")),
        (Some(66), Some("import_source_unexpected_entry")),
        (Some(66), Some("import_source_symlink")),
        (Some(66), None),
        (Some(67), None),
        (Some(65), Some("session_live")),
        (Some(65), None),
        (Some(69), None),
        (Some(73), None),
        (Some(74), None),
        (Some(76), None),
        (Some(77), None),
        (Some(1), None),
    ] {
        explanations.push(Box::new(move || explain::import(exit, code)));
    }
    for (exit, code) in [
        (Some(0), None),
        (Some(73), None),
        (Some(74), None),
        (Some(40), Some("invite_symlink")),
        (Some(40), Some("invite_extension_required")),
        (Some(40), Some("invite_linked")),
        (Some(40), Some("invite_missing")),
        (Some(40), Some("invite_not_canonical")),
        (Some(41), None),
        (Some(42), None),
        (Some(43), None),
        (Some(44), None),
        (Some(45), Some("enroll_certificate_expired")),
        (Some(45), Some("enroll_clock_failed")),
        (Some(45), Some("enroll_busy")),
        (Some(45), None),
        (Some(46), None),
        (Some(67), None),
        (Some(69), None),
        (Some(65), None),
        (Some(75), None),
        (Some(3), None),
    ] {
        explanations.push(Box::new(move || explain::join(exit, code)));
    }
    for exit in [Some(65), Some(69), None] {
        explanations.push(Box::new(move || explain::provider(exit)));
    }
    for code in [
        Some("connect_state_refused"),
        Some("existing_profile_not_idle"),
        Some("multiple_provider_profiles_refused"),
        Some("operation_expired"),
        Some("profile_save_failed"),
        Some("profile_relay_mismatch"),
        Some("provider_start_refused"),
        None,
    ] {
        explanations.push(Box::new(move || explain::profile(code)));
    }
    let english: Vec<String> = primaries
        .iter()
        .map(|p| p.title())
        .chain(activities.iter().map(|a| a.label().to_owned()))
        .chain(facets.iter().map(|f| f.text(NOW)))
        .chain(explanations.iter().map(|e| e()))
        .collect();
    let russian: Vec<String> = with(Lang::Ru, || {
        primaries
            .iter()
            .map(|p| p.title())
            .chain(activities.iter().map(|a| a.label().to_owned()))
            .chain(facets.iter().map(|f| f.text(NOW)))
            .chain(explanations.iter().map(|e| e()))
            .collect()
    });
    assert_eq!(english.len(), russian.len());
    for (en, ru) in english.iter().zip(&russian) {
        assert!(!cyrillic(en), "English text has Cyrillic: {en}");
        assert!(cyrillic(ru) && en != ru, "missing Russian for: {en}");
    }
    // A whole menu in Russian.
    let view = with(Lang::Ru, || derive(&ready(), NOW));
    assert_eq!(view.title, "Отключено");
    assert!(
        view.details.iter().all(|d| cyrillic(d)),
        "{:?}",
        view.details
    );
    assert_eq!(
        with(Lang::Ru, || explain::with_code("Текст", Some("code_x"))),
        "Текст (код: code_x)"
    );
}
