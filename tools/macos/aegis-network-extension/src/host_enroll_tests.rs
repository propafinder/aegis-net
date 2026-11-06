use super::*;
use crate::{
    app_group::CapturedAppGroupInputs,
    host_import::{conclude_import, tests::InProcessProvider, SourceTree},
    host_lifecycle::{parse_host_args, HostCommand},
    identity_import::{
        authorization::{test_support::fresh_form, IdentityChange},
        tests::TempContainer,
    },
    invite_package::tests::{bundle_of, package_for, token},
    provider_xpc::query_import,
    test_enrollment::{Answer, TestAuthority},
    test_fixture::{Issuance, ReadyTree},
};
use std::os::unix::fs::PermissionsExt;
use zeroize::Zeroizing;

/// A tree whose signed profile names a fresh loopback authority, and that
/// authority's listener.
fn tree_with_authority() -> (ReadyTree, std::net::TcpListener) {
    let listener = TestAuthority::bind();
    let tree = ReadyTree::issued_as(
        "127.0.0.1:443".parse().unwrap(),
        Issuance {
            authority: listener.local_addr().unwrap(),
            ..Issuance::default()
        },
    );
    (tree, listener)
}

fn always(answer: Answer) -> impl FnMut(usize, Option<ProofPurpose>) -> Answer + Send + 'static {
    move |_, purpose| {
        if purpose.is_some() {
            answer
        } else {
            Answer::Issue
        }
    }
}

fn run(package: &InvitePackage, root: &Path) -> (Result<Staged, Failure>, Vec<&'static str>) {
    let mut steps = Vec::new();
    let staged = stage(package, root, &mut |step| steps.push(step));
    (staged, steps)
}

fn leaves(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// Every file below `dir`.
fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

const ISSUED_IDENTITY: [&str; 8] = [
    ".lock",
    "bundle-profile.sha256",
    "device-ca.pem",
    "device.csr",
    "device.key",
    "device.pem",
    "identity.json",
    "online-completed.json",
];

#[test]
fn join_stages_redeems_and_imports_the_new_identity_end_to_end() {
    let (tree, listener) = tree_with_authority();
    let secret = token();
    let authority =
        TestAuthority::spawn_redeem(listener, &tree, &secret, 24 * 3600, always(Answer::Issue));
    let package = package_for(&tree, &secret);
    let home = TempContainer::new();
    let root = home.path().join(ENROLL_DIR);

    let (staged, steps) = run(&package, &root);
    let staged = staged.unwrap();
    assert_eq!(staged.redeemed, Redeemed::Issued);
    assert_eq!(steps, ["preparing", "contacting"]);
    assert!(steps.iter().all(|step| STEPS.contains(step)));
    assert_eq!(staged.dir, root.join(package.staging_name()));
    assert_eq!(leaves(&staged.dir), ["bundle", "identity"]);
    assert_eq!(leaves(&staged.dir.join("identity")), ISSUED_IDENTITY);
    assert_eq!(
        std::fs::symlink_metadata(&staged.dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    for file in files(&staged.dir) {
        let bytes = std::fs::read(&file).unwrap();
        assert!(!contains(&bytes, secret.as_bytes()), "{}", file.display());
        if file.starts_with(staged.dir.join("identity")) {
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o077,
                0
            );
        }
    }
    // Exactly one request reached the authority: an authorization that
    // carried the invitation.
    let seen = authority.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].purpose, ProofPurpose::Authorize);
    assert!(seen[0].invited);
    assert_eq!(
        seen[0].operation,
        aegis_core::secure_channel::enrollment::protocol::Operation::Redeem
    );
    assert_eq!(authority.issued(), 1);

    // The existing import admits the staging tree, commits it and removes it.
    let target = TempContainer::new();
    let provider = InProcessProvider::new(target.path());
    let source = SourceTree::open(&staged.dir).unwrap();
    let reply = query_import(&provider, source.payload(), &fresh_form());
    let outcome = conclude_import(&source, reply, true);
    drop(source);
    assert_eq!(outcome.exit, 0, "{outcome:?}");
    assert!(import_committed(&outcome));
    let line = import_line(staged.redeemed, &outcome, "kept");
    assert_eq!(
        line,
        "enroll_result=joined stage=done redeem=issued import=committed staging=removed invite=kept"
    );
    assert!(!staged.dir.exists());
    assert_eq!(leaves(&root), Vec::<String>::new());
    // The provider capture admits the committed identity: a new key and
    // certificate, the fixture's bundle.
    drop(CapturedAppGroupInputs::capture_test_root(target.path()).unwrap());
    let committed = std::fs::read(target.path().join("Aegis/identity/device.pem")).unwrap();
    assert_ne!(committed, tree.certificate_pem().as_bytes());
    assert_eq!(
        std::fs::read(target.path().join("Aegis/bundle/bundle.json")).unwrap(),
        bundle_of(&tree)[0]
    );
}

#[test]
fn a_second_run_resumes_the_journaled_request_instead_of_reusing_the_token_blindly() {
    let (tree, listener) = tree_with_authority();
    let secret = token();
    // Three busy answers (the whole first run), then issue.
    let authority = TestAuthority::spawn_redeem(
        listener,
        &tree,
        &secret,
        24 * 3600,
        |index, purpose| match (index, purpose) {
            (0..=2, Some(_)) => Answer::Busy,
            _ => Answer::Issue,
        },
    );
    let package = package_for(&tree, &secret);
    let home = TempContainer::new();
    let root = home.path().join(ENROLL_DIR);

    let (first, _) = run(&package, &root);
    let failure = first.expect_err("staged");
    assert_eq!(failure, Failure::Unreachable("enroll_authority_busy"));
    assert_eq!(failure.exit(), EXIT_ENROLL_UNREACHABLE);
    let identity = root.join(package.staging_name()).join("identity");
    assert!(identity.join("online-request.json").exists());
    assert!(!identity.join("device.pem").exists());

    let (second, _) = run(&package, &root);
    let staged = second.unwrap();
    assert_eq!(staged.redeemed, Redeemed::Resumed);
    let seen = authority.seen();
    let purposes: Vec<_> = seen.iter().map(|s| s.purpose).collect();
    assert_eq!(
        purposes,
        [
            ProofPurpose::Authorize,
            ProofPurpose::Receipt,
            ProofPurpose::Receipt,
            // The second run asks for the receipt first, then authorizes
            // the same request.
            ProofPurpose::Receipt,
            ProofPurpose::Authorize,
        ]
    );
    let invited: Vec<_> = seen.iter().map(|s| s.invited).collect();
    assert_eq!(invited, [true, false, false, false, true]);
    assert!(seen.iter().all(|s| s.request_id == seen[0].request_id));
    assert_eq!(authority.issued(), 1);
    assert!(!identity.join("online-request.json").exists());
    assert_eq!(leaves(&identity), ISSUED_IDENTITY);
}

#[test]
fn a_lost_response_is_recovered_by_its_receipt_without_a_second_authorization() {
    let (tree, listener) = tree_with_authority();
    let secret = token();
    let authority = TestAuthority::spawn_redeem(
        listener,
        &tree,
        &secret,
        24 * 3600,
        |index, purpose| match (index, purpose) {
            (0, Some(_)) => Answer::DropResponse,
            _ => Answer::Issue,
        },
    );
    let package = package_for(&tree, &secret);
    let home = TempContainer::new();
    let (staged, _) = run(&package, &home.path().join(ENROLL_DIR));
    assert_eq!(staged.unwrap().redeemed, Redeemed::Issued);
    let purposes: Vec<_> = authority.seen().iter().map(|s| s.purpose).collect();
    assert_eq!(purposes, [ProofPurpose::Authorize, ProofPurpose::Receipt]);
    assert_eq!(authority.issued(), 1);
}

#[test]
fn a_rejected_or_already_used_invitation_fails_with_its_own_code() {
    let (tree, listener) = tree_with_authority();
    let secret = token();
    let authority =
        TestAuthority::spawn_redeem(listener, &tree, &secret, 24 * 3600, always(Answer::Issue));
    let home = TempContainer::new();
    let root = home.path().join(ENROLL_DIR);

    // Another token than the authority's.
    let wrong = package_for(&tree, &token());
    let failure = run(&wrong, &root).0.expect_err("staged");
    assert_eq!(failure, Failure::Rejected);
    assert_eq!(failure.exit(), EXIT_ENROLL_REJECTED);
    assert_eq!(failure.code(), "enroll_invitation_rejected");
    assert_eq!(
        failure.line(),
        "enroll_result=failed stage=redeem redeem=rejected import=not_sent staging=kept invite=kept"
    );
    // Review fix: a rejected invitation leaves nothing behind (its request
    // can never be issued: no uncertified key, no dead token).
    assert!(!root.join(wrong.staging_name()).exists());

    // The right token, spent by one join: a second Mac (another staging
    // root, another key and request) is refused.
    let package = package_for(&tree, &secret);
    assert!(run(&package, &root).0.is_ok());
    let other = TempContainer::new();
    let failure = run(&package, &other.path().join(ENROLL_DIR))
        .0
        .expect_err("staged");
    assert_eq!(failure, Failure::Rejected);
    assert_eq!(authority.issued(), 1);
}

#[test]
fn an_unreachable_authority_writes_no_request_and_a_rerun_starts_cleanly() {
    let (tree, listener) = tree_with_authority();
    let secret = token();
    let package = package_for(&tree, &secret);
    let home = TempContainer::new();
    let root = home.path().join(ENROLL_DIR);
    {
        // Every connection ends right after the TCP accept.
        let authority =
            TestAuthority::spawn_redeem(listener, &tree, &secret, 24 * 3600, |_, _| Answer::Close);
        let failure = run(&package, &root).0.expect_err("staged");
        assert!(matches!(failure, Failure::Unreachable(_)), "{failure:?}");
        assert_eq!(failure.exit(), EXIT_ENROLL_UNREACHABLE);
        assert_eq!(authority.seen().len(), 0);
        assert_eq!(authority.accepts(), ATTEMPTS as usize);
    }
    // Nothing listens any more: refused connects, still no request.
    let failure = run(&package, &root).0.expect_err("staged");
    assert_eq!(
        failure,
        Failure::Unreachable("enroll_authority_unavailable")
    );
    let identity = root.join(package.staging_name()).join("identity");
    assert!(!identity.join("online-request.json").exists());
    assert!(identity.join("device.key").exists());
}

#[test]
fn an_issued_identity_whose_import_did_not_finish_goes_straight_to_the_import() {
    let (tree, listener) = tree_with_authority();
    let secret = token();
    let authority =
        TestAuthority::spawn_redeem(listener, &tree, &secret, 24 * 3600, always(Answer::Issue));
    let package = package_for(&tree, &secret);
    let home = TempContainer::new();
    let root = home.path().join(ENROLL_DIR);
    let first = run(&package, &root).0.unwrap();
    let key = std::fs::read(first.dir.join("identity/device.key")).unwrap();
    let accepts = authority.accepts();
    let (again, steps) = run(&package, &root);
    let again = again.unwrap();
    assert_eq!(again.redeemed, Redeemed::Earlier);
    assert_eq!(steps, ["preparing"]);
    assert_eq!(authority.accepts(), accepts, "no new connection");
    assert_eq!(again.not_after, first.not_after);
    assert_eq!(
        std::fs::read(again.dir.join("identity/device.key")).unwrap(),
        key
    );
}

#[test]
fn a_changed_staging_tree_or_another_invitation_is_refused() {
    let (tree, listener) = tree_with_authority();
    let secret = token();
    let _authority =
        TestAuthority::spawn_redeem(listener, &tree, &secret, 24 * 3600, always(Answer::Busy));
    let package = package_for(&tree, &secret);
    let home = TempContainer::new();
    let root = home.path().join(ENROLL_DIR);
    assert!(run(&package, &root).0.is_err());
    let dir = root.join(package.staging_name());

    // A changed public bundle member.
    let member = dir.join("bundle/inner-ca.pem");
    let original = std::fs::read(&member).unwrap();
    std::fs::write(&member, b"changed").unwrap();
    assert_eq!(
        run(&package, &root).0.err(),
        Some(Failure::Local(enroll_journal::CONFLICT))
    );
    std::fs::write(&member, &original).unwrap();
    // An entry no join writes (Finder's .DS_Store).
    std::fs::write(dir.join(".DS_Store"), b"").unwrap();
    assert_eq!(
        run(&package, &root).0.err(),
        Some(Failure::Local(enroll_journal::CONFLICT))
    );
    std::fs::remove_file(dir.join(".DS_Store")).unwrap();
    // A staging directory others may enter.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        run(&package, &root).0.err(),
        Some(Failure::Local(enroll_journal::CONFLICT))
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    // The journaled request belongs to this package's token only.
    let journal = EnrollJournal::open(&dir.join("identity")).unwrap();
    let profile = package.profile_sha256();
    assert!(journal.journaled(&profile, &secret).unwrap().is_some());
    assert_eq!(
        journal.journaled(&profile, &token()).err(),
        Some(enroll_journal::INVITATION_CONFLICT)
    );
    // A second join of the same package waits for the lock.
    assert_eq!(
        run(&package, &root).0.err(),
        Some(Failure::Local(enroll_journal::BUSY))
    );
    drop(journal);

    // Unrecorded key material is never adopted.
    let stray = TempContainer::new();
    let identity = stray.path().join("identity");
    std::fs::create_dir(&identity).unwrap();
    std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(identity.join("device.key"), b"stray").unwrap();
    std::fs::set_permissions(
        identity.join("device.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let journal = EnrollJournal::open(&identity).unwrap();
    assert_eq!(
        journal.prepare(tree.device_id(), tree.device_ca_pem().as_bytes()),
        Err(enroll_journal::CONFLICT)
    );
}

#[test]
fn the_redeem_request_keeps_the_binary_layout_and_the_renewal_journal_never_parses_it() {
    let (tree, listener) = tree_with_authority();
    let secret = token();
    let _authority =
        TestAuthority::spawn_redeem(listener, &tree, &secret, 24 * 3600, always(Answer::Busy));
    let package = package_for(&tree, &secret);
    let home = TempContainer::new();
    let root = home.path().join(ENROLL_DIR);
    assert!(run(&package, &root).0.is_err());
    let request = std::fs::read(
        root.join(package.staging_name())
            .join("identity/online-request.json"),
    )
    .unwrap();
    let text = std::str::from_utf8(&request).unwrap();
    assert!(
        text.starts_with("{\"version\":1,\"binding\":{\"operation\":\"redeem\","),
        "{text:.60}"
    );
    assert!(text.ends_with(&format!(
        ",\"predecessor_certificate_pem\":null,\"invitation\":\"{}\"}}",
        secret.as_str()
    )));
    assert_eq!(
        enroll_journal::test_access::pending_round_trip(&request).as_deref(),
        Some(request.as_slice())
    );
    assert!(!crate::renewal_journal::test_access::pending_parses(
        &request
    ));
}

#[test]
fn precheck_refuses_a_live_session_and_a_working_identity_unless_replaced() {
    let now = 1_800_000_000;
    let idle = ProviderView {
        session_phase: "none".into(),
        ..ProviderView::default()
    };
    assert_eq!(precheck(&idle, false, now), Ok(()));
    for phase in LIVE_PHASES {
        let live = ProviderView {
            session_phase: phase.into(),
            ..idle.clone()
        };
        assert_eq!(
            precheck(&live, true, now),
            Err(Failure::SessionLive),
            "{phase}"
        );
    }
    // Review fix: a session that ended (`joined`, kept until the provider
    // restarts) is no live session, and its expiry refusal makes the held
    // identity replaceable without asking.
    let ended = ProviderView {
        session_phase: "joined".into(),
        identity_present: true,
        session_refusal: Some("session_identity_expired".into()),
        ..ProviderView::default()
    };
    assert_eq!(precheck(&ended, false, now), Ok(()));
    assert_eq!(Failure::SessionLive.exit(), EXIT_ENROLL_SESSION_LIVE);
    let valid = ProviderView {
        identity_present: true,
        cert_state: Some("valid".into()),
        not_after: Some(now + 3600),
        ..idle.clone()
    };
    assert_eq!(precheck(&valid, false, now), Err(Failure::IdentityPresent));
    assert_eq!(
        Failure::IdentityPresent.exit(),
        EXIT_ENROLL_IDENTITY_PRESENT
    );
    assert_eq!(precheck(&valid, true, now), Ok(()));
    // Unknown validity (no session since the provider started) is kept.
    let unknown = ProviderView {
        identity_present: true,
        ..idle.clone()
    };
    assert_eq!(
        precheck(&unknown, false, now),
        Err(Failure::IdentityPresent)
    );
    for dead in [
        ProviderView {
            cert_state: Some("expired".into()),
            ..unknown.clone()
        },
        ProviderView {
            cert_state: Some("superseded".into()),
            ..unknown.clone()
        },
        ProviderView {
            cert_state: Some("valid".into()),
            not_after: Some(now),
            ..unknown.clone()
        },
        ProviderView {
            session_refusal: Some("session_identity_expired".into()),
            ..unknown.clone()
        },
    ] {
        assert!(dead.identity_dead(now), "{dead:?}");
        assert_eq!(precheck(&dead, false, now), Ok(()), "{dead:?}");
    }
}

#[test]
fn every_result_line_and_code_is_stable_and_masked() {
    let failures = [
        (
            Failure::Package("invite_not_canonical"),
            40,
            "refused",
            "package",
        ),
        (Failure::IdentityPresent, 41, "refused", "precheck"),
        (Failure::SessionLive, 42, "refused", "precheck"),
        (Failure::Rejected, 43, "failed", "redeem"),
        (
            Failure::Unreachable("enroll_authority_timeout"),
            44,
            "failed",
            "redeem",
        ),
        (Failure::Local(enroll_journal::WRITE), 45, "failed", "stage"),
        (Failure::RecoveryRequired, 46, "failed", "redeem"),
        (
            Failure::Provider(69, "service_unavailable"),
            69,
            "refused",
            "precheck",
        ),
    ];
    for (failure, exit, result, stage) in failures {
        assert_eq!(failure.exit(), exit, "{failure:?}");
        let line = failure.line();
        assert_eq!(field(&line, "enroll_result"), Some(result), "{line}");
        assert_eq!(field(&line, "stage"), Some(stage), "{line}");
        assert_eq!(field(&line, "import"), Some("not_sent"), "{line}");
        assert_eq!(field(&line, "invite"), Some("kept"), "{line}");
        assert!(!line.contains('/') && !line.contains(':'), "{line}");
        let code = failure.code();
        assert!(
            crate::menu_model::stderr_code(code).as_deref() == Some(code),
            "{code}"
        );
    }
    for code in enroll_journal::CODES {
        assert_eq!(crate::menu_model::stderr_code(code).as_deref(), Some(code));
    }
    assert_eq!(
        crate::menu_model::stderr_code(&format!("{PROGRESS}contacting")),
        None,
        "a progress line is never read as a code"
    );
    let refused = ImportOutcome {
        stdout: "import_result=refused manifest_match=false source=kept".into(),
        stderr: Some("provider_refused session_live".into()),
        exit: 65,
    };
    assert_eq!(
        import_line(Redeemed::Earlier, &refused, "kept"),
        "enroll_result=failed stage=import redeem=earlier import=refused staging=kept invite=kept"
    );
    assert!(!import_committed(&refused));
    let unknown = ImportOutcome {
        stdout: crate::host_import::TIMEOUT_LINE.into(),
        stderr: Some("xpc_timeout".into()),
        exit: 75,
    };
    assert_eq!(
        import_line(Redeemed::Issued, &unknown, "kept"),
        "enroll_result=unknown stage=import redeem=issued import=unknown staging=kept invite=kept"
    );
    for line in [APPROVAL_REFUSED_LINE, IMPORT_UNKNOWN_LINE] {
        assert!(line.starts_with("enroll_result="));
        assert_eq!(field(line, "staging"), Some("kept"));
    }
}

#[test]
fn enroll_parses_one_absolute_package_and_its_two_flags_in_any_order() {
    let argv = |args: &[&str]| {
        std::iter::once("aegis-ne-host")
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        parse_host_args(&argv(&["--enroll", "/Users/x/a.aegis-invite"])),
        Ok(HostCommand::Enroll {
            path: "/Users/x/a.aegis-invite".into(),
            remove_source: false,
            replace_identity: false,
        })
    );
    assert_eq!(
        parse_host_args(&argv(&[
            "--enroll",
            "--replace-identity",
            "/a.aegis-invite",
            "--remove-source"
        ])),
        Ok(HostCommand::Enroll {
            path: "/a.aegis-invite".into(),
            remove_source: true,
            replace_identity: true,
        })
    );
    for (args, code) in [
        (&["--enroll"][..], "enroll_path_required"),
        (
            &["--enroll", "a.aegis-invite"][..],
            "enroll_path_must_be_absolute",
        ),
        (&["--enroll", "/a", "/b"][..], "enroll_path_repeated"),
        (
            &["--enroll", "/a", "--remove-source", "--remove-source"][..],
            "duplicate_flag",
        ),
        (
            &["--enroll", "/a", "--replace-identity", "--replace-identity"][..],
            "duplicate_flag",
        ),
        (&["--enroll", "/a", "--force"][..], "unknown_flag"),
        (&["--enroll", "/a", "--enroll"][..], "duplicate_flag"),
    ] {
        assert_eq!(parse_host_args(&argv(args)), Err(code), "{args:?}");
    }
    assert!(crate::host_lifecycle::USAGE.contains("--enroll ABSOLUTE_FILE.aegis-invite"));
}

#[test]
fn the_join_prompt_names_the_device_in_the_system_language_and_never_a_path() {
    let english = IdentityChange::join_of("macos-friend-1", false, false).prompt();
    let english = english.to_str().unwrap();
    assert!(english.contains("\"macos-friend-1\""), "{english}");
    assert!(english.contains("(join)") && english.starts_with("AEGIS will install"));
    let russian = IdentityChange::join_of("macos-friend-1", true, false).prompt();
    let russian = russian.to_str().unwrap();
    assert!(russian.contains("«macos-friend-1»"), "{russian}");
    assert!(russian.contains("пароль администратора"));
    let hidden = IdentityChange::join_of("/Users/x/../evil", false, false).prompt();
    assert!(!hidden.to_str().unwrap().contains('/'));
    // Review fix: replacing a held identity says so, in both languages.
    let replacing = IdentityChange::join_of("macos-friend-1", false, true).prompt();
    assert!(replacing
        .to_str()
        .unwrap()
        .starts_with("AEGIS will replace this Mac's VPN device identity with \"macos-friend-1\""));
    let replacing = IdentityChange::join_of("macos-friend-1", true, true).prompt();
    assert!(replacing.to_str().unwrap().starts_with("AEGIS заменит"));
    // The package token never reaches a prompt: it is not an input.
    let _ = Zeroizing::new(String::new());
}

#[test]
fn only_this_packages_issued_identity_is_ever_sent() {
    let (tree, listener) = tree_with_authority();
    let secret = token();
    let _authority =
        TestAuthority::spawn_redeem(listener, &tree, &secret, 24 * 3600, always(Answer::Issue));
    let package = package_for(&tree, &secret);
    let home = TempContainer::new();
    let root = home.path().join(ENROLL_DIR);
    let staged = run(&package, &root).0.unwrap();
    let source = SourceTree::open(&staged.dir).unwrap();
    assert_eq!(admit_payload(&package, &staged, source.payload()), Ok(()));
    drop(source);

    // A bundle member changed after staging: refused before anything is sent.
    let member = staged.dir.join("bundle/outer-ca.pem");
    let original = std::fs::read(&member).unwrap();
    let mut changed = original.clone();
    changed.extend_from_slice(b"\n");
    std::fs::write(&member, &changed).unwrap();
    let source = SourceTree::open(&staged.dir).unwrap();
    assert_eq!(
        admit_payload(&package, &staged, source.payload()),
        Err("enroll_staging_changed")
    );
    drop(source);
    std::fs::write(&member, &original).unwrap();
    // Another package's view of the same tree (another token, same
    // device): the certificate is not the one this run staged.
    let other = Staged {
        certificate_sha256: "e".repeat(64),
        dir: staged.dir.clone(),
        redeemed: staged.redeemed,
        not_after: staged.not_after,
    };
    let source = SourceTree::open(&staged.dir).unwrap();
    assert_eq!(
        admit_payload(&package, &other, source.payload()),
        Err("enroll_staging_changed")
    );
    drop(source);
    // An optional sidecar dropped into the issued identity never rides
    // along: the next run refuses the tree before the import.
    std::fs::write(staged.dir.join("identity/web-response.toml"), b"x").unwrap();
    std::fs::set_permissions(
        staged.dir.join("identity/web-response.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(
        run(&package, &root).0.err(),
        Some(Failure::Local(enroll_journal::CONFLICT))
    );
    assert!(
        staged.dir.join("identity/device.pem").exists(),
        "issued: kept"
    );
}

#[test]
fn an_unsent_staging_tree_cut_mid_write_is_rebuilt_once() {
    let (tree, listener) = tree_with_authority();
    let secret = token();
    let authority =
        TestAuthority::spawn_redeem(listener, &tree, &secret, 24 * 3600, always(Answer::Issue));
    let package = package_for(&tree, &secret);
    let home = TempContainer::new();
    let root = home.path().join(ENROLL_DIR);
    // A cut inside the write of the device key: an empty key, no CSR, no
    // request, so nothing of it was ever sent.
    let dir = root.join(package.staging_name());
    let journal = EnrollJournal::open(&{
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir.join("identity")
    })
    .unwrap();
    journal
        .prepare(tree.device_id(), tree.device_ca_pem().as_bytes())
        .unwrap();
    drop(journal);
    std::fs::write(dir.join("identity/device.key"), b"").unwrap();
    std::fs::remove_file(dir.join("identity/device.csr")).unwrap();
    // A truncated bundle member from the same cut.
    std::fs::create_dir_all(dir.join("bundle")).unwrap();
    std::fs::set_permissions(dir.join("bundle"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(dir.join("bundle/bundle.json"), b"{").unwrap();
    std::fs::set_permissions(
        dir.join("bundle/bundle.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let staged = run(&package, &root).0.unwrap();
    assert_eq!(staged.redeemed, Redeemed::Issued);
    assert_eq!(authority.issued(), 1);
    assert_eq!(leaves(&staged.dir.join("identity")), ISSUED_IDENTITY);
}

#[test]
fn a_commit_sweeps_other_joins_that_never_got_a_certificate() {
    let (tree, listener) = tree_with_authority();
    let secret = token();
    let _authority = TestAuthority::spawn_redeem(
        listener,
        &tree,
        &secret,
        24 * 3600,
        |index, purpose| match (index, purpose) {
            (0..=2, Some(_)) => Answer::Busy,
            _ => Answer::Issue,
        },
    );
    let home = TempContainer::new();
    let root = home.path().join(ENROLL_DIR);
    // An abandoned join (journaled request, no certificate) of another file.
    let abandoned = package_for(&tree, &token());
    assert!(run(&abandoned, &root).0.is_err());
    let abandoned_dir = root.join(abandoned.staging_name());
    assert!(abandoned_dir.join("identity/online-request.json").exists());
    // An issued, not yet imported join is kept, as is one another join holds.
    let package = package_for(&tree, &secret);
    let issued = run(&package, &root).0.unwrap();
    let held = package_for(&tree, &token());
    let held_dir = root.join(held.staging_name());
    std::fs::create_dir(&held_dir).unwrap();
    std::fs::set_permissions(&held_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let lock = EnrollJournal::open(&held_dir.join("identity")).unwrap();
    // Something that is not a staging directory is never touched.
    std::fs::create_dir(root.join("notes")).unwrap();

    assert_eq!(sweep_unissued(&root), 1);
    assert!(!abandoned_dir.exists());
    assert!(issued.dir.exists());
    assert!(held_dir.exists());
    assert!(root.join("notes").exists());
    drop(lock);
    assert_eq!(sweep_unissued(&root), 1);
    assert!(!held_dir.exists());
}
