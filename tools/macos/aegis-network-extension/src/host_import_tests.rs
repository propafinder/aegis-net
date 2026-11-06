use super::*;
use crate::{
    app_group::CapturedAppGroupInputs,
    identity_import::{
        import_tree,
        tests::{gate, relay, snapshot, uid, TempContainer},
        CommittedFile, ImportReport, TreeGate,
    },
    provider_xpc::{
        query_import, respond_entries, ClientEndpoint, Endpoint, Observer, PingReport, StatusReport,
    },
    test_fixture::ReadyTree,
};
use aegis_core::https_bridge::SIDECAR;
use std::{
    cell::Cell,
    ffi::c_int,
    fs::File,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};

/// The provider side, in process: the real envelope parser and responder
/// (`respond_entries`) and the real S14 commit (`import_tree`) into a
/// temporary container. `tamper` may rewrite the reply frame.
pub(crate) struct InProcessProvider<'a> {
    target: &'a Path,
    gate: &'static TreeGate,
    tamper: fn(&mut serde_json::Value),
    exchanges: Cell<usize>,
}
impl<'a> InProcessProvider<'a> {
    pub(crate) fn new(target: &'a Path) -> Self {
        Self {
            target,
            gate: gate(),
            tamper: |_| {},
            exchanges: Cell::new(0),
        }
    }
}
impl Endpoint for InProcessProvider<'_> {
    fn require_peer(&self, _requirement: &CStr) -> c_int {
        0
    }
    fn set_handler(&self, _serve: bool) {}
    fn resume(&self) {}
    fn cancel(&self) {}
}
impl ClientEndpoint for InProcessProvider<'_> {
    fn exchange(&self, _request: &[u8]) -> Result<Vec<u8>, &'static str> {
        panic!("an import is never a bare frame");
    }
    fn exchange_entries(&self, entries: &[(&CStr, &[u8])]) -> Result<Vec<u8>, &'static str> {
        self.exchanges.set(self.exchanges.get() + 1);
        let observer = ImportObserver {
            target: self.target,
            gate: self.gate,
        };
        let reply = respond_entries(entries, Some(uid()), &observer);
        let mut value: serde_json::Value = serde_json::from_slice(&reply).unwrap();
        (self.tamper)(&mut value);
        Ok(serde_json::to_vec(&value).unwrap())
    }
}
struct ImportObserver<'a> {
    target: &'a Path,
    gate: &'static TreeGate,
}
impl Observer for ImportObserver<'_> {
    fn ping(&self) -> PingReport {
        unreachable!("import only")
    }
    fn status(&self) -> StatusReport {
        unreachable!("import only")
    }
    fn authorize(&self, _peer_euid: u32) -> Result<(), &'static str> {
        Ok(())
    }
    fn admit_authorization(&self, form: Option<&[u8]>) -> Result<(), &'static str> {
        use crate::identity_import::authorization::{
            test_support::AdmitEveryForm, AuthorizationGate,
        };
        AuthorizationGate::new().admit(form, &AdmitEveryForm)
    }
    fn import(&self, payload: &ImportPayload) -> Result<ImportReport, &'static str> {
        import_tree(self.target, uid(), self.gate, payload, |_| {})
    }
}

fn open(tree: &ReadyTree) -> SourceTree {
    SourceTree::open(tree.aegis()).unwrap()
}

fn refusal(path: &Path) -> &'static str {
    SourceTree::open(path).err().expect("source admitted")
}

fn private_write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Neither output line names a path, a digest or any file byte.
fn assert_quiet(outcome: &ImportOutcome, source: &SourceTree, tree: &ReadyTree) {
    let text = format!("{}\n{:?}", outcome.stdout, outcome.stderr);
    assert!(!text.contains('/'), "{text}");
    assert!(!text.contains("-----BEGIN"), "{text}");
    assert!(!text.contains(tree.aegis().to_str().unwrap()), "{text}");
    for entry in source.payload().manifest().entries() {
        assert!(!text.contains(&entry.sha256), "{text}");
    }
    assert!(!outcome.stdout.contains('\n'));
}

#[test]
fn host_import_round_trips_through_the_provider_parser_and_removes_only_with_the_flag() {
    let tree = ReadyTree::new(relay());
    let target = TempContainer::new();
    let provider = InProcessProvider::new(target.path());
    let before = snapshot(tree.aegis());

    // Without --remove-source the source is untouched.
    let source = open(&tree);
    assert_eq!(source.payload().manifest().entries().len(), 11);
    let reply = query_import(
        &provider,
        source.payload(),
        &crate::identity_import::authorization::test_support::fresh_form(),
    );
    let outcome = conclude_import(&source, reply, false);
    assert_eq!(outcome.exit, 0, "{outcome:?}");
    assert_eq!(
        outcome.stdout,
        "import_result=committed manifest_match=true committed_files=12 retired_removed=true remove_source=false source=kept"
    );
    assert_eq!(outcome.stderr, None);
    assert_quiet(&outcome, &source, &tree);
    assert_eq!(snapshot(tree.aegis()), before);
    // Exactly the source bytes were committed.
    for (member, bytes) in source.payload().files() {
        let committed = std::fs::read(target.path().join("Aegis").join(member.name())).unwrap();
        assert_eq!(committed, bytes, "{}", member.name());
    }
    drop(source);

    // With --remove-source and an exact echo the whole source goes.
    let source = open(&tree);
    let reply = query_import(
        &provider,
        source.payload(),
        &crate::identity_import::authorization::test_support::fresh_form(),
    );
    let outcome = conclude_import(&source, reply, true);
    assert_eq!(outcome.exit, 0, "{outcome:?}");
    assert!(outcome
        .stdout
        .ends_with("retired_removed=true remove_source=true source=removed"));
    assert_quiet(&outcome, &source, &tree);
    assert!(std::fs::symlink_metadata(tree.aegis()).is_err());
    assert_eq!(std::fs::read_dir(tree.root()).unwrap().count(), 0);
    assert_eq!(provider.exchanges.get(), 2);

    // The committed tree is what the provider capture admits.
    drop(CapturedAppGroupInputs::capture_test_root(target.path()).unwrap());
}

#[test]
fn host_import_manifest_mismatch_keeps_the_source() {
    let tree = ReadyTree::new(relay());
    let target = TempContainer::new();
    let before = snapshot(tree.aegis());
    let source = open(&tree);

    // A provider whose echo differs from what was sent, in any way.
    // A duplicate path never decodes; every other change is a mismatch.
    let mismatch = (
        EXIT_IMPORT_MANIFEST_MISMATCH,
        "import_result=manifest_mismatch manifest_match=false source=kept",
    );
    // The provider committed, then its reply did not decode: unknown.
    let undecodable = (
        crate::host_lifecycle::EXIT_IMPORT_COMMIT_UNKNOWN,
        TIMEOUT_LINE,
    );
    let tampers: [(fn(&mut serde_json::Value), _); 7] = [
        (
            |v| v["report"]["files"][4]["sha256"] = "0".repeat(64).into(),
            mismatch,
        ),
        (|v| v["report"]["files"][0]["length"] = 1.into(), mismatch),
        (
            |v| {
                v["report"]["files"].as_array_mut().unwrap().remove(5);
            },
            mismatch,
        ),
        (
            |v| {
                let files = v["report"]["files"].as_array_mut().unwrap();
                let lock = files.pop().unwrap();
                files.insert(0, lock);
            },
            mismatch,
        ),
        (
            |v| v["report"]["files"][11]["sha256"] = "1".repeat(64).into(),
            mismatch,
        ),
        (
            |v| v["report"]["files"][1]["path"] = "bundle/bundle.json".into(),
            undecodable,
        ),
        // The commit happened, then the read-back refused: unknown, not a
        // refusal before any write.
        (
            |v| {
                let schema = v["schema"].clone();
                *v = serde_json::json!({"schema": schema, "refused": "import_commit_unverified"});
            },
            undecodable,
        ),
    ];
    for (tamper, (exit, line)) in tampers {
        let provider = InProcessProvider {
            tamper,
            ..InProcessProvider::new(target.path())
        };
        let reply = query_import(
            &provider,
            source.payload(),
            &crate::identity_import::authorization::test_support::fresh_form(),
        );
        let outcome = conclude_import(&source, reply, true);
        assert_eq!((outcome.exit, outcome.stdout.as_str()), (exit, line));
        assert_quiet(&outcome, &source, &tree);
        assert_eq!(snapshot(tree.aegis()), before);
    }

    // The echo is compared again where deletion is decided: a mismatched
    // report handed straight to the decision keeps the source.
    let good = import_tree(target.path(), uid(), gate(), source.payload(), |_| {}).unwrap();
    let mut wrong = vec![good.clone(), good.clone(), good.clone(), good.clone()];
    wrong[0].files[6].sha256 = "2".repeat(64);
    wrong[1].files[3].length += 1;
    wrong[2].files.pop();
    wrong[3].files.push(CommittedFile {
        path: "identity/identity.json".into(),
        length: 1,
        sha256: "3".repeat(64),
    });
    for report in wrong {
        let outcome = conclude_import(&source, Ok(Reply::Import(report)), true);
        assert_eq!(outcome.exit, EXIT_IMPORT_MANIFEST_MISMATCH, "{outcome:?}");
        assert_eq!(
            outcome.stdout,
            "import_result=manifest_mismatch manifest_match=false source=kept"
        );
        assert_eq!(snapshot(tree.aegis()), before);
    }

    // Refusals, failures and malformed replies keep it too. Only a refusal
    // made before the commit is `refused`, and only a failure that cannot
    // have reached the provider is `unavailable`; everything else that
    // follows delivery is `unknown`, like the timeout.
    use crate::host_lifecycle::{EXIT_IMPORT_COMMIT_UNKNOWN, EXIT_XPC_UNAVAILABLE};
    let refused = Ok(Reply::Refused("session_live".into()));
    let forget = Ok(Reply::Forget(crate::identity_import::ForgetReport {
        identity_was_present: true,
        key_material_removed: true,
    }));
    let mut cases = vec![
        (refused, EXIT_XPC_REFUSED, "refused"),
        (
            Ok(Reply::Refused("import_commit_failed".into())),
            EXIT_XPC_REFUSED,
            "refused",
        ),
        (
            Err("import_reply_mismatch"),
            EXIT_IMPORT_MANIFEST_MISMATCH,
            "manifest_mismatch",
        ),
        (forget, EXIT_IMPORT_COMMIT_UNKNOWN, "unknown"),
    ];
    for code in [
        "import_commit_unverified",
        "reply_oversized",
        "reply_unencodable",
    ] {
        cases.push((
            Ok(Reply::Refused(code.into())),
            EXIT_IMPORT_COMMIT_UNKNOWN,
            "unknown",
        ));
    }
    for code in [
        "service_interrupted",
        "xpc_error",
        "xpc_no_reply",
        "reply_malformed",
        "reply_verb_mismatch",
        "frame_oversized",
        "envelope_shape",
        "schema_mismatch",
        "an_unlisted_code",
    ] {
        cases.push((Err(code), EXIT_IMPORT_COMMIT_UNKNOWN, "unknown"));
    }
    for code in [
        "xpc_connection_create_failed",
        "xpc_message_create_failed",
        "peer_requirement_not_set",
        "peer_requirement_unsatisfied",
        "service_unavailable",
    ] {
        cases.push((Err(code), EXIT_XPC_UNAVAILABLE, "unavailable"));
    }
    for (reply, exit, result) in cases {
        let outcome = conclude_import(&source, reply, true);
        assert_eq!(outcome.exit, exit, "{outcome:?}");
        let line = if result == "unknown" {
            TIMEOUT_LINE.to_owned()
        } else {
            format!("import_result={result} manifest_match=false source=kept")
        };
        assert_eq!(outcome.stdout, line, "{outcome:?}");
        assert!(outcome.stderr.is_some(), "{outcome:?}");
        assert_eq!(snapshot(tree.aegis()), before);
    }
    // The exact echo itself would have removed it.
    let outcome = conclude_import(&source, Ok(Reply::Import(good)), true);
    assert_eq!(outcome.exit, 0, "{outcome:?}");
    assert!(std::fs::symlink_metadata(tree.aegis()).is_err());
}

#[test]
fn host_import_removal_refuses_a_source_changed_after_it_was_sent() {
    let target = TempContainer::new();
    let changes: [fn(&ReadyTree); 8] = [
        // Same inode, different bytes of the same length.
        |t| {
            let path = t.identity_dir().join("device.key");
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[40] ^= 1;
            std::fs::write(&path, bytes).unwrap();
        },
        // A new inode at a sent name.
        |t| t.write_identity_file("device.pem", b"replaced"),
        // An entry that was not sent.
        |t| private_write(&t.identity_dir().join("device.key.next"), b"x"),
        |t| private_write(&t.aegis().join("bundle/extra.pem"), b"x"),
        // A sent file removed.
        |t| std::fs::remove_file(t.aegis().join("bundle/inner-ca.pem")).unwrap(),
        // The lock replaced.
        |t| t.write_identity_file(".lock", b""),
        // An entry beside `bundle` and `identity`.
        |t| private_write(&t.aegis().join("runtime.json"), b"{}"),
        // The identity directory moved away and an identical copy put in
        // its place: the held directory is no longer at its name.
        |t| {
            let moved = t.root().join("identity-moved");
            std::fs::rename(t.identity_dir(), &moved).unwrap();
            std::fs::create_dir(t.identity_dir()).unwrap();
            std::fs::set_permissions(t.identity_dir(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            for entry in std::fs::read_dir(&moved).unwrap() {
                let entry = entry.unwrap();
                private_write(
                    &t.identity_dir().join(entry.file_name()),
                    &std::fs::read(entry.path()).unwrap(),
                );
            }
        },
    ];
    for change in changes {
        let tree = ReadyTree::new(relay());
        let source = open(&tree);
        let report = import_tree(target.path(), uid(), gate(), source.payload(), |_| {}).unwrap();
        change(&tree);
        let changed = snapshot(tree.aegis());
        let outcome = conclude_import(&source, Ok(Reply::Import(report)), true);
        assert_eq!(outcome.exit, EXIT_IMPORT_SOURCE_NOT_REMOVED, "{outcome:?}");
        assert!(outcome.stdout.ends_with("remove_source=true source=kept"));
        assert_eq!(outcome.stderr.as_deref(), Some("import_source_changed"));
        // Nothing at all was removed.
        assert_eq!(snapshot(tree.aegis()), changed);
    }

    // The provider kept its replaced tree: that exit wins, the source
    // removal is still reported.
    let tree = ReadyTree::new(relay());
    let source = open(&tree);
    let mut report = import_tree(target.path(), uid(), gate(), source.payload(), |_| {}).unwrap();
    report.retired_removed = false;
    let outcome = conclude_import(&source, Ok(Reply::Import(report)), true);
    assert_eq!(outcome.exit, EXIT_XPC_REMOVAL_INCOMPLETE, "{outcome:?}");
    assert!(outcome
        .stdout
        .ends_with("retired_removed=false remove_source=true source=removed"));
    assert!(std::fs::symlink_metadata(tree.aegis()).is_err());
}

#[test]
fn host_import_refuses_unsafe_source_dirs() {
    let fresh = || ReadyTree::new(relay());
    let mode = |path: &Path, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
    };

    let tree = fresh();
    let before = snapshot(tree.aegis());
    assert!(SourceTree::open(tree.aegis()).is_ok());
    // Opening reads only.
    assert_eq!(snapshot(tree.aegis()), before);
    assert_eq!(
        SourceTree::open(Path::new("relative/Aegis")).err(),
        Some("import_dir_must_be_absolute")
    );
    assert_eq!(
        refusal(&tree.root().join("absent")),
        "import_source_missing"
    );
    assert_eq!(
        SourceTree::open_for(tree.aegis(), uid() + 1).err(),
        Some("import_source_not_owned")
    );

    // One spelling only: links, `.`, `..` and a trailing slash are refused.
    let alias = tree.root().join("alias");
    std::os::unix::fs::symlink(tree.aegis(), &alias).unwrap();
    assert_eq!(refusal(&alias), "import_source_not_canonical");
    let linked_parent = TempContainer::new();
    let parent_link = linked_parent.path().join("parent");
    std::os::unix::fs::symlink(tree.root(), &parent_link).unwrap();
    assert_eq!(
        refusal(&parent_link.join("Aegis")),
        "import_source_not_canonical"
    );
    let root = tree.root().to_str().unwrap();
    for spelling in [
        format!("{root}/./Aegis"),
        format!("{root}/Aegis/../Aegis"),
        format!("{root}//Aegis"),
        format!("{root}/Aegis/"),
    ] {
        assert_eq!(
            refusal(&PathBuf::from(&spelling)),
            "import_source_not_canonical",
            "{spelling}"
        );
    }
    assert_eq!(
        refusal(&tree.aegis().join("bundle/bundle.json")),
        "import_source_not_directory"
    );

    // The top directory is exactly 0700; the others have no group/other bits.
    for bad in [0o750, 0o705, 0o711, 0o500, 0o1700] {
        mode(tree.aegis(), bad);
        assert_eq!(
            refusal(tree.aegis()),
            "import_source_not_private",
            "{bad:o}"
        );
    }
    mode(tree.aegis(), 0o700);
    for dir in ["bundle", "identity"] {
        for bad in [0o750, 0o701, 0o1700] {
            mode(&tree.aegis().join(dir), bad);
            assert_eq!(
                refusal(tree.aegis()),
                "import_source_not_private",
                "{dir} {bad:o}"
            );
        }
        mode(&tree.aegis().join(dir), 0o700);
    }
    // Identity files are private; public bundle files may be readable.
    mode(&tree.identity_dir().join("device.key"), 0o640);
    assert_eq!(refusal(tree.aegis()), "import_source_not_private");
    mode(&tree.identity_dir().join("device.key"), 0o600);
    mode(&tree.aegis().join("bundle/bundle.json"), 0o644);
    assert!(SourceTree::open(tree.aegis()).is_ok());

    // No link anywhere below the source.
    let tree = fresh();
    let away = tree.root().join("bundle-elsewhere");
    std::fs::rename(tree.aegis().join("bundle"), &away).unwrap();
    std::os::unix::fs::symlink(&away, tree.aegis().join("bundle")).unwrap();
    assert_eq!(refusal(tree.aegis()), "import_source_symlink");
    let tree = fresh();
    let away = tree.root().join("key-elsewhere");
    std::fs::rename(tree.identity_dir().join("device.key"), &away).unwrap();
    std::os::unix::fs::symlink(&away, tree.identity_dir().join("device.key")).unwrap();
    assert_eq!(refusal(tree.aegis()), "import_source_symlink");
    let tree = fresh();
    std::fs::hard_link(
        tree.identity_dir().join("device.key"),
        tree.root().join("hard"),
    )
    .unwrap();
    assert_eq!(refusal(tree.aegis()), "import_source_linked");
    let tree = fresh();
    let csr = tree.identity_dir().join("device.csr");
    std::fs::remove_file(&csr).unwrap();
    let fifo = std::ffi::CString::new(csr.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert_eq!(refusal(tree.aegis()), "import_source_not_regular");

    // Only import members (and the Store's empty lock) may be present.
    for extra in [
        "runtime.json",
        "bundle/extra.pem",
        "identity/online-request.json",
    ] {
        let tree = fresh();
        private_write(&tree.aegis().join(extra), b"{}");
        assert_eq!(
            refusal(tree.aegis()),
            "import_source_unexpected_entry",
            "{extra}"
        );
    }
    let tree = fresh();
    private_write(&tree.identity_dir().join(".lock"), b"x");
    assert_eq!(refusal(tree.aegis()), "import_source_lock_invalid");
    let tree = fresh();
    std::fs::remove_file(tree.identity_dir().join(".lock")).unwrap();
    assert!(SourceTree::open(tree.aegis()).is_ok());
    for missing in [
        "identity/online-completed.json",
        "identity/device.key",
        "bundle/outer-ca.pem",
    ] {
        let tree = fresh();
        std::fs::remove_file(tree.aegis().join(missing)).unwrap();
        assert_eq!(refusal(tree.aegis()), "import_source_missing", "{missing}");
    }
    let tree = fresh();
    std::fs::remove_dir_all(tree.identity_dir()).unwrap();
    assert_eq!(refusal(tree.aegis()), "import_source_missing");
    let tree = fresh();
    private_write(
        &tree.aegis().join("bundle/bundle.json"),
        &[b' '; 64 * 1024 + 1],
    );
    assert_eq!(refusal(tree.aegis()), "import_source_oversized");
    let tree = fresh();
    private_write(&tree.identity_dir().join("device.csr"), b"");
    assert_eq!(refusal(tree.aegis()), "import_file_empty");
}

#[test]
fn host_import_every_directory_and_file_must_belong_to_the_caller() {
    // Each owner check on its own: a non-root test cannot chown, so the
    // directory and file checks are driven directly with another uid.
    let tree = ReadyTree::new(relay());
    let other = uid() + 1;
    let dir = File::open(tree.aegis()).unwrap();
    let stat = fstat(&dir).unwrap();
    assert_eq!(private_mode(&stat, uid(), true), Ok(()));
    assert_eq!(
        private_mode(&stat, other, true),
        Err("import_source_not_owned")
    );
    assert_eq!(
        private_mode(&stat, other, false),
        Err("import_source_not_owned")
    );
    let identity = File::open(tree.identity_dir()).unwrap();
    assert!(read_leaf(&identity, c"device.key", 64 * 1024, uid(), true)
        .unwrap()
        .is_some());
    assert_eq!(
        read_leaf(&identity, c"device.key", 64 * 1024, other, true).err(),
        Some("import_source_not_owned")
    );
    assert_eq!(
        read_leaf(&identity, c"absent", 64, uid(), true).map(|r| r.is_none()),
        Ok(true)
    );
    assert_eq!(
        SourceTree::open_for(tree.aegis(), other).err(),
        Some("import_source_not_owned")
    );
}

#[test]
fn host_import_bridge_credential_must_lie_inside_the_source() {
    let sidecar = |credential: &Path| {
        toml::to_string(&BridgeSettings {
            authority: "localhost".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: credential.to_owned(),
        })
        .unwrap()
    };
    let secret = format!("{}\n", "ab".repeat(32));

    let tree = ReadyTree::new(relay());
    let inside = tree.identity_dir().join(BRIDGE_CREDENTIAL);
    tree.write_identity_file(SIDECAR, sidecar(&inside).as_bytes());
    tree.write_identity_file(BRIDGE_CREDENTIAL, secret.as_bytes());
    let source = open(&tree);
    assert_eq!(source.payload().manifest().entries().len(), 13);
    let target = TempContainer::new();
    let provider = InProcessProvider::new(target.path());
    let outcome = conclude_import(
        &source,
        query_import(
            &provider,
            source.payload(),
            &crate::identity_import::authorization::test_support::fresh_form(),
        ),
        true,
    );
    assert_eq!(outcome.exit, 0, "{outcome:?}");
    assert!(outcome.stdout.contains("committed_files=14"));
    assert!(std::fs::symlink_metadata(tree.aegis()).is_err());

    // A credential named anywhere else is never read or sent.
    let tree = ReadyTree::new(relay());
    let elsewhere = tree.root().join("credential");
    private_write(&elsewhere, secret.as_bytes());
    tree.write_identity_file(SIDECAR, sidecar(&elsewhere).as_bytes());
    tree.write_identity_file(BRIDGE_CREDENTIAL, secret.as_bytes());
    assert_eq!(refusal(tree.aegis()), "import_source_credential_outside");
    let tree = ReadyTree::new(relay());
    tree.write_identity_file(SIDECAR, b"not toml [");
    assert_eq!(refusal(tree.aegis()), "import_source_sidecar_invalid");
    // Half a bridge is refused by the provider's own manifest rule.
    let tree = ReadyTree::new(relay());
    tree.write_identity_file(
        SIDECAR,
        sidecar(&tree.identity_dir().join(BRIDGE_CREDENTIAL)).as_bytes(),
    );
    assert_eq!(refusal(tree.aegis()), "import_bridge_incomplete");
    let tree = ReadyTree::new(relay());
    tree.write_identity_file(BRIDGE_CREDENTIAL, secret.as_bytes());
    assert_eq!(refusal(tree.aegis()), "import_bridge_incomplete");
}

#[test]
fn host_import_web_response_pair_stays_inside_exact_identity_tree() {
    let sidecar = |credential: &Path| {
        format!(
            "authority='web.example'\ndescriptor_path='/descriptor'\nallowed_ingress_ips=['192.0.2.11']\ncredential_file='{}'\n",
            credential.display()
        )
    };
    let tree = ReadyTree::new(relay());
    let inside = tree.identity_dir().join(WEB_RESPONSE_CREDENTIAL);
    tree.write_identity_file(
        aegis_client::device_web_response::SIDECAR,
        sidecar(&inside).as_bytes(),
    );
    assert_eq!(refusal(tree.aegis()), "import_web_response_incomplete");
    tree.write_identity_file(WEB_RESPONSE_CREDENTIAL, &[b'a'; 64]);
    // This H2-only fixture has no signed web route, so the pair cannot be
    // promoted by merely supplying private bytes.
    let source = open(&tree);
    let target = TempContainer::new();
    assert_eq!(
        import_tree(target.path(), uid(), gate(), source.payload(), |_| {}).err(),
        Some("import_bundle_refused")
    );

    let tree = ReadyTree::new(relay());
    let outside = tree.root().join(WEB_RESPONSE_CREDENTIAL);
    tree.write_identity_file(
        aegis_client::device_web_response::SIDECAR,
        sidecar(&outside).as_bytes(),
    );
    tree.write_identity_file(WEB_RESPONSE_CREDENTIAL, &[b'a'; 64]);
    assert_eq!(refusal(tree.aegis()), "import_source_credential_outside");
}

#[test]
fn host_import_sfu_files_are_atomic_and_do_not_enable_an_h2_profile() {
    let tree = ReadyTree::new(relay());
    let identity = tree.identity_dir();
    let sidecar = crate::sfu_media_custody::relocated_sidecar(&identity);
    tree.write_identity_file(crate::sfu_media_custody::SIDECAR, sidecar.as_bytes());
    assert_eq!(refusal(tree.aegis()), "import_sfu_media_incomplete");
    tree.write_identity_file(crate::sfu_media_custody::BROKER_KEY, &[b'a'; 64]);
    tree.write_identity_file(crate::sfu_media_custody::BROKER_CA, b"not a CA");
    tree.write_identity_file(crate::sfu_media_custody::MEDIA_CA, b"not a CA");
    let source = open(&tree);
    let target = TempContainer::new();
    assert_eq!(
        import_tree(target.path(), uid(), gate(), source.payload(), |_| {}).err(),
        Some("import_bundle_refused")
    );

    let tree = ReadyTree::new(relay());
    let wrong = crate::sfu_media_custody::relocated_sidecar(&tree.root().join("other"));
    tree.write_identity_file(crate::sfu_media_custody::SIDECAR, wrong.as_bytes());
    assert_eq!(refusal(tree.aegis()), "import_source_sidecar_invalid");
}

/// The installed fixture's relay: `AEGIS_B06_FIXTURE_RELAY_IPV4`, an IPv4
/// address with an optional port (default 443).
fn fixture_relay(text: &str) -> SocketAddr {
    if let Ok(address) = text.parse::<std::net::SocketAddrV4>() {
        return address.into();
    }
    let ip: std::net::Ipv4Addr = text
        .parse()
        .expect("AEGIS_B06_FIXTURE_RELAY_IPV4 must be an IPv4 address");
    SocketAddr::from((ip, 443))
}

/// Write the installed fixture at `aegis` and prove, in process, that the
/// host admits it and the S14 provider import commits it into a fresh
/// container whose capture admits it with `relay` pinned.
fn write_and_admit(aegis: &Path, relay: SocketAddr) -> ReadyTree {
    let tree = ReadyTree::installed(aegis, relay);
    assert_eq!(tree.aegis(), aegis);
    assert_eq!(
        std::fs::symlink_metadata(aegis).unwrap().mode() & 0o7777,
        0o700
    );
    let source = SourceTree::open(aegis).unwrap();
    assert_eq!(source.payload().manifest().entries().len(), 11);
    let target = TempContainer::new();
    let provider = InProcessProvider::new(target.path());
    let outcome = conclude_import(
        &source,
        query_import(
            &provider,
            source.payload(),
            &crate::identity_import::authorization::test_support::fresh_form(),
        ),
        false,
    );
    assert_eq!(outcome.exit, 0, "{outcome:?}");
    let inputs = CapturedAppGroupInputs::capture_test_root(target.path()).unwrap();
    let identity = crate::local_identity::CapturedLocalIdentity::from_claim(inputs).unwrap();
    let prepared = identity.prepare_crypto().unwrap();
    assert_eq!(prepared.pinned_peer().unwrap(), relay);
    tree
}

#[test]
fn host_import_installed_fixture_writer_output_is_admitted_by_the_provider_import() {
    let parent = TempContainer::new();
    let aegis = parent.path().join("installed-Aegis");
    let relay = fixture_relay("192.0.2.10");
    assert_eq!(
        relay,
        "192.0.2.10:443".parse::<std::net::SocketAddr>().unwrap()
    );
    assert_eq!(fixture_relay("192.0.2.10:8443").port(), 8443);
    let tree = write_and_admit(&aegis, relay);
    let material = parent.path().join("installed-Aegis.relay");
    tree.write_relay_material(&material);
    let mut leaves: Vec<_> = std::fs::read_dir(&material)
        .unwrap()
        .map(|e| e.unwrap())
        .map(|e| {
            let meta = e.metadata().unwrap();
            assert_eq!(meta.mode() & 0o7777, 0o600);
            e.file_name().into_string().unwrap()
        })
        .collect();
    leaves.sort();
    assert_eq!(
        leaves,
        [
            "device-ca.pem",
            "inner-server.key",
            "inner-server.pem",
            "outer-server.key",
            "outer-server.pem"
        ]
    );
    // A kept tree survives its owner; an existing directory is refused.
    tree.keep();
    assert!(SourceTree::open(&aegis).is_ok());
    assert!(std::panic::catch_unwind(|| ReadyTree::installed(&aegis, relay)).is_err());
}

/// B-06 S15: write the import source for the later installed run. Not run
/// by default. `AEGIS_B06_FIXTURE_DIR` is the absolute, not yet existing
/// `Aegis` directory to create (0700; its parent canonical, the caller's and
/// not group/other writable), `AEGIS_B06_FIXTURE_RELAY_IPV4` the relay
/// the signed bundle pins. The relay's server identities and the device CA
/// go to `<dir>.relay` (0700, files 0600), never into the import source.
/// The device certificate is valid for 24 hours from writing.
#[test]
#[ignore = "writes the installed-run fixture; set AEGIS_B06_FIXTURE_DIR and AEGIS_B06_FIXTURE_RELAY_IPV4"]
fn write_installed_fixture() {
    let aegis = PathBuf::from(
        std::env::var_os("AEGIS_B06_FIXTURE_DIR").expect("AEGIS_B06_FIXTURE_DIR is required"),
    );
    let relay = fixture_relay(
        &std::env::var("AEGIS_B06_FIXTURE_RELAY_IPV4")
            .expect("AEGIS_B06_FIXTURE_RELAY_IPV4 is required"),
    );
    let mut material = aegis.clone().into_os_string();
    material.push(".relay");
    let material = PathBuf::from(material);
    assert!(
        std::fs::symlink_metadata(&material).is_err(),
        "relay material dir must not exist"
    );
    let tree = write_and_admit(&aegis, relay);
    tree.write_relay_material(&material);
    tree.keep();
    println!("installed_fixture_dir={}", aegis.display());
    println!("relay_material_dir={}", material.display());
    println!("relay={relay}");
}

#[test]
fn every_import_attempt_appends_to_a_private_journal_and_a_link_is_refused() {
    let home = tempfile_dir("journal");
    let journal = home.join(IMPORT_JOURNAL);
    assert!(!journal.exists());
    record_import_attempt(&home).unwrap();
    let first = std::fs::read(&journal).unwrap();
    assert!(first.starts_with(b"import_attempt unix_ns="));
    assert_eq!(first.iter().filter(|b| **b == b'\n').count(), 1);
    assert_eq!(
        std::fs::metadata(&journal).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(journal.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    // Each attempt changes the journal, so a marker bound to its digest no
    // longer matches.
    record_import_attempt(&home).unwrap();
    let second = std::fs::read(&journal).unwrap();
    assert!(second.starts_with(&first) && second.len() > first.len());
    // A journal opened by others, a link or a second link is refused.
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(record_import_attempt(&home).is_err());
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
    let linked = home.join("linked");
    std::fs::hard_link(&journal, &linked).unwrap();
    assert!(record_import_attempt(&home).is_err());
    std::fs::remove_file(&linked).unwrap();
    let target = home.join("elsewhere");
    std::fs::rename(&journal, &target).unwrap();
    std::os::unix::fs::symlink(&target, &journal).unwrap();
    assert!(record_import_attempt(&home).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), second);
    std::fs::remove_dir_all(&home).unwrap();
}

fn tempfile_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aegis-s21-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    dir.canonicalize().unwrap()
}
