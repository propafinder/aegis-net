use super::*;
use crate::{
    app_group::CapturedAppGroupInputs, local_identity::CapturedLocalIdentity,
    test_fixture::ReadyTree,
};
use std::{
    collections::BTreeMap,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::mpsc,
    time::Duration,
};

/// A fresh private App Group container under the canonical per-user temp
/// directory, removed on drop.
pub(crate) struct TempContainer(PathBuf);
impl TempContainer {
    pub(crate) fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "aegis-import-target-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempContainer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

pub(crate) fn gate() -> &'static TreeGate {
    Box::leak(Box::new(TreeGate::new()))
}

pub(crate) fn relay() -> std::net::SocketAddr {
    "127.0.0.1:443".parse().unwrap()
}

/// The host's own reader (S15) over the fixture's `Aegis` directory.
pub(crate) fn payload_of(tree: &ReadyTree) -> ImportPayload {
    crate::host_import::SourceTree::open(tree.aegis())
        .unwrap()
        .into_payload()
}

/// Every entry below `root`: kind, mode and file bytes, without following
/// links. Equal snapshots mean the tree is untouched.
pub(crate) fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, (u32, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            let rel = path.strip_prefix(base).unwrap().to_owned();
            if meta.is_dir() {
                out.insert(rel, (meta.mode(), Vec::new()));
                walk(base, &path, out);
            } else if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                out.insert(
                    rel,
                    (meta.mode(), target.into_os_string().into_encoded_bytes()),
                );
            } else {
                out.insert(rel, (meta.mode(), std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn names(root: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn admitted_online(container: &Path) -> aegis_client::online_expectation::OnlineExpectation {
    let inputs = CapturedAppGroupInputs::capture_test_root(container).unwrap();
    let mut identity = CapturedLocalIdentity::from_claim(inputs).unwrap();
    identity.revalidate().unwrap()
}

fn same_online(
    a: &aegis_client::online_expectation::OnlineExpectation,
    b: &aegis_client::online_expectation::OnlineExpectation,
) -> bool {
    a.certificate_sha256 == b.certificate_sha256
        && a.not_after_unix_secs == b.not_after_unix_secs
        && a.issued_generation == b.issued_generation
        && a.snapshot_sha256 == b.snapshot_sha256
}

#[test]
fn identity_import_good_payload_commits_a_tree_capture_and_expectation_admit() {
    let source = ReadyTree::with_online_completed(relay());
    let payload = payload_of(&source);
    let target = TempContainer::new();
    let gate = gate();
    let report = import_tree(target.path(), uid(), gate, &payload, |_| {}).unwrap();
    assert!(report.retired_removed);
    verify_import_report(&payload.manifest(), &report).unwrap();
    // The manifest is the digest of every committed file, read back.
    let aegis = target.path().join("Aegis");
    assert_eq!(report.files.len(), payload.manifest().entries().len() + 1);
    for file in &report.files {
        let bytes = std::fs::read(aegis.join(&file.path)).unwrap();
        assert_eq!(file.length, bytes.len() as u64, "{}", file.path);
        assert_eq!(file.sha256, sha256_hex(&bytes), "{}", file.path);
        let meta = std::fs::symlink_metadata(aegis.join(&file.path)).unwrap();
        assert_eq!(meta.mode(), libc::S_IFREG as u32 | 0o600, "{}", file.path);
        assert_eq!((meta.uid(), meta.nlink()), (uid(), 1));
    }
    for (path, sent) in payload.files() {
        let committed = std::fs::read(aegis.join(path.name())).unwrap();
        assert_eq!(committed, sent, "{}", path.name());
    }
    for dir in ["", "bundle", "identity"] {
        let meta = std::fs::symlink_metadata(aegis.join(dir)).unwrap();
        assert_eq!(meta.mode(), libc::S_IFDIR as u32 | 0o700, "{dir}");
    }
    assert!(backup_excluded(
        &File::open(aegis.join("identity")).unwrap()
    ));
    // No staging or retired directory remains beside the tree.
    assert_eq!(names(target.path()), ["Aegis"]);
    // The committed tree is what capture and the Store admit.
    assert!(same_online(
        &admitted_online(target.path()),
        source.online()
    ));
    let store =
        ProtectedOnlineExpectation::open_existing(&aegis.join("identity"), source.profile_sha256())
            .unwrap();
    assert!(same_online(
        &store.expectation_at(registry::unix_now().unwrap()).unwrap(),
        source.online()
    ));
    drop(store);

    // A second import swaps the whole tree: the old key is gone.
    let old_key = std::fs::read(aegis.join("identity/device.key")).unwrap();
    let next = ReadyTree::new(relay());
    let report = import_tree(target.path(), uid(), gate, &payload_of(&next), |_| {}).unwrap();
    assert!(report.retired_removed);
    assert_eq!(names(target.path()), ["Aegis"]);
    assert_ne!(
        std::fs::read(aegis.join("identity/device.key")).unwrap(),
        old_key
    );
    assert_eq!(
        std::fs::read(aegis.join("identity/online-completed.json")).unwrap(),
        std::fs::read(next.identity_dir().join("online-completed.json")).unwrap()
    );
    assert!(same_online(&admitted_online(target.path()), next.online()));
    assert_eq!(gate.holders(), 0);
}

#[test]
fn identity_import_refusals_leave_the_target_untouched() {
    let target = TempContainer::new();
    let gate = gate();
    let installed = ReadyTree::new(relay());
    import_tree(target.path(), uid(), gate, &payload_of(&installed), |_| {}).unwrap();
    let before = snapshot(target.path());
    let source = ReadyTree::with_online_completed(relay());
    let good = payload_of(&source);
    let check = |result: Result<ImportReport, &'static str>, code: &str| {
        assert_eq!(result.err(), Some(code));
        assert_eq!(snapshot(target.path()), before, "{code}");
        assert!(same_online(
            &admitted_online(target.path()),
            installed.online()
        ));
    };

    // A symlink planted in staging, a replaced file and an extra entry.
    check(
        import_tree(target.path(), uid(), gate, &good, |staging| {
            let key = staging.join("identity/device.key");
            std::fs::rename(&key, staging.join("moved")).unwrap();
            std::os::unix::fs::symlink(staging.join("moved"), &key).unwrap();
        }),
        "import_staging_tampered",
    );
    check(
        import_tree(target.path(), uid(), gate, &good, |staging| {
            std::os::unix::fs::symlink("/etc/hosts", staging.join("bundle/extra")).unwrap();
        }),
        "import_staging_tampered",
    );
    check(
        import_tree(target.path(), uid(), gate, &good, |staging| {
            let pem = staging.join("identity/device.pem");
            let bytes = std::fs::read(&pem).unwrap();
            std::fs::remove_file(&pem).unwrap();
            std::fs::write(&pem, bytes).unwrap();
            std::fs::set_permissions(&pem, std::fs::Permissions::from_mode(0o600)).unwrap();
        }),
        "import_staging_tampered",
    );

    // The backup exclusion removed from the staged identity directory.
    check(
        import_tree(target.path(), uid(), gate, &good, |staging| {
            let path = CString::new(
                staging
                    .join("identity")
                    .into_os_string()
                    .into_encoded_bytes(),
            )
            .unwrap();
            assert_eq!(
                unsafe { libc::removexattr(path.as_ptr(), BACKUP_EXCLUDE_XATTR.as_ptr(), 0) },
                0
            );
        }),
        "import_staging_tampered",
    );

    // Payloads the production validators refuse.
    let mut files: Vec<(&str, Zeroizing<Vec<u8>>)> = good
        .files()
        .map(|(m, bytes)| (m.name(), Zeroizing::new(bytes.to_vec())))
        .collect();
    fn replace(files: &mut [(&str, Zeroizing<Vec<u8>>)], name: &str, bytes: &[u8]) {
        files.iter_mut().find(|(n, _)| *n == name).unwrap().1 = Zeroizing::new(bytes.to_vec());
    }
    let mut pin = files.clone();
    replace(
        &mut pin,
        "identity/bundle-profile.sha256",
        "e".repeat(64).as_bytes(),
    );
    check(
        import_tree(
            target.path(),
            uid(),
            gate,
            &ImportPayload::from_members(pin).unwrap(),
            |_| {},
        ),
        "import_identity_refused",
    );
    let other = ReadyTree::new(relay());
    let mut foreign_key = files.clone();
    let other_key = std::fs::read(other.identity_dir().join("device.key")).unwrap();
    replace(&mut foreign_key, "identity/device.key", &other_key);
    check(
        import_tree(
            target.path(),
            uid(),
            gate,
            &ImportPayload::from_members(foreign_key).unwrap(),
            |_| {},
        ),
        "import_identity_refused",
    );
    let mut bundle = files.clone();
    replace(&mut bundle, "bundle/bundle.json", b"{\"schema\":\"other\"}");
    check(
        import_tree(
            target.path(),
            uid(),
            gate,
            &ImportPayload::from_members(bundle).unwrap(),
            |_| {},
        ),
        "import_bundle_refused",
    );
    let mut private = files.clone();
    replace(
        &mut private,
        "bundle/outer-ca.pem",
        b"-----BEGIN PRIVATE KEY-----\n",
    );
    check(
        import_tree(
            target.path(),
            uid(),
            gate,
            &ImportPayload::from_members(private).unwrap(),
            |_| {},
        ),
        "import_bundle_refused",
    );
    // A missing required file is refused before any staging.
    files.retain(|(name, _)| *name != "identity/device.pem");
    assert_eq!(
        ImportPayload::from_members(files).err(),
        Some("import_file_missing")
    );
    assert_eq!(snapshot(target.path()), before);
}

#[test]
fn identity_import_and_forget_are_refused_while_a_capture_is_live() {
    let target = TempContainer::new();
    let gate = gate();
    let source = ReadyTree::new(relay());
    let payload = payload_of(&source);
    import_tree(target.path(), uid(), gate, &payload, |_| {}).unwrap();
    let before = snapshot(target.path());
    let live = CapturedAppGroupInputs::capture_test_root_leased(target.path(), gate).unwrap();
    assert_eq!(gate.holders(), 1);
    assert_eq!(
        import_tree(target.path(), uid(), gate, &payload, |_| {}).err(),
        Some("session_live")
    );
    assert_eq!(
        forget_identity(target.path(), uid(), gate).err(),
        Some("session_live")
    );
    assert_eq!(snapshot(target.path()), before);
    live.revalidate().unwrap();
    drop(live);
    assert_eq!(gate.holders(), 0);

    // Forget moves the identity away in one rename and removes the key.
    let report = forget_identity(target.path(), uid(), gate).unwrap();
    assert_eq!(
        report,
        ForgetReport {
            identity_was_present: true,
            key_material_removed: true
        }
    );
    assert_eq!(names(target.path()), ["Aegis"]);
    assert_eq!(names(&target.path().join("Aegis")), ["bundle"]);
    assert!(CapturedAppGroupInputs::capture_test_root(target.path()).is_err());
    let again = forget_identity(target.path(), uid(), gate).unwrap();
    assert!(!again.identity_was_present && again.key_material_removed);
    // With nothing imported at all, forget reports an absent identity.
    let empty = TempContainer::new();
    let report = forget_identity(empty.path(), uid(), gate).unwrap();
    assert!(!report.identity_was_present && report.key_material_removed);
    // Importing again over the bundle-only tree restores an admitted tree.
    import_tree(target.path(), uid(), gate, &payload, |_| {}).unwrap();
    assert!(same_online(
        &admitted_online(target.path()),
        source.online()
    ));
}

#[test]
fn identity_import_holds_the_gate_so_a_concurrent_capture_waits_for_the_commit() {
    let target = TempContainer::new();
    let gate = gate();
    let first = ReadyTree::new(relay());
    import_tree(target.path(), uid(), gate, &payload_of(&first), |_| {}).unwrap();
    let second = ReadyTree::with_online_completed(relay());
    let payload = payload_of(&second);
    let (tx, rx) = mpsc::channel();
    let container = target.path().to_owned();
    let mut racer = None;
    let report = import_tree(target.path(), uid(), gate, &payload, |_| {
        // A provider start arrives mid-import: it leases before capture.
        racer = Some(std::thread::spawn(move || {
            let lease = gate.lease();
            tx.send(()).unwrap();
            let inputs = CapturedAppGroupInputs::capture_test_root(&container).unwrap();
            let mut identity = CapturedLocalIdentity::from_claim(inputs).unwrap();
            let online = identity.revalidate().unwrap();
            drop(identity);
            drop(lease);
            online
        }));
        // It cannot lease while the import holds the gate.
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    })
    .unwrap();
    assert!(report.retired_removed);
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // The waiting capture saw only the committed second tree.
    let online = racer.unwrap().join().unwrap();
    assert!(same_online(&online, second.online()));
    assert_eq!(gate.holders(), 0);
}

#[test]
fn identity_import_first_import_creates_aegis_and_sweeps_leftovers() {
    let target = TempContainer::new();
    let gate = gate();
    // Leftovers of an interrupted import and forget, with key-like content.
    for leftover in [".aegis-import-1-2-3", ".aegis-retired-4-5-6"] {
        let dir = target.path().join(leftover).join("identity");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("device.key"), b"old").unwrap();
    }
    std::fs::write(target.path().join("unrelated"), b"kept").unwrap();
    let source = ReadyTree::new(relay());
    import_tree(target.path(), uid(), gate, &payload_of(&source), |_| {}).unwrap();
    assert_eq!(names(target.path()), ["Aegis", "unrelated"]);
    assert!(same_online(
        &admitted_online(target.path()),
        source.online()
    ));
}

#[test]
fn identity_import_refuses_an_unsafe_existing_tree_or_container() {
    let gate = gate();
    let source = ReadyTree::new(relay());
    let payload = payload_of(&source);
    // A symlinked Aegis is never swapped or followed.
    let target = TempContainer::new();
    let elsewhere = TempContainer::new();
    std::os::unix::fs::symlink(elsewhere.path(), target.path().join("Aegis")).unwrap();
    let before = (snapshot(target.path()), snapshot(elsewhere.path()));
    assert_eq!(
        import_tree(target.path(), uid(), gate, &payload, |_| {}).err(),
        Some("aegis_tree_unsafe")
    );
    assert_eq!(
        forget_identity(target.path(), uid(), gate).err(),
        Some("aegis_tree_unsafe")
    );
    assert_eq!(
        (snapshot(target.path()), snapshot(elsewhere.path())),
        before
    );
    // A group-readable Aegis directory is not a private tree.
    let loose = TempContainer::new();
    std::fs::create_dir(loose.path().join("Aegis")).unwrap();
    std::fs::set_permissions(
        loose.path().join("Aegis"),
        std::fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    assert_eq!(
        import_tree(loose.path(), uid(), gate, &payload, |_| {}).err(),
        Some("aegis_tree_unsafe")
    );
    // A container other users can write is refused by the S13 anchor.
    let open = TempContainer::new();
    std::fs::set_permissions(open.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(import_tree(open.path(), uid(), gate, &payload, |_| {}).is_err());
    assert_eq!(names(open.path()), Vec::<String>::new());
    // A non-canonical container spelling is refused.
    let alias = TempContainer::new();
    let link = alias.path().join("alias");
    std::os::unix::fs::symlink(open.path(), &link).unwrap();
    assert!(import_tree(&link, uid(), gate, &payload, |_| {}).is_err());
}

fn bridge_members(source: &ReadyTree, secret: &[u8]) -> Vec<(&'static str, Zeroizing<Vec<u8>>)> {
    let mut files: Vec<(&'static str, Zeroizing<Vec<u8>>)> = payload_of(source)
        .files()
        .map(|(m, bytes)| (m.name(), Zeroizing::new(bytes.to_vec())))
        .collect();
    let settings = BridgeSettings {
        authority: "localhost".into(),
        path: "/private/stream".into(),
        enrollment_path: "/private/enroll".into(),
        // The host's own spelling; the provider names its own container.
        credential_file: "/Users/someone/elsewhere/credential".into(),
    };
    files.push((
        "identity/https-bridge.toml",
        Zeroizing::new(toml::to_string(&settings).unwrap().into_bytes()),
    ));
    files.push((
        "identity/bridge-credential",
        Zeroizing::new(secret.to_vec()),
    ));
    files
}

#[test]
fn identity_import_commits_a_bridge_credential_under_the_provider_path() {
    let source = ReadyTree::new(relay());
    let target = TempContainer::new();
    let gate = gate();
    let secret = format!("{}\n", "ab".repeat(32));
    let payload = ImportPayload::from_members(bridge_members(&source, secret.as_bytes())).unwrap();
    let report = import_tree(target.path(), uid(), gate, &payload, |_| {}).unwrap();
    verify_import_report(&payload.manifest(), &report).unwrap();
    let identity = target.path().join("Aegis/identity");
    let committed: BridgeSettings =
        toml::from_str(&std::fs::read_to_string(identity.join(SIDECAR)).unwrap()).unwrap();
    assert_eq!(committed.credential_file, identity.join(BRIDGE_CREDENTIAL));
    let inputs = CapturedAppGroupInputs::capture_test_root(target.path()).unwrap();
    let snapshot = inputs.captured_bridge_snapshot().unwrap().unwrap();
    assert_eq!(snapshot.settings, committed);
    assert_eq!(&snapshot.secret[..], "ab".repeat(32).as_bytes());
    drop(inputs);

    // A weak or malformed credential, or half a bridge, is refused.
    let before = snapshot_of(target.path());
    for secret in ["0".repeat(64), "AB".repeat(32), "ab".repeat(31)] {
        let payload =
            ImportPayload::from_members(bridge_members(&source, secret.as_bytes())).unwrap();
        assert_eq!(
            import_tree(target.path(), uid(), gate, &payload, |_| {}).err(),
            Some("import_bridge_refused")
        );
        assert_eq!(snapshot_of(target.path()), before);
    }
    let mut half = bridge_members(&source, secret.as_bytes());
    half.pop();
    assert_eq!(
        ImportPayload::from_members(half).err(),
        Some("import_bridge_incomplete")
    );
}

fn snapshot_of(path: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
    snapshot(path)
}

#[test]
fn identity_import_manifest_is_versioned_canonical_and_bounded() {
    let source = ReadyTree::with_online_completed(relay());
    let payload = payload_of(&source);
    let manifest = payload.manifest();
    let bytes = encode_manifest(&manifest);
    assert!(bytes.len() <= MAX_MANIFEST_BYTES);
    assert_eq!(decode_manifest(&bytes), Ok(manifest.clone()));
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let mutate = |edit: &dyn Fn(&mut Value)| {
        let mut changed = value.clone();
        edit(&mut changed);
        serde_json::to_vec(&changed).unwrap()
    };
    let swap = |v: &mut Value| v["files"].as_array_mut().unwrap().swap(0, 1);
    let duplicate = |v: &mut Value| {
        let first = v["files"][0].clone();
        v["files"].as_array_mut().unwrap().insert(0, first);
    };
    let drop_pem = |v: &mut Value| {
        v["files"]
            .as_array_mut()
            .unwrap()
            .retain(|f| f["name"] != "identity/device.pem");
    };
    for (bytes, code) in [
        (
            mutate(&|v| v["version"] = json!(2)),
            "import_version_unknown",
        ),
        (
            mutate(&|v| v["version"] = json!("1")),
            "import_version_unknown",
        ),
        (
            mutate(&|v| v["version"] = json!(0)),
            "import_version_unknown",
        ),
        (
            mutate(&|v| {
                v.as_object_mut().unwrap().remove("version");
            }),
            "import_manifest_malformed",
        ),
        (
            mutate(&|v| v["extra"] = json!(1)),
            "import_manifest_malformed",
        ),
        (
            mutate(&|v| v["files"][0]["extra"] = json!(1)),
            "import_manifest_malformed",
        ),
        (
            mutate(&|v| v["files"][0]["name"] = json!("identity/runtime.json")),
            "import_file_unknown",
        ),
        (
            mutate(&|v| v["files"][0]["name"] = json!("../device.key")),
            "import_file_unknown",
        ),
        (mutate(&swap), "import_manifest_order"),
        (mutate(&duplicate), "import_manifest_order"),
        (mutate(&drop_pem), "import_file_missing"),
        (
            mutate(&|v| v["files"][0]["length"] = json!(64 * 1024 + 1)),
            "import_file_oversized",
        ),
        (
            mutate(&|v| v["files"][0]["length"] = json!(0)),
            "import_file_empty",
        ),
        (
            mutate(&|v| v["files"][0]["length"] = json!(-1)),
            "import_manifest_malformed",
        ),
        (
            mutate(&|v| v["files"][0]["sha256"] = json!("A".repeat(64))),
            "import_manifest_malformed",
        ),
        (
            mutate(&|v| v["files"][0]["sha256"] = json!("a".repeat(63))),
            "import_manifest_malformed",
        ),
        (b"[]".to_vec(), "import_manifest_malformed"),
        (b"not json".to_vec(), "import_manifest_malformed"),
        (
            vec![b' '; MAX_MANIFEST_BYTES + 1],
            "import_manifest_oversized",
        ),
    ] {
        assert_eq!(
            decode_manifest(&bytes).err(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }
    // One spelling only: whitespace or a duplicate key is refused.
    let mut spaced = bytes.clone();
    spaced.insert(1, b' ');
    assert_eq!(
        decode_manifest(&spaced).err(),
        Some("import_manifest_noncanonical")
    );
    let text = String::from_utf8(bytes.clone()).unwrap();
    let doubled = text.replacen('{', "{\"version\":2,", 1);
    assert_ne!(doubled, text);
    assert_eq!(
        decode_manifest(doubled.as_bytes()).err(),
        Some("import_manifest_noncanonical")
    );
    // Every cap together still fits the total bound (also a const assert).
    assert!(IMPORT_MEMBERS.iter().map(|m| m.cap).sum::<usize>() <= MAX_IMPORT_BYTES);

    // Received bytes are bound to the manifest: length, then digest.
    let files = || -> Vec<Zeroizing<Vec<u8>>> {
        payload
            .files()
            .map(|(_, b)| Zeroizing::new(b.to_vec()))
            .collect()
    };
    assert!(ImportPayload::verify(&manifest, files()).is_ok());
    let mut short = files();
    short[0].pop();
    assert_eq!(
        ImportPayload::verify(&manifest, short).err(),
        Some("import_file_truncated")
    );
    let mut long = files();
    long[0].push(b' ');
    assert_eq!(
        ImportPayload::verify(&manifest, long).err(),
        Some("import_file_length_mismatch")
    );
    let mut flipped = files();
    flipped[0][0] ^= 1;
    assert_eq!(
        ImportPayload::verify(&manifest, flipped).err(),
        Some("import_digest_mismatch")
    );
    let mut fewer = files();
    fewer.pop();
    assert_eq!(
        ImportPayload::verify(&manifest, fewer).err(),
        Some("import_file_missing")
    );
}

#[test]
fn identity_import_table_matches_capture_and_store_names() {
    assert_eq!(
        IMPORT_MEMBERS[..BUNDLE_MEMBERS]
            .iter()
            .map(|m| m.leaf)
            .collect::<Vec<_>>(),
        aegis_client::public_profile_file::MEMBERS
    );
    assert_eq!(IMPORT_MEMBERS[SIDECAR_MEMBER].leaf, SIDECAR);
    assert_eq!(
        IMPORT_MEMBERS[SIDECAR_MEMBER].name(),
        format!("identity/{SIDECAR}")
    );
    assert_eq!(IMPORT_MEMBERS[CREDENTIAL_MEMBER].leaf, BRIDGE_CREDENTIAL);
    for m in &IMPORT_MEMBERS {
        let dir = m.dir.name().to_str().unwrap();
        assert_eq!(m.name(), format!("{dir}/{}", m.leaf));
        assert!(m.cap > 0);
    }
    assert!(!IMPORT_MEMBERS.iter().any(|m| m.leaf == "runtime.json"));
    // The S22 custody members, and never an online transaction journal.
    for (index, leaf) in [
        (RECORD_MEMBER, "identity.json"),
        (KEY_MEMBER, "device.key"),
        (CSR_MEMBER, "device.csr"),
        (CERTIFICATE_MEMBER, "device.pem"),
        (DEVICE_CA_MEMBER, "device-ca.pem"),
        (COMPLETION_MEMBER, "online-completed.json"),
    ] {
        assert_eq!(IMPORT_MEMBERS[index].leaf, leaf);
        assert_eq!(IMPORT_MEMBERS[index].dir, Dir::Identity);
        assert_eq!(IMPORT_MEMBERS[index].kind, Kind::Required);
    }
    for leaf in crate::identity_custody::JOURNAL {
        assert!(!IMPORT_MEMBERS.iter().any(|m| m.leaf == leaf), "{leaf}");
        assert_eq!(committed_path_allowed(&format!("identity/{leaf}")), None);
    }
    assert_eq!(committed_path_allowed(LOCK_PATH), Some(0));
    assert_eq!(committed_path_allowed("identity/runtime.json"), None);
}

#[test]
fn identity_import_backup_exclusion_is_the_sticky_time_machine_plist() {
    type CfRef = *const c_void;
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFDataCreate(allocator: CfRef, bytes: *const u8, length: isize) -> CfRef;
        fn CFPropertyListCreateWithData(
            allocator: CfRef,
            data: CfRef,
            options: usize,
            format: *mut isize,
            error: *mut CfRef,
        ) -> CfRef;
        fn CFGetTypeID(value: CfRef) -> usize;
        fn CFStringGetTypeID() -> usize;
    }
    let data = unsafe {
        CFDataCreate(
            std::ptr::null(),
            BACKUP_EXCLUDE_VALUE.as_ptr(),
            BACKUP_EXCLUDE_VALUE.len() as isize,
        )
    };
    assert!(!data.is_null());
    let mut format = 0isize;
    let plist = unsafe {
        CFPropertyListCreateWithData(std::ptr::null(), data, 0, &mut format, std::ptr::null_mut())
    };
    assert!(!plist.is_null());
    // kCFPropertyListBinaryFormat_v1_0
    assert_eq!(format, 200);
    assert_eq!(unsafe { CFGetTypeID(plist) }, unsafe {
        CFStringGetTypeID()
    });
    let mut buffer = [0 as c_char; 64];
    assert_ne!(
        unsafe { CFStringGetCString(plist, buffer.as_mut_ptr(), 64, 0x0800_0100) },
        0
    );
    assert_eq!(
        unsafe { CStr::from_ptr(buffer.as_ptr()) },
        c"com.apple.backupd"
    );
    unsafe {
        CFRelease(plist);
        CFRelease(data);
    }
    let target = TempContainer::new();
    let dir = File::open(target.path()).unwrap();
    assert!(!backup_excluded(&dir));
    exclude_from_backup(&dir).unwrap();
    assert!(backup_excluded(&dir));
}

pub(crate) struct FakePrincipals {
    pub(crate) console: Result<u32, &'static str>,
    pub(crate) admins: Result<Vec<u32>, &'static str>,
}
impl Principals for FakePrincipals {
    fn console_uid(&self) -> Result<u32, &'static str> {
        self.console
    }
    fn is_admin(&self, uid: u32) -> Result<bool, &'static str> {
        self.admins.clone().map(|admins| admins.contains(&uid))
    }
    fn is_setup_user(&self, uid: u32) -> Result<bool, &'static str> {
        Ok(uid == FAKE_SETUP_UID)
    }
}
/// The one uid `FakePrincipals` reports in `_mbsetupuser`.
pub(crate) const FAKE_SETUP_UID: u32 = 248;

#[test]
fn identity_import_peer_must_be_the_console_user_and_an_admin() {
    let principals = |console, admins| FakePrincipals { console, admins };
    let admin = principals(Ok(501), Ok(vec![501]));
    assert_eq!(authorize_identity_peer(501, &admin), Ok(()));
    assert_eq!(
        authorize_identity_peer(502, &admin),
        Err("peer_not_console_user")
    );
    assert_eq!(
        authorize_identity_peer(0, &admin),
        Err("peer_not_console_user")
    );
    assert_eq!(
        authorize_identity_peer(501, &principals(Ok(501), Ok(vec![0, 502]))),
        Err("peer_not_admin")
    );
    // Root at the console (the login window) never authorizes, admin or not.
    assert_eq!(
        authorize_identity_peer(0, &principals(Ok(0), Ok(vec![0]))),
        Err("peer_not_console_user")
    );
    assert_eq!(
        authorize_identity_peer(501, &principals(Err("console_user_absent"), Ok(vec![501]))),
        Err("console_user_absent")
    );
    assert_eq!(
        authorize_identity_peer(501, &principals(Ok(501), Err("admin_membership_unknown"))),
        Err("admin_membership_unknown")
    );
    // v30: an admin console user in Setup Assistant's group never
    // authorizes (that session satisfies a branch of the proof right).
    assert_eq!(
        authorize_identity_peer(
            FAKE_SETUP_UID,
            &principals(Ok(FAKE_SETUP_UID), Ok(vec![FAKE_SETUP_UID]))
        ),
        Err("peer_in_setup_group")
    );
    // The native membership check: root is in admin, an unknown uid is not.
    assert_eq!(NativePrincipals.is_admin(0), Ok(true));
    assert_eq!(NativePrincipals.is_admin(3_999_999), Ok(false));
    // ...and the test's own user is no Setup Assistant user.
    assert_eq!(
        NativePrincipals.is_setup_user(unsafe { libc::geteuid() }),
        Ok(false)
    );
    // SETUP_GID is this Mac's `_mbsetupuser` (when the group exists).
    let group = unsafe { libc::getgrnam(c"_mbsetupuser".as_ptr()) };
    if !group.is_null() {
        assert_eq!(
            unsafe { (*group).gr_gid },
            crate::identity_import::SETUP_GID
        );
    }
    let admin_group = unsafe { libc::getgrnam(c"admin".as_ptr()) };
    if !admin_group.is_null() {
        assert_eq!(
            unsafe { (*admin_group).gr_gid },
            crate::identity_import::ADMIN_GID
        );
    }
    // The native console lookup names a real user or refuses; never root.
    match NativePrincipals.console_uid() {
        Ok(console) => assert_ne!(console, 0),
        Err(code) => assert!(["console_user_unknown", "console_user_absent"].contains(&code)),
    }
}

#[test]
fn identity_import_refuses_a_container_or_tree_that_changed_before_the_commit() {
    let gate = gate();
    let source = ReadyTree::new(relay());
    let payload = payload_of(&source);
    // The container path re-anchored to another directory mid-import.
    let parent = TempContainer::new();
    let container = parent.path().join("container");
    std::fs::create_dir(&container).unwrap();
    std::fs::set_permissions(&container, std::fs::Permissions::from_mode(0o700)).unwrap();
    let moved = parent.path().join("moved");
    assert_eq!(
        import_tree(&container, uid(), gate, &payload, |_| {
            std::fs::rename(&container, &moved).unwrap();
            std::fs::create_dir(&container).unwrap();
            std::fs::set_permissions(&container, std::fs::Permissions::from_mode(0o700)).unwrap();
        })
        .err(),
        Some("import_container_changed")
    );
    assert!(!container.join("Aegis").exists() && !moved.join("Aegis").exists());
    // The staging directory is removed through the held descriptor, in the
    // directory it was actually created in.
    assert_eq!(names(&moved), Vec::<String>::new());
    // An Aegis tree that appeared after the first look is never replaced.
    let target = TempContainer::new();
    let aegis = target.path().join("Aegis");
    assert_eq!(
        import_tree(target.path(), uid(), gate, &payload, |_| {
            std::fs::create_dir(&aegis).unwrap();
            std::fs::set_permissions(&aegis, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(aegis.join("marker"), b"kept").unwrap();
        })
        .err(),
        Some("import_tree_changed")
    );
    assert_eq!(names(&aegis), ["marker"]);
    assert_eq!(names(target.path()), ["Aegis"]);
}

#[test]
fn identity_import_staged_identity_is_excluded_before_any_write() {
    let target = TempContainer::new();
    let container = HeldContainer::open(target.path(), uid()).unwrap();
    let staging = Staging::create(&container, uid()).unwrap();
    // The exclusion is already set while the staged identity is still empty.
    assert_eq!(list(&staging.identity).unwrap(), Vec::<CString>::new());
    assert!(backup_excluded(&staging.identity));
    drop(staging);
    assert_eq!(names(target.path()), Vec::<String>::new());
}

#[test]
fn identity_import_sweep_unlinks_non_directory_leftovers_without_following() {
    let target = TempContainer::new();
    let elsewhere = TempContainer::new();
    std::fs::create_dir(elsewhere.path().join("identity")).unwrap();
    std::fs::write(elsewhere.path().join("identity/device.key"), b"kept").unwrap();
    use std::os::unix::fs::symlink as link;
    link(
        elsewhere.path().join("identity"),
        target.path().join(".aegis-retired-1-2-3"),
    )
    .unwrap();
    link(elsewhere.path(), target.path().join(".aegis-import-4-5-6")).unwrap();
    std::fs::write(target.path().join(".aegis-retired-7-8-9"), b"old").unwrap();
    link(elsewhere.path(), target.path().join("unrelated-link")).unwrap();
    let before = snapshot(elsewhere.path());
    let gate = gate();
    assert_eq!(
        forget_identity(target.path(), uid(), gate).unwrap(),
        ForgetReport {
            identity_was_present: false,
            key_material_removed: true
        }
    );
    // Only the prefixed entries went; no link was followed.
    assert_eq!(names(target.path()), ["unrelated-link"]);
    assert_eq!(snapshot(elsewhere.path()), before);
    let source = ReadyTree::new(relay());
    import_tree(target.path(), uid(), gate, &payload_of(&source), |_| {}).unwrap();
    assert_eq!(names(target.path()), ["Aegis", "unrelated-link"]);
    assert_eq!(snapshot(elsewhere.path()), before);
}

#[test]
fn identity_forget_refuses_an_identity_that_is_not_a_private_directory() {
    let gate = gate();
    let source = ReadyTree::new(relay());
    let payload = payload_of(&source);
    let target = TempContainer::new();
    let elsewhere = TempContainer::new();
    std::fs::create_dir(elsewhere.path().join("identity")).unwrap();
    std::fs::write(elsewhere.path().join("identity/device.key"), b"kept").unwrap();
    let identity = target.path().join("Aegis/identity");
    let replacements: [&dyn Fn(); 3] = [
        &|| std::os::unix::fs::symlink(elsewhere.path().join("identity"), &identity).unwrap(),
        &|| std::fs::write(&identity, b"not a directory").unwrap(),
        &|| {
            std::fs::create_dir(&identity).unwrap();
            std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o750)).unwrap();
        },
    ];
    for replace in replacements {
        import_tree(target.path(), uid(), gate, &payload, |_| {}).unwrap();
        std::fs::remove_dir_all(&identity).unwrap();
        replace();
        let before = (snapshot(target.path()), snapshot(elsewhere.path()));
        assert_eq!(
            forget_identity(target.path(), uid(), gate).err(),
            Some("aegis_tree_unsafe")
        );
        // Nothing moved into the sweep namespace; nothing was followed.
        assert_eq!(
            (snapshot(target.path()), snapshot(elsewhere.path())),
            before
        );
        // An import still replaces the whole tree and repairs it.
        let report = import_tree(target.path(), uid(), gate, &payload, |_| {}).unwrap();
        assert!(report.retired_removed);
        assert_eq!(names(target.path()), ["Aegis"]);
        assert!(same_online(
            &admitted_online(target.path()),
            source.online()
        ));
        assert_eq!(snapshot(elsewhere.path()), before.1);
    }
}

#[test]
fn identity_forget_removes_the_live_identity_despite_an_unremovable_leftover() {
    let gate = gate();
    let source = ReadyTree::new(relay());
    let payload = payload_of(&source);
    let target = TempContainer::new();
    import_tree(target.path(), uid(), gate, &payload, |_| {}).unwrap();
    // A retired tree deeper than the bounded removal walks.
    let leftover = target.path().join(".aegis-retired-1-1-1");
    let deep = (0..12).fold(leftover.clone(), |path, level| {
        path.join(format!("d{level}"))
    });
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("device.key"), b"old").unwrap();
    // Import still refuses to commit over an unremovable leftover.
    let before = snapshot(target.path());
    assert_eq!(
        import_tree(target.path(), uid(), gate, &payload, |_| {}).err(),
        Some("import_sweep_failed")
    );
    assert_eq!(snapshot(target.path()), before);
    // Forget still removes the live identity, but reports the leftover.
    assert_eq!(
        forget_identity(target.path(), uid(), gate).unwrap(),
        ForgetReport {
            identity_was_present: true,
            key_material_removed: false
        }
    );
    assert_eq!(names(&target.path().join("Aegis")), ["bundle"]);
    assert_eq!(names(target.path()), [".aegis-retired-1-1-1", "Aegis"]);
    assert_eq!(
        forget_identity(target.path(), uid(), gate).unwrap(),
        ForgetReport {
            identity_was_present: false,
            key_material_removed: false
        }
    );
    std::fs::remove_dir_all(&leftover).unwrap();
    assert_eq!(
        forget_identity(target.path(), uid(), gate).unwrap(),
        ForgetReport {
            identity_was_present: false,
            key_material_removed: true
        }
    );
}

fn member_bytes(payload: &ImportPayload) -> Vec<(&'static str, Zeroizing<Vec<u8>>)> {
    payload
        .files()
        .map(|(m, bytes)| (m.name(), Zeroizing::new(bytes.to_vec())))
        .collect()
}

fn with_member(
    payload: &ImportPayload,
    name: &str,
    bytes: &[u8],
) -> Result<ImportPayload, &'static str> {
    let mut files = member_bytes(payload);
    files.iter_mut().find(|(n, _)| *n == name).unwrap().1 = Zeroizing::new(bytes.to_vec());
    ImportPayload::from_members(files)
}

#[test]
fn identity_import_refuses_an_identity_without_a_completion_receipt() {
    // The host cannot even read an unissued tree into a payload.
    let unissued = ReadyTree::unissued(relay());
    assert_eq!(
        crate::host_import::SourceTree::open(unissued.aegis()).err(),
        Some("import_source_missing")
    );
    // A payload or manifest without the receipt is refused before staging.
    let source = ReadyTree::new(relay());
    let good = payload_of(&source);
    let mut files = member_bytes(&good);
    files.retain(|(name, _)| *name != "identity/online-completed.json");
    assert_eq!(
        ImportPayload::from_members(files).err(),
        Some("import_file_missing")
    );
    let mut manifest: Value = serde_json::from_slice(&encode_manifest(&good.manifest())).unwrap();
    manifest["files"]
        .as_array_mut()
        .unwrap()
        .retain(|f| f["name"] != "identity/online-completed.json");
    assert_eq!(
        decode_manifest(&serde_json::to_vec(&manifest).unwrap()).err(),
        Some("import_file_missing")
    );
    // The issued payload commits.
    let target = TempContainer::new();
    import_tree(target.path(), uid(), gate(), &good, |_| {}).unwrap();
    assert!(same_online(
        &admitted_online(target.path()),
        source.online()
    ));
}

#[test]
fn identity_import_refuses_swapped_completion_name_swapped_csr_and_reencoded_certificate() {
    let target = TempContainer::new();
    let gate = gate();
    let installed = ReadyTree::new(relay());
    import_tree(target.path(), uid(), gate, &payload_of(&installed), |_| {}).unwrap();
    let before = snapshot(target.path());
    let source = ReadyTree::new(relay());
    let other = ReadyTree::new(relay());
    let good = payload_of(&source);
    let refused = |payload: ImportPayload, name: &str| {
        assert_eq!(
            import_tree(target.path(), uid(), gate, &payload, |_| {}).err(),
            Some("import_identity_refused"),
            "{name}"
        );
        assert_eq!(snapshot(target.path()), before, "{name}");
        assert!(same_online(
            &admitted_online(target.path()),
            installed.online()
        ));
    };
    let completed = |tree: &ReadyTree| {
        std::fs::read(tree.identity_dir().join("online-completed.json")).unwrap()
    };
    refused(
        with_member(&good, "identity/online-completed.json", &completed(&other)).unwrap(),
        "foreign receipt",
    );
    let key = String::from_utf8(std::fs::read(source.identity_dir().join("device.key")).unwrap())
        .unwrap();
    let swapped =
        aegis_core::secure_channel::enrollment::csr_for_key("fixture-device-2", &key).unwrap();
    refused(
        with_member(&good, "identity/device.csr", swapped.as_bytes()).unwrap(),
        "name-swapped csr",
    );
    // A receipt whose certificate is re-encoded: the Store over the staged
    // tree admits it (same DER), the provider custody check does not.
    let mut value: Value = serde_json::from_slice(&completed(&source)).unwrap();
    let pem = value["receipt"]["certificate_pem"]
        .as_str()
        .unwrap()
        .to_owned();
    value["receipt"]["certificate_pem"] = json!(format!("{pem}\n"));
    let reencoded = serde_json::to_vec(&value).unwrap();
    source.write_identity_file("online-completed.json", &reencoded);
    let store =
        ProtectedOnlineExpectation::open_existing(&source.identity_dir(), source.profile_sha256())
            .unwrap();
    assert!(store.expectation_at(registry::unix_now().unwrap()).is_ok());
    drop(store);
    refused(
        with_member(&good, "identity/online-completed.json", &reencoded).unwrap(),
        "re-encoded certificate",
    );
    // The untouched payload still commits.
    import_tree(target.path(), uid(), gate, &good, |_| {}).unwrap();
    assert_eq!(gate.holders(), 0);
}

// ---------------------------------------------------------------------------
// Audit: transient read leases (public terms) never refuse import/forget as
// a live session, and cannot hold them off past the drain bound.

#[test]
fn identity_gate_waits_for_read_leases_instead_of_refusing() {
    let gate = gate();
    let reader = gate.read_lease();
    assert_eq!((gate.readers(), gate.holders()), (1, 0));
    let (release, released) = mpsc::channel::<()>();
    let dropper = std::thread::spawn(move || {
        released.recv().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        drop(reader);
    });
    release.send(()).unwrap();
    let started = std::time::Instant::now();
    let exclusive = gate.exclusive_for_test(Duration::from_secs(5)).unwrap();
    assert!(started.elapsed() >= Duration::from_millis(90));
    assert_eq!(gate_readers_while_held(&exclusive), 0);
    drop(exclusive);
    dropper.join().unwrap();
    // A session lease still refuses at once, and so does one that starts
    // while the import waits for readers.
    let session = gate.lease();
    let started = std::time::Instant::now();
    assert_eq!(
        gate.exclusive_for_test(Duration::from_secs(5)).err(),
        Some("session_live")
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(session);
    let reader = gate.read_lease();
    let starter = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        let session = gate.lease();
        std::thread::sleep(Duration::from_millis(100));
        drop(reader);
        session
    });
    assert_eq!(
        gate.exclusive_for_test(Duration::from_secs(5)).err(),
        Some("session_live")
    );
    drop(starter.join().unwrap());
    assert_eq!((gate.readers(), gate.holders()), (0, 0));
}

/// The held guard's view; the gate's own mutex is held by the guard.
fn gate_readers_while_held(exclusive: &ExclusiveTree<'_>) -> usize {
    exclusive.state.as_ref().unwrap().readers
}

#[test]
fn identity_gate_admits_no_new_reader_while_an_import_waits_or_runs() {
    let gate = gate();
    let first = gate.read_lease();
    let (events, observed) = mpsc::channel::<&'static str>();
    let writer_events = events.clone();
    let writer = std::thread::spawn(move || {
        let exclusive = gate.exclusive_for_test(Duration::from_secs(5)).unwrap();
        writer_events.send("exclusive").unwrap();
        std::thread::sleep(Duration::from_millis(150));
        // Sent before the release: a reader woken by the drop could
        // otherwise report first (a race under load, seen once in v30).
        writer_events.send("released").unwrap();
        drop(exclusive);
    });
    // The writer is waiting for `first`.
    let started = std::time::Instant::now();
    while gate.lock().writers_waiting == 0 {
        assert!(started.elapsed() < Duration::from_secs(2));
        std::thread::yield_now();
    }
    let reader = std::thread::spawn(move || {
        let lease = gate.read_lease();
        events.send("reader").unwrap();
        drop(lease);
    });
    // A new reader waits behind the writer, so readers can never overlap
    // into a continuous hold.
    assert!(observed.recv_timeout(Duration::from_millis(150)).is_err());
    drop(first);
    assert_eq!(
        observed.recv_timeout(Duration::from_secs(2)),
        Ok("exclusive")
    );
    assert_eq!(
        observed.recv_timeout(Duration::from_secs(2)),
        Ok("released")
    );
    assert_eq!(observed.recv_timeout(Duration::from_secs(2)), Ok("reader"));
    writer.join().unwrap();
    reader.join().unwrap();
    assert_eq!((gate.readers(), gate.holders()), (0, 0));
}

#[test]
fn identity_gate_reader_past_the_drain_is_busy_not_a_live_session() {
    let gate = gate();
    let stuck = gate.read_lease();
    let started = std::time::Instant::now();
    assert_eq!(
        gate.exclusive_for_test(Duration::from_millis(100)).err(),
        Some("tree_busy")
    );
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(90) && waited < Duration::from_secs(2));
    // The refused writer no longer holds readers off.
    assert_eq!(gate.lock().writers_waiting, 0);
    let other = gate.read_lease();
    drop((stuck, other));
    assert!(gate.exclusive_for_test(Duration::from_millis(100)).is_ok());
    assert_eq!(READER_DRAIN, Duration::from_secs(2));
}
