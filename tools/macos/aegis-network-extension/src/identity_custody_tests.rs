use super::*;
use crate::{
    app_group::{custody_refusal_code, CapturedAppGroupInputs},
    configuration::SavedProviderIntent,
    local_identity::{CapturedLocalIdentity, PreparedLocalSession},
    test_fixture::ReadyTree,
};
use aegis_client::protected_online_expectation::ProtectedOnlineExpectation;
use serde_json::json;
use std::{net::SocketAddr, os::unix::fs::PermissionsExt};

fn relay() -> SocketAddr {
    "127.0.0.1:443".parse().unwrap()
}

fn read(tree: &ReadyTree, leaf: &str) -> Vec<u8> {
    std::fs::read(tree.identity_dir().join(leaf)).unwrap()
}

/// The capture's refusal code, or None when it admits the tree.
fn capture_code(tree: &ReadyTree) -> Option<&'static str> {
    CapturedAppGroupInputs::capture_test_root(tree.root())
        .err()
        .map(|error| custody_refusal_code(&error))
}

/// The protected Store's own offline verdict over the same tree.
fn store_admits(tree: &ReadyTree) -> bool {
    ProtectedOnlineExpectation::open_existing(&tree.identity_dir(), tree.profile_sha256())
        .and_then(|store| store.expectation_at(registry::unix_now().unwrap()))
        .is_ok()
}

fn completion(tree: &ReadyTree) -> Value {
    serde_json::from_slice(&read(tree, "online-completed.json")).unwrap()
}

fn write_completion(tree: &ReadyTree, value: &Value) {
    tree.write_identity_file("online-completed.json", &serde_json::to_vec(value).unwrap());
}

fn verify_tree(tree: &ReadyTree) -> Result<HeldIssuance, &'static str> {
    let (record, key, csr, certificate, device_ca, completion) = (
        read(tree, "identity.json"),
        read(tree, "device.key"),
        read(tree, "device.csr"),
        read(tree, "device.pem"),
        read(tree, "device-ca.pem"),
        read(tree, "online-completed.json"),
    );
    verify(
        &HeldIdentityBytes {
            record: &record,
            key: &key,
            csr: &csr,
            certificate: &certificate,
            device_ca: &device_ca,
            completion: &completion,
        },
        tree.profile_sha256(),
    )
}

#[test]
fn custody_admits_only_the_issued_fixture_and_binds_its_issuance() {
    let tree = ReadyTree::new(relay());
    assert_eq!(capture_code(&tree), None);
    let inputs = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let identity = CapturedLocalIdentity::from_claim(inputs).unwrap();
    let mut prepared: PreparedLocalSession = identity.prepare_crypto().unwrap();
    let saved = SavedProviderIntent {
        generation: tree.generation().into(),
        policy: tree.policy().clone(),
    };
    let (_, online) = prepared.derive_runtime(&saved).unwrap();
    assert_eq!(online.issued_generation, Some(7));
    assert_eq!(
        online.snapshot_sha256.as_deref(),
        Some("c".repeat(64).as_str())
    );
    drop(prepared);

    // The offline-ready identity the Store admits is refused by the capture:
    // no completion receipt, no provider identity.
    let unissued = ReadyTree::unissued(relay());
    assert!(store_admits(&unissued));
    assert_eq!(
        capture_code(&unissued),
        Some("file_missing:online-completed.json")
    );
    // Removing the receipt of an issued tree is the same refusal.
    std::fs::remove_file(tree.identity_dir().join("online-completed.json")).unwrap();
    assert_eq!(
        capture_code(&tree),
        Some("file_missing:online-completed.json")
    );
}

#[test]
fn custody_capture_refuses_missing_mutated_name_swapped_and_foreign_csr() {
    // Missing.
    let tree = ReadyTree::new(relay());
    std::fs::remove_file(tree.identity_dir().join("device.csr")).unwrap();
    assert_eq!(capture_code(&tree), Some("file_missing:device.csr"));

    // Mutated: one base64 byte of the body, same length.
    let tree = ReadyTree::new(relay());
    let mut csr = read(&tree, "device.csr");
    // The midpoint byte is `+` or `/` for some keys; take the next letter or
    // digit (still mid-body, far from the padding bits before `=`).
    let at = (csr.len() / 2..csr.len())
        .find(|&i| csr[i].is_ascii_alphanumeric())
        .unwrap();
    csr[at] = if csr[at] == b'A' { b'B' } else { b'A' };
    tree.write_identity_file("device.csr", &csr);
    assert_eq!(capture_code(&tree), Some(CSR_MISMATCH));

    // Name-swapped: a valid CSR of the held key for another device id.
    let tree = ReadyTree::new(relay());
    let key = String::from_utf8(read(&tree, "device.key")).unwrap();
    let swapped = enrollment::csr_for_key("fixture-device-2", &key).unwrap();
    assert_ne!(swapped.as_bytes(), read(&tree, "device.csr"));
    tree.write_identity_file("device.csr", swapped.as_bytes());
    assert_eq!(capture_code(&tree), Some(CSR_MISMATCH));

    // Foreign: the CSR another key signs for the same device id.
    let tree = ReadyTree::new(relay());
    let other = ReadyTree::new(relay());
    assert_eq!(tree.device_id(), other.device_id());
    tree.write_identity_file("device.csr", &read(&other, "device.csr"));
    assert_eq!(capture_code(&tree), Some(CSR_MISMATCH));

    // A foreign key beside the held CSR breaks the same binding.
    let tree = ReadyTree::new(relay());
    tree.write_identity_file("device.key", &read(&other, "device.key"));
    assert_eq!(capture_code(&tree), Some(CSR_MISMATCH));
}

#[test]
fn custody_capture_refuses_swapped_and_rebound_completion_receipts() {
    let other = ReadyTree::new(relay());
    let check = |mutate: &dyn Fn(&mut Value), name: &str| {
        let tree = ReadyTree::new(relay());
        let mut value = completion(&tree);
        mutate(&mut value);
        write_completion(&tree, &value);
        assert_eq!(capture_code(&tree), Some(COMPLETION_REFUSED), "{name}");
    };
    // Another tree's receipt: same device id, generation and snapshot, but
    // another CSR and certificate.
    let foreign = completion(&other);
    check(&|value| *value = foreign.clone(), "foreign receipt");
    check(
        &|value| value["receipt"]["device_id"] = json!("fixture-device-2"),
        "device id",
    );
    check(
        &|value| value["receipt"]["binding"]["csr_sha256"] = json!("e".repeat(64)),
        "csr digest",
    );
    check(
        &|value| value["receipt"]["binding"]["profile_sha256"] = json!("e".repeat(64)),
        "profile",
    );
    check(
        &|value| value["receipt"]["certificate_sha256"] = json!("e".repeat(64)),
        "certificate digest",
    );
    check(
        &|value| {
            value["receipt"]["certificate_pem"] = foreign["receipt"]["certificate_pem"].clone()
        },
        "certificate",
    );
    check(
        &|value| value["predecessor_certificate_pem"] = json!("pem"),
        "redeem predecessor",
    );
    check(&|value| value["version"] = json!(2), "version");
    check(&|value| value["extra"] = json!(1), "extra field");
    check(
        &|value| value["receipt"]["extra"] = json!(1),
        "receipt field",
    );
    check(
        &|value| value["receipt"]["issued_generation"] = json!(0),
        "zero generation",
    );
    check(
        &|value| value["receipt"]["snapshot_sha256"] = json!("short"),
        "snapshot",
    );
    // S23: the window must be the held certificate's own signed validity.
    // A receipt edited to an earlier (already past) or later end, or start,
    // stays this terminal refusal: never read as an expired identity.
    let window = |end: &'static str, by: i64| {
        move |value: &mut Value| {
            let at = value["receipt"][end].as_u64().unwrap();
            value["receipt"][end] = json!(at.checked_add_signed(by).unwrap());
        }
    };
    let held = completion(&ReadyTree::new(relay()));
    let lifetime = held["receipt"]["not_after_unix_secs"].as_u64().unwrap()
        - held["receipt"]["not_before_unix_secs"].as_u64().unwrap();
    let past = i64::try_from(lifetime).unwrap() - 1;
    check(
        &window("not_after_unix_secs", -past),
        "not_after in the past",
    );
    check(&window("not_after_unix_secs", 1), "later not_after");
    check(&window("not_before_unix_secs", -1), "earlier not_before");
    check(&window("not_before_unix_secs", 1), "later not_before");

    // The receipt's certificate must be the held device.pem byte for byte.
    // A re-encoding the Store still admits (same DER) is refused here.
    let tree = ReadyTree::new(relay());
    let mut value = completion(&tree);
    let pem = value["receipt"]["certificate_pem"]
        .as_str()
        .unwrap()
        .to_owned();
    value["receipt"]["certificate_pem"] = json!(format!("{pem}\n"));
    write_completion(&tree, &value);
    assert!(store_admits(&tree));
    assert_eq!(capture_code(&tree), Some(COMPLETION_REFUSED));

    // Malformed bytes.
    let tree = ReadyTree::new(relay());
    tree.write_identity_file("online-completed.json", b"{");
    assert_eq!(capture_code(&tree), Some(COMPLETION_REFUSED));

    // S23: the window is judged under the device CA the record pins; a
    // swapped CA leaves the receipt's window unverified, so it is refused.
    // A record and receipt that agree on a digest the held certificate does
    // not have: the signed certificate decides.
    let tree = ReadyTree::new(relay());
    let mut record: Value = serde_json::from_slice(&read(&tree, "identity.json")).unwrap();
    record["certificate_sha256"] = json!("e".repeat(64));
    tree.write_identity_file("identity.json", &serde_json::to_vec(&record).unwrap());
    let mut value = completion(&tree);
    value["receipt"]["certificate_sha256"] = json!("e".repeat(64));
    write_completion(&tree, &value);
    assert_eq!(verify_tree(&tree), Err(COMPLETION_REFUSED));

    // That includes a re-encoding of the same CA the record does not pin.
    let tree = ReadyTree::new(relay());
    let mut reencoded = read(&tree, "device-ca.pem");
    reencoded.push(b'\n');
    for ca in [read(&other, "device-ca.pem"), reencoded] {
        tree.write_identity_file("device-ca.pem", &ca);
        assert_eq!(
            verify_tree(&tree).map(|held| held.window()),
            Err(COMPLETION_REFUSED)
        );
    }
}

#[test]
fn custody_capture_refuses_a_record_that_is_not_ready_version_one() {
    let check = |mutate: &dyn Fn(&mut Value), name: &str| {
        let tree = ReadyTree::new(relay());
        let mut record: Value = serde_json::from_slice(&read(&tree, "identity.json")).unwrap();
        mutate(&mut record);
        tree.write_identity_file("identity.json", &serde_json::to_vec(&record).unwrap());
        assert_eq!(capture_code(&tree), Some(RECORD_REFUSED), "{name}");
    };
    check(&|record| record["phase"] = json!("prepared"), "phase");
    check(&|record| record["version"] = json!(2), "version");
    check(&|record| record["extra"] = json!(1), "extra field");
    check(
        &|record| record["certificate_sha256"] = Value::Null,
        "no certificate",
    );
    check(
        &|record| record["certificate_sha256"] = json!("E".repeat(64)),
        "certificate digest spelling",
    );
    check(
        &|record| record["device_id"] = json!("bad id/with slash"),
        "device id",
    );
}

#[test]
fn custody_capture_refuses_a_pending_online_journal() {
    for leaf in JOURNAL {
        // A file, a directory or a link at the leaf: presence alone refuses.
        for kind in ["file", "dir", "link"] {
            let tree = ReadyTree::new(relay());
            let path = tree.identity_dir().join(leaf);
            match kind {
                "file" => tree.write_identity_file(leaf, b"{}"),
                "dir" => {
                    std::fs::create_dir(&path).unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
                _ => std::os::unix::fs::symlink("/nonexistent", &path).unwrap(),
            }
            assert_eq!(
                capture_code(&tree),
                Some(JOURNAL_PENDING),
                "{leaf} as {kind}"
            );
        }
    }
    // An in-place rewrite of the held CSR or receipt after capture (same
    // inode, so the directory is unchanged) fails the held file generation.
    for leaf in ["device.csr", "online-completed.json"] {
        let tree = ReadyTree::new(relay());
        let inputs = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let path = tree.identity_dir().join(leaf);
        let bytes = std::fs::read(&path).unwrap();
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        std::io::Write::write_all(&mut file, &bytes).unwrap();
        drop(file);
        assert!(inputs.revalidate().is_err(), "{leaf}");
    }
    // A journal created after capture fails the held identity generation.
    let tree = ReadyTree::new(relay());
    let inputs = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    inputs.revalidate().unwrap();
    tree.write_identity_file("online-request.json", b"{}");
    assert!(inputs.revalidate().is_err());
    drop(inputs);
    assert_eq!(capture_code(&tree), Some(JOURNAL_PENDING));
}

#[test]
fn custody_store_expectation_must_be_the_held_receipt_issuance() {
    let tree = ReadyTree::new(relay());
    let held = verify_tree(&tree).unwrap();
    held.ensure_matches(tree.online()).unwrap();
    let mut changed = Vec::new();
    let mut next = tree.online().clone();
    next.certificate_sha256 = "e".repeat(64);
    changed.push(next);
    next = tree.online().clone();
    next.not_after_unix_secs += 1;
    changed.push(next);
    next = tree.online().clone();
    next.issued_generation = Some(8);
    changed.push(next);
    next = tree.online().clone();
    next.snapshot_sha256 = Some("f".repeat(64));
    changed.push(next);
    next = tree.online().clone();
    next.issued_generation = None;
    changed.push(next);
    next = tree.online().clone();
    next.snapshot_sha256 = None;
    changed.push(next);
    let inputs = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    inputs.ensure_held_issuance(tree.online()).unwrap();
    for next in &changed {
        assert_eq!(held.ensure_matches(next), Err(ISSUANCE_MISMATCH));
        assert_eq!(
            custody_refusal_code(&inputs.ensure_held_issuance(next).unwrap_err()),
            ISSUANCE_MISMATCH
        );
    }
    // A receipt for another generation names that generation, never this
    // Store's: the held issuance follows the held bytes.
    drop(inputs);
    tree.rewrite_issued_generation(9);
    let renamed = verify_tree(&tree).unwrap();
    assert_ne!(renamed, held);
    assert_eq!(
        renamed.ensure_matches(tree.online()),
        Err(ISSUANCE_MISMATCH)
    );
}
