#![cfg(unix)]

use aegis_core::secure_channel::{enrollment, registry};
use rcgen::{CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

struct OwnedChild(Option<Child>);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_cli(root: &Path, args: Vec<OsString>) -> Output {
    // Normal client startup cannot use a caller's actual configuration. The
    // device commands must return before reading this nonexistent config.
    let mut child = OwnedChild(Some(
        Command::new(env!("CARGO_BIN_EXE_aegis-client"))
            .arg("--config")
            .arg(root.join("aegis.toml"))
            .args(args)
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn local device CLI"),
    ));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            return child.0.take().unwrap().wait_with_output().unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "device CLI did not terminate locally"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

// No assertion prints this map: it includes the fixture's private key bytes.
// Reads may change atime; every persistent stat8 component remains checked.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (Vec<u8>, [i128; 8])> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).unwrap();
        let bytes = if metadata.is_dir() {
            pending.extend(
                fs::read_dir(&path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path()),
            );
            Vec::new()
        } else {
            assert!(metadata.is_file(), "fixture gained a nonregular member");
            fs::read(&path).unwrap()
        };
        result.insert(
            path.strip_prefix(root).unwrap().to_owned(),
            (
                bytes,
                [
                    metadata.dev() as i128,
                    metadata.ino() as i128,
                    metadata.mode() as i128,
                    metadata.uid() as i128,
                    metadata.nlink() as i128,
                    metadata.size() as i128,
                    metadata.mtime() as i128 * 1_000_000_000 + metadata.mtime_nsec() as i128,
                    metadata.ctime() as i128 * 1_000_000_000 + metadata.ctime_nsec() as i128,
                ],
            ),
        );
    }
    result
}

#[test]
fn bundle_ready_cli_is_local_and_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let identity = root.join("identity");
    let bundle = root.join("public-bundle");
    let issuer_path = root.join("issuer.pem");
    let profile_path = root.join("public-profile.json");
    let certificate_path = root.join("response.pem");
    let device_id = "bundle_ready_e2e";
    assert!(!root.join("aegis.toml").exists());

    let issuer_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let issuer_pem = params.self_signed(&issuer_key).unwrap().pem();
    enrollment::write_private_new(&issuer_path, issuer_pem.as_bytes()).unwrap();
    // Reserved .invalid names and no listener/config; this fixture has no live
    // enrollment or relay endpoint, and uses only local offline signing.
    let profile = json!({
        "schema": "aegis_device_bundle_v3",
        "product_mode": "socks-only",
        "relay_server": "relay.invalid:443",
        "outer_server_name": "relay.invalid",
        "inner_server_name": "inner.invalid",
        "udp": false,
        "enrollment": {
            "protocol": "aegis-enrollment-v1",
            "authority_server": "authority.invalid:443",
            "outer_server_name": "authority.invalid",
            "inner_server_name": "issuer.invalid",
            "automatic_renewal": true,
            "renewal_policy": "same-key-v1"
        }
    });
    enrollment::write_private_new(&profile_path, &serde_json::to_vec(&profile).unwrap()).unwrap();
    let created = run_cli(
        &root,
        vec![
            "device".into(),
            "bundle-create".into(),
            "--bundle-dir".into(),
            bundle.clone().into(),
            "--profile".into(),
            profile_path.into(),
            "--outer-ca".into(),
            issuer_path.clone().into(),
            "--inner-ca".into(),
            issuer_path.clone().into(),
            "--device-ca".into(),
            issuer_path.clone().into(),
        ],
    );
    assert!(created.status.success(), "public bundle CLI failed");
    let mut members: Vec<_> = fs::read_dir(&bundle)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    members.sort();
    assert_eq!(
        members,
        [
            "bundle.json",
            "device-ca.pem",
            "inner-ca.pem",
            "outer-ca.pem"
        ]
        .map(OsString::from)
    );
    let prepared = run_cli(
        &root,
        vec![
            "device".into(),
            "prepare".into(),
            "--device-id".into(),
            device_id.into(),
            "--identity-dir".into(),
            identity.clone().into(),
            "--device-ca".into(),
            issuer_path.clone().into(),
        ],
    );
    assert!(prepared.status.success(), "identity preparation CLI failed");
    let inspected = run_cli(
        &root,
        vec![
            "device".into(),
            "bundle-inspect".into(),
            "--bundle-dir".into(),
            bundle.clone().into(),
            "--identity-dir".into(),
            identity.clone().into(),
            "--json".into(),
        ],
    );
    assert!(inspected.status.success(), "public profile pin CLI failed");
    let public: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    let mut digest = Sha256::new();
    for name in [
        "bundle.json",
        "outer-ca.pem",
        "inner-ca.pem",
        "device-ca.pem",
    ] {
        let bytes = fs::read(bundle.join(name)).unwrap();
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    let profile_sha256 = hex::encode(digest.finalize());
    assert_eq!(public["profile_sha256"], profile_sha256);
    assert!(fs::read(identity.join("bundle-profile.sha256")).unwrap() == profile_sha256.as_bytes());
    assert!(!identity.join("device.pem").exists());

    let ready_args = || {
        vec![
            "device".into(),
            "bundle-ready".into(),
            "--bundle-dir".into(),
            bundle.clone().into(),
            "--identity-dir".into(),
            identity.clone().into(),
            "--device-id".into(),
            device_id.into(),
        ]
    };
    let before_prepared = snapshot(&root);
    let refused = run_cli(&root, ready_args());
    assert!(!refused.status.success(), "prepared identity was admitted");
    assert!(
        refused.stdout.is_empty(),
        "prepared identity emitted success JSON"
    );
    // The default CLI deliberately conceals the internal error chain. The
    // refusal remains structured and does not expose identity-store details.
    let failure: serde_json::Value = serde_json::from_slice(&refused.stderr).unwrap();
    assert_eq!(failure["event_code"], "client_failed");
    assert_eq!(failure["diagnostics"], "private");
    assert!(failure["error_kind"].is_string());
    assert!(!String::from_utf8_lossy(&refused.stderr).contains("completed identity"));
    assert!(
        snapshot(&root) == before_prepared,
        "prepared readiness CLI wrote state"
    );
    let missing_id = run_cli(
        &root,
        vec![
            "device".into(),
            "bundle-ready".into(),
            "--bundle-dir".into(),
            bundle.clone().into(),
            "--identity-dir".into(),
            identity.clone().into(),
        ],
    );
    assert_eq!(missing_id.status.code(), Some(2));
    assert!(missing_id.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing_id.stderr).contains("--device-id"));
    assert!(
        snapshot(&root) == before_prepared,
        "parser refusal wrote state"
    );

    let now = registry::unix_now().unwrap();
    let csr = fs::read_to_string(identity.join("device.csr")).unwrap();
    let signed = enrollment::sign_csr(
        device_id,
        &csr,
        &issuer_pem,
        &issuer_key.serialize_pem(),
        now,
        300,
    )
    .unwrap();
    enrollment::write_private_new(&certificate_path, signed.certificate_pem.as_bytes()).unwrap();
    let completed = run_cli(
        &root,
        vec![
            "device".into(),
            "complete".into(),
            "--identity-dir".into(),
            identity.clone().into(),
            "--certificate".into(),
            certificate_path.into(),
            "--device-ca".into(),
            issuer_path.into(),
        ],
    );
    assert!(
        completed.status.success(),
        "offline certificate completion CLI failed"
    );
    let complete_status: serde_json::Value = serde_json::from_slice(&completed.stdout).unwrap();
    assert_eq!(complete_status["phase"], "ready");

    let before_ready = snapshot(&root);
    let checked_before = registry::unix_now().unwrap();
    let ready = run_cli(&root, ready_args());
    let checked_after = registry::unix_now().unwrap();
    assert!(
        ready.status.success(),
        "completed local identity was refused"
    );
    assert!(
        ready.stderr.is_empty(),
        "ready CLI emitted unexpected diagnostics"
    );
    let facts: serde_json::Value = serde_json::from_slice(&ready.stdout).unwrap();
    let checked = facts["checked_at_unix_secs"].as_u64().unwrap();
    assert!(checked_before <= checked && checked <= checked_after);
    assert_eq!(
        facts,
        json!({
            "schema": "aegis_device_bundle_ready_v1",
            "device_id": device_id,
            "profile_sha256": profile_sha256,
            "device_ca_sha256": hex::encode(Sha256::digest(issuer_pem.as_bytes())),
            "certificate_sha256": signed.record.certificate_sha256,
            "not_before_unix_secs": now,
            "not_after_unix_secs": now + 300,
            "checked_at_unix_secs": checked,
            "local_only": true
        })
    );
    let emitted = String::from_utf8(ready.stdout).unwrap();
    assert!(!emitted.contains("PRIVATE KEY") && !emitted.contains("CERTIFICATE"));
    let private_key = fs::read_to_string(identity.join("device.key")).unwrap();
    assert!(!emitted.contains(&private_key));
    assert!(!emitted.contains(&issuer_key.serialize_pem()));
    assert!(
        snapshot(&root) == before_ready,
        "ready CLI wrote fixture state"
    );
    assert!(!root.join("aegis.toml").exists());
}
