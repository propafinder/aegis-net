use super::*;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::os::unix::fs::{symlink, PermissionsExt};

struct Fixture {
    _directory: tempfile::TempDir,
    args: PrepareArgs,
    ca_pem: String,
    ca_key: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let ca_pem = ca_params.self_signed(&key).unwrap().pem();
        let device_ca = directory.path().join("issuer.pem");
        enrollment::write_private_new(&device_ca, ca_pem.as_bytes()).unwrap();
        Self {
            args: PrepareArgs {
                device_id: "test-device".into(),
                identity_dir: directory.path().join("identity"),
                device_ca,
            },
            _directory: directory,
            ca_pem,
            ca_key: key.serialize_pem(),
        }
    }

    fn certificate(&self) -> PathBuf {
        let csr = fs::read_to_string(self.args.identity_dir.join("device.csr")).unwrap();
        let issued = enrollment::sign_csr(
            &self.args.device_id,
            &csr,
            &self.ca_pem,
            &self.ca_key,
            registry::unix_now().unwrap(),
            300,
        )
        .unwrap();
        let certificate = self._directory.path().join("response.pem");
        enrollment::write_private_new(&certificate, issued.certificate_pem.as_bytes()).unwrap();
        certificate
    }
}

#[test]
fn prepare_complete_and_resume_preserve_the_only_local_key() {
    let fixture = Fixture::new();
    assert_eq!(prepare(&fixture.args).unwrap().phase, "prepared");
    let key_path = fixture.args.identity_dir.join("device.key");
    let key = fs::read(&key_path).unwrap();
    let csr = fs::read(fixture.args.identity_dir.join("device.csr")).unwrap();
    assert_eq!(prepare(&fixture.args).unwrap().phase, "prepared");
    assert_eq!(fs::read(&key_path).unwrap(), key);
    assert_eq!(
        fs::read(fixture.args.identity_dir.join("device.csr")).unwrap(),
        csr
    );
    let args = CompleteArgs {
        identity_dir: fixture.args.identity_dir.clone(),
        certificate: fixture.certificate(),
        device_ca: fixture.args.device_ca.clone(),
    };
    assert_eq!(complete(&args).unwrap().phase, "ready");
    assert_eq!(complete(&args).unwrap().phase, "ready");
    assert_eq!(prepare(&fixture.args).unwrap().phase, "ready");
    let json = serde_json::to_string(&status(&fixture.args.identity_dir).unwrap()).unwrap();
    assert!(!json.contains("BEGIN") && json.contains("csr_path"));
    assert_eq!(fs::read(&key_path).unwrap(), key);
    let mut key_count = 0;
    for entry in fs::read_dir(&fixture.args.identity_dir).unwrap() {
        let entry = entry.unwrap();
        assert_eq!(
            entry.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        let bytes = fs::read(entry.path()).unwrap();
        if bytes.windows(11).any(|bytes| bytes == b"PRIVATE KEY") {
            key_count += 1;
        }
    }
    assert_eq!(key_count, 1);
}

#[test]
fn prepared_identity_refuses_wrong_identity_ca_key_loss_and_key_alias() {
    let fixture = Fixture::new();
    prepare(&fixture.args).unwrap();
    let other = Fixture::new();
    let mut wrong = fixture.args.clone();
    wrong.device_id = "different-device".into();
    assert!(prepare(&wrong).is_err());
    wrong = fixture.args.clone();
    wrong.device_ca = other.args.device_ca;
    assert!(prepare(&wrong).is_err());
    let key = fixture.args.identity_dir.join("device.key");
    let old = fixture._directory.path().join("removed.key");
    fs::rename(&key, &old).unwrap();
    assert!(prepare(&fixture.args).is_err());
    assert!(!key.exists());
    symlink(&old, &key).unwrap();
    assert!(prepare(&fixture.args).is_err());
    assert!(status(&fixture.args.identity_dir).is_err());
    fs::remove_file(&key).unwrap();
    fs::hard_link(&old, &key).unwrap();
    assert!(prepare(&fixture.args).is_err());
}

#[test]
fn public_response_cannot_replace_trust_or_install_a_different_devices_certificate() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    prepare(&fixture.args).unwrap();
    prepare(&other.args).unwrap();
    let output = fixture.args.identity_dir.join("device.pem");
    let mut args = CompleteArgs {
        identity_dir: fixture.args.identity_dir.clone(),
        certificate: fixture.certificate(),
        device_ca: other.args.device_ca.clone(),
    };
    assert!(complete(&args).is_err());
    assert!(!output.exists());
    args.device_ca = fixture.args.device_ca.clone();
    args.certificate = other.certificate();
    assert!(complete(&args).is_err());
    assert!(!output.exists());
    assert_eq!(
        status(&fixture.args.identity_dir).unwrap().phase,
        "prepared"
    );
}

#[test]
fn initializing_resumes_existing_key_but_does_not_replace_a_lost_key_with_existing_csr() {
    let fixture = Fixture::new();
    prepare(&fixture.args).unwrap();
    let key_path = fixture.args.identity_dir.join("device.key");
    let key = fs::read(&key_path).unwrap();
    {
        let store = Store::open(&fixture.args.identity_dir, false).unwrap();
        let mut record = store.record().unwrap();
        record.phase = "initializing".into();
        store.save_record(&record, true).unwrap();
    }
    assert_eq!(prepare(&fixture.args).unwrap().phase, "prepared");
    assert_eq!(fs::read(&key_path).unwrap(), key);
    {
        let store = Store::open(&fixture.args.identity_dir, false).unwrap();
        let mut record = store.record().unwrap();
        record.phase = "initializing".into();
        store.save_record(&record, true).unwrap();
    }
    fs::remove_file(&key_path).unwrap();
    assert!(prepare(&fixture.args).is_err());
    assert!(!key_path.exists());
}

#[test]
fn partial_certificate_commit_resumes_and_lock_serializes_mutations() {
    let fixture = Fixture::new();
    prepare(&fixture.args).unwrap();
    let certificate = fixture.certificate();
    let args = CompleteArgs {
        identity_dir: fixture.args.identity_dir.clone(),
        certificate: certificate.clone(),
        device_ca: fixture.args.device_ca.clone(),
    };
    {
        let store = Store::open(&fixture.args.identity_dir, false).unwrap();
        store
            .save("device.pem", &fs::read(certificate).unwrap(), false)
            .unwrap();
        assert!(prepare(&fixture.args).is_err());
        assert!(complete(&args).is_err());
    }
    assert_eq!(complete(&args).unwrap().phase, "ready");
}

#[test]
fn identity_directory_must_be_private_and_never_adopts_unrecorded_secret() {
    let fixture = Fixture::new();
    fs::create_dir(&fixture.args.identity_dir).unwrap();
    fs::set_permissions(
        &fixture.args.identity_dir,
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(prepare(&fixture.args).is_err());
    assert!(!fixture.args.identity_dir.join("identity.json").exists());
    fs::set_permissions(
        &fixture.args.identity_dir,
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    enrollment::write_private_new(
        &fixture.args.identity_dir.join("device.key"),
        b"previous material",
    )
    .unwrap();
    assert!(prepare(&fixture.args).is_err());
    assert_eq!(
        fs::read(fixture.args.identity_dir.join("device.key")).unwrap(),
        b"previous material"
    );
}

#[test]
fn nested_fresh_identity_and_public_certificate_permissions_are_supported() {
    let mut fixture = Fixture::new();
    fixture.args.identity_dir = fixture._directory.path().join("new-parent/nested/client");
    fs::set_permissions(&fixture.args.device_ca, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(prepare(&fixture.args).unwrap().phase, "prepared");
    let certificate = fixture.certificate();
    fs::set_permissions(&certificate, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        complete(&CompleteArgs {
            identity_dir: fixture.args.identity_dir.clone(),
            device_ca: fixture.args.device_ca.clone(),
            certificate
        })
        .unwrap()
        .phase,
        "ready"
    );
    assert_eq!(
        fs::metadata(fixture._directory.path().join("new-parent"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn interrupted_key_write_and_orphan_files_never_generate_another_private_key() {
    let fixture = Fixture::new();
    let store = Store::open(&fixture.args.identity_dir, true).unwrap();
    let record = Record {
        version: 1,
        device_id: fixture.args.device_id.clone(),
        phase: "initializing".into(),
        device_ca_sha256: sha(fixture.ca_pem.as_bytes()),
        certificate_sha256: None,
    };
    store.save_record(&record, false).unwrap();
    store
        .save("device-ca.pem", fixture.ca_pem.as_bytes(), false)
        .unwrap();
    store.create_key(b"partial interrupted key").unwrap();
    drop(store);
    assert!(prepare(&fixture.args).is_err());
    assert_eq!(
        fs::read(fixture.args.identity_dir.join("device.key")).unwrap(),
        b"partial interrupted key"
    );
    fs::remove_file(fixture.args.identity_dir.join("device.key")).unwrap();
    enrollment::write_private_new(
        &fixture.args.identity_dir.join(".orphan-key"),
        b"previous staged key",
    )
    .unwrap();
    assert!(prepare(&fixture.args).is_err());
    assert!(!fixture.args.identity_dir.join("device.key").exists());
}

#[test]
fn shared_online_expectation_reuses_binary_store_lock_and_refuses_second_owner() {
    let fixture = Fixture::new();
    prepare(&fixture.args).unwrap();
    complete(&CompleteArgs {
        identity_dir: fixture.args.identity_dir.clone(),
        certificate: fixture.certificate(),
        device_ca: fixture.args.device_ca.clone(),
    })
    .unwrap();
    let digest = "a".repeat(64);
    enrollment::write_private_new(
        &fixture.args.identity_dir.join("bundle-profile.sha256"),
        digest.as_bytes(),
    )
    .unwrap();
    let now = registry::unix_now().unwrap();
    let store = Store::open(&fixture.args.identity_dir, false).unwrap();
    let borrowed =
        aegis_client::protected_online_expectation::ProtectedOnlineExpectation::from_held(
            &store.protected,
            &digest,
        )
        .unwrap();
    let bound = borrowed.expectation_at(now).unwrap();
    assert_eq!(bound.issued_generation, None);
    assert!(
        aegis_client::protected_online_expectation::ProtectedOnlineExpectation::open_existing(
            &fixture.args.identity_dir,
            &digest,
        )
        .is_err()
    );
    drop(borrowed);
    drop(store);
    let held =
        aegis_client::protected_online_expectation::ProtectedOnlineExpectation::open_existing(
            &fixture.args.identity_dir,
            &digest,
        )
        .unwrap();
    assert_eq!(
        held.expectation_at(now).unwrap().certificate_sha256,
        bound.certificate_sha256
    );
    assert!(Store::open(&fixture.args.identity_dir, false).is_err());
}

#[test]
fn held_online_expectation_refuses_mutated_certificate_and_lock_generation() {
    let fixture = Fixture::new();
    prepare(&fixture.args).unwrap();
    complete(&CompleteArgs {
        identity_dir: fixture.args.identity_dir.clone(),
        certificate: fixture.certificate(),
        device_ca: fixture.args.device_ca.clone(),
    })
    .unwrap();
    let digest = "b".repeat(64);
    enrollment::write_private_new(
        &fixture.args.identity_dir.join("bundle-profile.sha256"),
        digest.as_bytes(),
    )
    .unwrap();
    let held =
        aegis_client::protected_online_expectation::ProtectedOnlineExpectation::open_existing(
            &fixture.args.identity_dir,
            &digest,
        )
        .unwrap();
    let now = registry::unix_now().unwrap();
    held.expectation_at(now).unwrap();
    let certificate = fixture.args.identity_dir.join("device.pem");
    fs::rename(&certificate, fixture.args.identity_dir.join("old.pem")).unwrap();
    enrollment::write_private_new(&certificate, b"invalid certificate").unwrap();
    assert!(held.expectation_at(now).is_err());
    fs::remove_file(&certificate).unwrap();
    fs::rename(fixture.args.identity_dir.join("old.pem"), &certificate).unwrap();
    held.expectation_at(now).unwrap();
    fs::rename(
        fixture.args.identity_dir.join(".lock"),
        fixture.args.identity_dir.join("old.lock"),
    )
    .unwrap();
    enrollment::write_private_new(&fixture.args.identity_dir.join(".lock"), b"").unwrap();
    assert!(held.expectation_at(now).is_err());
}

#[test]
fn held_online_expectation_refuses_pending_invitation_without_decoding_it() {
    let fixture = Fixture::new();
    prepare(&fixture.args).unwrap();
    complete(&CompleteArgs {
        identity_dir: fixture.args.identity_dir.clone(),
        certificate: fixture.certificate(),
        device_ca: fixture.args.device_ca.clone(),
    })
    .unwrap();
    let digest = "c".repeat(64);
    enrollment::write_private_new(
        &fixture.args.identity_dir.join("bundle-profile.sha256"),
        digest.as_bytes(),
    )
    .unwrap();
    let held =
        aegis_client::protected_online_expectation::ProtectedOnlineExpectation::open_existing(
            &fixture.args.identity_dir,
            &digest,
        )
        .unwrap();
    let now = registry::unix_now().unwrap();
    held.expectation_at(now).unwrap();
    let pending = fixture.args.identity_dir.join("online-request.json");
    enrollment::write_private_new(&pending, b"synthetic-invitation-\xff-not-json").unwrap();
    let error = held.expectation_at(now).unwrap_err().to_string();
    assert!(error.contains("finish the online identity transition"));
    assert!(!error.contains("synthetic-invitation"));
    fs::remove_file(pending).unwrap();
    held.expectation_at(now).unwrap();
}
