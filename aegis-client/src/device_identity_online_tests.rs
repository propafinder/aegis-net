use super::*;
use aegis_core::secure_channel::enrollment_wire::ReceiptState;
use rcgen::{CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::os::unix::fs::{symlink, PermissionsExt};

#[path = "device_identity_online_activation_tests.rs"]
mod activation_tests;

struct Fixture {
    _temp: tempfile::TempDir,
    args: PrepareArgs,
    ca: String,
    ca_key: String,
    token: PathBuf,
    now: u64,
}
const PIN: &str = "abababababababababababababababababababababababababababababababab";
impl Fixture {
    fn new() -> Self {
        #[cfg(target_os = "macos")]
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        #[cfg(not(target_os = "macos"))]
        let temp = tempfile::tempdir().unwrap();
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = params.self_signed(&key).unwrap().pem();
        let device_ca = temp.path().join("issuer.pem");
        enrollment::write_private_new(&device_ca, ca.as_bytes()).unwrap();
        let args = PrepareArgs {
            device_id: "device_a".into(),
            identity_dir: temp.path().join("identity"),
            device_ca,
        };
        prepare(&args).unwrap();
        enrollment::write_private_new(&args.identity_dir.join(PROFILE), PIN.as_bytes()).unwrap();
        let token = temp.path().join("invitation");
        enrollment::write_private_new(
            &token,
            b"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        )
        .unwrap();
        Self {
            _temp: temp,
            args,
            ca,
            ca_key: key.serialize_pem(),
            token,
            now: registry::unix_now().unwrap(),
        }
    }
    fn begin(&self, operation: Operation, now: u64) -> RequestMaterial {
        let pin = String::from_utf8(self.bytes(PROFILE)).unwrap();
        begin_online_request(
            &self.args.identity_dir,
            operation,
            &pin,
            if operation == Operation::Redeem {
                Some(&self.token)
            } else {
                None
            },
            now,
        )
        .unwrap()
    }
    fn receipt(&self, request: &RequestMaterial, now: u64) -> EnrollmentReceipt {
        self.receipt_with_lifetime(request, now, 90)
    }
    fn receipt_with_lifetime(
        &self,
        request: &RequestMaterial,
        now: u64,
        lifetime: u64,
    ) -> EnrollmentReceipt {
        let issued = enrollment::sign_csr(
            &self.args.device_id,
            &request.csr_pem,
            &self.ca,
            &self.ca_key,
            now,
            lifetime,
        )
        .unwrap();
        EnrollmentReceipt {
            version: 1,
            binding: request.binding.clone(),
            device_id: self.args.device_id.clone(),
            certificate_pem: issued.certificate_pem,
            certificate_sha256: issued.record.certificate_sha256,
            not_before_unix_secs: now,
            not_after_unix_secs: now + lifetime,
            issued_generation: if request.binding.operation == Operation::Redeem {
                3
            } else {
                4
            },
            snapshot_sha256: "ef".repeat(32),
            state: ReceiptState::IssuedPendingDistribution,
        }
    }
    fn ready(&self) -> EnrollmentReceipt {
        let request = self.begin(Operation::Redeem, self.now);
        let receipt = self.receipt(&request, self.now);
        accept_online_response(&self.args.identity_dir, &receipt, self.now).unwrap();
        receipt
    }
    fn bytes(&self, name: &str) -> Vec<u8> {
        fs::read(self.args.identity_dir.join(name)).unwrap()
    }

    fn public_bundle(&self) -> PathBuf {
        use crate::device_bundle::{self, BundleCreateArgs, BundleInspectArgs};
        let profile = self._temp.path().join("public-profile.json");
        fs::write(&profile, br#"{"schema":"aegis_device_bundle_v3","product_mode":"socks-only","relay_server":"relay.test:443","outer_server_name":"relay.test","inner_server_name":"inner.test","udp":false,"enrollment":{"protocol":"aegis-enrollment-v1","authority_server":"authority.test:443","outer_server_name":"authority.test","inner_server_name":"issuer.test","automatic_renewal":true,"renewal_policy":"same-key-v1"}}"#).unwrap();
        let bundle = self._temp.path().join("public-bundle");
        device_bundle::create(&BundleCreateArgs {
            bundle_dir: bundle.clone(),
            profile,
            outer_ca: self.args.device_ca.clone(),
            inner_ca: self.args.device_ca.clone(),
            device_ca: self.args.device_ca.clone(),
        })
        .unwrap();
        // This fixture starts with a synthetic constant pin for older tests.
        // New tests instead establish the real four-file pin through the CLI.
        fs::remove_file(self.args.identity_dir.join(PROFILE)).unwrap();
        device_bundle::inspect(&BundleInspectArgs {
            bundle_dir: bundle.clone(),
            identity_dir: Some(self.args.identity_dir.clone()),
            json: true,
        })
        .unwrap();
        bundle
    }

    fn snapshot(&self) -> std::collections::BTreeMap<String, Vec<u8>> {
        fs::read_dir(&self.args.identity_dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (
                    path.file_name().unwrap().to_str().unwrap().to_owned(),
                    fs::read(path).unwrap(),
                )
            })
            .collect()
    }
}

#[test]
fn local_recovery_repairs_valid_successor_cuts_before_legacy_ready_checks() {
    use std::os::unix::fs::MetadataExt;
    for cut in 0..=3 {
        let mut f = Fixture::new();
        // Legacy prepare/status use the wall clock. A predecessor ending at
        // the current integer second is still valid to WebPKI, so leave it
        // strictly in the past and give its successor ample real-time margin.
        f.now -= 120;
        let bundle = f.public_bundle();
        let key = f.bytes("device.key");
        let key_inode = fs::metadata(f.args.identity_dir.join("device.key"))
            .unwrap()
            .ino();
        let receipt = interrupted_with_lifetime(&f, cut, 3600);
        let recovery_now = registry::unix_now().unwrap();
        assert!(
            f.now + 90 < recovery_now,
            "predecessor must be strictly expired"
        );
        assert!(receipt.not_before_unix_secs <= recovery_now);
        assert!(recovery_now + 60 < receipt.not_after_unix_secs);
        if cut <= 1 {
            assert!(
                prepare(&f.args).is_err(),
                "legacy prepare must see the crash boundary"
            );
            assert!(status(&f.args.identity_dir).is_err());
        }
        let recovery = recover_local(
            &f.args.identity_dir,
            &bundle,
            &f.args.device_id,
            recovery_now,
        )
        .unwrap();
        assert_eq!(recovery.phase, "ready");
        assert!(recovery.repaired && !recovery.pending_request);
        assert_eq!(f.bytes("device.pem"), receipt.certificate_pem.as_bytes());
        assert_eq!(f.bytes("device.key"), key);
        assert_eq!(
            fs::metadata(f.args.identity_dir.join("device.key"))
                .unwrap()
                .ino(),
            key_inode
        );
        assert!(!f.args.identity_dir.join(REQUEST).exists());
        assert!(!f.args.identity_dir.join(RESPONSE).exists());
        assert_eq!(prepare(&f.args).unwrap().phase, "ready");
        assert_eq!(status(&f.args.identity_dir).unwrap().phase, "ready");
        let before = f.snapshot();
        let again = recover_local(
            &f.args.identity_dir,
            &bundle,
            &f.args.device_id,
            recovery_now + 1,
        )
        .unwrap();
        assert_eq!(again.phase, "ready");
        assert!(!again.repaired);
        assert_eq!(f.snapshot(), before);
    }
}

#[test]
fn local_recovery_rejects_wrong_expectations_before_any_identity_write() {
    for wrong in ["id", "bundle", "ca", "missing-pin", "v2", "key", "csr"] {
        let mut f = Fixture::new();
        f.now -= 90;
        let bundle = f.public_bundle();
        interrupted(&f, 1);
        match wrong {
            "bundle" => {
                let mut bytes = fs::read(bundle.join("bundle.json")).unwrap();
                bytes.push(b'\n');
                fs::write(bundle.join("bundle.json"), bytes).unwrap();
            }
            "ca" | "v2" => {
                if wrong == "ca" {
                    let other = Fixture::new();
                    fs::write(bundle.join("device-ca.pem"), other.ca).unwrap();
                } else {
                    let mut profile: serde_json::Value =
                        serde_json::from_slice(&fs::read(bundle.join("bundle.json")).unwrap())
                            .unwrap();
                    profile["schema"] = "aegis_device_bundle_v2".into();
                    profile.as_object_mut().unwrap().remove("enrollment");
                    fs::write(
                        bundle.join("bundle.json"),
                        serde_json::to_vec(&profile).unwrap(),
                    )
                    .unwrap();
                }
                // Even an independently repinned public profile must match
                // the identity's original CA and remain explicitly v3.
                fs::remove_file(f.args.identity_dir.join(PROFILE)).unwrap();
                crate::device_bundle::inspect(&crate::device_bundle::BundleInspectArgs {
                    bundle_dir: bundle.clone(),
                    identity_dir: Some(f.args.identity_dir.clone()),
                    json: true,
                })
                .unwrap();
            }
            "missing-pin" => fs::remove_file(f.args.identity_dir.join(PROFILE)).unwrap(),
            "key" => fs::write(
                f.args.identity_dir.join("device.key"),
                KeyPair::generate_for(&rcgen::PKCS_ED25519)
                    .unwrap()
                    .serialize_pem(),
            )
            .unwrap(),
            "csr" => fs::write(f.args.identity_dir.join("device.csr"), b"changed CSR").unwrap(),
            _ => {}
        }
        let before = f.snapshot();
        let id = if wrong == "id" {
            "wrong-device"
        } else {
            &f.args.device_id
        };
        assert!(
            recover_local(&f.args.identity_dir, &bundle, id, f.now + 95).is_err(),
            "{wrong}"
        );
        assert_eq!(f.snapshot(), before, "{wrong}");
    }
}

#[test]
fn local_recovery_expired_pending_request_only_requires_managed_runtime_without_writes() {
    let mut f = Fixture::new();
    f.now -= 90;
    let bundle = f.public_bundle();
    f.ready();
    f.begin(Operation::Renew, f.now + 60);
    let before = f.snapshot();
    let recovery =
        recover_local(&f.args.identity_dir, &bundle, &f.args.device_id, f.now + 95).unwrap();
    assert_eq!(recovery.phase, "runtime_recovery_required");
    assert!(!recovery.repaired && recovery.pending_request);
    assert_eq!(f.snapshot(), before);
    // The same pending material is recoverable after expiry without a new
    // request. Only the managed network caller may obtain its signed receipt.
    let material = begin_online_request(
        &f.args.identity_dir,
        Operation::Renew,
        &String::from_utf8(f.bytes(PROFILE)).unwrap(),
        None,
        f.now + 95,
    )
    .unwrap();
    assert!(material.resume);
    assert_eq!(f.snapshot(), before);
}

#[test]
fn local_recovery_expired_request_rejects_changed_bindings_without_writes() {
    for wrong in ["csr", "profile", "predecessor", "operation"] {
        let mut f = Fixture::new();
        f.now -= 90;
        let bundle = f.public_bundle();
        f.ready();
        f.begin(Operation::Renew, f.now + 60);
        let mut pending: Pending = serde_json::from_slice(&f.bytes(REQUEST)).unwrap();
        match wrong {
            "csr" => pending.binding.csr_sha256 = "12".repeat(32),
            "profile" => pending.binding.profile_sha256 = "34".repeat(32),
            "predecessor" => pending.binding.predecessor_sha256 = Some("56".repeat(32)),
            "operation" => pending.binding.operation = Operation::Redeem,
            _ => unreachable!(),
        }
        fs::write(
            f.args.identity_dir.join(REQUEST),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();
        let before = f.snapshot();
        assert!(
            recover_local(&f.args.identity_dir, &bundle, &f.args.device_id, f.now + 95).is_err(),
            "{wrong}"
        );
        assert_eq!(f.snapshot(), before, "{wrong}");
    }
}

#[test]
fn local_recovery_expired_without_valid_successor_refuses_without_writes() {
    for saved_response in [false, true] {
        let mut f = Fixture::new();
        f.now -= 180;
        let bundle = f.public_bundle();
        if saved_response {
            interrupted(&f, 0);
        } else {
            f.ready();
        }
        let before = f.snapshot();
        assert!(recover_local(
            &f.args.identity_dir,
            &bundle,
            &f.args.device_id,
            f.now + 181
        )
        .is_err());
        assert_eq!(f.snapshot(), before);
    }
}

#[test]
fn local_recovery_prepared_and_missing_identity_never_create_state_or_requests() {
    let f = Fixture::new();
    let bundle = f.public_bundle();
    let before = f.snapshot();
    let result = recover_local(&f.args.identity_dir, &bundle, &f.args.device_id, f.now).unwrap();
    assert_eq!(result.phase, "prepared");
    assert!(!result.repaired && !result.pending_request);
    assert_eq!(f.snapshot(), before);
    f.begin(Operation::Redeem, f.now);
    let before = f.snapshot();
    let result = recover_local(&f.args.identity_dir, &bundle, &f.args.device_id, f.now).unwrap();
    assert_eq!(result.phase, "prepared");
    assert!(!result.repaired && result.pending_request);
    assert_eq!(f.snapshot(), before);
    {
        let _held = Store::open(&f.args.identity_dir, false).unwrap();
        assert!(recover_local(&f.args.identity_dir, &bundle, &f.args.device_id, f.now).is_err());
        assert_eq!(f.snapshot(), before);
    }
    let missing = f._temp.path().join("missing-identity");
    assert!(recover_local(&missing, &bundle, &f.args.device_id, f.now).is_err());
    assert!(!missing.exists());
}

#[test]
fn initial_pending_reuses_key_request_and_secret_without_secret_status_or_output() {
    let f = Fixture::new();
    let key = f.bytes("device.key");
    let first = f.begin(Operation::Redeem, f.now);
    assert!(!first.resume);
    let pending = f.bytes(REQUEST);
    let second = begin_online_request(
        &f.args.identity_dir,
        Operation::Redeem,
        PIN,
        None,
        f.now + 2,
    )
    .unwrap();
    assert!(second.resume);
    assert_eq!(first.binding, second.binding);
    assert_eq!(first.csr_pem, second.csr_pem);
    assert_eq!(
        first.invitation.as_deref().map(|s| s.as_str()),
        second.invitation.as_deref().map(|s| s.as_str())
    );
    assert_eq!(f.bytes("device.key"), key);
    assert_eq!(f.bytes(REQUEST), pending);
    let status =
        serde_json::to_string(&online_status(&f.args.identity_dir, f.now).unwrap()).unwrap();
    assert!(
        !status.contains("PRIVATE")
            && !status.contains("cdcd")
            && !status.contains(&first.binding.request_id)
    );
    assert_eq!(
        fs::metadata(f.args.identity_dir.join(REQUEST))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(f.token.exists(), "operator input is not silently deleted");
    let receipt = f.receipt(&first, f.now);
    let completion = accept_online_response(&f.args.identity_dir, &receipt, f.now).unwrap();
    assert!(completion.certificate_valid_now);
    assert_eq!(completion.state, "issued_pending_distribution");
    assert!(!f.args.identity_dir.join(REQUEST).exists());
    assert!(!f.args.identity_dir.join(RESPONSE).exists());
    assert!(!String::from_utf8_lossy(&f.bytes(COMPLETED)).contains("cdcdcd"));
    accept_online_response(&f.args.identity_dir, &receipt, f.now + 1).unwrap();
    assert_eq!(f.bytes("device.key"), key);
}

#[test]
fn pending_profile_invitation_and_proof_bindings_cannot_be_changed() {
    let f = Fixture::new();
    let request = f.begin(Operation::Redeem, f.now);
    let before = f.bytes(REQUEST);
    let alternate = f._temp.path().join("other-token");
    enrollment::write_private_new(&alternate, "aa".repeat(32).as_bytes()).unwrap();
    assert!(begin_online_request(
        &f.args.identity_dir,
        Operation::Redeem,
        PIN,
        Some(&alternate),
        f.now
    )
    .is_err());
    assert!(begin_online_request(
        &f.args.identity_dir,
        Operation::Redeem,
        &"ff".repeat(32),
        None,
        f.now
    )
    .is_err());
    let mut altered = request.binding.clone();
    altered.request_id = "11".repeat(32);
    let mut challenge = protocol::ConnectionChallenge::new(f.now).unwrap();
    assert!(sign_online_request(
        &f.args.identity_dir,
        &altered,
        &challenge.message(),
        ProofPurpose::Authorize,
        f.now
    )
    .is_err());
    let signature = sign_online_request(
        &f.args.identity_dir,
        &request.binding,
        &challenge.message(),
        ProofPurpose::Authorize,
        f.now,
    )
    .unwrap();
    challenge
        .verify(
            &request.binding,
            ProofPurpose::Authorize,
            &protocol::csr_public_key(&request.csr_pem).unwrap(),
            &signature,
            f.now,
        )
        .unwrap();
    assert_eq!(f.bytes(REQUEST), before);
    fs::write(f.args.identity_dir.join(PROFILE), "11".repeat(32)).unwrap();
    assert!(sign_online_request(
        &f.args.identity_dir,
        &request.binding,
        &challenge.message(),
        ProofPurpose::Receipt,
        f.now
    )
    .is_err());
}

#[test]
fn renewal_is_due_only_same_key_and_pending_expiry_allows_only_receipt_proof() {
    let f = Fixture::new();
    let first = f.ready();
    let key = f.bytes("device.key");
    assert!(
        !online_status(&f.args.identity_dir, f.now + 59)
            .unwrap()
            .renewal_due
    );
    assert!(begin_online_request(
        &f.args.identity_dir,
        Operation::Renew,
        PIN,
        None,
        f.now + 59
    )
    .is_err());
    assert!(
        online_status(&f.args.identity_dir, f.now + 60)
            .unwrap()
            .renewal_due
    );
    let pending = f.begin(Operation::Renew, f.now + 60);
    assert_eq!(
        pending.binding.predecessor_sha256.as_deref(),
        Some(first.certificate_sha256.as_str())
    );
    let again = f.begin(Operation::Renew, f.now + 95);
    assert_eq!(pending.binding, again.binding);
    assert!(again.resume);
    let expired = online_status(&f.args.identity_dir, f.now + 95).unwrap();
    assert_eq!(expired.state, "expired");
    assert!(expired.pending);
    assert!(!expired.renewal_due);
    let challenge = protocol::ConnectionChallenge::new(f.now + 95).unwrap();
    assert!(sign_online_request(
        &f.args.identity_dir,
        &pending.binding,
        &challenge.message(),
        ProofPurpose::Authorize,
        f.now + 95
    )
    .is_err());
    sign_online_request(
        &f.args.identity_dir,
        &pending.binding,
        &challenge.message(),
        ProofPurpose::Receipt,
        f.now + 95,
    )
    .unwrap();
    let receipt = f.receipt(&pending, f.now + 60);
    let result = accept_online_response(&f.args.identity_dir, &receipt, f.now + 95).unwrap();
    assert!(result.certificate_valid_now);
    assert_eq!(f.bytes("device.key"), key);
    assert_eq!(f.bytes("device.pem"), receipt.certificate_pem.as_bytes());
}

#[test]
fn invalid_response_cannot_replace_key_certificate_or_pending_request() {
    let f = Fixture::new();
    let first = f.ready();
    let pending = f.begin(Operation::Renew, f.now + 60);
    let key = f.bytes("device.key");
    let old = f.bytes("device.pem");
    let request = f.bytes(REQUEST);
    let mut receipt = f.receipt(&pending, f.now + 60);
    receipt.binding.request_id = "55".repeat(32);
    assert!(accept_online_response(&f.args.identity_dir, &receipt, f.now + 60).is_err());
    let mut receipt = f.receipt(&pending, f.now + 60);
    receipt.certificate_pem = first.certificate_pem;
    receipt.certificate_sha256 = first.certificate_sha256;
    receipt.not_before_unix_secs = f.now;
    receipt.not_after_unix_secs = f.now + 90;
    assert!(accept_online_response(&f.args.identity_dir, &receipt, f.now + 60).is_err());
    let mut receipt = f.receipt(&pending, f.now + 60);
    let alternate = enrollment::generate_csr("device_a").unwrap();
    let issued = enrollment::sign_csr(
        "device_a",
        &alternate.csr_pem,
        &f.ca,
        &f.ca_key,
        f.now + 60,
        90,
    )
    .unwrap();
    receipt.certificate_pem = issued.certificate_pem;
    receipt.certificate_sha256 = issued.record.certificate_sha256;
    assert!(accept_online_response(&f.args.identity_dir, &receipt, f.now + 60).is_err());
    assert_eq!(f.bytes("device.key"), key);
    assert_eq!(f.bytes("device.pem"), old);
    assert_eq!(f.bytes(REQUEST), request);
    assert!(!f.args.identity_dir.join(RESPONSE).exists());
}

fn interrupted(f: &Fixture, cut: u8) -> EnrollmentReceipt {
    interrupted_with_lifetime(f, cut, 90)
}
fn interrupted_with_lifetime(f: &Fixture, cut: u8, lifetime: u64) -> EnrollmentReceipt {
    f.ready();
    let request = f.begin(Operation::Renew, f.now + 60);
    let receipt = f.receipt_with_lifetime(&request, f.now + 60, lifetime);
    let old_record = f.bytes("identity.json");
    let old_certificate = f.bytes("device.pem");
    let pending_bytes = f.bytes(REQUEST);
    // Actual acceptance first proves these exact bytes pass every response
    // check. Then synthetic files reconstruct each durable crash boundary.
    accept_online_response(&f.args.identity_dir, &receipt, f.now + 60).unwrap();
    let saved: SavedResponse = serde_json::from_slice(&f.bytes(COMPLETED)).unwrap();
    if cut < 2 {
        fs::write(f.args.identity_dir.join("identity.json"), old_record).unwrap();
    }
    if cut == 0 {
        fs::write(f.args.identity_dir.join("device.pem"), old_certificate).unwrap();
    }
    if cut < 3 {
        enrollment::write_private_new(&f.args.identity_dir.join(REQUEST), &pending_bytes).unwrap();
    }
    let store = Store::open(&f.args.identity_dir, false).unwrap();
    save_large(&store, RESPONSE, &saved, false).unwrap();
    receipt
}
#[test]
fn response_before_certificate_record_and_request_unlink_cuts_resume_without_new_key() {
    for cut in 0..=3 {
        let f = Fixture::new();
        let key = f.bytes("device.key");
        let receipt = interrupted(&f, cut);
        let result = resume_online_response(&f.args.identity_dir, f.now + 65)
            .unwrap()
            .unwrap();
        assert!(result.certificate_valid_now);
        assert_eq!(
            f.bytes("device.pem"),
            receipt.certificate_pem.as_bytes(),
            "cut {cut}"
        );
        assert_eq!(f.bytes("device.key"), key);
        assert!(!f.args.identity_dir.join(REQUEST).exists());
        assert!(!f.args.identity_dir.join(RESPONSE).exists());
        assert!(resume_online_response(&f.args.identity_dir, f.now + 65)
            .unwrap()
            .is_none());
        assert_eq!(
            online_status(&f.args.identity_dir, f.now + 65)
                .unwrap()
                .state,
            "ready"
        );
    }
}
#[test]
fn expired_saved_response_finishes_state_but_cannot_claim_current_authorization() {
    let f = Fixture::new();
    interrupted(&f, 1);
    let result = resume_online_response(&f.args.identity_dir, f.now + 151)
        .unwrap()
        .unwrap();
    assert!(!result.certificate_valid_now);
    assert_eq!(
        online_status(&f.args.identity_dir, f.now + 151)
            .unwrap()
            .state,
        "expired"
    );
    assert!(begin_online_request(
        &f.args.identity_dir,
        Operation::Renew,
        PIN,
        None,
        f.now + 151
    )
    .is_err());
}
#[test]
fn offline_complete_refuses_an_online_transition_and_remains_no_overwrite() {
    let f = Fixture::new();
    let request = f.begin(Operation::Redeem, f.now);
    let receipt = f.receipt(&request, f.now);
    let cert = f._temp.path().join("certificate.pem");
    enrollment::write_private_new(&cert, receipt.certificate_pem.as_bytes()).unwrap();
    let args = CompleteArgs {
        identity_dir: f.args.identity_dir.clone(),
        certificate: cert,
        device_ca: f.args.device_ca.clone(),
    };
    assert!(complete(&args).is_err());
    assert!(!f.args.identity_dir.join("device.pem").exists());
    accept_online_response(&f.args.identity_dir, &receipt, f.now).unwrap();
    complete(&args).unwrap();
    let different = f.receipt(&request, f.now);
    fs::write(&args.certificate, different.certificate_pem).unwrap();
    assert!(complete(&args).is_err());
}
#[test]
fn exact_profile_migration_journal_recovers_each_cut_and_preserves_credentials() {
    for cut in 0..=1 {
        let f = Fixture::new();
        f.ready();
        let key = f.bytes("device.key");
        let cert = f.bytes("device.pem");
        let new = "11".repeat(32);
        let store = Store::open(&f.args.identity_dir, false).unwrap();
        save_large(
            &store,
            MIGRATION,
            &Migration {
                version: 1,
                old_sha256: PIN.into(),
                new_sha256: new.clone(),
            },
            false,
        )
        .unwrap();
        if cut == 1 {
            store.save(PROFILE, new.as_bytes(), true).unwrap();
        }
        drop(store);
        assert!(migrate_profile(&f.args.identity_dir, PIN, &"22".repeat(32)).is_err());
        migrate_profile(&f.args.identity_dir, PIN, &new).unwrap();
        migrate_profile(&f.args.identity_dir, PIN, &new).unwrap();
        assert_eq!(f.bytes(PROFILE), new.as_bytes());
        assert_eq!(f.bytes("device.key"), key);
        assert_eq!(f.bytes("device.pem"), cert);
    }
    let f = Fixture::new();
    f.begin(Operation::Redeem, f.now);
    assert!(migrate_profile(&f.args.identity_dir, PIN, &"11".repeat(32)).is_err());
}
#[test]
fn pending_secret_paths_links_and_bounds_are_enforced() {
    let f = Fixture::new();
    let alias = f._temp.path().join("alias");
    symlink(&f.token, &alias).unwrap();
    assert!(begin_online_request(
        &f.args.identity_dir,
        Operation::Redeem,
        PIN,
        Some(&alias),
        f.now
    )
    .is_err());
    let hard = f._temp.path().join("hard");
    fs::hard_link(&f.token, &hard).unwrap();
    assert!(begin_online_request(
        &f.args.identity_dir,
        Operation::Redeem,
        PIN,
        Some(&hard),
        f.now
    )
    .is_err());
    fs::remove_file(hard).unwrap();
    f.begin(Operation::Redeem, f.now);
    let path = f.args.identity_dir.join(REQUEST);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(online_status(&f.args.identity_dir, f.now).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let file = OpenOptions::new().write(true).open(path).unwrap();
    file.set_len(MAX_ONLINE + 1).unwrap();
    assert!(online_status(&f.args.identity_dir, f.now).is_err());
}

#[test]
fn live_ack_expectation_uses_only_current_certificate_and_matching_receipt() {
    let f = Fixture::new();
    let receipt = f.ready();
    let expectation = online_expectation(&f.args.identity_dir, PIN, f.now).unwrap();
    assert_eq!(expectation.certificate_sha256, receipt.certificate_sha256);
    assert_eq!(expectation.not_after_unix_secs, receipt.not_after_unix_secs);
    assert_eq!(
        expectation.issued_generation,
        Some(receipt.issued_generation)
    );
    assert_eq!(expectation.snapshot_sha256, Some(receipt.snapshot_sha256));
    assert!(online_expectation(&f.args.identity_dir, &"11".repeat(32), f.now).is_err());
    assert!(online_expectation(&f.args.identity_dir, PIN, f.now + 90).is_err());
    f.begin(Operation::Renew, f.now + 60);
    assert!(online_expectation(&f.args.identity_dir, PIN, f.now + 60).is_err());
    let store = Store::open(&f.args.identity_dir, false).unwrap();
    remove(&store, REQUEST).unwrap();
    let mut saved: SavedResponse = optional(&store, COMPLETED).unwrap().unwrap();
    saved.receipt.certificate_sha256 = "44".repeat(32);
    save_large(&store, COMPLETED, &saved, true).unwrap();
    drop(store);
    assert!(online_expectation(&f.args.identity_dir, PIN, f.now).is_err());
}

#[test]
fn verified_offline_identity_has_no_invented_issuance_generation() {
    let f = Fixture::new();
    let csr = std::str::from_utf8(&f.bytes("device.csr"))
        .unwrap()
        .to_owned();
    let issued =
        enrollment::sign_csr(&f.args.device_id, &csr, &f.ca, &f.ca_key, f.now, 90).unwrap();
    let certificate = f._temp.path().join("offline.pem");
    enrollment::write_private_new(&certificate, issued.certificate_pem.as_bytes()).unwrap();
    complete(&CompleteArgs {
        identity_dir: f.args.identity_dir.clone(),
        certificate,
        device_ca: f.args.device_ca.clone(),
    })
    .unwrap();
    let before = f.bytes("identity.json");
    let key = f.bytes("device.key");
    let expectation = online_expectation(&f.args.identity_dir, PIN, f.now).unwrap();
    assert_eq!(
        expectation.certificate_sha256,
        issued.record.certificate_sha256
    );
    assert!(expectation.issued_generation.is_none());
    assert!(expectation.snapshot_sha256.is_none());
    assert_eq!(f.bytes("identity.json"), before);
    assert_eq!(f.bytes("device.key"), key);
    assert!(!f.args.identity_dir.join(COMPLETED).exists());
}

#[test]
fn conflicting_local_journals_are_rejected_before_any_certificate_or_record_write() {
    let f = Fixture::new();
    interrupted(&f, 0);
    let certificate = f.bytes("device.pem");
    let record = f.bytes("identity.json");
    let key = f.bytes("device.key");
    let store = Store::open(&f.args.identity_dir, false).unwrap();
    let mut pending: Pending = optional(&store, REQUEST).unwrap().unwrap();
    pending.binding.request_id = "88".repeat(32);
    save_large(&store, REQUEST, &pending, true).unwrap();
    drop(store);
    assert!(resume_online_response(&f.args.identity_dir, f.now + 65).is_err());
    assert_eq!(f.bytes("device.pem"), certificate);
    assert_eq!(f.bytes("identity.json"), record);
    assert_eq!(f.bytes("device.key"), key);
    assert!(f.args.identity_dir.join(REQUEST).exists());
    assert!(f.args.identity_dir.join(RESPONSE).exists());
}

// Snapshot bytes and persistent file identity; ordinary reads may update atime.
fn bundle_ready_snapshot(
    f: &Fixture,
    bundle: &Path,
) -> std::collections::BTreeMap<String, (Vec<u8>, [i128; 8])> {
    use std::os::unix::fs::MetadataExt;
    let identity = f.snapshot();
    let mut result = std::collections::BTreeMap::new();
    for (scope, root) in [
        ("identity", f.args.identity_dir.as_path()),
        ("bundle", bundle),
    ] {
        let mut paths = vec![root.to_owned()];
        paths.extend(
            fs::read_dir(root)
                .unwrap()
                .map(|entry| entry.unwrap().path()),
        );
        for path in paths {
            let metadata = fs::symlink_metadata(&path).unwrap();
            let name = if path == root {
                String::new()
            } else {
                path.file_name().unwrap().to_str().unwrap().to_owned()
            };
            let bytes = if metadata.is_dir() {
                Vec::new()
            } else if scope == "identity" {
                identity[&name].clone()
            } else {
                fs::read(&path).unwrap()
            };
            result.insert(
                format!("{scope}/{name}"),
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
    }
    result
}

#[test]
fn bundle_ready_prepared_refused_without_writes() {
    let f = Fixture::new();
    let bundle = f.public_bundle();
    let args = crate::device_bundle::BundleReadyArgs {
        bundle_dir: bundle.clone(),
        identity_dir: f.args.identity_dir.clone(),
        device_id: f.args.device_id.clone(),
    };
    let before = bundle_ready_snapshot(&f, &bundle);
    assert!(!f.args.identity_dir.join("device.pem").exists());
    let error = crate::device_bundle::ready_metadata(&args, f.now)
        .err()
        .unwrap();
    assert!(error.to_string().contains("completed identity"));
    assert!(
        bundle_ready_snapshot(&f, &bundle) == before,
        "prepared inspection wrote state"
    );
}

#[test]
fn bundle_ready_public_facts_without_secrets_or_writes() {
    let f = Fixture::new();
    let bundle = f.public_bundle();
    let receipt = f.ready();
    let args = crate::device_bundle::BundleReadyArgs {
        bundle_dir: bundle.clone(),
        identity_dir: f.args.identity_dir.clone(),
        device_id: f.args.device_id.clone(),
    };
    let before = bundle_ready_snapshot(&f, &bundle);
    let facts = crate::device_bundle::ready_metadata(&args, f.now).unwrap();
    let actual = serde_json::to_value(&facts).unwrap();
    assert_eq!(
        actual,
        serde_json::json!({
            "schema": "aegis_device_bundle_ready_v1",
            "device_id": f.args.device_id,
            "profile_sha256": String::from_utf8(f.bytes(PROFILE)).unwrap(),
            "device_ca_sha256": sha(f.ca.as_bytes()),
            "certificate_sha256": receipt.certificate_sha256,
            "not_before_unix_secs": f.now,
            "not_after_unix_secs": f.now + 90,
            "checked_at_unix_secs": f.now,
            "local_only": true,
        })
    );
    let encoded = serde_json::to_string(&facts).unwrap();
    assert!(!encoded.contains("PRIVATE KEY") && !encoded.contains("CERTIFICATE"));
    assert!(!encoded.contains(std::str::from_utf8(&f.bytes("device.key")).unwrap()));
    assert!(!encoded.contains(std::str::from_utf8(&fs::read(&f.token).unwrap()).unwrap()));
    assert!(!encoded.contains(&receipt.binding.request_id));
    assert!(
        bundle_ready_snapshot(&f, &bundle) == before,
        "ready inspection wrote state"
    );
}

#[test]
fn bundle_ready_wrong_identity_ca_or_profile_refused_without_writes() {
    for wrong in ["id", "ca", "profile", "missing-pin"] {
        let f = Fixture::new();
        let bundle = f.public_bundle();
        f.ready();
        let mut args = crate::device_bundle::BundleReadyArgs {
            bundle_dir: bundle.clone(),
            identity_dir: f.args.identity_dir.clone(),
            device_id: f.args.device_id.clone(),
        };
        match wrong {
            "id" => args.device_id = "device_b".into(),
            "ca" => {
                let other = Fixture::new();
                fs::write(bundle.join("device-ca.pem"), other.ca.as_bytes()).unwrap();
                // Isolate CA binding from the independently checked profile pin.
                fs::remove_file(f.args.identity_dir.join(PROFILE)).unwrap();
                crate::device_bundle::inspect(&crate::device_bundle::BundleInspectArgs {
                    bundle_dir: bundle.clone(),
                    identity_dir: Some(f.args.identity_dir.clone()),
                    json: true,
                })
                .unwrap();
            }
            "profile" => {
                let mut bytes = fs::read(bundle.join("bundle.json")).unwrap();
                bytes.push(b'\n');
                fs::write(bundle.join("bundle.json"), bytes).unwrap();
            }
            "missing-pin" => fs::remove_file(f.args.identity_dir.join(PROFILE)).unwrap(),
            _ => unreachable!(),
        }
        let before = bundle_ready_snapshot(&f, &bundle);
        let error = crate::device_bundle::ready_metadata(&args, f.now)
            .err()
            .unwrap();
        if wrong == "ca" {
            assert!(error.to_string().contains("issuer CA differs"));
        }
        assert!(
            bundle_ready_snapshot(&f, &bundle) == before,
            "{wrong}: inspection wrote state"
        );
    }
}

#[test]
fn bundle_ready_lifetime_and_renewal_boundaries() {
    let f = Fixture::new();
    let bundle = f.public_bundle();
    f.ready();
    let args = crate::device_bundle::BundleReadyArgs {
        bundle_dir: bundle.clone(),
        identity_dir: f.args.identity_dir.clone(),
        device_id: f.args.device_id.clone(),
    };
    let before = bundle_ready_snapshot(&f, &bundle);
    let before_due = crate::device_bundle::ready_metadata(&args, f.now + 59).unwrap();
    assert_eq!(before_due.checked_at_unix_secs, f.now + 59);
    for (label, now) in [
        ("not-yet-valid", f.now - 1),
        ("due", f.now + 60),
        ("expired", f.now + 90),
    ] {
        let error = crate::device_bundle::ready_metadata(&args, now)
            .err()
            .unwrap();
        if label == "due" {
            assert!(error.to_string().contains("renewal is due"));
        }
        assert!(
            bundle_ready_snapshot(&f, &bundle) == before,
            "{label}: inspection wrote state"
        );
    }
}

#[test]
fn bundle_ready_pending_transitions_refused_without_recovery() {
    for transition in ["request", "response", "migration"] {
        let f = Fixture::new();
        let bundle = f.public_bundle();
        let now = match transition {
            "request" => {
                f.ready();
                f.begin(Operation::Renew, f.now + 60);
                assert!(f.args.identity_dir.join(REQUEST).exists());
                assert!(!f.args.identity_dir.join(RESPONSE).exists());
                f.now + 65
            }
            "response" => {
                interrupted(&f, 3);
                assert!(!f.args.identity_dir.join(REQUEST).exists());
                assert!(f.args.identity_dir.join(RESPONSE).exists());
                f.now + 65
            }
            "migration" => {
                f.ready();
                let store = Store::open(&f.args.identity_dir, false).unwrap();
                save_large(
                    &store,
                    MIGRATION,
                    &Migration {
                        version: 1,
                        old_sha256: String::from_utf8(f.bytes(PROFILE)).unwrap(),
                        new_sha256: "11".repeat(32),
                    },
                    false,
                )
                .unwrap();
                drop(store);
                f.now
            }
            _ => unreachable!(),
        };
        let args = crate::device_bundle::BundleReadyArgs {
            bundle_dir: bundle.clone(),
            identity_dir: f.args.identity_dir.clone(),
            device_id: f.args.device_id.clone(),
        };
        let before = bundle_ready_snapshot(&f, &bundle);
        let error = crate::device_bundle::ready_metadata(&args, now)
            .err()
            .unwrap();
        // Require the transition refusal, not a secondary due/expiry refusal.
        let reason = if transition == "migration" {
            "migration requires exact recovery"
        } else {
            "finish the online identity transition"
        };
        assert!(
            error.to_string().contains(reason),
            "{transition}: wrong refusal boundary"
        );
        assert!(
            bundle_ready_snapshot(&f, &bundle) == before,
            "{transition}: inspection recovered state"
        );
    }
}

#[test]
fn bundle_ready_tampered_certificate_or_matching_key_csr_refused_without_writes() {
    for changed in ["certificate", "key-and-csr"] {
        let f = Fixture::new();
        let bundle = f.public_bundle();
        f.ready();
        if changed == "certificate" {
            // Valid current same-ID/key/CA certificate, but a different record fingerprint.
            let replacement = enrollment::sign_csr(
                &f.args.device_id,
                std::str::from_utf8(&f.bytes("device.csr")).unwrap(),
                &f.ca,
                &f.ca_key,
                f.now,
                120,
            )
            .unwrap();
            fs::write(
                f.args.identity_dir.join("device.pem"),
                replacement.certificate_pem,
            )
            .unwrap();
        } else {
            // Keep CSR and replacement key consistent, so the certificate/key check is reached.
            let replacement = enrollment::generate_csr(&f.args.device_id).unwrap();
            fs::write(
                f.args.identity_dir.join("device.key"),
                replacement.private_key_pem,
            )
            .unwrap();
            fs::write(f.args.identity_dir.join("device.csr"), replacement.csr_pem).unwrap();
        }
        let args = crate::device_bundle::BundleReadyArgs {
            bundle_dir: bundle.clone(),
            identity_dir: f.args.identity_dir.clone(),
            device_id: f.args.device_id.clone(),
        };
        let before = bundle_ready_snapshot(&f, &bundle);
        assert!(
            crate::device_bundle::ready_metadata(&args, f.now).is_err(),
            "{changed}"
        );
        assert!(
            bundle_ready_snapshot(&f, &bundle) == before,
            "{changed}: inspection wrote state"
        );
    }
}

#[cfg(unix)]
fn refresh_recovery_paths(f: &Fixture) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let recovery = tempfile::tempdir_in(f._temp.path().parent().unwrap()).unwrap();
    fs::set_permissions(recovery.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let output = recovery.path().join("old-request-r1.json");
    let new_token = recovery.path().join("next-invitation");
    enrollment::write_private_new(&new_token, &[b'e'; 64]).unwrap();
    (recovery, output, new_token)
}

#[cfg(unix)]
#[test]
fn refresh_redeem_replaces_only_invitation_and_resumes_exact_crash_cuts() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new();
    let original = f.begin(Operation::Redeem, f.now);
    let key = f.bytes("device.key");
    let csr = f.bytes("device.csr");
    let key_inode = fs::metadata(f.args.identity_dir.join("device.key"))
        .unwrap()
        .ino();
    let old_request = f.bytes(REQUEST);
    let (_recovery, journal, new_token) = refresh_recovery_paths(&f);
    let snapshot = prepare_refresh(&f.args.identity_dir, PIN).unwrap();
    assert_eq!(snapshot.material.binding, original.binding);
    let replacement =
        replace_refresh_invitation(&f.args.identity_dir, PIN, &snapshot, &new_token, &journal)
            .unwrap();
    assert_eq!(replacement.binding, original.binding);
    assert!(!replacement.resume);
    assert_eq!(f.bytes("device.key"), key);
    assert_eq!(f.bytes("device.csr"), csr);
    assert_eq!(
        fs::metadata(f.args.identity_dir.join("device.key"))
            .unwrap()
            .ino(),
        key_inode
    );
    assert_ne!(f.bytes(REQUEST), old_request);
    assert_eq!(fs::metadata(&journal).unwrap().mode() & 0o777, 0o600);
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
    assert_eq!(
        hex::decode(saved["old_pending_hex"].as_str().unwrap()).unwrap(),
        old_request
    );
    assert!(
        begin_online_request(
            &f.args.identity_dir,
            Operation::Redeem,
            PIN,
            Some(&f.token),
            f.now
        )
        .is_err(),
        "default path must not accept old invitation"
    );
    let after_first = f.snapshot();
    // Reconstruct the durable cut after journal publication but before the
    // atomic Store replacement. The exact archive must complete it.
    let store = Store::open(&f.args.identity_dir, false).unwrap();
    store.save(REQUEST, &old_request, true).unwrap();
    drop(store);
    let old_snapshot = prepare_refresh(&f.args.identity_dir, PIN).unwrap();
    replace_refresh_invitation(
        &f.args.identity_dir,
        PIN,
        &old_snapshot,
        &new_token,
        &journal,
    )
    .unwrap();
    assert_eq!(f.snapshot(), after_first);
    // A rerun after the Store replacement is idempotent too.
    let next_snapshot = prepare_refresh(&f.args.identity_dir, PIN).unwrap();
    let resumed = replace_refresh_invitation(
        &f.args.identity_dir,
        PIN,
        &next_snapshot,
        &new_token,
        &journal,
    )
    .unwrap();
    assert_eq!(resumed.binding, original.binding);
    assert_eq!(
        f.snapshot(),
        after_first,
        "resume must not rewrite current identity"
    );
}

#[cfg(unix)]
#[test]
fn refresh_redeem_preflight_refuses_changed_key_profile_alias_and_lock() {
    let f = Fixture::new();
    f.begin(Operation::Redeem, f.now);
    let (_recovery, journal, new_token) = refresh_recovery_paths(&f);
    let snapshot = prepare_refresh(&f.args.identity_dir, PIN).unwrap();
    let before = f.snapshot();
    assert!(prepare_refresh(&f.args.identity_dir, &"ff".repeat(32)).is_err());
    let alias = f._temp.path().join("recovery-alias");
    symlink(journal.parent().unwrap(), &alias).unwrap();
    assert!(replace_refresh_invitation(
        &f.args.identity_dir,
        PIN,
        &snapshot,
        &new_token,
        &alias.join("old-request.json")
    )
    .is_err());
    let token_alias = f._temp.path().join("token-alias");
    symlink(&new_token, &token_alias).unwrap();
    assert!(replace_refresh_invitation(
        &f.args.identity_dir,
        PIN,
        &snapshot,
        &token_alias,
        &journal
    )
    .is_err());
    let wrong_root_token = f._temp.path().join("wrong-root-token");
    enrollment::write_private_new(&wrong_root_token, &[b'f'; 64]).unwrap();
    assert!(replace_refresh_invitation(
        &f.args.identity_dir,
        PIN,
        &snapshot,
        &wrong_root_token,
        &journal
    )
    .is_err());
    assert_eq!(f.snapshot(), before);
    assert!(!journal.exists());
    let old_key = f.bytes("device.key");
    let replacement_key = enrollment::generate_csr("device_a")
        .unwrap()
        .private_key_pem;
    fs::write(f.args.identity_dir.join("device.key"), replacement_key).unwrap();
    assert!(
        replace_refresh_invitation(&f.args.identity_dir, PIN, &snapshot, &new_token, &journal)
            .is_err()
    );
    fs::write(f.args.identity_dir.join("device.key"), old_key).unwrap();
    assert!(!journal.exists());
    let held = Store::open(&f.args.identity_dir, false).unwrap();
    assert!(prepare_refresh(&f.args.identity_dir, PIN).is_err());
    drop(held);
}
