use super::*;
use aegis_core::secure_channel::enrollment::protocol::{sign_proof, RequestBinding};
use rcgen::{CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

#[path = "enrollment_cancellation_tests.rs"]
mod cancellation;

#[path = "enrollment_cancellation_protocol_tests.rs"]
mod cancellation_protocol;

struct Fixture {
    _dir: tempfile::TempDir,
    issuer: Issuer,
    key: enrollment::DeviceCsr,
    token: String,
    now: u64,
}
impl Fixture {
    fn new() -> Self {
        Self::with_policy_start_offset(0)
    }
    // Simulate an initialization crossing a Unix-second boundary without a
    // real sleep or a weaker production policy check.
    fn with_policy_start_offset(offset: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let setup_now = registry::unix_now().unwrap();
        let registry_path = dir.path().join("registry.json");
        crate::devices::initialize(&registry_path).unwrap();
        if offset != 0 {
            let tx = RegistryTransaction::begin(&registry_path).unwrap();
            let mut policy = tx.load().unwrap();
            policy
                .refresh_validity(setup_now + offset, registry::DEFAULT_POLICY_TTL_SECS)
                .unwrap();
            tx.save(&registry_path, &policy, false).unwrap();
        }
        // Issuance uses an injected, fixed epoch. Bind it to the actual policy
        // produced by initialization, rather than an earlier wall-clock sample.
        let now = DeviceRegistry::load(&registry_path)
            .unwrap()
            .validity
            .unwrap()
            .issued_at_unix_secs;
        let token_path = dir.path().join("token");
        crate::devices::invite(&registry_path, "device_a", &token_path, 3600, now).unwrap();
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = params.self_signed(&ca_key).unwrap();
        let ca_cert = dir.path().join("ca.pem");
        let ca_key_path = dir.path().join("ca.key");
        enrollment::write_private_new(&ca_cert, ca.pem().as_bytes()).unwrap();
        enrollment::write_private_new(&ca_key_path, ca_key.serialize_pem().as_bytes()).unwrap();
        let config = IssuerConfig {
            registry: registry_path,
            ca_cert,
            ca_key: ca_key_path,
            profile_sha256: "ab".repeat(32),
            receipt_namespace: None,
            lifetime_secs: 90,
            max_receipts: 1024,
            max_receipt_bytes_total: MAX_TOTAL,
            receipt_grace_secs: 60,
        };
        let issuer = Issuer::open(&config).unwrap();
        let token = fs::read_to_string(token_path).unwrap();
        Self {
            _dir: dir,
            issuer,
            key: enrollment::generate_csr("device_a").unwrap(),
            token,
            now,
        }
    }
    fn request(
        &self,
        operation: Operation,
        purpose: ProofPurpose,
        id: u8,
        predecessor: Option<&EnrollmentReceipt>,
        now: u64,
    ) -> (ExchangeRequest, ConnectionChallenge) {
        let binding = RequestBinding {
            operation,
            request_id: hex::encode([id; 32]),
            profile_sha256: self.issuer.config.profile_sha256.clone(),
            csr_sha256: hex::encode(Sha256::digest(self.key.csr_pem.as_bytes())),
            predecessor_sha256: predecessor.map(|r| r.certificate_sha256.clone()),
        };
        let challenge = ConnectionChallenge::new(now).unwrap();
        let signature = sign_proof(
            self.key.private_key_pem.as_bytes(),
            &challenge.message(),
            &binding,
            purpose,
            now,
        )
        .unwrap();
        (
            ExchangeRequest {
                binding,
                purpose,
                csr_pem: self.key.csr_pem.clone(),
                signature: hex::encode(signature),
                invitation: if purpose == ProofPurpose::Authorize && operation == Operation::Redeem
                {
                    Some(self.token.clone())
                } else {
                    None
                },
                predecessor_certificate_pem: if purpose == ProofPurpose::Authorize {
                    predecessor.map(|r| r.certificate_pem.clone())
                } else {
                    None
                },
            },
            challenge,
        )
    }
    fn issue(&self) -> EnrollmentReceipt {
        let (request, mut challenge) = self.request(
            Operation::Redeem,
            ProofPurpose::Authorize,
            1,
            None,
            self.now,
        );
        self.issuer
            .exchange_with_clock(&request, &mut challenge, || Ok(self.now))
            .unwrap()
    }
    fn at_policy(&self, now: u64) {
        let tx = RegistryTransaction::begin(&self.issuer.config.registry).unwrap();
        let mut registry = tx.load().unwrap();
        registry.refresh_validity(now, 900).unwrap();
        tx.save(&self.issuer.config.registry, &registry, false)
            .unwrap();
    }
}

#[test]
fn fixture_issuance_survives_policy_initialization_second_boundary() {
    let f = Fixture::with_policy_start_offset(1);
    let validity = DeviceRegistry::load(&f.issuer.config.registry)
        .unwrap()
        .validity
        .unwrap();
    assert_eq!(f.now, validity.issued_at_unix_secs);
    let issued = f.issue();
    assert_eq!(issued.not_after_unix_secs, f.now + 90);
}

#[test]
fn opt_in_profile_receipts_preserve_legacy_replay_and_issue_independently() {
    let f = Fixture::new();
    let old = f.issue();
    let legacy_path = f
        .issuer
        .receipts
        .join(format!("{}.json", old.binding.request_id));
    let legacy_bytes = fs::read(&legacy_path).unwrap();
    assert!(legacy_path.exists());
    assert_eq!(f.issuer.config.receipt_namespace, None);

    let mut config = f.issuer.config.clone();
    config.profile_sha256 = "cd".repeat(32);
    config.receipt_namespace = Some(config.profile_sha256.clone());
    let new_issuer = Issuer::open(&config).unwrap();
    assert_eq!(
        new_issuer.receipts,
        PathBuf::from(format!(
            "{}.issuance-receipts-{}",
            config.registry.display(),
            config.profile_sha256
        ))
    );
    assert!(!new_issuer.receipts.exists());
    let token_path = f._dir.path().join("device-b-token");
    crate::devices::invite(&config.registry, "device_b", &token_path, 900, f.now + 1).unwrap();
    let token = fs::read_to_string(token_path).unwrap();
    let key = enrollment::generate_csr("device_b").unwrap();
    let binding = RequestBinding {
        operation: Operation::Redeem,
        request_id: hex::encode([2; 32]),
        profile_sha256: config.profile_sha256.clone(),
        csr_sha256: hex::encode(Sha256::digest(key.csr_pem.as_bytes())),
        predecessor_sha256: None,
    };
    let mut challenge = ConnectionChallenge::new(f.now + 1).unwrap();
    let request = ExchangeRequest {
        signature: hex::encode(
            sign_proof(
                key.private_key_pem.as_bytes(),
                &challenge.message(),
                &binding,
                ProofPurpose::Authorize,
                f.now + 1,
            )
            .unwrap(),
        ),
        binding: binding.clone(),
        purpose: ProofPurpose::Authorize,
        csr_pem: key.csr_pem.clone(),
        invitation: Some(token),
        predecessor_certificate_pem: None,
    };
    let issued = new_issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 1))
        .unwrap();
    assert_eq!(issued.device_id, "device_b");
    assert_eq!(fs::read(&legacy_path).unwrap(), legacy_bytes);
    assert!(new_issuer
        .receipts
        .join(format!("{}.json", issued.binding.request_id))
        .exists());

    let mut challenge = ConnectionChallenge::new(f.now + 2).unwrap();
    let replay = ExchangeRequest {
        binding: binding.clone(),
        purpose: ProofPurpose::Receipt,
        csr_pem: key.csr_pem.clone(),
        predecessor_certificate_pem: None,
        invitation: None,
        signature: hex::encode(
            sign_proof(
                key.private_key_pem.as_bytes(),
                &challenge.message(),
                &binding,
                ProofPurpose::Receipt,
                f.now + 2,
            )
            .unwrap(),
        ),
    };
    let same = new_issuer
        .exchange_with_clock(&replay, &mut challenge, || Ok(f.now + 2))
        .unwrap();
    assert_eq!(same.certificate_sha256, issued.certificate_sha256);
    let (old_replay, mut old_challenge) =
        f.request(Operation::Redeem, ProofPurpose::Receipt, 1, None, f.now + 2);
    assert_eq!(
        f.issuer
            .exchange_with_clock(&old_replay, &mut old_challenge, || Ok(f.now + 2))
            .unwrap()
            .certificate_sha256,
        old.certificate_sha256
    );
    assert_eq!(fs::read(&legacy_path).unwrap(), legacy_bytes);
    let (foreign_replay, mut foreign_challenge) =
        f.request(Operation::Redeem, ProofPurpose::Receipt, 1, None, f.now + 2);
    assert!(new_issuer
        .exchange_with_clock(&foreign_replay, &mut foreign_challenge, || Ok(f.now + 2))
        .is_err());
}

#[test]
fn receipt_namespace_refuses_wrong_or_malformed_profile_without_side_effects() {
    let f = Fixture::new();
    let mut wrong = f.issuer.config.clone();
    wrong.receipt_namespace = Some("cd".repeat(32));
    assert!(Issuer::open(&wrong).is_err());
    wrong.receipt_namespace = Some("not-a-digest".into());
    assert!(Issuer::open(&wrong).is_err());
    assert!(!f.issuer.receipts.exists());
    assert!(!PathBuf::from(format!(
        "{}.issuance-receipts-{}",
        wrong.registry.display(),
        "cd".repeat(32)
    ))
    .exists());
}

#[test]
fn cross_profile_pending_journal_blocks_new_namespace_startup() {
    let f = Fixture::new();
    let mut other = f.issuer.config.clone();
    other.profile_sha256 = "cd".repeat(32);
    other.receipt_namespace = Some(other.profile_sha256.clone());
    let _old = interrupted(&f, 0);
    assert!(registry::issuance_pending_path(&f.issuer.config.registry).exists());
    assert!(Issuer::open(&other).is_err());
    assert!(registry::issuance_pending_path(&f.issuer.config.registry).exists());
    assert!(!PathBuf::from(format!(
        "{}.issuance-receipts-{}",
        other.registry.display(),
        other.profile_sha256
    ))
    .exists());
}

#[test]
fn issuance_before_policy_start_refuses_without_registry_or_receipt_mutation() {
    let f = Fixture::with_policy_start_offset(1);
    let before = fs::read(&f.issuer.config.registry).unwrap();
    let validity = DeviceRegistry::load(&f.issuer.config.registry)
        .unwrap()
        .validity
        .unwrap();
    let stale = validity.issued_at_unix_secs - 1;
    let (request, mut challenge) =
        f.request(Operation::Redeem, ProofPurpose::Authorize, 1, None, stale);
    let error = f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(stale))
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), before);
    assert!(!f.issuer.receipts.exists());
    assert!(!registry::issuance_pending_path(&f.issuer.config.registry).exists());
}

#[test]
fn lost_response_receipt_and_authorize_replay_keep_exact_certificate_generation_and_policy() {
    let f = Fixture::new();
    assert!(!f.issuer.receipts.exists(), "open/check is read-only");
    let first = f.issue();
    let before = fs::read(&f.issuer.config.registry).unwrap();
    for purpose in [ProofPurpose::Receipt, ProofPurpose::Authorize] {
        let (request, mut challenge) = f.request(Operation::Redeem, purpose, 1, None, f.now + 1);
        let second = f
            .issuer
            .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 1))
            .unwrap();
        assert_eq!(
            serialize(&first, MAX_RECEIPT).unwrap(),
            serialize(&second, MAX_RECEIPT).unwrap()
        );
        assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), before);
    }
    let receipt_bytes = fs::read(
        f.issuer
            .receipts
            .join(format!("{}.json", first.binding.request_id)),
    )
    .unwrap();
    assert!(!String::from_utf8_lossy(&receipt_bytes).contains(&f.token));
    assert!(!String::from_utf8_lossy(&receipt_bytes).contains("PRIVATE KEY"));
    let (request, mut challenge) = f.request(
        Operation::Redeem,
        ProofPurpose::Authorize,
        2,
        None,
        f.now + 1,
    );
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 1))
        .is_err());
    assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), before);
}

#[test]
fn receipt_proof_without_a_committed_request_never_issues() {
    let f = Fixture::new();
    let before = fs::read(&f.issuer.config.registry).unwrap();
    let (request, mut challenge) =
        f.request(Operation::Redeem, ProofPurpose::Receipt, 1, None, f.now);
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now))
        .is_err());
    assert!(!f.issuer.receipts.exists());
    assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), before);
}

#[test]
fn renewal_is_same_key_due_only_and_receipt_survives_predecessor_expiry() {
    let f = Fixture::new();
    let first = f.issue();
    let (request, mut challenge) = f.request(
        Operation::Renew,
        ProofPurpose::Authorize,
        2,
        Some(&first),
        f.now + 59,
    );
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 59))
        .is_err());
    f.at_policy(f.now + 60);
    let (request, mut challenge) = f.request(
        Operation::Renew,
        ProofPurpose::Authorize,
        2,
        Some(&first),
        f.now + 60,
    );
    let renewed = f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 60))
        .unwrap();
    assert_ne!(renewed.certificate_sha256, first.certificate_sha256);
    assert_eq!(renewed.not_after_unix_secs, f.now + 150);
    let ca = read_public(&f.issuer.config.ca_cert).unwrap();
    let facts = enrollment::validate_device_certificate_public(
        "device_a",
        renewed.certificate_pem.as_bytes(),
        &ca,
        f.now + 60,
    )
    .unwrap();
    assert_eq!(
        facts.public_key,
        protocol::csr_public_key(&f.key.csr_pem).unwrap()
    );
    let before = fs::read(&f.issuer.config.registry).unwrap();
    let (request, mut challenge) = f.request(
        Operation::Renew,
        ProofPurpose::Receipt,
        2,
        Some(&first),
        f.now + 95,
    );
    let replay = f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 95))
        .unwrap();
    assert_eq!(replay.certificate_pem, renewed.certificate_pem);
    assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), before);
    let (request, mut challenge) = f.request(
        Operation::Renew,
        ProofPurpose::Authorize,
        3,
        Some(&first),
        f.now + 95,
    );
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 95))
        .is_err());
}

#[test]
fn changed_key_revoked_and_expired_predecessors_cannot_renew_or_recover() {
    let f = Fixture::new();
    let first = f.issue();
    let alternate = enrollment::generate_csr("device_a").unwrap();
    let (mut request, mut challenge) = f.request(
        Operation::Renew,
        ProofPurpose::Authorize,
        2,
        Some(&first),
        f.now + 60,
    );
    request.csr_pem = alternate.csr_pem;
    request.binding.csr_sha256 = hex::encode(Sha256::digest(request.csr_pem.as_bytes()));
    request.signature = hex::encode(
        sign_proof(
            alternate.private_key_pem.as_bytes(),
            &challenge.message(),
            &request.binding,
            request.purpose,
            f.now + 60,
        )
        .unwrap(),
    );
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 60))
        .is_err());
    for purpose in [ProofPurpose::Authorize, ProofPurpose::Receipt] {
        let (request, mut challenge) =
            f.request(Operation::Renew, purpose, 2, Some(&first), f.now + 90);
        assert!(f
            .issuer
            .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 90))
            .is_err());
    }
    crate::devices::revoke(&f.issuer.config.registry, "device_a").unwrap();
    let (request, mut challenge) =
        f.request(Operation::Redeem, ProofPurpose::Receipt, 1, None, f.now + 1);
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 1))
        .is_err());
    let (request, mut challenge) = f.request(
        Operation::Renew,
        ProofPurpose::Authorize,
        2,
        Some(&first),
        f.now + 60,
    );
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 60))
        .is_err());
}

#[test]
fn invitation_expiry_and_lock_wait_clock_are_not_extended() {
    let f = Fixture::new();
    let (request, mut challenge) =
        f.request(Operation::Redeem, ProofPurpose::Authorize, 1, None, f.now);
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 30))
        .is_err());
    let (request, mut challenge) = f.request(
        Operation::Redeem,
        ProofPurpose::Authorize,
        1,
        None,
        f.now + 3600,
    );
    f.at_policy(f.now + 3600);
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 3600))
        .is_err());
    assert!(!f.issuer.receipts.exists());
}

// Recreate each on-disk crash cut using synthetic files only. These writes do
// not expose a runtime fault-injection option, reset API or production bypass.
fn interrupted(f: &Fixture, cut: u8) -> EnrollmentReceipt {
    let old = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    let old_bytes = fs::read(&f.issuer.config.registry).unwrap();
    let old_floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    let receipt = f.issue();
    let new = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    let new_floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    let stored = f
        .issuer
        .receipt(&receipt.binding.request_id)
        .unwrap()
        .unwrap();
    let pending = Pending {
        version: 1,
        predecessor_generation: old.generation,
        predecessor_sha256: hex::encode(registry::registry_digest(&old).unwrap()),
        successor: new.clone(),
        stored,
    };
    if cut < 3 {
        fs::write(&f.issuer.config.registry, old_bytes).unwrap();
    }
    if cut < 2 {
        fs::write(registry::floor_path(&f.issuer.config.registry), old_floor).unwrap();
    } else {
        fs::write(registry::floor_path(&f.issuer.config.registry), new_floor).unwrap();
    }
    if cut == 1 || cut == 2 {
        enrollment::write_private_new(
            &registry::pending_path(&f.issuer.config.registry),
            &serde_json::to_vec(&new).unwrap(),
        )
        .unwrap();
    }
    if cut < 4 {
        fs::remove_file(
            f.issuer
                .receipts
                .join(format!("{}.json", receipt.binding.request_id)),
        )
        .unwrap();
    }
    write_new(
        &registry::issuance_pending_path(&f.issuer.config.registry),
        &serialize(&pending, MAX_JOURNAL).unwrap(),
    )
    .unwrap();
    receipt
}

#[test]
fn every_publication_crash_cut_recovers_exact_receipt_and_blocks_other_mutations() {
    for cut in 0..=4 {
        let f = Fixture::new();
        let receipt = interrupted(&f, cut);
        assert!(DeviceRegistry::load(&f.issuer.config.registry).is_err());
        assert!(crate::devices::revoke(&f.issuer.config.registry, "device_a").is_err());
        assert!(crate::devices::refresh_registry(&f.issuer.config.registry, 900).is_err());
        let restarted = Issuer::open(&f.issuer.config).unwrap();
        let (unrelated, mut challenge) =
            f.request(Operation::Redeem, ProofPurpose::Receipt, 8, None, f.now + 1);
        assert!(restarted
            .exchange_with_clock(&unrelated, &mut challenge, || Ok(f.now + 1))
            .is_err());
        assert!(registry::issuance_pending_path(&f.issuer.config.registry).exists());
        let (request, mut challenge) =
            f.request(Operation::Redeem, ProofPurpose::Receipt, 1, None, f.now + 1);
        let replay = restarted
            .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 1))
            .unwrap();
        assert_eq!(replay.certificate_pem, receipt.certificate_pem, "cut {cut}");
        let current = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
        assert_eq!(current.generation, receipt.issued_generation);
        assert!(!registry::pending_path(&f.issuer.config.registry).exists());
        assert!(!registry::issuance_pending_path(&f.issuer.config.registry).exists());
        assert!(registry::floor_path(&f.issuer.config.registry).exists());
        assert!(f
            .issuer
            .config
            .registry
            .with_extension("json.lock")
            .exists());
    }
}

#[test]
fn expired_pending_can_finish_without_authorizing_and_operator_can_recover_without_request_key() {
    let f = Fixture::new();
    let receipt = interrupted(&f, 2);
    let (request, mut challenge) = f.request(
        Operation::Redeem,
        ProofPurpose::Receipt,
        1,
        None,
        f.now + 100,
    );
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 100))
        .is_err());
    assert!(!registry::issuance_pending_path(&f.issuer.config.registry).exists());
    assert_eq!(
        DeviceRegistry::load(&f.issuer.config.registry)
            .unwrap()
            .generation,
        receipt.issued_generation
    );
    let f = Fixture::new();
    let receipt = interrupted(&f, 0);
    f.issuer.recover_pending().unwrap();
    assert_eq!(
        DeviceRegistry::load(&f.issuer.config.registry)
            .unwrap()
            .generation,
        receipt.issued_generation
    );
}

#[test]
fn quotas_are_bounded_and_invalid_requests_cannot_gc_or_create_state() {
    let mut f = Fixture::new();
    f.issuer.config.max_receipts = 1;
    let first = f.issue();
    f.at_policy(f.now + 60);
    let (request, mut challenge) = f.request(
        Operation::Renew,
        ProofPurpose::Authorize,
        2,
        Some(&first),
        f.now + 60,
    );
    assert_eq!(
        f.issuer
            .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 60))
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn journal_symlinks_hardlinks_corruption_and_limits_fail_closed() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let f = Fixture::new();
    let path = registry::issuance_pending_path(&f.issuer.config.registry);
    symlink(&f.issuer.config.ca_key, &path).unwrap();
    assert!(Issuer::open(&f.issuer.config).is_err());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&f.issuer.config.ca_key, &path).unwrap();
    assert!(Issuer::open(&f.issuer.config).is_err());
    fs::remove_file(&path).unwrap();
    enrollment::write_private_new(&path, b"{}").unwrap();
    assert!(Issuer::open(&f.issuer.config).is_err());
    let file = OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(MAX_JOURNAL + 1).unwrap();
    assert!(Issuer::open(&f.issuer.config).is_err());
    fs::remove_file(&path).unwrap();
    fs::set_permissions(&f.issuer.config.ca_key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Issuer::open(&f.issuer.config).is_err());
}

#[test]
fn startup_rejects_missing_registry_malformed_key_and_wrong_ca_key_without_mutations() {
    let f = Fixture::new();
    let before = fs::read(&f.issuer.config.registry).unwrap();
    let key = fs::read(&f.issuer.config.ca_key).unwrap();
    fs::write(&f.issuer.config.ca_key, b"invalid key").unwrap();
    assert!(Issuer::open(&f.issuer.config).is_err());
    let other = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    fs::write(&f.issuer.config.ca_key, other.serialize_pem()).unwrap();
    assert!(Issuer::open(&f.issuer.config).is_err());
    fs::write(&f.issuer.config.ca_key, key).unwrap();
    assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), before);
    assert!(!f.issuer.receipts.exists());
    fs::remove_file(&f.issuer.config.registry).unwrap();
    assert!(Issuer::open(&f.issuer.config).is_err());
}

#[test]
fn pending_recovery_cannot_recreate_a_lost_floor_and_registry() {
    let f = Fixture::new();
    interrupted(&f, 0);
    fs::remove_file(&f.issuer.config.registry).unwrap();
    fs::remove_file(registry::floor_path(&f.issuer.config.registry)).unwrap();
    assert!(f.issuer.recover_pending().is_err());
    assert!(registry::issuance_pending_path(&f.issuer.config.registry).exists());
    assert!(!f.issuer.config.registry.exists());
    assert!(!registry::floor_path(&f.issuer.config.registry).exists());
}

#[test]
fn expired_receipts_are_collected_only_after_authorization_with_count_bounded_replacement() {
    let mut f = Fixture::new();
    f.issuer.config.max_receipts = 1;
    let first = f.issue();
    let receipt_path = f
        .issuer
        .receipts
        .join(format!("{}.json", first.binding.request_id));
    let now = f.now + 151;
    f.at_policy(now);
    let (request, mut challenge) =
        f.request(Operation::Redeem, ProofPurpose::Receipt, 9, None, now);
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(now))
        .is_err());
    assert!(receipt_path.exists());
    let token_path = f._dir.path().join("neighbor-token");
    crate::devices::invite(
        &f.issuer.config.registry,
        "device_b",
        &token_path,
        3600,
        now,
    )
    .unwrap();
    f.token = fs::read_to_string(token_path).unwrap();
    f.key = enrollment::generate_csr("device_b").unwrap();
    let (request, mut challenge) =
        f.request(Operation::Redeem, ProofPurpose::Authorize, 2, None, now);
    let issued = f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(now))
        .unwrap();
    assert_eq!(issued.device_id, "device_b");
    assert!(!receipt_path.exists());
    assert_eq!(fs::read_dir(&f.issuer.receipts).unwrap().count(), 1);
}

#[test]
fn historical_recovery_with_expired_ca_and_missing_signer_cannot_issue() {
    let mut f = Fixture::new();
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2021, 1, 1);
    let ca = params.self_signed(&ca_key).unwrap();
    // Reconstruct an issuance that happened when this synthetic CA was valid,
    // then a crash and restart years later after the signing key was removed.
    fs::write(&f.issuer.config.ca_cert, ca.pem()).unwrap();
    fs::write(&f.issuer.config.ca_key, ca_key.serialize_pem()).unwrap();
    f.now = rcgen::date_time_ymd(2020, 6, 1).unix_timestamp() as u64;
    f.at_policy(f.now);
    let receipt = interrupted(&f, 2);
    assert!(
        Issuer::open(&f.issuer.config).is_err(),
        "normal startup rejects expired CA"
    );
    fs::remove_file(&f.issuer.config.ca_key).unwrap();
    let recovery = Issuer::open_recovery(&f.issuer.config).unwrap();
    let (request, mut challenge) = f.request(
        Operation::Redeem,
        ProofPurpose::Receipt,
        1,
        None,
        registry::unix_now().unwrap(),
    );
    assert!(recovery.exchange(&request, &mut challenge).is_err());
    recovery.recover_pending().unwrap();
    assert_eq!(
        DeviceRegistry::load(&f.issuer.config.registry)
            .unwrap()
            .generation,
        receipt.issued_generation
    );
    assert!(!registry::issuance_pending_path(&f.issuer.config.registry).exists());
    assert!(!f.issuer.config.ca_key.exists());
    assert!(Issuer::open(&f.issuer.config).is_err());
}

#[cfg(unix)]
#[test]
fn startup_publication_waits_for_os_lock_and_verified_new_floor() {
    use std::time::Duration;
    let f = Fixture::new();
    let transaction = RegistryTransaction::begin(&f.issuer.config.registry).unwrap();
    assert_eq!(
        DeviceRegistry::load(&f.issuer.config.registry)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let mut successor = transaction.load().unwrap();
    successor.generation += 1;
    successor.invitations[0].consumed = true;
    let (send, receive) = std::sync::mpsc::channel();
    let config = f.issuer.config.clone();
    let worker = std::thread::spawn(move || send.send(Issuer::open(&config)).unwrap());
    assert!(
        receive.recv_timeout(Duration::from_millis(100)).is_err(),
        "authority startup must wait for the live publication, not exit or adopt the old snapshot"
    );
    transaction
        .save(&f.issuer.config.registry, &successor, false)
        .unwrap();
    drop(transaction);
    let issuer = receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    worker.join().unwrap();
    let current = DeviceRegistry::load(&issuer.config.registry).unwrap();
    assert_eq!(current.generation, successor.generation);
    assert_eq!(
        registry::registry_digest(&current).unwrap(),
        registry::registry_digest(&successor).unwrap()
    );
    assert!(current.invitations[0].consumed);
    assert!(!issuer.receipts.exists(), "startup remains read-only");
}

#[cfg(unix)]
#[test]
fn startup_publication_deadline_and_attempt_bound_leave_state_unchanged() {
    use std::time::{Duration, Instant};
    let f = Fixture::new();
    let before = fs::read(&f.issuer.config.registry).unwrap();
    let floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    let _transaction = RegistryTransaction::begin(&f.issuer.config.registry).unwrap();
    let started = Instant::now();
    let error = load_registry_for_startup(
        &f.issuer.config.registry,
        Duration::from_millis(70),
        Duration::from_millis(10),
        101,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(started.elapsed() >= Duration::from_millis(70));
    assert!(started.elapsed() < Duration::from_secs(2));
    let started = Instant::now();
    let error = load_registry_for_startup(
        &f.issuer.config.registry,
        Duration::from_secs(5),
        Duration::from_secs(1),
        1,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), before);
    assert_eq!(
        fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap(),
        floor
    );
    assert!(!f.issuer.receipts.exists());
    drop(_transaction);
    // A valid pair is not permission to overrun the original startup clock.
    assert_eq!(
        load_registry_for_startup(
            &f.issuer.config.registry,
            Duration::ZERO,
            Duration::from_millis(50),
            101
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::TimedOut
    );
}

#[cfg(unix)]
#[test]
fn startup_publication_never_retries_malformed_missing_or_wrong_floor() {
    use std::time::{Duration, Instant};
    let f = Fixture::new();
    let before = fs::read(&f.issuer.config.registry).unwrap();
    let floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    fs::write(&f.issuer.config.registry, b"malformed registry").unwrap();
    let started = Instant::now();
    assert_eq!(
        load_registry_for_startup(
            &f.issuer.config.registry,
            Duration::from_secs(5),
            Duration::from_secs(1),
            101
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidData
    );
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(Issuer::open(&f.issuer.config).is_err());
    let mut wrong = serde_json::from_slice::<DeviceRegistry>(&before).unwrap();
    wrong.generation += 1;
    fs::write(
        &f.issuer.config.registry,
        serde_json::to_vec(&wrong).unwrap(),
    )
    .unwrap();
    let started = Instant::now();
    assert_eq!(
        load_registry_for_startup(
            &f.issuer.config.registry,
            Duration::from_secs(5),
            Duration::from_secs(1),
            101
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidData
    );
    assert!(started.elapsed() < Duration::from_millis(500));
    fs::remove_file(&f.issuer.config.registry).unwrap();
    let started = Instant::now();
    assert_eq!(
        load_registry_for_startup(
            &f.issuer.config.registry,
            Duration::from_secs(5),
            Duration::from_secs(1),
            101
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::NotFound
    );
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(
        fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap(),
        floor
    );
    assert!(!f.issuer.receipts.exists());
}

#[cfg(unix)]
#[test]
fn startup_publication_rechecks_floor_and_issuance_barrier_after_lock_release() {
    use std::time::Duration;
    for pending_journal in [false, true] {
        let f = Fixture::new();
        let before = fs::read(&f.issuer.config.registry).unwrap();
        let floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
        let transaction = RegistryTransaction::begin(&f.issuer.config.registry).unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let path = f.issuer.config.registry.clone();
        let worker = std::thread::spawn(move || {
            send.send(load_registry_for_startup(
                &path,
                Duration::from_secs(2),
                Duration::from_millis(10),
                201,
            ))
            .unwrap()
        });
        assert!(receive.recv_timeout(Duration::from_millis(50)).is_err());
        if pending_journal {
            write_new(
                &registry::issuance_pending_path(&f.issuer.config.registry),
                b"{}",
            )
            .unwrap();
        } else {
            let mut wrong = serde_json::from_slice::<DeviceRegistry>(&before).unwrap();
            wrong.generation += 1;
            fs::write(
                &f.issuer.config.registry,
                serde_json::to_vec(&wrong).unwrap(),
            )
            .unwrap();
        }
        drop(transaction);
        assert_eq!(
            receive
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        worker.join().unwrap();
        let started = std::time::Instant::now();
        assert!(Issuer::open(&f.issuer.config).is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(
            fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap(),
            floor
        );
        assert!(!f.issuer.receipts.exists());
        if pending_journal {
            assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), before);
            assert!(registry::issuance_pending_path(&f.issuer.config.registry).exists());
        }
    }
}

#[test]
fn startup_publication_preserves_authenticated_pending_recovery_semantics() {
    let f = Fixture::new();
    let receipt = interrupted(&f, 2);
    let registry_before = fs::read(&f.issuer.config.registry).unwrap();
    let floor_before = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    let journal_before =
        fs::read(registry::issuance_pending_path(&f.issuer.config.registry)).unwrap();
    let issuer = Issuer::open(&f.issuer.config).unwrap();
    let recovery = Issuer::open_recovery(&f.issuer.config).unwrap();
    assert!(!issuer.recovery_only);
    assert!(recovery.recovery_only);
    assert_eq!(
        fs::read(&f.issuer.config.registry).unwrap(),
        registry_before
    );
    assert_eq!(
        fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap(),
        floor_before
    );
    assert_eq!(
        fs::read(registry::issuance_pending_path(&f.issuer.config.registry)).unwrap(),
        journal_before
    );
    let (unrelated, mut challenge) =
        f.request(Operation::Redeem, ProofPurpose::Receipt, 8, None, f.now + 1);
    assert!(issuer
        .exchange_with_clock(&unrelated, &mut challenge, || Ok(f.now + 1))
        .is_err());
    assert!(recovery
        .exchange_with_clock(&unrelated, &mut challenge, || Ok(f.now + 1))
        .is_err());
    recovery.recover_pending().unwrap();
    let current = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    assert_eq!(current.generation, receipt.issued_generation);
    assert_eq!(
        current.devices[0].certificate_sha256,
        receipt.certificate_sha256
    );
}
