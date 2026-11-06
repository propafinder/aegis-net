use super::*;
use sha2::{Digest, Sha256};

fn request(csr: &str) -> RequestBinding {
    RequestBinding {
        operation: Operation::Redeem,
        request_id: "1".repeat(64),
        profile_sha256: "2".repeat(64),
        csr_sha256: hex::encode(Sha256::digest(csr.as_bytes())),
        predecessor_sha256: None,
    }
}

#[test]
fn existing_provider_verifies_standard_ed25519_empty_message_vector() {
    let key = digest("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    // RFC 8032 section 7.1, TEST 1 (public test vector):
    // https://www.rfc-editor.org/rfc/rfc8032#section-7.1
    let signature = hex::decode(concat!(
        "e5564300c360ac729086e2cc806e828a",
        "84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46b",
        "d25bf5f0595bbe24655141438e7a100b"
    ))
    .unwrap();
    verify_ed25519(&key, b"", &signature).unwrap();
    assert!(verify_ed25519(&key, b"changed", &signature).is_err());
}

#[test]
fn challenge_key_body_purpose_connection_and_single_use_are_bound() {
    let material = super::super::generate_csr("proof-device").unwrap();
    let key = csr_public_key(&material.csr_pem).unwrap();
    let binding = request(&material.csr_pem);
    let now = 1_700_000_000;
    let mut challenge = ConnectionChallenge::new(now).unwrap();
    let signature = sign_proof(
        material.private_key_pem.as_bytes(),
        &challenge.message(),
        &binding,
        ProofPurpose::Authorize,
        now,
    )
    .unwrap();
    let proof = challenge
        .verify(&binding, ProofPurpose::Authorize, &key, &signature, now)
        .unwrap();
    proof.check(&binding, &key, now, true).unwrap();
    assert!(challenge
        .verify(&binding, ProofPurpose::Authorize, &key, &signature, now)
        .is_err());
    assert!(proof
        .check(&binding, &key, now + CHALLENGE_SECS, true)
        .is_err());
    let mut other = ConnectionChallenge::new(now).unwrap();
    assert!(other
        .verify(&binding, ProofPurpose::Authorize, &key, &signature, now)
        .is_err());
    for variant in 0..4 {
        let mut fresh = ConnectionChallenge::new(now).unwrap();
        let signature = sign_proof(
            material.private_key_pem.as_bytes(),
            &fresh.message(),
            &binding,
            ProofPurpose::Authorize,
            now,
        )
        .unwrap();
        let mut changed = binding.clone();
        let mut changed_key = key;
        let mut purpose = ProofPurpose::Authorize;
        match variant {
            0 => changed.profile_sha256 = "3".repeat(64),
            1 => changed.csr_sha256 = "4".repeat(64),
            2 => changed_key[0] ^= 1,
            _ => purpose = ProofPurpose::Receipt,
        }
        assert!(fresh
            .verify(&changed, purpose, &changed_key, &signature, now)
            .is_err());
        assert!(fresh
            .verify(&binding, ProofPurpose::Authorize, &key, &signature, now)
            .is_err());
    }
}

#[test]
fn receipt_proof_cannot_authorize_new_issuance_and_clock_does_not_extend_it() {
    let material = super::super::generate_csr("recovery").unwrap();
    let key = csr_public_key(&material.csr_pem).unwrap();
    let binding = request(&material.csr_pem);
    let now = 1_700_000_000;
    let mut challenge = ConnectionChallenge::new(now).unwrap();
    let signature = sign_proof(
        material.private_key_pem.as_bytes(),
        &challenge.message(),
        &binding,
        ProofPurpose::Receipt,
        now,
    )
    .unwrap();
    let proof = challenge
        .verify(&binding, ProofPurpose::Receipt, &key, &signature, now)
        .unwrap();
    proof.check(&binding, &key, now, false).unwrap();
    assert!(proof.check(&binding, &key, now, true).is_err());
    assert!(proof.check(&binding, &key, now - 1, false).is_err());
    assert!(proof.check(&binding, &key, now + 30, false).is_err());
}

#[test]
fn malformed_binding_csr_and_non_ed25519_request_are_rejected() {
    let material = super::super::generate_csr("bounded").unwrap();
    assert!(csr_public_key(&(material.csr_pem.clone() + &material.private_key_pem)).is_err());
    assert!(csr_public_key(&"x".repeat(MAX_CSR_BYTES + 1)).is_err());
    let mut binding = request(&material.csr_pem);
    binding.request_id = "../path".into();
    assert!(binding.validate().is_err());
    binding = request(&material.csr_pem);
    binding.predecessor_sha256 = Some("3".repeat(64));
    assert!(binding.validate().is_err());
    binding.operation = Operation::Renew;
    binding.validate().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    assert!(csr_public_key(&csr).is_err());
}
