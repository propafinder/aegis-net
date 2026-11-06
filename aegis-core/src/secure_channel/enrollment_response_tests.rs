//! Independent synthetic-PKI tests for enrollment response and resume boundaries.
use crate::secure_channel::enrollment::{
    csr_for_key, generate_csr, sign_csr, validate_device_ca, validate_device_certificate,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};

const DEVICE: &str = "response-fixture-device";
const NOW: u64 = 1_800_000_000;

struct Fixture {
    ca_key: KeyPair,
    ca: Certificate,
    key: KeyPair,
}

fn instant(seconds: u64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(seconds as i64).unwrap()
}

impl Fixture {
    fn new() -> Self {
        Self::with_ca_validity(NOW - 86_400, NOW + 90 * 86_400)
    }

    fn with_ca_validity(not_before: u64, not_after: u64) -> Self {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.not_before = instant(not_before);
        params.not_after = instant(not_after);
        let ca = params.self_signed(&ca_key).unwrap();
        Self {
            ca_key,
            ca,
            key: KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap(),
        }
    }

    fn leaf(&self, change: impl FnOnce(&mut CertificateParams)) -> Certificate {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, DEVICE);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.is_ca = IsCa::NoCa;
        params.not_before = instant(NOW - 10);
        params.not_after = instant(NOW + 300);
        change(&mut params);
        params.signed_by(&self.key, &self.ca, &self.ca_key).unwrap()
    }

    fn validate(&self, certificate: &Certificate) -> std::io::Result<String> {
        validate_device_certificate(
            DEVICE,
            certificate.pem().as_bytes(),
            self.ca.pem().as_bytes(),
            self.key.serialize_pem().as_bytes(),
            NOW,
        )
    }
}

#[test]
fn response_accepts_real_issued_leaf_and_returns_exact_fingerprint() {
    let fixture = Fixture::new();
    let csr = csr_for_key(DEVICE, &fixture.key.serialize_pem()).unwrap();
    let issued = sign_csr(
        DEVICE,
        &csr,
        &fixture.ca.pem(),
        &fixture.ca_key.serialize_pem(),
        NOW,
        300,
    )
    .unwrap();
    let actual = validate_device_certificate(
        DEVICE,
        issued.certificate_pem.as_bytes(),
        fixture.ca.pem().as_bytes(),
        fixture.key.serialize_pem().as_bytes(),
        NOW,
    )
    .unwrap();
    assert_eq!(actual, issued.record.certificate_sha256);
    let independent = fixture.leaf(|_| {});
    assert_eq!(
        fixture.validate(&independent).unwrap(),
        hex::encode(Sha256::digest(independent.der().as_ref()))
    );
}

#[test]
fn response_rejects_wrong_key_with_otherwise_valid_chain_and_profile() {
    let fixture = Fixture::new();
    let certificate = fixture.leaf(|_| {});
    fixture.validate(&certificate).unwrap();
    let other_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    assert!(validate_device_certificate(
        DEVICE,
        certificate.pem().as_bytes(),
        fixture.ca.pem().as_bytes(),
        other_key.serialize_pem().as_bytes(),
        NOW,
    )
    .is_err());
}

#[test]
fn response_rejects_same_name_but_unprovisioned_ca() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    let certificate = fixture.leaf(|_| {});
    // Both CAs deliberately have the same subject. Trust comes from the
    // independently supplied key, not matching issuer text.
    assert!(validate_device_certificate(
        DEVICE,
        certificate.pem().as_bytes(),
        other.ca.pem().as_bytes(),
        fixture.key.serialize_pem().as_bytes(),
        NOW,
    )
    .is_err());
}

#[test]
fn response_rejects_wrong_requested_device_identity() {
    let fixture = Fixture::new();
    let certificate = fixture.leaf(|_| {});
    assert!(validate_device_certificate(
        "different-device",
        certificate.pem().as_bytes(),
        fixture.ca.pem().as_bytes(),
        fixture.key.serialize_pem().as_bytes(),
        NOW,
    )
    .is_err());
    let missing_cn = fixture.leaf(|params| {
        params.distinguished_name = DistinguishedName::new();
    });
    assert!(fixture.validate(&missing_cn).is_err());
}

#[test]
fn response_rejects_not_yet_valid_and_expired_certificates() {
    let fixture = Fixture::new();
    let future = fixture.leaf(|params| {
        params.not_before = instant(NOW + 60);
        params.not_after = instant(NOW + 300);
    });
    assert!(fixture.validate(&future).is_err());
    let expired = fixture.leaf(|params| {
        params.not_before = instant(NOW - 300);
        params.not_after = instant(NOW - 1);
    });
    assert!(fixture.validate(&expired).is_err());
    fixture.validate(&fixture.leaf(|_| {})).unwrap();
}

#[test]
fn response_rejects_validly_signed_but_wrong_certificate_profiles() {
    let fixture = Fixture::new();
    fixture.validate(&fixture.leaf(|_| {})).unwrap();
    for case in [
        "server_auth",
        "mixed_auth",
        "no_eku",
        "ca",
        "missing_key_usage",
        "extra_key_usage",
        "unexpected_san",
    ] {
        let certificate = fixture.leaf(|params| match case {
            "server_auth" => params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth],
            "mixed_auth" => {
                params.extended_key_usages = vec![
                    ExtendedKeyUsagePurpose::ClientAuth,
                    ExtendedKeyUsagePurpose::ServerAuth,
                ]
            }
            "no_eku" => params.extended_key_usages.clear(),
            "ca" => params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained),
            "missing_key_usage" => params.key_usages.clear(),
            "extra_key_usage" => params.key_usages.push(KeyUsagePurpose::KeyEncipherment),
            "unexpected_san" => {
                params.subject_alt_names = CertificateParams::new(vec!["unexpected.test".into()])
                    .unwrap()
                    .subject_alt_names
            }
            _ => unreachable!(),
        });
        assert!(fixture.validate(&certificate).is_err(), "accepted {case}");
    }
}

#[test]
fn response_rejects_corrupted_signature_and_does_not_select_a_later_leaf() {
    let fixture = Fixture::new();
    let certificate = fixture.leaf(|_| {});
    let mut lines: Vec<String> = certificate.pem().lines().map(str::to_owned).collect();
    let last_data = lines.len() - 2;
    let original = lines[last_data].as_bytes()[0];
    lines[last_data].replace_range(..1, if original == b'A' { "B" } else { "A" });
    let corrupted = lines.join("\n");
    // Keep valid PEM and a valid second certificate. Neither parsing nor chain
    // verification may silently skip the damaged leaf in favour of that one.
    for input in [corrupted.clone(), corrupted + "\n" + &certificate.pem()] {
        assert!(validate_device_certificate(
            DEVICE,
            input.as_bytes(),
            fixture.ca.pem().as_bytes(),
            fixture.key.serialize_pem().as_bytes(),
            NOW,
        )
        .is_err());
    }
}

#[test]
fn response_rejects_malformed_and_oversized_inputs() {
    let fixture = Fixture::new();
    let certificate = fixture.leaf(|_| {}).pem().into_bytes();
    let ca = fixture.ca.pem().into_bytes();
    let key = fixture.key.serialize_pem().into_bytes();
    for position in 0..3 {
        for replacement in [Vec::new(), vec![0xff], vec![b'x'; 64 * 1024 + 1]] {
            let mut inputs = [certificate.clone(), ca.clone(), key.clone()];
            inputs[position] = replacement;
            assert!(
                validate_device_certificate(DEVICE, &inputs[0], &inputs[1], &inputs[2], NOW,)
                    .is_err()
            );
        }
    }
}

#[test]
fn csr_resume_keeps_key_and_request_bytes_after_corrupted_request() {
    let original = generate_csr(DEVICE).unwrap();
    let resumed = csr_for_key(DEVICE, &original.private_key_pem).unwrap();
    assert_eq!(resumed, original.csr_pem);
    assert_eq!(
        resumed,
        csr_for_key(DEVICE, &original.private_key_pem).unwrap()
    );
    CertificateSigningRequestParams::from_pem(&resumed).unwrap();
    let mut corrupted: Vec<String> = resumed.lines().map(str::to_owned).collect();
    let last_data = corrupted.len() - 2;
    let original_byte = corrupted[last_data].as_bytes()[0];
    corrupted[last_data].replace_range(..1, if original_byte == b'A' { "B" } else { "A" });
    assert!(CertificateSigningRequestParams::from_pem(&corrupted.join("\n")).is_err());
    // Recovery derives the exact original signed request from the saved key;
    // a damaged or missing CSR never causes fresh private-key generation.
    assert_eq!(
        resumed,
        csr_for_key(DEVICE, &original.private_key_pem).unwrap()
    );
    let fixture = Fixture::new();
    let issued = sign_csr(
        DEVICE,
        &resumed,
        &fixture.ca.pem(),
        &fixture.ca_key.serialize_pem(),
        NOW,
        300,
    )
    .unwrap();
    assert_eq!(
        validate_device_certificate(
            DEVICE,
            issued.certificate_pem.as_bytes(),
            fixture.ca.pem().as_bytes(),
            original.private_key_pem.as_bytes(),
            NOW,
        )
        .unwrap(),
        issued.record.certificate_sha256
    );
}

#[test]
fn csr_resume_rejects_invalid_identity_corrupt_key_and_non_ed25519_key() {
    let original = generate_csr(DEVICE).unwrap();
    for identity in ["", "../device", "device with space"] {
        assert!(csr_for_key(identity, &original.private_key_pem).is_err());
    }
    assert!(csr_for_key(DEVICE, "not a private key").is_err());
    let other_algorithm = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    assert!(csr_for_key(DEVICE, &other_algorithm.serialize_pem()).is_err());
}

#[test]
fn response_rejects_matching_non_ed25519_identity_key() {
    let mut fixture = Fixture::new();
    fixture.key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    // Same trusted issuer, CN and client-only profile, and the key DOES match.
    // Enrollment's Ed25519 policy must still reject this different key type.
    let certificate = fixture.leaf(|_| {});
    assert!(fixture.validate(&certificate).is_err());
}

#[test]
fn public_response_and_ca_reject_mixed_private_pem_or_trailing_junk() {
    let fixture = Fixture::new();
    let certificate = fixture.leaf(|_| {}).pem();
    let ca = fixture.ca.pem();
    let private = fixture.key.serialize_pem();
    for (is_ca, public) in [(false, &certificate), (true, &ca)] {
        for unexpected in [
            &private,
            "unexpected trailing text",
            "-----BEGIN PRIVATE KEY-----",
        ] {
            for mixed in [
                format!("{public}\n{unexpected}"),
                format!("{unexpected}\n{public}"),
            ] {
                if is_ca {
                    assert!(validate_device_ca(mixed.as_bytes()).is_err());
                    assert!(validate_device_certificate(
                        DEVICE,
                        certificate.as_bytes(),
                        mixed.as_bytes(),
                        private.as_bytes(),
                        NOW,
                    )
                    .is_err());
                } else {
                    assert!(validate_device_certificate(
                        DEVICE,
                        mixed.as_bytes(),
                        ca.as_bytes(),
                        private.as_bytes(),
                        NOW,
                    )
                    .is_err());
                }
            }
        }
    }
    // Ordinary PEM whitespace remains acceptable; rejecting mixed secrets
    // must not turn harmless line-ending differences into an enrollment error.
    validate_device_ca(format!(" \r\n{ca}\n\t").as_bytes()).unwrap();
    validate_device_certificate(
        DEVICE,
        format!(" \r\n{certificate}\n\t").as_bytes(),
        ca.as_bytes(),
        private.as_bytes(),
        NOW,
    )
    .unwrap();
}

#[test]
fn device_ca_requires_ca_authority_and_certificate_signing_usage() {
    let fixture = Fixture::new();
    validate_device_ca(fixture.ca.pem().as_bytes()).unwrap();
    assert!(validate_device_ca(fixture.leaf(|_| {}).pem().as_bytes()).is_err());
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let incorrect_usage = params.self_signed(&fixture.ca_key).unwrap();
    assert!(validate_device_ca(incorrect_usage.pem().as_bytes()).is_err());
    // An explicit signing bit or an omitted KU extension are the documented
    // root profile; a present KU that forbids signing is rejected above.
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let unrestricted_ca = params.self_signed(&fixture.ca_key).unwrap();
    validate_device_ca(unrestricted_ca.pem().as_bytes()).unwrap();
}

#[test]
fn response_enforces_certificate_lifetime_with_exact_boundary_controls() {
    let fixture = Fixture::new();
    for lifetime in [59, 31 * 86_400] {
        let certificate = fixture.leaf(|params| {
            params.not_before = instant(NOW - 10);
            params.not_after = instant(NOW - 10 + lifetime);
        });
        assert!(
            fixture.validate(&certificate).is_err(),
            "accepted {lifetime}s"
        );
    }
    for lifetime in [60, 30 * 86_400] {
        let certificate = fixture.leaf(|params| {
            params.not_before = instant(NOW - 10);
            params.not_after = instant(NOW - 10 + lifetime);
        });
        fixture.validate(&certificate).unwrap();
    }
}

#[test]
fn public_ca_parser_rejects_ambiguous_issuers_and_incomplete_blocks() {
    let fixture = Fixture::new();
    let ca = fixture.ca.pem();
    validate_device_ca(ca.as_bytes()).unwrap();
    for count in [2, 8, 9] {
        assert!(validate_device_ca(ca.repeat(count).as_bytes()).is_err());
    }
    let incomplete = ca.replace("-----END CERTIFICATE-----", "");
    assert!(validate_device_ca(incomplete.as_bytes()).is_err());
    assert!(validate_device_ca(b" \n\t").is_err());
    assert!(validate_device_ca(&vec![b' '; 64 * 1024 + 1]).is_err());
}

#[test]
fn response_rejects_expired_or_not_yet_valid_pinned_issuer() {
    // The leaf is currently valid and its signature matches the supplied CA.
    // Trust-anchor dates need explicit policy; a root store is not enough.
    for (not_before, not_after) in [(NOW - 86_400, NOW - 1), (NOW + 60, NOW + 86_400)] {
        let fixture = Fixture::with_ca_validity(not_before, not_after);
        validate_device_ca(fixture.ca.pem().as_bytes()).unwrap();
        assert!(fixture.validate(&fixture.leaf(|_| {})).is_err());
    }
}

#[test]
fn response_cannot_outlive_currently_valid_issuer() {
    let short_issuer = Fixture::with_ca_validity(NOW - 60, NOW + 120);
    assert!(short_issuer.validate(&short_issuer.leaf(|_| {})).is_err());
    // Equality at the child/issuer not-after boundary is permitted while both
    // certificates are valid now; reject only an actual overrun.
    let matching_issuer = Fixture::with_ca_validity(NOW - 60, NOW + 300);
    matching_issuer
        .validate(&matching_issuer.leaf(|_| {}))
        .unwrap();
}
