use super::*;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
#[test]
fn windows_enrollment_resumes_and_preserves_original_key() {
    // The Codex/CI TEMP directory may intentionally grant sandbox users write
    // access. Enrollment must reject it; use an independent protected parent.
    let parent = std::path::PathBuf::from(std::env::var_os("ProgramData").unwrap());
    let root = tempfile::Builder::new()
        .prefix("AEGIS-enrollment-test-")
        .tempdir_in(&parent)
        .unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = params.self_signed(&ca_key).unwrap().pem();
    let ca_path = root.path().join("issuer.pem");
    aegis_core::windows_file::write_private_new(&ca_path, ca.as_bytes(), false).unwrap();
    let args = PrepareArgs {
        device_id: "windows-test-device".into(),
        identity_dir: root.path().join("identity"),
        device_ca: ca_path.clone(),
    };
    let prepared = prepare(&args).unwrap();
    assert_eq!(prepared.phase, "prepared");
    let original = read_private(&args.identity_dir.join("device.key")).unwrap();
    let csr = fs::read_to_string(args.identity_dir.join("device.csr")).unwrap();
    prepare(&args).unwrap();
    assert_eq!(
        *read_private(&args.identity_dir.join("device.key")).unwrap(),
        *original
    );
    let issued = enrollment::sign_csr(
        &args.device_id,
        &csr,
        &ca,
        &ca_key.serialize_pem(),
        registry::unix_now().unwrap(),
        300,
    )
    .unwrap();
    let certificate = root.path().join("response.pem");
    enrollment::write_private_new(&certificate, issued.certificate_pem.as_bytes()).unwrap();
    let args = CompleteArgs {
        identity_dir: args.identity_dir,
        certificate,
        device_ca: ca_path,
    };
    assert_eq!(complete(&args).unwrap().phase, "ready");
    assert_eq!(status(&args.identity_dir).unwrap().phase, "ready");
    assert_eq!(
        *read_private(&args.identity_dir.join("device.key")).unwrap(),
        *original
    );
    let store = Store::open(&args.identity_dir, false).unwrap();
    assert!(Store::open(&args.identity_dir, false).is_err());
    drop(store);
}

#[test]
fn machine_identity_is_resumable_and_does_not_adopt_user_secrets() {
    use aegis_core::windows_file as wf;
    let root = PathBuf::from(std::env::var_os("ProgramData").unwrap()).join(format!(
        "AEGIS-machine-identity-{}-{}",
        std::process::id(),
        registry::unix_now().unwrap()
    ));
    wf::create_machine_private_directory(&root).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    wf::trusted_system_directory(&root).unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = params.self_signed(&ca_key).unwrap().pem();
    let ca_path = root.join("issuer.pem");
    wf::atomic_write_machine_private(&ca_path, ca.as_bytes(), false).unwrap();
    let args = PrepareArgs {
        device_id: "windows-machine-test".into(),
        identity_dir: root.join("nested/identity"),
        device_ca: ca_path.clone(),
    };
    assert_eq!(prepare_system(&args).unwrap().phase, "prepared");
    let bundle = root.join("bundle");
    wf::create_machine_private_directory(&bundle).unwrap();
    for name in ["outer-ca.pem", "inner-ca.pem", "device-ca.pem"] {
        wf::atomic_write_machine_private(&bundle.join(name), ca.as_bytes(), false).unwrap();
    }
    wf::atomic_write_machine_private(&bundle.join("bundle.json"), br#"{"schema":"aegis_device_bundle_v1","relay_server":"127.0.0.1:443","outer_server_name":"outer.test","inner_server_name":"inner.test","udp":false}"#, false).unwrap();
    crate::device_bundle::inspect(&crate::device_bundle::BundleInspectArgs {
        bundle_dir: bundle,
        identity_dir: Some(args.identity_dir.clone()),
        json: true,
    })
    .unwrap();
    let original = read_private(&args.identity_dir.join("device.key")).unwrap();
    prepare_system(&args).unwrap();
    let csr = fs::read_to_string(args.identity_dir.join("device.csr")).unwrap();
    let issued = enrollment::sign_csr(
        &args.device_id,
        &csr,
        &ca,
        &ca_key.serialize_pem(),
        registry::unix_now().unwrap(),
        300,
    )
    .unwrap();
    let response = root.join("response.pem");
    wf::atomic_write_machine_private(&response, issued.certificate_pem.as_bytes(), false).unwrap();
    complete(&CompleteArgs {
        identity_dir: args.identity_dir.clone(),
        certificate: response,
        device_ca: ca_path.clone(),
    })
    .unwrap();
    assert_eq!(status(&args.identity_dir).unwrap().phase, "ready");
    assert_eq!(
        *read_private(&args.identity_dir.join("device.key")).unwrap(),
        *original
    );
    for entry in fs::read_dir(&args.identity_dir).unwrap() {
        let file = File::open(entry.unwrap().path()).unwrap();
        // Also rejects LocalService read grants, which are appropriate for
        // service configs but not the strict device identity store.
        wf::validate_machine_private(&file).unwrap();
    }
    if wf::current_sid().unwrap() != "S-1-5-18" {
        let user_args = PrepareArgs {
            identity_dir: root.join("user-identity"),
            ..args.clone()
        };
        prepare(&user_args).unwrap();
        let user_key = read_private(&user_args.identity_dir.join("device.key")).unwrap();
        assert!(prepare_system(&user_args).is_err());
        assert_eq!(
            *read_private(&user_args.identity_dir.join("device.key")).unwrap(),
            *user_key
        );
        // A machine-owned parent must not make a user-owned record acceptable.
        let record = args.identity_dir.join("identity.json");
        let bytes = read_private(&record).unwrap();
        wf::atomic_write_private(&record, &bytes, true, false).unwrap();
        assert!(status(&args.identity_dir).is_err());
        assert!(prepare_system(&args).is_err());
        assert_eq!(
            *read_private(&args.identity_dir.join("device.key")).unwrap(),
            *original
        );
    }
}
