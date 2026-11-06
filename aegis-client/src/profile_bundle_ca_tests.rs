use super::unix::{install, prepare};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

struct Fixture {
    _temp: tempfile::TempDir,
    bundle: PathBuf,
    stage: PathBuf,
    config: PathBuf,
    ca: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let bundle = root.join("bundle");
        let config = root.join("installed");
        for path in [&bundle, &config] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let ca = rcgen::generate_simple_self_signed(vec!["fixture.invalid".into()])
            .unwrap()
            .cert
            .pem()
            .into_bytes();
        let stage = root.join("stage");
        Self {
            _temp: temp,
            bundle,
            stage,
            config,
            ca,
        }
    }
    fn config(&self, reference: Option<&str>, mode: Option<&str>) -> Vec<u8> {
        let mut text = String::from("mode = \"relay\"\n[socks]\nlisten = \"127.0.0.1:1080\"\nauth_user = \"fixture-user\"\n[relay]\nauth_token = \"synthetic-relay-fixture\"\nserver = \"192.0.2.9:443\"\nserver_name = \"fixture.invalid\"\nca_cert = \"__CLIENT_CA_CERT_PATH__\"\n");
        if let Some(reference) = reference {
            text.push_str(&format!("masque_ca_cert = {reference:?}\n"));
        }
        if let Some(mode) = mode {
            text.push_str(&format!("masque_trust_mode = {mode:?}\n"));
        }
        // Every negative control starts with a valid complete configuration.
        toml::from_str::<aegis_core::Settings>(&text).unwrap();
        fs::write(self.bundle.join("aegis-client.toml"), &text).unwrap();
        fs::write(self.bundle.join("masque-ca.pem"), &self.ca).unwrap();
        text.into_bytes()
    }
    fn prepare(&self, purge: bool) -> std::io::Result<()> {
        prepare(&self.bundle, &self.stage, &self.config, owner(), purge)
    }
    fn install(&self) -> std::io::Result<()> {
        install(&self.stage, &self.config, owner())
    }
}
fn owner() -> u32 {
    // SAFETY: geteuid reads the process identity without pointer arguments.
    unsafe { libc::geteuid() }
}
fn typed(path: &Path) -> aegis_core::Settings {
    toml::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn explicit_bundled_reference_relocates_only_ca_and_preserves_both_modes() {
    for mode in [None, Some("configured_ca_only")] {
        let f = Fixture::new();
        f.config(Some("masque-ca.pem"), mode);
        let mut expected = typed(&f.bundle.join("aegis-client.toml"));
        expected.relay.masque_ca_cert = Some(f.config.join("masque-ca.pem"));
        f.prepare(false).unwrap();
        let actual = typed(&f.stage.join("aegis-client.toml"));
        assert_eq!(
            toml::Value::try_from(actual).unwrap(),
            toml::Value::try_from(expected).unwrap()
        );
        assert_eq!(fs::metadata(&f.stage).unwrap().mode() & 0o777, 0o700);
        for name in ["aegis-client.toml", "masque-ca.pem"] {
            assert_eq!(
                fs::metadata(f.stage.join(name)).unwrap().mode() & 0o777,
                0o600
            );
        }
        f.install().unwrap();
        let destination = f.config.join("masque-ca.pem");
        assert_eq!(fs::read(&destination).unwrap(), f.ca);
        assert_eq!(fs::metadata(&destination).unwrap().nlink(), 1);
        assert_eq!(fs::metadata(&destination).unwrap().mode() & 0o777, 0o600);
    }
}

#[test]
fn placeholder_and_dot_reference_use_the_same_exact_owned_asset() {
    for reference in ["./masque-ca.pem", "__CLIENT_MASQUE_CA_CERT_PATH__"] {
        let f = Fixture::new();
        f.config(Some(reference), None);
        f.prepare(false).unwrap();
        f.install().unwrap();
        assert_eq!(
            typed(&f.stage.join("aegis-client.toml"))
                .relay
                .masque_ca_cert,
            Some(f.config.join("masque-ca.pem"))
        );
    }
}

#[test]
fn absent_and_external_ca_leave_raw_config_and_assets_untouched() {
    for reference in [None, Some("/operator/external.pem"), Some("external.pem")] {
        for mode in [None, Some("configured_ca_only")] {
            let f = Fixture::new();
            let raw = f.config(reference, mode);
            // The unrelated asset's contents must not affect an external/absent reference.
            fs::write(
                f.bundle.join("masque-ca.pem"),
                b"unrelated unusable public input",
            )
            .unwrap();
            f.prepare(false).unwrap();
            f.install().unwrap();
            assert_eq!(fs::read(f.stage.join("aegis-client.toml")).unwrap(), raw);
            assert!(!f.stage.join("masque-ca.pem").exists());
            assert!(!f.config.join("masque-ca.pem").exists());
        }
    }
}

#[test]
fn missing_empty_invalid_and_oversized_ca_refuse_before_stage_or_target() {
    for case in 0..4 {
        let f = Fixture::new();
        f.config(Some("masque-ca.pem"), None);
        let source = f.bundle.join("masque-ca.pem");
        match case {
            0 => fs::remove_file(&source).unwrap(),
            1 => fs::write(&source, []).unwrap(),
            2 => fs::write(&source, b"not a certificate").unwrap(),
            _ => fs::write(&source, vec![b'x'; 4 * 1024 * 1024 + 1]).unwrap(),
        }
        assert!(f.prepare(false).is_err());
        assert!(!f.stage.exists());
        assert!(!f.config.join("masque-ca.pem").exists());
    }
}

#[test]
fn symlink_hardlink_and_alias_ancestry_refuse_before_stage() {
    for case in 0..3 {
        let f = Fixture::new();
        f.config(Some("masque-ca.pem"), None);
        let source = f.bundle.join("masque-ca.pem");
        if case == 0 {
            let original = f.bundle.join("public-original.pem");
            fs::rename(&source, &original).unwrap();
            symlink(&original, &source).unwrap();
        } else if case == 1 {
            fs::hard_link(&source, f.bundle.join("public-alias.pem")).unwrap();
        } else {
            let alias = f.bundle.parent().unwrap().join("bundle-alias");
            symlink(&f.bundle, &alias).unwrap();
            assert!(prepare(&alias, &f.stage, &f.config, owner(), false).is_err());
            assert!(!f.stage.exists());
            continue;
        }
        assert!(f.prepare(false).is_err());
        assert!(!f.stage.exists());
    }
}

#[test]
fn existing_destination_requires_explicit_purge_and_install_never_overwrites() {
    let f = Fixture::new();
    f.config(Some("masque-ca.pem"), None);
    let destination = f.config.join("masque-ca.pem");
    fs::write(&destination, b"original public anchor").unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(f.prepare(false).is_err());
    assert!(!f.stage.exists());
    f.prepare(true).unwrap();
    assert!(f.install().is_err());
    assert_eq!(fs::read(&destination).unwrap(), b"original public anchor");
    // Simulate only the caller's already-authorized original reinstall purge.
    fs::remove_file(&destination).unwrap();
    f.install().unwrap();
    assert_eq!(fs::read(&destination).unwrap(), f.ca);
}

#[test]
fn untrusted_existing_destination_and_existing_stage_are_retained() {
    let f = Fixture::new();
    f.config(Some("masque-ca.pem"), None);
    let original = f.config.join("public-original.pem");
    fs::write(&original, b"original anchor").unwrap();
    symlink(&original, f.config.join("masque-ca.pem")).unwrap();
    assert!(f.prepare(true).is_err());
    assert!(!f.stage.exists());
    assert_eq!(fs::read(&original).unwrap(), b"original anchor");
    fs::remove_file(f.config.join("masque-ca.pem")).unwrap();
    fs::create_dir(&f.stage).unwrap();
    fs::write(f.stage.join("sentinel"), b"retained").unwrap();
    assert!(f.prepare(false).is_err());
    assert_eq!(fs::read(f.stage.join("sentinel")).unwrap(), b"retained");
}

#[test]
fn stage_target_mismatch_and_writable_target_refuse_without_destination() {
    let f = Fixture::new();
    f.config(Some("masque-ca.pem"), None);
    f.prepare(false).unwrap();
    let different = f.config.parent().unwrap().join("different");
    fs::create_dir(&different).unwrap();
    fs::set_permissions(&different, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(install(&f.stage, &different, owner()).is_err());
    assert!(!different.join("masque-ca.pem").exists());
    fs::set_permissions(&f.config, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(f.install().is_err());
    assert!(!f.config.join("masque-ca.pem").exists());
}
