use super::*;

fn record(user: &str, password: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": 1, "username": user, "password": password
    }))
    .unwrap()
}

#[test]
fn valid_ordinary_credentials_and_byte_limits() {
    for (user, password) in [("custom-user", "non-hex password"), ("u", "é")] {
        let auth = LocalSocksAuth::from_bytes(&record(user, password)).unwrap();
        assert_eq!(auth.username(), user);
        assert_eq!(auth.password(), password);
        assert_eq!(format!("{auth:?}"), "LocalSocksAuth([redacted])");
    }
    assert!(LocalSocksAuth::from_bytes(&record(&"u".repeat(255), &"p".repeat(255))).is_ok());
    for (user, password) in [
        ("", "p".to_owned()),
        ("u", String::new()),
        ("u", "é".repeat(128)),
    ] {
        let error = LocalSocksAuth::from_bytes(&record(user, &password)).unwrap_err();
        assert_eq!(error.to_string(), "local SOCKS credential rejected");
    }
}

#[test]
fn malformed_version_unknown_fields_and_oversize_refuse() {
    for raw in [
        br#"{"version":2,"username":"u","password":"p"}"#.as_slice(),
        br#"{"version":1,"username":"u","password":"p","device_key":"unused"}"#,
        br#"{"version":1,"username":"u"}"#,
        br#"{"version":1,"username":"u","password":"p""#,
    ] {
        assert_eq!(
            LocalSocksAuth::from_bytes(raw).unwrap_err().to_string(),
            "local SOCKS credential rejected"
        );
    }
    assert!(LocalSocksAuth::from_bytes(&vec![b' '; 1025]).is_err());
    assert!(LocalSocksAuth::load(Path::new("relative-record.json")).is_err());
}

#[test]
fn private_existing_record_is_read_without_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("local-auth.json");
    let raw = record("fixture-user", "fixture-private-password");
    crate::secret_file::write_private_new(&path, &raw).unwrap();
    let auth = LocalSocksAuth::load(&path).unwrap();
    assert_eq!(auth.username(), "fixture-user");
    assert_eq!(auth.password(), "fixture-private-password");
    assert_eq!(std::fs::read(&path).unwrap(), raw);
    assert!(LocalSocksAuth::load(&dir.path().join("missing.json")).is_err());
    assert!(!dir.path().join("missing.json").exists());
}

#[cfg(unix)]
#[test]
fn public_symlink_nonregular_and_writable_parent_refuse() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("local-auth.json");
    crate::secret_file::write_private_new(&path, &record("u", "p")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(LocalSocksAuth::load(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("linked.json");
    symlink(&path, &link).unwrap();
    assert!(LocalSocksAuth::load(&link).is_err());
    assert!(LocalSocksAuth::load(dir.path()).is_err());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o722)).unwrap();
    assert!(LocalSocksAuth::load(&path).is_err());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}
