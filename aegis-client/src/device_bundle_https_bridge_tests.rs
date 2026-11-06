use super::*;
use aegis_core::https_bridge::{ClientSettings, SIDECAR};

fn overlay(identity: &Path, authority: &str) -> ClientSettings {
    let bridge = ClientSettings {
        authority: authority.into(),
        path: "/private/stream".into(),
        enrollment_path: "/private/enroll".into(),
        credential_file: identity.join("bridge-credential"),
    };
    enrollment::write_private_new(&bridge.credential_file, &[b'a'; 64]).unwrap();
    enrollment::write_private_new(
        &identity.join(SIDECAR),
        toml::to_string(&bridge).unwrap().as_bytes(),
    )
    .unwrap();
    bridge
}

#[test]
fn private_bridge_survives_render_and_online_renewal_without_public_changes() {
    let bundle = tests::fixture();
    let identity = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let mut public: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.path().join("bundle.json")).unwrap()).unwrap();
    public["schema"] = "aegis_device_bundle_v4".into();
    public["product_mode"] = "socks-only".into();
    public["relay_server"] = "127.0.0.1:443".into();
    public["relay_endpoints"] = serde_json::json!([
        {"server":"127.0.0.1:443", "server_name":"relay.test"},
        {"server":"127.0.0.2:443", "server_name":"bridge.test"}
    ]);
    public["carrier_program"] = serde_json::json!({
        "routes":[
            {"channel":"direct_h2", "endpoint_index":0},
            {"channel":"own_https_bridge", "endpoint_index":1},
        ],
        "bridge":{"authority":"bridge.test", "path":"/private/stream",
            "enrollment_path":"/private/enroll"}
    });
    public["enrollment"] = serde_json::json!({
        "protocol":"aegis-enrollment-v1", "authority_server":"authority.test:443",
        "outer_server_name":"bridge.test", "inner_server_name":"enroll.test",
        "automatic_renewal":true, "renewal_policy":"same-key-v1"
    });
    fs::write(
        bundle.path().join("bundle.json"),
        serde_json::to_vec(&public).unwrap(),
    )
    .unwrap();
    let public_before = load_snapshot(bundle.path()).unwrap();
    let preview_identity = identity.path().join("not-yet-enrolled");
    let preview_output = config.path().join("preview.toml");
    render(&BundleRenderArgs {
        bundle_dir: bundle.path().to_owned(),
        identity_dir: preview_identity.clone(),
        config_dir: config.path().to_owned(),
        output: preview_output.clone(),
        relay_geneva_request: None,
        relay_geneva_request_sha256: None,
        relay_geneva_profile_manifest: None,
        relay_geneva_profile_sha256: None,
        validate_only: true,
    })
    .unwrap();
    assert!(!preview_identity.exists() && !preview_output.exists());
    assert!(settings(&public_before.0, identity.path(), config.path()).is_err());
    let bridge = overlay(identity.path(), "bridge.test");
    for (source, destination) in [("outer-ca.pem", "ca.pem"), ("inner-ca.pem", "inner-ca.pem")] {
        fs::copy(bundle.path().join(source), config.path().join(destination)).unwrap();
    }
    fs::copy(
        bundle.path().join("device-ca.pem"),
        identity.path().join("device-ca.pem"),
    )
    .unwrap();
    let output = config.path().join("rendered.toml");
    render(&BundleRenderArgs {
        bundle_dir: bundle.path().to_owned(),
        identity_dir: identity.path().to_owned(),
        config_dir: config.path().to_owned(),
        output: output.clone(),
        relay_geneva_request: None,
        relay_geneva_request_sha256: None,
        relay_geneva_profile_manifest: None,
        relay_geneva_profile_sha256: None,
        validate_only: false,
    })
    .unwrap();
    let rendered = fs::read_to_string(&output).unwrap();
    assert!(!rendered.contains(&"a".repeat(64)));
    let managed: aegis_core::Settings = toml::from_str(&rendered).unwrap();
    assert_eq!(managed.relay.https_bridge, Some(bridge.clone()));
    assert_eq!(
        managed.relay.carrier_program,
        public_before.0.carrier_program
    );
    assert_eq!(managed.relay.endpoints.len(), 2);
    let (renewal, _) = online::OnlineProfile::for_runtime(bundle.path(), &managed).unwrap();
    assert_eq!(renewal.carrier().https_bridge, Some(bridge.clone()));
    assert!(renewal.carrier().inner_tls.is_none());
    let mut stripped = managed.clone();
    stripped.relay.https_bridge = None;
    assert!(online::OnlineProfile::for_runtime(bundle.path(), &stripped).is_err());
    let mut substituted = managed;
    substituted.relay.https_bridge.as_mut().unwrap().path = "/private/substituted".into();
    assert!(online::OnlineProfile::for_runtime(bundle.path(), &substituted).is_err());
    let public_after = load_snapshot(bundle.path()).unwrap();
    assert_eq!(public_before.1, public_after.1);
    assert_eq!(public_before.2, public_after.2);
    assert_eq!(fs::read_dir(bundle.path()).unwrap().count(), 4);
    assert!(inspection(&public_after.0)
        .unwrap()
        .get("https_bridge")
        .is_none());
    let mut changed: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.path().join("bundle.json")).unwrap()).unwrap();
    changed["carrier_program"]["bridge"]["path"] = "/private/other".into();
    let changed_profile = validate_profile(&serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(settings(&changed_profile, identity.path(), config.path()).is_err());
    changed["carrier_program"]["bridge"]["authority"] = "other.test".into();
    assert!(validate_profile(&serde_json::to_vec(&changed).unwrap()).is_err());
}

#[test]
fn bridge_sidecar_only_absent_leaf_is_optional_and_errors_are_sanitized() {
    let parent = tempfile::tempdir().unwrap();
    assert!(online::load_https_bridge(&parent.path().join("missing-identity")).is_err());
    assert!(online::load_https_bridge(parent.path()).unwrap().is_none());
    enrollment::write_private_new(&parent.path().join(SIDECAR), b"private-sentinel = [invalid")
        .unwrap();
    let error = online::load_https_bridge(parent.path()).unwrap_err();
    assert!(!format!("{error:#}").contains("private-sentinel"));
    fs::remove_file(parent.path().join(SIDECAR)).unwrap();
    let mut bridge = overlay(parent.path(), "relay.test");
    for path in [
        PathBuf::from("relative"),
        parent.path().join("device.key"),
        parent.path().join("device.pem"),
    ] {
        bridge.credential_file = path;
        fs::write(
            parent.path().join(SIDECAR),
            toml::to_string(&bridge).unwrap(),
        )
        .unwrap();
        assert!(online::load_https_bridge(parent.path()).is_err());
    }
}

#[cfg(unix)]
#[test]
fn bridge_sidecar_links_permissions_and_credential_aliases_fail_closed() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let identity = tempfile::tempdir().unwrap();
    let bridge = overlay(identity.path(), "relay.test");
    let sidecar = identity.path().join(SIDECAR);
    fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(online::load_https_bridge(identity.path()).is_err());
    fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&sidecar, identity.path().join("retained-sidecar")).unwrap();
    symlink(identity.path().join("retained-sidecar"), &sidecar).unwrap();
    assert!(online::load_https_bridge(identity.path()).is_err());
    fs::remove_file(&sidecar).unwrap();
    fs::rename(identity.path().join("retained-sidecar"), &sidecar).unwrap();
    fs::hard_link(&bridge.credential_file, identity.path().join("device.key")).unwrap();
    assert!(online::load_https_bridge(identity.path()).is_err());
}
