//! Renderer regressions only: no installed authorization, packet or target action.
use super::*;

#[test]
fn paired_request_arguments_refuse_before_input_reads_or_writes() {
    for (path, digest, manifest, manifest_digest, message) in [
        (
            Some(PathBuf::from("unread-private-request")),
            None,
            None,
            None,
            "must be supplied together",
        ),
        (
            None,
            Some("0".repeat(64)),
            None,
            None,
            "must be supplied together",
        ),
        (
            None,
            None,
            Some(PathBuf::from("unread-manifest")),
            None,
            "must be supplied together",
        ),
        (
            None,
            None,
            None,
            Some("0".repeat(64)),
            "must be supplied together",
        ),
        (
            None,
            None,
            Some(PathBuf::from("unread-manifest")),
            Some("0".repeat(64)),
            "requires the private request pair",
        ),
    ] {
        let parent = tempfile::tempdir().unwrap();
        let args = BundleRenderArgs {
            bundle_dir: parent.path().join("unread-bundle"),
            identity_dir: parent.path().join("identity"),
            config_dir: parent.path().join("config"),
            output: parent.path().join("config/new.toml"),
            relay_geneva_request: path,
            relay_geneva_request_sha256: digest,
            relay_geneva_profile_manifest: manifest,
            relay_geneva_profile_sha256: manifest_digest,
            validate_only: false,
        };
        let error = render(&args).unwrap_err();
        assert!(error.to_string().contains(message));
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
    for flag in [
        "--relay-geneva-request",
        "--relay-geneva-request-sha256",
        "--relay-geneva-profile-manifest",
        "--relay-geneva-profile-sha256",
    ] {
        let command = <BundleRenderArgs as clap::Args>::augment_args(clap::Command::new("render"));
        assert!(command
            .try_get_matches_from([
                "render",
                "--bundle-dir",
                "bundle",
                "--identity-dir",
                "identity",
                "--config-dir",
                "config",
                "--output",
                "new.toml",
                flag,
                "unpaired",
            ])
            .is_err());
    }
}

#[cfg(target_os = "linux")]
fn fixture() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    serde_json::Value,
    BundleRenderArgs,
) {
    let bundle = super::tests::fixture();
    let public = serde_json::json!({
        "schema":"aegis_device_bundle_v4", "product_mode":"full-wide-tun", "udp":true,
        "relay_server":"192.0.2.3:443", "outer_server_name":"relay.test",
        "inner_server_name":"origin.test",
        "relay_endpoints":[
            {"server":"192.0.2.3:443","server_name":"relay.test"},
            {"server":"192.0.2.4:443","server_name":"relay-b.test"}
        ],
        "enrollment":{
            "protocol":"aegis-enrollment-v1", "authority_server":"192.0.2.10:8443",
            "outer_server_name":"authority.test", "inner_server_name":"issuer.test",
            "automatic_renewal":true, "renewal_policy":"same-key-v1"
        }
    });
    fs::write(
        bundle.path().join("bundle.json"),
        serde_json::to_vec(&public).unwrap(),
    )
    .unwrap();
    let request = serde_json::json!({
        "schema":"aegis_relay_geneva_managed_request_v1",
        "profile_sha256":profile_digest(bundle.path()).unwrap(),
        "request":{
            "strategy":"[IP:ttl:64]-duplicate(,)-|", "interface":"eth0",
            "local_address":"192.0.2.2", "local_mac":[2,0,0,0,0,2],
            "next_hop_mac":[2,0,0,0,0,3], "outbound_queue":414, "inbound_queue":415,
            "socket_mark":2793, "max_duration_secs":900
        }
    });
    let local = tempfile::tempdir().unwrap();
    let mut args = BundleRenderArgs {
        bundle_dir: bundle.path().to_owned(),
        identity_dir: local.path().join("identity"),
        config_dir: local.path().join("config"),
        output: local.path().join("config/selected.toml"),
        relay_geneva_request: Some(local.path().join("private-request.json")),
        relay_geneva_request_sha256: None,
        relay_geneva_profile_manifest: None,
        relay_geneva_profile_sha256: None,
        validate_only: false,
    };
    write_request(&mut args, &serde_json::to_vec(&request).unwrap());
    (bundle, local, request, args)
}

#[cfg(target_os = "linux")]
fn write_request(args: &mut BundleRenderArgs, bytes: &[u8]) {
    use sha2::{Digest, Sha256};
    let path = args.relay_geneva_request.as_ref().unwrap();
    if path.exists() {
        fs::write(path, bytes).unwrap();
    } else {
        enrollment::write_private_new(path, bytes).unwrap();
    }
    args.relay_geneva_request_sha256 = Some(hex::encode(Sha256::digest(bytes)));
}

#[cfg(target_os = "linux")]
fn assert_refused_before_write(args: &BundleRenderArgs) {
    let error = render(args).unwrap_err();
    assert!(!format!("{error:#}").contains("private-sentinel"));
    assert!(!args.output.exists());
    assert!(!args.identity_dir.exists());
    assert!(!args.config_dir.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn linux_selected_validation_precedes_enrollment_and_real_render_preserves_public_bytes() {
    let (bundle, _local, _request, mut args) = fixture();
    let originals: Vec<_> = MEMBERS
        .iter()
        .map(|name| fs::read(bundle.path().join(name)).unwrap())
        .collect();
    let expected = profile_digest(bundle.path()).unwrap();
    let (_, snapshot_digest, member_pins) = load_snapshot(bundle.path()).unwrap();
    assert_eq!(snapshot_digest, expected);
    for (name, bytes) in MEMBERS.iter().zip(&originals) {
        use sha2::{Digest, Sha256};
        assert_eq!(member_pins[*name], hex::encode(Sha256::digest(bytes)));
    }
    args.validate_only = true;
    render(&args).unwrap();
    assert!(!args.identity_dir.exists());
    assert!(!args.config_dir.exists());
    assert!(!args.output.exists());
    // This is only a local render; no installed profile or guard is minted.
    fs::create_dir(&args.identity_dir).unwrap();
    fs::create_dir(&args.config_dir).unwrap();
    args.validate_only = false;
    render(&args).unwrap();
    let raw = fs::read_to_string(&args.output).unwrap();
    let loaded: aegis_core::Settings = toml::from_str(&raw).unwrap();
    loaded.validate_relay_outer_geneva().unwrap();
    validate_inner_tls_device_settings(WideProductMode::FullWideTun, true, &loaded).unwrap();
    assert!(matches!(loaded.mode, aegis_core::Mode::Relay));
    assert!(!loaded.direct.hybrid_geneva);
    assert!(loaded.direct.geneva_strategy.is_none());
    assert!(!loaded.ingress.allow_fallback);
    assert_eq!(loaded.relay.endpoints.len(), 2);
    assert_eq!(
        loaded.relay.outer_geneva.unwrap().strategy,
        "[IP:ttl:64]-duplicate(,)-|"
    );
    assert_eq!(
        fs::read(args.identity_dir.join("bundle-profile.sha256")).unwrap(),
        expected.as_bytes()
    );
    assert!(!raw.contains("profile_sha256"));
    assert!(!raw.contains(
        args.relay_geneva_request
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
    ));
    assert!(!raw.contains("PRIVATE KEY"));
    for (name, bytes) in MEMBERS.iter().zip(originals) {
        assert_eq!(fs::read(bundle.path().join(name)).unwrap(), bytes);
    }
    assert_eq!(fs::read_dir(bundle.path()).unwrap().count(), 4);
    assert_eq!(fs::read_dir(&args.identity_dir).unwrap().count(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn matching_online_installed_manifest_validates_and_renders_without_installed_grants() {
    use crate::profile_relay_geneva::InstalledProfile;
    use crate::profile_relay_geneva_role::{ExpectedRole, OnlineBundleExpectation};
    use aegis_core::relay_geneva::installed_guard::PublicGuardPolicy;
    use sha2::{Digest, Sha256};

    let (bundle, local, _request, mut args) = fixture();
    let public_bytes: Vec<_> = MEMBERS
        .iter()
        .map(|name| fs::read(bundle.path().join(name)).unwrap())
        .collect();
    let request_bytes = fs::read(args.relay_geneva_request.as_ref().unwrap()).unwrap();
    let (profile, profile_digest, member_pins) = load_snapshot(bundle.path()).unwrap();
    let mut selected =
        policy_settings_with_overlay(&profile, &args.identity_dir, &args.config_dir, false)
            .unwrap();
    select_relay_geneva_request(&args, &profile, &profile_digest, &mut selected).unwrap();
    let request = selected.relay.outer_geneva.as_ref().unwrap();
    let compiled_source = option_env!("AEGIS_BUILD_SOURCE_COMMIT")
        .or(option_env!("AEGIS_BUILD_GIT_SHA"))
        .expect("managed manifest integration requires the actual compiled source pin");
    let mut endpoints = std::iter::once(selected.relay.server.as_str())
        .chain(
            selected
                .relay
                .endpoints
                .iter()
                .map(|endpoint| endpoint.server.as_str()),
        )
        .map(|address| address.parse::<std::net::SocketAddrV4>().unwrap())
        .collect::<Vec<_>>();
    endpoints.sort_unstable();
    endpoints.dedup();
    assert_eq!(
        endpoints,
        vec![
            "192.0.2.3:443".parse::<std::net::SocketAddrV4>().unwrap(),
            "192.0.2.4:443".parse::<std::net::SocketAddrV4>().unwrap()
        ]
    );
    let expected_config = toml::to_string_pretty(&selected).unwrap();
    let manifest = InstalledProfile {
        schema: "aegis_relay_geneva_installed_profile_v1".into(),
        policy: PublicGuardPolicy {
            schema: "aegis_relay_geneva_installed_guard_v1".into(),
            source_commit: compiled_source.into(),
            interface: request.interface.clone(),
            local_address: request.local_address,
            socket_mark: request.socket_mark,
            relay_endpoints: endpoints,
            // Prospective fixture pins are only public proposal data. No
            // executable, installed guard or administrative role is created.
            device_guard_state_sha256: hex::encode(Sha256::digest(
                b"schema=aegis_device_guard_v2\narmed=1\nservice=aegis-client.service\n",
            )),
        },
        role: ExpectedRole {
            executable_path: "/usr/local/bin/aegis-client".into(),
            executable_argument_path: "/usr/local/bin/aegis-client".into(),
            executable_sha256: hex::encode(Sha256::digest(b"prospective test client image")),
            config_argument_path: "/etc/aegis/client/aegis.toml".into(),
            config_file_path: "/etc/aegis/client/aegis.toml".into(),
            config_sha256: hex::encode(Sha256::digest(expected_config.as_bytes())),
            runtime_events_argument_path: "/var/log/aegis-client/runtime-events.jsonl".into(),
            online_bundle: Some(OnlineBundleExpectation {
                argument_path: "/etc/aegis/client/device-bundle".into(),
                members_sha256: member_pins,
            }),
            fragment_path: "/etc/systemd/system/aegis-client.service".into(),
            fragment_sha256: hex::encode(Sha256::digest(include_bytes!(
                "../../packaging/systemd/aegis-client.service"
            ))),
            drop_in_paths_to_sha256: [(
                PathBuf::from(
                    "/etc/systemd/system/aegis-client.service.d/25-relay-geneva-profile.conf",
                ),
                hex::encode(Sha256::digest(include_bytes!(
                    "../../packaging/systemd/25-relay-geneva-profile.conf"
                ))),
            )]
            .into(),
            control_helper_path: "/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh".into(),
            control_helper_sha256: hex::encode(Sha256::digest(include_bytes!(
                "../../scripts/aegis-device-egress-guard.sh"
            ))),
        },
        recovery_helper_sha256: hex::encode(Sha256::digest(include_bytes!(
            "../../scripts/aegis-relay-geneva-profile.sh"
        ))),
    };
    let manifest_path = local.path().join("installed-proposal.json");
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    enrollment::write_private_new(&manifest_path, &manifest_bytes).unwrap();
    args.relay_geneva_profile_manifest = Some(manifest_path.clone());
    args.relay_geneva_profile_sha256 = Some(hex::encode(Sha256::digest(&manifest_bytes)));
    args.validate_only = true;

    // A semantically identical, otherwise valid proposal still needs its exact
    // original raw-byte pin before enrollment or renderer output is created.
    let mut changed_bytes = manifest_bytes.clone();
    changed_bytes.push(b'\n');
    fs::write(&manifest_path, changed_bytes).unwrap();
    assert_refused_before_write(&args);
    fs::write(&manifest_path, &manifest_bytes).unwrap();
    render(&args).unwrap();
    assert!(!args.identity_dir.exists());
    assert!(!args.config_dir.exists());
    assert!(!args.output.exists());
    assert_eq!(fs::read_dir(local.path()).unwrap().count(), 2);

    fs::create_dir(&args.identity_dir).unwrap();
    fs::create_dir(&args.config_dir).unwrap();
    args.validate_only = false;
    render(&args).unwrap();
    let config_bytes = fs::read(&args.output).unwrap();
    assert_eq!(config_bytes, expected_config.as_bytes());
    let configured: aegis_core::Settings =
        toml::from_str(std::str::from_utf8(&config_bytes).unwrap()).unwrap();
    configured.validate_relay_outer_geneva().unwrap();
    validate_inner_tls_device_settings(WideProductMode::FullWideTun, true, &configured).unwrap();
    assert!(matches!(configured.mode, aegis_core::Mode::Relay));
    assert_eq!(
        configured.relay.outer_geneva.as_ref().unwrap().strategy,
        request.strategy
    );
    assert!(configured.relay.inner_tls.is_some());
    assert!(matches!(
        configured.relay.tls_backend,
        aegis_core::RelayTlsBackend::Rustls
    ));
    assert_eq!(configured.relay.server, "192.0.2.3:443");
    assert_eq!(configured.relay.endpoints.len(), 2);
    assert!(matches!(
        configured.relay.transport_priority.as_slice(),
        [aegis_core::TunnelTransportFamily::GrpcStream]
    ));
    assert!(matches!(
        configured.relay.udp_transport_priority.as_deref(),
        Some([aegis_core::TunnelTransportFamily::GrpcDatagram])
    ));
    assert!(!configured.ingress.allow_fallback);
    assert!(!configured.direct.hybrid_geneva);
    assert!(configured.direct.geneva_strategy.is_none());
    assert_eq!(fs::read(&manifest_path).unwrap(), manifest_bytes);
    assert_eq!(
        fs::read(args.relay_geneva_request.as_ref().unwrap()).unwrap(),
        request_bytes
    );
    assert_eq!(
        fs::read(args.identity_dir.join("bundle-profile.sha256")).unwrap(),
        profile_digest.as_bytes()
    );
    for (name, bytes) in MEMBERS.iter().zip(public_bytes) {
        assert_eq!(fs::read(bundle.path().join(name)).unwrap(), bytes);
    }
    assert_eq!(fs::read_dir(bundle.path()).unwrap().count(), 4);
    // The only new managed outputs are the profile pin and private TOML. No
    // installed selected-profile/state/intent, identity key or native grant.
    assert_eq!(fs::read_dir(&args.identity_dir).unwrap().count(), 1);
    assert_eq!(fs::read_dir(&args.config_dir).unwrap().count(), 1);
    assert_eq!(fs::read_dir(local.path()).unwrap().count(), 4);
}

#[cfg(target_os = "linux")]
#[test]
fn pinned_malformed_installed_manifest_refuses_before_enrollment_or_render_writes() {
    use sha2::{Digest, Sha256};

    let (_bundle, local, _request, mut args) = fixture();
    args.validate_only = true;
    let manifest = local.path().join("installed-proposal.json");
    enrollment::write_private_new(&manifest, b"{}").unwrap();
    args.relay_geneva_profile_manifest = Some(manifest.clone());
    args.relay_geneva_profile_sha256 = Some("0".repeat(64));
    assert_refused_before_write(&args);
    for raw in [
        "{}",
        "{\"private-sentinel\":true}",
        "{\"schema\":\"unknown\",\"schema\":\"unknown\"}",
        "{\"private-sentinel\":",
    ] {
        fs::write(&manifest, raw).unwrap();
        args.relay_geneva_profile_sha256 = Some(hex::encode(Sha256::digest(raw.as_bytes())));
        assert_refused_before_write(&args);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn wrong_raw_digest_and_each_changed_public_member_refuse_before_write() {
    let (bundle, _local, _request, mut args) = fixture();
    let exact = args.relay_geneva_request_sha256.clone();
    for invalid in ["0".repeat(64), "A".repeat(64), "0".repeat(63)] {
        args.relay_geneva_request_sha256 = Some(invalid);
        assert_refused_before_write(&args);
    }
    args.relay_geneva_request_sha256 = exact;
    let path = args.relay_geneva_request.as_ref().unwrap();
    let original_request = fs::read(path).unwrap();
    let mut changed = original_request.clone();
    changed.push(b' '); // Same parsed request is insufficient: the exact raw pin must match.
    fs::write(path, changed).unwrap();
    assert_refused_before_write(&args);
    fs::write(path, original_request).unwrap();
    for name in MEMBERS {
        let path = bundle.path().join(name);
        let original = fs::read(&path).unwrap();
        let mut changed = original.clone();
        changed.push(b'\n');
        fs::write(&path, changed).unwrap();
        assert_refused_before_write(&args);
        fs::write(path, original).unwrap();
    }
    let mut public: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.path().join("bundle.json")).unwrap()).unwrap();
    public["relay_endpoints"][1]["server"] = "192.0.2.5:443".into();
    fs::write(
        bundle.path().join("bundle.json"),
        serde_json::to_vec(&public).unwrap(),
    )
    .unwrap();
    assert_refused_before_write(&args);
}

#[cfg(target_os = "linux")]
#[test]
fn typed_private_schema_duplicates_policy_and_error_privacy_refuse_before_write() {
    let (_bundle, _local, request, mut args) = fixture();
    args.validate_only = true;
    let mut invalid = Vec::new();
    for (outer, field, field_value) in [
        (true, "schema", serde_json::json!("other")),
        (true, "profile_sha256", serde_json::json!("0".repeat(64))),
        (true, "private-sentinel", serde_json::json!(true)),
        (false, "private-sentinel", serde_json::json!(true)),
        (false, "strategy", serde_json::json!("private-sentinel")),
        (false, "local_address", serde_json::json!("0.0.0.0")),
        (false, "outbound_queue", serde_json::json!(415)),
        (false, "socket_mark", serde_json::json!(0)),
        (false, "max_duration_secs", serde_json::json!(3601)),
        (false, "local_mac", serde_json::json!([0, 0, 0, 0, 0, 0])),
        (false, "target", serde_json::json!("private-sentinel")),
    ] {
        let mut changed = request.clone();
        if outer {
            changed[field] = field_value;
        } else {
            changed["request"][field] = field_value;
        }
        invalid.push(serde_json::to_vec(&changed).unwrap());
    }
    let raw = serde_json::to_string(&request).unwrap();
    invalid.push(
        format!(
            "{},\"prof\\u0069le_sha256\":\"{}\"}}",
            &raw[..raw.len() - 1],
            request["profile_sha256"].as_str().unwrap()
        )
        .into_bytes(),
    );
    invalid.push(
        raw.replace(
            "\"socket_mark\":",
            "\"socket_mark\":2793,\"socket\\u005fmark\":",
        )
        .into_bytes(),
    );
    invalid.push(b"{\"private-sentinel\":".to_vec());
    for bytes in invalid {
        write_request(&mut args, &bytes);
        assert_refused_before_write(&args);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn wrong_profile_mode_or_unusable_pool_cannot_select_geneva() {
    let (bundle, _local, mut request, mut args) = fixture();
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.path().join("bundle.json")).unwrap()).unwrap();
    for case in 0..3 {
        let mut public = original.clone();
        match case {
            0 => public["product_mode"] = "socks-only".into(),
            1 => public["relay_endpoints"][1]["server"] = "192.0.2.2:443".into(),
            _ => public["relay_endpoints"][1]["server"] = "[2001:db8::1]:443".into(),
        }
        fs::write(
            bundle.path().join("bundle.json"),
            serde_json::to_vec(&public).unwrap(),
        )
        .unwrap();
        request["profile_sha256"] = profile_digest(bundle.path()).unwrap().into();
        write_request(&mut args, &serde_json::to_vec(&request).unwrap());
        assert_refused_before_write(&args);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn private_file_custody_boundaries_and_public_output_refuse_before_pin() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (bundle, local, _request, mut args) = fixture();
    let original = args.relay_geneva_request.clone().unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();
    args.validate_only = true;
    assert_refused_before_write(&args);
    fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
    let linked = local.path().join("linked-request");
    fs::hard_link(&original, &linked).unwrap();
    assert_refused_before_write(&args);
    fs::remove_file(linked).unwrap();
    let alias = local.path().join("request-alias");
    symlink(&original, &alias).unwrap();
    args.relay_geneva_request = Some(alias);
    assert_refused_before_write(&args);
    args.relay_geneva_request = Some(PathBuf::from("relative-request"));
    assert_refused_before_write(&args);
    args.relay_geneva_request = Some(original.clone());
    let unsafe_parent = local.path().join("unsafe");
    fs::create_dir(&unsafe_parent).unwrap();
    fs::copy(&original, unsafe_parent.join("request")).unwrap();
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
    args.relay_geneva_request = Some(unsafe_parent.join("request"));
    assert_refused_before_write(&args);
    args.relay_geneva_request = Some(original);
    let good = fs::read(args.relay_geneva_request.as_ref().unwrap()).unwrap();
    write_request(&mut args, &vec![b' '; MAX_PUBLIC_BYTES as usize + 1]);
    assert_refused_before_write(&args);
    write_request(&mut args, &good);
    args.output = bundle.path().join("private-output.toml");
    assert_refused_before_write(&args);
    assert_eq!(fs::read_dir(bundle.path()).unwrap().count(), 4);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn selected_request_never_falls_back_on_other_platforms() {
    let bundle = super::tests::fixture();
    let parent = tempfile::tempdir().unwrap();
    let args = BundleRenderArgs {
        bundle_dir: bundle.path().to_owned(),
        identity_dir: parent.path().join("identity"),
        config_dir: parent.path().join("config"),
        output: parent.path().join("new.toml"),
        relay_geneva_request: Some(parent.path().join("unread-request")),
        relay_geneva_request_sha256: Some("0".repeat(64)),
        relay_geneva_profile_manifest: None,
        relay_geneva_profile_sha256: None,
        validate_only: true,
    };
    assert!(render(&args)
        .unwrap_err()
        .to_string()
        .contains("requires Linux"));
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}
