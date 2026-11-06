use super::*;
use online::{OnlineMigration, OnlineProfile};
use serde_json::{json, Value};

fn metadata() -> Value {
    json!({"protocol":"aegis-enrollment-v1", "authority_server":"authority.test:443",
        "outer_server_name":"front.test", "inner_server_name":"enroll.test",
        "automatic_renewal":true, "renewal_policy":"same-key-v1"})
}

fn v3(directory: &Path, full_wide: bool) -> Value {
    let mut p: Value =
        serde_json::from_slice(&fs::read(directory.join("bundle.json")).unwrap()).unwrap();
    p["schema"] = "aegis_device_bundle_v3".into();
    p["product_mode"] = if full_wide {
        "full-wide-tun"
    } else {
        "socks-only"
    }
    .into();
    p["udp"] = full_wide.into();
    p["enrollment"] = metadata();
    if full_wide {
        p["relay_server"] = "198.51.100.10:443".into();
        p["enrollment"]["authority_server"] = "198.51.100.11:8443".into();
    }
    p
}

fn write(directory: &Path, profile: &Value) {
    fs::write(
        directory.join("bundle.json"),
        serde_json::to_vec(profile).unwrap(),
    )
    .unwrap();
}

#[test]
fn online_carrier_retains_the_same_pinned_ech_request_and_refuses_clear_ip_name() {
    let bundle = tests::fixture();
    let identity = tempfile::tempdir().unwrap();
    let encoded = crate::relay::inline_ech_fixture();
    let mut profile = v3(bundle.path(), false);
    profile["ech_config_list"] = encoded.clone().into();
    write(bundle.path(), &profile);
    assert!(validate_profile(&serde_json::to_vec(&profile).unwrap()).is_ok());
    pin_profile(bundle.path(), identity.path()).unwrap();
    let loaded = OnlineProfile::load(bundle.path(), identity.path()).unwrap();
    assert_eq!(
        loaded.carrier().ech_config_list_base64.as_deref(),
        Some(encoded.as_str())
    );
    assert!(loaded.carrier().ech_config_list.is_none());
    assert_eq!(
        loaded.carrier().tls_backend,
        aegis_core::RelayTlsBackend::Rustls
    );
    assert_eq!(
        loaded.carrier().transport_priority,
        vec![aegis_core::TunnelTransportFamily::GrpcStream]
    );
    assert_eq!(loaded.carrier().udp_transport_priority, Some(Vec::new()));
    profile["enrollment"]["outer_server_name"] = "192.0.2.1".into();
    assert!(validate_profile(&serde_json::to_vec(&profile).unwrap()).is_err());
}

#[test]
fn installed_online_profile_refuses_ech_removal_substitution_or_file_downgrade() {
    let bundle = tests::fixture();
    let identity = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let mut profile = v3(bundle.path(), false);
    profile["ech_config_list"] = crate::relay::inline_ech_fixture().into();
    write(bundle.path(), &profile);
    for (source, destination) in [("outer-ca.pem", "ca.pem"), ("inner-ca.pem", "inner-ca.pem")] {
        fs::copy(bundle.path().join(source), config.path().join(destination)).unwrap();
    }
    fs::copy(
        bundle.path().join("device-ca.pem"),
        identity.path().join("device-ca.pem"),
    )
    .unwrap();
    pin_profile(bundle.path(), identity.path()).unwrap();
    let loaded = load(bundle.path()).unwrap();
    let managed = policy_settings(&loaded, identity.path(), config.path()).unwrap();
    OnlineProfile::for_runtime(bundle.path(), &managed).unwrap();
    let mut clear = managed.clone();
    clear.relay.ech_config_list_base64 = None;
    assert!(OnlineProfile::for_runtime(bundle.path(), &clear).is_err());
    let mut substituted = managed.clone();
    substituted.relay.ech_config_list_base64 = Some("different".into());
    assert!(OnlineProfile::for_runtime(bundle.path(), &substituted).is_err());
    let mut file = managed;
    file.relay.ech_config_list = Some("different.bin".into());
    assert!(OnlineProfile::for_runtime(bundle.path(), &file).is_err());
}

#[test]
fn v3_preserves_data_policy_and_requires_an_existing_exact_trust_pin() {
    for full_wide in [false, true] {
        let directory = tests::fixture();
        write(directory.path(), &v3(directory.path(), full_wide));
        let identity = tempfile::tempdir().unwrap();
        assert!(OnlineProfile::load(directory.path(), identity.path()).is_err());
        assert!(!identity.path().join("bundle-profile.sha256").exists());
        pin_profile(directory.path(), identity.path()).unwrap();
        let online = OnlineProfile::load(directory.path(), identity.path()).unwrap();
        assert_eq!(online.digest(), profile_digest(directory.path()).unwrap());
        assert!(online.carrier().auth_token.is_empty());
        assert!(online.carrier().inner_tls.is_none());
        assert_eq!(online.tls().server_name, "enroll.test");
        assert_eq!(
            online.tls().server_ca,
            directory.path().join("inner-ca.pem")
        );
        let inspected = inspection(&load(directory.path()).unwrap()).unwrap();
        assert_eq!(inspected["resolved"]["inner_tls"], true);
        assert_eq!(inspected["resolved"]["native_fallback"], false);
        assert_eq!(inspected["resolved"]["tcp_transport"], "grpc_stream");
        assert_eq!(
            inspected["resolved"]["udp_transport"],
            if full_wide {
                "grpc_datagram"
            } else {
                "disabled"
            }
        );
        let mut changed = v3(directory.path(), full_wide);
        changed["enrollment"]["inner_server_name"] = "substituted.test".into();
        write(directory.path(), &changed);
        assert!(OnlineProfile::load(directory.path(), identity.path()).is_err());
    }
}

#[test]
fn old_schemas_cannot_silently_enable_online_and_v3_options_are_closed() {
    let directory = tests::fixture();
    for schema in ["aegis_device_bundle_v1", "aegis_device_bundle_v2"] {
        let mut p = v3(directory.path(), false);
        p["schema"] = schema.into();
        if schema.ends_with("v1") {
            p.as_object_mut().unwrap().remove("product_mode");
        }
        assert!(validate_profile(&serde_json::to_vec(&p).unwrap()).is_err());
        p["enrollment"] = Value::Null;
        assert!(validate_profile(&serde_json::to_vec(&p).unwrap()).is_err());
    }
    let base = v3(directory.path(), false);
    for (field, value) in [
        ("protocol", json!("other")),
        ("automatic_renewal", json!(false)),
        ("renewal_policy", json!("new-key")),
        ("invitation", json!("secret")),
        ("server_ca", json!("/untrusted/ca.pem")),
        ("path", json!("/tunnel.v1.Channel/Connect")),
    ] {
        let mut p = base.clone();
        p["enrollment"][field] = value;
        assert!(
            validate_profile(&serde_json::to_vec(&p).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut p = base;
    p.as_object_mut().unwrap().remove("enrollment");
    assert!(validate_profile(&serde_json::to_vec(&p).unwrap()).is_err());
}

#[test]
fn authority_rejects_userinfo_url_fragments_and_ambiguous_hosts_before_create() {
    let directory = tests::fixture();
    for value in [
        "user@authority.test:443",
        "authority.test:443/path",
        "authority.test:443?q=1",
        "authority.test:443#x",
        "authority.test:443\\path",
        "authority.test:443\n",
        "author ity.test:443",
        "authority.test",
        ":443",
        "authority.test:0",
        "authority.test:99999",
        "https://authority.test:443",
        "authority.test:443\0",
        "[fe80::1%eth0]:443",
    ] {
        let mut p = v3(directory.path(), false);
        p["enrollment"]["authority_server"] = value.into();
        assert!(
            validate_profile(&serde_json::to_vec(&p).unwrap()).is_err(),
            "{value:?}"
        );
    }
    let mut p = v3(directory.path(), false);
    p["enrollment"]["authority_server"] = "user@authority.test:443".into();
    write(directory.path(), &p);
    let out = directory.path().join("must-not-exist");
    assert!(create(&BundleCreateArgs {
        bundle_dir: out.clone(),
        profile: directory.path().join("bundle.json"),
        outer_ca: directory.path().join("outer-ca.pem"),
        inner_ca: directory.path().join("inner-ca.pem"),
        device_ca: directory.path().join("device-ca.pem")
    })
    .is_err());
    assert!(!out.exists());
}

#[test]
fn full_wide_authority_is_independently_pinned_ipv4_outside_fake_ip_pool() {
    let directory = tests::fixture();
    let good = v3(directory.path(), true);
    assert!(validate_profile(&serde_json::to_vec(&good).unwrap()).is_ok());
    for address in [
        "authority.test:443",
        "[2001:db8::1]:443",
        "198.18.1.2:443",
        "198.19.1.2:443",
        "0.0.0.0:443",
        "224.1.1.1:443",
        "255.255.255.255:443",
    ] {
        let mut p = good.clone();
        p["enrollment"]["authority_server"] = address.into();
        assert!(
            validate_profile(&serde_json::to_vec(&p).unwrap()).is_err(),
            "{address}"
        );
    }
}

#[test]
fn validated_online_migration_is_only_an_intent_and_never_rewrites_pin() {
    let old = tests::fixture();
    let new = tests::fixture();
    for member in &MEMBERS[1..] {
        fs::copy(old.path().join(member), new.path().join(member)).unwrap();
    }
    let p = v3(new.path(), false);
    write(new.path(), &p);
    let identity = tempfile::tempdir().unwrap();
    pin_profile(old.path(), identity.path()).unwrap();
    let original = fs::read(identity.path().join("bundle-profile.sha256")).unwrap();
    let intent = OnlineMigration::validate(old.path(), new.path()).unwrap();
    assert_eq!(intent.old_digest().as_bytes(), original);
    assert_ne!(intent.old_digest(), intent.new_digest());
    assert_eq!(
        fs::read(identity.path().join("bundle-profile.sha256")).unwrap(),
        original
    );
    for field in ["relay_server", "outer_server_name", "inner_server_name"] {
        let mut changed = p.clone();
        changed[field] = if field == "relay_server" {
            "other.test:443"
        } else {
            "other.test"
        }
        .into();
        write(new.path(), &changed);
        assert!(OnlineMigration::validate(old.path(), new.path()).is_err());
    }
    write(new.path(), &p);
    let other = tests::fixture();
    fs::copy(
        other.path().join("outer-ca.pem"),
        new.path().join("outer-ca.pem"),
    )
    .unwrap();
    assert!(OnlineMigration::validate(old.path(), new.path()).is_err());
}

#[test]
fn full_wide_v2_migration_preserves_explicit_capture_and_udp_policy() {
    let old = tests::fixture();
    let new = tests::fixture();
    for member in &MEMBERS[1..] {
        fs::copy(old.path().join(member), new.path().join(member)).unwrap();
    }
    let successor = v3(new.path(), true);
    let mut predecessor = successor.clone();
    predecessor["schema"] = "aegis_device_bundle_v2".into();
    predecessor.as_object_mut().unwrap().remove("enrollment");
    write(old.path(), &predecessor);
    write(new.path(), &successor);
    OnlineMigration::validate(old.path(), new.path()).unwrap();
    let mut downgraded = successor;
    downgraded["product_mode"] = "socks-only".into();
    downgraded["udp"] = false.into();
    write(new.path(), &downgraded);
    assert!(OnlineMigration::validate(old.path(), new.path()).is_err());
    downgraded["product_mode"] = "full-wide-tun".into();
    write(new.path(), &downgraded);
    assert!(OnlineMigration::validate(old.path(), new.path()).is_err());
}

fn v4(directory: &Path) -> Value {
    let mut profile = v3(directory, true);
    profile["schema"] = "aegis_device_bundle_v4".into();
    profile["relay_endpoints"] = json!([
        {"server":profile["relay_server"], "server_name":profile["outer_server_name"]},
        {"server":"198.51.100.20:443", "server_name":"backup.test"}
    ]);
    profile
}

#[test]
fn v4_pool_is_bound_to_runtime_and_the_existing_identity_pin() {
    let directory = tests::fixture();
    let profile = v4(directory.path());
    write(directory.path(), &profile);
    let identity = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    fs::copy(
        directory.path().join("device-ca.pem"),
        identity.path().join("device-ca.pem"),
    )
    .unwrap();
    fs::copy(
        directory.path().join("outer-ca.pem"),
        config.path().join("ca.pem"),
    )
    .unwrap();
    fs::copy(
        directory.path().join("inner-ca.pem"),
        config.path().join("inner-ca.pem"),
    )
    .unwrap();
    pin_profile(directory.path(), identity.path()).unwrap();
    let loaded = load(directory.path()).unwrap();
    let settings = policy_settings(&loaded, identity.path(), config.path()).unwrap();
    assert_eq!(settings.relay.endpoints.len(), 2);
    OnlineProfile::for_runtime(directory.path(), &settings).unwrap();
    let mut substituted = settings.clone();
    substituted.relay.endpoints[1].server = "198.51.100.21:443".into();
    assert!(OnlineProfile::for_runtime(directory.path(), &substituted).is_err());
    substituted = settings.clone();
    substituted.relay.endpoints[1].server_name = "substitute.test".into();
    assert!(OnlineProfile::for_runtime(directory.path(), &substituted).is_err());
    substituted = settings;
    substituted.relay.endpoints.pop();
    assert!(OnlineProfile::for_runtime(directory.path(), &substituted).is_err());
    let mut changed = profile;
    changed["relay_endpoints"][1]["server"] = "198.51.100.21:443".into();
    write(directory.path(), &changed);
    assert!(OnlineProfile::load(directory.path(), identity.path()).is_err());
}

#[test]
fn v4_rejects_ambiguous_pools_dns_fallback_and_legacy_schema_injection() {
    let directory = tests::fixture();
    let good = v4(directory.path());
    assert!(validate_profile(&serde_json::to_vec(&good).unwrap()).is_ok());
    for pool in [
        Value::Null,
        json!([]),
        json!([good["relay_endpoints"][1]]),
        json!([good["relay_endpoints"][0], good["relay_endpoints"][0]]),
        json!(vec![good["relay_endpoints"][0].clone(); 17]),
    ] {
        let mut bad = good.clone();
        bad["relay_endpoints"] = pool;
        assert!(validate_profile(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    for server in [
        "backup.test:443",
        "198.18.0.1:443",
        "198.19.0.1:443",
        "[2001:db8::1]:443",
        "0.0.0.0:443",
        "224.0.0.1:443",
        "198.51.100.20:0",
    ] {
        let mut bad = good.clone();
        bad["relay_endpoints"][1]["server"] = server.into();
        assert!(
            validate_profile(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "{server}"
        );
    }
    for field in ["auth_token", "masque_server", "inner_server_name"] {
        let mut bad = good.clone();
        bad["relay_endpoints"][1][field] = "injected".into();
        assert!(validate_profile(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let mut bad = good.clone();
    bad.as_object_mut().unwrap().remove("relay_endpoints");
    assert!(validate_profile(&serde_json::to_vec(&bad).unwrap()).is_err());
    for schema in [
        "aegis_device_bundle_v1",
        "aegis_device_bundle_v2",
        "aegis_device_bundle_v3",
    ] {
        let mut bad = good.clone();
        bad["schema"] = schema.into();
        assert!(validate_profile(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
}

#[test]
fn installed_online_profile_binds_shaping_plan_and_paper_bandit_before_private_overlay() {
    let bundle = tests::fixture();
    let identity = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let mut public = v3(bundle.path(), false);
    public["schema"] = json!("aegis_device_bundle_v4");
    public["relay_server"] = json!("127.0.0.1:443");
    public["relay_endpoints"] = json!([{ "server":"127.0.0.1:443","server_name":public["outer_server_name"] },{ "server":"127.0.0.2:443","server_name":public["outer_server_name"] }]);
    public["endpoint_bandit"] = json!({"algorithm":{"algorithm":"sliding_window","rounds":16,"xi":1.0},"max_profiles":16,"max_contexts_per_profile":16,"pre_auth_block_ms":1000});
    public["endpoint_bandit"]["dependency_policy"] = json!({
        "a":{"nodes":[0,1,2],"edges":[[0,1],[1,2]]},
        "b":{"nodes":[0,1,2],"edges":[[0,1],[1,2]]},
        "dependency_pairs":[[0,0],[1,1],[2,2]],"endpoint_nodes":[0,2],
        "anchor_a":1,"anchor_b":1,"unavailable_b":[0]
    });
    public["authenticated_shaping"] = json!({"payload_bytes":1024,"cadence_ms":10,
        "buffer_bytes":4096,"max_wire_bytes":8388608,"io_timeout_ms":1000,
        "session_timeout_ms":10000,"max_queue_delay_ms":10000});
    public["privacy_plan"] = json!({"packet_modifiers":["constant_cadence"],
        "framing_budget":{"max_payload_bytes":1024,"max_buffer_bytes":4096,
            "max_wire_bytes_per_direction":8388608,"max_session_ms":10000,"max_queue_delay_ms":10000}});
    public["recent_routes"] = json!({"window_ms":60000,"max_observations":256,
        "diversity_penalty":0.25,"paper_algorithm":{"algorithm":"sliding_window","rounds":16,"xi":1.0}});
    write(bundle.path(), &public);
    for (source, name) in [("outer-ca.pem", "ca.pem"), ("inner-ca.pem", "inner-ca.pem")] {
        fs::copy(bundle.path().join(source), config.path().join(name)).unwrap();
    }
    fs::copy(
        bundle.path().join("device-ca.pem"),
        identity.path().join("device-ca.pem"),
    )
    .unwrap();
    pin_profile(bundle.path(), identity.path()).unwrap();
    let profile = load(bundle.path()).unwrap();
    let managed = policy_settings(&profile, identity.path(), config.path()).unwrap();
    OnlineProfile::for_runtime(bundle.path(), &managed).unwrap();
    let mut mutations = Vec::new();
    let mut changed = managed.clone();
    changed
        .relay
        .endpoint_bandit
        .as_mut()
        .unwrap()
        .dependency_policy = None;
    mutations.push(changed);
    let mut changed = managed.clone();
    changed
        .relay
        .endpoint_bandit
        .as_mut()
        .unwrap()
        .dependency_policy
        .as_mut()
        .unwrap()
        .endpoint_nodes
        .swap(0, 1);
    mutations.push(changed);
    let mut changed = managed.clone();
    changed
        .relay
        .endpoint_bandit
        .as_mut()
        .unwrap()
        .dependency_policy
        .as_mut()
        .unwrap()
        .unavailable_b
        .clear();
    mutations.push(changed);

    let mut changed = managed.clone();
    changed.relay.endpoint_bandit = None;
    mutations.push(changed);
    let mut changed = managed.clone();
    changed.relay.endpoint_bandit.as_mut().unwrap().algorithm =
        aegis_core::brain::recent_routes::paper_bandit::PaperAlgorithm::Discounted {
            gamma: 0.9,
            xi: 1.0,
        };
    mutations.push(changed);
    let mut changed = managed.clone();
    changed.relay.authenticated_shaping = None;
    changed.privacy_plan = None;
    mutations.push(changed);
    let mut changed = managed.clone();
    changed
        .relay
        .authenticated_shaping
        .as_mut()
        .unwrap()
        .payload_bytes = 512;
    mutations.push(changed);
    let mut changed = managed.clone();
    changed.privacy_plan = None;
    mutations.push(changed);
    let mut changed = managed.clone();
    changed
        .privacy_plan
        .as_mut()
        .unwrap()
        .diagnostics
        .push(aegis_core::traffic_privacy::plan::Diagnostic::LeakageAnalysis);
    mutations.push(changed);
    let mut changed = managed.clone();
    changed.direct.recent_routes = None;
    mutations.push(changed);
    let mut changed = managed.clone();
    changed
        .direct
        .recent_routes
        .as_mut()
        .unwrap()
        .paper_algorithm = Some(
        aegis_core::brain::recent_routes::paper_bandit::PaperAlgorithm::Discounted {
            gamma: 0.9,
            xi: 1.0,
        },
    );
    mutations.push(changed);
    for changed in &mutations {
        changed.validate_privacy_plan().unwrap();
        let error = OnlineProfile::for_runtime(bundle.path(), changed)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("research policy differs"), "{error}");
    }
    // Malformed private overlay is an actual read barrier: the unchanged policy
    // reaches it, while every otherwise admissible substituted policy refuses first.
    enrollment::write_private_new(
        &identity.path().join(aegis_core::https_bridge::SIDECAR),
        b"invalid-private-overlay",
    )
    .unwrap();
    assert!(OnlineProfile::for_runtime(bundle.path(), &managed)
        .err()
        .unwrap()
        .to_string()
        .contains("HTTPS bridge sidecar rejected"));
    for changed in &mutations {
        assert!(OnlineProfile::for_runtime(bundle.path(), changed)
            .err()
            .unwrap()
            .to_string()
            .contains("research policy differs"));
    }
}

#[test]
fn installed_online_absent_plan_is_distinct_from_admissible_empty_plan() {
    let bundle = tests::fixture();
    let identity = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    write(bundle.path(), &v3(bundle.path(), false));
    for (source, name) in [("outer-ca.pem", "ca.pem"), ("inner-ca.pem", "inner-ca.pem")] {
        fs::copy(bundle.path().join(source), config.path().join(name)).unwrap();
    }
    fs::copy(
        bundle.path().join("device-ca.pem"),
        identity.path().join("device-ca.pem"),
    )
    .unwrap();
    pin_profile(bundle.path(), identity.path()).unwrap();
    let profile = load(bundle.path()).unwrap();
    let mut managed = policy_settings(&profile, identity.path(), config.path()).unwrap();
    OnlineProfile::for_runtime(bundle.path(), &managed).unwrap();
    managed.privacy_plan = Some(Default::default());
    managed.validate_privacy_plan().unwrap();
    assert!(OnlineProfile::for_runtime(bundle.path(), &managed)
        .err()
        .unwrap()
        .to_string()
        .contains("research policy differs"));
}

/// CP-D3: the installed traffic configuration carries exactly the failover
/// policy the immutable public profile yields (explicit or the pool default);
/// removal or substitution refuses before network access.
#[test]
fn installed_online_profile_binds_the_carrier_failover_policy() {
    for explicit in [None, Some(json!({"base_cooldown_ms": 2000}))] {
        let bundle = tests::fixture();
        let identity = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let mut profile = v3(bundle.path(), true);
        profile["schema"] = "aegis_device_bundle_v4".into();
        profile["relay_endpoints"] = json!([
            {"server": "198.51.100.10:443", "server_name": "relay.test"},
            {"server": "203.0.113.20:443", "server_name": "front.test"}
        ]);
        if let Some(policy) = &explicit {
            profile["carrier_failover"] = policy.clone();
        }
        write(bundle.path(), &profile);
        for (source, destination) in [("outer-ca.pem", "ca.pem"), ("inner-ca.pem", "inner-ca.pem")]
        {
            fs::copy(bundle.path().join(source), config.path().join(destination)).unwrap();
        }
        fs::copy(
            bundle.path().join("device-ca.pem"),
            identity.path().join("device-ca.pem"),
        )
        .unwrap();
        pin_profile(bundle.path(), identity.path()).unwrap();
        let loaded = load(bundle.path()).unwrap();
        let managed = policy_settings(&loaded, identity.path(), config.path()).unwrap();
        let policy = managed.relay.carrier_failover.clone().expect("pool policy");
        assert_eq!(
            policy.base_cooldown_ms,
            if explicit.is_some() { 2000 } else { 5000 }
        );
        // Through the installed TOML and back.
        let reloaded: aegis_core::Settings =
            toml::from_str(&toml::to_string_pretty(&managed).unwrap()).unwrap();
        OnlineProfile::for_runtime(bundle.path(), &reloaded).unwrap();
        let mut removed = reloaded.clone();
        removed.relay.carrier_failover = None;
        assert!(OnlineProfile::for_runtime(bundle.path(), &removed).is_err());
        let mut substituted = reloaded;
        substituted
            .relay
            .carrier_failover
            .as_mut()
            .unwrap()
            .max_cooldown_ms += 1;
        assert!(OnlineProfile::for_runtime(bundle.path(), &substituted).is_err());
    }
}
