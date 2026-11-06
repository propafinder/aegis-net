//! Managed public-policy regressions: ordinary fixture files, never enrollment,
//! network, installed capture or proof of calibrated privacy on a real link.
use super::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn public_profile() -> Value {
    json!({
        "schema":"aegis_device_bundle_v4", "product_mode":"full-wide-tun", "udp":true,
        "relay_server":"127.0.0.1:443", "outer_server_name":"relay.test",
        "inner_server_name":"origin.test",
        "relay_endpoints":[{"server":"127.0.0.1:443","server_name":"relay.test"}],
        "enrollment":{"protocol":"aegis-enrollment-v1", "authority_server":"127.0.0.1:8443",
            "outer_server_name":"authority.test", "inner_server_name":"issuer.test",
            "automatic_renewal":true, "renewal_policy":"same-key-v1"}
    })
}
fn shaping() -> Value {
    json!({"payload_bytes":1024,"cadence_ms":10,"buffer_bytes":4096,
        "max_wire_bytes":8388608,"io_timeout_ms":1000,"session_timeout_ms":10000,
        "max_queue_delay_ms":10000})
}
fn plan(owner: &str) -> Value {
    json!({"packet_modifiers":[owner],"framing_budget":{"max_payload_bytes":1024,
        "max_buffer_bytes":4096,"max_wire_bytes_per_direction":8388608,
        "max_session_ms":10000,"max_queue_delay_ms":200000}})
}
fn recent(algorithm: Value) -> Value {
    json!({"window_ms":60000,"max_observations":256,"diversity_penalty":0.25,
        "paper_algorithm":algorithm,"failure_domains":{"grpc_stream":"declared-test-domain"}})
}
fn render_args(bundle: &Path, identity: &Path, config: &Path) -> BundleRenderArgs {
    BundleRenderArgs {
        bundle_dir: bundle.into(),
        identity_dir: identity.into(),
        config_dir: config.into(),
        output: config.join("aegis.toml"),
        relay_geneva_request: None,
        relay_geneva_request_sha256: None,
        relay_geneva_profile_manifest: None,
        relay_geneva_profile_sha256: None,
        validate_only: false,
    }
}
fn add_test_identity(identity: &Path, config: &Path, bundle: &Path) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.self_signed(&key).unwrap();
    for (name, bytes) in [
        ("device.key", key.serialize_pem()),
        ("device.pem", cert.pem()),
    ] {
        enrollment::write_private_new(&identity.join(name), bytes.as_bytes()).unwrap();
    }
    for (source, name) in [("outer-ca.pem", "ca.pem"), ("inner-ca.pem", "inner-ca.pem")] {
        enrollment::write_private_new(&config.join(name), &fs::read(bundle.join(source)).unwrap())
            .unwrap();
    }
}
fn owners() -> Vec<(&'static str, Value)> {
    let mut poisson = shaping();
    poisson["poisson_pacing"] = json!({"mean_interval_us":1000,"max_gap_us":10000});
    let mut net = shaping();
    net["net_shaper"] = json!({"slots":64,"cadence_ms":10,"window_ms":1000,"io_timeout_ms":10,
        "queue_cap":256,"release_cap":128,"sigma_bytes":1024,"rho_limit_n":"64","rho_limit_d":"1"});
    let mut bit = shaping();
    bit["bit_traps"] = json!({"slots":64,"cadence_ms":10,"io_timeout_ms":10,
        "queue_cap":256,"service":[[128,1],[256,1]]});
    let mut adaptive = shaping();
    adaptive["max_queue_delay_ms"] = json!(200000);
    adaptive["adaptive_channel"] = json!({"joint_counts":[[10,0],[0,10]],"length_bin_upper":[128,256],
        "actions":[{"padded_bytes":128,"delay_ms":0},{"padded_bytes":256,"delay_ms":0}],
        "delay_cost_per_ms":0,"cost_budget":256,"optimizer_iterations":1000,
        "optimizer_gap_millibits":1,"optimizer_timeout_ms":500,"buffer_bytes":1024,
        "max_wire_bytes":1048576,"io_timeout_ms":100,"session_timeout_ms":10000,"max_queue_delay_ms":200000});
    let mut cover = shaping();
    cover["cover_stream"] = json!({"tokens":[[65],[66],[67]],"weights":[4,2,1],"capacity":33,
        "horizon":1024,"max_records":32,"buffer_bytes":1024,"max_wire_bytes":32768,
        "io_timeout_ms":1000,"session_timeout_ms":10000});
    let mut liu = shaping();
    liu["max_queue_delay_ms"] = json!(200000);
    liu["liu_channel"] = json!({"class_weights":[1,3],"client_to_server_counts":[[3,1],[1,3]],"server_to_client_counts":[[3,1],[1,3]],"target_classes":[],"unmatched_traffic_class":1,"policy_ack_class":1,"distortion_microunits":125000,"optimizer_iterations":2000,"optimizer_gap_millibits":1,"optimizer_timeout_ms":3000,"buffer_bytes":1024,"wire_batch_bytes":1024,"max_wire_bytes":100000,"io_timeout_ms":100,"session_timeout_ms":10000,"max_queue_delay_ms":200000});
    let mut envelope = shaping();
    envelope["arrival_envelope"] = json!({"burst_bytes":1024,"arrival_rate_bytes_per_second":100,
        "service_rate_bytes_per_second":1000,"service_latency_ns":1010000000u64});
    vec![
        ("constant_cadence", shaping()),
        ("poisson_schedule", poisson),
        ("net_shaper_epoch", net),
        ("bit_traps_service", bit),
        ("adaptive_channel", adaptive),
        ("cover_stream", cover),
        ("liu_channel", liu),
        ("constant_cadence", envelope),
    ]
}

#[test]
fn all_managed_owners_and_paper_bandits_survive_raw_bundle_digest_render_and_real_load() {
    let mut cases: Vec<_> = owners()
        .into_iter()
        .map(|(owner, shape)| {
            let mut public = public_profile();
            public["authenticated_shaping"] = shape;
            public["privacy_plan"] = plan(owner);
            public
        })
        .collect();
    for algorithm in [
        json!({"algorithm":"sliding_window","rounds":16,"xi":1.0}),
        json!({"algorithm":"discounted","gamma":0.9,"xi":1.0}),
    ] {
        let mut public = public_profile();
        public["recent_routes"] = recent(algorithm);
        cases.push(public);
    }
    for algorithm in [
        json!({"algorithm":"sliding_window","rounds":16,"xi":1.0}),
        json!({"algorithm":"discounted","gamma":0.9,"xi":1.0}),
    ] {
        let mut public = public_profile();
        public["relay_endpoints"]
            .as_array_mut()
            .unwrap()
            .push(json!({"server":"127.0.0.2:443","server_name":"relay.test"}));
        public["endpoint_bandit"] = json!({"algorithm":algorithm,"max_profiles":16,"max_contexts_per_profile":8,"pre_auth_block_ms":1000});
        let mut with_topology = public.clone();
        with_topology["endpoint_bandit"]["dependency_policy"] = json!({
            "a":{"nodes":[0,1,2],"edges":[[0,1],[1,2]]},
            "b":{"nodes":[0,1,2],"edges":[[0,1],[1,2]]},
            "dependency_pairs":[[0,0],[1,1],[2,2]],"endpoint_nodes":[0,2],
            "anchor_a":1,"anchor_b":1,"unavailable_b":[0]
        });
        cases.push(public);
        cases.push(with_topology);
    }
    for public in cases {
        let original = super::tests::fixture();
        let raw = serde_json::to_vec(&public).unwrap();
        fs::write(original.path().join("bundle.json"), &raw).unwrap();
        let destination = tempfile::tempdir().unwrap();
        let bundle = destination.path().join("bundle");
        create(&BundleCreateArgs {
            bundle_dir: bundle.clone(),
            profile: original.path().join("bundle.json"),
            outer_ca: original.path().join("outer-ca.pem"),
            inner_ca: original.path().join("inner-ca.pem"),
            device_ca: original.path().join("device-ca.pem"),
        })
        .unwrap();
        assert_eq!(fs::read(bundle.join("bundle.json")).unwrap(), raw);
        let (profile, digest, pins) = load_snapshot(&bundle).unwrap();
        assert_eq!(pins["bundle.json"], hex::encode(Sha256::digest(&raw)));
        assert_eq!(digest, profile_digest(original.path()).unwrap());
        let identity = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        add_test_identity(identity.path(), config.path(), &bundle);
        let args = render_args(&bundle, identity.path(), config.path());
        render(&args).unwrap();
        let loaded = crate::config::load_config(&args.output).unwrap();
        assert_eq!(
            serde_json::to_value(&loaded.relay.endpoint_bandit).unwrap(),
            serde_json::to_value(&profile.endpoint_bandit).unwrap()
        );
        assert_eq!(
            loaded.relay.authenticated_shaping,
            profile.authenticated_shaping
        );
        assert_eq!(
            serde_json::to_value(loaded.privacy_plan).unwrap(),
            serde_json::to_value(profile.privacy_plan).unwrap()
        );
        assert_eq!(
            serde_json::to_value(loaded.direct.recent_routes).unwrap(),
            serde_json::to_value(profile.recent_routes).unwrap()
        );
        assert_eq!(
            fs::read_to_string(identity.path().join("bundle-profile.sha256")).unwrap(),
            digest
        );
        assert!(!config.path().join("device.key").exists());
    }
}

#[test]
fn absent_public_options_preserve_old_json_and_rendered_default_sections() {
    let bundle = super::tests::fixture();
    let raw = fs::read(bundle.path().join("bundle.json")).unwrap();
    let profile = validate_profile(&raw).unwrap();
    assert_eq!(serde_json::to_vec(&profile).unwrap(), raw);
    let identity = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let rendered =
        toml::to_string(&settings(&profile, identity.path(), config.path()).unwrap()).unwrap();
    for section in [
        "authenticated_shaping",
        "privacy_plan",
        "recent_routes",
        "endpoint_bandit",
        "carrier_program",
    ] {
        assert!(!rendered.contains(section));
    }
    assert!(
        profile.authenticated_shaping.is_none()
            && profile.privacy_plan.is_none()
            && profile.recent_routes.is_none()
    );
}

#[test]
fn signed_public_route_order_renders_and_rejects_aliases_before_identity_reads() {
    let mut public = public_profile();
    public["relay_endpoints"] = json!([
        {"server":"127.0.0.1:443","server_name":"relay.test"},
        {"server":"127.0.0.2:443","server_name":"relay.test"}
    ]);
    public["carrier_program"] = json!({"routes":[
        {"channel":"direct_h2","endpoint_index":1},
        {"channel":"fronted_h2","endpoint_index":0}
    ]});
    let parsed = validate_profile(&serde_json::to_vec(&public).unwrap()).unwrap();
    let identity = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let rendered = settings(&parsed, identity.path(), config.path()).unwrap();
    assert_eq!(rendered.relay.carrier_program, parsed.carrier_program);
    assert_eq!(rendered.relay.endpoints.len(), 2);
    assert_eq!(
        rendered.relay.tls_backend,
        aegis_core::RelayTlsBackend::Rustls
    );
    let mut unsupported_backend = rendered.clone();
    unsupported_backend.relay.tls_backend = aegis_core::RelayTlsBackend::ChromeLikeExperimental;
    assert!(unsupported_backend
        .relay
        .validate_inner_tls_transport()
        .is_err());
    public["carrier_program"]["routes"][1]["endpoint_index"] = json!(1);
    assert!(validate_profile(&serde_json::to_vec(&public).unwrap()).is_err());
    public["carrier_program"]["routes"][1]["endpoint_index"] = json!(0);
    public["carrier_program"]["routes"][1]["channel"] = json!("sfu_media");
    assert!(validate_profile(&serde_json::to_vec(&public).unwrap()).is_err());
}

#[test]
fn direct_primary_fronted_ech_authority_is_signed_and_route_scoped() {
    let mut public = public_profile();
    public["relay_endpoints"] = json!([
        {"server":"127.0.0.1:443","server_name":"relay.test"},
        {"server":"127.0.0.2:443","server_name":"fronted.test"}
    ]);
    public["carrier_program"] = json!({
        "routes":[
            {"channel":"direct_h2","endpoint_index":0},
            {"channel":"fronted_h2","endpoint_index":1}
        ],
        "ech_scope":"fronted_only",
        "fronted_ech_authority":"fronted.test"
    });
    public["ech_config_list"] = json!(crate::relay::inline_ech_fixture());
    let parsed = validate_profile(&serde_json::to_vec(&public).unwrap()).unwrap();
    let identity = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let rendered = settings(&parsed, identity.path(), config.path()).unwrap();
    let endpoints = aegis_client::relay_endpoint_policy::effective_relay_endpoints(&rendered.relay);
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0].server_name, "relay.test");
    assert_eq!(endpoints[1].server_name, "fronted.test");
    let direct = aegis_client::relay_endpoint_policy::relay_settings_for_endpoint(
        &rendered.relay,
        &endpoints[0],
    );
    let fronted = aegis_client::relay_endpoint_policy::relay_settings_for_endpoint(
        &rendered.relay,
        &endpoints[1],
    );
    assert!(direct.ech_config_list.is_none());
    assert!(direct.ech_config_list_base64.is_none());
    assert!(fronted.ech_config_list.is_some() || fronted.ech_config_list_base64.is_some());
    public["carrier_program"]["fronted_ech_authority"] = json!("relay.test");
    assert!(validate_profile(&serde_json::to_vec(&public).unwrap()).is_err());
    public["carrier_program"]
        .as_object_mut()
        .unwrap()
        .remove("fronted_ech_authority");
    assert!(validate_profile(&serde_json::to_vec(&public).unwrap()).is_err());
}

#[test]
fn full_wide_public_direct_to_bridge_plan_needs_no_private_key_at_preflight() {
    let mut public = public_profile();
    public["relay_endpoints"] = json!([
        {"server":"127.0.0.1:443","server_name":"relay.test"},
        {"server":"127.0.0.2:443","server_name":"bridge.test"}
    ]);
    public["carrier_program"] = json!({
        "routes":[
            {"channel":"direct_h2","endpoint_index":0},
            {"channel":"own_https_bridge","endpoint_index":1}
        ],
        "bridge":{"authority":"bridge.test","path":"/private/stream",
            "enrollment_path":"/private/enroll"}
    });
    validate_profile(&serde_json::to_vec(&public).unwrap()).unwrap();
    public["relay_endpoints"][1]["server_name"] = json!("foreign.test");
    assert!(validate_profile(&serde_json::to_vec(&public).unwrap()).is_err());
    public["relay_endpoints"][1]["server_name"] = json!("bridge.test");
    public["carrier_program"]["bridge"]["enrollment_path"] = json!("/private/stream");
    assert!(validate_profile(&serde_json::to_vec(&public).unwrap()).is_err());
    public["carrier_program"]["bridge"]["enrollment_path"] = json!("/private/enroll");
    public["carrier_program"]["routes"][0]["channel"] = json!("fronted_h2");
    public["carrier_program"]["ech_scope"] = json!("fronted_only");
    public["ech_config_list"] = json!(crate::relay::inline_ech_fixture());
    validate_profile(&serde_json::to_vec(&public).unwrap()).unwrap();
    public["carrier_program"]
        .as_object_mut()
        .unwrap()
        .remove("ech_scope");
    assert!(validate_profile(&serde_json::to_vec(&public).unwrap()).is_err());
}

#[test]
fn public_policy_change_changes_raw_digest_and_refuses_existing_identity_pin() {
    let bundle = super::tests::fixture();
    let mut public = public_profile();
    public["authenticated_shaping"] = shaping();
    public["privacy_plan"] = plan("constant_cadence");
    fs::write(
        bundle.path().join("bundle.json"),
        serde_json::to_vec(&public).unwrap(),
    )
    .unwrap();
    let identity = tempfile::tempdir().unwrap();
    pin_profile(bundle.path(), identity.path()).unwrap();
    let prior = profile_digest(bundle.path()).unwrap();
    public["authenticated_shaping"]["payload_bytes"] = json!(512);
    fs::write(
        bundle.path().join("bundle.json"),
        serde_json::to_vec(&public).unwrap(),
    )
    .unwrap();
    assert!(load(bundle.path()).is_ok());
    assert_ne!(profile_digest(bundle.path()).unwrap(), prior);
    assert!(pin_profile(bundle.path(), identity.path()).is_err());
    assert_eq!(
        fs::read_to_string(identity.path().join("bundle-profile.sha256")).unwrap(),
        prior
    );
}

#[test]
fn inconsistent_public_policy_refuses_before_absent_identity_overlay_and_output() {
    let mut invalids = Vec::new();
    let mut mismatch = public_profile();
    mismatch["authenticated_shaping"] = shaping();
    mismatch["privacy_plan"] = plan("cover_stream");
    invalids.push(mismatch);
    let mut nested = public_profile();
    let mut s = owners()[1].1.clone();
    s["bit_traps"] = owners()[3].1["bit_traps"].clone();
    nested["authenticated_shaping"] = s;
    invalids.push(nested);
    let mut guarantee = public_profile();
    guarantee["privacy_plan"] = json!({"requested_guarantee":"whole_flow_differential_privacy"});
    invalids.push(guarantee);
    let mut foreign = public_profile();
    foreign["recent_routes"] = recent(json!({"algorithm":"sliding_window","rounds":16,"xi":1.0}));
    foreign["recent_routes"]["failure_domains"] = json!({"masque_derived":"foreign"});
    invalids.push(foreign);
    let mut badalgorithm = public_profile();
    badalgorithm["recent_routes"] = recent(json!({"algorithm":"discounted","gamma":1.0,"xi":1.0}));
    invalids.push(badalgorithm);
    for public in invalids {
        let bundle = super::tests::fixture();
        fs::write(
            bundle.path().join("bundle.json"),
            serde_json::to_vec(&public).unwrap(),
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut args = render_args(
            bundle.path(),
            &root.path().join("absent-identity"),
            &root.path().join("absent-config"),
        );
        args.validate_only = true;
        assert!(render(&args).is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        assert!(create(&BundleCreateArgs {
            bundle_dir: root.path().join("new-bundle"),
            profile: bundle.path().join("bundle.json"),
            outer_ca: bundle.path().join("outer-ca.pem"),
            inner_ca: bundle.path().join("inner-ca.pem"),
            device_ca: bundle.path().join("device-ca.pem")
        })
        .is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        // Direct policy construction also refuses before reading the absent private overlay.
        let parsed: PublicProfile = serde_json::from_value(public).unwrap();
        assert!(
            policy_settings_with_overlay(&parsed, &args.identity_dir, &args.config_dir, true)
                .is_err()
        );
    }
}

#[test]
fn null_unknown_versions_and_nested_secret_fields_are_not_public_policy() {
    let base = public_profile();
    let mut bads = Vec::new();
    for field in [
        "authenticated_shaping",
        "privacy_plan",
        "recent_routes",
        "endpoint_bandit",
    ] {
        let mut bad = base.clone();
        bad[field] = Value::Null;
        bads.push(bad);
    }
    let mut bad = base.clone();
    bad["authenticated_shaping"] = shaping();
    bad["authenticated_shaping"]["key_path"] = json!("forbidden-private-key");
    bads.push(bad);
    let mut bad = base.clone();
    bad["privacy_plan"] = plan("constant_cadence");
    bad["privacy_plan"]["fallback"] = json!(true);
    bads.push(bad);
    let mut bad = base.clone();
    bad["recent_routes"] = recent(json!({"algorithm":"sliding_window","rounds":16,"xi":1.0}));
    bad["recent_routes"]["paper_algorithm"]["key"] = json!("forbidden");
    bads.push(bad);
    let mut bad = base.clone();
    bad["schema"] = json!("aegis_device_bundle_v999");
    bads.push(bad);
    for bad in bads {
        assert!(validate_profile(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
}

#[test]
fn valid_typed_shape_above_control_envelope_and_raw_public_cap_refuse() {
    let mut s = shaping();
    s["cover_stream"] = json!({"tokens":(0..64).map(|i|vec![i;32]).collect::<Vec<_>>(),
        "weights":vec![1;64],"capacity":2,"horizon":32,"max_records":2,
        "buffer_bytes":1024,"max_wire_bytes":2048,"io_timeout_ms":1000,"session_timeout_ms":10000});
    let mut public = public_profile();
    public["authenticated_shaping"] = s;
    let parsed: aegis_core::carrier_runtime::PrivacySettings =
        serde_json::from_value(public["authenticated_shaping"].clone()).unwrap();
    parsed.cover_stream.as_ref().unwrap().validate().unwrap();
    assert!(serde_json::to_vec(&parsed).unwrap().len() > 4096 - 64);
    assert!(validate_profile(&serde_json::to_vec(&public).unwrap()).is_err());
    let raw = vec![b' '; MAX_PUBLIC_BYTES as usize + 1];
    assert!(validate_profile(&raw)
        .unwrap_err()
        .to_string()
        .contains("too large"));
}

#[test]
fn nested_dependency_policy_refuses_null_unknown_mapping_and_bounds_before_bundle_writes() {
    let original = super::tests::fixture();
    let mut good = public_profile();
    good["relay_endpoints"]
        .as_array_mut()
        .unwrap()
        .push(json!({"server":"127.0.0.2:443","server_name":"relay.test"}));
    good["endpoint_bandit"] = json!({"algorithm":{"algorithm":"sliding_window","rounds":16,"xi":1.0},
        "max_profiles":16,"max_contexts_per_profile":8,"pre_auth_block_ms":1000,
        "dependency_policy":{"a":{"nodes":[0,1,2],"edges":[[0,1],[1,2]]},
        "b":{"nodes":[0,1,2],"edges":[[0,1],[1,2]]},"dependency_pairs":[[0,0],[1,1],[2,2]],
        "endpoint_nodes":[0,2],"anchor_a":1,"anchor_b":1}});
    validate_profile(&serde_json::to_vec(&good).unwrap()).unwrap();
    let mut bads = Vec::new();
    let mut bad = good.clone();
    bad["endpoint_bandit"]["dependency_policy"] = Value::Null;
    bads.push(bad);
    let mut bad = good.clone();
    bad["endpoint_bandit"]["dependency_policy"]["discover"] = json!(true);
    bads.push(bad);
    let mut bad = good.clone();
    bad["endpoint_bandit"]["dependency_policy"]["a"]["key_path"] = json!("private");
    bads.push(bad);
    let mut bad = good.clone();
    bad["endpoint_bandit"]["dependency_policy"]["endpoint_nodes"] = json!([0, 0]);
    bads.push(bad);
    let mut bad = good.clone();
    bad["endpoint_bandit"]["dependency_policy"]["a"]["nodes"] = json!((0..33).collect::<Vec<_>>());
    bads.push(bad);
    for bad in bads {
        fs::write(
            original.path().join("bundle.json"),
            serde_json::to_vec(&bad).unwrap(),
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        assert!(create(&BundleCreateArgs {
            bundle_dir: root.path().join("bundle"),
            profile: original.path().join("bundle.json"),
            outer_ca: original.path().join("outer-ca.pem"),
            inner_ca: original.path().join("inner-ca.pem"),
            device_ca: original.path().join("device-ca.pem")
        })
        .is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn liu_managed_profile_rejects_null_unknown_composition_and_digest_changes() {
    let (_, shape) = owners()
        .into_iter()
        .find(|(m, _)| *m == "liu_channel")
        .unwrap();
    let mut good = public_profile();
    good["authenticated_shaping"] = shape.clone();
    good["privacy_plan"] = plan("liu_channel");
    validate_profile(&serde_json::to_vec(&good).unwrap()).unwrap();
    for change in 0..4 {
        let mut bad = good.clone();
        match change {
            0 => bad["authenticated_shaping"]["liu_channel"] = Value::Null,
            1 => bad["authenticated_shaping"]["liu_channel"]["private_key"] = json!("forbidden"),
            2 => {
                bad["authenticated_shaping"]["cover_stream"] = owners()
                    .into_iter()
                    .find(|(m, _)| *m == "cover_stream")
                    .unwrap()
                    .1["cover_stream"]
                    .clone()
            }
            _ => {
                bad["authenticated_shaping"]["liu_channel"]["client_to_server_counts"][0][0] =
                    json!(0)
            }
        };
        assert!(validate_profile(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let f = super::tests::fixture();
    let original = fs::read(f.path().join("bundle.json")).unwrap();
    let before = profile_digest(f.path()).unwrap();
    fs::write(
        f.path().join("bundle.json"),
        serde_json::to_vec(&good).unwrap(),
    )
    .unwrap();
    let added = profile_digest(f.path()).unwrap();
    assert_ne!(before, added);
    good["authenticated_shaping"]["liu_channel"]["policy_ack_class"] = json!(0);
    fs::write(
        f.path().join("bundle.json"),
        serde_json::to_vec(&good).unwrap(),
    )
    .unwrap();
    assert_ne!(added, profile_digest(f.path()).unwrap());
    fs::write(f.path().join("bundle.json"), original).unwrap();
}
