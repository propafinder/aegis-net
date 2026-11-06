use super::*;
use aegis_core::{
    ExternalKnowledgePrior, ExternalWitnessCalibration, Settings, TunnelTransportFamily,
};
use tempfile::TempDir;

fn snapshot(stale: bool) -> ExternalCalibrationSnapshot {
    let generated = if stale {
        1
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    };
    ExternalCalibrationSnapshot {
        schema_version: 1,
        source: "public_runtime_fixture".into(),
        generated_at_unix_ms: Some(generated),
        freshness_half_life_secs: Some(if stale { 1 } else { 86400 }),
        witness: vec![
            ExternalWitnessCalibration {
                label: "https_ws".into(),
                records: 6,
                combined_avg: 0.96,
                ja3_present_avg: 1.0,
                alpn_match_avg: 0.95,
                sni_structure_avg: 0.92,
            },
            ExternalWitnessCalibration {
                label: "legacy_tls".into(),
                records: 6,
                combined_avg: 0.15,
                ja3_present_avg: 0.0,
                alpn_match_avg: 0.0,
                sni_structure_avg: 0.45,
            },
        ],
        knowledge: vec![
            ExternalKnowledgePrior {
                target_class: "https_ws".into(),
                region_id: None,
                score: 0.95,
                confidence: 0.95,
                hard_excluded: false,
                fail_closed: false,
                generated_at_unix_ms: Some(generated),
            },
            ExternalKnowledgePrior {
                target_class: "legacy_tls".into(),
                region_id: None,
                score: 0.05,
                confidence: 0.9,
                hard_excluded: false,
                fail_closed: false,
                generated_at_unix_ms: Some(generated),
            },
        ],
        ..Default::default()
    }
}

fn settings(dir: &TempDir) -> Settings {
    let mut cfg = Settings {
        mode: Mode::Relay,
        ..Default::default()
    };
    cfg.direct.state_path = dir.path().join("existing-history.json");
    // Relay must remain RAM-only even if another mode's consent was retained.
    cfg.direct.persist_state = true;
    cfg.direct.epsilon = 0.0;
    cfg.relay.transport_priority = vec![
        TunnelTransportFamily::LegacyTls,
        TunnelTransportFamily::HttpsWs,
    ];
    cfg
}

#[tokio::test]
async fn live_relay_builder_imports_fresh_public_calibration_without_disk_history() {
    for stale in [false, true] {
        let dir = TempDir::new().unwrap();
        let cfg = settings(&dir);
        let mut previous = aegis_core::StateSnapshot::default();
        previous
            .strategy_stats
            .insert("old-destination|relay".into(), Default::default());
        let history = serde_json::to_vec(&previous).unwrap();
        std::fs::write(&cfg.direct.state_path, &history).unwrap();
        let public_path = dir.path().join("public-calibration.json");
        std::fs::write(&public_path, serde_json::to_vec(&snapshot(stale)).unwrap()).unwrap();
        let public = read_snapshot(&public_path).unwrap();
        let runtime = crate::RuntimeContext::from_settings_with_calibration(&cfg, Some(&public))
            .await
            .unwrap();
        let crate::RuntimeContext::Relay { brain, store } = runtime else {
            panic!("expected relay");
        };
        assert_eq!(store.snapshot().await.external_calibration, Some(public));
        assert!(store.snapshot().await.strategy_stats.is_empty());
        let adjusted = crate::calibrated_relay_settings_for_session(
            &cfg.relay,
            &brain,
            &store,
            "relay.example.invalid",
            443,
            "203.0.113.9:443".parse().unwrap(),
        )
        .await;
        assert_eq!(
            adjusted.transport_priority[0],
            if stale {
                TunnelTransportFamily::LegacyTls
            } else {
                TunnelTransportFamily::HttpsWs
            }
        );
        store
            .update(|state| {
                state
                    .strategy_stats
                    .insert("new-destination|relay".into(), Default::default());
            })
            .await;
        store.flush().await.unwrap();
        assert_eq!(std::fs::read(&cfg.direct.state_path).unwrap(), history);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            2,
            "no key or state sidecars"
        );
    }
}

#[tokio::test]
async fn live_relay_builder_without_import_keeps_configured_order_and_no_disk_history() {
    let dir = TempDir::new().unwrap();
    let cfg = settings(&dir);
    let history = serde_json::to_vec(&aegis_core::StateSnapshot {
        external_calibration: Some(snapshot(false)),
        ..Default::default()
    })
    .unwrap();
    std::fs::write(&cfg.direct.state_path, &history).unwrap();
    let runtime = crate::RuntimeContext::from_settings_with_calibration(&cfg, None)
        .await
        .unwrap();
    let crate::RuntimeContext::Relay { brain, store } = runtime else {
        panic!("expected relay");
    };
    assert!(store.snapshot().await.external_calibration.is_none());
    let adjusted = crate::calibrated_relay_settings_for_session(
        &cfg.relay,
        &brain,
        &store,
        "relay.example.invalid",
        443,
        "203.0.113.9:443".parse().unwrap(),
    )
    .await;
    assert_eq!(adjusted.transport_priority, cfg.relay.transport_priority);
    store.flush().await.unwrap();
    assert_eq!(std::fs::read(&cfg.direct.state_path).unwrap(), history);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn forensic_public_import_keeps_destination_state_in_ram() {
    let dir = TempDir::new().unwrap();
    let mut cfg = settings(&dir);
    cfg.mode = Mode::Direct;
    let public = snapshot(false);
    let store = load_runtime(&cfg.direct, cfg.mode, true, Some(&public))
        .await
        .unwrap();
    assert_eq!(store.snapshot().await.external_calibration, Some(public));
    store
        .update(|state| {
            state
                .strategy_stats
                .insert("forensic-destination|direct".into(), Default::default());
        })
        .await;
    store.flush().await.unwrap();
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn reader_accepts_existing_summary_builder_shape() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("summary.json");
    std::fs::write(&path, serde_json::to_vec(&serde_json::json!({
        "event":"external_calibration_summary", "schema_version":1,
        "witness":{"labels":[{"label":"https_ws", "records":2, "combined_avg":0.7, "ja3_present_avg":1.0, "alpn_match_avg":0.75, "sni_structure_avg":0.55}]},
        "verdict":{"status":"MEASURED", "acceptance_degraded":false, "reasons":[]}
    })).unwrap()).unwrap();
    let public = read_snapshot(&path).unwrap();
    assert_eq!(public.source, "external_calibration_summary");
    assert_eq!(public.witness[0].combined_avg, 0.7);
}

#[test]
fn reader_rejects_unbounded_or_invalid_public_input() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("public.json");
    for bytes in [
        b"not-json".to_vec(),
        b"[]".to_vec(),
        vec![b' '; MAX_BYTES as usize + 1],
    ] {
        std::fs::write(&path, bytes).unwrap();
        assert!(read_snapshot(&path).is_err());
    }
    let mut invalid = Vec::new();
    let mut value = serde_json::to_value(snapshot(false)).unwrap();
    value["schema_version"] = serde_json::json!(257);
    invalid.push(value);
    let mut value = serde_json::to_value(snapshot(false)).unwrap();
    value["witness"][0]["combined_avg"] = serde_json::json!(1.01);
    invalid.push(value);
    let mut value = serde_json::to_value(snapshot(false)).unwrap();
    value["freshness_half_life_secs"] = serde_json::json!(0);
    invalid.push(value);
    let mut value = serde_json::to_value(snapshot(false)).unwrap();
    value["knowledge"][0]["target_class"] = serde_json::json!("x".repeat(MAX_IDENTIFIER_BYTES + 1));
    invalid.push(value);
    let mut value = serde_json::to_value(snapshot(false)).unwrap();
    value["witness"] = serde_json::Value::Array(vec![value["witness"][0].clone(); MAX_ENTRIES + 1]);
    invalid.push(value);
    for value in invalid {
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_snapshot(&path).is_err(), "{value}");
    }
}

#[cfg(unix)]
#[test]
fn reader_refuses_fifo_without_waiting_for_a_writer() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("public.fifo");
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(read_snapshot(&path).is_err());
}
