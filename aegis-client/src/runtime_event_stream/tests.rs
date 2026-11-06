use super::*;
use aegis_core::signals::classify::FailSignal;
use aegis_core::{
    ExternalAdversarialCalibration, ExternalCalibrationSnapshot, ExternalCalibrationVerdict,
    ExternalKnowledgePrior, ExternalWitnessCalibration,
};
use serde_json::{json, Value};
use std::fs;

fn temp_jsonl_path(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("aegis-runtime-event-{label}-{unique}.jsonl"))
}

fn read_single_jsonl_record(path: &Path) -> Value {
    let written = std::fs::read_to_string(path).expect("read jsonl");
    std::fs::remove_file(path).ok();
    let line = written.lines().next().expect("jsonl line");
    serde_json::from_str(line).expect("parse jsonl record")
}

async fn sample_relay_preferred_advisory() -> aegis_core::DirectSessionAdvisory {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("aegis-runtime-advisory-{unique}"));
    fs::create_dir_all(&dir).expect("create temp advisory dir");
    let store = aegis_core::AsyncStateStore::load(dir.join("state.json"))
        .await
        .expect("load state store");
    let key = aegis_core::StrategyKey::for_target(
        "203.0.113.79:443".parse().expect("socket addr"),
        "probe-advisory.example",
        443,
        Some("probe-advisory.example"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            snap.key_observations.insert(
                hk.clone(),
                aegis_core::KeyObservation {
                    matched_packets: 2,
                    capture_status: aegis_core::PacketCaptureStatus::Active,
                    first_data_ttl: Some(58),
                    ..Default::default()
                },
            );
            snap.stall_probe_stats.insert(
                hk,
                aegis_core::StallProbeStats {
                    trials: 3,
                    collapses: 2,
                    timeouts: 1,
                    consecutive_stall_failures: 2,
                    last_signal: Some(FailSignal::Timeout),
                    ..Default::default()
                },
            );
        })
        .await;
    let brain = aegis_core::Brain::new(0.0, vec!["passthrough".into(), "ttl_desync".into()], store);
    let advisory = brain.direct_session_advisory(&key).await;
    fs::remove_dir_all(&dir).ok();
    advisory
}

#[test]
fn runtime_event_stream_writes_jsonl_record() {
    let path = temp_jsonl_path("ingress-started");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "info",
        RuntimeEventCode::IngressBackendStarted,
        "client ingress backend started",
        json!({
            "backend": "wide_primary",
            "backend_runtime_id": "wide_primary_linux",
            "available": true,
            "listen": "127.0.0.1:15080",
            "requested_primary": "Wide",
            "requested_primary_code": "wide",
            "kind_code": "wide_primary",
            "startup_path_code": "wide_primary_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": null,
            "wide_supported": true,
            "wide_platform_family_supported": true,
            "wide_runtime_readiness": "ready",
            "mode": "direct",
            "mode_code": "direct",
            "rollout_profile_code": "output_only_safe",
            "wide_dns_port": 53,
            "wide_udp_capture_contract": "preview_allowlist_only",
            "wide_udp_capture_policy": "allowlist_ports",
            "wide_udp_capture_runtime_scope": "linux_ipv4_only",
            "wide_udp_preview_policy": "allowlist_ports",
            "wide_udp_preview_ports": [5353, 853],
            "wide_dns_capture_preview_status": "active",
            "wide_dns_capture_preview_error_kind": null,
            "wide_dns_capture_preview_error": null
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_backend_started");
    assert_eq!(record["message"], "client ingress backend started");
    assert_eq!(record["fields"]["backend"], "wide_primary");
    assert_eq!(record["fields"]["backend_runtime_id"], "wide_primary_linux");
    assert_eq!(record["fields"]["available"], true);
    assert_eq!(record["fields"]["listen"], "127.0.0.1:15080");
    assert_eq!(record["fields"]["requested_primary"], "Wide");
    assert_eq!(record["fields"]["requested_primary_code"], "wide");
    assert_eq!(record["fields"]["kind_code"], "wide_primary");
    assert_eq!(record["fields"]["mode_code"], "direct");
    assert_eq!(record["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "wide_primary_started"
    );
    assert_eq!(record["fields"]["wide_runtime_readiness"], "ready");
    assert_eq!(record["fields"]["wide_dns_port"], 53);
    assert_eq!(
        record["fields"]["wide_udp_capture_contract"],
        "preview_allowlist_only"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_policy"],
        "allowlist_ports"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_runtime_scope"],
        "linux_ipv4_only"
    );
    assert_eq!(
        record["fields"]["wide_udp_preview_policy"],
        "allowlist_ports"
    );
    assert_eq!(
        record["fields"]["wide_udp_preview_ports"],
        json!([5353, 853])
    );
    assert_eq!(
        record["fields"]["wide_dns_capture_preview_status"],
        "active"
    );
    assert_eq!(
        record["fields"]["wide_dns_capture_preview_error_kind"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["wide_dns_capture_preview_error"],
        serde_json::Value::Null
    );
}

#[test]
fn runtime_event_stream_writes_boundary_only_backend_started_record() {
    let path = temp_jsonl_path("ingress-started-boundary-only");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
            "info",
            RuntimeEventCode::IngressBackendStarted,
            "client ingress backend started",
            json!({
                "backend": "socks5_fallback",
                "backend_runtime_id": "socks5_fallback",
                "available": true,
                "listen": "127.0.0.1:15080",
                "requested_primary": "Wide",
                "requested_primary_code": "wide",
                "kind_code": "socks5_fallback",
                "startup_path_code": "socks5_fallback_started",
                "startup_fallback_reason_code": "wide_backend_boundary_only",
                "startup_fallback_reason": "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists",
                "startup_bind_error_code": null,
                "wide_supported": false,
                "wide_platform_family_supported": true,
                "wide_runtime_readiness": "boundary_only",
                "mode": "direct",
                "mode_code": "direct",
                "rollout_profile_code": "output_only_safe",
                "wide_dns_port": null,
                "wide_udp_capture_contract": null,
                "wide_udp_capture_policy": null,
                "wide_udp_capture_runtime_scope": null,
                "wide_udp_preview_policy": null,
                "wide_udp_preview_ports": [],
                "wide_dns_capture_preview_status": null,
                "wide_dns_capture_preview_error_kind": null,
                "wide_dns_capture_preview_error": null
            }),
        );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_backend_started");
    assert_eq!(record["message"], "client ingress backend started");
    assert_eq!(record["fields"]["backend"], "socks5_fallback");
    assert_eq!(record["fields"]["backend_runtime_id"], "socks5_fallback");
    assert_eq!(record["fields"]["available"], true);
    assert_eq!(record["fields"]["listen"], "127.0.0.1:15080");
    assert_eq!(record["fields"]["requested_primary"], "Wide");
    assert_eq!(record["fields"]["requested_primary_code"], "wide");
    assert_eq!(record["fields"]["kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["mode_code"], "direct");
    assert_eq!(record["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        "wide_backend_boundary_only"
    );
    assert_eq!(
            record["fields"]["startup_fallback_reason"],
            "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
        );
    assert_eq!(record["fields"]["wide_runtime_readiness"], "boundary_only");
    assert_eq!(record["fields"]["wide_dns_port"], serde_json::Value::Null);
    assert_eq!(
        record["fields"]["wide_udp_capture_contract"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_policy"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_runtime_scope"],
        serde_json::Value::Null
    );
}

#[test]
fn runtime_event_stream_writes_startup_plan_evaluated_fields() {
    let path = temp_jsonl_path("startup-plan");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "info",
        RuntimeEventCode::IngressStartupPlanEvaluated,
        "evaluated ingress startup plan",
        json!({
            "allow_fallback": true,
            "requested_primary": "Wide",
            "requested_primary_code": "wide",
            "selected_backend": "Socks5Fallback",
            "selected_backend_code": "socks5_fallback",
            "fallback_reason_code": "wide_disabled_in_config",
            "fallback_reason": "wide ingress is disabled in config",
            "socks_listen": "127.0.0.1:1080",
            "wide_enabled": false,
            "wide_listen": "0.0.0.0:15080",
            "wide_platform": "Auto",
            "wide_platform_code": "auto",
            "wide_platform_family_supported": false,
            "wide_prerouting_interface": null,
            "wide_rollout_profile": "OutputOnlySafe",
            "wide_rollout_profile_code": "output_only_safe",
            "wide_runtime_readiness": "disabled",
            "wide_supported": false
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_startup_plan_evaluated");
    assert_eq!(record["fields"]["requested_primary"], "Wide");
    assert_eq!(record["fields"]["requested_primary_code"], "wide");
    assert_eq!(record["fields"]["selected_backend"], "Socks5Fallback");
    assert_eq!(record["fields"]["selected_backend_code"], "socks5_fallback");
    assert_eq!(
        record["fields"]["fallback_reason_code"],
        "wide_disabled_in_config"
    );
    assert_eq!(
        record["fields"]["fallback_reason"],
        "wide ingress is disabled in config"
    );
    assert_eq!(record["fields"]["wide_platform_code"], "auto");
    assert_eq!(
        record["fields"]["wide_rollout_profile_code"],
        "output_only_safe"
    );
    assert_eq!(record["fields"]["wide_runtime_readiness"], "disabled");
}

#[test]
fn runtime_event_stream_writes_boundary_only_startup_plan_evaluated_fields() {
    let path = temp_jsonl_path("startup-plan-boundary-only");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
            "info",
            RuntimeEventCode::IngressStartupPlanEvaluated,
            "evaluated ingress startup plan",
            json!({
                "allow_fallback": true,
                "requested_primary": "Wide",
                "requested_primary_code": "wide",
                "selected_backend": "Socks5Fallback",
                "selected_backend_code": "socks5_fallback",
                "fallback_reason_code": "wide_backend_boundary_only",
                "fallback_reason": "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists",
                "socks_listen": "127.0.0.1:1080",
                "wide_enabled": true,
                "wide_listen": "0.0.0.0:15080",
                "wide_platform": "MacosPf",
                "wide_platform_code": "macos_pf",
                "wide_platform_family_supported": true,
                "wide_prerouting_interface": null,
                "wide_rollout_profile": "OutputOnlySafe",
                "wide_rollout_profile_code": "output_only_safe",
                "wide_runtime_readiness": "boundary_only",
                "wide_supported": false,
                "wide_udp_capture_contract_requested": "generic_capture_unstable",
                "wide_udp_capture_support_tier_requested": "guarded_unstable",
                "wide_udp_capture_contract": null,
                "wide_udp_capture_support_tier": null,
                "wide_udp_capture_policy": null,
                "wide_udp_capture_runtime_scope": null
            }),
        );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_startup_plan_evaluated");
    assert_eq!(record["fields"]["requested_primary"], "Wide");
    assert_eq!(record["fields"]["requested_primary_code"], "wide");
    assert_eq!(record["fields"]["selected_backend"], "Socks5Fallback");
    assert_eq!(record["fields"]["selected_backend_code"], "socks5_fallback");
    assert_eq!(
        record["fields"]["fallback_reason_code"],
        "wide_backend_boundary_only"
    );
    assert_eq!(
            record["fields"]["fallback_reason"],
            "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
        );
    assert_eq!(record["fields"]["socks_listen"], "127.0.0.1:1080");
    assert_eq!(record["fields"]["wide_enabled"], true);
    assert_eq!(record["fields"]["wide_listen"], "0.0.0.0:15080");
    assert_eq!(record["fields"]["wide_platform"], "MacosPf");
    assert_eq!(record["fields"]["wide_platform_code"], "macos_pf");
    assert_eq!(record["fields"]["wide_platform_family_supported"], true);
    assert_eq!(
        record["fields"]["wide_rollout_profile_code"],
        "output_only_safe"
    );
    assert_eq!(record["fields"]["wide_runtime_readiness"], "boundary_only");
    assert_eq!(record["fields"]["wide_supported"], false);
    assert_eq!(
        record["fields"]["wide_udp_capture_contract_requested"],
        "generic_capture_unstable"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_support_tier_requested"],
        "guarded_unstable"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_contract"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_support_tier"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_policy"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_runtime_scope"],
        serde_json::Value::Null
    );
}

#[test]
fn runtime_event_stream_writes_preflight_hint_fields() {
    let path = temp_jsonl_path("preflight-hint");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "warn",
        RuntimeEventCode::IngressPreflightHint,
        "ingress preflight",
        json!({
            "hint_code": "linux_tproxy_requires_ip_transparent",
            "severity": "warn",
            "hint": "selected wide backend requires additional platform privileges"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_preflight_hint");
    assert_eq!(
        record["fields"]["hint_code"],
        "linux_tproxy_requires_ip_transparent"
    );
    assert_eq!(record["fields"]["severity"], "warn");
    assert_eq!(
        record["fields"]["hint"],
        "selected wide backend requires additional platform privileges"
    );
}

#[test]
fn runtime_event_stream_writes_external_calibration_applied_fields() {
    let path = temp_jsonl_path("external-calibration-applied");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let snapshot = ExternalCalibrationSnapshot {
        schema_version: 1,
        source: "external_calibration_summary".to_string(),
        generated_at_unix_ms: None,
        freshness_half_life_secs: None,
        witness: vec![ExternalWitnessCalibration {
            label: "https_ws".to_string(),
            records: 2,
            combined_avg: 0.7,
            ja3_present_avg: 1.0,
            alpn_match_avg: 0.75,
            sni_structure_avg: 0.55,
        }],
        adversarial: vec![ExternalAdversarialCalibration {
            transport: "https_ws".to_string(),
            records: 2,
            measured: 2,
            planned: 0,
            passed: 1,
            failed: 1,
            pass_rate: Some(0.5),
            threshold: Some(0.85),
        }],
        knowledge: Vec::new(),
        verdict: ExternalCalibrationVerdict {
            status: "MEASURED".to_string(),
            acceptance_degraded: false,
            reasons: Vec::new(),
        },
    };

    stream.emit_external_calibration_applied(&snapshot);

    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "external_calibration_applied");
    assert_eq!(record["fields"]["source"], "external_calibration_summary");
    assert_eq!(record["fields"]["witness_label_count"], 1);
    assert_eq!(record["fields"]["adversarial_transport_count"], 1);
    assert_eq!(record["fields"]["verdict_status"], "MEASURED");
    assert_eq!(record["fields"]["acceptance_degraded"], false);
}

#[test]
fn runtime_event_stream_writes_knowledge_prior_applied_fields() {
    let path = temp_jsonl_path("knowledge-prior-applied");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let prior = ExternalKnowledgePrior {
        target_class: "https_ws".to_string(),
        region_id: Some("0x4f2a1b8e".to_string()),
        score: 0.72,
        confidence: 0.65,
        hard_excluded: false,
        fail_closed: false,
        generated_at_unix_ms: None,
    };

    stream.emit_knowledge_prior_applied(&prior);

    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "knowledge_prior_applied");
    assert_eq!(record["fields"]["target_class"], "https_ws");
    assert_eq!(record["fields"]["region_id"], "0x4f2a1b8e");
    assert_eq!(record["fields"]["score"], 0.72);
    assert_eq!(record["fields"]["confidence"], 0.65);
    assert_eq!(record["fields"]["hard_excluded"], false);
}

#[test]
fn runtime_event_stream_writes_startup_selection_failed_fields() {
    let path = temp_jsonl_path("startup-selection-failed");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "error",
        RuntimeEventCode::IngressStartupSelectionFailed,
        "ingress startup selection failed",
        json!({
            "allow_fallback": false,
            "requested_primary": "Wide",
            "requested_primary_code": "wide",
            "reason": "selected wide backend is unsupported on this platform",
            "selection_error_code": "unsupported_wide_backend",
            "selection_hint_code": "use_supported_backend_or_allow_fallback",
            "hint": "switch to socks5 primary or choose a supported wide backend",
            "wide_enabled": true,
            "wide_supported": false,
            "wide_platform_family_supported": false,
            "wide_runtime_readiness": "unsupported_adapter",
            "wide_platform": "MacosPf",
            "wide_platform_code": "macos_pf",
            "wide_rollout_profile": "OutputOnlySafe",
            "wide_rollout_profile_code": "output_only_safe",
            "wide_prerouting_interface": null,
            "wide_udp_capture_contract_requested": "preview_allowlist_only",
            "wide_udp_capture_support_tier_requested": "supported_preview",
            "wide_udp_capture_contract": null,
            "wide_udp_capture_support_tier": null,
            "wide_udp_capture_policy": null,
            "wide_udp_capture_runtime_scope": null
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_startup_selection_failed");
    assert_eq!(
        record["fields"]["selection_error_code"],
        "unsupported_wide_backend"
    );
    assert_eq!(
        record["fields"]["selection_hint_code"],
        "use_supported_backend_or_allow_fallback"
    );
    assert_eq!(record["fields"]["requested_primary"], "Wide");
    assert_eq!(record["fields"]["requested_primary_code"], "wide");
    assert_eq!(record["fields"]["wide_platform_code"], "macos_pf");
    assert_eq!(
        record["fields"]["wide_udp_capture_contract_requested"],
        "preview_allowlist_only"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_support_tier_requested"],
        "supported_preview"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_contract"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_support_tier"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_policy"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_runtime_scope"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["wide_rollout_profile_code"],
        "output_only_safe"
    );
    assert_eq!(
        record["fields"]["wide_runtime_readiness"],
        "unsupported_adapter"
    );
}

#[test]
fn runtime_event_stream_writes_boundary_only_startup_selection_failed_fields() {
    let path = temp_jsonl_path("startup-selection-failed-boundary-only");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
            "error",
            RuntimeEventCode::IngressStartupSelectionFailed,
            "ingress startup selection failed",
            json!({
                "allow_fallback": false,
                "requested_primary": "Wide",
                "requested_primary_code": "wide",
                "reason": "wide ingress is selected, but unavailable: macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists",
                "selection_error_code": "wide_backend_boundary_only",
                "selection_hint_code": "use_supported_backend_or_allow_fallback",
                "hint": "macos_pf system_wide_phase3 is currently boundary-only; allow fallback or stay on the narrower tcp_only/dns_preview contours while testing",
                "wide_enabled": true,
                "wide_supported": false,
                "wide_platform_family_supported": true,
                "wide_runtime_readiness": "boundary_only",
                "wide_platform": "MacosPf",
                "wide_platform_code": "macos_pf",
                "wide_rollout_profile": "OutputOnlySafe",
                "wide_rollout_profile_code": "output_only_safe",
                "wide_prerouting_interface": null,
                "wide_udp_capture_contract_requested": "generic_capture_unstable",
                "wide_udp_capture_support_tier_requested": "guarded_unstable",
                "wide_udp_capture_contract": null,
                "wide_udp_capture_support_tier": null,
                "wide_udp_capture_policy": null,
                "wide_udp_capture_runtime_scope": null
            }),
        );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_startup_selection_failed");
    assert_eq!(
        record["fields"]["selection_error_code"],
        "wide_backend_boundary_only"
    );
    assert_eq!(
        record["fields"]["selection_hint_code"],
        "use_supported_backend_or_allow_fallback"
    );
    assert_eq!(
            record["fields"]["reason"],
            "wide ingress is selected, but unavailable: macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
        );
    assert_eq!(
            record["fields"]["hint"],
            "macos_pf system_wide_phase3 is currently boundary-only; allow fallback or stay on the narrower tcp_only/dns_preview contours while testing"
        );
    assert_eq!(record["fields"]["wide_platform_code"], "macos_pf");
    assert_eq!(
        record["fields"]["wide_udp_capture_contract_requested"],
        "generic_capture_unstable"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_support_tier_requested"],
        "guarded_unstable"
    );
    assert_eq!(record["fields"]["wide_runtime_readiness"], "boundary_only");
}

#[test]
fn runtime_event_stream_writes_wide_bind_fallback_fields() {
    let path = temp_jsonl_path("wide-bind-fallback");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "warn",
        RuntimeEventCode::IngressWideBindFallback,
        "wide ingress bind failed, falling back to SOCKS5 backend",
        json!({
            "requested_primary": "Wide",
            "requested_primary_code": "wide",
            "listen": "0.0.0.0:15080",
            "wide_supported": true,
            "wide_platform_family_supported": true,
            "wide_runtime_readiness": "ready",
            "platform_backend": "LinuxRedirect",
            "platform_backend_code": "linux_redirect",
            "rollout_profile": "OutputOnlySafe",
            "rollout_profile_code": "output_only_safe",
            "prerouting_interface": null,
            "fallback_backend": "socks5_fallback",
            "bind_error_code": "listener_busy",
            "bind_hint_code": "verify_wide_listen_is_free",
            "error": "Address already in use (os error 48)",
            "hint": "verify that the configured wide listen address/port is free"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_wide_bind_fallback");
    assert_eq!(record["fields"]["requested_primary"], "Wide");
    assert_eq!(record["fields"]["requested_primary_code"], "wide");
    assert_eq!(record["fields"]["wide_runtime_readiness"], "ready");
    assert_eq!(record["fields"]["fallback_backend"], "socks5_fallback");
    assert_eq!(record["fields"]["bind_error_code"], "listener_busy");
    assert_eq!(
        record["fields"]["bind_hint_code"],
        "verify_wide_listen_is_free"
    );
    assert_eq!(record["fields"]["platform_backend"], "LinuxRedirect");
    assert_eq!(record["fields"]["platform_backend_code"], "linux_redirect");
    assert_eq!(record["fields"]["rollout_profile_code"], "output_only_safe");
}

#[test]
fn runtime_event_stream_writes_startup_fallback_selected_fields() {
    let path = temp_jsonl_path("startup-fallback-selected");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "warn",
        RuntimeEventCode::IngressStartupFallbackSelected,
        "wide ingress unavailable, falling back to SOCKS5 backend",
        json!({
            "requested_primary": "Wide",
            "requested_primary_code": "wide",
            "listen": "127.0.0.1:1080",
            "fallback_reason_code": "wide_disabled_in_config",
            "reason": "wide ingress is disabled in config",
            "wide_enabled": false,
            "wide_supported": false,
            "wide_platform_family_supported": false,
            "wide_runtime_readiness": "disabled",
            "wide_platform": "Auto",
            "wide_platform_code": "auto",
            "wide_rollout_profile": "OutputOnlySafe",
            "wide_rollout_profile_code": "output_only_safe",
            "wide_prerouting_interface": null,
            "fallback_backend": "socks5_fallback"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_startup_fallback_selected");
    assert_eq!(record["fields"]["requested_primary"], "Wide");
    assert_eq!(record["fields"]["requested_primary_code"], "wide");
    assert_eq!(
        record["fields"]["fallback_reason_code"],
        "wide_disabled_in_config"
    );
    assert_eq!(record["fields"]["wide_runtime_readiness"], "disabled");
    assert_eq!(record["fields"]["wide_platform_code"], "auto");
    assert_eq!(
        record["fields"]["wide_rollout_profile_code"],
        "output_only_safe"
    );
    assert_eq!(record["fields"]["fallback_backend"], "socks5_fallback");
    assert_eq!(record["fields"]["listen"], "127.0.0.1:1080");
}

#[test]
fn runtime_event_stream_writes_boundary_only_startup_fallback_selected_fields() {
    let path = temp_jsonl_path("startup-fallback-selected-boundary-only");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
            "warn",
            RuntimeEventCode::IngressStartupFallbackSelected,
            "wide ingress unavailable, falling back to SOCKS5 backend",
            json!({
                "requested_primary": "Wide",
                "requested_primary_code": "wide",
                "listen": "127.0.0.1:1080",
                "fallback_reason_code": "wide_backend_boundary_only",
                "reason": "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists",
                "wide_enabled": true,
                "wide_supported": false,
                "wide_platform_family_supported": true,
                "wide_runtime_readiness": "boundary_only",
                "wide_platform": "MacosPf",
                "wide_platform_code": "macos_pf",
                "wide_rollout_profile": "OutputOnlySafe",
                "wide_rollout_profile_code": "output_only_safe",
                "wide_prerouting_interface": null,
                "fallback_backend": "socks5_fallback"
            }),
        );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_startup_fallback_selected");
    assert_eq!(
        record["fields"]["fallback_reason_code"],
        "wide_backend_boundary_only"
    );
    assert_eq!(
            record["fields"]["reason"],
            "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
        );
    assert_eq!(record["fields"]["wide_runtime_readiness"], "boundary_only");
    assert_eq!(record["fields"]["wide_platform_code"], "macos_pf");
    assert_eq!(record["fields"]["fallback_backend"], "socks5_fallback");
    assert_eq!(record["fields"]["listen"], "127.0.0.1:1080");
}

#[test]
fn runtime_event_stream_writes_accept_failed_fields() {
    let path = temp_jsonl_path("accept-failed");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "warn",
        RuntimeEventCode::IngressAcceptFailed,
        "ingress accept failed",
        json!({
            "backend": "socks5_fallback",
            "backend_runtime_id": "socks5_fallback",
            "backend_kind": "Socks5Fallback",
            "backend_kind_code": "socks5_fallback",
            "requested_primary": "Socks5",
            "requested_primary_code": "socks5",
            "mode": "Direct",
            "mode_code": "direct",
            "wide_supported": true,
            "wide_platform_family_supported": true,
            "wide_runtime_readiness": "ready",
            "rollout_profile": "OutputOnlySafe",
            "rollout_profile_code": "output_only_safe",
            "prerouting_interface": null,
            "startup_path_code": "socks5_fallback_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": null,
            "accept_error_kind": "unexpected_eof",
            "error": "socks5_handshake: early eof"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_accept_failed");
    assert_eq!(record["fields"]["backend"], "socks5_fallback");
    assert_eq!(record["fields"]["backend_runtime_id"], "socks5_fallback");
    assert_eq!(record["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(record["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["requested_primary"], "Socks5");
    assert_eq!(record["fields"]["requested_primary_code"], "socks5");
    assert_eq!(record["fields"]["mode"], "Direct");
    assert_eq!(record["fields"]["mode_code"], "direct");
    assert_eq!(record["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(record["fields"]["accept_error_kind"], "unexpected_eof");
    assert_eq!(record["fields"]["error"], "socks5_handshake: early eof");
}

#[test]
fn runtime_event_stream_writes_session_failed_fields() {
    let path = temp_jsonl_path("session-failed");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "error",
        RuntimeEventCode::IngressSessionFailed,
        "ingress session failed",
        json!({
            "peer": "127.0.0.1:45678",
            "ingress_kind": "Socks5Fallback",
            "ingress_kind_code": "socks5_fallback",
            "session_kind": "Socks5Fallback",
            "session_kind_code": "socks5_fallback",
            "backend": "socks5_fallback",
            "backend_kind": "Socks5Fallback",
            "backend_kind_code": "socks5_fallback",
            "requested_primary": "Wide",
            "requested_primary_code": "wide",
            "mode": "Direct",
            "mode_code": "direct",
            "wide_supported": false,
            "wide_platform_family_supported": false,
            "wide_runtime_readiness": "disabled",
            "rollout_profile": "OutputOnlySafe",
            "rollout_profile_code": "output_only_safe",
            "prerouting_interface": null,
            "startup_path_code": "wide_bind_failed_fallback_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": "listener_busy",
            "relay_terminal": true,
            "relay_target": "127.0.0.1",
            "relay_port": 443,
            "relay_server": "127.0.0.1:1",
            "relay_server_name": "localhost",
            "relay_attempts_total": 1,
            "relay_planned_transports": ["LegacyTls"],
            "relay_last_transport": "LegacyTls",
            "direct_relay_handoff": true,
            "direct_relay_handoff_path": "runtime_failover",
            "direct_relay_handoff_reason_code": "probe_retry_budget_exhausted",
            "direct_relay_handoff_retry_attempted": true,
            "session_error_kind": "connection_refused",
            "error": "connect relay 127.0.0.1:1: Connection refused (os error 61)",
            "error_chain": [
                "connect relay 127.0.0.1:1",
                "Connection refused (os error 61)"
            ]
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_session_failed");
    assert_eq!(record["fields"]["backend"], "socks5_fallback");
    assert_eq!(record["fields"]["requested_primary"], "Wide");
    assert_eq!(record["fields"]["requested_primary_code"], "wide");
    assert_eq!(record["fields"]["wide_runtime_readiness"], "disabled");
    assert_eq!(record["fields"]["session_kind"], "Socks5Fallback");
    assert_eq!(record["fields"]["ingress_kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["session_kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["mode_code"], "direct");
    assert_eq!(record["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "wide_bind_failed_fallback_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(record["fields"]["startup_bind_error_code"], "listener_busy");
    assert_eq!(record["fields"]["relay_terminal"], true);
    assert_eq!(record["fields"]["relay_target"], "127.0.0.1");
    assert_eq!(record["fields"]["relay_port"], 443);
    assert_eq!(record["fields"]["relay_attempts_total"], 1);
    assert_eq!(
        record["fields"]["relay_planned_transports"],
        json!(["LegacyTls"])
    );
    assert_eq!(record["fields"]["relay_last_transport"], "LegacyTls");
    assert_eq!(record["fields"]["direct_relay_handoff"], true);
    assert_eq!(
        record["fields"]["direct_relay_handoff_path"],
        "runtime_failover"
    );
    assert_eq!(
        record["fields"]["direct_relay_handoff_reason_code"],
        "probe_retry_budget_exhausted"
    );
    assert_eq!(
        record["fields"]["direct_relay_handoff_retry_attempted"],
        true
    );
    assert_eq!(record["fields"]["session_error_kind"], "connection_refused");
    assert_eq!(
        record["fields"]["error_chain"],
        json!([
            "connect relay 127.0.0.1:1",
            "Connection refused (os error 61)"
        ])
    );
}

#[test]
fn runtime_event_stream_writes_session_broker_failed_fields() {
    let path = temp_jsonl_path("session-broker-failed");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "error",
        RuntimeEventCode::IngressSessionBrokerFailed,
        "session broker failed",
        json!({
            "peer": "127.0.0.1:45679",
            "ingress_kind": "Socks5Fallback",
            "ingress_kind_code": "socks5_fallback",
            "backend": "socks5_fallback",
            "backend_kind": "Socks5Fallback",
            "backend_kind_code": "socks5_fallback",
            "requested_primary": "Socks5",
            "requested_primary_code": "socks5",
            "mode": "Direct",
            "mode_code": "direct",
            "wide_supported": true,
            "wide_platform_family_supported": true,
            "wide_runtime_readiness": "ready",
            "rollout_profile": "OutputOnlySafe",
            "rollout_profile_code": "output_only_safe",
            "prerouting_interface": null,
            "startup_path_code": "wide_bind_failed_fallback_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": "listener_busy",
            "broker_error_code": "resolve_failed",
            "broker_source_error_kind": "other",
            "request_kind": "TcpConnect",
            "broker_stage": "resolve_target",
            "target_host": "nonexistent.invalid",
            "target_port": 443,
            "client_ip": null,
            "udp_bind_addr": null,
            "response_action": null,
            "error": "resolve target nonexistent.invalid:443: failed to lookup address information"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_session_broker_failed");
    assert_eq!(record["fields"]["backend"], "socks5_fallback");
    assert_eq!(record["fields"]["requested_primary"], "Socks5");
    assert_eq!(record["fields"]["requested_primary_code"], "socks5");
    assert_eq!(record["fields"]["wide_runtime_readiness"], "ready");
    assert_eq!(record["fields"]["ingress_kind"], "Socks5Fallback");
    assert_eq!(record["fields"]["ingress_kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["mode_code"], "direct");
    assert_eq!(record["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "wide_bind_failed_fallback_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(record["fields"]["startup_bind_error_code"], "listener_busy");
    assert_eq!(record["fields"]["broker_error_code"], "resolve_failed");
    assert_eq!(record["fields"]["broker_source_error_kind"], "other");
    assert_eq!(record["fields"]["request_kind"], "TcpConnect");
    assert_eq!(record["fields"]["broker_stage"], "resolve_target");
    assert_eq!(record["fields"]["target_host"], "nonexistent.invalid");
    assert_eq!(record["fields"]["target_port"], 443);
}

#[test]
fn runtime_event_stream_writes_boundary_only_session_broker_failed_fields() {
    let path = temp_jsonl_path("session-broker-failed-boundary-only");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
            "error",
            RuntimeEventCode::IngressSessionBrokerFailed,
            "session broker failed",
            json!({
                "peer": "127.0.0.1:45679",
                "ingress_kind": "Socks5Fallback",
                "ingress_kind_code": "socks5_fallback",
                "backend": "socks5_fallback",
                "backend_kind": "Socks5Fallback",
                "backend_kind_code": "socks5_fallback",
                "requested_primary": "Wide",
                "requested_primary_code": "wide",
                "mode": "Direct",
                "mode_code": "direct",
                "wide_supported": false,
                "wide_platform_family_supported": true,
                "wide_runtime_readiness": "boundary_only",
                "rollout_profile": "OutputOnlySafe",
                "rollout_profile_code": "output_only_safe",
                "prerouting_interface": null,
                "startup_path_code": "socks5_fallback_started",
                "startup_fallback_reason_code": "wide_backend_boundary_only",
                "startup_fallback_reason": "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists",
                "startup_bind_error_code": null,
                "broker_error_code": "resolve_failed",
                "broker_source_error_kind": "other",
                "request_kind": "TcpConnect",
                "broker_stage": "resolve_target",
                "target_host": "nonexistent.invalid",
                "target_port": 443,
                "client_ip": null,
                "udp_bind_addr": null,
                "response_action": null,
                "error": "resolve target nonexistent.invalid:443: failed to lookup address information"
            }),
        );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_session_broker_failed");
    assert_eq!(record["fields"]["backend"], "socks5_fallback");
    assert_eq!(record["fields"]["requested_primary"], "Wide");
    assert_eq!(record["fields"]["requested_primary_code"], "wide");
    assert_eq!(record["fields"]["wide_runtime_readiness"], "boundary_only");
    assert_eq!(record["fields"]["ingress_kind"], "Socks5Fallback");
    assert_eq!(record["fields"]["ingress_kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["mode_code"], "direct");
    assert_eq!(record["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        "wide_backend_boundary_only"
    );
    assert_eq!(
            record["fields"]["startup_fallback_reason"],
            "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
        );
    assert_eq!(
        record["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(record["fields"]["broker_error_code"], "resolve_failed");
    assert_eq!(record["fields"]["broker_source_error_kind"], "other");
    assert_eq!(record["fields"]["request_kind"], "TcpConnect");
    assert_eq!(record["fields"]["broker_stage"], "resolve_target");
    assert_eq!(record["fields"]["target_host"], "nonexistent.invalid");
    assert_eq!(record["fields"]["target_port"], 443);
}

#[test]
fn runtime_event_stream_writes_tcp_connect_rejected_fields() {
    let path = temp_jsonl_path("tcp-connect-rejected");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "error",
        RuntimeEventCode::IngressTcpConnectRejected,
        "tcp connect rejected",
        json!({
            "peer": "127.0.0.1:45680",
            "backend": "socks5_fallback",
            "backend_kind": "Socks5Fallback",
            "backend_kind_code": "socks5_fallback",
            "requested_primary": "Socks5",
            "requested_primary_code": "socks5",
            "mode": "Relay",
            "mode_code": "relay",
            "wide_supported": true,
            "wide_platform_family_supported": true,
            "wide_runtime_readiness": "ready",
            "rollout_profile": "OutputOnlySafe",
            "rollout_profile_code": "output_only_safe",
            "prerouting_interface": null,
            "startup_path_code": "socks5_fallback_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": null,
            "request_kind": "TcpConnect",
            "reject_stage": "pre_broker_runtime_gate",
            "response_action": "send_general_failure",
            "response_reply_code": 1,
            "reject_reason_code": "tcp_connect_requires_runtime_ready_relay_transport",
            "reason": "relay mode requires a runtime-ready relay transport"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_tcp_connect_rejected");
    assert_eq!(record["fields"]["backend"], "socks5_fallback");
    assert_eq!(record["fields"]["requested_primary"], "Socks5");
    assert_eq!(record["fields"]["requested_primary_code"], "socks5");
    assert_eq!(record["fields"]["mode"], "Relay");
    assert_eq!(record["fields"]["mode_code"], "relay");
    assert_eq!(record["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(record["fields"]["request_kind"], "TcpConnect");
    assert_eq!(record["fields"]["reject_stage"], "pre_broker_runtime_gate");
    assert_eq!(record["fields"]["response_action"], "send_general_failure");
    assert_eq!(record["fields"]["response_reply_code"], 1);
    assert_eq!(
        record["fields"]["reject_reason_code"],
        "tcp_connect_requires_runtime_ready_relay_transport"
    );
    assert_eq!(
        record["fields"]["reason"],
        "relay mode requires a runtime-ready relay transport"
    );
}

#[test]
fn runtime_event_stream_writes_tcp_connect_reject_response_failed_fields() {
    let path = temp_jsonl_path("tcp-connect-reject-response-failed");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "error",
        RuntimeEventCode::IngressTcpConnectRejectResponseFailed,
        "failed to reject TCP connect response",
        json!({
            "peer": "127.0.0.1:45681",
            "backend": "socks5_fallback",
            "backend_kind": "Socks5Fallback",
            "backend_kind_code": "socks5_fallback",
            "requested_primary": "Socks5",
            "requested_primary_code": "socks5",
            "mode": "Relay",
            "mode_code": "relay",
            "wide_supported": true,
            "wide_platform_family_supported": true,
            "wide_runtime_readiness": "ready",
            "rollout_profile": "OutputOnlySafe",
            "rollout_profile_code": "output_only_safe",
            "prerouting_interface": null,
            "startup_path_code": "socks5_fallback_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": null,
            "request_kind": "TcpConnect",
            "reject_stage": "pre_broker_runtime_gate",
            "response_action": "send_general_failure",
            "response_reply_code": 1,
            "reject_reason_code": "tcp_connect_requires_runtime_ready_relay_transport",
            "reason": "relay mode requires a runtime-ready relay transport",
            "response_error_kind": "broken_pipe",
            "error": "Broken pipe (os error 32)"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(
        record["event_code"],
        "ingress_tcp_connect_reject_response_failed"
    );
    assert_eq!(record["fields"]["backend"], "socks5_fallback");
    assert_eq!(record["fields"]["requested_primary"], "Socks5");
    assert_eq!(record["fields"]["requested_primary_code"], "socks5");
    assert_eq!(record["fields"]["mode"], "Relay");
    assert_eq!(record["fields"]["mode_code"], "relay");
    assert_eq!(record["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(record["fields"]["request_kind"], "TcpConnect");
    assert_eq!(record["fields"]["reject_stage"], "pre_broker_runtime_gate");
    assert_eq!(record["fields"]["response_action"], "send_general_failure");
    assert_eq!(record["fields"]["response_reply_code"], 1);
    assert_eq!(
        record["fields"]["reject_reason_code"],
        "tcp_connect_requires_runtime_ready_relay_transport"
    );
    assert_eq!(
        record["fields"]["reason"],
        "relay mode requires a runtime-ready relay transport"
    );
    assert_eq!(record["fields"]["response_error_kind"], "broken_pipe");
    assert_eq!(record["fields"]["error"], "Broken pipe (os error 32)");
}

#[test]
fn runtime_event_stream_writes_udp_associate_rejected_fields() {
    let path = temp_jsonl_path("udp-associate-rejected");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "error",
        RuntimeEventCode::IngressUdpAssociateRejected,
        "udp associate rejected",
        json!({
            "peer": "127.0.0.1:45680",
            "backend": "socks5_fallback",
            "backend_kind": "Socks5Fallback",
            "backend_kind_code": "socks5_fallback",
            "requested_primary": "Socks5",
            "requested_primary_code": "socks5",
            "mode": "Direct",
            "mode_code": "direct",
            "wide_supported": true,
            "wide_platform_family_supported": true,
            "wide_runtime_readiness": "ready",
            "rollout_profile": "OutputOnlySafe",
            "rollout_profile_code": "output_only_safe",
            "prerouting_interface": null,
            "startup_path_code": "socks5_fallback_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": null,
            "request_kind": "UdpAssociate",
            "reject_stage": "pre_broker_runtime_gate",
            "response_action": "send_command_not_supported",
            "response_reply_code": 7,
            "reject_reason_code": "udp_associate_requires_relay_mode",
            "reason": "udp associate requires relay mode"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_udp_associate_rejected");
    assert_eq!(record["fields"]["backend"], "socks5_fallback");
    assert_eq!(record["fields"]["requested_primary"], "Socks5");
    assert_eq!(record["fields"]["requested_primary_code"], "socks5");
    assert_eq!(record["fields"]["wide_runtime_readiness"], "ready");
    assert_eq!(record["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["mode_code"], "direct");
    assert_eq!(record["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(record["fields"]["request_kind"], "UdpAssociate");
    assert_eq!(record["fields"]["reject_stage"], "pre_broker_runtime_gate");
    assert_eq!(
        record["fields"]["response_action"],
        "send_command_not_supported"
    );
    assert_eq!(record["fields"]["response_reply_code"], 7);
    assert_eq!(
        record["fields"]["reject_reason_code"],
        "udp_associate_requires_relay_mode"
    );
    assert_eq!(
        record["fields"]["reason"],
        "udp associate requires relay mode"
    );
}

#[test]
fn runtime_event_stream_writes_udp_associate_reject_response_failed_fields() {
    let path = temp_jsonl_path("udp-associate-reject-response-failed");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "error",
        RuntimeEventCode::IngressUdpAssociateRejectResponseFailed,
        "failed to reject UDP associate response",
        json!({
            "peer": "127.0.0.1:45681",
            "backend": "socks5_fallback",
            "backend_kind": "Socks5Fallback",
            "backend_kind_code": "socks5_fallback",
            "requested_primary": "Socks5",
            "requested_primary_code": "socks5",
            "mode": "Direct",
            "mode_code": "direct",
            "wide_supported": true,
            "wide_platform_family_supported": true,
            "wide_runtime_readiness": "ready",
            "rollout_profile": "OutputOnlySafe",
            "rollout_profile_code": "output_only_safe",
            "prerouting_interface": null,
            "startup_path_code": "socks5_fallback_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": null,
            "request_kind": "UdpAssociate",
            "reject_stage": "pre_broker_runtime_gate",
            "response_action": "send_general_failure",
            "response_reply_code": 1,
            "reject_reason_code": "udp_associate_requires_udp_capable_relay_transport",
            "reason": "udp associate requires a configured MASQUE relay; gRPC datagrams are fixed-destination only",
            "response_error_kind": "broken_pipe",
            "error": "Broken pipe (os error 32)"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(
        record["event_code"],
        "ingress_udp_associate_reject_response_failed"
    );
    assert_eq!(record["fields"]["backend"], "socks5_fallback");
    assert_eq!(record["fields"]["requested_primary"], "Socks5");
    assert_eq!(record["fields"]["requested_primary_code"], "socks5");
    assert_eq!(record["fields"]["wide_runtime_readiness"], "ready");
    assert_eq!(record["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(record["fields"]["mode_code"], "direct");
    assert_eq!(record["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(record["fields"]["request_kind"], "UdpAssociate");
    assert_eq!(record["fields"]["reject_stage"], "pre_broker_runtime_gate");
    assert_eq!(record["fields"]["response_action"], "send_general_failure");
    assert_eq!(record["fields"]["response_reply_code"], 1);
    assert_eq!(
        record["fields"]["reject_reason_code"],
        "udp_associate_requires_udp_capable_relay_transport"
    );
    assert_eq!(
        record["fields"]["reason"],
        "udp associate requires a configured MASQUE relay; gRPC datagrams are fixed-destination only"
    );
    assert_eq!(record["fields"]["response_error_kind"], "broken_pipe");
    assert_eq!(record["fields"]["error"], "Broken pipe (os error 32)");
}

#[test]
fn runtime_event_stream_writes_relay_transport_failed_fields() {
    let path = temp_jsonl_path("relay-transport-failed");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "warn",
        RuntimeEventCode::RelayTransportFailed,
        "relay transport failed",
        json!({
            "transport": "LegacyTls",
            "target": "127.0.0.1",
            "port": 443,
            "relay_server": "127.0.0.1:1",
            "relay_server_name": "localhost",
            "attempt_index": 1,
            "attempts_total": 1,
            "planned_transports": ["LegacyTls"],
            "relay_error_kind": "connection_refused",
            "relay_failure_scope": "real_transport_outage",
            "relay_tunnel_status": null,
            "error": "connect relay 127.0.0.1:1",
            "error_chain": [
                "connect relay 127.0.0.1:1",
                "Connection refused (os error 61)"
            ]
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "relay_transport_failed");
    assert_eq!(record["fields"]["transport"], "LegacyTls");
    assert_eq!(record["fields"]["target"], "127.0.0.1");
    assert_eq!(record["fields"]["relay_server"], "127.0.0.1:1");
    assert_eq!(record["fields"]["attempt_index"], 1);
    assert_eq!(record["fields"]["planned_transports"][0], "LegacyTls");
    assert_eq!(record["fields"]["relay_error_kind"], "connection_refused");
    assert_eq!(
        record["fields"]["relay_failure_scope"],
        "real_transport_outage"
    );
    assert_eq!(record["fields"]["relay_tunnel_status"], Value::Null);
    assert_eq!(record["fields"]["error"], "connect relay 127.0.0.1:1");
    assert_eq!(
        record["fields"]["error_chain"],
        json!([
            "connect relay 127.0.0.1:1",
            "Connection refused (os error 61)"
        ])
    );
}

#[test]
fn runtime_event_stream_writes_udp_datagram_observed_fields() {
    let path = temp_jsonl_path("udp-datagram-observed");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "info",
        RuntimeEventCode::IngressUdpDatagramObserved,
        "ingress udp datagram observed",
        json!({
            "peer": "198.18.0.2:53000",
            "backend": "wide_primary",
            "backend_runtime_id": "wide_primary_linux",
            "backend_kind": "WidePrimary",
            "backend_kind_code": "wide_primary",
            "requested_primary": "Wide",
            "requested_primary_code": "wide",
            "mode": "Relay",
            "mode_code": "relay",
            "wide_supported": true,
            "wide_platform_family_supported": true,
            "wide_runtime_readiness": "ready",
            "rollout_profile": "TransparentPrivileged",
            "rollout_profile_code": "transparent_privileged",
            "prerouting_interface": "aegisvh1",
            "startup_path_code": "wide_primary_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": null,
            "wide_udp_capture_contract": "preview_allowlist_only",
            "wide_udp_capture_policy": "allowlist_ports",
            "wide_udp_capture_runtime_scope": "linux_ipv4_only",
            "wide_udp_capture_match_kind": "dns_port",
            "wide_udp_capture_accept_reason_code": "matched_dns_port_allowlist",
            "wide_udp_preview_policy": "allowlist_ports",
            "wide_udp_preview_match_kind": "dns_port",
            "wide_udp_preview_accept_reason_code": "matched_dns_port_allowlist",
            "wide_udp_preview_ports": [53, 5353],
            "target_host": "198.18.0.53",
            "target_port": 53,
            "payload_len": 17,
            "response_action": "local_udp"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_udp_datagram_observed");
    assert_eq!(record["fields"]["backend"], "wide_primary");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "wide_primary_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(record["fields"]["target_host"], "198.18.0.53");
    assert_eq!(record["fields"]["target_port"], 53);
    assert_eq!(
        record["fields"]["wide_udp_capture_contract"],
        "preview_allowlist_only"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_policy"],
        "allowlist_ports"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_runtime_scope"],
        "linux_ipv4_only"
    );
    assert_eq!(record["fields"]["wide_udp_capture_match_kind"], "dns_port");
    assert_eq!(
        record["fields"]["wide_udp_capture_accept_reason_code"],
        "matched_dns_port_allowlist"
    );
    assert_eq!(
        record["fields"]["wide_udp_preview_policy"],
        "allowlist_ports"
    );
    assert_eq!(record["fields"]["wide_udp_preview_match_kind"], "dns_port");
    assert_eq!(
        record["fields"]["wide_udp_preview_accept_reason_code"],
        "matched_dns_port_allowlist"
    );
    assert_eq!(
        record["fields"]["wide_udp_preview_ports"],
        json!([53, 5353])
    );
    assert_eq!(record["fields"]["payload_len"], 17);
    assert_eq!(record["fields"]["response_action"], "local_udp");
}

#[test]
fn runtime_event_stream_writes_udp_datagram_dropped_fields() {
    let path = temp_jsonl_path("udp-datagram-dropped");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "info",
        RuntimeEventCode::IngressUdpDatagramDropped,
        "ingress udp datagram dropped",
        json!({
            "peer": "198.18.0.2:53000",
            "startup_path_code": "wide_primary_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": null,
            "target_host": "198.18.0.53",
            "target_port": 15080,
            "payload_len": 17,
            "wide_udp_capture_contract": "preview_allowlist_only",
            "wide_udp_capture_policy": "allowlist_ports",
            "wide_udp_capture_runtime_scope": "linux_ipv4_only",
            "wide_udp_capture_drop_stage": "capture_policy_gate",
            "wide_udp_capture_drop_reason_code": "target_port_outside_capture_policy",
            "wide_udp_preview_policy": "allowlist_ports",
            "expected_dns_port": 53,
            "expected_udp_preview_ports": [53, 5353],
            "drop_reason_code": "target_port_not_udp_preview"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_udp_datagram_dropped");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "wide_primary_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(record["fields"]["target_host"], "198.18.0.53");
    assert_eq!(record["fields"]["target_port"], 15080);
    assert_eq!(
        record["fields"]["wide_udp_capture_contract"],
        "preview_allowlist_only"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_policy"],
        "allowlist_ports"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_runtime_scope"],
        "linux_ipv4_only"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_drop_stage"],
        "capture_policy_gate"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_drop_reason_code"],
        "target_port_outside_capture_policy"
    );
    assert_eq!(
        record["fields"]["wide_udp_preview_policy"],
        "allowlist_ports"
    );
    assert_eq!(record["fields"]["expected_dns_port"], 53);
    assert_eq!(
        record["fields"]["expected_udp_preview_ports"],
        json!([53, 5353])
    );
    assert_eq!(
        record["fields"]["drop_reason_code"],
        "target_port_not_udp_preview"
    );
}

#[test]
fn runtime_event_stream_writes_udp_datagram_completed_fields() {
    let path = temp_jsonl_path("udp-datagram-completed");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "info",
        RuntimeEventCode::IngressUdpDatagramCompleted,
        "ingress udp datagram completed",
        json!({
            "peer": "198.18.0.2:53000",
            "backend": "wide_primary",
            "backend_runtime_id": "wide_primary_linux",
            "backend_kind": "WidePrimary",
            "backend_kind_code": "wide_primary",
            "requested_primary": "Wide",
            "requested_primary_code": "wide",
            "mode": "Relay",
            "mode_code": "relay",
            "wide_supported": true,
            "wide_platform_family_supported": true,
            "wide_runtime_readiness": "ready",
            "rollout_profile": "TransparentPrivileged",
            "rollout_profile_code": "transparent_privileged",
            "prerouting_interface": "aegisvh1",
            "startup_path_code": "wide_primary_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": null,
            "wide_udp_capture_contract": "preview_allowlist_only",
            "wide_udp_capture_policy": "allowlist_ports",
            "wide_udp_capture_runtime_scope": "linux_ipv4_only",
            "wide_udp_capture_match_kind": "dns_port",
            "wide_udp_capture_accept_reason_code": "matched_dns_port_allowlist",
            "wide_udp_preview_policy": "allowlist_ports",
            "wide_udp_preview_match_kind": "dns_port",
            "wide_udp_preview_accept_reason_code": "matched_dns_port_allowlist",
            "wide_udp_preview_ports": [53, 5353],
            "target_host": "198.18.0.53",
            "target_port": 53,
            "response_len": 17,
            "response_action": "local_udp"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_udp_datagram_completed");
    assert_eq!(record["fields"]["backend"], "wide_primary");
    assert_eq!(record["fields"]["backend_runtime_id"], "wide_primary_linux");
    assert_eq!(record["fields"]["backend_kind"], "WidePrimary");
    assert_eq!(record["fields"]["backend_kind_code"], "wide_primary");
    assert_eq!(record["fields"]["requested_primary"], "Wide");
    assert_eq!(record["fields"]["requested_primary_code"], "wide");
    assert_eq!(record["fields"]["mode"], "Relay");
    assert_eq!(record["fields"]["mode_code"], "relay");
    assert_eq!(record["fields"]["wide_supported"], true);
    assert_eq!(record["fields"]["wide_platform_family_supported"], true);
    assert_eq!(record["fields"]["wide_runtime_readiness"], "ready");
    assert_eq!(record["fields"]["rollout_profile"], "TransparentPrivileged");
    assert_eq!(
        record["fields"]["rollout_profile_code"],
        "transparent_privileged"
    );
    assert_eq!(record["fields"]["prerouting_interface"], "aegisvh1");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "wide_primary_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(record["fields"]["target_host"], "198.18.0.53");
    assert_eq!(
        record["fields"]["wide_udp_capture_contract"],
        "preview_allowlist_only"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_policy"],
        "allowlist_ports"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_runtime_scope"],
        "linux_ipv4_only"
    );
    assert_eq!(record["fields"]["wide_udp_capture_match_kind"], "dns_port");
    assert_eq!(
        record["fields"]["wide_udp_capture_accept_reason_code"],
        "matched_dns_port_allowlist"
    );
    assert_eq!(
        record["fields"]["wide_udp_preview_policy"],
        "allowlist_ports"
    );
    assert_eq!(record["fields"]["wide_udp_preview_match_kind"], "dns_port");
    assert_eq!(
        record["fields"]["wide_udp_preview_accept_reason_code"],
        "matched_dns_port_allowlist"
    );
    assert_eq!(
        record["fields"]["wide_udp_preview_ports"],
        json!([53, 5353])
    );
    assert_eq!(record["fields"]["response_len"], 17);
    assert_eq!(record["fields"]["response_action"], "local_udp");
}

#[test]
fn runtime_event_stream_writes_generic_udp_datagram_observed_fields() {
    let path = temp_jsonl_path("udp-datagram-observed-generic");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "info",
        RuntimeEventCode::IngressUdpDatagramObserved,
        "ingress udp datagram observed",
        json!({
            "peer": "198.18.0.2:53000",
            "backend": "wide_primary",
            "backend_runtime_id": "wide_primary_linux",
            "backend_kind": "WidePrimary",
            "backend_kind_code": "wide_primary",
            "requested_primary": "Wide",
            "requested_primary_code": "wide",
            "mode": "Relay",
            "mode_code": "relay",
            "wide_supported": true,
            "wide_platform_family_supported": true,
            "wide_runtime_readiness": "ready",
            "rollout_profile": "TransparentPrivileged",
            "rollout_profile_code": "transparent_privileged",
            "prerouting_interface": "aegisvh1",
            "startup_path_code": "wide_primary_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": null,
            "wide_udp_capture_contract": "generic_capture_unstable",
            "wide_udp_capture_policy": "any_target_port_linux_ipv4_unstable",
            "wide_udp_capture_runtime_scope": "linux_ipv4_only",
            "wide_udp_capture_match_kind": "generic_capture_contract",
            "wide_udp_capture_accept_reason_code": "matched_generic_udp_capture_contract",
            "wide_udp_preview_policy": serde_json::Value::Null,
            "wide_udp_preview_match_kind": serde_json::Value::Null,
            "wide_udp_preview_accept_reason_code": serde_json::Value::Null,
            "wide_udp_preview_ports": [],
            "target_host": "198.18.0.55",
            "target_port": 54321,
            "payload_len": 17,
            "response_action": "local_udp"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_udp_datagram_observed");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "wide_primary_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_contract"],
        "generic_capture_unstable"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_policy"],
        "any_target_port_linux_ipv4_unstable"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_runtime_scope"],
        "linux_ipv4_only"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_match_kind"],
        "generic_capture_contract"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_accept_reason_code"],
        "matched_generic_udp_capture_contract"
    );
    assert_eq!(record["fields"]["wide_udp_preview_policy"], json!(null));
    assert_eq!(record["fields"]["wide_udp_preview_match_kind"], json!(null));
    assert_eq!(
        record["fields"]["wide_udp_preview_accept_reason_code"],
        json!(null)
    );
}

#[test]
fn runtime_event_stream_writes_generic_udp_datagram_completed_fields() {
    let path = temp_jsonl_path("udp-datagram-completed-generic");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "info",
        RuntimeEventCode::IngressUdpDatagramCompleted,
        "ingress udp datagram completed",
        json!({
            "peer": "198.18.0.2:53000",
            "backend": "wide_primary",
            "backend_runtime_id": "wide_primary_linux",
            "backend_kind": "WidePrimary",
            "backend_kind_code": "wide_primary",
            "requested_primary": "Wide",
            "requested_primary_code": "wide",
            "mode": "Relay",
            "mode_code": "relay",
            "wide_supported": true,
            "wide_platform_family_supported": true,
            "wide_runtime_readiness": "ready",
            "rollout_profile": "TransparentPrivileged",
            "rollout_profile_code": "transparent_privileged",
            "prerouting_interface": "aegisvh1",
            "startup_path_code": "wide_primary_started",
            "startup_fallback_reason_code": null,
            "startup_fallback_reason": null,
            "startup_bind_error_code": null,
            "wide_udp_capture_contract": "generic_capture_unstable",
            "wide_udp_capture_policy": "any_target_port_linux_ipv4_unstable",
            "wide_udp_capture_runtime_scope": "linux_ipv4_only",
            "wide_udp_capture_match_kind": "generic_capture_contract",
            "wide_udp_capture_accept_reason_code": "matched_generic_udp_capture_contract",
            "wide_udp_preview_policy": serde_json::Value::Null,
            "wide_udp_preview_match_kind": serde_json::Value::Null,
            "wide_udp_preview_accept_reason_code": serde_json::Value::Null,
            "wide_udp_preview_ports": [],
            "target_host": "198.18.0.55",
            "target_port": 54321,
            "response_len": 17,
            "response_action": "local_udp"
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_udp_datagram_completed");
    assert_eq!(record["fields"]["backend"], "wide_primary");
    assert_eq!(record["fields"]["backend_runtime_id"], "wide_primary_linux");
    assert_eq!(record["fields"]["backend_kind"], "WidePrimary");
    assert_eq!(record["fields"]["backend_kind_code"], "wide_primary");
    assert_eq!(record["fields"]["requested_primary"], "Wide");
    assert_eq!(record["fields"]["requested_primary_code"], "wide");
    assert_eq!(record["fields"]["mode"], "Relay");
    assert_eq!(record["fields"]["mode_code"], "relay");
    assert_eq!(record["fields"]["wide_supported"], true);
    assert_eq!(record["fields"]["wide_platform_family_supported"], true);
    assert_eq!(record["fields"]["wide_runtime_readiness"], "ready");
    assert_eq!(record["fields"]["rollout_profile"], "TransparentPrivileged");
    assert_eq!(
        record["fields"]["rollout_profile_code"],
        "transparent_privileged"
    );
    assert_eq!(record["fields"]["prerouting_interface"], "aegisvh1");
    assert_eq!(
        record["fields"]["startup_path_code"],
        "wide_primary_started"
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_contract"],
        "generic_capture_unstable"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_policy"],
        "any_target_port_linux_ipv4_unstable"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_runtime_scope"],
        "linux_ipv4_only"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_match_kind"],
        "generic_capture_contract"
    );
    assert_eq!(
        record["fields"]["wide_udp_capture_accept_reason_code"],
        "matched_generic_udp_capture_contract"
    );
    assert_eq!(record["fields"]["wide_udp_preview_policy"], json!(null));
    assert_eq!(record["fields"]["wide_udp_preview_match_kind"], json!(null));
    assert_eq!(
        record["fields"]["wide_udp_preview_accept_reason_code"],
        json!(null)
    );
}

#[test]
fn runtime_event_stream_writes_udp_datagram_response_stage_fields() {
    let path = temp_jsonl_path("udp-datagram-response-stage");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "info",
        RuntimeEventCode::IngressUdpDatagramResponseStage,
        "ingress udp datagram response stage",
        json!({
            "stage": "local_udp_send_done",
            "peer": "198.18.0.2:53000",
            "response_action": "local_udp",
            "payload_len": 16
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "ingress_udp_datagram_response_stage");
    assert_eq!(record["fields"]["stage"], "local_udp_send_done");
    assert_eq!(record["fields"]["peer"], "198.18.0.2:53000");
    assert_eq!(record["fields"]["response_action"], "local_udp");
    assert_eq!(record["fields"]["payload_len"], 16);
}

#[test]
fn runtime_event_stream_writes_relay_udp_datagram_stage_fields() {
    let path = temp_jsonl_path("relay-udp-datagram-stage");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "info",
        RuntimeEventCode::RelayUdpDatagramStage,
        "relay udp datagram stage",
        json!({
            "stage": "connect_udp_response_ready",
            "target": "198.18.0.53",
            "port": 53,
            "relay_server": "127.0.0.1:49727",
            "relay_server_name": "localhost",
            "payload_len": 16
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "relay_udp_datagram_stage");
    assert_eq!(record["fields"]["stage"], "connect_udp_response_ready");
    assert_eq!(record["fields"]["target"], "198.18.0.53");
    assert_eq!(record["fields"]["port"], 53);
    assert_eq!(record["fields"]["payload_len"], 16);
}

#[tokio::test]
async fn runtime_event_stream_writes_relay_preferred_fields() {
    let path = temp_jsonl_path("relay-preferred");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let advisory = sample_relay_preferred_advisory().await;
    let event = advisory.relay_preference_event_data("probe-advisory.example", 443);
    stream.emit(
        "info",
        RuntimeEventCode::DirectRelayPreferredFromProbeHistory,
        event.message,
        event.runtime_fields,
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(
        record["event_code"],
        "direct_relay_preferred_from_probe_history"
    );
    assert_eq!(record["fields"]["target"], "probe-advisory.example");
    assert_eq!(record["fields"]["port"], 443);
    assert_eq!(
        record["fields"]["probe_history_disposition"],
        "prefer_relay"
    );
    assert_eq!(
        record["fields"]["probe_history_reason_code"],
        "repeated_stall_prefer_relay"
    );
}

#[test]
fn runtime_event_stream_writes_direct_planner_order_selected_fields() {
    let path = temp_jsonl_path("direct-planner-order-selected");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let mut candidate = serde_json::Map::new();
    candidate.insert("strategy".into(), json!("passthrough"));
    candidate.insert("rank".into(), json!(0));
    candidate.insert("has_previous_candidate_trace".into(), json!(false));
    candidate.insert("previous_rank".into(), Value::Null);
    candidate.insert("rank_delta".into(), Value::Null);
    candidate.insert("estimated_reward".into(), json!(0.9));
    candidate.insert("previous_estimated_reward".into(), Value::Null);
    candidate.insert("estimated_reward_delta".into(), Value::Null);
    candidate.insert("estimated_trials".into(), json!(2.0));
    candidate.insert("previous_estimated_trials".into(), Value::Null);
    candidate.insert("estimated_trials_delta".into(), Value::Null);
    candidate.insert("total_trials".into(), json!(2.0));
    candidate.insert("previous_total_trials".into(), Value::Null);
    candidate.insert("total_trials_delta".into(), Value::Null);
    candidate.insert("probe_history_strategy_bias".into(), json!(0.0));
    candidate.insert("previous_probe_history_strategy_bias".into(), Value::Null);
    candidate.insert("probe_history_strategy_bias_delta".into(), Value::Null);
    candidate.insert("selection_score_reward_component".into(), json!(0.9));
    candidate.insert(
        "previous_selection_score_reward_component".into(),
        Value::Null,
    );
    candidate.insert("selection_score_reward_component_delta".into(), Value::Null);
    candidate.insert("selection_score_ucb_exploration_bonus".into(), json!(0.3));
    candidate.insert(
        "previous_selection_score_ucb_exploration_bonus".into(),
        Value::Null,
    );
    candidate.insert(
        "selection_score_ucb_exploration_bonus_delta".into(),
        Value::Null,
    );
    candidate.insert("selection_score_probe_bias_component".into(), json!(0.0));
    candidate.insert(
        "previous_selection_score_probe_bias_component".into(),
        Value::Null,
    );
    candidate.insert(
        "selection_score_probe_bias_component_delta".into(),
        Value::Null,
    );
    candidate.insert("selection_score".into(), json!(1.2));
    candidate.insert("previous_selection_score".into(), Value::Null);
    candidate.insert("selection_score_delta".into(), Value::Null);
    candidate.insert("cold_start_exploration".into(), json!(false));
    candidate.insert(
        "selection_score_dominant_component".into(),
        json!("reward_component"),
    );
    candidate.insert("selection_score_probe_bias_effect".into(), json!("neutral"));

    let mut fields = serde_json::Map::new();
    fields.insert("target".into(), json!("planner.example"));
    fields.insert("port".into(), json!(443));
    fields.insert(
        "planner_selector_mode".into(),
        json!("ucb1_contextual_reward"),
    );
    fields.insert(
        "planner_reward_selection_source".into(),
        json!("brain_reward_loop"),
    );
    fields.insert(
        "planner_top_candidate_strategy".into(),
        json!("passthrough"),
    );
    fields.insert(
        "planner_top_candidate_primary_reason".into(),
        json!("top_candidate_reward_component"),
    );
    fields.insert(
        "planner_previous_top_candidate_primary_reason".into(),
        Value::Null,
    );
    fields.insert(
        "planner_top_candidate_primary_reason_changed".into(),
        json!(false),
    );
    fields.insert(
        "planner_top_candidate_dominant_component".into(),
        json!("reward_component"),
    );
    fields.insert(
        "planner_previous_top_candidate_dominant_component".into(),
        Value::Null,
    );
    fields.insert(
        "planner_top_candidate_dominant_component_changed".into(),
        json!(false),
    );
    fields.insert(
        "planner_explainability_trace_source".into(),
        json!("state_snapshot_contextual_reward"),
    );
    fields.insert(
        "planner_explainability_observation_source".into(),
        json!("advisory_state_snapshot_observation"),
    );
    fields.insert(
        "planner_explainability_live_runtime_observation_used".into(),
        json!(false),
    );
    fields.insert(
        "planner_order_resolution".into(),
        json!("advisory_probe_branch"),
    );
    fields.insert("planner_previous_order_resolution".into(), Value::Null);
    fields.insert("planner_order_resolution_changed".into(), json!(false));
    fields.insert(
        "planner_resolved_order_primary_reason".into(),
        json!("advisory_probe_branch_reordered_reward_loop"),
    );
    fields.insert(
        "planner_previous_resolved_order_primary_reason".into(),
        Value::Null,
    );
    fields.insert(
        "planner_resolved_order_primary_reason_changed".into(),
        json!(false),
    );
    fields.insert("planner_post_brain_reorder_applied".into(), json!(true));
    fields.insert(
        "planner_previous_post_brain_reorder_applied".into(),
        Value::Null,
    );
    fields.insert(
        "planner_post_brain_reorder_path_changed".into(),
        json!(false),
    );
    fields.insert("planner_reward_loop_order_preserved".into(), json!(false));
    fields.insert("planner_lua_order_configured".into(), json!(false));
    fields.insert("planner_lua_order_applied".into(), json!(false));
    fields.insert("planner_previous_lua_order_applied".into(), Value::Null);
    fields.insert("planner_lua_order_applied_changed".into(), json!(false));
    fields.insert("planner_advisory_reorder_requested".into(), json!(true));
    fields.insert("planner_advisory_reorder_allowed".into(), json!(true));
    fields.insert("planner_advisory_reorder_applied".into(), json!(true));
    fields.insert(
        "planner_previous_advisory_reorder_applied".into(),
        Value::Null,
    );
    fields.insert(
        "planner_advisory_reorder_applied_changed".into(),
        json!(false),
    );
    fields.insert(
        "planner_selection_stage".into(),
        json!("initial_session_order"),
    );
    fields.insert("planner_retry_attempt".into(), json!(0));
    fields.insert("planner_has_previous_selection".into(), json!(false));
    fields.insert("planner_previous_reward_selected_order".into(), Value::Null);
    fields.insert("planner_previous_resolved_order".into(), Value::Null);
    fields.insert("planner_reward_selected_order_changed".into(), json!(false));
    fields.insert("planner_resolved_order_changed".into(), json!(false));
    fields.insert(
        "planner_reward_selected_order".into(),
        json!(["passthrough", "ttl_desync", "overlap"]),
    );
    fields.insert(
        "planner_resolved_order".into(),
        json!(["ttl_desync", "overlap", "passthrough"]),
    );
    fields.insert("observation_contract".into(), json!("deep_observed"));
    fields.insert(
        "observation_capture_confidence".into(),
        json!("deep_observed"),
    );
    fields.insert(
        "probe_history_disposition".into(),
        json!("bias_probe_branch"),
    );
    fields.insert(
        "probe_history_reason_code".into(),
        json!("single_stall_bias_probe_branch"),
    );
    fields.insert(
        "cross_session_signal_bias".into(),
        json!("probe_branch_bias"),
    );
    fields.insert("cross_session_confidence_score".into(), json!(0.8));
    fields.insert("cross_session_reuse_weight".into(), json!(0.7));
    fields.insert("cross_session_stall_severity".into(), json!(0.4));
    fields.insert("cross_session_probe_branch_score".into(), json!(0.6));
    fields.insert("cross_session_relay_preference_score".into(), json!(0.0));
    fields.insert(
        "mimicry_capability_signal_origin".into(),
        json!("advisory_latest_observation"),
    );
    fields.insert(
        "mimicry_capability_stage".into(),
        json!("early_pre_wire_capability_layer"),
    );
    fields.insert(
        "mimicry_capability_readiness".into(),
        json!("composite_signal_ready"),
    );
    fields.insert(
        "mimicry_capability_observation_capture_confidence".into(),
        json!("deep_observed"),
    );
    fields.insert("mimicry_capability_server_hint_ready".into(), json!(true));
    fields.insert(
        "mimicry_capability_window_profile_ready".into(),
        json!(true),
    );
    fields.insert(
        "mimicry_capability_reference_path_ready".into(),
        json!(true),
    );
    fields.insert("mimicry_capability_rst_path_ready".into(), json!(false));
    fields.insert("mimicry_capability_server_hint".into(), json!("likely_cdn"));
    fields.insert("mimicry_capability_window_profile".into(), json!("huge"));
    fields.insert("mimicry_capability_reference_path_hops".into(), json!(2));
    fields.insert("mimicry_capability_rst_path_hops".into(), Value::Null);
    fields.insert(
        "planner_ranked_candidates".into(),
        Value::Array(vec![Value::Object(candidate)]),
    );
    stream.emit(
        "info",
        RuntimeEventCode::DirectPlannerOrderSelected,
        "selected direct planner order",
        Value::Object(fields),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "direct_planner_order_selected");
    assert_eq!(record["fields"]["target"], "planner.example");
    assert_eq!(
        record["fields"]["planner_order_resolution"],
        "advisory_probe_branch"
    );
    assert_eq!(
        record["fields"]["planner_reward_selection_source"],
        "brain_reward_loop"
    );
    assert_eq!(
        record["fields"]["planner_top_candidate_strategy"],
        "passthrough"
    );
    assert_eq!(
        record["fields"]["planner_top_candidate_primary_reason"],
        "top_candidate_reward_component"
    );
    assert!(record["fields"]["planner_previous_top_candidate_primary_reason"].is_null());
    assert_eq!(
        record["fields"]["planner_top_candidate_primary_reason_changed"],
        false
    );
    assert_eq!(
        record["fields"]["planner_top_candidate_dominant_component"],
        "reward_component"
    );
    assert!(record["fields"]["planner_previous_top_candidate_dominant_component"].is_null());
    assert_eq!(
        record["fields"]["planner_top_candidate_dominant_component_changed"],
        false
    );
    assert_eq!(
        record["fields"]["planner_explainability_trace_source"],
        "state_snapshot_contextual_reward"
    );
    assert_eq!(
        record["fields"]["planner_explainability_observation_source"],
        "advisory_state_snapshot_observation"
    );
    assert_eq!(
        record["fields"]["planner_explainability_live_runtime_observation_used"],
        false
    );
    assert_eq!(record["fields"]["planner_post_brain_reorder_applied"], true);
    assert_eq!(
        record["fields"]["planner_resolved_order_primary_reason"],
        "advisory_probe_branch_reordered_reward_loop"
    );
    assert!(record["fields"]["planner_previous_order_resolution"].is_null());
    assert_eq!(record["fields"]["planner_order_resolution_changed"], false);
    assert!(record["fields"]["planner_previous_resolved_order_primary_reason"].is_null());
    assert_eq!(
        record["fields"]["planner_resolved_order_primary_reason_changed"],
        false
    );
    assert_eq!(
        record["fields"]["planner_reward_loop_order_preserved"],
        false
    );
    assert!(record["fields"]["planner_previous_post_brain_reorder_applied"].is_null());
    assert_eq!(
        record["fields"]["planner_post_brain_reorder_path_changed"],
        false
    );
    assert_eq!(record["fields"]["planner_lua_order_configured"], false);
    assert_eq!(record["fields"]["planner_lua_order_applied"], false);
    assert!(record["fields"]["planner_previous_lua_order_applied"].is_null());
    assert_eq!(record["fields"]["planner_lua_order_applied_changed"], false);
    assert_eq!(record["fields"]["planner_advisory_reorder_requested"], true);
    assert_eq!(record["fields"]["planner_advisory_reorder_allowed"], true);
    assert_eq!(record["fields"]["planner_advisory_reorder_applied"], true);
    assert!(record["fields"]["planner_previous_advisory_reorder_applied"].is_null());
    assert_eq!(
        record["fields"]["planner_advisory_reorder_applied_changed"],
        false
    );
    assert_eq!(
        record["fields"]["planner_selection_stage"],
        "initial_session_order"
    );
    assert_eq!(record["fields"]["planner_retry_attempt"], 0);
    assert_eq!(
        record["fields"]["mimicry_capability_signal_origin"],
        "advisory_latest_observation"
    );
    assert_eq!(
        record["fields"]["mimicry_capability_stage"],
        "early_pre_wire_capability_layer"
    );
    assert_eq!(
        record["fields"]["mimicry_capability_readiness"],
        "composite_signal_ready"
    );
    assert_eq!(
        record["fields"]["mimicry_capability_observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(record["fields"]["cross_session_reuse_weight"], json!(0.7));
    assert_eq!(
        record["fields"]["mimicry_capability_server_hint_ready"],
        true
    );
    assert_eq!(
        record["fields"]["mimicry_capability_window_profile_ready"],
        true
    );
    assert_eq!(
        record["fields"]["mimicry_capability_reference_path_ready"],
        true
    );
    assert_eq!(record["fields"]["mimicry_capability_rst_path_ready"], false);
    assert_eq!(
        record["fields"]["mimicry_capability_server_hint"],
        "likely_cdn"
    );
    assert_eq!(
        record["fields"]["mimicry_capability_window_profile"],
        "huge"
    );
    assert_eq!(
        record["fields"]["mimicry_capability_reference_path_hops"],
        2
    );
    assert!(record["fields"]["mimicry_capability_rst_path_hops"].is_null());
    assert_eq!(
        record["fields"]["planner_ranked_candidates"][0]["strategy"],
        "passthrough"
    );
    assert_eq!(
        record["fields"]["planner_ranked_candidates"][0]["selection_score_dominant_component"],
        "reward_component"
    );
    assert_eq!(
        record["fields"]["planner_ranked_candidates"][0]["selection_score_probe_bias_effect"],
        "neutral"
    );
}

#[test]
fn runtime_event_stream_writes_path_only_mimicry_planner_fields() {
    let path = temp_jsonl_path("direct-planner-path-only");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let mut candidate = serde_json::Map::new();
    candidate.insert("strategy".into(), json!("passthrough"));
    candidate.insert("rank".into(), json!(0));
    candidate.insert("has_previous_candidate_trace".into(), json!(false));
    candidate.insert("previous_rank".into(), Value::Null);
    candidate.insert("rank_delta".into(), Value::Null);
    candidate.insert("estimated_reward".into(), json!(0.55));
    candidate.insert("previous_estimated_reward".into(), Value::Null);
    candidate.insert("estimated_reward_delta".into(), Value::Null);
    candidate.insert("estimated_trials".into(), json!(2.0));
    candidate.insert("previous_estimated_trials".into(), Value::Null);
    candidate.insert("estimated_trials_delta".into(), Value::Null);
    candidate.insert("total_trials".into(), json!(2.0));
    candidate.insert("previous_total_trials".into(), Value::Null);
    candidate.insert("total_trials_delta".into(), Value::Null);
    candidate.insert("probe_history_strategy_bias".into(), json!(0.0));
    candidate.insert("previous_probe_history_strategy_bias".into(), Value::Null);
    candidate.insert("probe_history_strategy_bias_delta".into(), Value::Null);
    candidate.insert("selection_score_reward_component".into(), json!(0.55));
    candidate.insert(
        "previous_selection_score_reward_component".into(),
        Value::Null,
    );
    candidate.insert("selection_score_reward_component_delta".into(), Value::Null);
    candidate.insert("selection_score_ucb_exploration_bonus".into(), json!(0.3));
    candidate.insert(
        "previous_selection_score_ucb_exploration_bonus".into(),
        Value::Null,
    );
    candidate.insert(
        "selection_score_ucb_exploration_bonus_delta".into(),
        Value::Null,
    );
    candidate.insert("selection_score_probe_bias_component".into(), json!(0.0));
    candidate.insert(
        "previous_selection_score_probe_bias_component".into(),
        Value::Null,
    );
    candidate.insert(
        "selection_score_probe_bias_component_delta".into(),
        Value::Null,
    );
    candidate.insert("selection_score".into(), json!(0.85));
    candidate.insert("previous_selection_score".into(), Value::Null);
    candidate.insert("selection_score_delta".into(), Value::Null);
    candidate.insert("cold_start_exploration".into(), json!(false));
    candidate.insert(
        "selection_score_dominant_component".into(),
        json!("reward_component"),
    );
    candidate.insert("selection_score_probe_bias_effect".into(), json!("neutral"));

    let mut fields = serde_json::Map::new();
    fields.insert("target".into(), json!("planner-runtime-only.example"));
    fields.insert("port".into(), json!(443));
    fields.insert(
        "planner_selector_mode".into(),
        json!("ucb1_contextual_reward"),
    );
    fields.insert(
        "planner_reward_selection_source".into(),
        json!("brain_reward_loop"),
    );
    fields.insert(
        "planner_top_candidate_strategy".into(),
        json!("passthrough"),
    );
    fields.insert(
        "planner_top_candidate_primary_reason".into(),
        json!("top_candidate_reward_component"),
    );
    fields.insert(
        "planner_previous_top_candidate_primary_reason".into(),
        Value::Null,
    );
    fields.insert(
        "planner_top_candidate_primary_reason_changed".into(),
        json!(false),
    );
    fields.insert(
        "planner_top_candidate_dominant_component".into(),
        json!("reward_component"),
    );
    fields.insert(
        "planner_previous_top_candidate_dominant_component".into(),
        Value::Null,
    );
    fields.insert(
        "planner_top_candidate_dominant_component_changed".into(),
        json!(false),
    );
    fields.insert(
        "planner_explainability_trace_source".into(),
        json!("state_snapshot_contextual_reward"),
    );
    fields.insert(
        "planner_explainability_observation_source".into(),
        json!("advisory_state_snapshot_observation"),
    );
    fields.insert(
        "planner_explainability_live_runtime_observation_used".into(),
        json!(false),
    );
    fields.insert("planner_order_resolution".into(), json!("reward_loop_only"));
    fields.insert("planner_previous_order_resolution".into(), Value::Null);
    fields.insert("planner_order_resolution_changed".into(), json!(false));
    fields.insert(
        "planner_resolved_order_primary_reason".into(),
        json!("reward_loop_preserved"),
    );
    fields.insert(
        "planner_previous_resolved_order_primary_reason".into(),
        Value::Null,
    );
    fields.insert(
        "planner_resolved_order_primary_reason_changed".into(),
        json!(false),
    );
    fields.insert("planner_post_brain_reorder_applied".into(), json!(false));
    fields.insert(
        "planner_previous_post_brain_reorder_applied".into(),
        Value::Null,
    );
    fields.insert(
        "planner_post_brain_reorder_path_changed".into(),
        json!(false),
    );
    fields.insert("planner_reward_loop_order_preserved".into(), json!(true));
    fields.insert("planner_lua_order_configured".into(), json!(false));
    fields.insert("planner_lua_order_applied".into(), json!(false));
    fields.insert("planner_previous_lua_order_applied".into(), Value::Null);
    fields.insert("planner_lua_order_applied_changed".into(), json!(false));
    fields.insert("planner_advisory_reorder_requested".into(), json!(false));
    fields.insert("planner_advisory_reorder_allowed".into(), json!(true));
    fields.insert("planner_advisory_reorder_applied".into(), json!(false));
    fields.insert(
        "planner_previous_advisory_reorder_applied".into(),
        Value::Null,
    );
    fields.insert(
        "planner_advisory_reorder_applied_changed".into(),
        json!(false),
    );
    fields.insert(
        "planner_selection_stage".into(),
        json!("initial_session_order"),
    );
    fields.insert("planner_retry_attempt".into(), json!(0));
    fields.insert("planner_has_previous_selection".into(), json!(false));
    fields.insert("planner_previous_reward_selected_order".into(), Value::Null);
    fields.insert("planner_previous_resolved_order".into(), Value::Null);
    fields.insert("planner_reward_selected_order_changed".into(), json!(false));
    fields.insert("planner_resolved_order_changed".into(), json!(false));
    fields.insert(
        "planner_reward_selected_order".into(),
        json!(["passthrough", "ttl_desync"]),
    );
    fields.insert(
        "planner_resolved_order".into(),
        json!(["passthrough", "ttl_desync"]),
    );
    fields.insert("observation_contract".into(), json!("runtime_only"));
    fields.insert(
        "observation_capture_confidence".into(),
        json!("runtime_only"),
    );
    fields.insert("probe_history_disposition".into(), json!("none"));
    fields.insert(
        "probe_history_reason_code".into(),
        json!("probe_observation_not_probe_capable"),
    );
    fields.insert(
        "cross_session_signal_bias".into(),
        json!("neutral_advisory_bias"),
    );
    fields.insert("cross_session_confidence_score".into(), json!(0.0));
    fields.insert("cross_session_reuse_weight".into(), json!(0.55));
    fields.insert("cross_session_stall_severity".into(), json!(0.0));
    fields.insert("cross_session_probe_branch_score".into(), json!(0.0));
    fields.insert("cross_session_relay_preference_score".into(), json!(0.0));
    fields.insert(
        "mimicry_capability_signal_origin".into(),
        json!("live_active_probe_observation"),
    );
    fields.insert(
        "mimicry_capability_stage".into(),
        json!("early_pre_wire_capability_layer"),
    );
    fields.insert(
        "mimicry_capability_readiness".into(),
        json!("path_signal_ready"),
    );
    fields.insert(
        "mimicry_capability_observation_capture_confidence".into(),
        json!("runtime_only"),
    );
    fields.insert("mimicry_capability_server_hint_ready".into(), json!(false));
    fields.insert(
        "mimicry_capability_window_profile_ready".into(),
        json!(false),
    );
    fields.insert(
        "mimicry_capability_reference_path_ready".into(),
        json!(true),
    );
    fields.insert("mimicry_capability_rst_path_ready".into(), json!(false));
    fields.insert("mimicry_capability_server_hint".into(), Value::Null);
    fields.insert("mimicry_capability_window_profile".into(), Value::Null);
    fields.insert("mimicry_capability_reference_path_hops".into(), json!(2));
    fields.insert("mimicry_capability_rst_path_hops".into(), Value::Null);
    fields.insert(
        "planner_ranked_candidates".into(),
        Value::Array(vec![Value::Object(candidate)]),
    );
    stream.emit(
        "info",
        RuntimeEventCode::DirectPlannerOrderSelected,
        "selected direct planner order",
        Value::Object(fields),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(
        record["fields"]["mimicry_capability_readiness"],
        "path_signal_ready"
    );
    assert_eq!(
        record["fields"]["mimicry_capability_observation_capture_confidence"],
        "runtime_only"
    );
    assert_eq!(
        record["fields"]["planner_reward_selection_source"],
        "brain_reward_loop"
    );
    assert_eq!(
        record["fields"]["planner_top_candidate_strategy"],
        "passthrough"
    );
    assert_eq!(
        record["fields"]["planner_top_candidate_primary_reason"],
        "top_candidate_reward_component"
    );
    assert!(record["fields"]["planner_previous_top_candidate_primary_reason"].is_null());
    assert_eq!(
        record["fields"]["planner_top_candidate_primary_reason_changed"],
        false
    );
    assert_eq!(
        record["fields"]["planner_top_candidate_dominant_component"],
        "reward_component"
    );
    assert!(record["fields"]["planner_previous_top_candidate_dominant_component"].is_null());
    assert_eq!(
        record["fields"]["planner_top_candidate_dominant_component_changed"],
        false
    );
    assert_eq!(
        record["fields"]["planner_explainability_trace_source"],
        "state_snapshot_contextual_reward"
    );
    assert_eq!(
        record["fields"]["planner_explainability_observation_source"],
        "advisory_state_snapshot_observation"
    );
    assert_eq!(
        record["fields"]["planner_explainability_live_runtime_observation_used"],
        false
    );
    assert_eq!(
        record["fields"]["planner_post_brain_reorder_applied"],
        false
    );
    assert_eq!(
        record["fields"]["planner_resolved_order_primary_reason"],
        "reward_loop_preserved"
    );
    assert!(record["fields"]["planner_previous_order_resolution"].is_null());
    assert_eq!(record["fields"]["planner_order_resolution_changed"], false);
    assert!(record["fields"]["planner_previous_resolved_order_primary_reason"].is_null());
    assert_eq!(
        record["fields"]["planner_resolved_order_primary_reason_changed"],
        false
    );
    assert_eq!(
        record["fields"]["planner_reward_loop_order_preserved"],
        true
    );
    assert!(record["fields"]["planner_previous_post_brain_reorder_applied"].is_null());
    assert_eq!(
        record["fields"]["planner_post_brain_reorder_path_changed"],
        false
    );
    assert_eq!(record["fields"]["planner_lua_order_configured"], false);
    assert_eq!(record["fields"]["planner_lua_order_applied"], false);
    assert!(record["fields"]["planner_previous_lua_order_applied"].is_null());
    assert_eq!(record["fields"]["planner_lua_order_applied_changed"], false);
    assert_eq!(
        record["fields"]["planner_advisory_reorder_requested"],
        false
    );
    assert_eq!(record["fields"]["planner_advisory_reorder_allowed"], true);
    assert_eq!(record["fields"]["planner_advisory_reorder_applied"], false);
    assert!(record["fields"]["planner_previous_advisory_reorder_applied"].is_null());
    assert_eq!(
        record["fields"]["planner_advisory_reorder_applied_changed"],
        false
    );
    assert_eq!(
        record["fields"]["planner_ranked_candidates"][0]["selection_score_dominant_component"],
        "reward_component"
    );
    assert_eq!(
        record["fields"]["planner_ranked_candidates"][0]["selection_score_probe_bias_effect"],
        "neutral"
    );
    assert_eq!(
        record["fields"]["mimicry_capability_server_hint_ready"],
        false
    );
    assert_eq!(
        record["fields"]["mimicry_capability_window_profile_ready"],
        false
    );
    assert_eq!(
        record["fields"]["mimicry_capability_reference_path_ready"],
        true
    );
    assert_eq!(record["fields"]["mimicry_capability_rst_path_ready"], false);
    assert!(record["fields"]["mimicry_capability_server_hint"].is_null());
    assert!(record["fields"]["mimicry_capability_window_profile"].is_null());
    assert_eq!(
        record["fields"]["mimicry_capability_reference_path_hops"],
        2
    );
    assert!(record["fields"]["mimicry_capability_rst_path_hops"].is_null());
}

#[test]
fn runtime_event_stream_writes_direct_session_succeeded_fields() {
    let path = temp_jsonl_path("direct-success");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let observation = aegis_core::KeyObservation {
        first_response_bytes: 512,
        relay_client_to_remote_bytes: 64,
        relay_remote_to_client_bytes: 1024,
        relay_lifetime_ms: 87,
        matched_packets: 2,
        capture_status: aegis_core::PacketCaptureStatus::Active,
        first_data_ttl: Some(58),
        ..Default::default()
    };
    let event = aegis_core::direct_session_succeeded_event_data(
        "ttl_desync",
        &FailSignal::SuccessDegraded,
        &observation,
        aegis_core::ProbeHistoryDisposition::BiasProbeBranch,
        aegis_core::ProbeHistoryReasonCode::SingleStallBiasProbeBranch,
        aegis_core::RuntimeEndpoint {
            target: "direct-success.example",
            port: 443,
        },
        aegis_core::DirectSessionSuccessMetrics {
            latency_ms: 123,
            bytes_sent: 64,
            retry_attempts_used: 1,
        },
    );
    stream.emit(
        "info",
        RuntimeEventCode::DirectSessionSucceeded,
        event.message,
        event.runtime_fields,
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "direct_session_succeeded");
    assert_eq!(record["fields"]["strategy"], "ttl_desync");
    assert_eq!(record["fields"]["signal"], "SuccessDegraded");
    assert_eq!(record["fields"]["probe_outcome_class"], "success_degraded");
    assert_eq!(record["fields"]["direct_path_health_tier"], "degraded");
    assert_eq!(
        record["fields"]["direct_path_health_reason_code"],
        "success_latency_degraded"
    );
    assert_eq!(
        record["fields"]["probe_history_disposition"],
        "bias_probe_branch"
    );
    assert_eq!(
        record["fields"]["probe_history_reason_code"],
        "single_stall_bias_probe_branch"
    );
    assert_eq!(record["fields"]["capture_status"], "Active");
    assert_eq!(
        record["fields"]["observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(record["fields"]["reference_path_hops"], 2);
    assert_eq!(record["fields"]["retry_attempts_used"], 1);
    assert_eq!(record["fields"]["active_stall_probe_retry_attempted"], true);
}

#[test]
fn runtime_event_stream_writes_probe_branch_selected_fields() {
    let path = temp_jsonl_path("probe-branch-selected");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let advisory = aegis_core::DirectSessionAdvisory {
        latest_observation: Some(aegis_core::KeyObservation {
            matched_packets: 2,
            capture_status: aegis_core::PacketCaptureStatus::Active,
            first_data_ttl: Some(58),
            ..Default::default()
        }),
        latest_probe_stats: Some(aegis_core::StallProbeStats {
            trials: 1,
            collapses: 1,
            consecutive_stall_failures: 1,
            last_signal: Some(FailSignal::ThroughputCollapse),
            ..Default::default()
        }),
        observation_contract: aegis_core::ObservationContract::DeepObserved,
        probe_history_disposition: aegis_core::ProbeHistoryDisposition::BiasProbeBranch,
        probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::SingleStallBiasProbeBranch,
        cross_session_signal_metrics: aegis_core::CrossSessionSignalMetrics::default(),
    };
    let branch_order = vec![
        "ttl_desync".to_string(),
        "overlap".to_string(),
        "passthrough".to_string(),
    ];
    let event =
        advisory.probe_branch_event_data("probe-branch.example", 443, 1, 4, &[1, 3], &branch_order);
    stream.emit(
        "info",
        RuntimeEventCode::DirectActiveProbeBranchSelected,
        event.message,
        event.runtime_fields,
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "direct_active_probe_branch_selected");
    assert_eq!(record["fields"]["target"], "probe-branch.example");
    assert_eq!(
        record["fields"]["probe_history_disposition"],
        "bias_probe_branch"
    );
    assert_eq!(
        record["fields"]["probe_history_reason_code"],
        "single_stall_bias_probe_branch"
    );
    assert_eq!(record["fields"]["planned_probe_budget"], 4);
    assert_eq!(record["fields"]["branch_order"][0], "ttl_desync");
}

#[test]
fn runtime_event_stream_writes_probe_launched_fields() {
    let path = temp_jsonl_path("probe-launched");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let event = aegis_core::active_stall_probe_launched_event_data(
        &FailSignal::SessionFreeze {
            bytes_before_stall: 16384,
        },
        aegis_core::ObservationContract::DeepObserved,
        "probe-launched.example",
        443,
        2,
        3,
        &[2, 1, 3],
    );
    stream.emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeLaunched,
        event.message,
        event.runtime_fields,
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "direct_active_stall_probe_launched");
    assert_eq!(record["fields"]["target"], "probe-launched.example");
    assert_eq!(record["fields"]["direct_path_health_tier"], "unstable");
    assert_eq!(
        record["fields"]["direct_path_health_reason_code"],
        "active_probe_in_flight"
    );
    assert_eq!(record["fields"]["observation_contract"], "deep_observed");
    assert_eq!(record["fields"]["planned_probe_budget"], 3);
    assert_eq!(record["fields"]["planned_probe_ttl_candidates"][0], 2);
}

#[test]
fn runtime_event_stream_writes_probe_finished_fields() {
    let path = temp_jsonl_path("probe-finished");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let observation = aegis_core::KeyObservation {
        matched_packets: 2,
        capture_status: aegis_core::PacketCaptureStatus::Active,
        first_data_ttl: Some(58),
        ..Default::default()
    };
    let event = aegis_core::active_stall_probe_finished_event_data(
        &FailSignal::Success,
        &observation,
        aegis_core::RuntimeEndpoint {
            target: "probe-finished.example",
            port: 443,
        },
        aegis_core::ActiveStallProbePlanContext {
            preferred_ttl: 2,
            budget: 3,
            ttl_candidates: &[2, 1, 3],
        },
        aegis_core::ActiveStallProbeFinishContext {
            latency_ms: 123,
            first_response_bytes: 512,
            terminal_stage: None,
        },
    );
    stream.emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeFinished,
        event.message,
        event.runtime_fields,
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "direct_active_stall_probe_finished");
    assert_eq!(record["fields"]["target"], "probe-finished.example");
    assert_eq!(record["fields"]["probe_outcome_class"], "success");
    assert_eq!(record["fields"]["direct_path_health_tier"], "degraded");
    assert_eq!(
        record["fields"]["direct_path_health_reason_code"],
        "active_probe_recovered_path"
    );
    assert_eq!(record["fields"]["capture_status"], "Active");
    assert_eq!(
        record["fields"]["observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(record["fields"]["latency_ms"], 123);
    assert_eq!(record["fields"]["first_response_bytes"], 512);
    assert_eq!(
        record["fields"]["probe_terminal_stage"],
        serde_json::Value::Null
    );
}

#[test]
fn runtime_event_stream_writes_direct_failover_reason_fields() {
    let path = temp_jsonl_path("direct-failover");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let event = aegis_core::direct_relay_failover_event_data(
        &aegis_core::signals::classify::FailSignal::ThroughputCollapse,
        aegis_core::ObservationContract::DeepObserved,
        "deep_observed",
        aegis_core::DirectRelayFailoverReasonCode::ProbeRetryBudgetExhausted,
        aegis_core::ObservationPathContext {
            reference_path_hops: Some(7),
            rst_path_hops: Some(3),
        },
        aegis_core::ActiveStallProbeFailoverContext {
            recommended: true,
            retry_attempted: true,
            terminal_stage: Some("active_probe_connect_remote"),
        },
        aegis_core::RuntimeEndpoint {
            target: "probe-advisory.example",
            port: 443,
        },
    );
    stream.emit(
        "info",
        RuntimeEventCode::DirectRelayFailoverTriggered,
        event.message,
        event.runtime_fields,
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "direct_relay_failover_triggered");
    assert_eq!(record["fields"]["signal"], "ThroughputCollapse");
    assert_eq!(
        record["fields"]["probe_outcome_class"],
        "throughput_collapse"
    );
    assert_eq!(record["fields"]["direct_path_health_tier"], "unstable");
    assert_eq!(
        record["fields"]["direct_path_health_reason_code"],
        "direct_relay_failover_triggered"
    );
    assert_eq!(
        record["fields"]["direct_path_degraded_before_terminal"],
        true
    );
    assert_eq!(
        record["fields"]["direct_path_unstable_before_failover"],
        true
    );
    assert_eq!(
        record["fields"]["observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(
        record["fields"]["direct_relay_failover_reason_code"],
        "probe_retry_budget_exhausted"
    );
    assert_eq!(
        record["fields"]["probe_terminal_stage"],
        "active_probe_connect_remote"
    );
}

#[test]
fn runtime_event_stream_writes_hybrid_ambiguous_send_fail_closed_fields() {
    let path = temp_jsonl_path("hybrid-flow-blocked");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    stream.emit(
        "warn",
        RuntimeEventCode::HybridFlowBlockedFailClosed,
        "captured direct flow blocked fail closed",
        json!({
            "terminal_reason": "strategies_exhausted",
            "terminal_action": "block",
            "relay_replay_safe": false,
            "relay_runtime_ready": true,
            "no_native_fallback": true,
            "target": "mutation.example",
            "port": 443,
        }),
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(record["event_code"], "hybrid_flow_blocked_fail_closed");
    assert_eq!(record["fields"]["terminal_reason"], "strategies_exhausted");
    assert_eq!(record["fields"]["terminal_action"], "block");
    assert_eq!(record["fields"]["relay_replay_safe"], false);
    assert_eq!(record["fields"]["relay_runtime_ready"], true);
    assert_eq!(record["fields"]["no_native_fallback"], true);
    assert_eq!(record["fields"]["target"], "mutation.example");
    assert_eq!(record["fields"]["port"], 443);
}

#[test]
fn runtime_event_stream_writes_probe_budget_exhausted_fields() {
    let path = temp_jsonl_path("probe-budget");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let event = aegis_core::active_stall_probe_retry_budget_exhausted_event_data(
        &aegis_core::signals::classify::FailSignal::SessionFreeze {
            bytes_before_stall: 16384,
        },
        aegis_core::ObservationContract::DeepObserved,
        "deep_observed",
        aegis_core::ObservationPathContext {
            reference_path_hops: Some(7),
            rst_path_hops: Some(3),
        },
        aegis_core::RetryBudgetContext {
            attempts_used: 2,
            attempts_budget: 2,
        },
        Some("active_probe_first_response_timeout"),
        aegis_core::RuntimeEndpoint {
            target: "probe-advisory.example",
            port: 443,
        },
    );
    stream.emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeRetryBudgetExhausted,
        event.message,
        event.runtime_fields,
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(
        record["event_code"],
        "direct_active_stall_probe_retry_budget_exhausted"
    );
    assert_eq!(
        record["fields"]["signal"],
        "SessionFreeze { bytes_before_stall: 16384 }"
    );
    assert_eq!(record["fields"]["probe_outcome_class"], "session_freeze");
    assert_eq!(record["fields"]["direct_path_health_tier"], "unstable");
    assert_eq!(
        record["fields"]["direct_path_health_reason_code"],
        "probe_retry_budget_exhausted"
    );
    assert_eq!(
        record["fields"]["direct_path_degraded_before_terminal"],
        true
    );
    assert_eq!(
        record["fields"]["direct_path_unstable_before_failover"],
        true
    );
    assert_eq!(
        record["fields"]["observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(record["fields"]["retry_attempts_used"], 2);
    assert_eq!(
        record["fields"]["probe_terminal_stage"],
        "active_probe_first_response_timeout"
    );
}

#[tokio::test]
async fn runtime_event_stream_writes_probe_retry_selected_fields() {
    let path = temp_jsonl_path("probe-retry-selected");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let advisory = sample_relay_preferred_advisory().await;
    let event = advisory.active_stall_probe_retry_event_data(
        aegis_core::RuntimeEndpoint {
            target: "probe-advisory.example",
            port: 443,
        },
        &FailSignal::SuccessDegraded,
        aegis_core::ActiveStallProbePlanContext {
            preferred_ttl: 2,
            budget: 3,
            ttl_candidates: &[2, 1, 3],
        },
        Some("active_probe_connect_remote"),
    );
    stream.emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeRetrySelected,
        event.message,
        event.runtime_fields,
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(
        record["event_code"],
        "direct_active_stall_probe_retry_selected"
    );
    assert_eq!(record["fields"]["signal"], "SuccessDegraded");
    assert_eq!(record["fields"]["probe_outcome_class"], "success_degraded");
    assert_eq!(record["fields"]["direct_path_health_tier"], "degraded");
    assert_eq!(
        record["fields"]["direct_path_health_reason_code"],
        "active_probe_recovered_but_latency_degraded"
    );
    assert_eq!(
        record["fields"]["probe_history_disposition"],
        "prefer_relay"
    );
    assert_eq!(
        record["fields"]["observation_capture_confidence"],
        "deep_observed"
    );
    assert!(
        record["fields"]["cross_session_confidence_score"]
            .as_f64()
            .expect("confidence score")
            > 0.0
    );
    assert!(
        record["fields"]["cross_session_reuse_weight"]
            .as_f64()
            .expect("reuse weight")
            > 0.0
    );
    assert_eq!(
        record["fields"]["probe_terminal_stage"],
        "active_probe_connect_remote"
    );
}

#[tokio::test]
async fn runtime_event_stream_writes_probe_retry_skipped_fields() {
    let path = temp_jsonl_path("probe-retry-skipped");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let advisory = sample_relay_preferred_advisory().await;
    let event = advisory.active_stall_probe_retry_skipped_event_data(
        aegis_core::RuntimeEndpoint {
            target: "probe-advisory.example",
            port: 443,
        },
        &FailSignal::ThroughputCollapse,
        aegis_core::ActiveStallProbeRetrySuppressedReasonCode::AdvisoryPreferRelay,
        aegis_core::RetryBudgetContext {
            attempts_used: 1,
            attempts_budget: 2,
        },
        Some("active_probe_first_response_timeout"),
    );
    stream.emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeRetrySkipped,
        event.message,
        event.runtime_fields,
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(
        record["event_code"],
        "direct_active_stall_probe_retry_skipped"
    );
    assert_eq!(record["fields"]["signal"], "ThroughputCollapse");
    assert_eq!(
        record["fields"]["probe_outcome_class"],
        "throughput_collapse"
    );
    assert_eq!(record["fields"]["direct_path_health_tier"], "unstable");
    assert_eq!(
        record["fields"]["direct_path_health_reason_code"],
        "probe_retry_suppressed"
    );
    assert_eq!(
        record["fields"]["direct_path_degraded_before_terminal"],
        false
    );
    assert_eq!(
        record["fields"]["direct_path_unstable_before_failover"],
        true
    );
    assert_eq!(
        record["fields"]["retry_suppressed_reason_code"],
        "advisory_prefer_relay"
    );
    assert_eq!(
        record["fields"]["observation_capture_confidence"],
        "deep_observed"
    );
    assert!(
        record["fields"]["cross_session_confidence_score"]
            .as_f64()
            .expect("confidence score")
            > 0.0
    );
    assert!(
        record["fields"]["cross_session_reuse_weight"]
            .as_f64()
            .expect("reuse weight")
            > 0.0
    );
    assert!(
        record["fields"]["cross_session_relay_preference_score"]
            .as_f64()
            .expect("relay preference score")
            > 0.0
    );
    assert_eq!(
        record["fields"]["probe_terminal_stage"],
        "active_probe_first_response_timeout"
    );
}

#[tokio::test]
async fn runtime_event_stream_writes_capture_backed_retry_gap_reason() {
    let path = temp_jsonl_path("probe-retry-capture-gap");
    let stream = RuntimeEventStream::new(&path).expect("stream");
    let advisory = sample_relay_preferred_advisory().await;
    let event = advisory.active_stall_probe_retry_skipped_event_data(
        aegis_core::RuntimeEndpoint {
            target: "probe-runtime-only.example",
            port: 443,
        },
        &FailSignal::Success,
        aegis_core::ActiveStallProbeRetrySuppressedReasonCode::ProbeObservationNotCaptureBacked,
        aegis_core::RetryBudgetContext {
            attempts_used: 1,
            attempts_budget: 2,
        },
        Some("active_probe_first_response_timeout"),
    );
    stream.emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeRetrySkipped,
        event.message,
        event.runtime_fields,
    );
    let record = read_single_jsonl_record(&path);
    assert_eq!(
        record["fields"]["retry_suppressed_reason_code"],
        "probe_observation_not_capture_backed"
    );
    assert_eq!(record["fields"]["signal"], "Success");
    assert_eq!(record["fields"]["probe_outcome_class"], "success");
    assert_eq!(
        record["fields"]["probe_terminal_stage"],
        "active_probe_first_response_timeout"
    );
}

#[cfg(unix)]
#[test]
fn runtime_log_restricts_existing_file_before_writing() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.path().join("events.jsonl");
    std::fs::write(&path, b"existing\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let stream = RuntimeEventStream::new(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"existing\n");
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o755
    );
    drop(stream);

    let null_mode = std::fs::metadata("/dev/null").unwrap().permissions().mode();
    let null_path = dir.path().join("null-sink");
    std::os::unix::fs::symlink("/dev/null", &null_path).unwrap();
    let _null_sink = RuntimeEventStream::new(&null_path).unwrap();
    assert_eq!(
        std::fs::metadata("/dev/null").unwrap().permissions().mode(),
        null_mode
    );
}
