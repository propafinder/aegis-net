use std::{collections::BTreeSet, fs, path::Path};

use serde_json::{json, Value};

use super::evidence_support::{list_tar_gz_entries, read_bundle_sha256_value};

pub fn phase_c_multi_relay_evidence(
    events: &[Value],
    single_relay_backward_compatible: bool,
    runtime_events_jsonl: &Path,
) -> Value {
    let mut relay_servers = BTreeSet::new();
    let mut relay_failures = Vec::new();
    let mut relay_successes = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let code = event["event_code"].as_str().unwrap_or("");
        if !matches!(
            code,
            "relay_session_started"
                | "relay_transport_selected"
                | "relay_transport_failed"
                | "relay_session_succeeded"
        ) {
            continue;
        }
        if let Some(server) = event_field(event, "relay_server").and_then(Value::as_str) {
            if !server.trim().is_empty() {
                relay_servers.insert(server.to_string());
            }
        }
        let ts = event["ts_unix_ms"]
            .as_u64()
            .or_else(|| event_field(event, "ts_unix_ms").and_then(Value::as_u64));
        let relay_server = event_field(event, "relay_server")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        match code {
            "relay_transport_failed" => {
                relay_failures.push((index, ts, relay_server));
            }
            "relay_session_succeeded" => {
                relay_successes.push((index, ts, relay_server));
            }
            _ => {}
        }
    }

    let mut recovery_secs = Vec::new();
    for (failure_index, failure_ts, failure_server) in &relay_failures {
        let Some((_, success_ts, _success_server)) =
            relay_successes
                .iter()
                .find(|(success_index, _, success_server)| {
                    success_index > failure_index
                        && !success_server.is_empty()
                        && success_server != failure_server
                })
        else {
            continue;
        };
        if let (Some(failure_ts), Some(success_ts)) = (failure_ts, success_ts) {
            if success_ts >= failure_ts {
                recovery_secs.push((*success_ts - *failure_ts) as f64 / 1000.0);
            }
        }
    }
    recovery_secs.sort_by(|left, right| left.total_cmp(right));
    let median_recovery = median_f64(&recovery_secs);
    let mid_session_primary_block_survived = !recovery_secs.is_empty();
    let mut blockers = Vec::new();
    if relay_servers.len() < 2 {
        blockers.push("fewer_than_two_relay_endpoints_observed");
    }
    if median_recovery.is_none_or(|value| value >= 30.0) {
        blockers.push("primary_block_recovery_median_not_below_30s");
    }
    if !mid_session_primary_block_survived {
        blockers.push("mid_session_primary_block_survival_missing");
    }
    if !single_relay_backward_compatible {
        blockers.push("single_relay_backward_compatibility_missing");
    }

    json!({
        "event": "phase_c_multi_relay_evidence",
        "schema_version": 1,
        "status": if blockers.is_empty() { "PASS" } else { "FAIL" },
        "blockers": blockers,
        "primary_block_recovery_median_secs": median_recovery,
        "mid_session_primary_block_survived": mid_session_primary_block_survived,
        "single_relay_backward_compatible": single_relay_backward_compatible,
        "observed_relay_servers": relay_servers.into_iter().collect::<Vec<_>>(),
        "relay_transport_failures": relay_failures.len(),
        "relay_session_successes": relay_successes.len(),
        "recovery_samples_secs": recovery_secs,
        "artifacts": {
            "runtime_events_jsonl": runtime_events_jsonl,
        },
    })
}

pub fn phase_c_bundle_mirrors_evidence(
    primary_fetch: &Value,
    mirror_fetch: &Value,
    voucher_flow: &Value,
    bundle_archive: &Path,
    bundle_sha256: &Path,
    operator_doc: &Path,
) -> Value {
    let expected_sha256 = read_bundle_sha256_value(bundle_sha256);
    let mirror_sha256 = mirror_fetch["bundle_sha256"].as_str().unwrap_or("");
    let primary_blocked = primary_fetch["status"].as_str() == Some("BLOCKED")
        || primary_fetch["blocked"].as_bool() == Some(true);
    let mirror_pass = mirror_fetch["status"].as_str() == Some("PASS");
    let mirror_checksum_matches =
        !expected_sha256.is_empty() && mirror_sha256 == expected_sha256.as_str();
    let primary_bundle_host_block_survives =
        primary_blocked && mirror_pass && mirror_checksum_matches;

    let voucher_expiry_revoke_pass = voucher_flow["status"].as_str() == Some("PASS")
        && voucher_flow["issued_token"].as_bool() == Some(true)
        && voucher_flow["redeem_once_pass"].as_bool() == Some(true)
        && voucher_flow["second_redeem_rejected"].as_bool() == Some(true)
        && voucher_flow["expired_token_rejected"].as_bool() == Some(true)
        && voucher_flow["revoked_token_rejected"].as_bool() == Some(true);

    let archive_exists = bundle_archive.is_file();
    let sha_file_exists = bundle_sha256.is_file();
    let archive_entries = list_tar_gz_entries(bundle_archive).unwrap_or_default();
    let manifest_present = archive_entries
        .iter()
        .any(|entry| entry.ends_with("/bundle.manifest.json") || entry == "bundle.manifest.json");
    let checksums_present = archive_entries
        .iter()
        .any(|entry| entry.ends_with("/SHA256SUMS") || entry == "SHA256SUMS");
    let client_config_present = archive_entries
        .iter()
        .any(|entry| entry.ends_with("/aegis-client.toml") || entry == "aegis-client.toml");
    let client_ca_present = archive_entries
        .iter()
        .any(|entry| entry.ends_with("/ca.pem") || entry == "ca.pem");
    let release_bundle_verification_surface = manifest_present && checksums_present;
    let client_bundle_verification_surface =
        client_config_present && client_ca_present && sha_file_exists;
    let signed_bundle_verification_preserved = archive_exists
        && sha_file_exists
        && (release_bundle_verification_surface || client_bundle_verification_surface)
        && mirror_checksum_matches;

    let operator_doc_text = fs::read_to_string(operator_doc)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let operator_mirror_setup_documented = operator_doc.is_file()
        && operator_doc_text.contains("mirror")
        && operator_doc_text.contains("voucher");

    let mut blockers = Vec::new();
    if !primary_bundle_host_block_survives {
        blockers.push("primary_bundle_host_block_survival_missing");
    }
    if !voucher_expiry_revoke_pass {
        blockers.push("voucher_expiry_revoke_not_pass");
    }
    if !signed_bundle_verification_preserved {
        blockers.push("signed_bundle_verification_not_preserved");
    }
    if !operator_mirror_setup_documented {
        blockers.push("operator_mirror_setup_not_documented");
    }

    json!({
        "status": if blockers.is_empty() { "PASS" } else { "FAIL" },
        "blockers": blockers,
        "primary_bundle_host_block_survives": primary_bundle_host_block_survives,
        "voucher_expiry_revoke_pass": voucher_expiry_revoke_pass,
        "signed_bundle_verification_preserved": signed_bundle_verification_preserved,
        "operator_mirror_setup_documented": operator_mirror_setup_documented,
        "checks": {
            "primary_fetch_blocked": primary_blocked,
            "mirror_fetch_pass": mirror_pass,
            "mirror_checksum_matches": mirror_checksum_matches,
            "archive_exists": archive_exists,
            "sha256_file_exists": sha_file_exists,
            "bundle_manifest_present": manifest_present,
            "sha256sums_present": checksums_present,
            "client_config_present": client_config_present,
            "client_ca_present": client_ca_present,
            "voucher_issued_token": voucher_flow["issued_token"].as_bool() == Some(true),
            "voucher_redeem_once_pass": voucher_flow["redeem_once_pass"].as_bool() == Some(true),
            "voucher_second_redeem_rejected": voucher_flow["second_redeem_rejected"].as_bool() == Some(true),
            "voucher_expired_token_rejected": voucher_flow["expired_token_rejected"].as_bool() == Some(true),
            "voucher_revoked_token_rejected": voucher_flow["revoked_token_rejected"].as_bool() == Some(true),
        },
        "artifacts": {
            "primary_fetch_json_status": primary_fetch["status"].clone(),
            "mirror_fetch_json_status": mirror_fetch["status"].clone(),
            "bundle_archive": bundle_archive,
            "bundle_sha256": bundle_sha256,
            "operator_doc": operator_doc,
            "expected_bundle_sha256": expected_sha256,
            "mirror_bundle_sha256": mirror_sha256,
        },
    })
}

fn median_f64(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        Some((values[mid - 1] + values[mid]) / 2.0)
    } else {
        Some(values[mid])
    }
}

fn event_field<'a>(event: &'a Value, field: &str) -> Option<&'a Value> {
    event
        .get(field)
        .or_else(|| event.get("fields").and_then(|fields| fields.get(field)))
}
