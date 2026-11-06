use std::{collections::BTreeMap, path::Path};

use serde_json::{json, Value};

fn event_field<'a>(event: &'a Value, key: &str) -> Option<&'a Value> {
    event
        .get("fields")
        .and_then(|fields| fields.get(key))
        .or_else(|| event.get(key))
}

fn event_code(event: &Value) -> Option<&str> {
    event.get("event_code").and_then(Value::as_str)
}

fn canonical_transport(transport: &str) -> String {
    match transport {
        "https_ws" | "HttpsWs" | "https-ws" => "HttpsWs".to_string(),
        "grpc_stream" | "GrpcStream" | "grpc-stream" => "GrpcStream".to_string(),
        other => other.to_string(),
    }
}

fn value_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_u64))
}

fn classifier_risk_count(classifier: &Value) -> Option<u64> {
    value_u64(
        classifier,
        &[
            "ndpi_risk_count",
            "risk_count",
            "riskCount",
            "ndpiRiskCount",
        ],
    )
}

fn suricata_alert_count(classifier: &Value) -> Option<u64> {
    value_u64(
        classifier,
        &[
            "suricata_alert_count",
            "alert_count",
            "alertCount",
            "suricataAlertCount",
        ],
    )
}

fn classifier_clean(classifier: &Value) -> bool {
    let status_clean = matches!(
        classifier.get("status").and_then(Value::as_str),
        Some("PASS") | Some("READY") | Some("CLEAN")
    );
    let no_fails = classifier
        .get("verdict_counts")
        .and_then(|counts| counts.get("fail"))
        .and_then(Value::as_u64)
        == Some(0);
    let ndpi_clean = classifier_risk_count(classifier) == Some(0);
    let suricata_clean = suricata_alert_count(classifier) == Some(0);
    status_clean && no_fails && ndpi_clean && suricata_clean
}

fn numeric_summary(values: &[u64]) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    // On supported 32/64-bit targets an in-memory slice of u64 samples has
    // fewer than 2^64 elements; their exact sum therefore fits in u128.
    let sum: u128 = sorted.iter().map(|value| u128::from(*value)).sum();
    json!({
        "count": sorted.len(),
        "min": sorted[0],
        "max": sorted[sorted.len() - 1],
        "avg": sum as f64 / sorted.len() as f64,
        "p50": sorted[sorted.len() / 2],
    })
}

fn histogram(values: &[u64]) -> BTreeMap<String, u64> {
    let mut buckets = BTreeMap::new();
    for value in values {
        let label = match *value {
            0..=255 => "0000_0255",
            256..=511 => "0256_0511",
            512..=1023 => "0512_1023",
            1024..=4095 => "1024_4095",
            4096..=16383 => "4096_16383",
            _ => "16384_plus",
        };
        *buckets.entry(label.to_string()).or_default() += 1;
    }
    buckets
}

fn array_u64(value: Option<&Value>) -> Vec<u64> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default()
}

fn flat_summary(value: &Value, prefix: &str) -> Option<Value> {
    let min = value.get(format!("{prefix}_min"))?;
    let max = value.get(format!("{prefix}_max"))?;
    let mean = value.get(format!("{prefix}_mean"))?;
    let p50 = value.get(format!("{prefix}_p50"))?;
    let p90 = value.get(format!("{prefix}_p90"));
    let p99 = value.get(format!("{prefix}_p99"));
    Some(json!({
        "count": value.get(format!("{prefix}_count")),
        "min": min,
        "max": max,
        "avg": mean,
        "p50": p50,
        "p90": p90,
        "p99": p99,
    }))
}

fn finite_nonnegative(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .filter(|number| number.is_finite() && *number >= 0.0)
}

fn valid_timing_summary(summary: &Value, max_samples: u64) -> bool {
    let Some(count) = summary.get("count").and_then(Value::as_u64) else {
        return false;
    };
    if count == 0 || count > max_samples {
        return false;
    }
    let Some(p50) = summary.get("p50").and_then(finite_nonnegative) else {
        return false;
    };
    // The original summary contract supplies count and p50. Preserve it while
    // checking every additional statistic that the producer actually supplied.
    for key in ["min", "max", "avg", "mean", "p90", "p99"] {
        if let Some(value) = summary.get(key).filter(|value| !value.is_null()) {
            if finite_nonnegative(value).is_none() {
                return false;
            }
        }
    }
    let minimum = summary.get("min").and_then(finite_nonnegative);
    let maximum = summary.get("max").and_then(finite_nonnegative);
    if minimum.is_some_and(|minimum| minimum > p50) || maximum.is_some_and(|maximum| maximum < p50)
    {
        return false;
    }
    for key in ["avg", "mean", "p90", "p99"] {
        if let Some(number) = summary.get(key).and_then(finite_nonnegative) {
            if minimum.is_some_and(|minimum| number < minimum)
                || maximum.is_some_and(|maximum| number > maximum)
            {
                return false;
            }
        }
    }
    let p90 = summary.get("p90").and_then(finite_nonnegative);
    let p99 = summary.get("p99").and_then(finite_nonnegative);
    !p90.is_some_and(|p90| p90 < p50) && !p99.is_some_and(|p99| p99 < p90.unwrap_or(p50))
}

fn timing_array_summary(value: &Value, max_samples: u64) -> Option<Value> {
    let values = value.as_array()?;
    if values.is_empty() || values.len() as u64 > max_samples {
        return None;
    }
    // Do not filter out invalid samples: that would silently manufacture a
    // clean summary from a partially corrupt series.
    let mut sorted = values
        .iter()
        .map(finite_nonnegative)
        .collect::<Option<Vec<_>>>()?;
    sorted.sort_unstable_by(|left, right| left.total_cmp(right));
    let average = sorted
        .iter()
        .map(|value| value / sorted.len() as f64)
        .sum::<f64>();
    if !average.is_finite() {
        return None;
    }
    Some(json!({
        "count": sorted.len(),
        "min": sorted[0],
        "max": sorted[sorted.len() - 1],
        "avg": average,
        "p50": sorted[sorted.len() / 2],
    }))
}

fn measured_timing_summary(
    timing: Option<&Value>,
    pcap: &Value,
    packet_count: Option<u64>,
) -> Option<Value> {
    let max_samples = packet_count?.checked_sub(1)?;
    if max_samples == 0 {
        return None;
    }
    for source in timing.into_iter().chain(std::iter::once(pcap)) {
        if let Some(summary) = source.get("inter_arrival_ms_summary") {
            if valid_timing_summary(summary, max_samples) {
                return Some(summary.clone());
            }
        }
        if valid_timing_summary(source, max_samples) {
            return Some(source.clone());
        }
        if let Some(summary) = source
            .get("inter_arrival_ms")
            .and_then(|values| timing_array_summary(values, max_samples))
        {
            return Some(summary);
        }
        if let Some(mut summary) = flat_summary(source, "inter_arrival_ms") {
            // witness_score's flat metrics are computed from all packet rows,
            // giving exactly packet_count - 1 inter-arrival samples. Retain
            // compatibility with that producer when no explicit count exists.
            if source.get("inter_arrival_ms_count").is_none() {
                summary["count"] = json!(max_samples);
            }
            if valid_timing_summary(&summary, max_samples)
                && ["min", "max", "avg"]
                    .into_iter()
                    .all(|key| summary.get(key).and_then(finite_nonnegative).is_some())
            {
                return Some(summary);
            }
        }
    }
    None
}

fn selected_and_succeeded(events: &[Value], expected: &str) -> (bool, bool, Vec<String>) {
    let mut selected = false;
    let mut succeeded = false;
    let mut other_selected = Vec::new();

    for event in events {
        match event_code(event) {
            Some("relay_transport_selected") => {
                let transport = event_field(event, "transport").and_then(Value::as_str);
                if transport == Some(expected) {
                    selected = true;
                } else if let Some(transport) = transport {
                    other_selected.push(transport.to_string());
                }
            }
            Some("relay_session_succeeded") => {
                let chosen = event_field(event, "chosen_transport")
                    .or_else(|| event_field(event, "transport"))
                    .and_then(Value::as_str);
                if chosen == Some(expected) {
                    succeeded = true;
                }
            }
            _ => {}
        }
    }

    other_selected.sort();
    other_selected.dedup();
    (selected, succeeded, other_selected)
}

/// Scores completeness of the supplied evidence, not detection probability or
/// an indistinguishability guarantee. A raw capture path requires a measured
/// positive packet count; its existence alone never establishes a valid pcap.
pub fn traffic_shape_score(
    transport: &str,
    runtime_events: &[Value],
    classifier_summary: &Value,
    pcap_summary: Option<&Value>,
    timing_summary: Option<&Value>,
    pcap_path: Option<&Path>,
    netem_profile: &str,
) -> Value {
    let expected = canonical_transport(transport);
    let (runtime_selected, relay_session_succeeded, fallback_transports_seen) =
        selected_and_succeeded(runtime_events, &expected);
    let runtime_linked = runtime_selected && relay_session_succeeded;

    let pcap_raw_file_present = pcap_path
        .and_then(|path| path.metadata().ok())
        .is_some_and(|metadata| metadata.is_file() && metadata.len() > 0);
    let pcap = pcap_summary.unwrap_or(&Value::Null);
    let packet_count = value_u64(
        pcap,
        &["packet_count", "packets", "tcpdump_packets_captured"],
    );
    let pcap_present = packet_count.is_some_and(|count| count > 0);
    let byte_count = value_u64(pcap, &["byte_count", "bytes", "packet_capture_size_bytes"]);
    let upload_bytes = value_u64(pcap, &["upload_bytes", "client_to_relay_bytes"]);
    let download_bytes = value_u64(pcap, &["download_bytes", "relay_to_client_bytes"]);
    let upload_download_ratio = if let Some(ratio) = pcap.get("upload_download_ratio") {
        // An explicitly invalid ratio must not be hidden by a derived fallback.
        finite_nonnegative(ratio)
    } else {
        match (upload_bytes, download_bytes) {
            (Some(upload), Some(download)) if download > 0 => Some(upload as f64 / download as f64),
            _ => None,
        }
    };

    let runtime_chunk_sizes = runtime_events
        .iter()
        .filter_map(|event| event_field(event, "relay_surface_write_chunk_size"))
        .filter_map(Value::as_u64)
        .collect::<Vec<_>>();
    let runtime_delays = runtime_events
        .iter()
        .filter_map(|event| event_field(event, "relay_surface_inter_chunk_delay_ms"))
        .filter_map(Value::as_u64)
        .collect::<Vec<_>>();

    let packet_sizes = array_u64(pcap.get("packet_sizes"));
    let measured_timing = measured_timing_summary(timing_summary, pcap, packet_count);
    let timing_present = measured_timing.is_some();
    let ratio_present = upload_download_ratio.is_some();
    let classifier_clean = classifier_clean(classifier_summary);
    let ndpi_risk_count = classifier_risk_count(classifier_summary);
    let suricata_alert_count = suricata_alert_count(classifier_summary);

    let mut blockers = Vec::new();
    if !runtime_linked {
        blockers.push("runtime_selected_transport_or_success_missing");
    }
    if !fallback_transports_seen.is_empty() {
        blockers.push("fallback_or_mixed_transport_attempts_seen");
    }
    if !pcap_present {
        blockers.push("relay_only_pcap_missing");
        if pcap_raw_file_present {
            blockers.push("raw_pcap_packet_count_unvalidated");
        }
    }
    if !classifier_clean {
        blockers.push("classifier_not_clean_or_counts_missing");
    }
    if ndpi_risk_count.is_none() {
        blockers.push("ndpi_risk_count_missing");
    }
    if suricata_alert_count.is_none() {
        blockers.push("suricata_alert_count_missing");
    }
    if !timing_present {
        blockers.push("pcap_timing_summary_missing");
    }
    if !ratio_present {
        blockers.push("upload_download_ratio_missing");
    }

    let score_status = if !runtime_linked || !pcap_present {
        "BLOCKED"
    } else if classifier_clean
        && ndpi_risk_count.is_some()
        && suricata_alert_count.is_some()
        && timing_present
        && ratio_present
        && fallback_transports_seen.is_empty()
    {
        "PASS"
    } else {
        "PARTIAL"
    };
    let shape_score = if score_status == "PASS" {
        1.0
    } else {
        [
            runtime_linked,
            pcap_present,
            classifier_clean,
            timing_present,
            ratio_present,
            fallback_transports_seen.is_empty(),
        ]
        .into_iter()
        .filter(|value| *value)
        .count() as f64
            / 6.0
    };

    json!({
        "artifact_schema": "traffic_shape_score_v1",
        "transport": transport,
        "expected_runtime_transport": expected,
        "score_status": score_status,
        "shape_score": shape_score,
        "shape_score_interpretation": "evidence_completeness_not_detection_probability",
        "classifier_clean": classifier_clean,
        "timing_present": timing_present,
        "ratio_present": ratio_present,
        "pcap_present": pcap_present,
        "pcap_raw_file_present": pcap_raw_file_present,
        "runtime_linked": runtime_linked,
        "runtime_selected_transport": runtime_selected,
        "relay_session_succeeded": relay_session_succeeded,
        "fallback_transports_seen": fallback_transports_seen,
        "netem_profile": netem_profile,
        "metrics": {
            "packet_count": packet_count,
            "byte_count": byte_count,
            "upload_bytes": upload_bytes,
            "download_bytes": download_bytes,
            "upload_download_ratio": upload_download_ratio,
            "packet_size_histogram": if packet_sizes.is_empty() { Value::Null } else { json!(histogram(&packet_sizes)) },
            "inter_arrival_ms_summary": measured_timing,
            "burst_count": value_u64(pcap, &["burst_count"]),
            "session_duration_ms": value_u64(pcap, &["session_duration_ms"]),
            "tls_record_size_summary": pcap.get("tls_record_size_summary").cloned(),
            "websocket_message_size_summary": pcap.get("websocket_message_size_summary").cloned(),
            "grpc_message_size_summary": pcap.get("grpc_message_size_summary").cloned(),
            "runtime_write_chunk_size_summary": numeric_summary(&runtime_chunk_sizes),
            "runtime_inter_chunk_delay_ms_summary": numeric_summary(&runtime_delays),
            "ndpi_risk_count": ndpi_risk_count,
            "suricata_alert_count": suricata_alert_count,
        },
        "ja3_status": "NOT_MEASURED",
        "ja4_status": "NOT_MEASURED",
        "blockers": blockers,
        "next_action": if score_status == "PASS" {
            "none"
        } else if !pcap_present {
            "collect_per_transport_relay_only_pcap"
        } else {
            "expand_netem_matrix_and_tls_fingerprint_scoring"
        },
    })
}

pub fn traffic_shape_score_markdown(score: &Value) -> String {
    format!(
        "# Traffic Shape Score\n\n\
         - Transport: `{}`\n\
         - Score status: `{}`\n\
         - Shape score: `{}`\n\
         - Runtime linked: `{}`\n\
         - Pcap present: `{}`\n\
         - Timing present: `{}`\n\
         - Ratio present: `{}`\n\
         - Classifier clean: `{}`\n\
         - JA3: `{}`\n\
         - JA4: `{}`\n\
         - Next action: `{}`\n",
        score["transport"].as_str().unwrap_or("unknown"),
        score["score_status"].as_str().unwrap_or("UNKNOWN"),
        score["shape_score"].as_f64().unwrap_or(0.0),
        score["runtime_linked"].as_bool().unwrap_or(false),
        score["pcap_present"].as_bool().unwrap_or(false),
        score["timing_present"].as_bool().unwrap_or(false),
        score["ratio_present"].as_bool().unwrap_or(false),
        score["classifier_clean"].as_bool().unwrap_or(false),
        score["ja3_status"].as_str().unwrap_or("UNKNOWN"),
        score["ja4_status"].as_str().unwrap_or("UNKNOWN"),
        score["next_action"].as_str().unwrap_or("unknown"),
    )
}

#[cfg(test)]
mod runtime_completion_tests {
    use super::*;

    #[test]
    fn maximum_runtime_samples_do_not_overflow_the_average() {
        let summary = numeric_summary(&[u64::MAX, u64::MAX]);
        assert_eq!(summary["count"], 2);
        assert_eq!(summary["min"], u64::MAX);
        assert_eq!(summary["max"], u64::MAX);
        assert_eq!(summary["avg"].as_f64(), Some(u64::MAX as f64));
        let mixed = numeric_summary(&[0, u64::MAX, u64::MAX]);
        assert_eq!(mixed["avg"].as_f64(), Some((u64::MAX as f64 * 2.0) / 3.0));
    }

    fn runtime_score(events: &[Value]) -> Value {
        traffic_shape_score(
            "grpc_stream",
            events,
            &json!({}),
            None,
            None,
            None,
            "runtime-only",
        )
    }

    #[test]
    fn a03_neutral_completion_cannot_supply_runtime_success() {
        // The cancelled fixture only protects the consumer's neutral-event
        // contract; producer cancellation may instead emit no terminal event.
        for reason in ["no_response_observed", "no_attempt_observed", "cancelled"] {
            for prior_failure in [false, true] {
                let mut events = vec![json!({
                    "event_code": "relay_transport_selected",
                    "fields": { "transport": "GrpcStream" },
                })];
                if prior_failure {
                    events.push(json!({
                        "event_code": "relay_transport_failed",
                        "fields": { "relay_failure_scope": "real_transport_outage" },
                    }));
                }
                events.push(json!({
                    "event_code": "relay_session_completed",
                    "fields": {
                        "relay_session_kind": "tcp_tunnel",
                        "chosen_transport": "GrpcStream",
                        "completion_reason": reason,
                        "application_response_observed": false,
                        "transfer_result": if reason == "cancelled" { "cancelled" } else { "ok" },
                        "bytes_received_observed": 0,
                    },
                }));

                let score = runtime_score(&events);
                assert_eq!(score["runtime_selected_transport"], true);
                assert_eq!(score["relay_session_succeeded"], false);
                assert_eq!(score["runtime_linked"], false);
                assert_eq!(score["score_status"], "BLOCKED");
                assert!(score["blockers"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("runtime_selected_transport_or_success_missing")));

                events.push(json!({
                    "event_code": "relay_session_succeeded",
                    "fields": {
                        "chosen_transport": "GrpcStream",
                        "application_response_observed": true,
                        "transfer_result": "ok",
                        "bytes_received_observed": 8,
                    },
                }));
                let success = runtime_score(&events);
                assert_eq!(success["relay_session_succeeded"], true);
                assert_eq!(success["runtime_linked"], true);
                assert!(!success["blockers"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("runtime_selected_transport_or_success_missing")));
            }
        }
    }
}

#[cfg(test)]
mod evidence_completeness_tests {
    use super::*;

    fn runtime() -> Vec<Value> {
        vec![
            json!({"event_code": "relay_transport_selected", "fields": {"transport": "HttpsWs"}}),
            json!({"event_code": "relay_session_succeeded", "fields": {"chosen_transport": "HttpsWs"}}),
        ]
    }

    fn classifier() -> Value {
        json!({
            "status": "PASS",
            "verdict_counts": {"fail": 0, "pass": 2, "unknown": 0},
            "ndpi_risk_count": 0,
            "suricata_alert_count": 0,
        })
    }

    fn pcap() -> Value {
        // Match the established CLI contract: packet/timing summaries may
        // describe a sample subset of the positive capture packet count.
        json!({
            "packet_count": 12,
            "upload_bytes": 10240,
            "download_bytes": 30720,
            "inter_arrival_ms_summary": {"count": 4, "p50": 4},
        })
    }

    fn score(classifier: &Value, pcap: Option<&Value>, timing: Option<&Value>) -> Value {
        traffic_shape_score(
            "https_ws",
            &runtime(),
            classifier,
            pcap,
            timing,
            None,
            "deterministic-evidence-fixture",
        )
    }

    #[test]
    fn established_positive_capture_and_timing_contract_passes() {
        let score = score(&classifier(), Some(&pcap()), None);
        assert_eq!(score["artifact_schema"], "traffic_shape_score_v1");
        assert_eq!(score["score_status"], "PASS");
        assert_eq!(score["shape_score"], 1.0);
        assert_eq!(score["metrics"]["inter_arrival_ms_summary"]["count"], 4);
        assert_eq!(
            score["shape_score_interpretation"],
            "evidence_completeness_not_detection_probability"
        );
        assert!(score["blockers"].as_array().unwrap().is_empty());
    }

    #[test]
    fn missing_classifier_counts_cannot_be_clean_or_score_one() {
        for field in ["ndpi_risk_count", "suricata_alert_count", "verdict_counts"] {
            let mut incomplete = classifier();
            incomplete.as_object_mut().unwrap().remove(field);
            let score = score(&incomplete, Some(&pcap()), None);
            assert_eq!(score["score_status"], "PARTIAL", "{field}");
            assert_eq!(score["classifier_clean"], false, "{field}");
            assert!(score["shape_score"].as_f64().unwrap() < 1.0, "{field}");
            assert!(score["blockers"]
                .as_array()
                .unwrap()
                .contains(&json!("classifier_not_clean_or_counts_missing")));
        }
        let mut fail_count_missing = classifier();
        fail_count_missing["verdict_counts"]
            .as_object_mut()
            .unwrap()
            .remove("fail");
        assert_eq!(
            score(&fail_count_missing, Some(&pcap()), None)["classifier_clean"],
            false
        );
    }

    #[test]
    fn null_empty_and_zero_packet_summaries_are_not_capture_evidence() {
        let timing = json!({"inter_arrival_ms_summary": {"count": 1, "p50": 4}});
        for capture in [
            Value::Null,
            json!({}),
            json!({"packet_count": 0}),
            json!({"packet_count": null}),
            json!({"packet_count": -1}),
            json!({"packet_count": "12"}),
        ] {
            let score = score(&classifier(), Some(&capture), Some(&timing));
            assert_eq!(score["score_status"], "BLOCKED", "{capture}");
            assert_eq!(score["pcap_present"], false, "{capture}");
            assert!(score["shape_score"].as_f64().unwrap() < 1.0);
        }
    }

    #[test]
    fn raw_capture_path_requires_measured_packet_evidence() {
        let path = std::env::temp_dir().join(format!(
            "aegis-shape-evidence-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"nonempty arbitrary bytes").unwrap();
        let score = traffic_shape_score(
            "https_ws",
            &runtime(),
            &classifier(),
            None,
            None,
            Some(&path),
            "raw-path-fixture",
        );
        std::fs::remove_file(&path).unwrap();
        assert_eq!(score["pcap_raw_file_present"], true);
        assert_eq!(score["pcap_present"], false);
        assert_eq!(score["score_status"], "BLOCKED");
        assert!(score["blockers"]
            .as_array()
            .unwrap()
            .contains(&json!("raw_pcap_packet_count_unvalidated")));
    }

    #[test]
    fn null_empty_and_inconsistent_timing_cannot_complete_evidence() {
        let mut capture = pcap();
        capture
            .as_object_mut()
            .unwrap()
            .remove("inter_arrival_ms_summary");
        for timing in [
            Value::Null,
            json!({}),
            json!({"inter_arrival_ms_summary": null}),
            json!({"inter_arrival_ms_summary": {}}),
            json!({"inter_arrival_ms_summary": {"count": 0, "p50": 4}}),
            json!({"inter_arrival_ms_summary": {"count": 1, "p50": null}}),
            json!({"inter_arrival_ms_summary": {"count": 1, "p50": -1}}),
            json!({"inter_arrival_ms_summary": {"count": 12, "p50": 4}}),
            json!({"inter_arrival_ms_summary": {"count": 1, "p50": 4, "p90": 3}}),
            json!({"inter_arrival_ms_summary": {"count": 1, "p50": 4, "max": 3}}),
            json!({"inter_arrival_ms": []}),
            json!({"inter_arrival_ms": [null]}),
            json!({"inter_arrival_ms": [4, "bad", 3]}),
            json!({"inter_arrival_ms": [-1]}),
            json!({"inter_arrival_ms_p50": 4}),
        ] {
            let score = score(&classifier(), Some(&capture), Some(&timing));
            assert_eq!(score["score_status"], "PARTIAL", "{timing}");
            assert_eq!(score["timing_present"], false, "{timing}");
            assert!(score["metrics"]["inter_arrival_ms_summary"].is_null());
            assert!(score["shape_score"].as_f64().unwrap() < 1.0);
        }
    }

    #[test]
    fn valid_sample_arrays_and_witness_flat_metrics_remain_supported() {
        let mut capture = pcap();
        capture
            .as_object_mut()
            .unwrap()
            .remove("inter_arrival_ms_summary");
        let timing = json!({"inter_arrival_ms": [0, 0.5, 4]});
        let measured = score(&classifier(), Some(&capture), Some(&timing));
        assert_eq!(measured["score_status"], "PASS");
        assert_eq!(measured["metrics"]["inter_arrival_ms_summary"]["count"], 3);

        let flat = json!({
            "inter_arrival_ms_min": 0,
            "inter_arrival_ms_max": 8,
            "inter_arrival_ms_mean": 4,
            "inter_arrival_ms_p50": 4,
            "inter_arrival_ms_p90": 8,
            "inter_arrival_ms_p99": 8,
        });
        let measured = score(&classifier(), Some(&capture), Some(&flat));
        assert_eq!(measured["score_status"], "PASS");
        assert_eq!(measured["metrics"]["inter_arrival_ms_summary"]["count"], 11);

        let mut invalid_flat = flat;
        invalid_flat["inter_arrival_ms_count"] = json!(0);
        assert_eq!(
            score(&classifier(), Some(&capture), Some(&invalid_flat))["timing_present"],
            false
        );
    }

    #[test]
    fn invalid_explicit_ratios_are_not_repaired_by_positive_byte_counts() {
        for ratio in [
            json!(-0.1),
            Value::Null,
            json!("NaN"),
            json!("Infinity"),
            json!(f64::NAN),
            json!(f64::INFINITY),
        ] {
            let mut capture = pcap();
            capture["upload_download_ratio"] = ratio;
            let score = score(&classifier(), Some(&capture), None);
            assert_eq!(score["score_status"], "PARTIAL");
            assert_eq!(score["ratio_present"], false);
            assert!(score["metrics"]["upload_download_ratio"].is_null());
            assert!(score["shape_score"].as_f64().unwrap() < 1.0);
        }
        let mut zero_upload = pcap();
        zero_upload["upload_bytes"] = json!(0);
        assert_eq!(
            score(&classifier(), Some(&zero_upload), None)["score_status"],
            "PASS"
        );
    }
}
